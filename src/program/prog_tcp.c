/*
 * The protocol's wire layout and its segmentation rule.
 *
 * Compiler output, hand-written in the form `mtpc` would emit. This is the
 * first file in the tree that is allowed to know what a TCP header is; rule 4
 * permits protocol identity here and nowhere else.
 *
 * From the `.mtp` source:
 *
 *     pkt_bp TCPBP { uint16 src_port, dst_port; uint32 seq_no, ack_seq;
 *                    uint8 data_off, flags; uint16 window;
 *                    checksum16_t checksum; uint16 urg_ptr;
 *                    tcp_options opts; data_t data; }
 *
 *     seg_rule seg_seq(x) [ TCPBP::seq_no, x, prev.hdr.seq_no + prev.payload_len ]
 */
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

#include "contract.h"
#include "prog_params.h"
#include "prog_ctx.h"

/* Field offsets within the serialised header. The compiler knows these from
 * the pkt_bp declaration; nothing outside src/program/ does. */
#define TCPH_SEQ	4
#define TCPH_ACK	8
#define TCPH_DOFF	12
#define TCPH_FLAGS	13
#define TCPH_WINDOW	14
#define TCPH_CSUM	16

/*
 * The segmentation rule, at the target's segmentation point (CR-1).
 *
 * TCP's recurrence is PER BYTE — the next segment's sequence number is the
 * previous one's plus the previous payload length — which is why TCP is safe
 * under coalescing and under any other optimisation that changes how a
 * blueprint is split. A protocol whose recurrence is per PACKET is not: QUIC
 * advances its packet number once per packet, pkt_gen does not report how it
 * split, and the program's prediction is then wrong. Recorded here because
 * this is the file a future protocol's author will copy from.
 */
void
mtp_program_segment(const struct mtp_seg_view *v)
{
	uint32_t seq;

	if (!v->prev_hdr)
		return;			/* segment 0 keeps what the program built */

	memcpy(&seq, (const uint8_t *)v->prev_hdr + TCPH_SEQ, 4);
	seq = htonl(ntohl(seq) + v->prev_paylen);
	memcpy((uint8_t *)v->hdr + TCPH_SEQ, &seq, 4);
}

/*
 * Serialise the header once, when the blueprint is built — not per segment.
 * The prototype re-serialises the options for every segment; there is one
 * serialisation here and the per-segment work is the rule above.
 *
 * The option layout is frozen from the donor (tcp_out.c:83-124, 181-192) and
 * is an M1 exit item byte for byte, because moving serialisation into the
 * program is the one place the wire can change with no protocol logic changing.
 *
 *   SYN / SYN-ACK, exactly 20 bytes:
 *     MSS(2,4,hi,lo) NOP NOP Timestamp(8,10,TSval,TSecr) NOP WScale(3,3,7)
 *   every non-SYN, exactly 12 bytes:
 *     NOP NOP Timestamp
 */
uint16_t
tcp_build_header(uint8_t *out, const struct tcp_ctx *c, uint32_t seq,
		 uint8_t flags, uint32_t ts_val, uint32_t ts_ecr)
{
	int is_syn = (flags & 0x02) != 0;
	uint8_t *o;
	uint16_t hdr_len, w;
	uint32_t v32;

	memset(out, 0, 20);
	w = htons(c->loc_port);   memcpy(out + 0, &w, 2);
	w = htons(c->rem_port);   memcpy(out + 2, &w, 2);
	v32 = htonl(seq);         memcpy(out + TCPH_SEQ, &v32, 4);
	v32 = htonl(c->recv_next); memcpy(out + TCPH_ACK, &v32, 4);

	/* PSH is never set: tested at tcp_out.c:172,265 and passed by no
	 * caller. The program builds the header now, so this is a flag bit
	 * that could diverge with nothing else wrong. */
	out[TCPH_FLAGS] = (uint8_t)(flags & ~(PARITY_SET_PSH ? 0 : 0x08));

	w = htons(tcp_window_field(c, is_syn));
	memcpy(out + TCPH_WINDOW, &w, 2);

	o = out + 20;
	if (is_syn) {
		*o++ = 2; *o++ = 4;
		w = htons(PARITY_MSS_ADVERTISED); memcpy(o, &w, 2); o += 2;
		*o++ = 1; *o++ = 1;
		*o++ = 8; *o++ = 10;
		v32 = htonl(ts_val); memcpy(o, &v32, 4); o += 4;
		v32 = htonl(ts_ecr); memcpy(o, &v32, 4); o += 4;
		*o++ = 1;
		*o++ = 3; *o++ = 3; *o++ = PARITY_WSCALE;
	} else {
		*o++ = 1; *o++ = 1;
		*o++ = 8; *o++ = 10;
		v32 = htonl(ts_val); memcpy(o, &v32, 4); o += 4;
		v32 = htonl(ts_ecr); memcpy(o, &v32, 4); o += 4;
	}

	hdr_len = (uint16_t)(o - out);
	out[TCPH_DOFF] = (uint8_t)((hdr_len / 4) << 4);
	return hdr_len;
}

/*============================================================================*
 * The parser, the processors, and the dispatch
 *============================================================================*
 *
 * All generated in the form `mtpc` would emit. The `.mtp` source is
 * mtp/tcp.mtp; every processor below carries the section it comes from.
 *
 * M1c scope (docs/PLAN.md §6.1): passive open, bulk send under cwnd/rwnd, ACK
 * generation, FIN teardown, RTO. Not here: fast retransmit, SACK, PAWS,
 * zero-window probe, RST emission, out-of-order reassembly, reaping.
 */
/*
 * The listening endpoint, in the program's global state.
 *
 * `context` granularity is declared in `deploy`; this is the `global` one. It
 * is deliberately NOT the target's listener table: matching a listener is
 * protocol policy — G8 is "match on (ip, port), not port alone", which is a
 * statement about TCP — and the target has no business holding it.
 *
 * mTCP matches on port alone, so a socket bound to one address answers for
 * every address on the host. Matched on both here.
 */
static struct {
	uint32_t ip;
	uint16_t port;
	uint8_t  listening;

	/*
	 * The object the application has posted to serve. A one-shot server
	 * hands it over once and every accepted connection receives it; that
	 * is what epserver does with a file, and it is enough to drive bulk
	 * send.
	 *
	 * It arrives through the app interface as a SEND op, not as something
	 * this program invented — the bytes are the application's and the
	 * program only decides when they go.
	 */
	const void *obj;
	uint32_t    obj_len;
} prog_listener;

#define TCP_FIN	0x01
#define TCP_SYN	0x02
#define TCP_RST	0x04
#define TCP_ACK	0x10

/* Everything the parser pulls out of one packet. This is the program's event
 * in the compiler's flattened form. */
struct tcp_ev {
	uint32_t seq, ack;
	uint16_t sport, dport, window;
	uint8_t  flags, hdr_len;
	uint32_t ts_val, ts_ecr;
	uint8_t  wscale;
	bool     has_wscale;
	const uint8_t *payload;
	uint32_t payload_len;
};

/*
 * Options. The prototype's parser has two defects that must not reappear here,
 * and moving parsing into the program is exactly what makes them easy to
 * re-create: its option struct is an uninitialised stack local and its
 * extractor only ever sets valid=TRUE, so an ABSENT option reads stack garbage;
 * and the end-of-list kind falls into a default branch that moves the index
 * backwards and never terminates.
 *
 * So: the block is initialised, and kind 0 terminates explicitly.
 */
static void
parse_options(struct tcp_ev *e, const uint8_t *o, uint32_t len)
{
	uint32_t i = 0;

	e->ts_val = 0;
	e->ts_ecr = 0;
	e->wscale = 0;
	e->has_wscale = false;

	while (i < len) {
		uint8_t kind = o[i];

		if (kind == 0)			/* end of list — terminates */
			return;
		if (kind == 1) {		/* NOP */
			i++;
			continue;
		}
		if (i + 1 >= len)
			return;
		if (o[i + 1] < 2)		/* a zero/one length would loop */
			return;
		if (kind == 8 && o[i + 1] == 10 && i + 10 <= len) {
			memcpy(&e->ts_val, o + i + 2, 4);
			memcpy(&e->ts_ecr, o + i + 6, 4);
			e->ts_val = ntohl(e->ts_val);
			e->ts_ecr = ntohl(e->ts_ecr);
		}
		if (kind == 3 && o[i + 1] == 3 && i + 3 <= len) {
			e->wscale = o[i + 2];
			e->has_wscale = true;
		}
		i += o[i + 1];
	}
}

static int
parse_packet(const uint8_t *l4, uint16_t len, struct tcp_ev *e)
{
	uint16_t w;

	if (len < 20)
		return -1;

	memcpy(&w, l4 + 0, 2); e->sport = ntohs(w);
	memcpy(&w, l4 + 2, 2); e->dport = ntohs(w);
	memcpy(&e->seq, l4 + TCPH_SEQ, 4); e->seq = ntohl(e->seq);
	memcpy(&e->ack, l4 + TCPH_ACK, 4); e->ack = ntohl(e->ack);
	e->hdr_len = (uint8_t)((l4[TCPH_DOFF] >> 4) * 4);
	e->flags = l4[TCPH_FLAGS];
	memcpy(&w, l4 + TCPH_WINDOW, 2); e->window = ntohs(w);

	if (e->hdr_len < 20 || e->hdr_len > len)
		return -1;

	parse_options(e, l4 + 20, (uint32_t)(e->hdr_len - 20));
	e->payload = l4 + e->hdr_len;
	e->payload_len = (uint32_t)(len - e->hdr_len);
	return 0;
}

/*
 * The flow key, CANONICALISED so both directions resolve one context (CR-5).
 *
 * The target cannot do this: it may not read a field of the key, and only this
 * program knows that v0/v2 are the local half. An inbound packet's destination
 * is our local endpoint; an application operation's `local` is the same thing.
 * Build them in the same order and the two directions meet.
 */
static flowkey_t
key_of_inbound(uint32_t loc_ip, uint32_t rem_ip, uint16_t loc_port,
	       uint16_t rem_port)
{
	flowkey_t k;

	memset(&k, 0, sizeof(k));	/* the target compares BYTES */
	k.v0 = loc_ip; k.v1 = rem_ip; k.v2 = loc_port; k.v3 = rem_port;
	return k;
}

/*----------------------------------------------------------------------------*/
/* mtp/tcp.mtp §proc_passive_open — a SYN with no context and a listener. */
static void
proc_passive_open(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	uint16_t hdr_len;
	struct mtp_tx_payload none = { 0 };

	c->state = TCP_SYN_RCVD;
	c->recv_next = e->seq + 1;		/* the SYN consumes one byte */

	/*
	 * `delivered` is the SAME ORIGIN as recv_next, not zero.
	 *
	 * §window_rule computes rcv_wnd = RCVBUF - (recv_next - delivered), and
	 * that difference has to be a BYTE COUNT. recv_next is an absolute
	 * sequence number seeded from the peer's ISN, so leaving delivered at
	 * zero makes the difference a sequence number and the window arbitrary
	 * — it advertised 29423 on the first acknowledgement here.
	 *
	 * Fourth instance of the units bug this increment (docs/PLAN.md §3):
	 * two quantities of the same C type, one absolute and one relative,
	 * subtracted. Nothing type-checks it and the wire is where it shows.
	 */
	c->rcv_base = c->recv_next;
	c->delivered = c->rcv_base;
	c->ts_recent = e->ts_val;

	/*
	 * The peer's window scale, from ITS SYN. It applies to every window it
	 * advertises AFTER the handshake and not to the SYN's own field, which
	 * is unscaled — so this records the shift and the SYN's window is taken
	 * raw. Reading a later window raw sent 502 bytes where the peer had
	 * offered 64256 and the congestion window should have bounded the send
	 * at 2920, which is a throughput difference with no visible cause.
	 */
	c->snd_wscale = e->has_wscale ? e->wscale : 0;
	c->send_wnd = e->window;

	/*
	 * D-01, behind PARITY_OPENING_TRAJECTORY. mTCP never assigns ssthresh
	 * on the passive-open path, so the server runs with ssthresh == 0, the
	 * slow-start test is false from the first ACK, and it does congestion
	 * avoidance from cwnd = 2*MSS. Reproduced knowingly.
	 *
	 * The flag gates snd_wl1 and last_ack_seq too, which have no live
	 * consequence TODAY only because the ISN is frozen at 0 — lift that and
	 * snd_wl1's divergence activates with nothing in the diff pointing at
	 * the cause.
	 */
	c->send_una = PARITY_ISN;
	c->send_next = PARITY_ISN;
	c->cwnd = PARITY_INIT_CWND;
	c->ssthresh = PARITY_OPENING_TRAJECTORY ? PARITY_SSTHRESH_PASSIVE
					        : PARITY_SSTHRESH_ACTIVE;

	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_SYN | TCP_ACK,
				   now, c->ts_recent);
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1) == 0) {
		c->send_next++;			/* the SYN-ACK consumes one */
		c->snd_base = c->send_next;	/* ...so data starts one past */
	}
}

/* mtp/tcp.mtp §proc_open_done — the ACK that completes a passive open. */
static void
proc_open_done(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	if (c->state != TCP_SYN_RCVD || !(e->flags & TCP_ACK))
		return;
	if (e->ack != c->send_next)
		return;
	c->send_una = e->ack;
	c->send_wnd = (uint32_t)e->window << c->snd_wscale;
	c->ts_recent = e->ts_val;
	c->state = TCP_ESTABLISHED;
	mtp_notify(c->f, &(struct mtp_notif){ .kind = MTP_NOTIF_STATE });

	/* the application posted an object before listening; serve it */
	if (prog_listener.obj_len)
		tcp_app_send(c, prog_listener.obj, prog_listener.obj_len, now);
}

/*
 * G16, stated as the donor states it: ANY TRANSMISSION THAT CONSUMES SEQUENCE
 * SPACE ARMS THE RETRANSMISSION TIMER. SendTCPPacket counts a SYN or a FIN as
 * one byte of payload before the arm, so one rule covers SYN, SYN-ACK, FIN and
 * data — "armed in the handshake processors" makes it easy to forget the FIN.
 *
 * The donor has NO FLOOR and NO CEILING on the RTO (differences.md §1.1), so
 * the effective value here is about 3 ms — roughly twenty times the measured
 * round trip. Reproduced: a retransmission on this link is a real event.
 */
static void
arm_rto(struct tcp_ctx *c)
{
	c->rto.ctx = c;
	mtp_timer_start(&c->rto, (uint64_t)PARITY_INITIAL_RTO_MS * 1000000ULL
			<< (c->rtx_count < 7 ? c->rtx_count : 7));
}

/*----------------------------------------------------------------------------*/
/* mtp/tcp.mtp §proc_ack — an acknowledgement of our data. */
static void
proc_ack(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	uint32_t acked;

	if (c->state != TCP_ESTABLISHED || !(e->flags & TCP_ACK))
		return;

	c->send_wnd = (uint32_t)e->window << c->snd_wscale;
	c->ts_recent = e->ts_val;

	acked = e->ack - c->send_una;
	if ((int32_t)acked <= 0)
		return;			/* duplicate or stale */

	c->send_una = e->ack;
	mtp_tx_flush_and_notify(&c->tx, acked);

	/* progress: cancel, and reset the backoff. Re-armed below if anything
	 * is still outstanding. */
	c->rtx_count = 0;
	mtp_timer_stop(&c->rto);
	if (c->send_una != c->send_next)
		arm_rto(c);

	/*
	 * Congestion window growth, with the donor's granularity: packets is
	 * floor(rmlen / 1448), and B found the packets++ at tcp_in.c:519 is
	 * unreachable dead code — so AN ACKNOWLEDGEMENT COVERING FEWER THAN
	 * 1448 NEW BYTES GROWS THE WINDOW BY NOTHING AT ALL. Reproduced; the
	 * inventory's "rounded up" was corrected to this.
	 *
	 * ssthresh is 0 on a passive open (D-01), so cwnd < ssthresh is false
	 * from the first acknowledgement and this is always congestion
	 * avoidance. The server has no slow start. Reproduce, do not correct.
	 */
	{
		uint32_t packets = acked / PARITY_MSS_PAYLOAD;

		if (packets && c->cwnd >= c->ssthresh)
			c->cwnd += (PARITY_MSS_ADVERTISED * PARITY_MSS_ADVERTISED)
				   / c->cwnd * packets;
		else if (packets)
			c->cwnd += PARITY_MSS_ADVERTISED * packets;
	}

	tcp_gen_seg(c, now);
}

/* mtp/tcp.mtp §proc_recv and §send_ack — in-order payload, then acknowledge. */
static void
proc_recv(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload none = { 0 };
	uint16_t hdr_len;

	/*
	 * The data-acknowledgement path, silenced permanently once a FIN has
	 * been accepted (D-20). One state test that says what it means, which
	 * is the prototype's mechanism rather than mTCP's emergent counter
	 * arithmetic — reproducing that would mean reproducing the arithmetic
	 * to obtain a side effect.
	 */
	if (c->state != TCP_ESTABLISHED)
		return;
	if (!e->payload_len)
		return;
	if (e->seq != c->recv_next)
		return;			/* out of order: M2, and it does not
					 * fire at -c 1 on a clean LAN */

	/* §window_rule recompute point 1: payload merged in order. Nothing
	 * else in this program may write rcv_wnd. */
	tcp_on_payload_merged(c, c->recv_next + e->payload_len);

	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_ACK, now,
				   c->ts_recent);
	mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1);
}

/*----------------------------------------------------------------------------*/
/*
 * mtp/tcp.mtp §proc_fin — the peer closes.
 *
 * The acknowledgement of the peer's FIN comes from the CONTROL path and must
 * not be suppressed (D-20, corrected): once a FIN is accepted the
 * DATA-acknowledgement path goes quiet for this stream permanently, and the
 * control path keeps emitting. Suppressing both stalls teardown and the peer
 * retransmits its FIN.
 *
 * Ordering, from C on the prototype and easy to invert: the acknowledgement is
 * built BEFORE the state transition, so it is still emitted for the FIN itself.
 * Transition first and the guard that silences the data path would silence this
 * too.
 */
static void
proc_fin(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload none = { 0 };
	uint16_t hdr_len;

	if (!(e->flags & TCP_FIN))
		return;
	if (c->state != TCP_ESTABLISHED)
		return;
	if (e->seq != c->recv_next)
		return;			/* a FIN ahead of a gap does not
					 * transition; the segment that fills
					 * the hole performs it (C) */

	c->recv_next = e->seq + 1;	/* the FIN consumes one byte */

	/* built before the transition, deliberately */
	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_ACK, now,
				   c->ts_recent);
	mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1);

	c->state = TCP_CLOSE_WAIT;
	mtp_notify(c->f, &(struct mtp_notif){ .kind = MTP_NOTIF_STATE });
}

/*
 * mtp/tcp.mtp §gen_fin — our own FIN.
 *
 * G10, and the constraint is narrower than "order the FIN". Against data
 * already turned into blueprints the per-flow ring is FIFO, so a FIN committed
 * after them cannot overtake them. What must not happen is a FIN ahead of data
 * the program has NOT yet handed to the target — the window- or
 * congestion-limited case — which in the prototype goes out at one past ALL
 * buffered data, leaving a sequence gap and a second FIN once the buffer
 * drains.
 *
 * So the gate is exactly: send_next has caught up with write_end. The
 * prototype gates this in one of its two close paths and not the other, which
 * is the evidence it is an oversight rather than a decision.
 */
static void
gen_fin(struct tcp_ctx *c, uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload none = { 0 };
	uint16_t hdr_len;

	if (c->state != TCP_CLOSE_WAIT)
		return;
	if (c->send_next - c->snd_base != c->write_end)
		return;			/* G10: not ahead of unsent data */

	hdr_len = tcp_build_header(hdr, c, c->send_next,
				   TCP_ACK | TCP_FIN, now, c->ts_recent);
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1) == 0) {
		c->send_next++;		/* the FIN consumes one byte */
		c->state = TCP_LAST_ACK;
	}
}

/*----------------------------------------------------------------------------*/
/*
 * The generated dispatch: a static switch on event type calling the processors
 * directly, not a runtime table. One flow-table lookup per packet — two on a
 * passive open, where the flow lookup misses and the listener table is
 * consulted, which is once per connection rather than once per packet.
 */
int
mtp_program_net_input(const uint8_t *l4, uint16_t len, const struct iphdr *iph,
		      uint32_t now_ms)
{
	struct tcp_ev e;
	struct tcp_ctx *c;
	flowkey_t k;

	if (parse_packet(l4, len, &e) < 0)
		return -1;

	k = key_of_inbound(iph->daddr, iph->saddr, e.dport, e.sport);

	c = mtp_ctx_lookup(&k);				/* lookup 1 */
	if (!c) {
		if (!(e.flags & TCP_SYN) || (e.flags & TCP_ACK))
			return 0;			/* no context, not an open */
		/* G8: both halves must match. A miss is a miss — never a null
		 * context handed onward, which is how the prototype turns a
		 * missed lookup into a crash. */
		if (!prog_listener.listening ||
		    prog_listener.port != e.dport ||
		    prog_listener.ip != iph->daddr)
			return 0;
		c = mtp_new_ctx(&k, sizeof(*c));
		if (!c)
			return -1;
		c->rcv_wnd = PARITY_INITIAL_WINDOW;
		c->loc_port = e.dport;
		c->rem_port = e.sport;
		proc_passive_open(c, &e, now_ms);
		return 0;
	}

	proc_open_done(c, &e, now_ms);
	proc_ack(c, &e, now_ms);
	proc_recv(c, &e, now_ms);
	proc_fin(c, &e, now_ms);
	gen_fin(c, now_ms);

	/* the final acknowledgement of our FIN */
	if (c->state == TCP_LAST_ACK && (e.flags & TCP_ACK) &&
	    e.ack == c->send_next) {
		c->state = TCP_CLOSED;
		mtp_del_ctx(&k);
	}
	return 0;
}

/*----------------------------------------------------------------------------*/
/*
 * app_parser socket { bind -> sock_bind; listen -> sock_listen; }
 *
 * CR-7: the target defines the interface's op schema and the program maps the
 * ops it needs into its own events. There is no built-in listen; this program
 * binds it because it is a passive-open protocol. DESIGN.md §17.1 has the
 * schema.
 */
int
mtp_program_app_op(const struct mtp_app_op *op, uint32_t now_ms)
{
	(void)now_ms;

	switch (op->kind) {
	case MTP_APP_BIND:
		/*
		 * The op's endpoint is in NETWORK order, as the schema
		 * declares; this program works in host order once past the
		 * parser. Converting here rather than at the comparison site
		 * keeps the one representation choice in one place — the two
		 * being out of step is what made the listener never match and
		 * swallowed every SYN silently.
		 */
		prog_listener.ip = op->local.ip;	/* stays network order:
							 * compared against
							 * iph->daddr, which is */
		prog_listener.port = ntohs(op->local.port);
		return 0;
	case MTP_APP_LISTEN:
		prog_listener.listening = 1;
		return 0;
	case MTP_APP_SEND:
		/* posted before any connection exists: the object every
		 * accepted connection is served. A real accept/send pair
		 * arrives with the application queues. */
		prog_listener.obj = op->data.base;
		prog_listener.obj_len = op->len;
		return 0;
	default:
		return -1;		/* an op this program does not bind */
	}
}

/* No timers are armed until the RTO lands, so nothing reaches this yet. */
/*
 * mtp/tcp.mtp §proc_timeout — the retransmission timer fired.
 *
 * After an RTO the donor sets cwnd = MSS and ssthresh = max(cwnd/2, 2*MSS).
 * One segment leaves, and B established WHY: cwnd == MSS while a segment
 * consumes MSS - 12, so the window bail fires after the first segment
 * regardless of which constant it is compared against. It is NOT the
 * 1460-versus-1448 mismatch, which was the earlier and wrong explanation.
 */
void
mtp_program_timer(struct mtp_timer *t, uint32_t now_ms)
{
	struct tcp_ctx *c = t->ctx;

	if (!c || c->state == TCP_CLOSED)
		return;

	if (++c->rtx_count > PARITY_MAX_RTX) {
		c->state = TCP_CLOSED;		/* G11: closed at 16 */
		mtp_notify(c->f, &(struct mtp_notif){ .kind = MTP_NOTIF_ERROR });
		return;
	}

	c->ssthresh = (c->cwnd / 2 > 2 * PARITY_MSS_ADVERTISED)
		      ? c->cwnd / 2 : 2 * PARITY_MSS_ADVERTISED;
	c->cwnd = PARITY_MSS_ADVERTISED;

	/* retransmit from the oldest unacknowledged byte, not the unsent tail
	 * (G13 — the prototype sizes this from the wrong end) */
	c->send_next = c->send_una;
	tcp_gen_seg(c, now_ms);
}

/*============================================================================*
 * mtp/tcp.mtp §gen_seg — the send decision
 *============================================================================*/
/*
 * One pkt_gen for the whole sendable run; the target segments it and the seg
 * rule assigns each segment's sequence number. That is P4 — deferred
 * segmentation — and it is why the recurrence in §seg_rule has to be per BYTE:
 * the program does not know, and must not need to know, how the run was split.
 *
 * G2, the sender-side silly-window rule, is the DONOR'S and not the
 * prototype's rounding: refuse a sub-MSS segment when anything is in flight.
 * And it is reproduced with the donor's constants — the window is compared
 * against 1460 while a segment consumes 1448.
 *
 * That mismatch is NOT why an RTO sends one segment; B withdrew its own earlier
 * agreement with that explanation. After an RTO cwnd is 1460, the first segment
 * consumes 1448, and the remaining 12 is below either threshold, so the bail
 * fires identically whichever constant is used. One segment per RTO follows
 * from cwnd == MSS while a segment consumes MSS - 12, and nothing else. The
 * mismatch is observable only when min(cwnd, peer_wnd) - inflight lands in
 * [1448, 1460).
 */
void
tcp_gen_seg(struct tcp_ctx *c, uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload pay;
	uint32_t win, to_send;
	uint16_t hdr_len;

	if (c->state != TCP_ESTABLISHED)
		return;

	win = c->cwnd < c->send_wnd ? c->cwnd : c->send_wnd;

	/*
	 * THE DONOR'S LOOP PREDICATE, not a restatement of it.
	 *
	 *     remaining_window = MIN(cwnd, peer_wnd) - (seq - snd_una)
	 *     if (remaining_window <= 0 ||
	 *         (remaining_window < mss && seq - snd_una > 0)) bail
	 *     len     = MIN(len, remaining_window)
	 *     pkt_len = MIN(len, mss - 12)
	 *
	 * Two things a rounding rule would lose, and both matter:
	 *
	 *   `seq - snd_una > 0` IS AN ESCAPE. With nothing in flight the rule
	 *   does not apply and the donor sends whatever fits, down to one byte.
	 *   Rounding down to a multiple of the payload maximum with no escape
	 *   withholds the last partial segment for ever whenever the buffer
	 *   does not refill — which is the end of every object. Nine short
	 *   segments traded for a transfer that never completes.
	 *
	 *   The predicate is on unused WINDOW, not on the amount available to
	 *   send: `len` does not appear in it. The two coincide in the common
	 *   case and come apart when the window binds rather than the data.
	 *
	 * We run the loop to decide HOW MUCH, then issue one pkt_gen and let
	 * the target segment (P4) — so the program never learns how it split,
	 * which is what makes the per-byte recurrence safe.
	 */
	{
		uint32_t seq = c->send_next;

		to_send = 0;
		for (;;) {
			uint32_t inflight_here = seq - c->send_una;
			int32_t rw = (int32_t)win - (int32_t)inflight_here;
			uint32_t avail_here, len, pkt;

			if (rw <= 0)
				break;
			if (rw < PARITY_MSS_ADVERTISED && inflight_here > 0)
				break;

			avail_here = c->write_end - (seq - c->snd_base);
			if (!avail_here)
				break;

			len = avail_here < (uint32_t)rw ? avail_here : (uint32_t)rw;
			pkt = len < PARITY_MSS_PAYLOAD ? len : PARITY_MSS_PAYLOAD;

			to_send += pkt;
			seq += pkt;
		}
	}

	if (to_send == 0)
		return;

	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_ACK, now,
				   c->ts_recent);

	pay.u   = &c->tx;
	pay.off = c->send_next - c->snd_base;	/* into the unit, not the stream */
	pay.len = to_send;

	if (mtp_pkt_gen(c->f, hdr, hdr_len, &pay, PARITY_MSS_PAYLOAD, 0, 1) == 0) {
		c->send_next += to_send;
		arm_rto(c);
	}
}

/*
 * mtp/tcp.mtp §record_data — application data arrives.
 *
 * The send buffer is created lazily, on first write, which is the donor's
 * behaviour (its eager-allocation counterpart is the prototype's and is an
 * unjudged difference, not a gap). write_end is the program's own mirror of how
 * much it has appended — the target has no accessor to ask, and §2.4b's
 * withdrawal rests on exactly this working.
 */
int
tcp_app_send(struct tcp_ctx *c, const void *data, uint32_t len, uint32_t now)
{
	struct mtp_tx_addr addr;
	int wrote;

	if (c->state != TCP_ESTABLISHED)
		return -1;

	if (!c->tx_open) {
		mtp_new_tx_ordered_data(&c->tx, MTP_SIZE_INF);
		c->tx_open = true;
	}

	addr.base = data;
	addr.len = len;
	wrote = mtp_add_tx_data(&c->tx, addr, len);
	if (wrote > 0)
		c->write_end += (uint32_t)wrote;

	tcp_gen_seg(c, now);
	return wrote;
}

/*============================================================================*
 * mtp/tcp.mtp §coalesce — what a merged packet keeps
 *============================================================================*/
/*
 * Two classes, which is all TCP needs and is exactly the prototype's three
 * merges once they are put on the right axis:
 *
 *   data     inherit_base = true.  The older sequence and payload origin, the
 *                                  newer acknowledgement, window and timestamp.
 *   pure ack inherit_base = false. Both contributions are empty, so the emitted
 *                                  acknowledgement carries the LATEST cumulative
 *                                  value — which is the whole mechanism behind
 *                                  the difference report's D4.
 *
 * The key is the flags byte, so a data segment never merges with a pure
 * acknowledgement and a SYN or FIN never merges with anything: a control packet
 * consumes sequence space and merging it would lose that.
 */
void
mtp_program_coalesce(const uint8_t *hdr, uint16_t hdr_len,
		     uint8_t *class, uint32_t *key, bool *inherit_base)
{
	uint8_t flags = hdr[TCPH_FLAGS];

	(void)hdr_len;

	/* anything consuming sequence space stands alone */
	if (flags & (TCP_SYN | TCP_FIN | TCP_RST)) {
		*class = 0;
		return;
	}

	*class = 1;
	*key = flags;
	*inherit_base = true;
}
