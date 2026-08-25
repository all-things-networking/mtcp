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
 *     bp.data = unseg_data(addr, to_send, MSS,
 *                          [TCPBP::seq_no, ctx.send_next,
 *                           prev.seq_no + prev.payload_len]);
 *
 * The rule is an argument to the segmentation, written at the call as every
 * reference program writes it -- not a free-standing `seg_rule` declaration
 * named in a `deploy` block, which was ours and is gone (2026-08-18).
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "contract.h"
#include "prog_params.h"
#include "prog_ctx.h"

/* Defined far below; tcp_build_header is its first caller and comes before it. */
static void tcp_touch_idle(struct tcp_ctx *c);
static uint16_t tcp_build_rst_header(uint8_t *out, uint16_t loc_port,
				     uint16_t rem_port, uint32_t seq,
				     uint32_t ack, uint8_t flags);

/*
 * INSTRUMENTATION, INERT UNLESS ENABLED AT RUN TIME.
 *
 * D-03's rule applied to our own program rather than to a reference. Sixty-nine
 * counter and histogram sites accumulated across this investigation with no
 * guard of any kind: every one ran in every build, on the packet path, whether
 * or not anyone was reading them.
 *
 * One branch on a file-scope int, resolved once. The branch predicts perfectly
 * and the counters cost nothing when off; the point is not the cycles saved but
 * that a measurement build and a shipping build stop being the same binary by
 * accident.
 *
 * MTP_INSTR=1 turns them on. Default OFF -- "inert unless enabled" means the
 * default is inert, or the rule says nothing.
 *
 * NOT gated: fault detection, the reference-fault dump, the reachability
 * invariant and the assertions. Those are correctness, not measurement, and
 * D-03 does not ask for them to be switchable.
 */
static int g_instr = -1;

static inline int instr_on(void)
{
	if (g_instr < 0)
		g_instr = getenv("MTP_INSTR") ? 1 : 0;
	return g_instr;
}

#define INSTR(stmt) do { if (instr_on()) { stmt; } } while (0)


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
/*
 * A reset's header, built WITHOUT A CONTEXT, because a reset for a connection
 * that does not exist has none. Ports come from the offending segment with the
 * halves swapped, and there are no options: the donor's SendTCPPacketStandalone
 * sends none on this path, and a timestamp echo would need a ts_recent we have
 * never had.
 */
static uint16_t
tcp_build_rst_header(uint8_t *out, uint16_t loc_port, uint16_t rem_port,
		     uint32_t seq, uint32_t ack, uint8_t flags)
{
	uint16_t w;
	uint32_t v32;

	memset(out, 0, 20);
	w = htons(loc_port);   memcpy(out + 0, &w, 2);
	w = htons(rem_port);   memcpy(out + 2, &w, 2);
	v32 = htonl(seq);      memcpy(out + TCPH_SEQ, &v32, 4);
	v32 = htonl(ack);      memcpy(out + TCPH_ACK, &v32, 4);
	out[TCPH_FLAGS] = flags;
	out[TCPH_DOFF] = (uint8_t)(5 << 4);	/* 20 bytes, no options */
	/* Window zero: there is no receive buffer behind a connection that does
	 * not exist, and the donor passes 0 at every standalone site. */
	return 20;
}

uint16_t
tcp_build_header(uint8_t *out, struct tcp_ctx *c, uint32_t seq,
		 uint8_t flags, uint32_t ts_val, uint32_t ts_ecr)
{
	/*
	 * EVERY PACKET THAT ACKNOWLEDGES RESETS THE PROBE'S CLOCK, which is the
	 * donor's rule and was not ours. It sets ts_lastack_sent on any segment
	 * carrying the ACK flag (tcp_out.c:293) -- so on a busy connection its
	 * "500 ms since our last acknowledgement" gate is never satisfied and
	 * the probe effectively fires only once the connection has gone quiet.
	 *
	 * Ours stamped this only when a PROBE was emitted, so the gate measured
	 * the interval between probes and we would probe where the donor would
	 * not. Found by checking the donor's code rather than our comment about
	 * it, after claiming the two matched.
	 *
	 * Here rather than at the five emission sites because there is exactly
	 * one header built per emission, and a rule enforced at five call sites
	 * is a rule the sixth will not follow.
	 */
	if (flags & TCPH_ACK) {
		c->last_ack_sent_ms = ts_val;
		/*
		 * AND THE IDLE CLOCK. The donor stamps last_active_ts on the
		 * same line it stamps ts_lastack_sent (tcp_out.c:293-296), and
		 * again on every received packet (tcp_in.c:1292). Restarting
		 * the timer is our equivalent of its UpdateTimeoutList moving
		 * the stream to the tail of an ordered list.
		 */
		tcp_touch_idle(c);
	}

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
/*
 * THE LISTEN CONTEXT WAS A FILE-SCOPE STRUCT, so this program could hold
 * exactly one listening socket (DEFERRED.md D4). It is a context now, one
 * instance per endpoint, stored under key_of_listener and reached the same way
 * every other context is. Nothing about it is file-scope any more.
 */

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
	bool     has_ts;	/* a timestamp option was PRESENT, as against
				 * ts_val happening to be zero. PAWS turns on
				 * the difference: absent is a drop, zero is a
				 * legal value */
	const uint8_t *payload;
	uint32_t payload_len;
};

/*
 * mtp/tcp.mtp §scratchpad — per-dispatch working state, one instance per
 * event, discarded when the chain ends. It is how one processor tells the next
 * something without either of them owning it.
 *
 * `ctx_dead` is not in the program's declared scratchpad and is not protocol
 * state: it is how `del_ctx` ends the chain it was issued from. The context is
 * freed the moment that instruction runs, so every later processor in the
 * chain would read freed memory. A target that deferred destruction to the end
 * of the pass would not need it; ours frees immediately.
 */
struct tcp_scratch {
	uint32_t	acked;		/* new bytes this acknowledgement retired */
	uint32_t	delivered;	/* bytes the application took */
	bool		ack_now;	/* an acknowledgement is owed */
	bool		ctx_dead;	/* del_ctx ran: stop the chain */
	/*
	 * The donor does NOT attempt a send on a fourth-or-later duplicate: it
	 * inflates cwnd and re-adds nothing to its send list. gen_seg is the
	 * next link in this chain and would otherwise attempt one, so the
	 * decision is carried here rather than by gen_seg guessing.
	 */
	bool		no_send;
};

/* Defined below, forward-declared for the acknowledgement chain. */
static void enter_time_wait(struct tcp_ctx *c);
static void gen_rst_from_ctx(struct tcp_ctx *c, const struct tcp_ev *e);
static void gen_syn(struct tcp_ctx *c, uint32_t now);
static int  record_data(struct tcp_ctx *c, struct mtp_tx_addr addr, uint32_t len);
static void gen_fin(struct tcp_ctx *c, uint32_t now);

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
	e->has_ts = false;

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
			e->has_ts = true;
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

/*
 * The key of a LISTENING endpoint. Same table, same shape, and it cannot
 * collide with a connection's: a connection always has a remote port, and this
 * always has zero for both remote halves.
 *
 * WHICH IS WHY THE TARGET NEEDS NO LISTENER TABLE. Matching a listener is
 * protocol policy — G8 is "match on address AND port", which is a statement
 * about TCP, and the donor matches on port alone (fhash.c:137-143), so a socket
 * bound to one address answers every address on its host. Encoding that choice
 * as a KEY rather than as a table keeps it in the program, where a different
 * protocol can choose differently. `src/target/flow_table.c` still carries a
 * listener table keyed on (ip, port); it is unused and should go
 * (DEFERRED.md F9).
 */
static flowkey_t
key_of_listener(uint32_t loc_ip, uint16_t loc_port)
{
	return key_of_inbound(loc_ip, 0, loc_port, 0);
}

/*----------------------------------------------------------------------------*/
/*
 * WHAT WE EMITTED, BY CAUSE — and this is an audit of the fingerprint, not a
 * new curiosity.
 *
 * `zero=4` aggregates the SYN-ACK, the pure acknowledgement, the FIN and the
 * final acknowledgement. It read correctly when it moved 2 -> 4 only because
 * we happened to know active close had landed. The window probe ALSO emits a
 * zero-payload acknowledgement, so `zero` in this build already means something
 * different from `zero` in the recorded fingerprint — and nobody noticed,
 * because the two runs were against different peers.
 *
 * That is the same failure as `timers fired`: an aggregate silently absorbing a
 * new mechanism, so the same digits stop meaning the same thing without anyone
 * editing the number. A fingerprint is a promise that a number means the same
 * thing next time, and the promise is only as good as the counters behind it.
 *
 * Counted in the PROGRAM, where the cause is known. The target cannot classify
 * these without reading protocol flags, which rule 4 forbids it.
 */
enum { EM_SYNACK, EM_ACK_DATA, EM_ACK_FIN, EM_PROBE, EM_PROBE_REPLY, EM_FIN,
       EM_DATA, EM_DATA_RTX, EM_RST, EM_SYN, EM__N };
/*
 * THE PROGRAM'S TRANSMIT SCHEDULING POLICY (D-17).
 *
 * The target provides MTP_PRIO_CLASSES classes and drains the highest first.
 * It attaches no meaning to them. What each class MEANS is stated here, in the
 * program, and nowhere else -- that is what keeps the protocol out of the
 * target while still producing the donor's observable ordering: control ahead
 * of pure acknowledgements ahead of data.
 */
#define PRIO_CONTROL	2	/* SYN: ahead of everything, holds no data position */
#define PRIO_ACK	1	/* pure acknowledgements and window probes */
#define PRIO_DATA	0	/* payload -- and the FIN, see below */

/*
 * THE FIN IS PRIO_DATA, NOT PRIO_CONTROL, AND THE REASON IS ORDERING.
 *
 * A FIN occupies a sequence position after the data it terminates. Class 2
 * drains before class 0, so classifying it as control sends it AHEAD of the
 * payload it follows: the peer sees a FIN at a sequence number it has not
 * reached, and the transfer never completes. Measured, not reasoned -- the
 * server reported a full object served and the client reported zero
 * completions, because it never saw EOF.
 *
 * The rule this is an instance of: ANYTHING THAT CONSUMES SEQUENCE SPACE MUST
 * BE ORDERED WITH THE DATA. Pure acknowledgements and SYN do not, so they may
 * overtake; a FIN does.
 *
 * mTCP reaches the same place BY CONSTRUCTION rather than by rule: its FIN
 * leaves from the send path, not the control list, so the question never
 * arises there. A reader comparing the two should not expect to find this rule
 * stated anywhere in the donor -- its structure makes it unnecessary, and ours
 * does not.
 */

static uint64_t g_emit[EM__N];
static uint64_t g_app_bytes;   /* bytes accepted from the application */

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
	/*
	 * PAWS applies only to a peer that timestamps, and the donor decides it
	 * once, here, from the SYN's options (tcp_util.c:47-51). ts_recent is
	 * seeded at the same moment and by the same line there.
	 */
	c->saw_timestamp = e->has_ts;
	/* the boundary starts where the peer's first data byte will */
	mtp_sw_init(&c->rx_wnd, c->recv_next);
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
	INSTR(g_emit[EM_SYNACK]++);
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, PRIO_CONTROL, 1, 0 /* not a retransmission */) == 0) {
		c->send_next++;			/* the SYN-ACK consumes one */
		c->snd_base = c->send_next;	/* ...so data starts one past */
		/*
		 * CR-E: the ring exists from establishment, not from the first
		 * send. The target buffers into it on the application thread
		 * (mtp_app_send) and needs f->tx_unit valid before the
		 * application's first write, which a lazy open cannot promise.
		 */
		if (!c->tx_open) {
			mtp_new_tx_ordered_data(&c->tx, MTP_SIZE_INF);
			c->tx_open = true;
		}
	}
}

/*
 * Our send path is open, which is not the same as the connection being
 * ESTABLISHED. CLOSE_WAIT is a sending state — it is the whole point of it:
 * the peer's FIN closes the PEER's path (D-20, per-path), and ours stays open
 * until the application closes it.
 *
 * This is one predicate rather than three state tests because it was three:
 * accepting the write, generating the segments, and processing the ACKs that
 * come back each tested ESTABLISHED separately, and fixing them one at a time
 * moved the failure rather than removing it. A response to a request whose FIN
 * arrived with it needs all three.
 */
/*
 * WHY THE SEND DECISION EMITTED NOTHING, counted per reason.
 *
 * This inverts the search. Counters built for other purposes can only narrow
 * "what stopped us sending" by inference backwards; a refusal reason answers it
 * forwards. It is the same instrument as `APPSEND refused: state=5`, which
 * named the close-gating bug in one line after the counters had only bracketed
 * it — and if the decision is never CALLED, no reason appears at all, which is
 * a different answer rather than a missing one.
 */
enum { REF_STATE, REF_WINDOW, REF_SWS, REF_NODATA, REF_SENT, REF__N };
static uint64_t g_refuse[REF__N];

/* Available-window census — see the discriminator in tcp_gen_seg. */
static uint64_t g_avail_bucket[6];
static uint64_t g_rtt_bucket[6], g_rtt_sum, g_rtt_n, g_rtt_max;
static uint64_t g_cwnd_sum, g_inflight_sum;
static uint64_t g_ack_hist[8], g_ack_sum, g_ack_n, g_ack_max;
static uint64_t g_emit_unacked;
static uint64_t g_int_rtx, g_int_clean, g_bytes_rtx, g_bytes_clean;
static uint64_t g_rto_sum, g_rto_n, g_rto_max;
static uint64_t g_nodata_held[7], g_nodata_held_sum, g_nodata_n;
static uint64_t g_nodata_cwnd, g_nodata_peer, g_nodata_infl, g_nodata_atwin, g_nodata_nearwin;
#define MIN64(a,b) ((a) < (b) ? (a) : (b))
static uint64_t g_ring_hist[8], g_ring_empty_by[3];
static uint64_t g_gap_full, g_gap_full_dt, g_gap_all, g_gap_all_dt;
static uint32_t g_sws_rw;
static uint64_t g_sws_cwnd, g_sws_peer, g_sws_infl, g_sws_bind[2];
static uint64_t g_sws_cwnd_h[6], g_sws_peer_h[6];
static uint64_t g_sws_withheld, g_sws_n, g_sws_max;
static uint64_t g_age_hist[8], g_age_time, g_age_dt, g_age_max, g_age_max_at;
static unsigned g_age_max_flow;	/* byte-microseconds, emitted and unacked */
static uint64_t g_inf_hist[8];	/* flow-microseconds by unacknowledged bytes */
static uint64_t g_recv_calls, g_recv_bytes, g_recv_empty, g_recv_nohead;

/*
 * TIME-AVERAGED in-flight, so Little's law can be checked as an identity.
 *
 * The census above samples at the generation decision, which happens when there
 * is data to send and therefore catches in-flight at its high points -- biased
 * by construction, in the direction that made rate x RTT overshoot by 4x. This
 * integrates in-flight against the clock instead: sum(bytes x microseconds),
 * divided at the end by the elapsed microseconds it covers.
 *
 * Sampled every 1024th stack iteration rather than every one. At ~25M
 * iterations a second that is still ~24k samples a second, the weighting makes
 * the interval irrelevant to the mean, and it keeps the cost off a loop where
 * instrumentation has twice become the measurement.
 */
static struct tcp_ctx *g_live[MTP_MAX_FLOWS_SAMPLED];
static unsigned g_live_n;
static uint64_t g_inf_integral, g_inf_span_us, g_inf_last_us, g_inf_samples;
/*
 * Live-context census. Two questions: is the count STEADY or GROWING -- a
 * lifecycle characteristic against a leak in the destroy path reworked this
 * week -- and what the correct denominator is for per-flow in-flight, which is
 * the time-weighted mean live count and not the configured concurrency.
 */
static uint64_t g_live_integral, g_live_max, g_ctx_created, g_ctx_destroyed;
static uint64_t g_stage_occ[ST__N];	/* byte-microseconds... flow-microseconds */
static uint64_t g_stage_enter[ST__N];	/* how many times each stage began */
static uint32_t g_live_series[12];	/* live count in each 5 s of the run */
static uint64_t g_first_us;
static uint64_t g_avail_sum, g_avail_max, g_bind_cwnd, g_bind_peer;

/*
 * THE RECEIVE PATH, STAGE BY STAGE — the same instrument pointed the other way.
 *
 * A refusal reason inside proc_ack only answers "reached it and was rejected".
 * If packets are lost BEFORE dispatch no reason appears at all, and an absence
 * is not an answer — so each stage is counted, and the stage where the count
 * drops is the stage at fault.
 *
 * ACK_DUP is the one to watch: if the peer's acknowledgements are being read as
 * duplicates, send_una cannot advance BY CONSTRUCTION, and the send side's
 * sws-holdoff is then a correct response to a window we are keeping shut
 * ourselves.
 */
enum { TMR_RTO, TMR_TIMEWAIT, TMR_PROBE, TMR_IDLE, TMR__N };
static uint64_t g_tmr[TMR__N];

enum { RXS_DISPATCH, RXS_CTX, RXS_ACK_CALLED, RXS_ACK_NOFLAG, RXS_ACK_DUP,
       RXS_ACK_ADVANCED, RXS_RST, RXS_ACK_PAST_NEXT, RXS_BACKLOG_FULL,
       RXS_PAWS_NOTS, RXS_PAWS_OLD, RXS_SEQ_BAD, RXS_FAST_RTX,
       RXS_DUP_INFLATE, RXS_RST_HANDLED, RXS__N };
static uint64_t g_rx[RXS__N];

static void
prog_unregister(const struct tcp_ctx *c)
{
	unsigned i;

	for (i = 0; i < g_live_n; i++)
		if (g_live[i] == c) {
			g_live[i] = g_live[--g_live_n];
			g_ctx_destroyed++;
			return;
		}
}

/* Called by the stack loop, every 1024th iteration. */
void
prog_sample_inflight(uint64_t now_us)
{
	uint64_t inflight = 0;
	unsigned i;

	if (g_inf_last_us) {
		uint64_t dt = now_us - g_inf_last_us;

		for (i = 0; i < g_live_n; i++) {
			struct tcp_ctx *c = g_live[i];

			{
				/*
				 * PER-FLOW DISTRIBUTION, time-weighted. A mean
				 * cannot say whether we sit at a ceiling or
				 * average one, and "how much do we hold
				 * unacknowledged" is only a limiter if it is
				 * pinned rather than merely low.
				 */
				uint64_t q = (uint64_t)(c->send_next
						        - c->send_una);
				unsigned b = 0;

				while (b < 7 && q >= (16384ull << b))
					b++;
				INSTR(g_inf_hist[b] += dt);
			}
			inflight += (uint64_t)(c->send_next - c->send_una);

			/*
			 * EMITTED-unacknowledged, alongside GENERATED-
			 * unacknowledged above. This is the aggregate that
			 * measures exactly what the emission-to-ACK probe
			 * samples, so Little's law over it and the probe's mean
			 * become directly comparable with the definitional
			 * difference -- blueprints generated but not yet on the
			 * wire -- removed.
			 *
			 * UNITS: emitted_hwm is unit-relative; send_una and
			 * snd_base are absolute, so the acknowledged position
			 * is brought into unit space before subtracting.
			 */
			{
				uint64_t acked = (uint64_t)(c->send_una
							    - c->snd_base);
				uint64_t emit = mtp_tx_emitted(&c->tx);

				{
					/*
					 * RING OCCUPANCY, time-weighted. The
					 * contradiction this tests: the ring
					 * refuses 16% of writes and is empty at
					 * 24.6% of generation decisions. Those
					 * cannot both describe a steady level.
					 */
					uint64_t held = c->tx.tail_seq
						      - c->tx.head_seq;
					unsigned rb;

					if (!held) {
						rb = 0;
						INSTR(g_ring_empty_by[
						  mtp_app_state_read() % 3] += dt);
					} else if (held >= c->tx.cap) {
						rb = 7;
						/*
						 * THE GAP, CONDITIONED ON THE
						 * FULL PHASE. A time-average of
						 * generated-minus-emitted over
						 * the whole run would hide a
						 * sharp divergence confined to
						 * exactly the periods when the
						 * ring is full -- which is when
						 * generation can run ahead of
						 * emission at all.
						 */
						INSTR(g_gap_full += (uint64_t)
						  (c->send_next - c->send_una
						   - MIN64(c->send_next
							   - c->send_una,
							   mtp_tx_emitted(&c->tx)
							   - (c->send_una
							      - c->snd_base)))
						  * dt);
						INSTR(g_gap_full_dt += dt);
					} else {
						rb = 1 + (unsigned)((held * 6)
								    / c->tx.cap);
					}
					INSTR(g_ring_hist[rb] += dt);
					{
						uint64_t gen = c->send_next
							     - c->send_una;
						uint64_t em = mtp_tx_emitted(&c->tx)
							    - (c->send_una
							       - c->snd_base);

						INSTR(g_gap_all += (gen - MIN64(gen, em))
							     * dt);
						INSTR(g_gap_all_dt += dt);
					}
				}

				if (emit > acked) {
					uint64_t age, a;
					unsigned b;

					INSTR(g_emit_unacked += (emit - acked) * dt);
					if (c->in_rtx)
						INSTR(g_int_rtx += (emit - acked) * dt);
					else
						INSTR(g_int_clean += (emit - acked) * dt);

					/*
					 * THE TAIL. Time-sampled, so a stuck
					 * flow is counted for every tick it
					 * stays stuck rather than contributing
					 * one late sample when it finally
					 * moves.
					 */
					if (!c->una_advanced_us)
						c->una_advanced_us = now_us;
					age = now_us - c->una_advanced_us;
					for (b = 0, a = 100; b < 7 && age >= a;
					     b++, a *= 5)
						;
					INSTR(g_age_hist[b] += dt);
					INSTR(g_age_time += age * dt);
					INSTR(g_age_dt += dt);
					if (age > g_age_max) {
						g_age_max = age;
						g_age_max_flow = i;
						g_age_max_at = now_us;
					}
				}
			}

			/*
			 * Generated-to-emitted is the target's to observe, and
			 * it is observed here rather than pushed from the emit
			 * path: a hook on every segment would be an instrument
			 * on the hot path, which is what this project has been
			 * burned by three times. The occupancy is unaffected --
			 * the stage is credited for whatever time it was in.
			 */
			/*
			 * UNITS. emitted_hwm is an offset INTO THE UNIT --
			 * pay.off is `send_next - snd_base` -- while stage_seq
			 * is an absolute sequence. Comparing them directly was
			 * false for every object after the first, which parked
			 * every flow in this stage for ever and reported 99.8%
			 * occupancy that was entirely the bug.
			 */
			/* ARM ON THE CLOCK, not on the last probe closing.
			 * Switchable so the aggregate can be re-taken with
			 * the emit-path stamp inert, in ONE binary. */
			if (!MTP_ENV_ON("MTP_NO_ACKPROBE")
			    && !c->tx.probe_wanted && !c->tx.probe_pending)
				c->tx.probe_wanted = 1;

			if (c->stage == ST_AWAIT_EMIT
			    && mtp_tx_emitted(&c->tx) + c->snd_base
			       >= c->stage_seq) {
				c->stage = ST_AWAIT_ACK;
				g_stage_enter[ST_AWAIT_ACK]++;
			}
			g_stage_occ[c->stage] += dt;
		}
		g_inf_integral += inflight * dt;
		g_live_integral += (uint64_t)g_live_n * dt;
		g_inf_span_us += dt;
		g_inf_samples++;
		if (g_live_n > g_live_max)
			g_live_max = g_live_n;
		{
			uint64_t slot = (now_us - g_first_us) / 5000000u;

			if (slot < 12)
				g_live_series[slot] = g_live_n;
		}
	}
	if (!g_first_us)
		g_first_us = now_us;
	g_inf_last_us = now_us;
}

void
prog_report_stages(void)
{
	static const char *n[ST__N] = { "idle (nothing to send)",
					"awaiting the send decision",
					"awaiting emission (drain)",
					"awaiting the acknowledgement" };
	uint64_t busy = g_stage_occ[ST_AWAIT_DECISION] + g_stage_occ[ST_AWAIT_EMIT]
		      + g_stage_occ[ST_AWAIT_ACK];
	int i;

	fprintf(stderr, "send-loop occupancy, flow-microseconds, time-weighted "
		"(busy total %llu):\n", (unsigned long long)busy);
	for (i = 0; i < ST__N; i++)
		fprintf(stderr, "  %-30s %14llu  %5.1f%% of busy   entered %llu\n",
			n[i], (unsigned long long)g_stage_occ[i],
			busy ? 100.0 * (double)g_stage_occ[i] / (double)busy : 0.0,
			(unsigned long long)g_stage_enter[i]);
}

void
prog_report_inflight(void)
{
	uint64_t mean = g_inf_span_us ? g_inf_integral / g_inf_span_us : 0;

	uint64_t live_x100 = g_inf_span_us
			   ? (g_live_integral * 100) / g_inf_span_us : 0;
	int i;

	{
		static const char *n[8] = { "<100us", "<500us", "<2.5ms",
					    "<12.5ms", "<62ms", "<312ms",
					    "<1.6s", ">=1.6s" };
		uint64_t tot = 0;
		int k;

		for (k = 0; k < 8; k++)
			tot += g_age_hist[k];
		{
		static const char *n[8] = { "EMPTY", "<1/6", "<2/6", "<3/6",
					    "<4/6", "<5/6", "<6/6", "FULL" };
		static const char *w[3] = { "running", "in a write", "waiting" };
		uint64_t tot = 0, et = 0;
		int k;

		for (k = 0; k < 8; k++)
			tot += g_ring_hist[k];
		for (k = 0; k < 3; k++)
			et += g_ring_empty_by[k];
		fprintf(stderr, "generated-minus-emitted, time-weighted: all %llu B, "
		"WHILE THE RING IS FULL %llu B\n",
		(unsigned long long)(g_gap_all_dt ? g_gap_all / g_gap_all_dt : 0),
		(unsigned long long)(g_gap_full_dt ? g_gap_full / g_gap_full_dt : 0));
	fprintf(stderr, "TRANSMIT RING occupancy, time-weighted:\n");
		for (k = 0; k < 8; k++)
			fprintf(stderr, "  %-6s %5.1f%%\n", n[k],
				tot ? 100.0 * (double)g_ring_hist[k] / (double)tot : 0.0);
		fprintf(stderr, "  when EMPTY the application was:");
		for (k = 0; k < 3; k++)
			fprintf(stderr, " %s %.1f%%", w[k],
				et ? 100.0 * (double)g_ring_empty_by[k] / (double)et : 0.0);
		fprintf(stderr, "\n");
	}
	{
		static const char *n[7] = { "<4K", "<16K", "<64K", "<256K",
					    "<1M", "<4M", ">=4M" };
		int k;

		fprintf(stderr, "AT 'nothing buffered': %llu decisions, mean "
			"ring held %llu B\n  held:",
			(unsigned long long)g_nodata_n,
			(unsigned long long)(g_nodata_n ? g_nodata_held_sum / g_nodata_n : 0));
		for (k = 0; k < 7; k++)
			fprintf(stderr, " %s %.1f%%", n[k],
				g_nodata_n ? 100.0 * (double)g_nodata_held[k] / (double)g_nodata_n : 0.0);
		fprintf(stderr, "\n");
		fprintf(stderr, "  at that exit: mean in flight %llu B, mean "
			"cwnd %llu B, mean peer %llu B; AT the window %llu "
			"(%.1f%%), within one MSS %llu (%.1f%%)\n",
			(unsigned long long)(g_nodata_n ? g_nodata_infl / g_nodata_n : 0),
			(unsigned long long)(g_nodata_n ? g_nodata_cwnd / g_nodata_n : 0),
			(unsigned long long)(g_nodata_n ? g_nodata_peer / g_nodata_n : 0),
			(unsigned long long)g_nodata_atwin,
			g_nodata_n ? 100.0 * (double)g_nodata_atwin / (double)g_nodata_n : 0.0,
			(unsigned long long)g_nodata_nearwin,
			g_nodata_n ? 100.0 * (double)g_nodata_nearwin / (double)g_nodata_n : 0.0);
	}
	fprintf(stderr, "SWS hold-off: %llu deferrals, mean withheld %llu B, "
		"max %llu B\n", (unsigned long long)g_sws_n,
		(unsigned long long)(g_sws_n ? g_sws_withheld / g_sws_n : 0),
		(unsigned long long)g_sws_max);
	{
		uint64_t t = g_sws_bind[0] + g_sws_bind[1];
		static const char *e[6] = { "<4K", "<16K", "<64K", "<256K",
					    "<1M", ">=1M" };
		int k;

		fprintf(stderr, "  AT THOSE DECISIONS: mean cwnd %llu, mean "
			"peer window %llu, mean inflight %llu; binding arm "
			"cwnd %llu / peer %llu\n",
			(unsigned long long)(t ? g_sws_cwnd / t : 0),
			(unsigned long long)(t ? g_sws_peer / t : 0),
			(unsigned long long)(t ? g_sws_infl / t : 0),
			(unsigned long long)g_sws_bind[0],
			(unsigned long long)g_sws_bind[1]);
		fprintf(stderr, "  cwnd:");
		for (k = 0; k < 6; k++)
			fprintf(stderr, " %s %.1f%%", e[k],
				t ? 100.0 * (double)g_sws_cwnd_h[k] / (double)t : 0.0);
		fprintf(stderr, "\n  peer:");
		for (k = 0; k < 6; k++)
			fprintf(stderr, " %s %.1f%%", e[k],
				t ? 100.0 * (double)g_sws_peer_h[k] / (double)t : 0.0);
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "AGE of the oldest unacknowledged byte, "
			"time-sampled (mean %llu us, max %llu us on flow %u "
			"at t=%llu):\n",
			(unsigned long long)(g_age_dt ? g_age_time / g_age_dt : 0),
			(unsigned long long)g_age_max, g_age_max_flow,
			(unsigned long long)g_age_max_at);
		for (k = 0; k < 8; k++)
			fprintf(stderr, "  %-8s %5.1f%% of stuck-flow time\n",
				n[k], tot ? 100.0 * (double)g_age_hist[k] / (double)tot : 0.0);
	}
	fprintf(stderr,
		"LOOP SPLIT by whether the flow was in loss recovery:\n"
		"  clean : integral %llu B.us / %llu B  -> W = %llu us  (%.2f%% of bytes)\n"
		"  in rtx: integral %llu B.us / %llu B  -> W = %llu us  (%.2f%% of bytes)\n"
		"  RTO in use: mean %llu ms, max %llu ms over %llu samples\n",
		(unsigned long long)g_int_clean, (unsigned long long)g_bytes_clean,
		(unsigned long long)(g_bytes_clean ? g_int_clean / g_bytes_clean : 0),
		100.0 * (double)g_bytes_clean / (double)(g_bytes_clean + g_bytes_rtx + 1),
		(unsigned long long)g_int_rtx, (unsigned long long)g_bytes_rtx,
		(unsigned long long)(g_bytes_rtx ? g_int_rtx / g_bytes_rtx : 0),
		100.0 * (double)g_bytes_rtx / (double)(g_bytes_clean + g_bytes_rtx + 1),
		(unsigned long long)(g_rto_n ? g_rto_sum / g_rto_n : 0),
		(unsigned long long)g_rto_max, (unsigned long long)g_rto_n);
	fprintf(stderr,
		"time-averaged EMITTED-unacked: %llu B across all flows -- "
		"Little's law over exactly what the emission probe samples\n",
		(unsigned long long)(g_inf_span_us
				     ? g_emit_unacked / g_inf_span_us : 0));
	fprintf(stderr,
		"time-averaged in flight: %llu B across all flows over %llu us "
		"(%llu samples)\n"
		"  live contexts: time-weighted mean %llu.%02llu, max %llu, "
		"at exit %u; created %llu, destroyed %llu, outstanding %lld\n"
		"  per-flow in flight at the MEASURED mean live count: %llu B\n"
		"  live count per 5 s:",
		(unsigned long long)mean,
		(unsigned long long)g_inf_span_us,
		(unsigned long long)g_inf_samples,
		(unsigned long long)(live_x100 / 100),
		(unsigned long long)(live_x100 % 100),
		(unsigned long long)g_live_max, g_live_n,
		(unsigned long long)g_ctx_created,
		(unsigned long long)g_ctx_destroyed,
		(long long)g_ctx_created - (long long)g_ctx_destroyed,
		(unsigned long long)(live_x100 ? mean * 100 / live_x100 : 0));
	for (i = 0; i < 12; i++)
		fprintf(stderr, " %u", g_live_series[i]);
	fprintf(stderr, "\n");
}

void
prog_report_recv(void)
{
	unsigned i, stuck = 0;
	uint64_t unread = 0;

	/* Which flows are PERMANENTLY readable: the level-triggered re-arm
	 * fires while tail exceeds head, so any flow left in that state is
	 * re-presented on every poll for the rest of its life. */
	for (i = 0; i < g_live_n; i++)
		if (g_live[i]->rx.tail_seq > g_live[i]->rx.head_seq) {
			stuck++;
			unread += g_live[i]->rx.tail_seq - g_live[i]->rx.head_seq;
		}
	{
		static const char *n[8] = { "<16K", "16-32K", "32-64K",
					    "64-128K", "128-256K", "256-512K",
					    "512K-1M", ">=1M" };
		uint64_t tot = 0;
		int k;

		for (k = 0; k < 8; k++)
			tot += g_inf_hist[k];
		fprintf(stderr, "unacknowledged per flow, time-weighted:\n");
		for (k = 0; k < 8; k++)
			fprintf(stderr, "  %-9s %5.1f%%\n", n[k],
				tot ? 100.0 * (double)g_inf_hist[k] / (double)tot : 0.0);
	}
	fprintf(stderr, "  live flows with unread bytes: %u of %u, %llu bytes "
		"total\n", stuck, g_live_n, (unsigned long long)unread);
	fprintf(stderr, "app RECV: %llu calls, %llu bytes, %llu returned "
		"nothing, %llu left head_seq unmoved\n",
		(unsigned long long)g_recv_calls,
		(unsigned long long)g_recv_bytes,
		(unsigned long long)g_recv_empty,
		(unsigned long long)g_recv_nohead);
}

void
prog_report_acklat(void)
{
	static const char *n[8] = { "< 50 us", "< 100 us", "< 250 us",
				    "< 500 us", "< 1 ms", "< 2.5 ms",
				    "< 10 ms", ">= 10 ms" };
	int i;

	fprintf(stderr, "EMISSION -> covering ACK (clock-armed; bias REDUCED, not removed): "
		"%llu samples, mean %llu us, max %llu us\n",
		(unsigned long long)g_ack_n,
		(unsigned long long)(g_ack_n ? g_ack_sum / g_ack_n : 0),
		(unsigned long long)g_ack_max);
	for (i = 0; i < 8; i++)
		fprintf(stderr, "  %-9s %10llu  %5.1f%%\n", n[i],
			(unsigned long long)g_ack_hist[i],
			g_ack_n ? 100.0 * (double)g_ack_hist[i] / (double)g_ack_n : 0.0);
}

void
prog_report_rtt(void)
{
	static const char *n[6] = { "< 200 us", "< 1 ms  ", "< 5 ms  ",
				    "< 20 ms ", "< 50 ms ", ">= 50 ms" };
	int i;

	fprintf(stderr, "effective round trip (generation -> covering ACK): "
		"%llu samples, mean %llu us, max %llu us\n",
		(unsigned long long)g_rtt_n,
		(unsigned long long)(g_rtt_n ? g_rtt_sum / g_rtt_n : 0),
		(unsigned long long)g_rtt_max);
	for (i = 0; i < 6; i++)
		fprintf(stderr, "  %s %10llu  %5.1f%%\n", n[i],
			(unsigned long long)g_rtt_bucket[i],
			g_rtt_n ? 100.0 * (double)g_rtt_bucket[i] / (double)g_rtt_n : 0.0);
}

void
prog_report_avail(void)
{
	static const char *n[6] = { "avail <= 0        (window-limited)",
				    "avail < 1 MSS     ",
				    "avail < 4 MSS     ",
				    "avail < 16 MSS    ",
				    "avail < 64 MSS    ",
				    "avail >= 64 MSS   (decision-limited)" };
	uint64_t tot = 0;
	int i;

	for (i = 0; i < 6; i++)
		tot += g_avail_bucket[i];
	fprintf(stderr, "send-window census: %llu generation decisions\n",
		(unsigned long long)tot);
	for (i = 0; i < 6; i++)
		fprintf(stderr, "  %s %10llu  %5.1f%%\n", n[i],
			(unsigned long long)g_avail_bucket[i],
			tot ? 100.0 * (double)g_avail_bucket[i] / (double)tot : 0.0);
	fprintf(stderr,
		"  BYTES:  mean cwnd %llu, mean in flight %llu, mean available "
		"%llu, max available %llu\n"
		"  COUNTS: decisions where cwnd bound %llu, where the peer's "
		"window bound %llu\n",
		(unsigned long long)(tot ? g_cwnd_sum / tot : 0),
		(unsigned long long)(tot ? g_inflight_sum / tot : 0),
		(unsigned long long)(tot ? g_avail_sum / tot : 0),
		(unsigned long long)g_avail_max,
		(unsigned long long)g_bind_cwnd,
		(unsigned long long)g_bind_peer);
}

void
prog_report_refusals(void)
{
	static const char *n[REF__N] = { "state-gate", "window-closed",
					 "sws-holdoff", "nothing-buffered",
					 "SENT" };
	/*
	 * ONE NAME PER COUNTER, and the array is sized by the enum so a missing
	 * one is a compile error rather than a NULL passed to %s. It was short
	 * by four: RXS_BACKLOG_FULL and the three validation counters were added
	 * without extending it, and C zero-fills the rest.
	 */
	static const char *r[RXS__N] = { "reached dispatch", "flow ctx found",
					 "proc_ack called", "  no ACK flag",
					 "  DUPLICATE/STALE", "  ADVANCED una",
					 "INBOUND RST (discarded)",
					 "ack past send_next",
					 "SYN dropped, backlog full",
					 "PAWS: no timestamp",
					 "PAWS: timestamp went back",
					 "outside the receive window",
					 "FAST RETRANSMIT (3rd duplicate)",
					 "  4th+ duplicate: inflate only",
					 "INBOUND RST (handled)" };
	/* A name for every counter, checked at compile time rather than by
	 * whoever next adds one. */
	_Static_assert(sizeof(r) / sizeof(r[0]) == RXS__N,
		       "recv-path counter names are out of step with the enum");
	int i;

	for (i = 0; i < REF__N; i++)
		fprintf(stderr, "send decision %-17s %llu\n", n[i],
			(unsigned long long)g_refuse[i]);
	{
		static const char *en[EM__N] = { "SYN-ACK", "ack of data",
						 "ack of FIN", "window probe",
						 "reply to their probe",
						 "our FIN", "data (first send)",
						 "data (retransmission)" };
		int j;

		for (j = 0; j < EM__N; j++)
			fprintf(stderr, "emitted      %-21s %llu\n", en[j],
				(unsigned long long)g_emit[j]);
	}
	{
		/*
		 * SPLIT BY KIND, because "timers fired" aggregates mechanisms
		 * and the fingerprint recorded 0 when the wheel held only the
		 * retransmission timeout. TIME_WAIT and the probe now share
		 * that counter, so the same digits mean different things
		 * before and after D-24 — the 2047 problem again, in a counter
		 * rather than a window value.
		 */
		static const char *tn[TMR__N] = { "retransmission", "TIME_WAIT",
						  "window-probe", "connection idle" };
		/* One name per timer, checked rather than remembered. */
		_Static_assert(sizeof(tn) / sizeof(tn[0]) == TMR__N,
			       "timer names are out of step with the enum");
		int j;

		for (j = 0; j < TMR__N; j++)
			fprintf(stderr, "timer fired  %-17s %llu\n", tn[j],
				(unsigned long long)g_tmr[j]);
	}
	fprintf(stderr, "app bytes accepted %llu  (SYN-ACKs %llu -> %.0f bytes/connection,"
		" object is 1048721)\n",
		(unsigned long long)g_app_bytes,
		(unsigned long long)g_emit[EM_SYNACK],
		g_emit[EM_SYNACK] ? (double)g_app_bytes / g_emit[EM_SYNACK] : 0.0);
	for (i = 0; i < RXS__N; i++)
		fprintf(stderr, "recv path     %-17s %llu\n", r[i],
			(unsigned long long)g_rx[i]);
}

static void send_window_probe(struct tcp_ctx *c, uint32_t now);

static bool
send_side_open(const struct tcp_ctx *c)
{
	return c->state == TCP_ESTABLISHED || c->state == TCP_CLOSE_WAIT;
}

/*
 * Our receive path is open. Not the mirror of send_side_open: after WE close,
 * the peer has not, and its data keeps arriving and keeps needing
 * acknowledgement (D-20, per-path — the same rule from the other side).
 */
static bool
recv_side_open(const struct tcp_ctx *c)
{
	return c->state == TCP_ESTABLISHED ||
	       c->state == TCP_FIN_WAIT_1 ||
	       c->state == TCP_FIN_WAIT_2;
}

/*
 * THE THIRD ROW, and the one symmetry would miss (DESIGN-CLOSE.md §3).
 *
 * An acknowledgement of our own sequence space must be processed in states
 * where NEITHER direction is open — FIN_WAIT_1 and CLOSING exist precisely to
 * wait for the acknowledgement of our FIN, so gating proc_ack on
 * send_side_open() would make it impossible to ever leave them. That is this
 * bug reproduced in a new state, which is why this is a table of three and not
 * a pair of predicates.
 */
static bool
conn_exists(const struct tcp_ctx *c)
{
	return c->state != TCP_CLOSED && c->state != TCP_LISTEN &&
	       c->state != TCP_SYN_RCVD;
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

	/*
	 * D9: READABLE ON THE LISTENING CONTEXT, which is what makes accept()
	 * return. We were raising a STATE notification on the CONNECTION, which
	 * is neither what the donor does nor something an accepting application
	 * can act on -- the donor enqueues the stream on the accept queue
	 * (tcp_in.c:884) and raises EPOLLIN on the listening socket (:898-900).
	 */
	/*
	 * A RUNTIME TOGGLE, so both arms of the comparison come from ONE binary
	 * -- the pattern this tree already uses for MTP_RTO_ARM_ON_GENERATION,
	 * and for the same reason: the two arms must differ in nothing but this,
	 * not in build, not in staging, not in session.
	 *
	 * MTP_LEGACY_OPEN_NOTIFY restores the old behaviour -- a STATE
	 * notification on the CONNECTION, no queue, no listener event. It exists
	 * because moving to the donor's channel coincided with an 8.7x change in
	 * completions at c=1 that nothing in the counters explains, and an
	 * unexplained factor of eight is not something to build on.
	 */
	{
		static int legacy = -1;

		if (legacy < 0)
			legacy = MTP_ENV_ON("MTP_LEGACY_OPEN_NOTIFY") ? 1 : 0;
		if (legacy) {
			mtp_notify(c->f, &(struct mtp_notif){
					.kind = MTP_NOTIF_STATE });
		} else if (c->lst && c->lst->pending_n < PROG_MAX_BACKLOG) {
			c->lst->pending[c->lst->pending_n++] = c->f;
			mtp_notify(c->lst->f, &(struct mtp_notif){
					.kind = MTP_NOTIF_READABLE });
		}
	}

	/* the application posted an object before listening; serve it */
	if (c->lst && c->lst->obj_len) {
		struct mtp_tx_addr addr;
		int wrote;

		/*
		 * CR-E: buffer, then hand over the EXTENT -- the same two steps
		 * the application thread takes, except that this path already
		 * runs on the stack thread, so it does both itself.
		 */
		addr.base = c->lst->obj;
		addr.len = c->lst->obj_len;
		wrote = mtp_add_tx_data(&c->tx, addr, c->lst->obj_len);
		if (wrote > 0)
			tcp_app_send(c, (uint32_t)wrote, now);
		c->app_closed = true;	/* a one-shot server has said all it will */
	}
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
/*
 * Is there data ON THE WIRE that has not been acknowledged? The only thing a
 * retransmission timer should be waiting for.
 *
 * NOT `send_una != send_next`: send_next advances at GENERATION, so that test
 * is true for a blueprint still sitting in the ring. Arming on it lets the
 * timer expire against data that never went out, and the expiry rewinds
 * send_next and regenerates -- producing a retransmission for a range a live
 * blueprint is still carrying, whose reference can then never drain.
 *
 * That is the reading this change exists to test, and it is changed ALONE so
 * the test means something: if the overlapping new-x-RTX pairs vanish, the
 * mechanism is established; if they persist, the reading is wrong and the
 * remaining sites are correctness work rather than the fix.
 */
static bool
unacked_on_wire(const struct tcp_ctx *c)
{
	uint64_t acked = (uint64_t)(c->send_una - c->snd_base);
	static int on_generation = -1;

	/*
	 * A RUNTIME TOGGLE, so both arms of the comparison come from ONE
	 * binary. The overlap rate is 3-5 events per minute and the crash rate
	 * has been shown to move on identical code, so the two arms must differ
	 * in nothing but this -- not in build, not in staging, not in session.
	 * MTP_RTO_ARM_ON_GENERATION restores the old behaviour.
	 */
	if (on_generation < 0)
		on_generation = MTP_ENV_ON("MTP_RTO_ARM_ON_GENERATION") ? 1 : 0;
	if (on_generation)
		return c->send_una != c->send_next;	/* generated */

	if (c->tx_open && mtp_tx_emitted(&c->tx) > acked)
		return true;

	/*
	 * THE FIN. Wire-based means "emitted payload beyond what is
	 * acknowledged", and a FIN emits no payload -- so once the data is all
	 * acknowledged this test went false, the timer was stopped, and a lost
	 * FIN was never retransmitted. The generation-based arm returned
	 * send_una != send_next and happened to cover it; switching to the wire
	 * dropped the FIN from retransmission protection without anything
	 * saying so.
	 */
	return c->fin_pending && c->send_una != c->send_next;
}

static void
arm_rto(struct tcp_ctx *c)
{
	/*
	 * A SEPARATE FLAG, not `rto_ms != 0`. The donor has no floor, so an
	 * estimate of zero is legal and common on a link whose round trip is
	 * far below the tick — and testing the value treats that legal zero as
	 * "no estimate yet" and falls back to 500 ms for ever. The estimator
	 * then works perfectly and changes nothing, which is what happened.
	 */
	uint32_t base = c->have_rtt ? c->rto_ms : PARITY_INITIAL_RTO_MS;

	c->rto.ctx = c;
	/* backoff is `base << MIN(nrtx, 7)`, and the base is RECOMPUTED from
	 * the estimator rather than the previous value doubled */
	mtp_timer_start(&c->rto, (uint64_t)base * 1000000ULL
			<< (c->rtx_count < 7 ? c->rtx_count : 7));
}

/*
 * The round-trip estimator, from the donor: rto = (srtt >> 3) + rttvar, with
 * srtt held scaled by eight. NO FLOOR AND NO CEILING — reproduce, do not
 * correct.
 *
 * The sample comes from the timestamp the peer echoes, which is why this
 * program sends timestamps on every segment. PARITY_INITIAL_RTO_MS applies
 * ONLY until the first sample: the earlier code armed with it on every arm and
 * never estimated, so a loss cost 500 ms where the donor takes about 3 — a
 * factor of 150, invisible on any link that loses nothing.
 */
static void
estimate_rtt(struct tcp_ctx *c, uint32_t now, uint32_t ts_ecr)
{
	uint32_t m;


	if (!ts_ecr)
		return;
	m = now - ts_ecr;		/* in 1 ms ticks */

	/*
	 * A SAMPLE OF AT LEAST ONE TICK, which is what the donor's recorded
	 * state says it takes. differences.md §1.1 has the donor sitting at
	 * srtt = 8, rttvar = 2 — and those are exactly this function's
	 * first-sample initialisation (m << 3, m << 1) with m = 1, not m = 0.
	 * The round trip here is at most 0.229 ms, so a same-tick echo gives
	 * m = 0, srtt = 0, rttvar = 0 and a timeout of 0 that the wheel floors
	 * at one tick — a THIRD of the donor's three, and we retransmit on an
	 * idle link where it does not.
	 *
	 * This is a floor on the SAMPLE, not on the RTO. The RTO still has
	 * none, which is the property both stacks share and which we reproduce
	 * deliberately.
	 *
	 * AND IT IS THE DONOR'S COMPLETE CHECK. `if (m == 0) m = 1;` is all it
	 * does — no bound, no ahead-of-clock test, no Karn's rule. B simulated
	 * an echo five ticks ahead and the donor produces an RTO of about 149
	 * hours with its own assert passing, because `long m = mrtt` widens a
	 * wrapped uint32 to a large POSITIVE long and a sign check never fires.
	 * So we add no validation the donor lacks; the wheel's refusal is where
	 * an impossible interval is caught, and that is a recorded divergence.
	 *
	 * The donor's srtt is scaled by eight, which is why the timeout is
	 * (srtt >> 3) + rttvar: one tick from the smoothed term plus two from
	 * the variance term. `srtt = 8` is not eight milliseconds, and an
	 * estimator that computed "the same thing" directly in milliseconds
	 * would be simpler than the original — which is the tell.
	 */
	if (m == 0)
		m = 1;

	/*
	 * THE DONOR'S RECURRENCE, WITH ITS TRUNCATIONS. Not a corrected
	 * estimator that computes "the same thing" — B compiled the donor's and
	 * simulated it rather than reasoning about it (D-21), and the
	 * truncations are the behaviour.
	 *
	 * With m == 1, which is what this testbed always produces: srtt = 8,
	 * mdev = 2, RTO = 3 ticks, and it does NOT move — over 200 samples,
	 * first to last. rttvar cannot decay because `mdev >> 2` is 0 at
	 * mdev = 2, so mdev never decreases.
	 *
	 * AND NOTE THE FORM, because the next reader will think `mdev` is an
	 * idiosyncratic way of writing the textbook one and simplify it:
	 *
	 *     textbook   rttvar += (|err| - rttvar) >> 2     decays
	 *     donor      mdev   += |err| - (mdev >> 2)       pinned
	 *
	 * Same intent, same shape, opposite behaviour, and neither is wrong on
	 * its own terms. The textbook form is what you get from knowing how a
	 * retransmission timer is supposed to work — which is exactly what rule
	 * 1 forbids: parameter values are part of behaviour and come from the
	 * donor's running code, not from a standard or from memory. Reading
	 * either would not have found this; only running both did.
	 *
	 * THE RATCHET IS THE POINT. One 2-tick sample — jitter, a delayed
	 * acknowledgement — takes srtt to 9 and mdev to 3 and the timeout to 4
	 * ticks PERMANENTLY, still 4 after 350 clean samples. At these
	 * magnitudes the donor's timeout is monotonically non-decreasing. An
	 * estimator that decays properly sits at 3 where the donor sits at 4,
	 * and timers then fire at different moments. My previous version
	 * decayed: `rttvar += (|err| - rttvar) >> 2` reaches -1 per sample at
	 * rttvar = 2 and walks the timeout down.
	 */
	if (!c->srtt) {
		c->srtt = m << 3;
		c->mdev = m << 1;
	} else {
		int32_t d = (int32_t)m - (int32_t)(c->srtt >> 3);

		c->srtt = (uint32_t)((int32_t)c->srtt + d);
		if (d < 0) {
			d = -d;
			d -= (int32_t)(c->mdev >> 2);
			if (d > 0)
				d >>= 3;
		} else {
			d -= (int32_t)(c->mdev >> 2);
		}
		c->mdev = (uint32_t)((int32_t)c->mdev + d);
	}
	c->rttvar = c->mdev;

	c->rto_ms = (c->srtt >> 3) + c->rttvar;
	c->have_rtt = true;
}

/*----------------------------------------------------------------------------*/
/*
 * THE ACKNOWLEDGEMENT CHAIN — one processor per responsibility.
 *
 *   tcp_ack -> { proc_timestamp, proc_open_done, proc_rtt, proc_fast_retransmit,
 *                proc_congestion, proc_ack, gen_seg, gen_fin }
 *
 * docs/events/EVENT-ACK.md §1, following the paper's decomposition of the same
 * chain. THE SPLIT IS NOT COSMETIC: it puts each mechanism where its ABSENCE is
 * visible. `proc_fast_retransmit` is a processor with no body rather than a
 * branch nobody wrote inside a larger one.
 *
 * EVERY PROCESSOR GUARDS ITSELF. The dispatch decides which chain runs, never
 * which link of it does — so a processor reached by two events (proc_ack is
 * reached by tcp_ack, tcp_data and tcp_fin) needs no knowledge of which one.
 *
 * `acked` is recomputed in each processor rather than threaded through the
 * scratchpad, because `proc_ack` is the only writer of `send_una` and it runs
 * last: all three read the same value.
 */

/*
 * mtp/tcp.mtp §proc_window — the peer's advertised window, RFC 793's rule.
 *
 * A SEPARATE PROCESSOR, AND AHEAD OF proc_fast_retransmit, because the donor
 * updates the window BEFORE it counts duplicates and the duplicate test asks
 * whether that update moved the right edge. Folded into proc_congestion, where
 * it used to live, the test could not be written.
 *
 * The window moves only if this segment is newer than the one that last moved
 * it, or is the same segment offering more (tcp_in.c:348-357). We assigned it
 * unconditionally on every acknowledgement, so a reordered segment carrying a
 * stale window shrank ours.
 */
static void
proc_window(struct tcp_ctx *c, const struct tcp_ev *e)
{
	uint32_t cwindow;

	if (!conn_exists(c) || !(e->flags & TCP_ACK))
		return;
	cwindow = (uint32_t)e->window << c->snd_wscale;

	/* Before the update, for the duplicate test that follows. */
	c->right_wnd_edge = c->snd_wl2 + c->send_wnd;

	if ((int32_t)(c->snd_wl1 - e->seq) < 0 ||
	    (c->snd_wl1 == e->seq && (int32_t)(c->snd_wl2 - e->ack) < 0) ||
	    (c->snd_wl2 == e->ack && cwindow > c->send_wnd)) {
		c->send_wnd = cwindow;
		c->snd_wl1 = e->seq;
		c->snd_wl2 = e->ack;
	}
}

/* mtp/tcp.mtp §proc_timestamp — record the peer's echo for our own. */
static void
proc_timestamp(struct tcp_ctx *c, const struct tcp_ev *e)
{
	if (!conn_exists(c) || !(e->flags & TCP_ACK))
		return;
	/*
	 * ONLY FOR A PEER THAT DOES NOT TIMESTAMP. For one that does,
	 * proc_validate has already set it -- before dispatch, and only for a
	 * segment it accepted, which is the donor's placement. Setting it here
	 * as well moved ts_recent on segments the donor would have rejected.
	 */
	if (!c->saw_timestamp)
		c->ts_recent = e->ts_val;
}

/*
 * mtp/tcp.mtp §proc_rtt — update the round-trip estimate.
 *
 * Guarded on the acknowledgement advancing, which is why it sits ahead of
 * proc_ack in the chain: proc_ack is what moves send_una, so this must read it
 * first.
 */
static void
proc_rtt(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	if (!conn_exists(c) || !(e->flags & TCP_ACK))
		return;
	if ((int32_t)(e->ack - c->send_una) <= 0)
		return;
	estimate_rtt(c, now, e->ts_ecr);
}

/*
 * mtp/tcp.mtp §proc_fast_retransmit — NOT IMPLEMENTED.
 *
 * `fast_retransmit` on the absence register: the donor retransmits and halves
 * its window on the THIRD duplicate acknowledgement (tcp_in.c:464) and we do
 * nothing. A rule-1 gap — the two stacks are not running the same protocol
 * until it lands.
 *
 * It is a processor with an empty body ON PURPOSE. A missing mechanism should
 * read as a missing body, not as a branch that was never written inside
 * proc_ack, because the second is invisible and the first is not.
 *
 * D-30 settles what goes here: the donor's behaviour exactly, third duplicate
 * only, INCLUDING its refusal to attempt a send on the fourth and later. That
 * change and the removal of our per-duplicate attempt in gen_seg's caller are
 * one change, and the per-iteration retry list lands before both.
 */
static void
proc_fast_retransmit(struct tcp_ctx *c, const struct tcp_ev *e,
		     struct tcp_scratch *sc, uint32_t now)
{
	bool dup = false;

	(void)now;
	if (!conn_exists(c) || !(e->flags & TCP_ACK))
		return;

	/*
	 * THE DONOR'S FIVE CONDITIONS, in its own order (tcp_in.c:373-396):
	 * the acknowledgement is old, carries no payload, leaves the window's
	 * right edge where it was, and repeats the last one seen.
	 *
	 * `snd_wl2 + send_wnd` is the right edge AFTER proc_window has run, so
	 * comparing it against the edge BEFORE is what "the window did not
	 * change" means. proc_window is ahead of this processor in the chain
	 * for exactly that reason.
	 */
	if ((int32_t)(e->ack - c->send_next) < 0 &&
	    e->ack == c->last_ack_seq && e->payload_len == 0 &&
	    c->snd_wl2 + c->send_wnd == c->right_wnd_edge) {
		c->dup_acks++;
		dup = true;
	}
	if (!dup) {
		c->dup_acks = 0;
		c->last_ack_seq = e->ack;
		return;
	}

	if (c->dup_acks == PARITY_DUP_ACK_THRESH) {
		/*
		 * THE THIRD DUPLICATE, AND ONLY THE THIRD. Rewind to what the
		 * peer is asking for, halve the window, and attempt one send.
		 * gen_seg is the next link but one and does the attempt; this
		 * processor does not generate.
		 */
		if ((int32_t)(e->ack - c->send_next) < 0)
			c->send_next = e->ack;

		c->ssthresh = (c->cwnd < c->send_wnd ? c->cwnd : c->send_wnd) / 2;
		if (c->ssthresh < 2 * PARITY_MSS_ADVERTISED)
			c->ssthresh = 2 * PARITY_MSS_ADVERTISED;
		c->cwnd = c->ssthresh + 3 * PARITY_MSS_ADVERTISED;

		if (c->rtx_count < PARITY_MAX_RTX)
			c->rtx_count++;
		INSTR(g_rx[RXS_FAST_RTX]++);
		c->in_rtx = true;
		c->rtx_mark = c->send_high;
	} else if (c->dup_acks > PARITY_DUP_ACK_THRESH) {
		/*
		 * FOURTH AND LATER: INFLATE, AND ATTEMPT NOTHING. That is the
		 * donor (tcp_in.c:466-473) and it is arguably wrong -- NewReno
		 * inflates precisely so the sender clocks out one segment per
		 * duplicate, and mTCP inflates and never attempts, so it does
		 * no packet conservation during recovery.
		 *
		 * D-30: match the donor, defect included, because parity is
		 * measured against the donor and "more correct than the donor"
		 * is a divergence like any other. REVISIT before any writeup --
		 * a reader will expect NewReno here.
		 *
		 * OUR PER-DUPLICATE SEND ATTEMPT DIES HERE. gen_seg follows in
		 * this chain and would attempt one; the flag is what stops it,
		 * and the per-iteration retry list (D3) is what took over the
		 * recovery that attempt was doing.
		 */
		if (c->cwnd + PARITY_MSS_ADVERTISED > c->cwnd)
			c->cwnd += PARITY_MSS_ADVERTISED;
		INSTR(g_rx[RXS_DUP_INFLATE]++);
		sc->no_send = true;
	} else {
		/* first and second: counted, nothing else, no attempt */
		sc->no_send = true;
	}
}

/*
 * mtp/tcp.mtp §proc_congestion — the send window and the congestion window.
 *
 * The peer's advertised window is refreshed by EVERY acknowledgement, including
 * one that advances nothing: a window reopening IS an acknowledgement that
 * advances nothing.
 */
static void
proc_congestion(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	uint32_t acked;

	(void)now;
	if (!conn_exists(c) || !(e->flags & TCP_ACK))
		return;

	/* The peer's window is proc_window's, ahead of this in the chain. */
	acked = e->ack - c->send_una;
	if ((int32_t)acked <= 0)
		return;

	/*
	 * An acknowledgement past send_next, and BOTH halves of the donor's
	 * guard — before send_una moves, which is the ordering that makes the
	 * comparison meaningful.
	 *
	 * This is the NORMAL outcome of a successful recovery, not an edge
	 * case: after a retransmission fills a hole the receiver has been
	 * holding later data out of order, so its cumulative acknowledgement
	 * jumps past everything we rewound send_next to.
	 *
	 * Both halves or neither. Taking `snd_nxt = ack_seq` alone would match
	 * the donor's sequence numbers exactly while diverging on its
	 * congestion trajectory — which is the observable rule 1 names, and
	 * which the packet count and the size histogram would both pass.
	 *
	 * IT LIVES HERE, AHEAD OF THE GROWTH, and the pair must stay in this
	 * order: `cwnd = ssthresh` is a reset that the growth below then builds
	 * on. Run the growth first and a recovery would be credited twice.
	 */
	if ((int32_t)(e->ack - c->send_next) > 0) {
		/*
		 * COUNTED UNCONDITIONALLY. The trace print in proc_ack is
		 * getenv-gated and no run has ever enabled it, so "has this
		 * ever happened?" was unanswerable from every log we hold --
		 * absence of the string was absence of the INSTRUMENT, not
		 * absence of the condition.
		 */
		INSTR(g_rx[RXS_ACK_PAST_NEXT]++);
		c->send_next = e->ack;
		c->cwnd = c->ssthresh;
	}

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
}

/*
 * mtp/tcp.mtp §proc_ack — retire the acknowledged bytes.
 *
 * It no longer calls the generator. `gen_seg` follows it in every chain that
 * can send, so the duplicate case that used to call `tcp_gen_seg` inline
 * simply returns and the dispatch runs it — DEFERRED.md D2, one of the two
 * places the dispatch was hand-inlined.
 */
static void
proc_ack(struct tcp_ctx *c, const struct tcp_ev *e, struct tcp_scratch *sc,
	 uint32_t now)
{
	uint32_t acked;

	INSTR(g_rx[RXS_ACK_CALLED]++);
	if (!conn_exists(c) || !(e->flags & TCP_ACK)) {
		INSTR(g_rx[RXS_ACK_NOFLAG]++);
		return;
	}

	/*
	 * THE ACKNOWLEDGEMENT OF OUR OWN FIN, which consumes sequence space and
	 * so is this processor's to retire. It sits ahead of the duplicate test
	 * because a retransmitted acknowledgement of our FIN advances nothing
	 * and must still complete the teardown.
	 *
	 * Reached from the tcp_fin chain as well, where proc_ack runs BEFORE
	 * proc_fin: a segment carrying both the peer's FIN and the
	 * acknowledgement of ours takes FIN_WAIT_1 -> FIN_WAIT_2 here and then
	 * FIN_WAIT_2 -> TIME_WAIT in proc_fin. That is DESIGN-CLOSE.md §4's
	 * "peer FIN and ack of ours -> TIME_WAIT" row, reached by the other of
	 * its two routes; the CLOSING route is still live for the ordering
	 * where the peer's FIN arrives first.
	 */
	if (e->ack == c->send_next) {
		if (c->state == TCP_LAST_ACK) {
			c->state = TCP_CLOSED;
			prog_unregister(c);
			mtp_del_ctx(&c->key);
			/*
			 * THE CONTEXT IS GONE. Every processor after this one
			 * in the chain would run against freed memory, so the
			 * dispatch stops here. `del_ctx` ends the chain it is
			 * issued from; nothing else in this program ends a
			 * chain early.
			 */
			sc->ctx_dead = true;
			return;
		}
		if (c->state == TCP_FIN_WAIT_1)
			c->state = TCP_FIN_WAIT_2;
		else if (c->state == TCP_CLOSING)
			enter_time_wait(c);
	}

	acked = e->ack - c->send_una;
	if ((int32_t)acked <= 0) {
		INSTR(g_rx[RXS_ACK_DUP]++);
		/*
		 * ADVANCES NOTHING, BUT IT IS STILL AN EVENT. proc_congestion
		 * has just refreshed the window from this segment, and a peer
		 * whose window reopens tells us with exactly this: ack ==
		 * send_una, a larger window, no new data acknowledged.
		 *
		 * D-25: the send attempt that acts on it is `gen_seg`, next in
		 * the chain. It used to be called from here, which was the
		 * dispatch hand-inlined; the behaviour is unchanged and the
		 * shape is not.
		 *
		 * CORRECTED 2026-08-18. This used to say the donor "puts the
		 * stream on the send list and re-runs the flush every
		 * event-loop iteration", so that an rx-driven retry and a
		 * per-iteration retry were "observably identical". B has
		 * withdrawn that: THE SEND LIST IS DRAINED, NOT PERSISTENT --
		 * cleared at tcp_out.c:806 with explicit removals at three
		 * further sites. A stream flushed once is off the list, and a
		 * later attempt needs a fresh AddtoSendList.
		 *
		 * So attempting here is D-25, not an equivalence with the
		 * donor -- and D-30 rules that it goes away once the
		 * per-iteration retry list can take over the recovery.
		 */
		return;
	}
	INSTR(g_rx[RXS_ACK_ADVANCED]++);
	sc->acked = acked;
	if (c->in_rtx)
		INSTR(g_bytes_rtx += acked);
	else
		INSTR(g_bytes_clean += acked);
	if (c->in_rtx && (int32_t)(e->ack - c->rtx_mark) >= 0)
		c->in_rtx = false;
	if (c->have_rtt) {
		INSTR(g_rto_sum += c->rto_ms);
		INSTR(g_rto_n++);
		if (c->rto_ms > g_rto_max)
			INSTR(g_rto_max = c->rto_ms);
	}
	c->una_advanced_us = mtp_now_us();

	/*
	 * Close the probe: this is EFFECTIVE round trip -- generation to the
	 * acknowledgement that covers it -- not network round trip. The two
	 * differ by however long the segment waited to be drained and however
	 * long the acknowledgement waited to be processed, which is exactly
	 * the interval in question.
	 */
	if (c->probe_us && (int32_t)(e->ack - c->probe_seq) >= 0) {
		uint64_t d = mtp_now_us() - c->probe_us;
		unsigned b;

		if (d < 200)		b = 0;
		else if (d < 1000)	b = 1;
		else if (d < 5000)	b = 2;
		else if (d < 20000)	b = 3;
		else if (d < 50000)	b = 4;
		else			b = 5;
		INSTR(g_rtt_bucket[b]++);
		INSTR(g_rtt_sum += d);
		INSTR(g_rtt_n++);
		if (d > g_rtt_max)
			INSTR(g_rtt_max = d);
		c->probe_us = 0;
	}
	/*
	 * UNITS: probe_seq_end is unit-relative, e->ack is absolute. Saying
	 * that out loud is the rule adopted after a unit-relative offset was
	 * compared against an absolute sequence and reported 99.8% occupancy
	 * that was entirely the bug.
	 */
	if (c->tx.probe_pending
	    && (uint64_t)(e->ack - c->snd_base) >= c->tx.probe_seq_end) {
		uint64_t d = mtp_now_us() - c->tx.probe_us;
		unsigned b;

		if (d < 50)		b = 0;
		else if (d < 100)	b = 1;
		else if (d < 250)	b = 2;
		else if (d < 500)	b = 3;
		else if (d < 1000)	b = 4;
		else if (d < 2500)	b = 5;
		else if (d < 10000)	b = 6;
		else			b = 7;
		INSTR(g_ack_hist[b]++);
		INSTR(g_ack_sum += d);
		INSTR(g_ack_n++);
		if (d > g_ack_max)
			INSTR(g_ack_max = d);
		c->tx.probe_pending = 0;
	}

	if (c->fin_pending && (int32_t)(e->ack - (c->fin_seq + 1)) >= 0)
		c->fin_pending = false;
	if (c->stage == ST_AWAIT_ACK && (int32_t)(e->ack - c->stage_seq) >= 0) {
		c->stage = ST_AWAIT_DECISION;
		g_stage_enter[ST_AWAIT_DECISION]++;
	}

	if (MTP_ENV_ON("MTP_TRACE_SEQ"))
		fprintf(stderr, "ACK  ack=%u una=%u next=%u acked=%u%s\n",
			e->ack, c->send_una, c->send_next, acked,
			(int32_t)(c->send_next - e->ack) < 0
			? "  <<< ack PAST send_next" : "");

	c->send_una = e->ack;
	mtp_tx_flush_and_notify(&c->tx, acked);

	/* progress: cancel, and reset the backoff. Re-armed below if anything
	 * is still outstanding. */
	c->rtx_count = 0;
	mtp_timer_stop(&c->rto);
	if (unacked_on_wire(c))
		arm_rto(c);
}

/* mtp/tcp.mtp §proc_recv — in-order payload. The acknowledgement it owes is
 * `send_ack`'s, next in the chain. */
static void
proc_recv(struct tcp_ctx *c, const struct tcp_ev *e, struct tcp_scratch *sc,
	  uint32_t now)
{
	(void)now;
	if (MTP_ENV_ON("MTP_TRACE_SEQ"))
		fprintf(stderr, "PROCRECV state=%u seq=%u recv_next=%u paylen=%u "
			"flags=0x%x\n", c->state, e->seq, c->recv_next,
			e->payload_len, e->flags);
	/*
	 * The data-acknowledgement path, silenced permanently once a FIN has
	 * been accepted (D-20). One state test that says what it means, which
	 * is the prototype's mechanism rather than mTCP's emergent counter
	 * arithmetic — reproducing that would mean reproducing the arithmetic
	 * to obtain a side effect.
	 */
	if (!recv_side_open(c))
		return;

	/*
	 * D-25 piece 3 — ANSWER THE PEER'S WINDOW PROBE. Not optional, and easy
	 * to miss because it is receive-side work that exists only to serve the
	 * other end's send-side mechanism.
	 *
	 * The donor probes with a pure ACK at seq = snd_nxt - 1, deliberately
	 * OUTSIDE our receive window, so that we are obliged to respond. If we
	 * do not, the donor as sender never learns our window reopened and the
	 * stall simply moves to the other end of the connection — the same bug
	 * with the roles swapped, which is exactly the sort of thing that would
	 * be found late and blamed on the sender.
	 *
	 * One byte behind what we expect next is the signature; nothing else
	 * legitimately arrives there.
	 */
	if (!e->payload_len)
		return;

	/*
	 * The bytes actually go into the receive stream now. Until this landed
	 * the unit was declared in the context and never held a byte —
	 * declared and never connected, the fourth instance, and one the wiring
	 * gate could not see because these are contract instructions rather
	 * than program constants.
	 */
	if (!c->rx_open) {
		mtp_new_rx_ordered_data(&c->rx, MTP_SIZE_INF);
		c->rx_open = true;
	}
	{
		struct mtp_rx_addr a = { .data = e->payload, .len = e->payload_len };

		/*
		 * Store the bytes at their OWN sequence number. The target
		 * copies to an offset; it does not interpret and reports
		 * nothing back. A refusal here is the window being full, not
		 * the segment being out of order.
		 */
		if (mtp_add_rx_data_seg(&c->rx, a, e->payload_len, e->seq) < 0)
			return;
	}

	/*
	 * Mark the range as arrived, wherever it landed, then advance over
	 * everything contiguously arrived. THERE IS NO IN-ORDER BRANCH BECAUSE
	 * THERE DOES NOT NEED TO BE ONE: a segment past the boundary marks a
	 * range the slide does not reach, and a later segment that fills the
	 * gap lets the same slide run past both.
	 *
	 * Duplicates, overlaps and multiple holes need no code at all. Marking
	 * a range twice is the same as marking it once; a partial overlap marks
	 * the union; two losses leave two runs and the slide stops at the
	 * first.
	 */
	mtp_sw_set(&c->rx_wnd, e->seq, e->seq + e->payload_len);
	{
		uint32_t next = (uint32_t)mtp_sw_slide(&c->rx_wnd);

		/*
		 * Stored past a gap: the boundary did not move, so nothing new
		 * is acknowledged and the window rule has nothing to
		 * recompute. THE ACKNOWLEDGEMENT STILL GOES OUT, repeating the
		 * same cumulative number -- that duplicate is what tells the
		 * peer where the hole is, and suppressing it would remove the
		 * only signal that triggers the peer's fast retransmit.
		 */
		if (next != c->recv_next)
			/* §window_rule recompute point 1: payload merged in
			 * order. Nothing else in this program writes rcv_wnd. */
			tcp_on_payload_merged(c, next);
	}

	INSTR(g_emit[EM_ACK_DATA]++);
	sc->ack_now = true;
}

/*
 * mtp/tcp.mtp §send_ack — emit the acknowledgement the chain decided it owed.
 *
 * IT RE-TESTS NOTHING. Every guard that decides whether an acknowledgement is
 * due — recv_side_open, the in-order test, the FIN's ordering — lives at the
 * decision site, and this only acts on `sc.ack_now`. That is what makes it safe
 * to run after proc_fin's state transition: the old code had to build the FIN's
 * acknowledgement BEFORE the transition, because the guard that silences the
 * data path would otherwise have silenced it too. With the decision separated
 * from the emission, the ordering hazard is gone rather than commented.
 */
static void
send_ack(struct tcp_ctx *c, const struct tcp_ev *e, struct tcp_scratch *sc,
	 uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload none = { 0 };
	uint16_t hdr_len;

	(void)e;
	if (!sc->ack_now)
		return;
	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_ACK, now,
				   c->ts_recent);
	mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, PRIO_ACK, 1,
		    0 /* not a retransmission */);
}

/*----------------------------------------------------------------------------*/
/*
 * D-24. The acknowledgement of the peer's FIN has already been committed to the
 * target by the caller; this is the state that OWES it, held open across the
 * iteration in which it drains. Skipping the state does not skip a wait — it
 * removes the place that acknowledgement is owed from, which is why zero is a
 * real duration here and not an argument for having no state.
 *
 * The GUARD is what is being reproduced, not the timer value.
 */
static void
enter_time_wait(struct tcp_ctx *c)
{
	c->state = TCP_TIME_WAIT;
	c->tw.ctx = c;
	mtp_timer_start(&c->tw, (uint64_t)PARITY_TIMEWAIT_MS * 1000000ULL);
}


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
proc_fin(struct tcp_ctx *c, const struct tcp_ev *e, struct tcp_scratch *sc,
	 uint32_t now)
{
	uint32_t fin_seq;

	(void)now;
	if (!(e->flags & TCP_FIN))
		return;
	if (!recv_side_open(c))
		return;
	/*
	 * THE FIN'S SEQUENCE IS PAST ITS OWN PAYLOAD, which is the donor's test
	 * verbatim: `if (seq + payloadlen == cur_stream->rcv_nxt)`, tcp_in.c,
	 * under its own comment "FIN packet is allowed to push payload". Testing
	 * e->seq alone refuses a data-carrying FIN as out of order and the
	 * connection never tears down.
	 *
	 * proc_recv has already run for this segment -- the parser raises
	 * tcp_data before tcp_fin -- so recv_next is past the payload by now if
	 * the payload was in order.
	 */
	fin_seq = e->seq + e->payload_len;
	if (fin_seq != c->recv_next) {
		/*
		 * A FIN ahead of a gap does not transition; the segment that
		 * fills the hole performs it. It is still ACKNOWLEDGED, which
		 * is the donor's else branch (EnqueueACK with ACK_OPT_NOW) --
		 * without it the peer learns nothing and retransmits blind.
		 */
		sc->ack_now = true;
		return;
	}

	c->recv_next = fin_seq + 1;	/* the FIN consumes one byte */
	mtp_sw_set(&c->rx_wnd, fin_seq, fin_seq + 1);
	mtp_sw_slide(&c->rx_wnd);	/* keep the window's boundary and
					 * recv_next the same number */
	c->fin_consumed = true;		/* ...which is not data: G14 */

	INSTR(g_emit[EM_ACK_FIN]++);
	sc->ack_now = true;		/* send_ack emits it, after the transition
					 * below; see send_ack on why that is now
					 * safe */

	/*
	 * DESIGN-CLOSE.md §4. Where the peer's FIN takes us depends on whether
	 * we have already sent ours; CLOSING is the simultaneous close, one row
	 * and worth it — leaving it out wedges exactly the way the missing
	 * active close did.
	 */
	if (c->state == TCP_FIN_WAIT_1) {
		c->state = TCP_CLOSING;
	} else if (c->state == TCP_FIN_WAIT_2) {
		enter_time_wait(c);
	} else {
		int was_established = (c->state == TCP_ESTABLISHED);

		c->state = TCP_CLOSE_WAIT;
		/*
		 * D8: READABLE, AND ONLY OUT OF ESTABLISHED. The donor raises a
		 * read event here and nowhere else on the FIN path --
		 * tcp_in.c:954, immediately after the CLOSE_WAIT transition and
		 * inside the branch that only ESTABLISHED reaches. We were
		 * issuing a STATE notification, on every transition.
		 *
		 * It is READABLE because that is what an application waiting on
		 * a socket acts on: read() returning 0 is how end-of-stream is
		 * delivered, and a state notification is not something the
		 * donor's API has. The simultaneous-close and FIN_WAIT_2 rows
		 * above raise nothing, which is also the donor.
		 */
		if (was_established)
			mtp_notify(c->f, &(struct mtp_notif){
					.kind = MTP_NOTIF_READABLE });
	}
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
/*
 * Build and issue the FIN. Separated from gen_fin because the retransmission
 * path needs the packet WITHOUT the state transition: gen_fin's guards --
 * app_closed, state ESTABLISHED or CLOSE_WAIT -- are all false by the time a
 * FIN needs resending, so the retransmit could never have gone through it.
 */
static bool
fin_emit(struct tcp_ctx *c, uint32_t now, uint32_t rtx)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload none = { 0 };
	uint16_t hdr_len;

	hdr_len = tcp_build_header(hdr, c, c->send_next,
				   TCP_ACK | TCP_FIN, now, c->ts_recent);
	INSTR(g_emit[EM_FIN]++);
	return mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, PRIO_DATA, 1,
			   rtx) == 0;
}

static void
gen_fin(struct tcp_ctx *c, uint32_t now)
{
	if (MTP_ENV_ON("MTP_TRACE_SEQ") && c->state == TCP_CLOSE_WAIT)
		fprintf(stderr, "GENFIN now=%u send_next=%u snd_base=%u "
			"write_end=%u\n", now, c->send_next, c->snd_base,
			c->write_end);
	/*
	 * DESIGN-CLOSE.md §3. The condition is that the APPLICATION has closed
	 * and everything it handed us has been sent. Whether we then go to
	 * LAST_ACK or FIN_WAIT_1 is a CONSEQUENCE of whether the peer closed
	 * first, not a precondition for closing at all.
	 *
	 * The old gate was `state == CLOSE_WAIT`, which encoded "the peer closed
	 * first" as a requirement. Against a peer that never closes first — any
	 * mTCP peer, and so every peer we will ever measure against — the object
	 * was delivered and the connection then hung forever with no FIN.
	 */
	if (!c->app_closed)
		return;
	if (c->state != TCP_ESTABLISHED && c->state != TCP_CLOSE_WAIT)
		return;			/* already closing, or not yet open */
	if (c->send_next - c->snd_base != c->write_end)
		return;			/* G10: not ahead of unsent data */

	if (fin_emit(c, now, 0 /* not a retransmission */)) {
		c->fin_pending = true;
		c->fin_seq = c->send_next;
		c->send_next++;		/* the FIN consumes one byte */
		c->state = (c->state == TCP_CLOSE_WAIT) ? TCP_LAST_ACK
							: TCP_FIN_WAIT_1;
	}
}

/*----------------------------------------------------------------------------*/
/*
 * THE DISPATCH — one function per event, which is what a compiler emits from
 * `dispatch tcp_dispatch { ... }`. DEFERRED.md D1.
 *
 * What it replaces: `mtp_program_net_input` ran proc_open_done, proc_ack,
 * proc_recv, proc_fin and gen_fin on EVERY packet and let each guard itself.
 * That produced correct behaviour and was not the emitted form of the dispatch
 * table — it is why proc_recv ran on a pure acknowledgement.
 *
 * Each dispatch takes a fresh scratchpad: it exists for the length of one
 * chain and nothing carries across events.
 *
 * `del_ctx` takes the flow's key, and the context keeps its own copy for
 * exactly that: a timer chain outlives the packet that created the flow and has
 * no key to hand.
 */

/*
 * mtp/tcp.mtp §proc_idle's clock — the connection did something.
 *
 * Restarts the idle timer rather than recording a timestamp, because the
 * question the donor asks per tick ("has this been quiet for 30 s?") is the
 * question a timer answers by expiring. The observable is the same and there is
 * no list to walk.
 */
static void
tcp_touch_idle(struct tcp_ctx *c)
{
	if (c->state == TCP_CLOSED || c->state == TCP_TIME_WAIT)
		return;			/* nothing left to reap */
	/*
	 * MTP_IDLE_MS shortens the timeout so the mechanism can be DEMONSTRATED
	 * rather than declared. At the donor's 30 s nothing on this testbed
	 * stays quiet long enough for it to fire, and a reaper that has never
	 * been seen to reap is the same dead mechanism as a counter never seen
	 * to increment. Resolved once; the default is the donor's.
	 */
	static uint32_t idle_ms;

	if (!idle_ms) {
		const char *e = getenv("MTP_IDLE_MS");

		idle_ms = e && atoi(e) > 0 ? (uint32_t)atoi(e) : PARITY_IDLE_MS;
	}
	c->idle.ctx = c;
	mtp_timer_start(&c->idle, (uint64_t)idle_ms * 1000000ULL);
}

/*
 * mtp/tcp.mtp §proc_validate — PAWS and the sequence-acceptability test.
 *
 * `seq_validation` and `paws`, off the list of mechanisms we did not have. Both
 * run on EVERY packet, which is why their absence contaminated the
 * cycles-per-byte comparison at its root: we were cheaper per packet partly
 * because we validated less.
 *
 * IT IS THE DONOR'S ValidateSequence, reproduced rather than re-derived, and
 * three things about it are worth stating because a standards-based
 * implementation would differ:
 *
 *   - the acceptability test is on `seq + payloadlen` lying inside
 *     [recv_next, recv_next + rcv_wnd]. RFC 793's test is on the segment's
 *     first and last bytes separately; this is the donor's, and rule 1 says
 *     reproduce the donor;
 *   - a segment from a timestamping peer that carries NO timestamp is dropped.
 *     The donor leaves a TODO where a standards-based handler would go;
 *   - `ts_recent` is updated HERE, before dispatch, and only for a timestamping
 *     peer. Ours updated it in proc_timestamp for any acknowledgement, so it
 *     moved on segments the donor would have rejected.
 *
 * RETURNS FALSE TO DROP THE SEGMENT, having queued whatever acknowledgement the
 * donor queues on that path. Called after the context lookup and before any
 * event is raised, which is where the donor calls it -- ProcessTCPPacket, and
 * only once the connection is past SYN_RCVD.
 */
static bool
proc_validate(struct tcp_ctx *c, const struct tcp_ev *e,
	      struct tcp_scratch *sc, uint32_t now)
{
	uint32_t seg_end;

	(void)now;
	/* Before the handshake completes there is nothing to validate against:
	 * the donor guards the whole call with `state > TCP_ST_SYN_RCVD`. */
	if (c->state == TCP_CLOSED || c->state == TCP_LISTEN ||
	    c->state == TCP_SYN_RCVD)
		return true;

	/* --- PAWS ------------------------------------------------------- */
	if (!(e->flags & TCP_RST) && c->saw_timestamp) {
		if (!e->has_ts) {
			INSTR(g_rx[RXS_PAWS_NOTS]++);
			return false;		/* no timestamp from a peer that
						 * timestamps: dropped */
		}
		if ((int32_t)(e->ts_val - c->ts_recent) < 0) {
			/* RFC 1323: SEG.TSval < TS.Recent -> drop, and
			 * acknowledge so the peer learns where we are. */
			INSTR(g_rx[RXS_PAWS_OLD]++);
			sc->ack_now = true;
			return false;
		}
		c->ts_recent = e->ts_val;
	}

	/* --- sequence acceptability -------------------------------------- */
	seg_end = e->seq + e->payload_len;
	if ((int32_t)(seg_end - c->recv_next) >= 0 &&
	    (int32_t)(seg_end - (c->recv_next + c->rcv_wnd)) <= 0)
		return true;			/* acceptable */

	INSTR(g_rx[RXS_SEQ_BAD]++);
	if (e->flags & TCP_RST)
		return false;			/* a reset outside the window is
						 * ignored, not answered */

	if (c->state == TCP_ESTABLISHED) {
		/*
		 * THE PEER'S WINDOW PROBE, and it lives here rather than in
		 * proc_recv, which is where we had it. The donor answers it
		 * from inside validation and then STOPS PROCESSING the segment
		 * -- one byte behind what we expect next is deliberately
		 * outside our window, so it can only be a probe.
		 */
		sc->ack_now = true;
		if (e->seq + 1 == c->recv_next)
			INSTR(g_emit[EM_PROBE_REPLY]++);
	} else {
		/*
		 * Outside ESTABLISHED the donor puts the stream on its control
		 * list -- an acknowledgement from the control path -- and
		 * refreshes the TIME_WAIT deadline if that is where it is.
		 */
		if (c->state == TCP_TIME_WAIT)
			enter_time_wait(c);
		sc->ack_now = true;
	}
	return false;
}

/*
 * mtp/tcp.mtp §gen_rst — answer a segment that belongs to no connection.
 *
 * THE DONOR SENDS A RESET ONLY HERE. All six of its emission sites are in
 * ProcessTCPPacket, for a segment with no live stream, via
 * SendTCPPacketStandalone. It never sends one from an established connection
 * and mtcp_close always sends a FIN -- so an abortive close has no
 * representation in the DONOR either, and adding one here would be a divergence
 * rather than parity (docs/events/EVENT-RST.md).
 *
 * Two shapes, and which one depends on whether the offending segment carried an
 * acknowledgement (tcp_in.c:744 and :748):
 *
 *   with ACK: seq = its ack, no ACK flag of our own, no acknowledgement number
 *   without:  seq = 0, ACK flag set, ack = its seq + its length (+1 for a SYN)
 *
 * The second form has to acknowledge something because a bare reset with
 * sequence zero would be discarded by any receiver checking the window.
 */
static void
gen_rst(uint32_t local_ip, uint32_t remote_ip, const struct tcp_ev *e)
{
	uint8_t hdr[PROG_HDR_MAX];
	uint16_t hdr_len;
	uint32_t seq, ack;
	uint8_t flags;

	if (e->flags & TCP_RST)
		return;			/* never answer a reset with a reset */

	if (e->flags & TCP_ACK) {
		seq = e->ack;
		ack = 0;
		flags = TCP_RST;
	} else {
		seq = 0;
		ack = e->seq + e->payload_len + ((e->flags & TCP_SYN) ? 1 : 0);
		flags = TCP_RST | TCP_ACK;
	}

	hdr_len = tcp_build_rst_header(hdr, e->dport, e->sport, seq, ack, flags);
	INSTR(g_emit[EM_RST]++);
	mtp_pkt_gen_orphan(local_ip, remote_ip, hdr, hdr_len, 1 /* offload */);
}

/*
 * A reset for a connection we DO have a context for -- the one case the donor
 * resets from a stream it knows about (Handle_TCP_ST_SYN_SENT, an
 * unacceptable acknowledgement). It still goes out through the orphan path,
 * because the reset carries the offending segment's numbers rather than ours.
 */
static void
gen_rst_from_ctx(struct tcp_ctx *c, const struct tcp_ev *e)
{
	uint8_t hdr[PROG_HDR_MAX];
	uint16_t hdr_len;

	if (e->flags & TCP_RST)
		return;
	hdr_len = tcp_build_rst_header(hdr, c->loc_port, c->rem_port,
				       e->ack, 0, TCP_RST);
	INSTR(g_emit[EM_RST]++);
	mtp_pkt_gen_orphan(c->local_ip, c->remote_ip, hdr, hdr_len, 1);
}

/*
 * mtp/tcp.mtp §proc_rst — the peer reset the connection.
 *
 * docs/events/EVENT-RST.md, which is A's design and not an agreed one.
 * Reproduced from the donor's ProcessRST, and TWO OF ITS ODDITIES ARE
 * DELIBERATE:
 *
 *   - a reset on an ESTABLISHED connection leaves it in CLOSE_WAIT, not
 *     CLOSED, and destroys nothing. The donor's own destroy is commented out
 *     there. So the application still has to close it and the flow stays alive
 *     until it does;
 *   - the application is not told WHY. NotifyConnectionReset is commented out
 *     in the donor; it raises a close event, so the application learns the
 *     socket is readable and then reads end-of-stream.
 *
 * Rule 1: reproduce, do not correct. REVISIT before any writeup.
 *
 * The donor also has `TODO: we need reset validation logic` at the top and does
 * NOT check that the reset's sequence lies in the window -- the check RFC 5961
 * exists for. Reproducing that reproduces its exposure to blind reset attacks,
 * which is what rule 1 asks for and is worth saying out loud.
 */
static bool
proc_rst(struct tcp_ctx *c, const struct tcp_ev *e, struct tcp_scratch *sc,
	 uint32_t now)
{
	(void)sc; (void)now;
	INSTR(g_rx[RXS_RST_HANDLED]++);

	/* Below ESTABLISHED the donor does not handle it here at all. */
	if (c->state == TCP_CLOSED || c->state == TCP_LISTEN)
		return true;

	if (c->state == TCP_SYN_RCVD) {
		/* Only a reset that acknowledges our SYN-ACK exactly. */
		if (e->ack == c->send_next) {
			c->state = TCP_CLOSED;
			prog_unregister(c);
			mtp_del_ctx(&c->key);
			return false;		/* the context is gone */
		}
		return true;
	}

	if (c->state == TCP_FIN_WAIT_1 || c->state == TCP_FIN_WAIT_2 ||
	    c->state == TCP_LAST_ACK   || c->state == TCP_CLOSING ||
	    c->state == TCP_TIME_WAIT) {
		/* Already closing; the reset just ends it. */
		c->state = TCP_CLOSED;
		prog_unregister(c);
		mtp_del_ctx(&c->key);
		return false;
	}

	/* ESTABLISHED or CLOSE_WAIT: see the note above. */
	c->state = TCP_CLOSE_WAIT;
	c->fin_consumed = true;		/* the receive side is over, however it
					 * ended: nothing more will arrive */
	mtp_notify(c->f, &(struct mtp_notif){ .kind = MTP_NOTIF_READABLE });
	return true;
}

/*
 * mtp/tcp.mtp §net_parser — which events this segment raises.
 *
 * INCLUSIVE, AND THAT IS THE DONOR'S SHAPE, not a convenience. mTCP's
 * Handle_TCP_ST_ESTABLISHED (tcp_in.c) runs three independent tests on one
 * packet —
 *
 *      if (payloadlen > 0) { ProcessTCPPayload(...) }
 *      if (tcph->ack)      { ProcessACK(...) }
 *      if (tcph->fin)      { ... }
 *
 * — so a segment carrying payload, an acknowledgement and a FIN does all three
 * jobs there. An exclusive classification, one event per segment, would drop
 * the payload of a FIN that carries data and would fail to establish a
 * connection whose handshake-completing acknowledgement carries the request.
 * Neither is a design choice we are entitled to make: rule 1 says the two
 * stacks put the same thing on the wire.
 *
 * ORDER: acknowledgement before payload, which is the reverse of the donor's
 * internal order and is not observable — the donor defers both its
 * acknowledgement and its send to the end of the pass, so nothing it emits
 * depends on which ran first. Ours is ordered this way because proc_congestion
 * lives in the tcp_ack chain and reads `ack - send_una`: let tcp_data's
 * proc_ack retire the bytes first and the congestion window would see nothing
 * newly acknowledged and stop growing.
 *
 * THE CHAINS DO NOT OVERLAP. `proc_ack` is in the tcp_ack chain and in no
 * other, so no processor runs twice for one segment. The dispatch table as
 * first written had it heading tcp_data and tcp_fin as well -- correct under an
 * exclusive classification, where a data segment raises tcp_data and nothing
 * else and so needs its own way to retire the acknowledgement. Under an
 * inclusive one that is a repeat, and the repeat buys nothing: proc_ack's first
 * guard is `!(flags & ACK) -> return`, and the only segment that raises
 * tcp_data or tcp_fin WITHOUT raising tcp_ack is one with no ACK flag, where
 * proc_ack would return on that guard anyway.
 *
 * So each chain does its own job and the acknowledgement is done once, by the
 * event that means "this segment acknowledges". Lead's call, 2026-08-24.
 */
enum tcp_event_kind {
	EV_RST,
	EV_SYN,
	EV_SYNACK,
	EV_ACK,
	EV_DATA,
	EV_FIN,
	EV_KIND__N
};

static unsigned
parse_tcp_events(const struct tcp_ev *e, enum tcp_event_kind out[EV_KIND__N])
{
	unsigned n = 0;

	/*
	 * A RESET RAISES tcp_rst AND NOTHING ELSE, which is the one place the
	 * inclusive classification above does not apply. The donor calls
	 * ProcessRST and returns from ProcessTCPPacket on a true result, so no
	 * payload is delivered and no acknowledgement is retired from that
	 * segment.
	 */
	if (e->flags & TCP_RST) {
		out[n++] = EV_RST;
		return n;
	}
	if (e->flags & TCP_SYN) {
		/* A handshake segment raises one event and nothing else: no
		 * payload of ours is in sequence yet, and the acknowledgement
		 * it may carry is the handshake's own. */
		out[n++] = (e->flags & TCP_ACK) ? EV_SYNACK : EV_SYN;
		return n;
	}
	if (e->flags & TCP_ACK)
		out[n++] = EV_ACK;
	if (e->payload_len)
		out[n++] = EV_DATA;
	if (e->flags & TCP_FIN)
		out[n++] = EV_FIN;
	return n;
}

/* generated from: tcp_ack -> { proc_timestamp, proc_open_done, proc_rtt,
 *                              proc_fast_retransmit, proc_congestion, proc_ack,
 *                              gen_seg, gen_fin } */
static bool
dispatch_tcp_ack(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	struct tcp_scratch sc = { 0 };

	proc_timestamp(c, e);
	proc_open_done(c, e, now);
	proc_window(c, e);
	proc_rtt(c, e, now);
	proc_fast_retransmit(c, e, &sc, now);
	proc_congestion(c, e, now);
	proc_ack(c, e, &sc, now);
	if (sc.ctx_dead)
		return false;
	/*
	 * THE DONOR DOES NOT ATTEMPT A SEND ON A DUPLICATE it is not acting on
	 * (D-30). We attempted on every one -- the D-25 stall fix -- and the
	 * per-iteration retry list is what took that recovery over.
	 */
	if (!sc.no_send)
		tcp_gen_seg(c, now);
	gen_fin(c, now);
	return true;
}

/* generated from: tcp_rst -> { proc_rst } */
static bool
dispatch_tcp_rst(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	struct tcp_scratch sc = { 0 };

	return proc_rst(c, e, &sc, now);
}

/* generated from: tcp_data -> { proc_recv, send_ack } */
static bool
dispatch_tcp_data(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	struct tcp_scratch sc = { 0 };

	proc_recv(c, e, &sc, now);
	send_ack(c, e, &sc, now);
	return true;
}

/* generated from: tcp_fin -> { proc_fin, send_ack } */
static bool
dispatch_tcp_fin(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	struct tcp_scratch sc = { 0 };

	proc_fin(c, e, &sc, now);
	send_ack(c, e, &sc, now);
	return true;
}

/*
 * mtp/tcp.mtp §proc_synack — NOT IMPLEMENTED.
 *
 * `active_open` on the absence register. Nothing we run opens a connection, so
 * a SYN-ACK reaching us is a segment for a connection we did not initiate.
 * DEFERRED.md C7 and E1: the donor's active-open path is unread, and
 * EVENT-SYNACK.md §3.2 is checked against the paper alone. It is not written to
 * until that has been read.
 */
/*
 * mtp/tcp.mtp §gen_syn — our SYN, emitted or re-attempted.
 *
 * Separate from proc_connect because it is issued twice in the ordinary case:
 * once when the application asks, and again from the retry list once the
 * address resolves.
 */
static void
gen_syn(struct tcp_ctx *c, uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload none = { 0 };
	uint16_t hdr_len;

	if (c->state != TCP_SYN_SENT || c->send_next != c->snd_base)
		return;			/* already on the wire */

	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_SYN, now, 0);
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, PRIO_CONTROL, 1, 0) != 0) {
		mtp_retry(c->f);	/* the address is not resolved yet */
		return;
	}
	INSTR(g_emit[EM_SYN]++);
	c->send_next++;			/* the SYN consumes one */
	arm_rto(c);
}

/*
 * mtp/tcp.mtp §proc_synack — the peer accepted our connection.
 *
 * The donor's HandleActiveOpen plus the SYN_SENT arm of
 * Handle_TCP_ST_SYN_SENT, read 2026-08-25 (DEFERRED.md E1 discharged --
 * EVENT-SYNACK.md §3.2 had been checked against the paper alone).
 *
 * THREE THINGS THE DOCUMENTS DID NOT HAVE:
 *
 *   - mtcp_connect sets cwnd = 1 and this does
 *     `cwnd = (cwnd == 1) ? mss * TCP_INIT_CWND : mss`, so the initial window
 *     arrives HERE and not at connect;
 *   - the ACTIVE open sets ssthresh = mss * 10, where the passive open never
 *     assigns it at all. D-01 is that asymmetry seen from the other side, and
 *     it means an active-open connection DOES slow-start where our server
 *     does not;
 *   - completion reaches the application as a WRITABLE event
 *     (RaiseWriteEvent), not a state event.
 */
static void
proc_synack(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	if (c->state != TCP_SYN_SENT)
		return;

	/*
	 * The acknowledgement must be for the SYN we sent: strictly above the
	 * initial sequence and no higher than what we have sent. The donor
	 * answers a violation with a reset, which is why that had to exist
	 * first.
	 */
	if ((int32_t)(e->ack - c->snd_base) <= 0 ||
	    (int32_t)(e->ack - c->send_next) > 0) {
		gen_rst_from_ctx(c, e);
		return;
	}

	c->send_una = e->ack;
	c->recv_next = e->seq + 1;		/* irs + 1 */
	c->rcv_base = c->recv_next;
	mtp_sw_init(&c->rx_wnd, c->recv_next);
	c->snd_wl1 = e->seq - 1;
	c->snd_wl2 = e->ack;
	c->last_ack_seq = e->ack;
	c->send_wnd = (uint32_t)e->window << c->snd_wscale;
	c->ts_recent = e->ts_val;
	c->saw_timestamp = e->has_ts;
	if (e->has_wscale)
		c->snd_wscale = e->wscale;

	c->cwnd = PARITY_INIT_CWND;		/* mss * TCP_INIT_CWND */
	c->ssthresh = PARITY_SSTHRESH_ACTIVE;	/* the passive open sets none */
	c->rtx_count = 0;
	mtp_timer_stop(&c->rto);

	if (!c->tx_open) {
		mtp_new_tx_ordered_data(&c->tx, MTP_SIZE_INF);
		c->tx_open = true;
	}
	c->state = TCP_ESTABLISHED;

	/* WRITABLE: what makes a blocked connect() return. */
	mtp_notify(c->f, &(struct mtp_notif){ .kind = MTP_NOTIF_WRITABLE });

	/* The handshake's own acknowledgement. */
	{
		uint8_t hdr[PROG_HDR_MAX];
		struct mtp_tx_payload none = { 0 };
		uint16_t hdr_len = tcp_build_header(hdr, c, c->send_next,
						    TCP_ACK, now, c->ts_recent);

		mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, PRIO_ACK, 1, 0);
	}
}

/* generated from: tcp_synack -> { proc_synack } */
static bool
dispatch_tcp_synack(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	proc_synack(c, e, now);
	return true;
}

/*
 * The parse, the lookup, and the chain per event. ONE flow-table lookup per
 * packet — two on a passive open, where the flow lookup misses and the listener
 * table is consulted, which is once per connection rather than once per packet.
 */
int
mtp_program_net_input(const uint8_t *l4, uint16_t len, const struct iphdr *iph,
		      uint32_t now_ms)
{
	enum tcp_event_kind evs[EV_KIND__N];
	struct tcp_ev e;
	struct tcp_ctx *c;
	struct tcp_listen_ctx *lst;
	flowkey_t k;
	unsigned n, i;

	if (parse_packet(l4, len, &e) < 0)
		return -1;

	k = key_of_inbound(iph->daddr, iph->saddr, e.dport, e.sport);

	c = mtp_ctx_lookup(&k);				/* lookup 1 */
	if (!c) {
		if (!(e.flags & TCP_SYN) || (e.flags & TCP_ACK)) {
			/*
			 * A segment for a connection that does not exist.
			 * tcp_in.c:744/748 -- the donor answers with a reset
			 * rather than dropping it, which is what lets a peer
			 * holding a stale connection find out.
			 */
			gen_rst(iph->daddr, iph->saddr, &e);
			return 0;
		}
		/* G8: both halves must match. A miss is a miss — never a null
		 * context handed onward, which is how the prototype turns a
		 * missed lookup into a crash. */
		{
			/*
			 * G8: BOTH HALVES MUST MATCH, and the match is a
			 * lookup now rather than a comparison against the one
			 * listener there used to be. A miss is a miss — never a
			 * null context handed onward, which is how the
			 * prototype turns a missed lookup into a crash.
			 */
			flowkey_t lk = key_of_listener(iph->daddr, e.dport);

			lst = mtp_ctx_lookup(&lk);
			if (!lst || lst->state != TCP_LISTEN) {
				/* tcp_in.c:700 -- a SYN the listener filter
				 * refuses is answered with a reset. */
				gen_rst(iph->daddr, iph->saddr, &e);
				return 0;
			}
			/*
			 * C3: A SYN ARRIVING WITH THE QUEUE FULL IS DROPPED,
			 * and dropped here -- before any context exists, so
			 * nothing is allocated for a connection that will not
			 * be accepted. The peer retransmits its SYN and finds
			 * room later, which is the behaviour a backlog is for.
			 *
			 * `pending_cap` is what the application asked for at
			 * listen(); PROG_MAX_BACKLOG is what the context can
			 * physically hold. Both bound it, and they are
			 * different questions.
			 */
			if (lst->pending_n >= lst->pending_cap) {
				INSTR(g_rx[RXS_BACKLOG_FULL]++);
				return 0;	/* a full backlog DROPS, it
						 * does not reset: the donor
						 * resets a refused listener
						 * and an exhausted pool, and
						 * a full accept queue is
						 * neither */
			}
		}
		c = mtp_new_ctx(&k, sizeof(*c));
		if (!c)
			return -1;
		if (g_live_n < MTP_MAX_FLOWS_SAMPLED)
			g_live[g_live_n++] = c;
		g_ctx_created++;
		c->rcv_wnd = PARITY_INITIAL_WINDOW;
		c->loc_port = e.dport;
		c->rem_port = e.sport;
		c->local_ip = iph->daddr;
		c->remote_ip = iph->saddr;
		/*
		 * OUR OWN COPY OF THE KEY. The field was declared for exactly
		 * this and never assigned, so the TIME_WAIT timer's
		 * `mtp_del_ctx(&c->key)` has been deleting a zeroed key since
		 * D-24 landed -- silently, because nothing checks the return.
		 * Every connection that reached TIME_WAIT leaked its context.
		 */
		c->key = k;
		c->lst = lst;		/* which endpoint accepted it */
		/* generated from: tcp_syn -> { proc_passive_open } */
		proc_passive_open(c, &e, now_ms);
		return 0;
	}

	INSTR(g_rx[RXS_CTX]++);
	/* tcp_in.c:1292 -- the donor stamps activity on EVERY received packet,
	 * before validation and before any state test. */
	tcp_touch_idle(c);
	/*
	 * INBOUND RST, counted and nothing else. DESIGN-CLOSE.md §5 records that
	 * this program has no RST path: a peer that has gone away answers our
	 * retransmissions with a reset and we discard it. That was written down
	 * as a known absence before the between-transfer frame flood existed, and
	 * it predicts exactly that shape — so it is worth TESTING, not believing.
	 * If resets are not arriving in quantity, the reading is dead.
	 */
	if (e.flags & TCP_RST)
		INSTR(g_rx[RXS_RST]++);

	/*
	 * VALIDATE BEFORE ANY EVENT IS RAISED. The donor calls ValidateSequence
	 * from ProcessTCPPacket, after the flow lookup and before the state
	 * handlers, and drops the segment on a false return -- so an
	 * unacceptable segment reaches no processor at all. Its scratchpad is
	 * separate because it belongs to no event; send_ack is called directly
	 * for the acknowledgement the donor queues on those paths.
	 */
	{
		struct tcp_scratch vsc = { 0 };

		if (!proc_validate(c, &e, &vsc, now_ms)) {
			send_ack(c, &e, &vsc, now_ms);
			return 0;
		}
	}

	n = parse_tcp_events(&e, evs);
	for (i = 0; i < n; i++) {
		bool alive;

		switch (evs[i]) {
		case EV_SYN:
			/* a SYN for a context that already exists: a
			 * retransmitted SYN, handled by the passive open on
			 * the first one and by nothing here */
			alive = true;
			break;
		case EV_RST:    alive = dispatch_tcp_rst(c, &e, now_ms);    break;
		case EV_SYNACK: alive = dispatch_tcp_synack(c, &e, now_ms); break;
		case EV_ACK:    alive = dispatch_tcp_ack(c, &e, now_ms);    break;
		case EV_DATA:   alive = dispatch_tcp_data(c, &e, now_ms);   break;
		case EV_FIN:    alive = dispatch_tcp_fin(c, &e, now_ms);    break;
		default:        alive = true;                                   break;
		}
		if (!alive)
			return 0;	/* del_ctx ran: the context is gone */
	}

	/*
	 * TIME_WAIT's EXIT IS DELIBERATELY NOT IMPLEMENTED — DESIGN-CLOSE.md §5
	 * is open pending B on what the donor does at tcp_timewait = 0, and
	 * specifically on what retransmits the final acknowledgement if it is
	 * lost. Destroying the context here would be committing to reading (1)
	 * by default, which is the reading A2 already got wrong once.
	 *
	 * The context therefore persists for the rest of the run. That is
	 * correct for a bounded experiment and wrong for a server, and it is
	 * written here rather than left to be noticed.
	 */
	return 0;
}

/*----------------------------------------------------------------------------*/
/*
 * mtp/tcp.mtp §mark_closed — the application has no more to send.
 *
 * Split out of the close handler so that `app_close -> { mark_closed, gen_fin }`
 * is a chain the dispatch runs, not a processor calling a generator. That
 * direct call was the second of DEFERRED.md D2's two hand-inlined dispatches;
 * the first was proc_ack's call to the generator.
 */
static void
mark_closed(struct tcp_ctx *c, uint32_t now)
{
	(void)now;
	c->app_closed = true;
}

/* generated from: app_close -> { mark_closed, gen_fin } */
static void
dispatch_app_close(struct tcp_ctx *c, uint32_t now)
{
	mark_closed(c, now);
	/*
	 * Attempted immediately, because the peer may already have finished and
	 * no further packet will arrive to run a chain that contains gen_fin.
	 */
	gen_fin(c, now);
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
mtp_program_app_op(struct mtp_app_op *op, uint32_t now_ms)
{
	switch (op->kind) {
	case MTP_APP_BIND: {
		/*
		 * mtp/tcp.mtp §proc_bind — THIS EVENT IS WHAT BRINGS A LISTEN
		 * CONTEXT INTO EXISTENCE. It exists after bind and is not yet
		 * matchable: proc_passive_open tests for ST_LISTEN, so a SYN
		 * for a bound-but-not-listening endpoint is dropped.
		 *
		 * The op's endpoint is in NETWORK order, as the schema
		 * declares; this program works in host order once past the
		 * parser. Converting here rather than at the comparison site
		 * keeps the one representation choice in one place — the two
		 * being out of step is what made the listener never match and
		 * swallowed every SYN silently.
		 */
		struct tcp_listen_ctx *l;
		flowkey_t k = key_of_listener(op->local.ip,
					      ntohs(op->local.port));

		if (mtp_ctx_lookup(&k))
			return -1;		/* already bound */
		l = mtp_new_ctx(&k, sizeof(*l));
		if (!l)
			return -1;
		l->local_ip = op->local.ip;	/* stays network order:
						 * compared against
						 * iph->daddr, which is */
		l->local_port = ntohs(op->local.port);
		l->state = TCP_CLOSED;
		return 0;
	}
	case MTP_APP_LISTEN: {
		/*
		 * mtp/tcp.mtp §proc_listen — the endpoint starts answering.
		 * No instructions: it flips a state and sets a bound. Everything
		 * that follows happens because proc_passive_open now finds a
		 * listen context in ST_LISTEN.
		 *
		 * The analogue of the donor's ListenerHTInsert. bind created the
		 * context and recorded the endpoint; this is where it becomes
		 * matchable — which is also why the duplicate-endpoint check is
		 * in bind above and the donor makes it here.
		 */
		struct tcp_listen_ctx *l;
		flowkey_t k = key_of_listener(op->local.ip,
					      ntohs(op->local.port));

		l = mtp_ctx_lookup(&k);
		if (!l)
			return -1;		/* listen before bind */
		l->state = TCP_LISTEN;
		l->pending_cap = op->len ? op->len : PROG_MAX_BACKLOG;
		if (l->pending_cap > PROG_MAX_BACKLOG)
			l->pending_cap = PROG_MAX_BACKLOG;
		/* The application interface needs a handle for the LISTENING
		 * endpoint, because that is the one that becomes readable when
		 * a connection is waiting. */
		op->flow = l->f;
		return 0;
	}
	/*
	 * mtp/tcp.mtp §proc_accept — the application takes a pending connection.
	 *
	 * THE BACKLOG IS PROTOCOL STATE AND THIS IS WHAT DRAINS IT.
	 * proc_open_done adds an entry when a handshake completes; this removes
	 * one. Without it `pending` would only ever grow and `pending_cap` would
	 * start refusing connections the application had in fact already taken.
	 *
	 * Everything else about accept -- copying the peer address out,
	 * allocating a descriptor -- is the application interface's business.
	 * The queue it consumes is the protocol's, which is why this is an event
	 * rather than a convenience in the compatibility layer.
	 */
	/*
	 * mtp/tcp.mtp §proc_connect — the application opens a connection.
	 *
	 * DEFERRED.md C7. The op carries both endpoints because THE LOCAL PORT
	 * IS THE CALLER'S (B4): the donor allocates from a per-core address pool
	 * in mtcp_connect and fails EAGAIN when exhausted, and whose job that is
	 * in general is undecided -- it is protocol policy in TCP and not
	 * obviously so elsewhere. The shim picks it, as it did before.
	 *
	 * cwnd is NOT set to the initial window here. The donor sets cwnd = 1 at
	 * connect and HandleActiveOpen turns that into mss * TCP_INIT_CWND when
	 * the SYN-ACK arrives, so the initial window is a property of the
	 * handshake completing rather than of asking.
	 */
	case MTP_APP_CONNECT: {
		struct tcp_ctx *c;
		flowkey_t k = key_of_inbound(op->local.ip, op->remote.ip,
					     ntohs(op->local.port),
					     ntohs(op->remote.port));
		uint8_t hdr[PROG_HDR_MAX];
		struct mtp_tx_payload none = { 0 };
		uint16_t hdr_len;

		if (mtp_ctx_lookup(&k))
			return -1;			/* already connecting */
		c = mtp_new_ctx(&k, sizeof(*c));
		if (!c)
			return -1;
		c->key = k;
		c->local_ip = op->local.ip;
		c->remote_ip = op->remote.ip;
		c->loc_port = ntohs(op->local.port);
		c->rem_port = ntohs(op->remote.port);
		c->rcv_wnd = PARITY_INITIAL_WINDOW;
		c->snd_base = PARITY_ISN;
		c->send_una = PARITY_ISN;
		c->send_next = PARITY_ISN;
		c->cwnd = 1;			/* the donor's, and it means
						 * "not yet opened" rather than
						 * one byte */
		c->ssthresh = PARITY_SSTHRESH_ACTIVE;
		c->state = TCP_SYN_SENT;
		/* No packet created this flow, so the target has no addresses
		 * for it. See contract.h. */
		mtp_ctx_endpoints(c->f, c->local_ip, c->remote_ip);

		/*
		 * A REFUSED SYN IS NORMAL AND IS NOT A FAILED CONNECT.
		 *
		 * The first packet to an unresolved peer ALWAYS fails: the
		 * target sends an ARP request and returns "retry later"
		 * (ip_out.c:123-127). Destroying the context here -- which this
		 * did -- meant every connect to a peer we had not spoken to
		 * died, and since the client speaks first, that was every
		 * connect. The server never saw a SYN.
		 *
		 * So it goes on the retry list and the SYN leaves when the
		 * address resolves. That is D3 doing exactly what it was built
		 * for, on a path that did not exist when it was built.
		 */
		(void)hdr; (void)none; (void)hdr_len;
		gen_syn(c, now_ms);
		tcp_touch_idle(c);
		op->flow = c->f;		/* the caller needs the handle */
		return 0;
	}
	case MTP_APP_ACCEPT: {
		struct tcp_listen_ctx *l;
		flowkey_t k = key_of_listener(op->local.ip,
					      ntohs(op->local.port));
		unsigned i;

		l = mtp_ctx_lookup(&k);
		if (!l || l->state != TCP_LISTEN)
			return -1;
		if (!l->pending_n)
			return -1;		/* nothing to hand over */

		op->flow = l->pending[0];
		for (i = 1; i < l->pending_n; i++)
			l->pending[i - 1] = l->pending[i];
		l->pending_n--;

		/*
		 * LEVEL-TRIGGERED, and it has to be re-raised HERE. The
		 * notification path coalesces by kind, so a second completed
		 * handshake while the first is still queued sets a bit that is
		 * already set. Re-raising on every accept that leaves the queue
		 * non-empty is what keeps the count right -- the same shape as
		 * the receive stream's re-arm inside the read.
		 */
		if (l->pending_n)
			mtp_notify(l->f, &(struct mtp_notif){
					.kind = MTP_NOTIF_READABLE });
		return 0;
	}
	/*
	 * mtp/tcp.mtp §sock_close. The application has no more to send. Our
	 * FIN is gated on this and not on the peer's: a peer FIN closes the
	 * peer's path, and until this arrives our own path is still open.
	 * Try immediately, because the peer may already have finished and
	 * nothing else will call gen_fin if no further packet arrives.
	 */
	case MTP_APP_CLOSE: {
		struct tcp_ctx *c;

		if (!op->flow)
			return -1;
		c = (struct tcp_ctx *)mtp_ctx_of(op->flow);
		if (!c)
			return -1;
		dispatch_app_close(c, now_ms);
		return 0;
	}
	case MTP_APP_RECV: {
		/*
		 * mtp/tcp.mtp §sock_recv — RECOMPUTE POINT 2. The application
		 * has taken bytes, so `delivered` advances by what the
		 * instruction REPORTS it handed over, and the advertised window
		 * is recomputed. This is the second of the donor's two points
		 * and the only place `delivered` moves.
		 */
		struct tcp_ctx *c = (struct tcp_ctx *)mtp_ctx_of(op->flow);
		struct mtp_rx_addr a;
		int got;

		if (!c)
			return -1;
		a.data = (const uint8_t *)op->data.base;
		a.len = op->len;
		{
			/*
			 * DID THE APPLICATION ACTUALLY TAKE THE BYTES? The
			 * level-triggered re-arm re-raises READABLE while
			 * tail_seq > head_seq, so a read that returns data
			 * without consuming it -- or a read never issued --
			 * both present as an unbounded re-arm. These separate
			 * them: calls, bytes, and whether the head moved.
			 */
			uint64_t before = c->rx.head_seq;

			got = mtp_rx_flush_and_notify(&c->rx, op->len, a);
			INSTR(g_recv_calls++);
			if (got > 0) {
				INSTR(g_recv_bytes += (uint64_t)got);
				sock_recv(c, (uint32_t)got);
			} else {
				INSTR(g_recv_empty++);
			}
			if (c->rx.head_seq == before)
				INSTR(g_recv_nohead++);
		}
		return got;
	}
	case MTP_APP_SEND: {
		/*
		 * On a named flow this is an ordinary send. With no flow it is
		 * the object posted before any connection exists, which is how
		 * a one-shot server hands over what every accepted connection
		 * receives.
		 */
		struct tcp_ctx *c;

		if (MTP_ENV_ON("MTP_TRACE_SEQ"))
			fprintf(stderr, "APPOP send now=%u flow=%p len=%u\n",
				now_ms, (void *)op->flow, op->len);
		if (!op->flow) {
			/*
			 * Posted to a LISTENER, not to the process. The op
			 * carries the endpoint for exactly this; with several
			 * listeners there is no "the" listener to post to.
			 */
			struct tcp_listen_ctx *l;
			flowkey_t lk = key_of_listener(op->local.ip,
						       ntohs(op->local.port));

			l = mtp_ctx_lookup(&lk);
			if (!l)
				return -1;
			l->obj = op->data.base;
			l->obj_len = op->len;
			return 0;
		}
		c = (struct tcp_ctx *)mtp_ctx_of(op->flow);
		if (!c)
			return -1;
		/*
		 * generated from: app_send -> { record_data, gen_seg }, SPLIT
		 * ACROSS THREADS. contract.h MTP_OP_PHASE_* says why, and why
		 * the branch is here rather than anywhere in the program's own
		 * logic: the compiler made the placement, so the dispatch it
		 * emits is what knows about it.
		 */
		if (op->flags & MTP_OP_PHASE_RECORD)
			return record_data(c, op->data, op->len);
		return tcp_app_send(c, op->len, now_ms);
	}
	default:
		return -1;		/* an op this program does not bind */
	}
}

/*----------------------------------------------------------------------------*/
/*
 * THE TIMER CHAINS — one timer, one event, one chain.
 *
 * The program declared ONE timer and the C ran THREE (DEFERRED.md C2): `rto`,
 * `tw` and `probe` all arrived at a single handler that told them apart by
 * comparing addresses. A timer is bound at declaration to the event its expiry
 * raises — `timer_t rto_timer -> tcp_rto_timeout` — so the compiler emits one
 * object and one callback per declared timer, and "which timer fired" is not a
 * question the program should be answering at run time.
 *
 * `mtp_program_timer` below is the PARSER for the timer side: it maps a fired
 * timer object to the event it raises, exactly as `parse_tcp_events` maps a
 * segment to its events. Nothing else compares timer addresses any more.
 */

/*
 * mtp/tcp.mtp §proc_rto — the retransmission timer fired.
 *
 * After an RTO the donor sets cwnd = MSS and ssthresh = max(cwnd/2, 2*MSS).
 * One segment leaves, and B established WHY: cwnd == MSS while a segment
 * consumes MSS - 12, so the window bail fires after the first segment
 * regardless of which constant it is compared against. It is NOT the
 * 1460-versus-1448 mismatch, which was the earlier and wrong explanation.
 */
static void
proc_rto(struct tcp_ctx *c, uint32_t now_ms)
{
	INSTR(g_tmr[TMR_RTO]++);
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
	if (MTP_ENV_ON("MTP_TRACE_SEQ"))
		fprintf(stderr, "RTO  rewind next %u -> una %u\n",
			c->send_next, c->send_una);
	/*
	 * MARKING THE CALLER DOES NOT WORK, and the measurement said so: the
	 * timeout fired once and emitted NOTHING — `timer fired retransmission
	 * 1` with `data (retransmission) 0` — because tcp_gen_seg refused here
	 * and the rewound data actually went out later, from the
	 * acknowledgement path. The rewind and the re-emission are SEPARATED IN
	 * TIME, so the caller is not the fact; the sequence position is.
	 *
	 * So it is marked by send_high — the highest send_next ever reached.
	 * Emitting below it is a retransmission whoever asked. The program
	 * still inspects only its own state, which was the point.
	 */
	c->send_next = c->send_una;
	tcp_gen_seg(c, now_ms);

	/*
	 * Resend the FIN if it is what is outstanding. tcp_gen_seg above emits
	 * payload only, and gen_fin refuses in LAST_ACK and FIN_WAIT_1, so
	 * without this the rewind puts send_next back to the FIN's sequence and
	 * nothing ever reoccupies it -- the flow waits for an acknowledgement of
	 * a FIN that is no longer on the wire.
	 */
	if (c->fin_pending && c->send_next == c->fin_seq
	    && fin_emit(c, now_ms, 1 /* a retransmission */))
		c->send_next++;
}

/*
 * mtp/tcp.mtp §proc_timewait_done — D-24, the TIME_WAIT interval expired.
 *
 * Reproduces the DONOR'S GUARD, not its timer value: even at tcp_timewait = 0
 * the state must be entered and left, because skipping it does not skip a wait,
 * it removes the place the final acknowledgement is owed from. That
 * acknowledgement was committed to the target in the iteration that entered
 * this state, so by the time this fires it has drained and the context can go.
 *
 * NOTHING RETRANSMITS THAT ACKNOWLEDGEMENT, deliberately: the donor does not.
 * If it is lost the stream is already gone, the peer's retransmitted FIN finds
 * no flow-table entry and is answered with a bare RST, and teardown completes
 * on that instead. Wire-observable when it happens, and the donor's behaviour
 * rather than an omission.
 */
static void
proc_timewait_done(struct tcp_ctx *c, uint32_t now_ms)
{
	(void)now_ms;
	INSTR(g_tmr[TMR_TIMEWAIT]++);
	c->state = TCP_CLOSED;
	prog_unregister(c);
	mtp_del_ctx(&c->key);
}

/* mtp/tcp.mtp §proc_probe — the window-blocked probe's timer fired. */
static void
proc_probe(struct tcp_ctx *c, uint32_t now_ms)
{
	INSTR(g_tmr[TMR_PROBE]++);
	send_window_probe(c, now_ms);
}

/* generated from: tcp_rto_timeout -> { proc_rto } */
static void
dispatch_tcp_rto_timeout(struct tcp_ctx *c, uint32_t now_ms)
{
	proc_rto(c, now_ms);
}

/* generated from: tcp_timewait_timeout -> { proc_timewait_done } */
static void
dispatch_tcp_timewait_timeout(struct tcp_ctx *c, uint32_t now_ms)
{
	proc_timewait_done(c, now_ms);
}

/*
 * mtp/tcp.mtp §proc_idle — the connection has been quiet too long.
 *
 * THE DONOR TELLS THE APPLICATION WITH AN ERROR, not a clean close
 * (timer.c, CheckConnectionTimeout): state goes to CLOSED with
 * close_reason = TCP_TIMEDOUT, and a stream that still has a socket gets
 * RaiseErrorEvent -- only one with no socket is destroyed silently. No FIN is
 * sent, so the peer learns nothing; that is the donor's behaviour and it is
 * why D-27 calls the mechanism a workaround for its own close path rather than
 * protocol.
 */
static void
proc_idle(struct tcp_ctx *c, uint32_t now_ms)
{
	(void)now_ms;
	INSTR(g_tmr[TMR_IDLE]++);
	c->state = TCP_CLOSED;
	mtp_notify(c->f, &(struct mtp_notif){ .kind = MTP_NOTIF_ERROR });
	prog_unregister(c);
	mtp_del_ctx(&c->key);
}

/* generated from: tcp_idle_timeout -> { proc_idle } */
static void
dispatch_tcp_idle_timeout(struct tcp_ctx *c, uint32_t now_ms)
{
	proc_idle(c, now_ms);
}

/* generated from: tcp_probe_timeout -> { proc_probe } */
static void
dispatch_tcp_probe_timeout(struct tcp_ctx *c, uint32_t now_ms)
{
	proc_probe(c, now_ms);
}

/*
 * The timer-side parser: which declared timer fired, hence which event.
 *
 * A generated version would not compare addresses at all -- each timer object
 * would carry its own callback, emitted from its `-> event` binding. Ours
 * compares, because the target's timer wheel hands back the object and one
 * program entry point. That is the one place the emitted form and the
 * hand-written one differ here, and it is a target-interface question rather
 * than a program one.
 */
void
mtp_program_timer(struct mtp_timer *t, uint32_t now_ms)
{
	struct tcp_ctx *c = t->ctx;

	if (!c || c->state == TCP_CLOSED)
		return;

	if (t == &c->idle)
		dispatch_tcp_idle_timeout(c, now_ms);
	else if (t == &c->probe)
		dispatch_tcp_probe_timeout(c, now_ms);
	else if (t == &c->tw)
		dispatch_tcp_timewait_timeout(c, now_ms);
	else
		dispatch_tcp_rto_timeout(c, now_ms);
}

/*
 * mtp/tcp.mtp SS-probe -- D-25 piece 2, the closed-window probe.
 *
 * WHAT IT IS FOR, AND IT IS NOT WHAT THE STALL TURNED OUT TO BE. The rx-driven
 * retry recovers a window whose reopening is ANNOUNCED; this recovers one whose
 * announcement is LOST. No retry can substitute for a message that never
 * arrives, and no run so far has produced that case -- which is exactly why
 * this would be easy to skip now that the symptom is gone. An absence that
 * currently produces the donor's behaviour is not agreement with the donor (A2).
 *
 * The donor's mechanism, from B:
 *   - a PURE ACK, zero payload, at seq = snd_nxt - 1. Deliberately OUTSIDE the
 *     peer's receive window, so the peer must answer it -- and it works against
 *     a non-mTCP peer because the standard requires an acknowledgement to an
 *     unacceptable segment.
 *   - gated on peer_wnd <= cwnd AND more than 500 ms since the last ACK WE
 *     SENT. Not received.
 *   - NO BACKOFF: the probe carries an ACK, so it resets its own clock.
 *
 * wack_sent is NOT reproduced: dead code in the donor, a per-call local on a
 * branch that returns immediately, so the predicate is just the timing.
 */
static void
send_window_probe(struct tcp_ctx *c, uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload none = { 0 };
	uint16_t hdr_len;

	if (c->send_wnd > c->cwnd)
		return;
	if (now - c->last_ack_sent_ms <= PARITY_PROBE_MS)
		return;

	hdr_len = tcp_build_header(hdr, c, c->send_next - 1, TCP_ACK, now,
				   c->ts_recent);
	INSTR(g_emit[EM_PROBE]++);
	mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, PRIO_ACK, 1,
		    0 /* not a retransmission */);
	mtp_timer_start(&c->probe, (uint64_t)PARITY_PROBE_MS * 1000000ULL);
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
	uint32_t rtx;		/* below the high-water mark: a retransmission */
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload pay;
	uint32_t win, to_send;
	uint16_t hdr_len;
	int why = REF_NODATA;

	if (!send_side_open(c)) {
		INSTR(g_refuse[REF_STATE]++);
		return;
	}

	win = c->cwnd < c->send_wnd ? c->cwnd : c->send_wnd;

	/*
	 * THE DISCRIMINATOR: available send window at the moment the program is
	 * asked to generate. Two opposite faults look identical from outside --
	 * window-limited (allowed to send nothing) and decision-limited (allowed
	 * to send and not doing it) -- and this one series separates them.
	 *
	 * Bucketed and accumulated, never logged per event. Instrumentation cost
	 * has been the measurement twice today; this is six compares and one
	 * increment on a path that already computes every term it needs.
	 */
	{
		int64_t avail = (int64_t)win
			      - (int64_t)(c->send_next - c->send_una);
		unsigned b;

		if (avail <= 0)			b = 0;
		else if (avail < 1448)		b = 1;
		else if (avail < 4 * 1448)	b = 2;
		else if (avail < 16 * 1448)	b = 3;
		else if (avail < 64 * 1448)	b = 4;
		else				b = 5;
		INSTR(g_avail_bucket[b]++);
		INSTR(g_avail_sum += avail > 0 ? (uint64_t)avail : 0);
		/* IN BYTES, and labelled as such. The binding-window figures
		 * below are COUNTS of decisions; reporting them beside a byte
		 * mean invited exactly the misreading that produced a derived
		 * round trip of 28 ms against a measured 843 us. */
		INSTR(g_cwnd_sum += c->cwnd);
		INSTR(g_inflight_sum += (uint64_t)(c->send_next - c->send_una));
		if (avail > (int64_t)g_avail_max)
			INSTR(g_avail_max = (uint64_t)avail);
		/* which of the two windows is the binding one, when either is */
		if (c->cwnd <= c->send_wnd)
			INSTR(g_bind_cwnd++);
		else
			INSTR(g_bind_peer++);
	}

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

		/*
		 * REVERTED, and the reason is a real one rather than caution.
		 *
		 * This counts GENERATED-unacknowledged, which under deferred
		 * segmentation includes blueprints still in the ring. Basing it
		 * on the emitted position instead -- which is what "in flight"
		 * ought to mean -- removed the only thing bounding GENERATION:
		 * with a backlog, emitted lags generated, in flight reads low,
		 * the loop generates further ahead, the ring fills and the flow
		 * stalls. Measured: 0, 0 and 4 completions in three 60-second
		 * runs at 128 MB against 28, 26 and 28 before the change, with
		 * 52 to 58 of 63 seconds silent.
		 *
		 * So this site is NOT a one-line substitution. The congestion
		 * window should bound what is on the wire while something else
		 * bounds how far generation may run ahead of it, and we have no
		 * second bound -- the conflation is currently what supplies it.
		 * Splitting them is a design change, not correctness work, and
		 * it is recorded in DESIGN.md §25 rather than done in passing.
		 */
		to_send = 0;
		for (;;) {
			uint32_t inflight_here = seq - c->send_una;
			int32_t rw = (int32_t)win - (int32_t)inflight_here;
			uint32_t avail_here, len, pkt;

			if (rw <= 0) {
				why = REF_WINDOW;
				break;
			}
			if (rw < PARITY_MSS_ADVERTISED && inflight_here > 0) {
				why = REF_SWS;
				/* what the rule is holding back, for
				 * comparison against the donor's mean */
				g_sws_rw = (uint32_t)rw;
				/*
				 * WHICH ARM OF THE MIN IS SMALL. rw is
				 * MIN(cwnd, peer) - inflight, and the three
				 * ways it can be under one MSS have three
				 * different owners: our congestion control,
				 * the peer's advertised window, or inflight
				 * being large. A mean of rw cannot tell them
				 * apart and neither can a mean of cwnd.
				 */
				INSTR(g_sws_cwnd += c->cwnd);
				INSTR(g_sws_peer += c->send_wnd);
				INSTR(g_sws_infl += inflight_here);
				INSTR(g_sws_bind[c->cwnd <= c->send_wnd ? 0 : 1]++);
				{
					unsigned k;
					uint32_t v;

					for (k = 0, v = 4096;
					     k < 5 && c->cwnd >= v; k++, v *= 4)
						;
					INSTR(g_sws_cwnd_h[k]++);
					for (k = 0, v = 4096;
					     k < 5 && c->send_wnd >= v;
					     k++, v *= 4)
						;
					INSTR(g_sws_peer_h[k]++);
				}
				break;
			}

			avail_here = c->write_end - (seq - c->snd_base);
			if (!avail_here) {
				why = REF_NODATA;
				/*
				 * WHAT THE FLOW LOOKS LIKE WHEN IT REPORTS
				 * NOTHING BUFFERED.
				 *
				 * The "backlog is large" branch is impossible
				 * here BY CONSTRUCTION -- avail_here == 0 IS
				 * this exit -- so the discriminating quantity
				 * is not the backlog but the RING HELD, which
				 * at this point equals what is in flight:
				 * held is written-minus-acknowledged and
				 * written has caught up with generated.
				 *
				 *   held near zero -> the flow is genuinely
				 *     idle, nothing outstanding and nothing
				 *     written: the application has not come
				 *     round to it. Starvation.
				 *
				 *   held large -> the flow has everything it
				 *     was given on the wire and is waiting for
				 *     acknowledgements. "Nothing buffered" is
				 *     true and misleading: the flow is not
				 *     starved, it is acknowledgement-bound,
				 *     and counting it as starvation overstates
				 *     the application's share.
				 */
				{
					uint64_t held = c->tx.tail_seq
						      - c->tx.head_seq;
					unsigned b;
					uint64_t lim;

					for (b = 0, lim = 4096;
					     b < 6 && held >= lim;
					     b++, lim *= 4)
						;
					INSTR(g_nodata_held[b]++);
					INSTR(g_nodata_held_sum += held);
					INSTR(g_nodata_n++);

					/*
					 * IS THE WINDOW ALREADY FULL HERE?
					 * If in-flight at this exit is at or
					 * above MIN(cwnd, peer), then we are
					 * window-blocked and reporting
					 * "nothing buffered" -- the exit is
					 * mislabelled and the application is
					 * not the constraint. If it is well
					 * below, we genuinely have room and
					 * nothing to put in it.
					 */
					{
						uint32_t win = c->cwnd < c->send_wnd
							     ? c->cwnd : c->send_wnd;

						INSTR(g_nodata_cwnd += c->cwnd);
						INSTR(g_nodata_peer += c->send_wnd);
						INSTR(g_nodata_infl += inflight_here);
						if (inflight_here >= win)
							INSTR(g_nodata_atwin++);
						else if (inflight_here + PARITY_MSS_ADVERTISED
							 >= win)
							INSTR(g_nodata_nearwin++);
					}
				}
				break;
			}

			len = avail_here < (uint32_t)rw ? avail_here : (uint32_t)rw;
			pkt = len < PARITY_MSS_PAYLOAD ? len : PARITY_MSS_PAYLOAD;

			to_send += pkt;
			seq += pkt;
		}
	}

	if (to_send == 0) {
		INSTR(g_refuse[why]++);
		if (why == REF_SWS) {
			/*
			 * WITHHELD ONLY WHEN NOTHING WENT OUT. The census
			 * records the loop's EXIT REASON and is counted only
			 * on the to_send == 0 path, so a hold-off here is a
			 * genuine deferral rather than "the loop filled the
			 * window and stopped".
			 */
			INSTR(g_sws_withheld += g_sws_rw);
			INSTR(g_sws_n++);
			if (g_sws_rw > g_sws_max)
				INSTR(g_sws_max = g_sws_rw);
		}
		/*
		 * D3: ASK TO BE ATTEMPTED AGAIN NEXT PASS. The donor keeps a
		 * window-blocked stream on its send list and retries every
		 * pass; we retried on EVENTS, which coincides with it whenever
		 * the window reopens BECAUSE an acknowledgement arrived, and
		 * differs for back-pressure that resolves without an inbound
		 * packet -- ring space freed by our own drain, most of all.
		 *
		 * Asked for on every refusal that has something to send, not
		 * only the window one: REF_SWS is also "held back, will go
		 * later", and REF_NODATA and REF_STATE have nothing to retry.
		 */
		if (why == REF_WINDOW || why == REF_SWS)
			mtp_retry(c->f);
		if (why == REF_WINDOW) {
			/*
			 * AND THE PROBE AS WELL, not instead. The retry
			 * recovers a window whose reopening is announced; this
			 * recovers one whose announcement was LOST, and no
			 * retry substitutes for a message that never arrives
			 * (D-25 piece 2).
			 */
			c->probe.ctx = c;
			mtp_timer_start(&c->probe,
					(uint64_t)PARITY_PROBE_MS * 1000000ULL);
		}
		if (why == REF_WINDOW && MTP_ENV_ON("MTP_TRACE_SEQ"))
			fprintf(stderr, "REFUSE window cwnd=%u peer=%u una=%u "
				"next=%u inflight=%u write_end=%u\n", c->cwnd,
				c->send_wnd, c->send_una, c->send_next,
				c->send_next - c->send_una, c->write_end);
		return;
	}
	INSTR(g_refuse[REF_SENT]++);

	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_ACK, now,
				   c->ts_recent);

	pay.u   = &c->tx;
	pay.off = c->send_next - c->snd_base;	/* into the unit, not the stream */

	if (MTP_ENV_ON("MTP_TRACE_SEQ"))
		fprintf(stderr, "SEND una=%u next=%u base=%u off=%llu len=%u "
			"inflight=%u\n", c->send_una, c->send_next, c->snd_base,
			(unsigned long long)pay.off, to_send,
			c->send_next - c->send_una);
	pay.len = to_send;

	/*
	 * Below the high-water mark is a retransmission, whoever asked. Marking
	 * the CALLER did not work: the timeout rewinds and its own send is
	 * refused, so the re-emission happens later from the acknowledgement
	 * path — the rewind and the re-send are separated in time.
	 */
	rtx = c->send_next < c->send_high;
	if (rtx) {
		INSTR(g_emit[EM_DATA_RTX]++);
		if (!c->in_rtx) {
			c->in_rtx = true;
			c->rtx_mark = c->send_high;
		}
		if (MTP_ENV_ON("MTP_TRACE_EV"))
			fprintf(stderr, "EV rtx off=%u len=%u\n",
				c->send_next - c->snd_base, to_send);
	} else {
		INSTR(g_emit[EM_DATA]++);
	}
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &pay, PARITY_MSS_PAYLOAD, PRIO_DATA, 1,
			rtx) == 0) {
		c->send_next += to_send;

		/* Arm the round-trip probe if one is not outstanding. O(1),
		 * no allocation, and at most one sample in flight per flow --
		 * the shape TCP's own RTTM uses, for the same reason. */
		if (!c->probe_us) {
			c->probe_seq = c->send_next;
			c->probe_us = mtp_now_us();
		}
		c->stage = ST_AWAIT_EMIT;
		c->stage_seq = c->send_next;
		g_stage_enter[ST_AWAIT_EMIT]++;
		if (c->send_next > c->send_high)
			c->send_high = c->send_next;
		if (unacked_on_wire(c))
			arm_rto(c);
	}
}

/*
 * mtp/tcp.mtp §record_data — application data arrives.
 *
 * The send buffer is created AT ESTABLISHMENT (CR-E), not lazily on first
 * write: the target buffers into it from the application thread and needs
 * f->tx_unit valid before the application's first write, which a lazy open
 * cannot promise. write_end is the program's own mirror of how
 * much it has appended — the target has no accessor to ask, and §2.4b's
 * withdrawal rests on exactly this working.
 */
int
tcp_app_send(struct tcp_ctx *c, uint32_t len, uint32_t now)
{
	/*
	 * CR-E: `len` is an EXTENT ALREADY IN THE RING, not a pointer to copy.
	 * The application thread put the bytes there through mtp_app_send and
	 * the target published the extent; this runs on the STACK thread, so
	 * tcp_gen_seg -- and with it send_next, cwnd and snd_base -- is touched
	 * by one thread only. Doing the generation on the application thread is
	 * the race this representation exists to remove.
	 */
	if (c->state == TCP_SYN_SENT) {
		gen_syn(c, now);	/* the handshake, not data */
		return 0;
	}
	if (!send_side_open(c))
		return -1;

	if (MTP_ENV_ON("MTP_TRACE_SEQ"))
		fprintf(stderr, "APPSEND state=%u extent=%u write_end=%u "
			"send_next=%u snd_base=%u cwnd=%u send_wnd=%u\n",
			c->state, len, c->write_end, c->send_next,
			c->snd_base, c->cwnd, c->send_wnd);

	tcp_gen_seg(c, now);
	return (int)len;
}

/*
 * mtp/tcp.mtp §record_data — the application's bytes into the transmit stream.
 *
 * RUNS ON THE CALLING THREAD, which is what makes the instruction below the
 * thing that causes the copy rather than a note about one that already
 * happened. It touches the stream and `write_end`; neither generates a packet,
 * so nothing here belongs to the stack.
 *
 * The count it returns is what the application is told it wrote. A short return
 * is back-pressure, not an error.
 */
static int
record_data(struct tcp_ctx *c, struct mtp_tx_addr addr, uint32_t len)
{
	int wrote;

	if (!send_side_open(c))
		return -1;
	if (!c->tx_open)
		return -1;		/* not established: no stream yet */

	wrote = mtp_add_tx_data(&c->tx, addr, len);
	if (wrote <= 0)
		return wrote;

	g_app_bytes += (uint64_t)wrote;
	c->write_end += (uint32_t)wrote;
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
/*
 * The program's terms for a flow, printed only from the target's
 * reference-fault dump (tx_stream.c). Zero cost until that path is taken.
 *
 * WHY THE TERMS AND NOT THE RESULT. The overshoot is exactly 27.00 MSS in two
 * separate runs at different absolute offsets. A race smears; a deterministic
 * multiple is a computation. So the thing to show is every quantity `upto` was
 * built from, as terms, because if the discrepancy is a base or a unit rather
 * than one wrong term, only the terms side by side make it obvious.
 *
 * The flush advances by `acked`, which is `e->ack - send_una` computed BEFORE
 * send_una was advanced -- so at fault time send_una already equals that ack.
 */
void
prog_dump_flow_state(void *owner)
{
	struct tcp_ctx *c = (struct tcp_ctx *)mtp_ctx_of((flow_t *)owner);

	if (!c) {
		fprintf(stderr, "  (no program context for this flow)\n");
		return;
	}
	fprintf(stderr,
		"  program terms:\n"
		"    state       = %d\n"
		"    send_una    = %u   (the ack just applied)\n"
		"    send_next   = %u\n"
		"    write_end   = %u   (highest byte the app has handed us)\n"
		"    una - next  = %d   (POSITIVE = acknowledged past what we sent)\n"
		"    next - una  = %u   (in flight)\n",
		c->state, c->send_una, c->send_next, c->write_end,
		(int32_t)(c->send_una - c->send_next),
		(uint32_t)(c->send_next - c->send_una));
	/* The unit's own fields are the TARGET's to print, and it does so above
	 * this in the same dump. src/program/ may not read them --
	 * tools/check_wiring.sh enforces that boundary and caught this when the
	 * dump was first written. */
}

void
mtp_program_coalesce(const uint8_t *hdr, uint16_t hdr_len,
		     uint8_t *class, uint32_t *key, bool *inherit_base,
		     uint16_t *keep_off, uint16_t *keep_len)
{
	uint8_t flags = hdr[TCPH_FLAGS];

	(void)hdr_len;

	/*
	 * The sequence number describes THIS SEGMENT'S PAYLOAD, so when the
	 * merge inherits the older payload origin it must inherit this too.
	 * Everything else in the header describes the receiver's state and must
	 * move forward — that is what C's review established, and taking the
	 * whole newer header took one field too many.
	 */
	*keep_off = TCPH_SEQ;
	*keep_len = 4;

	/* anything consuming sequence space stands alone */
	if (flags & (TCP_SYN | TCP_FIN | TCP_RST)) {
		*class = 0;
		return;
	}

	*class = 1;
	*key = flags;
	*inherit_base = true;
}
