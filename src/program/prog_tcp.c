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
#include <stdio.h>
#include <stdlib.h>
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
       EM_DATA, EM_DATA_RTX, EM__N };
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
	g_emit[EM_SYNACK]++;
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1) == 0) {
		c->send_next++;			/* the SYN-ACK consumes one */
		c->snd_base = c->send_next;	/* ...so data starts one past */
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
enum { TMR_RTO, TMR_TIMEWAIT, TMR_PROBE, TMR__N };
static uint64_t g_tmr[TMR__N];

enum { RXS_DISPATCH, RXS_CTX, RXS_ACK_CALLED, RXS_ACK_NOFLAG, RXS_ACK_DUP,
       RXS_ACK_ADVANCED, RXS_RST, RXS_ACK_PAST_NEXT, RXS__N };
static uint64_t g_rx[RXS__N];

void
prog_report_refusals(void)
{
	static const char *n[REF__N] = { "state-gate", "window-closed",
					 "sws-holdoff", "nothing-buffered",
					 "SENT" };
	static const char *r[RXS__N] = { "reached dispatch", "flow ctx found",
					 "proc_ack called", "  no ACK flag",
					 "  DUPLICATE/STALE", "  ADVANCED una",
					 "INBOUND RST (discarded)",
		"ack past send_next" };
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
						  "window-probe" };
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
	mtp_notify(c->f, &(struct mtp_notif){ .kind = MTP_NOTIF_STATE });

	/* the application posted an object before listening; serve it */
	if (prog_listener.obj_len) {
		tcp_app_send(c, prog_listener.obj, prog_listener.obj_len, now);
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
/* mtp/tcp.mtp §proc_ack — an acknowledgement of our data. */
static void
proc_ack(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	uint32_t acked;

	g_rx[RXS_ACK_CALLED]++;
	if (!conn_exists(c) || !(e->flags & TCP_ACK)) {
		g_rx[RXS_ACK_NOFLAG]++;
		return;
	}

	c->send_wnd = (uint32_t)e->window << c->snd_wscale;
	c->ts_recent = e->ts_val;

	acked = e->ack - c->send_una;
	if ((int32_t)acked <= 0) {
		g_rx[RXS_ACK_DUP]++;
		/*
		 * ADVANCES NOTHING, BUT IT IS STILL AN EVENT. The window above
		 * has just been refreshed from this segment, and a peer whose
		 * window reopens tells us with exactly this: ack == send_una,
		 * a larger window, no new data acknowledged. Returning here
		 * used the segment and then discarded it, so we learned the
		 * window had reopened and never acted on it, and the flow
		 * stalled with data buffered and a window that was open.
		 *
		 * The donor reaches the same place by a different route: it
		 * puts the stream on the send list and re-runs the flush every
		 * event-loop iteration. A closed window can only reopen by the
		 * peer telling us, and that telling is an rx event, so an
		 * rx-driven retry and a per-iteration retry are observably
		 * identical — there is nothing to retry between segments. That
		 * is why this needs no new entry point and the contract's
		 * three keep their monopoly (D-15/D-16).
		 */
		tcp_gen_seg(c, now);
		return;
	}
	g_rx[RXS_ACK_ADVANCED]++;

	if (getenv("MTP_TRACE_SEQ"))
		fprintf(stderr, "ACK  ack=%u una=%u next=%u acked=%u%s\n",
			e->ack, c->send_una, c->send_next, acked,
			(int32_t)(c->send_next - e->ack) < 0
			? "  <<< ack PAST send_next" : "");

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
	 */
	if ((int32_t)(e->ack - c->send_next) > 0) {
		/*
		 * COUNTED UNCONDITIONALLY. The print above is getenv-gated and
		 * no run has ever enabled it, so "has this ever happened?" was
		 * unanswerable from every log we hold -- absence of the string
		 * was absence of the INSTRUMENT, not absence of the condition.
		 * A counter costs an increment on a path already taken.
		 */
		g_rx[RXS_ACK_PAST_NEXT]++;
		c->send_next = e->ack;
		c->cwnd = c->ssthresh;
	}

	c->send_una = e->ack;
	estimate_rtt(c, now, e->ts_ecr);
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
	if (getenv("MTP_TRACE_SEQ"))
		fprintf(stderr, "PROCRECV state=%u seq=%u recv_next=%u paylen=%u "
			"flags=0x%x\n", c->state, e->seq, c->recv_next,
			e->payload_len, e->flags);
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
	if (e->seq + 1 == c->recv_next) {
		uint8_t phdr[PROG_HDR_MAX];
		struct mtp_tx_payload none = { 0 };
		uint16_t plen = tcp_build_header(phdr, c, c->send_next, TCP_ACK,
						 now, c->ts_recent);

		g_emit[EM_PROBE_REPLY]++;
		mtp_pkt_gen(c->f, phdr, plen, &none, 0, 0, 1);
		return;
	}

	if (!e->payload_len)
		return;
	if (e->seq != c->recv_next)
		return;			/* out of order: M2, and it does not
					 * fire at -c 1 on a clean LAN */

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

		if (mtp_add_rx_data_seg(&c->rx, a, e->payload_len, e->seq) < 0)
			return;		/* refused: not in order, M2 */
	}

	/* §window_rule recompute point 1: payload merged in order. Nothing
	 * else in this program may write rcv_wnd. */
	tcp_on_payload_merged(c, c->recv_next + e->payload_len);

	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_ACK, now,
				   c->ts_recent);
	g_emit[EM_ACK_DATA]++;
	mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1);
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
proc_fin(struct tcp_ctx *c, const struct tcp_ev *e, uint32_t now)
{
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload none = { 0 };
	uint16_t hdr_len;

	if (!(e->flags & TCP_FIN))
		return;
	if (!recv_side_open(c))
		return;
	if (e->seq != c->recv_next)
		return;			/* a FIN ahead of a gap does not
					 * transition; the segment that fills
					 * the hole performs it (C) */

	c->recv_next = e->seq + 1;	/* the FIN consumes one byte */
	c->fin_consumed = true;		/* ...which is not data: G14 */

	/* built before the transition, deliberately */
	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_ACK, now,
				   c->ts_recent);
	g_emit[EM_ACK_FIN]++;
	mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1);

	/*
	 * DESIGN-CLOSE.md §4. Where the peer's FIN takes us depends on whether
	 * we have already sent ours; CLOSING is the simultaneous close, one row
	 * and worth it — leaving it out wedges exactly the way the missing
	 * active close did.
	 */
	if (c->state == TCP_FIN_WAIT_1)
		c->state = TCP_CLOSING;
	else if (c->state == TCP_FIN_WAIT_2)
		enter_time_wait(c);
	else
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

	if (getenv("MTP_TRACE_SEQ") && c->state == TCP_CLOSE_WAIT)
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

	hdr_len = tcp_build_header(hdr, c, c->send_next,
				   TCP_ACK | TCP_FIN, now, c->ts_recent);
	g_emit[EM_FIN]++;
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1) == 0) {
		c->send_next++;		/* the FIN consumes one byte */
		c->state = (c->state == TCP_CLOSE_WAIT) ? TCP_LAST_ACK
							: TCP_FIN_WAIT_1;
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

	g_rx[RXS_CTX]++;
	/*
	 * INBOUND RST, counted and nothing else. DESIGN-CLOSE.md §5 records that
	 * this program has no RST path: a peer that has gone away answers our
	 * retransmissions with a reset and we discard it. That was written down
	 * as a known absence before the between-transfer frame flood existed, and
	 * it predicts exactly that shape — so it is worth TESTING, not believing.
	 * If resets are not arriving in quantity, the reading is dead.
	 */
	if (e.flags & TCP_RST)
		g_rx[RXS_RST]++;
	proc_open_done(c, &e, now_ms);
	proc_ack(c, &e, now_ms);
	proc_recv(c, &e, now_ms);
	proc_fin(c, &e, now_ms);
	gen_fin(c, now_ms);

	/*
	 * The acknowledgement of OUR FIN. Runs after proc_fin, so a packet
	 * carrying both the peer's FIN and the acknowledgement of ours takes
	 * FIN_WAIT_1 -> CLOSING here and then CLOSING -> TIME_WAIT, which is
	 * DESIGN-CLOSE.md §4's "peer FIN and ack of ours -> TIME_WAIT" row
	 * without needing a row of its own.
	 */
	if ((e.flags & TCP_ACK) && e.ack == c->send_next) {
		if (c->state == TCP_LAST_ACK) {
			c->state = TCP_CLOSED;
			mtp_del_ctx(&k);
		} else if (c->state == TCP_FIN_WAIT_1) {
			c->state = TCP_FIN_WAIT_2;
		} else if (c->state == TCP_CLOSING) {
			enter_time_wait(c);
		}
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
		c->app_closed = true;
		gen_fin(c, now_ms);
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
		got = mtp_rx_flush_and_notify(&c->rx, op->len, a);
		if (got > 0)
			sock_recv(c, (uint32_t)got);
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

		if (getenv("MTP_TRACE_SEQ"))
			fprintf(stderr, "APPOP send now=%u flow=%p len=%u\n",
				now_ms, (void *)op->flow, op->len);
		if (!op->flow) {
			prog_listener.obj = op->data.base;
			prog_listener.obj_len = op->len;
			return 0;
		}
		c = (struct tcp_ctx *)mtp_ctx_of(op->flow);
		if (!c)
			return -1;
		return tcp_app_send(c, op->data.base, op->len, now_ms);
	}
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

	/*
	 * D-24 — TIME_WAIT expiring. Reproduces the DONOR'S GUARD, not its
	 * timer value: even at tcp_timewait = 0 the state must be entered and
	 * left, because skipping it does not skip a wait, it removes the place
	 * the final acknowledgement is owed from. The acknowledgement was
	 * committed to the target in the iteration that entered this state, so
	 * by the time this fires it has drained and the context can go.
	 *
	 * NOTHING RETRANSMITS THAT ACKNOWLEDGEMENT, deliberately: the donor does
	 * not. If it is lost the stream is already gone, the peer's retransmitted
	 * FIN finds no flow-table entry and is answered with a bare RST, and
	 * teardown completes on that instead. That is wire-observable when it
	 * happens, and it is the donor's behaviour rather than an omission.
	 */
	if (t == &c->probe) {
		g_tmr[TMR_PROBE]++;
		send_window_probe(c, now_ms);
		return;
	}
	if (t == &c->tw) {
		g_tmr[TMR_TIMEWAIT]++;
		c->state = TCP_CLOSED;
		mtp_del_ctx(&c->key);
		return;
	}

	g_tmr[TMR_RTO]++;
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
	if (getenv("MTP_TRACE_SEQ"))
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
	g_emit[EM_PROBE]++;
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &none, 0, 0, 1) == 0)
		c->last_ack_sent_ms = now;
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
	uint8_t hdr[PROG_HDR_MAX];
	struct mtp_tx_payload pay;
	uint32_t win, to_send;
	uint16_t hdr_len;
	int why = REF_NODATA;

	if (!send_side_open(c)) {
		g_refuse[REF_STATE]++;
		return;
	}

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

			if (rw <= 0) {
				why = REF_WINDOW;
				break;
			}
			if (rw < PARITY_MSS_ADVERTISED && inflight_here > 0) {
				why = REF_SWS;
				break;
			}

			avail_here = c->write_end - (seq - c->snd_base);
			if (!avail_here) {
				why = REF_NODATA;
				break;
			}

			len = avail_here < (uint32_t)rw ? avail_here : (uint32_t)rw;
			pkt = len < PARITY_MSS_PAYLOAD ? len : PARITY_MSS_PAYLOAD;

			to_send += pkt;
			seq += pkt;
		}
	}

	if (to_send == 0) {
		g_refuse[why]++;
		if (why == REF_WINDOW) {
			c->probe.ctx = c;
			mtp_timer_start(&c->probe,
					(uint64_t)PARITY_PROBE_MS * 1000000ULL);
		}
		if (why == REF_WINDOW && getenv("MTP_TRACE_SEQ"))
			fprintf(stderr, "REFUSE window cwnd=%u peer=%u una=%u "
				"next=%u inflight=%u write_end=%u\n", c->cwnd,
				c->send_wnd, c->send_una, c->send_next,
				c->send_next - c->send_una, c->write_end);
		return;
	}
	g_refuse[REF_SENT]++;

	hdr_len = tcp_build_header(hdr, c, c->send_next, TCP_ACK, now,
				   c->ts_recent);

	pay.u   = &c->tx;
	pay.off = c->send_next - c->snd_base;	/* into the unit, not the stream */

	if (getenv("MTP_TRACE_SEQ"))
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
	if (c->send_next < c->send_high) {
		g_emit[EM_DATA_RTX]++;
		if (getenv("MTP_TRACE_EV"))
			fprintf(stderr, "EV rtx off=%u len=%u\n",
				c->send_next - c->snd_base, to_send);
	} else {
		g_emit[EM_DATA]++;
	}
	if (mtp_pkt_gen(c->f, hdr, hdr_len, &pay, PARITY_MSS_PAYLOAD, 0, 1) == 0) {
		c->send_next += to_send;
		if (c->send_next > c->send_high)
			c->send_high = c->send_next;
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

	if (!send_side_open(c))
		return -1;

	if (!c->tx_open) {
		mtp_new_tx_ordered_data(&c->tx, MTP_SIZE_INF);
		c->tx_open = true;
	}

	addr.base = data;
	addr.len = len;
	wrote = mtp_add_tx_data(&c->tx, addr, len);
	/*
	 * BYTES THE APPLICATION HANDED US, in total. Splits the problem in half:
	 * if the application wrote ~1 MB per connection and the wire carried
	 * ~11 MB, the transport is re-sending; if it wrote ~11 MB, the transport
	 * is faithfully sending what it was given and the fault is above this
	 * line. A client that reads its 1 MB and closes would never notice.
	 */
	if (wrote > 0)
		g_app_bytes += (uint64_t)wrote;
	if (getenv("MTP_TRACE_SEQ"))
		fprintf(stderr, "APPSEND state=%u len=%u wrote=%d write_end=%u "
			"send_next=%u snd_base=%u cwnd=%u send_wnd=%u\n",
			c->state, len, wrote, c->write_end, c->send_next,
			c->snd_base, c->cwnd, c->send_wnd);
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
