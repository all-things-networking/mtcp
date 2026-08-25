#ifndef PROG_CTX_H
#define PROG_CTX_H
/*
 * Compiler output: the context struct, from the program's `context` block.
 *
 * Under CR-3 the context IS this generated struct — the target does not hand
 * out an opaque block and does not know what is in it. Granularity is declared
 * in `deploy` (per-flow here).
 *
 * Increment 1 declares only the receive-window state, because that is the only
 * rule written so far. The rest arrives with the transport.
 */
#include <stdint.h>
#include <stdbool.h>

#include "contract.h"
#include "prog_params.h"

/* TCP connection states. M1c exercises passive open through teardown. */
#define TCP_CLOSED	0
#define TCP_LISTEN	1
#define TCP_SYN_RCVD	2
#define TCP_ESTABLISHED	3
#define TCP_CLOSE_WAIT	4
#define TCP_LAST_ACK	5
/* the active-close path — DESIGN-CLOSE.md §4. Absent until 2026-08-13, which
 * is why we could not initiate a close at all against a peer that never
 * closes first. */
#define TCP_FIN_WAIT_1	6
#define TCP_FIN_WAIT_2	7
#define TCP_CLOSING	8	/* simultaneous close */
#define TCP_TIME_WAIT	9
/* the ACTIVE-open path, absent until 2026-08-25 for the same reason: nothing
 * we ran ever opened a connection, so the state had no way to be entered. */
#define TCP_SYN_SENT	10

/*
 * mtp/tcp.mtp §tcp_listen_ctx — ONE INSTANCE PER LISTENING ENDPOINT.
 *
 * It was a single file-scope struct, so the program could hold exactly one
 * listening socket (DEFERRED.md D4). There is no granularity keyword in MTP: a
 * context is declared, there are as many instances as the protocol needs, and
 * the endpoint being a FIELD of the context is what makes several listeners
 * possible without any new machinery.
 *
 * It is stored like any other context, under a key the PROGRAM builds from
 * (ip, port) — see key_of_listener. The target holds no listener table and no
 * matching rule: "match on address AND port" is a statement about TCP (G8, and
 * the donor matches on port alone), and protocol policy does not belong in
 * target infrastructure.
 */
struct tcp_listen_ctx {
	flow_t  *f;			/* the target's handle, first, as above */

	uint32_t local_ip;		/* network order, compared against iph->daddr */
	uint16_t local_port;		/* host order */
	uint8_t  state;			/* ST_CLOSED until listen(); then ST_LISTEN */

	/*
	 * THE ACCEPT BACKLOG (C3/C4). `pending_cap` is protocol state: a SYN
	 * arriving with the queue full must be dropped, and the cap is what
	 * makes that decision expressible in the program rather than in the
	 * target — or, as it is today, in the compatibility shim.
	 */
	uint32_t pending_cap;
	uint32_t pending_n;
	flow_t  *pending[PROG_MAX_BACKLOG];

	/*
	 * The object the application has posted to serve, per listener rather
	 * than per process. A one-shot server hands it over once and every
	 * accepted connection receives it; that is what epserver does with a
	 * file, and it is enough to drive bulk send.
	 *
	 * It arrives through the app interface as a SEND op, not as something
	 * this program invented — the bytes are the application's and the
	 * program only decides when they go.
	 */
	const void *obj;
	uint32_t    obj_len;
};

struct tcp_ctx {
	/*
	 * The target's handle for this flow, placed here by the target when it
	 * creates the context. The compiler emits the context struct, so it can
	 * put a target handle in it; the program passes it back to pkt_gen and
	 * notify and never looks inside.
	 */
	flow_t  *f;

	uint8_t  state;

	/* --- receive side, sequence space ------------------------------- */
	/*
	 * The receive side's bridge, named for symmetry with snd_base. The peer's
	 * SYN consumes one, so the first data byte it sends is at ISN+1, and
	 * `delivered` is seeded here rather than at zero — otherwise
	 * §window_rule subtracts a sequence number from a byte count. That is
	 * the same bug as the send side's, in the same week, and the two were
	 * found separately because neither bridge had a name. They do now.
	 */
	uint32_t rcv_base;	/* sequence of the first data byte the peer sends */

	uint32_t recv_next;	/* next in-order sequence expected; the cumulative ACK */

	/*
	 * mtp/tcp.mtp: `sliding_wnd rx_wnd`. THE WINDOW TRACKS THE HOLES, which
	 * is what the primitive is for, so the program keeps nothing beside it:
	 * no held-run list, no out-of-order counter, no in-order branch. Mark
	 * what arrived, slide, read the boundary back.
	 *
	 * The target's receive unit keeps one of its own, for the boundary the
	 * APPLICATION may read to. The arithmetic is done twice because the two
	 * boundaries answer different questions and the contract has no read
	 * side by which either could ask the other -- withdrawn deliberately,
	 * see contract.h. Two small tables per flow is the price of that.
	 */
	struct mtp_sliding_wnd rx_wnd;
	uint32_t delivered;	/* what the application has taken, accumulated from
				 * mtp_rx_flush_and_notify()'s return value */

	/*
	 * The advertised window, as PROTOCOL STATE rather than a buffer query.
	 * Initialised to the donor's constant and recomputed at exactly two
	 * points (prog_app.c). Answering every packet with the buffer's free
	 * space instead would advertise 2048 from the first ACK and never emit
	 * 14592 at all — a divergence in the first RTT of every connection.
	 */
	uint32_t rcv_wnd;

	/* --- endpoints, for building outbound headers -------------------- */
	uint16_t loc_port, rem_port;
	/*
	 * The endpoints, in network order. The PASSIVE open never needed them:
	 * every packet it answers arrives with them, and pkt_gen takes the flow
	 * whose route the target already resolved. An ACTIVE open has to build
	 * the first packet with no packet to copy from, and a reset built from
	 * a context goes out through the orphan path, which takes addresses
	 * rather than a flow.
	 */
	uint32_t local_ip, remote_ip;

	/* --- send side, sequence space ----------------------------------- */
	/*
	 * TWO SPACES, and conflating them is the fifth instance of the class in
	 * docs/PLAN.md §3. The transmit unit's offsets start at 0. The sequence
	 * space starts at the ISN, and the SYN CONSUMES ONE, so the first data
	 * byte is sequence ISN+1. snd_base is that, and it is the only bridge
	 * between the two — anything relating a unit offset to a sequence
	 * number goes through it.
	 */
	uint32_t snd_base;	/* sequence of unit offset 0 */

	uint32_t send_una;	/* oldest unacknowledged */
	uint32_t send_next;	/* next to send */
	uint32_t write_end;	/* highest app byte appended */
	uint32_t send_wnd;	/* the peer's advertised window, ALREADY SCALED */
	uint8_t  snd_wscale;	/* the shift the peer asked for on its SYN */
	uint32_t cwnd, ssthresh;

	/*
	 * THE DONOR'S WINDOW-UPDATE AND DUPLICATE-ACKNOWLEDGEMENT STATE.
	 *
	 * snd_wl1/snd_wl2 are RFC 793's: the sequence and acknowledgement
	 * numbers of the segment that last moved the peer's window. They decide
	 * whether a segment updates the window at all, and the duplicate test
	 * then asks whether the window's right edge MOVED -- which is why
	 * counting duplicates needs them and why send_wnd could not simply be
	 * assigned on every acknowledgement as it was.
	 *
	 * D-01 already recorded snd_wl1 as a divergence masked by the ISN
	 * freeze. It stops being masked here.
	 */
	uint32_t snd_wl1, snd_wl2;
	/*
	 * The window's right edge as it stood BEFORE this segment was allowed
	 * to move it. The donor computes it at the top of ProcessACK
	 * (tcp_in.c:326) and compares against it after the update, which is how
	 * "the advertised window did not change" is expressed. Captured by
	 * proc_window, read by proc_fast_retransmit, and meaningless outside
	 * one chain.
	 */
	uint32_t right_wnd_edge;
	uint32_t last_ack_seq;	/* the last acknowledgement number seen, for the
				 * "ack_seq is old and unchanged" half */
	uint32_t dup_acks;	/* consecutive duplicates, reset by any
				 * non-duplicate */

	/* --- the peer's timestamp, echoed in ours ------------------------ */
	uint32_t ts_recent;
	/*
	 * PAWS runs only against a peer that uses timestamps, and the donor
	 * decides that once, from the SYN's options (tcp_util.c:47-51 sets
	 * saw_timestamp and seeds ts_recent there). A peer that sent none is not
	 * PAWS-checked at all -- so this is not an optimisation, it is the
	 * condition the check is defined under.
	 */
	bool     saw_timestamp;

	/* The retransmission estimator, from the donor. NO FLOOR AND NO
	 * CEILING (differences.md §1.1), so on this testbed the effective
	 * timeout is about 3 ms — roughly twenty times the measured round
	 * trip. A retransmission on an idle link is therefore a real event. */
	/* One outstanding round-trip probe per flow: sequence to clear it and
	 * the microsecond it was generated. Measurement only -- srtt below is
	 * the protocol's estimate and is in the donor's 1 ms ticks. */
	/* Which stage of the send loop this flow is waiting in, and the sequence
	 * that clears the current one. Occupancy is accumulated against the clock
	 * (see prog_sample_inflight), never as an average of per-event samples:
	 * a per-event mean is resample-biased and cost us a factor of ~2.3 once
	 * already. */
	/*
	 * When send_una last moved. Time since then is a LOWER BOUND on the age
	 * of the oldest unacknowledged byte, and unlike a probe it can be
	 * sampled while the flow is stuck -- a flow frozen for 50 ms is seen
	 * fifty times, not once. That is the only way to see a tail an
	 * event-armed probe cannot arm during.
	 */
	uint64_t una_advanced_us;

	/*
	 * In loss recovery: a retransmission is outstanding and the
	 * acknowledgement for it has not arrived. Splits the in-flight integral
	 * so Little's law can be applied to retransmitted and clean bytes
	 * separately -- the two must reconstruct the overall loop, which is the
	 * check that the split is sound.
	 */
	uint32_t rtx_mark;
	bool     in_rtx;

	uint8_t  stage;
	uint32_t stage_seq;
	uint32_t probe_seq;
	uint64_t probe_us;

	uint32_t srtt;		/* scaled by 8, as the donor keeps it */
	uint32_t mdev;		/* the donor's mean deviation; rttvar tracks it */
	uint32_t rttvar;
	uint32_t rto_ms;
	bool     have_rtt;	/* a sample has been taken; rto_ms is live */

	uint32_t rtx_count;

	/* CR-2/CR-6: a timer object embedded here, bound to tcp_timeout. */
	struct mtp_timer rto;

	/* --- the data units, embedded, per CR-3 -------------------------- */
	/* Embedded BY VALUE (D-19): the context owns the storage and
	 * new_tx_ordered_data initialises it. The ring buffer inside is still
	 * allocated lazily on first write, which IS the donor's shape — mTCP
	 * takes its send buffer from a pool on first send, not at accept. */
	struct mtp_data_unit tx;
	struct mtp_data_unit rx;
	bool     tx_open;
	/*
	 * A FIN is outstanding. It CONSUMES SEQUENCE SPACE AND CARRIES NO
	 * PAYLOAD, so the wire-based unacked test -- emitted payload against
	 * acknowledged payload -- cannot see it, and without this the
	 * retransmission timer is never armed for a FIN that is the only thing
	 * left. Condition B, and section 21.1 constraint 5: the answer is in
	 * the design, not in a reaper.
	 */
	bool     fin_pending;
	uint32_t fin_seq;
	/*
	 * The application has closed its send direction. The peer's FIN closes
	 * the peer's path only (D-20: the rule is per-path), so our FIN waits
	 * for this. A one-shot server sets it when it hands over its object.
	 */
	bool     app_closed;
	uint32_t send_high;	/* highest send_next ever reached; below it is
				 * a retransmission (see prog_tcp.c) */
	/* TIME_WAIT's own timer. A SECOND timer object on one flow, which is
	 * the first time the wheel has held more than one — A4 leaving the
	 * dormant list, with the standing expectation attached. */
	struct mtp_timer tw;
	/* D-25 piece 2: the closed-window probe. A THIRD timer on one flow. */
	struct mtp_timer probe;
	/* idle_reaping: a FOURTH. The donor keeps one ordered list and walks it
	 * per tick; a per-flow timer is a different mechanism with the same
	 * observable -- 30 s without activity and the connection is gone. */
	struct mtp_timer idle;
	uint32_t last_ack_sent_ms;	/* the probe's 500 ms is since OUR ack */
	/* our own copy of the key, so a timer that outlives the packet path can
	 * still name the context to destroy (D-24) */
	flowkey_t key;
	/* The endpoint that accepted this connection. Its object is what a
	 * one-shot server serves, and its context is where the handshake's
	 * readable event belongs. */
	struct tcp_listen_ctx *lst;
	bool     rx_open;
	bool     fin_consumed;	/* the peer's FIN took a sequence number */	/* new_tx_ordered_data issued (lazily, as the
				 * donor allocates its send buffer lazily) */
};

/* from the program's `context` initialiser */
#define TCP_CTX_INIT	{ .rcv_wnd = PARITY_INITIAL_WINDOW }

/* How many flows the in-flight sampler tracks. Sized to the configured
 * concurrency ceiling; a run beyond it under-reports rather than corrupting. */
#define MTP_MAX_FLOWS_SAMPLED 1024

/* Stages of one turn of the send loop. IDLE is separated from the rest so a
 * flow with nothing to send is never counted as latency. */
enum { ST_IDLE = 0, ST_AWAIT_DECISION, ST_AWAIT_EMIT, ST_AWAIT_ACK, ST__N };

void     prog_sample_inflight(uint64_t now_us);
void     tcp_on_payload_merged(struct tcp_ctx *c, uint32_t new_recv_next);
void     sock_recv(struct tcp_ctx *c, uint32_t delivered_now);
uint16_t tcp_window_field(const struct tcp_ctx *c, int is_syn);
/* NOT const: it stamps last_ack_sent_ms, which the window probe's gate reads.
 * See the definition. */
uint16_t tcp_build_header(uint8_t *out, struct tcp_ctx *c, uint32_t seq,
			  uint8_t flags, uint32_t ts_val, uint32_t ts_ecr);
void     tcp_gen_seg(struct tcp_ctx *c, uint32_t now);
/* CR-E: `len` is an EXTENT ALREADY IN THE RING, not a pointer to copy.
 * The application thread buffers via mtp_app_send; this runs on the stack. */
int      tcp_app_send(struct tcp_ctx *c, uint32_t len, uint32_t now);

#endif /* PROG_CTX_H */
