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

	/* --- the peer's timestamp, echoed in ours ------------------------ */
	uint32_t ts_recent;

	/* The retransmission estimator, from the donor. NO FLOOR AND NO
	 * CEILING (differences.md §1.1), so on this testbed the effective
	 * timeout is about 3 ms — roughly twenty times the measured round
	 * trip. A retransmission on an idle link is therefore a real event. */
	/* One outstanding round-trip probe per flow: sequence to clear it and
	 * the microsecond it was generated. Measurement only -- srtt below is
	 * the protocol's estimate and is in the donor's 1 ms ticks. */
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
	uint32_t last_ack_sent_ms;	/* the probe's 500 ms is since OUR ack */
	/* our own copy of the key, so a timer that outlives the packet path can
	 * still name the context to destroy (D-24) */
	flowkey_t key;
	bool     rx_open;
	bool     fin_consumed;	/* the peer's FIN took a sequence number */	/* new_tx_ordered_data issued (lazily, as the
				 * donor allocates its send buffer lazily) */
};

/* from the program's `context` initialiser */
#define TCP_CTX_INIT	{ .rcv_wnd = PARITY_INITIAL_WINDOW }

/* How many flows the in-flight sampler tracks. Sized to the configured
 * concurrency ceiling; a run beyond it under-reports rather than corrupting. */
#define MTP_MAX_FLOWS_SAMPLED 1024

void     prog_sample_inflight(uint64_t now_us);
void     tcp_on_payload_merged(struct tcp_ctx *c, uint32_t new_recv_next);
void     sock_recv(struct tcp_ctx *c, uint32_t delivered_now);
uint16_t tcp_window_field(const struct tcp_ctx *c, int is_syn);
uint16_t tcp_build_header(uint8_t *out, const struct tcp_ctx *c, uint32_t seq,
			  uint8_t flags, uint32_t ts_val, uint32_t ts_ecr);
void     tcp_gen_seg(struct tcp_ctx *c, uint32_t now);
/* CR-E: `len` is an EXTENT ALREADY IN THE RING, not a pointer to copy.
 * The application thread buffers via mtp_app_send; this runs on the stack. */
int      tcp_app_send(struct tcp_ctx *c, uint32_t len, uint32_t now);

#endif /* PROG_CTX_H */
