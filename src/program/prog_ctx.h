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
	uint32_t send_una;	/* oldest unacknowledged */
	uint32_t send_next;	/* next to send */
	uint32_t write_end;	/* highest app byte appended */
	uint32_t send_wnd;	/* the peer's advertised window */
	uint32_t cwnd, ssthresh;

	/* --- the peer's timestamp, echoed in ours ------------------------ */
	uint32_t ts_recent;

	/* --- the data units, embedded, per CR-3 -------------------------- */
	/* Embedded BY VALUE (D-19): the context owns the storage and
	 * new_tx_ordered_data initialises it. The ring buffer inside is still
	 * allocated lazily on first write, which IS the donor's shape — mTCP
	 * takes its send buffer from a pool on first send, not at accept. */
	struct mtp_data_unit tx;
	struct mtp_data_unit rx;
	bool     tx_open;	/* new_tx_ordered_data issued (lazily, as the
				 * donor allocates its send buffer lazily) */
};

/* from the program's `context` initialiser */
#define TCP_CTX_INIT	{ .rcv_wnd = PARITY_INITIAL_WINDOW }

void     tcp_on_payload_merged(struct tcp_ctx *c, uint32_t new_recv_next);
void     sock_recv(struct tcp_ctx *c, uint32_t delivered_now);
uint16_t tcp_window_field(const struct tcp_ctx *c, int is_syn);
uint16_t tcp_build_header(uint8_t *out, const struct tcp_ctx *c, uint32_t seq,
			  uint8_t flags, uint32_t ts_val, uint32_t ts_ecr);
void     tcp_gen_seg(struct tcp_ctx *c, uint32_t now);
int      tcp_app_send(struct tcp_ctx *c, const void *data, uint32_t len,
		      uint32_t now);

#endif /* PROG_CTX_H */
