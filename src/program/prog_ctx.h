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

#include "contract.h"
#include "prog_params.h"

struct tcp_ctx {
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

	/* --- the data units, embedded, per CR-3 -------------------------- */
	struct mtp_data_unit *tx;
	struct mtp_data_unit *rx;
};

/* from the program's `context` initialiser */
#define TCP_CTX_INIT	{ .rcv_wnd = PARITY_INITIAL_WINDOW }

void     tcp_on_payload_merged(struct tcp_ctx *c, uint32_t new_recv_next);
void     sock_recv(struct tcp_ctx *c, uint32_t delivered_now);
uint16_t tcp_window_field(const struct tcp_ctx *c, int is_syn);

#endif /* PROG_CTX_H */
