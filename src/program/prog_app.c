/*
 * The application-interface half of the program: the socket ops this protocol
 * binds, and what they do.
 *
 * Compiler output, hand-written in the form `mtpc` would emit. The `.mtp`
 * source these come from:
 *
 *     app_parser socket {
 *         send    -> sock_send;
 *         recv    -> sock_recv;
 *         connect -> sock_open;
 *     }
 *
 * WHY `recv` IS BOUND. It is an event like any other event — there is no
 * special category, and §7a's remark that a stream socket's recv is
 * runtime-served describes what the example program happens to do rather than a
 * rule. This program needs the event: the donor recomputes its advertised
 * window when the application drains (api.c:1141), and a program that is never
 * told the application drained cannot reproduce that. Without it a connection
 * that reaches a zero window has nothing to reopen it.
 *
 * Increment 1 has no dispatch and no event processors, so what is here is the
 * window rule and the two points it is recomputed at — the part that had to be
 * written down before the target's read accessors were withdrawn, to prove the
 * withdrawal took nothing parity needs. The rest of the program lands with the
 * transport, and `mtp/tcp.mtp` is written whole rather than as a fragment: a
 * partial program file that does not describe the running system is exactly the
 * failure the difference report records against the prototype's own `tcp.mtp`.
 */
#include <stdio.h>
#include <stdlib.h>

#include "contract.h"
#include "prog_params.h"
#include "prog_ctx.h"

/*
 * The donor's rule, in one place so there is one place to be wrong.
 *
 *     rcv_wnd = capacity - merged_len
 *
 * where merged_len is the in-order bytes held but not yet taken by the
 * application. Both terms are this program's own state — `recv_next` is the
 * variable the cumulative ACK is built from, and `delivered` accumulates what
 * mtp_rx_flush_and_notify() reports it handed over — so no target accessor is
 * involved, which is what makes the withdrawal safe.
 *
 * The subtraction is in sequence space and wraps, as everything else here does.
 */
static void
recompute_rcv_wnd(struct tcp_ctx *c)
{
	/*
	 * G14. A FIN CONSUMES A SEQUENCE NUMBER AND IS NOT DATA, so once one
	 * has been accepted `recv_next` is one ahead of anything the
	 * application can ever take. Counting that byte as held advertises a
	 * window one short for the rest of the connection — and, because it is
	 * exactly one, it is indistinguishable on the wire from the legitimate
	 * "one byte held and undrained" case.
	 *
	 * The program knows the stream ended; the target cannot, which is why
	 * the difference report puts this on the program's side.
	 */
	uint32_t held = (uint32_t)(c->recv_next - c->delivered);

	if (c->fin_consumed && held)
		held--;

	c->rcv_wnd = PARITY_RCVBUF_SIZE - held;
}

/*
 * RECOMPUTE POINT 1 — payload merged in order. from mTCP tcp_in.c:659.
 * Called from the receive processor after add_rx_data_seg has advanced the
 * in-order edge, and not from anywhere else: the donor does not recompute on a
 * pure ACK, on an out-of-order segment, or on a retransmission that adds no new
 * in-order bytes, and neither may this.
 */
void
tcp_on_payload_merged(struct tcp_ctx *c, uint32_t new_recv_next)
{
	c->recv_next = new_recv_next;
	recompute_rcv_wnd(c);
}

/*
 * RECOMPUTE POINT 2 — the application drained. from mTCP api.c:1141.
 * This is the op-parser for the socket's `recv`, and the only reason the op is
 * bound. `delivered` is what mtp_rx_flush_and_notify() returned, so the
 * accounting cannot drift from what the target actually handed over.
 *
 * The window that results is advertised on the next segment this flow sends —
 * one main-loop iteration later, as the donor does it. B established that
 * mTCP's application thread never emits a packet, so deferring by one iteration
 * is the donor's behaviour and not a shortcut.
 */
void
sock_recv(struct tcp_ctx *c, uint32_t delivered_now)
{
	c->delivered += delivered_now;
	recompute_rcv_wnd(c);

	/*
	 * D11. Generation is the stack's, so this only ASKS: the retry list
	 * runs the send chain on the stack thread, and that is where the
	 * window update is built. See tcp_app_send.
	 */
	if (c->need_wnd_adv && c->rcv_wnd > PARITY_MSS_PAYLOAD)
		mtp_retry(c->f);

	/*
	 * PRINTED SEPARATELY, on purpose. Three mechanisms run here for the
	 * first time — the flush instruction's return, `delivered`'s advance,
	 * and this recompute. If the window is wrong, one number cannot say
	 * which of the three moved; three can. Collapsing them into one
	 * observable is how three runs went on the retransmit path.
	 */
	if (MTP_ENV_ON("MTP_TRACE_SEQ"))
		fprintf(stderr, "RECV got=%u delivered=%u recv_next=%u "
			"held=%u rcv_wnd=%u field=%u\n",
			delivered_now, c->delivered, c->recv_next,
			(uint32_t)(c->recv_next - c->delivered), c->rcv_wnd,
			tcp_window_field(c, 0));
}

/*
 * What goes in the header's window field. Unscaled on a SYN, because window
 * scaling is not in effect until the handshake completes; shifted thereafter.
 *
 * This is the whole of the observed sequence 14600 -> 14592 -> 2048:
 *   - rcv_wnd starts at 14600 and nothing recomputes it until payload arrives,
 *     so a SYN carries 14600 and every non-SYN before the first payload carries
 *     14600 >> 7 = 114, which the peer reads back as 14592;
 *   - after payload has been merged and drained, rcv_wnd is the full 262144 and
 *     the field is 2048.
 *
 * A VALUE ONE BELOW 2048 IS CORRECT, NOT AN OFF-BY-ONE. Between the merge and
 * the application's read the bytes are held, so the window is RCVBUF minus
 * what is held: one byte held advertises 2047. Observed on the wire
 * 2026-08-13. Anyone "fixing" this to an unconditional 2048 would be removing
 * the mechanism, and would only find out from a trace diff.
 */
uint16_t
tcp_window_field(const struct tcp_ctx *c, int is_syn)
{
	if (is_syn)
		return (uint16_t)c->rcv_wnd;
	return (uint16_t)(c->rcv_wnd >> PARITY_WSCALE);
}
