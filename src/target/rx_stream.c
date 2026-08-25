/*
 * The receive data unit.
 *
 * Same shape as the transmit ring and the same independence: capacity is a
 * parameter, nothing here reaches infra.h, so it is testable without a NIC.
 *
 * OUT-OF-ORDER SEGMENTS ARE STORED, at their own offset. That is the donor's
 * shape as well as ours: mTCP calls RBPut unconditionally (tcp_in.c:645) and
 * has no out-of-order branch in its receive path at all, because the
 * reassembly is one level down, inside the buffer.
 *
 * `head_seq` is the first byte still held and `tail_seq` is one past the last
 * CONTIGUOUSLY held byte -- the boundary the application may read to. Bytes
 * beyond a gap are in the ring and are not readable, which is exactly the
 * property that makes a hole invisible to everything downstream: `tail_seq`
 * advances over the contiguous prefix only, while later segments sit stored.
 *
 * THE WINDOW IS WHAT KNOWS WHERE THE HOLES ARE. This file does no interval
 * arithmetic of its own; it marks what arrived and reads back a boundary.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "contract.h"
#include "internal.h"

static inline uint32_t rx_off(const struct mtp_data_unit *u, uint64_t seq)
{
	return (uint32_t)((seq - u->head_seq + (u->head_seq & (u->cap - 1)))
			  & (u->cap - 1));
}

/* Returns the ring. Called once, from FlowDestroy. */
void
tgt_rx_unit_fini(struct mtp_data_unit *u)
{
	free(u->buf);
	u->buf = NULL;
	u->cap = 0;
}

int
tgt_rx_unit_init(struct mtp_data_unit *u, uint64_t size, uint32_t cap,
		 uint64_t base)
{
	memset(u, 0, sizeof(*u));
	u->size = size;
	u->cap = cap;
	u->head_seq = base;
	u->tail_seq = base;
	u->established = base ? 1 : 0;
	mtp_sw_init(&u->arrived, base);
	u->buf = malloc(u->cap);
	return u->buf ? 0 : -1;
}

/* mtp_new_rx_ordered_data lives in scheduler.c, where CONFIG is visible —
 * same split as the transmit side: the ring takes its capacity as a parameter
 * and knows nothing about a configuration system. */

int
mtp_add_rx_data_seg(struct mtp_data_unit *u, struct mtp_rx_addr addr,
		    uint32_t len, uint64_t offset)
{
	uint32_t at, first;

	if (!len)
		return 0;
	/*
	 * The FIRST segment establishes the base. A receive stream's offsets
	 * are the peer's sequence numbers, which the target may not derive —
	 * the peer's ISN is protocol knowledge — so the unit adopts the first
	 * offset it is given rather than assuming zero. That is the receive
	 * side's bridge, and putting it here means nothing downstream converts.
	 */
	if (!u->established) {
		u->head_seq = offset;
		u->tail_seq = offset;
		u->established = 1;
		mtp_sw_init(&u->arrived, offset);
	}

	/*
	 * Wholly behind the boundary: every byte has already been delivered or
	 * is already held. Not an error and not a refusal -- a retransmission
	 * the peer sent because our acknowledgement was lost looks exactly like
	 * this, and it must not read as a failure to store.
	 */
	if ((int64_t)(offset + len - u->head_seq) <= 0)
		return 0;
	/* the part below the boundary is already here; keep the rest */
	if ((int64_t)(offset - u->head_seq) < 0) {
		uint64_t skip = u->head_seq - offset;

		addr.data += skip;
		len -= (uint32_t)skip;
		offset = u->head_seq;
	}
	if (offset + len - u->head_seq > u->cap)
		return -1;			/* would overrun the window */

	at = rx_off(u, offset);
	first = u->cap - at;
	if (first >= len) {
		memcpy(u->buf + at, addr.data, len);
	} else {
		memcpy(u->buf + at, addr.data, first);
		memcpy(u->buf, addr.data + first, len - first);
	}
	/*
	 * Mark, then slide. The boundary lands wherever the arrivals reach --
	 * one past this segment if it was in order, unchanged if it sits past a
	 * gap, past several segments at once if this one filled the gap. There
	 * is no in-order branch because there does not need to be one.
	 */
	{
		uint64_t before = u->tail_seq;

		mtp_sw_set(&u->arrived, offset, offset + len);
		u->tail_seq = mtp_sw_slide(&u->arrived);

		/*
		 * THE ARRIVAL EDGE, and it did not exist.
		 *
		 * READABLE was raised in exactly one place on this side: the
		 * re-arm at the bottom of mtp_rx_flush_and_notify, AFTER a read.
		 * Nothing raised it when data first arrived.
		 *
		 * A SERVER NEVER NOTICED. Its application registers interest on
		 * a socket it has just accepted, by which time the request is
		 * already in the stream, and mtp_ready_arm's registration edge
		 * finds it. A CLIENT registers before any data exists: that edge
		 * finds nothing, data then arrives, and nobody is told. Measured
		 * before the fix: the 256 KB receive buffer filled completely
		 * before the application was woken once, and it was woken about
		 * once a second thereafter.
		 *
		 * Only when the in-order boundary MOVES. Bytes stored past a gap
		 * are not readable, so they are not an edge, and the whole point
		 * of tail_seq is that it answers exactly this question.
		 */
		if (u->tail_seq > before && u->tail_seq > u->head_seq &&
		    u->owner && tgt_ready_edge)
			tgt_ready_edge(u->owner, MTP_NOTIF_READABLE);
	}
	return (int)len;
}

/*
 * Hand the next in-order bytes to the application and report HOW MANY.
 *
 * The return value is load-bearing: it is the only way a program learns that
 * the application drained, and §7.2's advertised-window rule is written on it —
 * recompute point 2, which has never run because this instruction has never
 * been called.
 */
int
mtp_rx_flush_and_notify(struct mtp_data_unit *u, uint32_t len,
			struct mtp_rx_addr addr)
{
	uint32_t held = (uint32_t)(u->tail_seq - u->head_seq);
	uint32_t at, first;
	uint8_t *dst = (uint8_t *)addr.data;

	if (len > held)
		len = held;
	if (!len || !dst)
		return 0;

	at = rx_off(u, u->head_seq);
	first = u->cap - at;
	if (first >= len) {
		memcpy(dst, u->buf + at, len);
	} else {
		memcpy(dst, u->buf + at, first);
		memcpy(dst + first, u->buf, len - first);
	}
	u->head_seq += len;

	/*
	 * THE SHORT READ RE-ARMS, AND IT DOES SO HERE, INSIDE THE READ.
	 * docs/DESIGN-READINESS.md. Not after the read in the caller: a read
	 * that empties the stream concurrently with an arrival would then lose
	 * the arrival, and with no poll-time re-evaluation to repair it that
	 * loss is permanent. This is the one placement the design cannot get
	 * wrong quietly.
	 */
	if (u->tail_seq > u->head_seq && u->owner && tgt_ready_edge)
		tgt_ready_edge(u->owner, MTP_NOTIF_READABLE);
	return (int)len;
}
