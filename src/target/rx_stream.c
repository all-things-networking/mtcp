/*
 * The receive data unit.
 *
 * Same shape as the transmit ring and the same independence: capacity is a
 * parameter, nothing here reaches infra.h, so it is testable without a NIC.
 *
 * IN-ORDER ONLY. M1 excludes out-of-order reassembly (both references have it,
 * so its absence is a parity gap and it is declared in tcp.mtp's absence
 * register). A segment that does not start at the unit's tail is REFUSED
 * rather than buffered, and the caller must not advance its receive sequence.
 * Refusing loudly is the point: silently accepting one would put a hole in the
 * delivered stream that only a content check would ever find.
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
	}

	if (offset != u->tail_seq)
		return -1;			/* out of order: refused */
	if (u->tail_seq - u->head_seq + len > u->cap)
		return -1;			/* would overrun the window */

	at = rx_off(u, offset);
	first = u->cap - at;
	if (first >= len) {
		memcpy(u->buf + at, addr.data, len);
	} else {
		memcpy(u->buf + at, addr.data, first);
		memcpy(u->buf, addr.data + first, len - first);
	}
	u->tail_seq += len;
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
	return (int)len;
}
