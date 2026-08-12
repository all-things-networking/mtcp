/*
 * The transmit data unit: a TRUE RING, and the payload references taken out of
 * it.
 *
 * mTCP's send buffer re-linearises with a memmove when it wraps, and
 * re-derives the payload pointer inside the same lock hold that copies from it.
 * That is what makes the donor safe. This one never moves bytes, so a
 * blueprint's snapshot stays valid without a lock — which is P1 — and the wrap
 * is carried in the reference instead (§0a's five pieces, built together with
 * the coalescing per D-06).
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "flow.h"
#include "target_core.h"
#include "debug.h"

/*
 * Opaque to the program and to contract.h. The generated context embeds a
 * pointer to one of these per unit it declares, so a protocol has exactly as
 * many as it needs and no signature widens.
 */
struct mtp_data_unit {
	uint8_t		*buf;
	uint32_t	 cap;		/* a power of two: the ring's wrap mask */
	uint64_t	 size;		/* MTP_SIZE_INF, or a message length */

	uint64_t	 head_seq;	/* first byte still held */
	uint64_t	 tail_seq;	/* one past the last byte held */

	/* the oldest committed-and-undrained blueprint referencing this unit,
	 * and how many there are. This is what internal.h §3's assertion reads
	 * and what tells the flush whether it must drain first. */
	uint64_t	 live_ref_base;
	uint32_t	 live_refs;
};

static inline uint32_t off_of(const struct mtp_data_unit *u, uint64_t seq)
{
	return (uint32_t)((seq - u->head_seq + (u->head_seq & (u->cap - 1)))
			  & (u->cap - 1));
}

/*----------------------------------------------------------------------------*/
void
mtp_new_tx_ordered_data(struct mtp_data_unit *u, uint64_t size)
{
	memset(u, 0, sizeof(*u));
	u->size = size;
	/* the donor's running sndbuf, from its configuration. A byte stream
	 * gets the configured buffer; a message gets its own length rounded up,
	 * which is the same instruction parameterised by data. */
	u->cap = (uint32_t)CONFIG.sndbuf_size;
	u->buf = malloc(u->cap);
}

int
mtp_add_tx_data(struct mtp_data_unit *u, struct mtp_tx_addr addr, uint32_t len)
{
	uint32_t held = (uint32_t)(u->tail_seq - u->head_seq);
	uint32_t space = u->cap - held;
	uint32_t at, first;

	if (len > space)
		len = space;
	if (!len)
		return 0;

	/* split at the wrap; NO memmove. mTCP's re-linearisation is the first
	 * of §0a's five pieces and it is the one that makes a resolved pointer
	 * unsafe. */
	at = off_of(u, u->tail_seq);
	first = u->cap - at;
	if (first >= len) {
		memcpy(u->buf + at, addr.base, len);
	} else {
		memcpy(u->buf + at, addr.base, first);
		memcpy(u->buf, (const uint8_t *)addr.base + first, len - first);
	}
	u->tail_seq += len;
	return (int)len;
}

/*----------------------------------------------------------------------------*/
/*
 * Retire the first `len` bytes.
 *
 * N-A: the reference a program handed to pkt_gen is valid until the program
 * flushes that range, and the program flushing is what ends it — so this call
 * is always legitimate and can never be a program error.
 *
 * The difficulty is ours. We defer packet generation, so at this moment we may
 * still be holding that reference in an undrained blueprint, and we need it to
 * live a little longer than the contract promises. So we DRAIN FIRST. Nothing
 * is declined; the cost is one early drain in a case that is rare, and it cuts
 * a coalescing run short, which is why it is counted.
 */
int
mtp_tx_flush_and_notify(struct mtp_data_unit *u, uint32_t len)
{
	struct core_ctx *core = g_core[0];	/* single core; see scheduler.c */
	uint64_t upto = u->head_seq + len;

	if (u->live_refs && upto > u->live_ref_base) {
		TransportOf(core)->forced_drains++;
		tgt_drain(core);
	}

	/* Now our own invariant must hold. This never accuses the program: a
	 * failure here means the drain above did not do its job. */
	assert(!u->live_refs || upto <= u->live_ref_base);

	if (upto > u->tail_seq)
		upto = u->tail_seq;
	u->head_seq = upto;
	return 0;
}

/*----------------------------------------------------------------------------*/
/*
 * Resolve [seq, seq+len) into a reference the drain can dereference without
 * touching this unit again — the one copy of a computation that appears nine
 * times across two of the prototype's sibling branches.
 *
 * Fails and leaves *out untouched if the range is not wholly held. Returning a
 * plausible pointer near the base is exactly how the sweep's out-of-bounds case
 * happens.
 */
int
tgt_tx_ref(struct mtp_data_unit *u, uint64_t seq, uint32_t len, payref_t *out)
{
	uint32_t at, to_end;

	if (seq < u->head_seq || seq + len > u->tail_seq)
		return -1;

	at = off_of(u, seq);
	to_end = u->cap - at;

	out->data = u->buf + at;
	out->len = len;
	if (to_end >= len) {
		out->wraps = false;
		out->wrap_at_seq = 0;
		out->wrap_data = NULL;
	} else {
		/* C traced the exact-boundary case and established it is safe;
		 * the note is carried here so nobody re-derives the worry. */
		out->wraps = true;
		out->wrap_at_seq = seq + to_end;
		out->wrap_data = u->buf;
	}

	if (!u->live_refs || seq < u->live_ref_base)
		u->live_ref_base = seq;
	u->live_refs++;
	return 0;
}

void
tgt_tx_ref_release(struct mtp_data_unit *u)
{
	if (u->live_refs)
		u->live_refs--;
}
