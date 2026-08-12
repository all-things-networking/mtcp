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

	/*
	 * The bases of every committed-and-undrained blueprint referencing this
	 * unit, oldest first. This is what internal.h §3's assertion reads and
	 * what tells the flush whether it must drain first.
	 *
	 * A FIFO rather than a single low-water mark, because a single mark
	 * cannot be raised when the oldest reference is released — it only ever
	 * knows how to fall. References are taken in increasing sequence order
	 * and released in the same order (the ring drains FIFO), so a ring of
	 * bases is exact and costs one slot per blueprint.
	 */
	uint64_t	 ref_base[BP_RING_DEPTH];
	uint16_t	 ref_head, ref_tail;
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

	/*
	 * The donor's running sndbuf, from its configuration.
	 *
	 * `size` is read only to reject what is not yet built: a bounded unit —
	 * a message, which is how Homa and QUIC use this instruction — would
	 * size its buffer from its own length. That path does not exist. TCP
	 * passes MTP_SIZE_INF and gets the configured buffer, and anything else
	 * fails loudly rather than silently getting a TCP-shaped buffer.
	 */
	assert(size == MTP_SIZE_INF);

	/*
	 * off_of() masks with cap-1, so the capacity must be a power of two.
	 * The donor's running config is 262144 = 2^18 and config.c only
	 * enforces >= 64, so `sndbuf = 100000` is an ordinary thing to write
	 * and would silently corrupt every wrap. Round up and say so.
	 */
	u->cap = 1;
	while (u->cap < (uint32_t)CONFIG.sndbuf_size)
		u->cap <<= 1;
	if (u->cap != (uint32_t)CONFIG.sndbuf_size)
		TRACE_CONFIG("sndbuf %d is not a power of two; the transmit "
			     "ring uses %u. Set sndbuf to a power of two to "
			     "keep the buffer size the donor is measured "
			     "with.\n", CONFIG.sndbuf_size, u->cap);

	u->buf = malloc(u->cap);
	if (!u->buf) {
		TRACE_ERROR("could not allocate a %u byte transmit ring\n", u->cap);
		u->cap = 0;
	}
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

	if (u->live_refs && upto > u->ref_base[u->ref_head]) {
		TransportOf(core)->forced_drains++;
		tgt_drain(core);
	}

	/* Now our own invariant must hold. This never accuses the program: a
	 * failure here means the drain above did not do its job. */
	assert(!u->live_refs || upto <= u->ref_base[u->ref_head]);

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

	assert(u->live_refs < BP_RING_DEPTH);
	u->ref_base[u->ref_tail] = seq;
	u->ref_tail = (uint16_t)((u->ref_tail + 1) % BP_RING_DEPTH);
	u->live_refs++;
	return 0;
}

/*
 * Liveness ENDS when the drain has copied the blueprint's last byte into an
 * mbuf — internal.h §3 — so this is called once per blueprint, from the drain,
 * after its final segment and not per segment.
 *
 * Nothing called it for one commit, which is worth recording rather than
 * quietly fixing: live_refs only ever rose, so the oldest base stayed pinned at
 * the first byte the flow ever sent. In a debug build the first flush past the
 * first data packet would have tripped an assertion written to catch the
 * target; with NDEBUG it would have taken the forced-drain branch on every
 * flush for ever, cutting every coalescing run short. It would have passed
 * traffic and benchmarked cleanly while handing back the mechanism the whole
 * comparison rests on.
 */
void
tgt_tx_ref_release(struct mtp_data_unit *u)
{
	if (!u->live_refs)
		return;
	u->ref_head = (uint16_t)((u->ref_head + 1) % BP_RING_DEPTH);
	u->live_refs--;
}
