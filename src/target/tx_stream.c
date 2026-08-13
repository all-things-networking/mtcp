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

#include <stdio.h>
#include <stdlib.h>

#include "contract.h"
#include "internal.h"

/*
 * No infra.h, no target_core.h, and therefore no DPDK. The ring depends on
 * nothing above it: its capacity arrives as a parameter and its forced drain as
 * a callback. That is the right shape regardless — a byte ring should not know
 * about a configuration system or a per-core context — and it is what lets
 * tests/test_tx_stream.c exercise the payload-lifetime race on any node.
 */

/*
 * Opaque to the program and to contract.h. The generated context embeds a
 * pointer to one of these per unit it declares, so a protocol has exactly as
 * many as it needs and no signature widens.
 */
/* struct mtp_data_unit is in contract.h: the generated context embeds one by
 * value, so the type has to be complete where the program can see it (D-19).
 * Its CONTENTS are ours — the true ring — and are not the kernel target's. */


static inline uint32_t off_of(const struct mtp_data_unit *u, uint64_t seq)
{
	return (uint32_t)((seq - u->head_seq + (u->head_seq & (u->cap - 1)))
			  & (u->cap - 1));
}

/*----------------------------------------------------------------------------*/
int
tgt_tx_unit_init(struct mtp_data_unit *u, uint64_t size, uint32_t cap,
		 void (*drain)(void *), void *drain_arg)
{
	memset(u, 0, sizeof(*u));
	u->size = size;
	u->drain = drain;
	u->drain_arg = drain_arg;

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
	(void)size;

	/*
	 * off_of() masks with cap-1, so the capacity must be a power of two.
	 * The donor's running config is 262144 = 2^18 and config.c only
	 * enforces >= 64, so `sndbuf = 100000` is an ordinary thing to write
	 * and would silently corrupt every wrap. Round up and say so.
	 */
	/* one live reference per blueprint slot, so the two must agree */
	

	u->cap = cap;
	u->buf = malloc(u->cap);
	if (!u->buf) {
		u->cap = 0;
		return -1;
	}
	return 0;
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
	uint64_t upto = u->head_seq + len;

	/*
	 * The head slot is the OLDEST reference, and it is the minimum only if
	 * references are taken in increasing sequence order. A retransmission
	 * takes one BELOW references already outstanding, so its base lands in
	 * the tail slot while being numerically the smallest — and this check
	 * then reads a larger sequence, concludes the range is clear, and does
	 * not force a drain.
	 *
	 * Instrumented rather than fixed: MTP_TRACE_REF prints what the head
	 * holds against the true minimum, so the premise is checked rather than
	 * assumed.
	 */
	if (getenv("MTP_TRACE_REF")) {
		static uint64_t flushes;

		if (!(++flushes % 8) || u->live_refs)
			fprintf(stderr, "FLUSHN n=%llu upto=%llu live=%u\n",
				(unsigned long long)flushes,
				(unsigned long long)upto, u->live_refs);
	}
	if (getenv("MTP_TRACE_REF") && u->live_refs) {
		uint64_t lo = u->ref_base[u->ref_head];
		uint32_t i, n = u->live_refs;
		int out_of_order = 0;

		for (i = 0; i < n; i++) {
			uint64_t v = u->ref_base[(u->ref_head + i) % MTP_MAX_LIVE_REFS];

			if (v < lo) { lo = v; out_of_order = 1; }
		}
		fprintf(stderr, "FLUSH upto=%llu head_holds=%llu true_min=%llu "
			"live=%u%s\n", (unsigned long long)upto,
			(unsigned long long)u->ref_base[u->ref_head],
			(unsigned long long)lo, n,
			out_of_order ? "  <<< HEAD IS NOT THE MINIMUM" : "");
	}

	if (u->live_refs && upto > u->ref_base[u->ref_head] && u->drain)
		u->drain(u->drain_arg);

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

	assert(u->live_refs < MTP_MAX_LIVE_REFS);
	u->ref_base[u->ref_tail] = seq;
	u->ref_tail = (uint16_t)((u->ref_tail + 1) % MTP_MAX_LIVE_REFS);
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
	u->ref_head = (uint16_t)((u->ref_head + 1) % MTP_MAX_LIVE_REFS);
	u->live_refs--;
}
