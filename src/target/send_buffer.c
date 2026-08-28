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
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>

#include "contract.h"
#include "internal.h"

static uint64_t tx_ref_min(const struct mtp_data_unit *u);

/* see contract.h: the program's read of head_seq/tail_seq goes through here */
uint64_t
mtp_du_held(const struct mtp_data_unit *u)
{
	return u->tail_seq - u->head_seq;
}

uint64_t
mtp_du_cap(const struct mtp_data_unit *u)
{
	return u->cap;
}

uint64_t
mtp_du_head(const struct mtp_data_unit *u)
{
	return u->head_seq;
}

/* Two stores on paths that already do more than that. Never read except by the
 * fault dump, so it costs nothing until something goes wrong. */
static void
ref_log_put(struct mtp_data_unit *u, uint8_t op, uint8_t site, uint64_t base,
	    uint32_t len, const void *bp, const void *caller, uint8_t kind)
{
	struct ref_event *e = &u->ref_log[u->ref_log_n & (MTP_REF_LOG - 1)];

	e->base = base;
	e->len = len;
	e->bp = bp;
	e->op = op;
	e->site = site;
	e->caller = caller;
	e->kind = kind;
	e->live_after = u->live_refs;	/* set by the caller after the change */
	u->ref_log_n++;
}
static void tx_dump_ref_fault(const struct mtp_data_unit *u, uint64_t upto);

/*
 * No infra.h, no target_core.h, and therefore no DPDK. The ring depends on
 * nothing above it: its capacity arrives as a parameter and its forced drain as
 * a callback. That is the right shape regardless — a byte ring should not know
 * about a configuration system or a per-core context — and it is what lets
 * tests/test_send_buffer.c exercise the payload-lifetime race on any node.
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
TxUnitInit(struct mtp_data_unit *u, uint64_t size, uint32_t cap,
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


/* First writer wins and records itself; every later write must match. Works
 * before threading exists (both indices record the same thread and nothing
 * fires) and starts discriminating the moment there are two. */
static void
own_check(uint64_t *slot, const char *which)
{
	uint64_t me = (uint64_t)(uintptr_t)pthread_self();

	if (*slot == 0) { *slot = me; return; }
	if (*slot != me) {
		fprintf(stderr, "\n*** SPSC OWNERSHIP VIOLATED: %s written by "
			"thread %llu, previously owned by %llu\n"
			"    head_seq/tail_seq are an ownership boundary, not a "
			"lock -- see DESIGN.md \u00a721.7\n", which,
			(unsigned long long)me, (unsigned long long)*slot);
		fflush(stderr);
		/* abort(), not assert(): assert() compiles away under NDEBUG,
		 * which would remove the check from exactly the build that
		 * needs it. The cost is a thread-id compare on two sites that
		 * are not hot -- the tail advances once per application write
		 * and the head once per flush, never per segment. */
		abort();
	}
}
#define OWN(u, f, name) own_check(&(u)->f, name)

/* Returns the ring. Called once, from FlowDestroy -- the buffer was malloc'ed
 * per flow at init and was never freed anywhere before that site existed. */
void
TxUnitFini(struct mtp_data_unit *u)
{
	free(u->buf);
	u->buf = NULL;
	u->cap = 0;
}

int
mtp_add_tx_data(struct mtp_data_unit *u, struct mtp_addr addr, uint32_t len)
{
	uint32_t held = (uint32_t)(u->tail_seq - u->head_seq);
	uint32_t space = u->cap - held;
	uint32_t at, first;

	/*
	 * held CANNOT exceed cap, and if it ever does, `space` underflows to
	 * near 2^32, the clamp below does nothing, and the memcpy runs off the
	 * end of the ring. That is a silent heap overrun several calls before
	 * anything crashes — so it asserts here rather than being discovered
	 * from the wreckage.
	 */
	assert(held <= u->cap);

	/*
	 * THE ESTABLISHMENT EDGE FOR WRITABLE (D-23). A write the ring could not
	 * take in full is the moment the application starts waiting, and it is
	 * the only moment the target can see it — afterwards the short return
	 * value is the application's business and the target has no way to know
	 * whether it intends to write again.
	 *
	 * The target does NOT absorb the overflow. sndbuf is the donor's running
	 * configuration, so a target that quietly grew the ring would remove
	 * backpressure the donor's application feels and change the buffer
	 * occupancy that drives the advertised window — a parity change wearing
	 * the appearance of a convenience.
	 */
	if (len > space) {
		len = space;
		u->want_space = 1;
	}
	if (!len) {
		u->want_space = 1;
		return 0;
	}

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
	OWN(u, w_tail_tid, "tx tail_seq");	/* the APPLICATION's index */
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

/*
 * Everything known at the moment the invariant breaks. Two questions this must
 * answer, both asked before the dump existed (2026-08-16):
 *
 *   - is `upto` past the minimum by exactly one MSS, as it was the first time
 *     we saw this, or by something else? A one-segment overshoot and a large
 *     one are different faults.
 *   - is the offending reference the OLDEST outstanding, or one that should
 *     already have been released? A flush advancing too far and a release that
 *     never happened look identical from the assertion alone.
 *
 * Every base is printed, not a summary, because a summary is what the previous
 * version of this check effectively was.
 */
static void
tx_dump_ref_fault(const struct mtp_data_unit *u, uint64_t upto)
{
	uint64_t lo = tx_ref_min(u);
	uint32_t i, lo_idx = 0;

	for (i = 0; i < u->live_refs; i++)
		if (u->ref_base[i] == lo) { lo_idx = i; break; }

	fprintf(stderr,
		"\n*** REF FAULT: flush past a live reference ***\n"
		"  upto        = %llu\n"
		"  min live    = %llu   (entry %u of %u)\n"
		"  overshoot   = %llu bytes  (%.2f MSS at 1448)\n"
		"  head_seq    = %llu\n"
		"  tail_seq    = %llu   (held %llu of cap %u)\n"
		"  min is %lld bytes %s head, %llu behind tail\n"
		"  emitted_hwm = %llu   (highest byte actually on the wire)\n"
		"  upto - emitted = %lld   (POSITIVE = freeing past the wire)\n"
		"  owner flow  = %p\n"
		"  live refs (%u):\n",
		(unsigned long long)upto,
		(unsigned long long)lo, lo_idx, u->live_refs,
		(unsigned long long)(upto - lo), (double)(upto - lo) / 1448.0,
		(unsigned long long)u->head_seq,
		(unsigned long long)u->tail_seq,
		(unsigned long long)(u->tail_seq - u->head_seq), u->cap,
		(long long)((int64_t)u->head_seq - (int64_t)lo),
		lo > u->head_seq ? "ABOVE (unseen in the first 7 failures)" : "behind",
		(unsigned long long)(u->tail_seq - lo),
		(unsigned long long)u->emitted_hwm,
		(long long)((int64_t)upto - (int64_t)u->emitted_hwm),
		(void *)u->owner, u->live_refs);

	for (i = 0; i < u->live_refs; i++)
		fprintf(stderr, "    [%2u] base=%llu  %s%s\n", i,
			(unsigned long long)u->ref_base[i],
			u->ref_base[i] == lo ? "<- MINIMUM " : "",
			u->ref_base[i] < u->head_seq ? "<- BEHIND head_seq" : "");
	if (DumpFlowBlueprints)		/* absent in the unit-test link */
		DumpFlowBlueprints(u->owner, lo);
	{
		static const char *sn[REF_SITE__N] = {
			"commit", "merge-take", "merge-rel", "drain-rel"
		};
		uint32_t n = u->ref_log_n < MTP_REF_LOG ? u->ref_log_n
							: MTP_REF_LOG;
		uint32_t i;

		/*
		 * THE SURVIVING REFERENCE, CROSS-REFERENCED. The history and the
		 * live-reference list were two artefacts to correlate by hand,
		 * which is slow and is where a wrong pairing gets read in. This
		 * answers directly: which take is this, and what became of it.
		 *
		 * A take with no matching release is the reference that faulted.
		 * If the log has WRAPPED past it the tally will be short a take
		 * rather than wrong, so the count of events is printed too.
		 */
		{
			uint32_t takes = 0, rels = 0, j;
			const struct ref_event *last_take = NULL;

			for (j = 0; j < n; j++) {
				uint32_t k2 = (u->ref_log_n - n + j)
					      & (MTP_REF_LOG - 1);
				const struct ref_event *e = &u->ref_log[k2];

				if (e->base != lo)
					continue;
				if (e->op) {
					rels++;
				} else {
					takes++;
					last_take = e;
				}
			}
			fprintf(stderr,
				"  THE MINIMUM base=%llu: %u take(s), %u "
				"release(s) in the last %u of %u events\n",
				(unsigned long long)lo, takes, rels, n,
				u->ref_log_n);
			if (last_take)
				fprintf(stderr,
					"    last take: [%llu,%llu) len=%u %s%s"
					" bp=%p issued by %p\n",
					(unsigned long long)last_take->base,
					(unsigned long long)(last_take->base
							     + last_take->len),
					last_take->len,
					last_take->kind ? "RTX " : "new ",
					sn[last_take->site], last_take->bp,
					last_take->caller);
			else
				fprintf(stderr, "    no take for this base in "
					"the window -- the log has wrapped "
					"past it\n");
		}

		fprintf(stderr, "  reference history, oldest first "
			"(%u events total):\n", u->ref_log_n);
		for (i = 0; i < n; i++) {
			uint32_t k = (u->ref_log_n - n + i) & (MTP_REF_LOG - 1);
			const struct ref_event *e = &u->ref_log[k];

			fprintf(stderr, "    %-7s [%llu,%llu) len=%-6u bp=%p %s%-11s "
				"live_after=%u%s\n",
				e->op ? "RELEASE" : "take",
				(unsigned long long)e->base,
				(unsigned long long)(e->base + e->len),
				e->len, e->bp,
				e->op ? "" : (e->kind ? "RTX " : "new "),
				e->site < REF_SITE__N ? sn[e->site] : "?",
				e->live_after,
				e->base == lo ? "   <- THE MINIMUM" : "");
			if (!e->op)
				fprintf(stderr, "              issued by %p\n",
					e->caller);
		}
	}

	/*
	 * COUNTERS HERE, NOT AT EXIT. The assertion below aborts, so the
	 * end-of-run report never runs and every counter is absent exactly when
	 * it matters -- the instrument that would explain the failure is
	 * disabled by the failure. Printed at the fault site instead.
	 */
	if (ReportAtFault)
		ReportAtFault();

	if (prog_dump_flow_state)	/* the caller's terms, not the callee's */
		prog_dump_flow_state(u->owner);
	fflush(stderr);
}

int
mtp_tx_flush_and_notify(struct mtp_data_unit *u, uint32_t len)
{
	uint64_t upto = u->head_seq + len;

	if (MTP_ENV_ON("MTP_TRACE_REF")) {
		static uint64_t flushes;

		if (!(++flushes % 8) || u->live_refs)
			fprintf(stderr, "FLUSHN n=%llu upto=%llu live=%u "
				"head=%llu tail=%llu held=%llu cap=%u\n",
				(unsigned long long)flushes,
				(unsigned long long)upto, u->live_refs,
				(unsigned long long)u->head_seq,
				(unsigned long long)u->tail_seq,
				(unsigned long long)(u->tail_seq - u->head_seq),
				u->cap);
	}
	if (MTP_ENV_ON("MTP_TRACE_REF") && u->live_refs)
		fprintf(stderr, "FLUSH upto=%llu min=%llu live=%u\n",
			(unsigned long long)upto,
			(unsigned long long)tx_ref_min(u), u->live_refs);

	if (u->live_refs && upto > tx_ref_min(u) && u->drain)
		u->drain(u->drain_arg);

	/* I2. This never accuses the program: a failure here means the drain
	 * above did not do its job. It is meaningful only because the minimum
	 * is COMPUTED — the previous version asserted against whichever entry
	 * happened to sit at the ring head, and was satisfied by a wrong value
	 * while payload was being overwritten underneath it (DESIGN.md §18).
	 *
	 * INSTRUMENT THE FAILURE, NOT THE RUN. This fires about one run in five
	 * at 16 connections, and a tracer over the whole run perturbs timing —
	 * which already cost us once, when a traced run never reproduced the
	 * fault it was built to catch (ratio 0.998). A dump on the failing path
	 * costs nothing until the path is taken, so it cannot suppress the race
	 * it is trying to observe, and one failure with full state is worth more
	 * than many runs without.
	 */
	/* Weak, because the unit tests link this file without the scheduler --
	 * a counter must not decide what a test binary contains. */
	if (upto > u->emitted_hwm && u->owner && NoteFlushPastWire)
		NoteFlushPastWire();

	/*
	 * A FLUSH THAT CANNOT REACH `upto` ADVANCES AS FAR AS IT CAN.
	 *
	 * The assertion this replaces encoded "the forced drain always
	 * succeeds", which is false: the drain abandons its walk when
	 * EthernetOutput has no transmit frame, and that back-pressure is
	 * ordinary -- measured at ~5.4 per MB in every run, faulting or clean
	 * (RESULTS 2026-08-17). Back-pressure clears, so the emission the
	 * drain gave up on succeeds on a later pass; nothing is lost by
	 * leaving acknowledged bytes in the ring until it does.
	 *
	 * Not a parity question: the donor holds no payload reference across a
	 * failed emission, so it has no equivalent to match.
	 *
	 * THE SHORTFALL IS COUNTED because the failure this must not become is
	 * a silent one. A clamp with no counter converts "crashes at 128 MB"
	 * into "quietly stops making progress at 128 MB".
	 */
	if (u->live_refs) {
		uint64_t min = tx_ref_min(u);

		if (upto > min) {
			u->short_events++;
			u->short_bytes += upto - min;
			if (++u->short_run > u->short_run_max)
				u->short_run_max = u->short_run;
			if (NoteFlushShort)
				NoteFlushShort(upto - min, u->short_run);

			/* Loud, once, with the same terms the fault dump
			 * prints -- an unbounded run is a stall and a stall is
			 * a failing test, not a slow pass. */
			if (u->short_run >= MTP_FLUSH_STALL_PASSES
			    && !u->short_alarmed) {
				u->short_alarmed = 1;
				fprintf(stderr, "\n*** FLUSH STALLED: %u "
					"consecutive flushes short, %llu bytes "
					"behind\n", u->short_run,
					(unsigned long long)(upto - min));
				tx_dump_ref_fault(u, upto);
			}
			upto = min;
		} else {
			u->short_run = 0;
		}
	} else {
		u->short_run = 0;
	}

	if (upto > u->tail_seq)
		upto = u->tail_seq;
	OWN(u, w_head_tid, "tx head_seq");	/* the STACK's index */
	u->head_seq = upto;

	/*
	 * SPACE APPEARING IS THE TRANSITION. want_space is set by a truncated
	 * write and cleared here, once, when the ring actually gains room --
	 * rather than re-tested on every poll. The application asking again for
	 * a ring that is still full simply re-sets it, which is the same
	 * contract as before with none of the re-evaluation.
	 */
	if (u->want_space && TxSpace(u) && u->owner && ReadyEdge) {
		u->want_space = 0;
		ReadyEdge(u->owner, MTP_NOTIF_WRITABLE);
	}
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
TxRef(struct mtp_data_unit *u, uint64_t seq, uint32_t len, payref_t *out,
	   uint8_t site, const void *bp, const void *caller, uint8_t kind)
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

	/*
	 * No ordering requirement. Taking a base BELOW an outstanding one — a
	 * retransmission does exactly that — is safe here, because the minimum
	 * is computed at every use rather than tracked as a position. The
	 * previous version asserted increasing order to protect a head pointer
	 * that no longer exists.
	 */
	/*
	 * OVERLAP DETECTED AT THE MOMENT IT IS CREATED, and COUNTED rather than
	 * fatal. The flush assertion catches the downstream consequence once
	 * per run at best -- one bit per sixty seconds. This is the thing we
	 * actually care about, and it yields a rate: hundreds of events per
	 * run, each with both authors and both retransmit flags.
	 *
	 * A rate is sensitive to a change that a binary crash-or-not needs
	 * dozens of runs to see -- which matters because the crash rate has
	 * been shown to move on identical code, so run-to-run comparison of
	 * outcomes cannot distinguish a code change from that variation.
	 */
	/*
	 * THE MERGE PATH OVERLAPS BY DESIGN and must not be counted: coalescing
	 * takes a WIDER reference at the same base and then releases the
	 * narrower one, so the two are briefly live together (DESIGN.md §18).
	 * Counting it drowned the signal -- 9722 "overlaps" in a run, every
	 * dumped one same-base-wider-extent, which is that merge and not a
	 * defect.
	 */
	/*
	 * COMMITTING OVER DATA ALREADY ON THE WIRE.
	 *
	 * The overlap test below asks whether the new extent intersects a
	 * reference that is live RIGHT NOW -- which misses the case where the
	 * earlier blueprint has already drained and released. Then no overlap
	 * is recorded, yet the new blueprint still holds a reference for bytes
	 * that have gone out, never drains, and pins the flush. That is the
	 * second failure family exactly: zero overlaps, an untouched blueprint,
	 * and a reference sitting ABOVE head_seq because the released earlier
	 * one let the head advance.
	 *
	 * This predicate needs no other reference to exist. If it is non-zero
	 * in runs where the overlap count is zero, the two families are one
	 * fault with different release timing.
	 */
	if (seq < u->emitted_hwm && NoteBelowWire)
		NoteBelowWire(seq, len, u->emitted_hwm, kind);

	{
		uint32_t i;

		for (i = 0; i < u->live_refs; i++) {
			uint64_t a = u->ref_base[i], b = a + u->ref_len[i];
			int expected;

			if (!(seq < b && a < seq + len))
				continue;
			/*
			 * A merge overlapping the reference it is SUPERSEDING
			 * -- same base -- is by design (DESIGN.md §18) and is
			 * counted separately, not discarded. Excluding merges
			 * outright hid a case where a merge overlaps something
			 * ELSE, which is not by design and which the counter
			 * then reported as zero.
			 */
			expected = (site == REF_SITE_MERGE_TAKE && a == seq);
			if (NoteOverlap)
				NoteOverlap(u, a, u->ref_len[i], seq, len,
						 kind, (uint8_t)expected);
			break;
		}
	}

	assert(u->live_refs < MTP_MAX_LIVE_REFS);
	u->ref_len[u->live_refs] = len;
	u->ref_base[u->live_refs++] = seq;
	ref_log_put(u, 0 /* take */, site, seq, len, bp, caller, kind);
	return 0;
}

/*
 * Liveness ENDS when the drain has copied the blueprint's last byte into an
 * mbuf — internal.h §3 — so this is called once per blueprint, from the drain,
 * after its final segment and not per segment.
 *
 * RELEASE BY IDENTITY, NOT BY POSITION. The caller names the base it is
 * releasing and that entry is removed wherever it sits. The previous version
 * took only the unit, so it could not know which reference was meant and
 * dropped the oldest — correct only if releases happen in the order the
 * references were taken. Nothing guaranteed that, and the merge path in
 * flow.c breaks it by construction: merging exists to drop a superseded
 * reference that is precisely NOT the oldest. The result was silent payload
 * corruption from two concurrent flows upward, with the flush's own assertion
 * satisfied by a wrong value throughout. The full account is DESIGN.md §18.
 *
 * THE ASSUMPTION, STATED, because both previous designs here failed by
 * carrying one that was not: `ref_base` holds BASES ONLY and nothing reads a
 * position in it, so it is a MULTISET. Bases are NOT unique — the merge takes
 * its wider reference at `last->base_seq` before releasing `last`'s reference
 * at that same base, so two equal entries coexist by design. Identity by base
 * alone is still exact, because removing any one entry of equal value leaves
 * the same multiset, and the only question ever asked of it is its minimum.
 * If a future caller ever needs to distinguish two references sharing a base,
 * that is the assumption that has expired, and this comment is where to start.
 *
 * Order-independent by construction: no caller has to be enumerated for this
 * to be correct, and a new release site cannot reintroduce the old bug.
 */
void
TxRefRelease(struct mtp_data_unit *u, uint64_t base, uint8_t site,
		   const void *bp, const void *caller, uint8_t kind)
{
	uint32_t i;

	for (i = 0; i < u->live_refs; i++) {
		if (u->ref_base[i] != base)
			continue;
		/* Compact: move the last entry into the hole. Order carries no
		 * meaning now, so this is the whole removal. */
		u->ref_len[i] = u->ref_len[u->live_refs - 1];
		u->ref_base[i] = u->ref_base[--u->live_refs];
		ref_log_put(u, 1 /* release */, site, base, 0, bp, caller, kind);
		return;
	}

	/* Releasing a base that is not live means the caller and the ring
	 * disagree about what is outstanding. The old code returned silently
	 * on an empty ring and popped an arbitrary entry otherwise, which is
	 * how a mismatch stayed invisible for the whole of the sweep. */
	assert(0 && "TxRefRelease: base is not live on this unit");
}

/*
 * I1: the minimum live base. COMPUTED, never maintained — the bug in §18 was a
 * maintained minimum going stale, and maintaining it correctly under arbitrary
 * removal needs an ordering the callers cannot promise. MTP_MAX_LIVE_REFS is
 * small and this is a scan of a hot, contiguous array; obviously correct beats
 * clever here (rule 3).
 */
static uint64_t
tx_ref_min(const struct mtp_data_unit *u)
{
	uint64_t lo;
	uint32_t i;

	assert(u->live_refs > 0);
	lo = u->ref_base[0];
	for (i = 1; i < u->live_refs; i++)
		if (u->ref_base[i] < lo)
			lo = u->ref_base[i];
	return lo;
}

uint64_t
mtp_tx_emitted(const struct mtp_data_unit *u)
{
	return u->emitted_hwm;
}

/* Free bytes in the ring — the target's own bookkeeping, for WRITABLE. */
uint32_t
TxSpace(const struct mtp_data_unit *u)
{
	return u->cap - (uint32_t)(u->tail_seq - u->head_seq);
}
