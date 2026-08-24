/*
 * `sliding_wnd` — the MTP language's window primitive, for real.
 *
 * WHAT THE CONTRACT REFERENCE HAS, AND WHY IT IS NOT ENOUGH.
 * MTP-kernel-test/mtpc/codegen.py:557-563 emits
 *
 *     struct mtp_sliding_wnd { u64 lo, hi; };
 *     mtp_sw_set(w, a, b);  mtp_sw_slide(w, d);  mtp_sw_head(w);
 *
 * — one interval and a slide distance the CALLER supplies. That cannot express
 * a hole, so it cannot express reassembly: a program using it would have to
 * know how far to slide, which is the one thing only the window knows.
 * docs/events/EVENT-DATA.md §1 records this and says the target has to provide
 * the real thing.
 *
 * SO `slide()` TAKES NO DISTANCE. It advances the head over everything
 * contiguously arrived and stops at the first gap, which is the whole point:
 * "the program never sees a hole — it sees where the boundary ended up."
 * That is a divergence from the contract reference's signature and is recorded
 * in docs/DIVERGENCE.md as a contract-change candidate.
 *
 * NOTHING HERE NAMES A PROTOCOL. It is arithmetic over unsigned ranges: a
 * receive boundary in one program, something else in the next. Rule 4.
 */
#include <string.h>

#include "contract.h"
#include "internal.h"

/*
 * HOW MANY HOLES A WINDOW CAN HOLD IS THE PRIMITIVE'S BUSINESS, and a limit
 * exists on both sides: the donor bounds its equivalent with a pool, the
 * fragment chain allocated at tcp_ring_buffer.c:103-107. Ours is here.
 *
 * Overflow is not a correctness failure — a range the window refuses to
 * remember is a range the peer retransmits — but it IS a performance cliff, so
 * it is counted rather than silently absorbed. See mtp_sw_overflows().
 */
static uint64_t g_sw_overflow;		/* stack thread only: every caller is a
					 * receive-path processor */

uint64_t
mtp_sw_overflows(void)
{
	return g_sw_overflow;
}

void
mtp_sw_init(struct mtp_sliding_wnd *w, uint64_t head)
{
	memset(w, 0, sizeof(*w));
	w->head = head;
}

/*
 * Mark [a, b) as arrived.
 *
 * DUPLICATES, OVERLAPS AND MULTIPLE HOLES NEED NO CODE AT ALL, which is the
 * property the whole design rests on: marking a range twice is the same as
 * marking it once, a partial overlap marks the union, and two losses leave two
 * runs with the slide stopping at the first.
 */
void
mtp_sw_set(struct mtp_sliding_wnd *w, uint64_t a, uint64_t b)
{
	unsigned i, j;

	if ((int64_t)(a - w->head) < 0)
		a = w->head;			/* the part below the boundary
						 * has already arrived */
	if ((int64_t)(b - a) <= 0)
		return;				/* entirely behind us */

	/*
	 * Absorb every run this range touches or abuts, widening [a,b) to their
	 * union, then reinsert once. Abutting counts — [0,10) and [10,20) are
	 * one run, not two — or a stream arriving in order backwards would fill
	 * the table with runs that never merge.
	 */
	for (i = 0, j = 0; i < w->n; i++) {
		uint64_t lo = w->run[i].lo, hi = w->run[i].hi;

		if ((int64_t)(hi - a) < 0 || (int64_t)(b - lo) < 0) {
			w->run[j++] = w->run[i];	/* disjoint: keep */
			continue;
		}
		if ((int64_t)(lo - a) < 0)
			a = lo;
		if ((int64_t)(hi - b) > 0)
			b = hi;
	}
	w->n = j;

	if (w->n == MTP_WND_MAX_RUNS) {
		g_sw_overflow++;
		return;				/* refused; the peer resends */
	}
	/* insertion sort by lo: the table is tiny and stays ordered, which is
	 * what lets slide() stop at the first gap without a search */
	for (i = w->n; i > 0; i--) {
		if ((int64_t)(w->run[i - 1].lo - a) < 0)
			break;
		w->run[i] = w->run[i - 1];
	}
	w->run[i].lo = a;
	w->run[i].hi = b;
	w->n++;
}

/*
 * Advance the head over everything contiguously arrived. Stops at the first
 * gap. Returns the new head.
 */
uint64_t
mtp_sw_slide(struct mtp_sliding_wnd *w)
{
	unsigned i = 0;

	while (i < w->n && (int64_t)(w->run[i].lo - w->head) <= 0) {
		if ((int64_t)(w->run[i].hi - w->head) > 0)
			w->head = w->run[i].hi;
		i++;
	}
	if (i) {
		memmove(w->run, w->run + i, (w->n - i) * sizeof(w->run[0]));
		w->n -= i;
	}
	return w->head;
}

uint64_t
mtp_sw_head(const struct mtp_sliding_wnd *w)
{
	return w->head;
}

/* One past the highest byte any run reaches, or the head if there are none.
 * The target's own capacity arithmetic needs it; no program reads it. */
uint64_t
mtp_sw_extent(const struct mtp_sliding_wnd *w)
{
	return w->n ? w->run[w->n - 1].hi : w->head;
}
