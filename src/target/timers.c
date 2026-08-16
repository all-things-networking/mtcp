/*
 * The timing wheel.
 *
 * Shape from mTCP's hashed RTO store, which is also what the ORIGINAL
 * prototype used — `mina-mtp`'s TimerStart is a thin wrapper over it with no
 * timer identifier. The three per-timer lists on `mtp-dpdk-clean` are the prior
 * session's replacement and the outlier; they assume arm order equals expiry
 * order, which is false for a retransmission timer under backoff. Rule 1 points
 * at the wheel and so does the original prototype.
 *
 * The interface is the kernel contract's, not the donor's: timer OBJECTS the
 * program embeds (CR-2), bound to the event they raise (CR-6). The same split
 * as D-19 — the boundary conforms and the contents are ours.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "contract.h"
#include "internal.h"
#include "target_core.h"
#include "debug.h"

#define WHEEL_MASK	(WHEEL_BUCKETS - 1)

/* The longest interval this wheel will accept. Generous — the donor's maximum
 * backoff is 60 s and this is more — so exceeding it means a broken caller
 * rather than a long timer. */
#define TIMER_MAX_TICKS	(120u * 1000u)

/*
 * The wheel lives in the per-core transport (target_core.h), not here. These
 * accessors keep the 40-odd references in this file readable without threading
 * a parameter through every one; the state itself is per core, which is what
 * both references do and what this file previously did not.
 */
#define TW		(&TransportOf(g_core[0])->timers)
#define wheel		(TW->bucket)
#define overflow	(TW->overflow)
#define wheel_now	(TW->now)
#define wheel_started	(TW->started)
#define fires		(TW->fires)

static void
unlink_timer(struct mtp_timer *t)
{
	struct mtp_timer **pp;

	if (!t->armed)
		return;
	pp = (t->deadline - wheel_now < WHEEL_BUCKETS)
	     ? &wheel[t->deadline & WHEEL_MASK] : &overflow;
	for (; *pp; pp = &(*pp)->wnext) {
		if (*pp == t) {
			*pp = t->wnext;
			break;
		}
	}
	t->armed = 0;
	t->wnext = NULL;
}

/*
 * O(1) arm, O(1) cancel, and NO ORDERING ASSUMPTION — which is the whole point
 * against the per-timer lists, whose sweep stops at the first entry that is not
 * due. Under exponential backoff a timer armed later can be due sooner, so that
 * sweep silently stops firing.
 */
int
mtp_timer_start(struct mtp_timer *t, uint64_t ns)
{
	uint32_t ticks = (uint32_t)(ns / 1000000);	/* the 1 ms tick */

	unlink_timer(t);

	/*
	 * AN UNREPRESENTABLE DEADLINE IS LOUD, NOT FILED.
	 *
	 * The overflow list is legitimate for a deadline beyond the wheel's
	 * range but still in the future — a 60 s backoff is 60000 ticks and
	 * belongs there. What is not legitimate is a deadline so far out that
	 * `deadline - now` wraps below the current tick: the promotion test can
	 * then never become true, the timer is never swept, and the flow waits
	 * for something that cannot arrive. That is exactly what a nonsense RTT
	 * sample produced — 2^30 + 2 ticks — and the wheel accepted it in
	 * silence and said nothing.
	 *
	 * Silently accepting an impossible input and producing a
	 * plausible-looking state is the defect class this whole increment has
	 * been made of. So: assert where an assert can be seen, and refuse
	 * where it cannot, rather than defer for ever.
	 */
	if (ticks > TIMER_MAX_TICKS) {
		TRACE_ERROR("timer armed for %u ticks, beyond the %u this wheel "
			    "can represent — the caller's interval is wrong, "
			    "not this timer. Clamping rather than filing it "
			    "where the sweep will never reach it.\n",
			    ticks, TIMER_MAX_TICKS);
		assert(0);
		ticks = TIMER_MAX_TICKS;
	}

	/*
	 * A ZERO INTERVAL BECOMES ONE TICK, SILENTLY — recorded 2026-08-13
	 * because DESIGN-CLOSE.md §5 may depend on it and it has never run.
	 *
	 * This is the third appearance of a legal zero read as a sentinel: the
	 * RTO floor treated a computed zero as "unset", and `ticks ? ticks : 1`
	 * treats a requested zero as "the caller meant the minimum". For a
	 * retransmission timeout that is right — a zero-tick RTO is a busy
	 * loop. For TIME_WAIT at the donor's tcp_timewait = 0 it may be a
	 * DIVERGENCE, because one tick is not immediately.
	 *
	 * Left as it is rather than changed, because which behaviour is correct
	 * depends on B's answer about the donor at zero, and changing it now
	 * would be choosing without knowing. What is NOT acceptable is that it
	 * is silent, so it says so when it happens.
	 */
	if (!ticks && getenv("MTP_TRACE_SEQ"))
		fprintf(stderr, "ARM  zero interval rounded up to one tick "
			"— see DESIGN-CLOSE.md §5\n");
	t->deadline = wheel_now + (ticks ? ticks : 1);
	t->armed = 1;

	if (getenv("MTP_TRACE_SEQ"))
		fprintf(stderr, "ARM  ns=%llu ticks=%u now=%u deadline=%u "
			"in_range=%d bucket=%u\n", (unsigned long long)ns,
			ticks, wheel_now, t->deadline,
			(t->deadline - wheel_now < WHEEL_BUCKETS),
			t->deadline & WHEEL_MASK);

	if (t->deadline - wheel_now < WHEEL_BUCKETS) {
		t->wnext = wheel[t->deadline & WHEEL_MASK];
		wheel[t->deadline & WHEEL_MASK] = t;
	} else {
		t->wnext = overflow;
		overflow = t;
	}
	return 0;
}

int
mtp_timer_stop(struct mtp_timer *t)
{
	unlink_timer(t);
	return 0;
}

/*
 * Advance to `now` and fire what is due. Called once per main-loop iteration
 * with the one clock value that iteration uses, so every timer in the stack
 * sees the same time — a parity property of both references.
 */
void
TimerTick(uint32_t now)
{
	struct mtp_timer **pp, *t;

	/*
	 * The wheel's clock has to START at the first tick it sees. `now` is a
	 * millisecond epoch, not a count from zero, so a wheel initialised to 0
	 * tries to step four billion buckets on its first call and the process
	 * hangs before it ever receives a packet — which is what happened, and
	 * it looked like a crash rather than a loop.
	 */
	if (!wheel_started) {
		wheel_now = now;
		wheel_started = 1;
	}

	/* promote anything from the overflow list that is now in range */
	pp = &overflow;
	while ((t = *pp)) {
		if (t->deadline - now < WHEEL_BUCKETS) {
			*pp = t->wnext;
			t->wnext = wheel[t->deadline & WHEEL_MASK];
			wheel[t->deadline & WHEEL_MASK] = t;
		} else {
			pp = &t->wnext;
		}
	}

	/*
	 * NOT SAFE TO ENABLE ON THE THREADED PATH. The two statics below are
	 * function-scope but process-global, so with the stack thread running
	 * they are shared state without synchronisation. They are a rate
	 * limiter for a debug print and nothing reads them for a result -- but
	 * a concurrency investigation is exactly when someone reaches for this
	 * trace, and exactly when it would produce a plausible wrong number.
	 */
	if (getenv("MTP_TRACE_SEQ")) {
		static uint32_t last;

		if (now != last) {
			static uint64_t n;

			if (!(n++ % 512))
				fprintf(stderr, "TICK sweep=%u -> now=%u\n",
					wheel_now, now);
			last = now;
		}
	}

	while (wheel_now != now) {
		struct mtp_timer *b;

		wheel_now++;
		b = wheel[wheel_now & WHEEL_MASK];
		wheel[wheel_now & WHEEL_MASK] = NULL;

		while (b) {
			struct mtp_timer *next = b->wnext;

			if (b->armed && b->deadline == wheel_now) {
				b->armed = 0;
				b->wnext = NULL;
				fires++;
				/* CR-6: expiry raises the bound event, which
				 * flows through dispatch like any other */
				/*
				 * `now`, NOT `wheel_now`. They are meant to be
				 * equal and are separate variables, and the
				 * wheel's is derived from its own sweep state —
				 * so a processor reached from here built its
				 * headers on a DIFFERENT CLOCK from every other
				 * processor in the same iteration.
				 *
				 * That is how a timestamp echo came back ahead
				 * of our clock: a segment sent from a timer
				 * carried the wheel's position as its TSval,
				 * the peer echoed it, and the estimator
				 * subtracted it from the loop's `now`. Unsigned,
				 * so an echo one tick ahead becomes a sample of
				 * ~2^32 and an interval the wheel cannot
				 * represent. The donor needs a backwards NTP
				 * step to reach that state; we reached it with
				 * a second clock.
				 *
				 * Both references read the clock once per
				 * iteration and use that one value everywhere,
				 * and it is a parity property, not a tidiness
				 * one.
				 */
				mtp_program_timer(b, now);
			} else if (b->armed) {
				/* a bucket collision from a later revolution */
				b->wnext = wheel[b->deadline & WHEEL_MASK];
				wheel[b->deadline & WHEEL_MASK] = b;
			}
			b = next;
		}
	}
}

uint64_t TimerFires(void) { return fires; }
