/*
 * The window primitive, which is the whole of reassembly's arithmetic.
 *
 * Worth its own test because the property the design rests on is a NEGATIVE
 * one — "duplicates, overlaps and multiple holes need no code at all" — and a
 * negative property is exactly what nobody checks. Every case below is one the
 * receive path will meet on a lossy link and none of them fires at -c 1 on a
 * clean LAN, so the run that would catch a defect here is not the run anyone
 * does first.
 *
 * No NIC, no DPDK: runs on the orchestrator.
 */
#include <stdio.h>
#include <string.h>

#include "contract.h"

static int failures;

#define CHECK(cond, fmt, ...) do {					\
	if (!(cond)) {							\
		printf("  FAIL %s:%d " fmt "\n",			\
		       __func__, __LINE__, ##__VA_ARGS__);		\
		failures++;						\
	}								\
} while (0)

#define HEAD(w) ((unsigned long long)mtp_sw_head(w))

/* In order: every segment moves the boundary by its own length. */
static void
test_in_order(void)
{
	struct mtp_sliding_wnd w;
	int i;

	mtp_sw_init(&w, 1000);
	for (i = 0; i < 8; i++) {
		mtp_sw_set(&w, 1000 + i * 100, 1000 + (i + 1) * 100);
		mtp_sw_slide(&w);
		CHECK(mtp_sw_head(&w) == (uint64_t)(1000 + (i + 1) * 100),
		      "head %llu after segment %d", HEAD(&w), i);
	}
	CHECK(w.n == 0, "in-order arrivals left %u runs behind", w.n);
}

/* One hole: the boundary stops at it and jumps the whole way when it fills. */
static void
test_one_hole(void)
{
	struct mtp_sliding_wnd w;

	mtp_sw_init(&w, 0);
	mtp_sw_set(&w, 0, 100);   mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 100, "head %llu", HEAD(&w));

	/* 100..200 is lost; 200..300 and 300..400 arrive */
	mtp_sw_set(&w, 200, 300); mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 100, "head moved past a hole: %llu", HEAD(&w));
	mtp_sw_set(&w, 300, 400); mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 100, "head moved past a hole: %llu", HEAD(&w));

	/* the retransmission fills it: one slide passes all three */
	mtp_sw_set(&w, 100, 200); mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 400, "head %llu after the gap filled", HEAD(&w));
	CHECK(w.n == 0, "%u runs left after the gap filled", w.n);
}

/* Two holes: the boundary stops at the FIRST, then at the second. */
static void
test_two_holes(void)
{
	struct mtp_sliding_wnd w;

	mtp_sw_init(&w, 0);
	mtp_sw_set(&w, 100, 200);
	mtp_sw_set(&w, 300, 400);
	mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 0, "head %llu with nothing at the boundary",
	      HEAD(&w));
	CHECK(w.n == 2, "expected 2 runs, got %u", w.n);

	mtp_sw_set(&w, 0, 100); mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 200, "head %llu: should stop at the second hole",
	      HEAD(&w));
	mtp_sw_set(&w, 200, 300); mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 400, "head %llu after both gaps filled", HEAD(&w));
}

/* Marking a range twice is the same as marking it once. */
static void
test_duplicates(void)
{
	struct mtp_sliding_wnd w;

	mtp_sw_init(&w, 0);
	mtp_sw_set(&w, 0, 100);
	mtp_sw_set(&w, 0, 100);
	mtp_sw_set(&w, 0, 100);
	mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 100, "head %llu", HEAD(&w));
	CHECK(w.n == 0, "%u runs after three identical marks", w.n);

	/* wholly behind the boundary: a retransmission whose acknowledgement
	 * was lost. Absorbed, not counted, not an error. */
	mtp_sw_set(&w, 0, 50);
	mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 100, "head moved backwards: %llu", HEAD(&w));
	CHECK(w.n == 0, "a wholly-duplicate range left %u runs", w.n);
}

/* A partial overlap marks the union. */
static void
test_overlap(void)
{
	struct mtp_sliding_wnd w;

	mtp_sw_init(&w, 0);
	mtp_sw_set(&w, 200, 400);
	mtp_sw_set(&w, 300, 500);		/* overlaps the tail */
	CHECK(w.n == 1, "overlap left %u runs, not 1", w.n);
	CHECK(w.run[0].lo == 200 && w.run[0].hi == 500,
	      "union is [%llu,%llu), expected [200,500)",
	      (unsigned long long)w.run[0].lo, (unsigned long long)w.run[0].hi);

	mtp_sw_set(&w, 100, 250);		/* overlaps the head */
	CHECK(w.n == 1, "overlap left %u runs, not 1", w.n);
	CHECK(w.run[0].lo == 100 && w.run[0].hi == 500,
	      "union is [%llu,%llu), expected [100,500)",
	      (unsigned long long)w.run[0].lo, (unsigned long long)w.run[0].hi);

	/* straddling the boundary: the part below is already ours */
	mtp_sw_init(&w, 100);
	mtp_sw_set(&w, 50, 150);
	mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 150, "head %llu after a straddling range",
	      HEAD(&w));
}

/*
 * ABUTTING RUNS MERGE. Without this, a stream arriving backwards fills the
 * table with runs that never join and the window overflows on traffic that has
 * no hole in it at all.
 */
static void
test_abutting(void)
{
	struct mtp_sliding_wnd w;
	int i;

	mtp_sw_init(&w, 0);
	for (i = 20; i > 0; i--)			/* backwards, no gaps */
		mtp_sw_set(&w, i * 100, (i + 1) * 100);
	CHECK(w.n == 1, "20 abutting ranges left %u runs, not 1", w.n);
	mtp_sw_set(&w, 0, 100);
	mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 2100, "head %llu, expected 2100", HEAD(&w));
}

/*
 * Overflow is refused and counted, never absorbed. A range the window cannot
 * remember is one the peer retransmits, so this is a performance cliff and not
 * a correctness failure -- but it must be visible, because a silent one reads
 * as a clean run.
 */
static void
test_overflow(void)
{
	struct mtp_sliding_wnd w;
	uint64_t before = mtp_sw_overflows();
	int i;

	mtp_sw_init(&w, 0);
	for (i = 1; i <= MTP_WND_MAX_RUNS + 4; i++)	/* every one disjoint */
		mtp_sw_set(&w, i * 1000, i * 1000 + 100);
	CHECK(w.n == MTP_WND_MAX_RUNS, "held %u runs, cap is %d", w.n,
	      MTP_WND_MAX_RUNS);
	CHECK(mtp_sw_overflows() == before + 4,
	      "counted %llu overflows, expected 4",
	      (unsigned long long)(mtp_sw_overflows() - before));

	/* and it still works: filling from the bottom slides normally */
	mtp_sw_set(&w, 0, 1100);
	mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == 1100, "head %llu after a full window slid",
	      HEAD(&w));
}

/* Sequence numbers wrap. Every comparison in the primitive is signed-delta for
 * this reason, so the boundary must cross 2^32 and 2^64 without inverting. */
static void
test_wrap(void)
{
	struct mtp_sliding_wnd w;
	uint64_t base = 0xFFFFFFFFFFFFFF00ULL;

	mtp_sw_init(&w, base);
	mtp_sw_set(&w, base + 0x100, base + 0x200);	/* past the wrap */
	mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == base, "head %llu should not have moved",
	      HEAD(&w));
	mtp_sw_set(&w, base, base + 0x100);
	mtp_sw_slide(&w);
	CHECK(mtp_sw_head(&w) == base + 0x200,
	      "head %llu did not cross the wrap", HEAD(&w));
}

int
main(void)
{
	printf("test_sliding_wnd:\n");
	test_in_order();
	test_one_hole();
	test_two_holes();
	test_duplicates();
	test_overlap();
	test_abutting();
	test_overflow();
	test_wrap();
	if (failures) {
		printf("  %d FAILURES\n", failures);
		return 1;
	}
	printf("  all checks passed\n");
	return 0;
}
