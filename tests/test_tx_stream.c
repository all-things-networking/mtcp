/*
 * The transmit ring, and the payload-lifetime race.
 *
 * This is the test the reference-release bug should have failed. It was written
 * skipped in increment 1 because there was no send path, and stayed skipped
 * afterwards because tx_stream.c reached DPDK. Both reasons are gone: the ring
 * takes its capacity as a parameter and its forced drain as a callback, so it
 * depends on nothing above it and runs on any node.
 */
#include <stdio.h>
#include <string.h>

#include "contract.h"
#include "internal.h"

static int failures;
static int drains;

#define CHECK(cond, fmt, ...) do {					\
	if (!(cond)) {							\
		printf("  FAIL %s:%d " fmt "\n",			\
		       __func__, __LINE__, ##__VA_ARGS__);		\
		failures++;						\
	}								\
} while (0)

/*
 * Stands in for tgt_drain: emits whatever is pending and, critically, RELEASES
 * the references those blueprints held. The real drain does that in
 * release_bp() after a blueprint's last segment. A stub that counted without
 * releasing tripped the assertion in mtp_tx_flush_and_notify — correctly,
 * because that assertion's whole job is to catch a drain that did not do its
 * job, and this is the first time anything has demonstrated it firing.
 */
static struct mtp_data_unit *drain_unit;

static void count_drain(void *arg)
{
	(void)arg;
	drains++;
	/* Releases every reference by naming one that is live each time. Any
	 * order is correct now — that is the point of release-by-identity. */
	while (drain_unit && drain_unit->live_refs)
		tgt_tx_ref_release(drain_unit, drain_unit->ref_base[0], REF_SITE_DRAIN_REL, NULL, NULL);
}

static void
fill(struct mtp_data_unit *u, uint32_t n)
{
	static uint8_t src[8192];
	struct mtp_tx_addr a = { .base = src, .len = n };

	mtp_add_tx_data(u, a, n);
}

/* The true ring: bytes never move, so a resolved pointer stays valid. That is
 * what takes the send-buffer lock off the generation path (P1). */
static void
test_ring_does_not_move_bytes(void)
{
	struct mtp_data_unit u;
	payref_t r1, r2;

	tgt_tx_unit_init(&u, MTP_SIZE_INF, 4096, count_drain, NULL);
	drain_unit = NULL;
	fill(&u, 1000);

	CHECK(tgt_tx_ref(&u, 0, 500, &r1, REF_SITE_COMMIT, NULL, NULL) == 0, "ref of held bytes failed");
	fill(&u, 1000);
	CHECK(tgt_tx_ref(&u, 500, 500, &r2, REF_SITE_COMMIT, NULL, NULL) == 0, "second ref failed");
	CHECK(r1.data + 500 == r2.data, "the ring moved bytes under a reference");
}

/* A reference outside the live range FAILS and leaves the output untouched.
 * Returning a plausible pointer near the base is how the sibling branches'
 * out-of-bounds case happens. */
static void
test_ref_refuses_out_of_range(void)
{
	struct mtp_data_unit u;
	payref_t r;

	tgt_tx_unit_init(&u, MTP_SIZE_INF, 4096, count_drain, NULL);
	drain_unit = &u;
	fill(&u, 100);

	memset(&r, 0xAA, sizeof(r));
	CHECK(tgt_tx_ref(&u, 50, 100, &r, REF_SITE_COMMIT, NULL, NULL) < 0, "ref past the tail succeeded");
	CHECK(r.len == 0xAAAAAAAA, "a failed ref wrote to *out");

	mtp_tx_flush_and_notify(&u, 50);
	CHECK(tgt_tx_ref(&u, 0, 10, &r, REF_SITE_COMMIT, NULL, NULL) < 0, "ref below the head succeeded");
}

/* A payload straddling the end is described by the reference, not linearised. */
static void
test_ref_describes_the_wrap(void)
{
	struct mtp_data_unit u;
	payref_t r;

	tgt_tx_unit_init(&u, MTP_SIZE_INF, 1024, count_drain, NULL);
	drain_unit = &u;
	fill(&u, 1024);
	mtp_tx_flush_and_notify(&u, 900);	/* head to 900 */
	fill(&u, 800);				/* wraps */

	CHECK(tgt_tx_ref(&u, 1000, 100, &r, REF_SITE_COMMIT, NULL, NULL) == 0, "ref across the wrap failed");
	CHECK(r.wraps, "a straddling payload was not marked as wrapping");
	CHECK(r.wrap_at_seq == 1024, "wrap point is %llu, want 1024",
	      (unsigned long long)r.wrap_at_seq);
}

/*
 * THE RACE. A committed blueprint holds a reference; the program then flushes
 * over it, which it is entitled to do — validity ends when the program flushes.
 * The target must force a drain first, because deferring packet generation
 * means it may still be holding the reference.
 *
 * This is what the reference-release bug broke: nothing released, so the oldest
 * base stayed pinned at the first byte ever sent and every flush forced a
 * drain for ever, cutting every coalescing run short while still passing
 * traffic.
 */
static void
test_flush_over_live_reference(void)
{
	struct mtp_data_unit u;
	payref_t r;

	drains = 0;
	tgt_tx_unit_init(&u, MTP_SIZE_INF, 4096, count_drain, NULL);
	drain_unit = &u;
	fill(&u, 2000);

	tgt_tx_ref(&u, 0, 1000, &r, REF_SITE_COMMIT, NULL, NULL);		/* a blueprint is holding [0,1000) */
	mtp_tx_flush_and_notify(&u, 1000);	/* the program flushes over it */
	CHECK(drains == 1, "a flush across a live reference did not force a "
	      "drain (drains=%d)", drains);

	/* the drain released it, so the next flush must NOT force another — the
	 * bug was that it always did, silently, cutting every coalescing run
	 * short while still passing traffic */
	drains = 0;
	fill(&u, 1000);
	mtp_tx_flush_and_notify(&u, 500);
	CHECK(drains == 0, "a flush with no live reference forced a drain "
	      "(drains=%d) — references are not being released", drains);
}

/*
 * DESIGN.md §18, in nine lines: RELEASING A REFERENCE THAT IS NOT THE OLDEST.
 *
 * The merge path drops a superseded reference which is, by construction, not
 * the oldest outstanding. The old release took only the unit, so it dropped
 * whatever sat at the ring head — the OLDEST — and that blueprint's base left
 * the ring while the blueprint was still live. The computed minimum jumped
 * forward, the next flush concluded the range was clear, and bytes moved under
 * a live reference. Silent payload corruption from two concurrent flows
 * upward; it only announced itself as an abort at sixteen.
 *
 * This test fails on the old code at the FIRST check that follows the release.
 */
static void
test_release_of_a_non_oldest_reference(void)
{
	struct mtp_data_unit u;
	payref_t x, y;

	drains = 0;
	tgt_tx_unit_init(&u, MTP_SIZE_INF, 4096, count_drain, NULL);
	drain_unit = &u;
	fill(&u, 3000);

	CHECK(tgt_tx_ref(&u, 0, 1000, &x, REF_SITE_COMMIT, NULL, NULL) == 0, "X ref failed");
	CHECK(tgt_tx_ref(&u, 1000, 1000, &y, REF_SITE_COMMIT, NULL, NULL) == 0, "Y ref failed");
	CHECK(u.live_refs == 2, "expected 2 live refs, got %u", u.live_refs);

	/* Y goes first: the merge path's case, and not the oldest. */
	tgt_tx_ref_release(&u, 1000, REF_SITE_DRAIN_REL, NULL, NULL);
	CHECK(u.live_refs == 1, "expected 1 live ref, got %u", u.live_refs);
	CHECK(u.ref_base[0] == 0,
	      "the surviving reference has base %llu, want 0 — the WRONG entry "
	      "was released", (unsigned long long)u.ref_base[0]);

	/* X is still live at base 0, so a flush into its range must force a
	 * drain. Having dropped X, the old code sails straight past. */
	mtp_tx_flush_and_notify(&u, 500);
	CHECK(drains == 1, "a flush over the surviving oldest reference did not "
	      "force a drain (drains=%d) — its bytes were freed underneath it",
	      drains);
}

int
main(void)
{
	printf("test_tx_stream:\n");
	test_ring_does_not_move_bytes();
	test_ref_refuses_out_of_range();
	test_ref_describes_the_wrap();
	test_flush_over_live_reference();
	test_release_of_a_non_oldest_reference();

	printf("%s\n", failures ? "FAILED" : "  all checks passed");
	return failures != 0;
}
