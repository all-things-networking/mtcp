/*
 * The SPSC ring (DESIGN.md §21). Tests the properties the design depends on,
 * not just that push and pop round-trip:
 *
 *   - a batch publishes atomically from the consumer's view;
 *   - full and empty are distinguishable (one slot kept empty);
 *   - the two indices are on SEPARATE cache lines, because if they are not,
 *     the ring is correct and slow, and slow-by-false-sharing is precisely the
 *     cost this design exists to avoid. A layout regression would otherwise be
 *     invisible until it showed up as an unexplained throughput number.
 */
#include <stdio.h>
#include <string.h>

#include "spsc.h"

static int failures;

#define CHECK(cond, fmt, ...) do {					\
	if (!(cond)) {							\
		printf("  FAIL %s:%d " fmt "\n",			\
		       __func__, __LINE__, ##__VA_ARGS__);		\
		failures++;						\
	}								\
} while (0)

static void
test_indices_do_not_share_a_line(void)
{
	struct spsc q;
	size_t h = (size_t)((char *)&q.head - (char *)&q);
	size_t t = (size_t)((char *)&q.tail - (char *)&q);
	size_t apart = t > h ? t - h : h - t;

	CHECK(apart >= SPSC_CACHELINE,
	      "head and tail are %zu bytes apart, want >= %d — false sharing",
	      apart, SPSC_CACHELINE);
	CHECK(h % SPSC_CACHELINE == 0, "head is not cache-line aligned (%zu)", h);
	CHECK(t % SPSC_CACHELINE == 0, "tail is not cache-line aligned (%zu)", t);
}

static void
test_rejects_non_power_of_two(void)
{
	struct spsc q;
	struct spsc_slot s[8];

	CHECK(!spsc_init(&q, s, 6), "a capacity of 6 was accepted");
	CHECK(!spsc_init(&q, s, 0), "a capacity of 0 was accepted");
	CHECK(spsc_init(&q, s, 8), "a capacity of 8 was refused");
}

static void
test_batch_and_backpressure(void)
{
	struct spsc q;
	struct spsc_slot s[8], in[8], out[8];
	uint32_t i, n;

	spsc_init(&q, s, 8);
	for (i = 0; i < 8; i++) { in[i].a = i; in[i].b = i * 10; }

	/* one slot is kept empty, so 8 capacity accepts 7 */
	n = spsc_push_n(&q, in, 8);
	CHECK(n == 7, "pushed %u of 8 into a ring of 8, want 7", n);
	CHECK(spsc_count(&q) == 7, "count is %u, want 7", spsc_count(&q));

	n = spsc_push_n(&q, in, 1);
	CHECK(n == 0, "a full ring accepted %u more", n);

	n = spsc_pop_n(&q, out, 8);
	CHECK(n == 7, "popped %u, want 7", n);
	for (i = 0; i < 7; i++)
		CHECK(out[i].a == i && out[i].b == i * 10,
		      "slot %u came back as %llu/%llu", i,
		      (unsigned long long)out[i].a, (unsigned long long)out[i].b);

	n = spsc_pop_n(&q, out, 8);
	CHECK(n == 0, "an empty ring returned %u", n);
}

static void
test_wraps(void)
{
	struct spsc q;
	struct spsc_slot s[4], one, got;
	uint32_t i;

	spsc_init(&q, s, 4);
	/* drive it several times round so the mask arithmetic is exercised */
	for (i = 0; i < 100; i++) {
		one.a = i; one.b = ~(uint64_t)i;
		CHECK(spsc_push_n(&q, &one, 1) == 1, "push %u refused", i);
		CHECK(spsc_pop_n(&q, &got, 1) == 1, "pop %u empty", i);
		CHECK(got.a == i && got.b == ~(uint64_t)i,
		      "wrap corrupted item %u", i);
	}
}

int
main(void)
{
	printf("test_spsc:\n");
	test_indices_do_not_share_a_line();
	test_rejects_non_power_of_two();
	test_batch_and_backpressure();
	test_wraps();
	printf("%s\n", failures ? "FAILED" : "  all checks passed");
	return failures != 0;
}
