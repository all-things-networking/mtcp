/*
 * handoff_bench — what does one crossing of the thread boundary cost?
 *
 * Measured on the PRIMITIVE, early, and deliberately before the thread bodies
 * are written (DESIGN.md §21.1). The reason is structural rather than
 * curiosity: the donor runs two spinning threads pinned to ONE core, neither
 * of which ever blocks, so neither yields voluntarily and they alternate by
 * PREEMPTION. If that makes a crossing scheduler-quantum-scale rather than
 * cache-line-scale, then no amount of alignment or batching moves it, and
 * batching is not an optimisation but the whole design. Better to know that
 * before writing the rest around per-item crossings.
 *
 * It also answers, for the shim, whether an application thread asking for
 * readiness will sit behind a quantum every time.
 *
 * Three configurations, because the difference between them IS the finding:
 *   same core   — the donor's shape, and the one we are matching;
 *   two cores   — the contrast, to separate scheduler cost from cache cost;
 *   batch sizes — 1, 8, 64, to show what amortising the barrier buys.
 *
 * No protocol identity: rule 4 is unaffected.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "spsc.h"

#define RING_CAP	1024
#define PINGPONG_N	200
#define STREAM_N	20000

static struct spsc		 q_fwd, q_rev;
static struct spsc_slot		 s_fwd[RING_CAP], s_rev[RING_CAP];
static atomic_int		 go, stop;
static int			 cpu_a, cpu_b;

static void
pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set))
		fprintf(stderr, "warning: could not pin to cpu %d\n", cpu);
}

static double
now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

/* The echo side: spins, never blocks, never yields — the donor's shape. */
static void *
echo_thread(void *arg)
{
	struct spsc_slot buf[64];

	(void)arg;
	pin(cpu_b);
	atomic_fetch_add(&go, 1);
	while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
		uint32_t n = spsc_pop_n(&q_fwd, buf, 64);

		if (n)
			while (spsc_push_n(&q_rev, buf, n) == 0)
				if (atomic_load_explicit(&stop, memory_order_relaxed))
					return NULL;
	}
	return NULL;
}

/* Round trip: one item across and back. This is the latency the shim's
 * epoll_wait would pay if it asked and waited. */
static void
run_pingpong(void)
{
	struct spsc_slot one = { 1, 2 }, got;
	double t0, t1;
	int i;

	t0 = now_ns();
	for (i = 0; i < PINGPONG_N; i++) {
		while (spsc_push_n(&q_fwd, &one, 1) == 0)
			;
		while (spsc_pop_n(&q_rev, &got, 1) == 0)
			;
	}
	t1 = now_ns();
	printf("  round trip:   %8.0f ns   (%d iterations)\n",
	       (t1 - t0) / PINGPONG_N, PINGPONG_N);
}

/* One-way rate at a given batch size: what amortising the barrier buys. */
static void
run_stream(int b)
{
	struct spsc_slot in[64], got[64];
	double t0, t1;
	long sent = 0, back = 0;
	int i;

	for (i = 0; i < 64; i++) { in[i].a = (uint64_t)i; in[i].b = 0; }
	t0 = now_ns();
	while (sent < STREAM_N) {
		uint32_t n = spsc_push_n(&q_fwd, in, (uint32_t)b);

		sent += n;
		back += spsc_pop_n(&q_rev, got, 64);
	}
	while (back < sent)
		back += spsc_pop_n(&q_rev, got, 64);
	t1 = now_ns();
	printf("  batch %-3d:    %8.1f M items/s   %6.0f ns per crossing\n",
	       b, (double)sent / ((t1 - t0) / 1e9) / 1e6,
	       (t1 - t0) / ((double)sent / b));
}

static void
scenario(const char *name, int a, int bcpu)
{
	pthread_t th;
	int bs[3] = { 1, 8, 64 }, i;

	cpu_a = a; cpu_b = bcpu;
	spsc_init(&q_fwd, s_fwd, RING_CAP);
	spsc_init(&q_rev, s_rev, RING_CAP);
	atomic_store(&go, 0);
	atomic_store(&stop, 0);

	pthread_create(&th, NULL, echo_thread, NULL);
	while (atomic_load(&go) == 0)
		;
	pin(cpu_a);

	printf("%s (producer cpu %d, echo cpu %d)\n", name, a, bcpu);
	run_pingpong();
	for (i = 0; i < 3; i++)
		run_stream(bs[i]);

	atomic_store(&stop, 1);
	pthread_join(th, NULL);
	printf("\n");
}

int
main(void)
{
	printf("handoff_bench — cost of one crossing of the thread boundary\n");
	printf("(batch is items per push; 'per crossing' is time per push call)\n\n");

	/* The donor's shape first: both threads on ONE core, both spinning. */
	scenario("SAME CORE  — the donor's shape, and what we are matching", 2, 2);
	scenario("TWO CORES  — contrast only, NOT what we are building", 2, 3);
	return 0;
}
