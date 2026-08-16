/*
 * SPSC ring — the one thing that crosses between the stack thread and the
 * application thread (DESIGN.md §21).
 *
 * WHY THIS SHAPE
 *
 * The donor's cross-thread queues are entirely unsynchronised: its lock macros
 * compile to nothing and the lock members are not declared. That is safe there
 * only because both its threads share a core and never truly run at once. **We
 * match the concurrency; we do not match the missing synchronisation** — the
 * donor's premature FIN is where the missing half becomes observable, and it is
 * a bug rather than something we owe the reference.
 *
 * But correctness must not be paid for per item. Two properties keep it cheap,
 * and both are requirements from §21.1 rather than optimisations:
 *
 *   - **The indices sit on separate cache lines.** Producer and consumer each
 *     write one index and read the other. On one line, every push invalidates
 *     the consumer's copy and every pop invalidates the producer's, and the
 *     handoff cost becomes false sharing rather than work.
 *
 *   - **Ordering is amortised over a BATCH.** A push publishes with one release
 *     store; a batch of N publishes with one release store for all N. The
 *     barrier is per crossing, not per item.
 *
 * OWNERSHIP, stated rather than implied. The producer owns `head` and the slots
 * in [head, ...); the consumer owns `tail` and the slots in [tail, head). A
 * release store on `head` is what transfers a slot's contents to the consumer;
 * an acquire load on `head` is what makes those contents visible. Same pair in
 * the other direction for space.
 *
 * Capacity is a power of two so the mask is an AND, and one slot is always left
 * empty so full and empty are distinguishable without a third variable.
 *
 * No protocol identity here: rule 4 is unaffected.
 */
#ifndef SPSC_H
#define SPSC_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define SPSC_CACHELINE 64

/*
 * The element type is fixed rather than templated: C has no generics worth the
 * macro soup, and two concrete rings (app->stack requests, stack->app
 * readiness) do not justify it. `u64[2]` carries a pointer and a word, which is
 * what both directions need.
 */
struct spsc_slot {
	uint64_t a;
	uint64_t b;
};

struct spsc {
	/* written by the producer, read by the consumer */
	_Alignas(SPSC_CACHELINE) atomic_uint_least32_t head;
	/* written by the consumer, read by the producer */
	_Alignas(SPSC_CACHELINE) atomic_uint_least32_t tail;
	/* immutable after init, so it may share either line */
	_Alignas(SPSC_CACHELINE) uint32_t mask;
	struct spsc_slot *slot;
};

/* `cap` must be a power of two. Returns false if it is not, rather than
 * silently rounding — a ring whose capacity is not what the caller believes is
 * the kind of quiet mismatch this project keeps paying for. */
static inline bool
spsc_init(struct spsc *q, struct spsc_slot *storage, uint32_t cap)
{
	if (!cap || (cap & (cap - 1)))
		return false;
	q->slot = storage;
	q->mask = cap - 1;
	atomic_init(&q->head, 0);
	atomic_init(&q->tail, 0);
	return true;
}

/*
 * BATCHED PUSH. Stages up to `n` slots and publishes them with ONE release
 * store, so the ordering cost is per call rather than per item. Returns how
 * many were taken; a short return is back-pressure, not an error.
 */
static inline uint32_t
spsc_push_n(struct spsc *q, const struct spsc_slot *in, uint32_t n)
{
	uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
	uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
	uint32_t free_slots = q->mask - (head - tail);	/* one slot kept empty */
	uint32_t i;

	if (n > free_slots)
		n = free_slots;
	for (i = 0; i < n; i++)
		q->slot[(head + i) & q->mask] = in[i];
	/* the one barrier: everything staged above is visible before the index
	 * that publishes it */
	atomic_store_explicit(&q->head, head + n, memory_order_release);
	return n;
}

/*
 * BATCHED POP. One acquire load covers the whole batch, for the same reason.
 */
static inline uint32_t
spsc_pop_n(struct spsc *q, struct spsc_slot *out, uint32_t n)
{
	uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
	uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
	uint32_t avail = head - tail;
	uint32_t i;

	if (n > avail)
		n = avail;
	for (i = 0; i < n; i++)
		out[i] = q->slot[(tail + i) & q->mask];
	atomic_store_explicit(&q->tail, tail + n, memory_order_release);
	return n;
}

static inline uint32_t
spsc_count(const struct spsc *q)
{
	uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);

	return head - tail;
}

#endif /* SPSC_H */
