/*
 * A queue of flows crossing the thread boundary.
 *
 * PORTED FROM mTCP's `struct stream_queue` (`mtcp/src/tcp_stream_queue.c`,
 * donor 7fbb223c), deliberately and near-literally. It replaces an SPSC ring of
 * our own — power-of-two mask, batched publish, C11 acquire/release — which was
 * three differences from the reference where none was needed (DESIGN.md §23,
 * rows 3/4/5). Where mTCP does a thing, we do that thing.
 *
 * WHAT IS KEPT FROM THE ORIGINAL, and why each is not an accident:
 *
 *   - `capacity + 1` slots, the spare distinguishing full from empty without a
 *     count. `NextIndex` wraps at `_capacity`, so the usable depth is
 *     `capacity`.
 *   - `volatile` head and tail rather than atomics, with a **compiler barrier
 *     only** between writing a slot and publishing the index
 *     (`__asm__ volatile("" : : "m"(...))`). Correct here for one producer and
 *     one consumer: on x86 TSO the two stores cannot be reordered by the
 *     hardware, and the barrier stops the compiler. We previously used real
 *     acquire/release, which was needed only because we batched; batching is
 *     gone, so the reason is gone.
 *   - The producer writes the slot, then the index; the consumer reads the
 *     slot, then advances. Single producer, single consumer, no lock: in mTCP
 *     `LOCK_STREAM_QUEUE` is FALSE and every `SQ_LOCK` compiles to `(void) 0`.
 *
 * CAPACITY IS FLOW COUNT, not a rate — and that is sound ONLY because every
 * producer is gated on a per-flow membership flag, so a flow written to three
 * hundred times in a scheduling slice enqueues once. mTCP relies on the same
 * property and does not check `StreamEnqueue`'s -1 at any call site. We put the
 * guard inside our enqueue helper instead of at the call sites, which the lead
 * has approved (§24) — the prototype is the worked example of call-site
 * guarding failing, having added a producer that sets the flag without testing
 * it (`api.c:1313-1320`).
 *
 * mTCP's `connectq` is sized `BACKLOG_SIZE`, not `max_concurrency`, so
 * "capacity by flow count" is not universal even in the reference. A queue
 * whose producers are not flow-gated needs its own capacity argument.
 *
 * No protocol identity here or in the name: rule 4 is unaffected.
 */
#ifndef FLOW_QUEUE_H
#define FLOW_QUEUE_H

#include <stdint.h>
#include <stdlib.h>

struct flow;

typedef uint32_t fq_index_t;

struct flow_queue {
	fq_index_t		 capacity;
	volatile fq_index_t	 head;
	volatile fq_index_t	 tail;
	struct flow * volatile	*q;
};

static inline fq_index_t
fq_next(const struct flow_queue *fq, fq_index_t i)
{
	return i != fq->capacity ? i + 1 : 0;
}

/* mTCP's StreamMemoryBarrier, name and all: a compiler barrier, no fence. */
static inline void
fq_memory_barrier(struct flow * volatile f, volatile fq_index_t i)
{
	__asm__ volatile("" : : "m" (f), "m" (i));
}

static inline int
fq_init(struct flow_queue *fq, fq_index_t capacity)
{
	fq->q = calloc((size_t)capacity + 1, sizeof(*fq->q));
	if (!fq->q)
		return -1;
	fq->capacity = capacity;
	fq->head = fq->tail = 0;
	return 0;
}

/* 0 on success, -1 if full. Full is structurally impossible while the
 * membership guard holds; the caller treats -1 as a broken invariant, not as
 * back-pressure. */
static inline int
fq_enqueue(struct flow_queue *fq, struct flow *f)
{
	fq_index_t h = fq->head;
	fq_index_t t = fq->tail;
	fq_index_t nt = fq_next(fq, t);

	if (nt != h) {
		fq->q[t] = f;
		fq_memory_barrier(fq->q[t], fq->tail);
		fq->tail = nt;
		return 0;
	}
	return -1;
}

static inline struct flow *
fq_dequeue(struct flow_queue *fq)
{
	fq_index_t h = fq->head;
	fq_index_t t = fq->tail;

	if (h != t) {
		struct flow *f = fq->q[h];

		fq_memory_barrier(fq->q[h], fq->head);
		fq->head = fq_next(fq, h);
		return f;
	}
	return NULL;
}

#endif /* FLOW_QUEUE_H */
