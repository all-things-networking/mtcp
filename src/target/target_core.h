#ifndef TARGET_CORE_H
#define TARGET_CORE_H
/*
 * The per-core transport state, hung off core_ctx->transport — which the
 * infrastructure allocates nothing for and never dereferences.
 *
 * Per core and shared-nothing. A file-scope static would be correct with one
 * stack thread and silently wrong with two, which is the mistake the kernel
 * effort's Homa branch makes with its scheduler globals.
 */
#include <sys/queue.h>

#include "contract.h"
#include "infra.h"
#include "flow_queue.h"

struct flow;
struct flow_table;
struct listener_table;
struct bp;

struct transport {
	struct flow_table	*flows;
	struct listener_table	*listeners;

	struct flow		*flow_pool;
	struct bp		*bp_pool;
	uint32_t		 flow_next;

	/* One per priority class; drained highest first (D-17). */
	TAILQ_HEAD(gen_head, flow) gen_list[MTP_PRIO_CLASSES];

	/*
	 * CROSS-THREAD NOTIFICATION (DESIGN.md §21.9/§21.10). The application
	 * thread cannot touch gen_list -- the stack thread walks it -- so it
	 * publishes the flow here and the stack thread moves it across at the
	 * top of its pass.
	 *
	 * CAPACITY IS FLOW COUNT, not a rate, and that is only sound because
	 * every producer is gated on the per-flow membership flag. A flow
	 * written to three hundred times in one scheduling slice enqueues ONCE.
	 * The guard therefore lives inside tgt_sched_enqueue() and not at the
	 * call sites: the prototype kept this ring, kept the capacity, then
	 * added a producer (mtcp_recv) that sets the flag without testing it,
	 * and its "this always success" comment quietly became false. A new
	 * producer cannot omit a guard it cannot reach.
	 */
	struct flow_queue	 q_notify;
	uint64_t		 stack_tid;	/* 0 until the stack thread runs */

	/*
	 * The readiness list — §17.6's target→app edge. Coalesced per flow, so
	 * it is bounded by flows rather than by packets; without that it is
	 * unbounded, which makes coalescing a correctness property and not only
	 * a performance one.
	 */
	/*
	 * Readiness, target->app. Two structures because two threads:
	 *
	 *   q_ready     the STACK publishes into this (flow pointers, same
	 *               ported queue as q_notify, same membership guard);
	 *   ready_list  the APPLICATION's own list, drained from q_ready at
	 *               poll time and re-armed into by the level check.
	 *
	 * The split is what lets the level-triggered re-arm stay in the target
	 * -- it runs on the application thread and touches only the
	 * application's list, so no structure has two writers.
	 */
	TAILQ_HEAD(ready_head, flow) ready_list;
	struct flow_queue	 q_ready;
	/* CR-E: application -> stack, "this flow has buffered bytes". */
	struct flow_queue	 q_send;

	/*
	 * The packet being dispatched, if any. The target attaches its L3
	 * addressing to a context the program creates during that dispatch,
	 * because the program's key is a shape it may not read and an address
	 * is below the transport boundary. NULL outside a packet dispatch.
	 */
	const struct iphdr	*cur_iph;
	struct flow		*cur_flow;	/* the flow being dispatched */

	/* counters that answer questions logs otherwise cannot */
	uint64_t		 tx_packets, tx_bytes, tx_bursted;
	uint64_t		 forced_drains;
	uint64_t		 bp_full, ring_drain_calls, merges;
	uint64_t		 tx_dropped_for_test;
	/*
	 * Frames the emit path decided on and did NOT put on the wire: the
	 * deliberate drop, and IPOutput refusing for want of an ARP entry.
	 * tx_packets counts frames that reached the END of emit_segment; the
	 * donor counts at SendTCPPacket, BEFORE any driver outcome. Without
	 * this the two totals are not the same set, and the difference carries
	 * the sign of the gap the comparison is trying to measure.
	 */
	uint64_t		 tx_suppressed;
	uint64_t		 drain_depth[5];	/* blueprints pending when the drain ran */
	uint64_t		 tx_hist_zero, tx_hist_full, tx_hist_short;
	uint32_t		 tx_hist_short_mode;
	uint64_t		 tx_hist_short_mode_n;
	uint64_t		 notifies[4];
	/* readiness, from both ends: what the transport put on the list and
	 * what the application found there. The pair discriminates "never
	 * notified" from "notified and the application saw nothing". */
	uint64_t		 polls;
	uint64_t		 poll_entries;
};

static inline struct transport *TransportOf(struct core_ctx *core)
{
	return (struct transport *)core->transport;
}

#endif /* TARGET_CORE_H */
