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

	TAILQ_HEAD(gen_head, flow) gen_list;

	/*
	 * The readiness list — §17.6's target→app edge. Coalesced per flow, so
	 * it is bounded by flows rather than by packets; without that it is
	 * unbounded, which makes coalescing a correctness property and not only
	 * a performance one.
	 */
	TAILQ_HEAD(ready_head, flow) ready_list;

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
