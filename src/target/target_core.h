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

/*
 * THE TIMER WHEEL, PER CORE -- both references keep their timer state in the
 * per-core manager and neither has a file-scope timer static. Ours were five
 * (timer.c), which is the "only one thread touches it" assumption in the same
 * form as everything else this rework has been unwinding, and it stopped being
 * true the moment a second thread existed.
 */
/* One entry per flow at most: the membership flag makes duplicates
 * impossible, so this cannot need more than the flow pool holds. */
#define MTP_RETRY_MAX	4096

#define WHEEL_BUCKETS	4096		/* 1-tick buckets, ~4 s of range */

struct timer_wheel {
	struct mtp_timer *bucket[WHEEL_BUCKETS];
	struct mtp_timer *overflow;	/* deadlines beyond the wheel's range */
	uint32_t	  now;
	int		  started;
	uint64_t	  fires;
};

struct transport {
	struct flow_table	*flows;
	struct listener_table	*listeners;

	/* GAUGE: flows whose protocol has finished and whose application has not
	 * let go. Rises on del_ctx, falls when the detach arrives, and whatever
	 * is left at exit is a real leak -- a context and two ring buffers each.
	 * Nothing else reports it. */
	uint64_t		 awaiting_app;

	/* D3: flows the program asked to re-attempt next pass, and how many
	 * such attempts have been made. A flow blocked for a long time is
	 * retried every pass, which is the donor's cost as well as ours. */
	struct flow		*retry[MTP_RETRY_MAX];
	unsigned		 retry_n;
	uint64_t		 retries;

	/*
	 * A PACKET THAT BELONGS TO NO FLOW needs a route cache and an IP
	 * identifier and nothing else, so this is four scalars rather than a
	 * flow record. Deliberately not a `struct flow`: it is in no table, has
	 * no context, is never looked up, and giving it the type would invite
	 * all three.
	 */
	int			 orphan_nif;	/* route cache, per destination */
	uint8_t			 orphan_external;
	uint16_t		 orphan_ip_id;
	uint32_t		 orphan_saddr, orphan_daddr;
	uint64_t		 orphans_sent;
	uint64_t		 ready_inserted, ready_coalesced;
	uint64_t		 wait_calls, wait_early_q, wait_early_list;
	uint8_t			 wake_pending;	/* this pass made something ready */
	/*
	 * THE FIVE THAT MUST COMPOSE. del_ctx and detach are the two events;
	 * destroyed is what should equal the number of flows that saw both.
	 * They are here because the gauge above read 112-of-112 while the
	 * application had demonstrably called close 112 times, and those two
	 * cannot both be true.
	 */
	uint64_t		 n_delctx;	/* del_ctx calls that found a flow */
	uint64_t		 n_delctx_miss;	/* ...and ones that did not */
	uint64_t		 n_detach;	/* app close calls */
	uint64_t		 n_detach_late;	/* ...that found proto_done */
	uint64_t		 n_destroyed;	/* flows actually destroyed */

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
	 * The guard therefore lives inside AddtoSendList() and not at the
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
	/* flows the program has finished with, destroyed at a safe point */
	TAILQ_HEAD(destroy_head, flow) destroy_list;

	/* per core, not file scope */
	struct timer_wheel	 timers;
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
	uint16_t		 cur_sport, cur_dport;	/* the same, at L4 */
	/* The application op being dispatched, for a flow no packet created.
	 * NULL outside an app call, exactly as cur_iph is outside a packet. */
	const struct mtp_app_op	*cur_op;
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

	/*
	 * BOUNDARY CROSSINGS, counted because the 3.2x throughput loss under
	 * threading is unattributed and this is what tests the obvious
	 * attribution. The donor crosses once per application write and once
	 * per readiness event; if ours is comparable and we still lose 3.2x,
	 * the boundary is not the cost. If ours is an order of magnitude
	 * higher, the boundary is carrying something §21.6 says it must not.
	 */
	uint64_t		 cross_send;	/* app -> stack: send/close */
	uint64_t		 cross_notify;	/* app -> stack: generation */
	uint64_t		 cross_ready;	/* stack -> app: readiness */

	/*
	 * A flush asking to free past what the wire has carried. The existing
	 * ack-past-send_next counter CANNOT see this case: send_next runs ahead
	 * of the wire by the undrained backlog, so an acknowledgement past the
	 * wire but short of send_next is silent by construction. This is the
	 * bound that matters.
	 */
	uint64_t		 flush_past_emitted;

	/* Overlapping commits, by whether the NEW one is a retransmission.
	 * The rate, not the crash, is the measurable. */
	uint64_t		 overlap_rtx;
	/* references a flow still held when it was destroyed -- see FlowDestroy */
	uint64_t		 refs_at_destroy;
	uint32_t		 refs_at_destroy_shown;
	uint64_t		 overlap_new;
	uint64_t		 overlap_merge_ok;	/* superseding its own: by design */
	uint64_t		 overlap_merge_bad;	/* a merge over something else */
	uint64_t		 release_base_mismatch;	/* release names a base the take did not */
	uint64_t		 unreachable_ring;	/* ring non-empty, flow not listed */
	/*
	 * THE APPLICATION'S SLEEP. From mTCP: its application thread blocks in
	 * mtcp_epoll_wait -> pthread_cond_wait with no spin first, and its stack
	 * thread wakes it -- B measured 15 695 voluntary switches a second on the
	 * donor's application thread against 0 on its stack thread. Two threads
	 * that both spin on one core only alternate when preempted, at a 4 ms
	 * slice; this hands the core over when the work appears.
	 */
	pthread_mutex_t		 app_lock;
	pthread_cond_t		 app_cv;
	volatile int		 app_waiting;
	/* What the application thread is doing, sampled by the stack when the
	 * transmit ring is empty. Distinguishes a capacity problem from a
	 * scheduling one: a ring that is empty while the application is blocked
	 * in a write is not the same fault as one empty while it waits. */
	volatile uint8_t	 app_state;	/* 0 running, 1 in write, 2 waiting */
	uint64_t		 app_sleeps, app_wakes, app_timeouts;

	/* Staging-to-flush: when the FIRST frame of this pass was handed an
	 * mbuf, and how many have been staged since. The per-iteration clock
	 * cannot measure this -- it is read once per pass, so if staging and
	 * flushing share a pass it reads zero by construction. */
	uint64_t		 stage_first_us;
	uint32_t		 staged;
	uint64_t		 stage_hist[8], stage_n, stage_sum, stage_max;
	uint64_t		 depth_hist[8];

	uint64_t		 flush_short;		/* flushes that could not reach upto */
	uint64_t		 flush_short_bytes;
	uint32_t		 flush_short_run_max;	/* longest consecutive run */
	uint64_t		 emit_refused;		/* emit_bp said no: walk abandoned */
	uint64_t		 emit_refused_arp;	/* ...ARP entry absent */
	uint64_t		 emit_refused_noframe;	/* ...no transmit frame: back-pressure */
	uint64_t		 emit_refused_offload;	/* ...offload not advertised */
	uint64_t		 drain_pass;		/* monotonic drain-pass number */
	uint8_t			 forced_drain_gave_up;	/* ...on the most recent forced one */
	uint64_t		 below_wire_rtx;	/* commit below emitted_hwm */
	uint64_t		 below_wire_new;	/* starts below, has new bytes on top */
	uint64_t		 below_wire_dead;	/* entirely below: can never drain */

	/*
	 * High-water pending blueprints per class, so the ring depths are sized
	 * from what the classes actually hold rather than from one number
	 * copied across all three. Depth 64 is a data-path figure; control and
	 * acknowledgement are not the data path.
	 */
	uint32_t		 ring_hwm[MTP_PRIO_CLASSES];
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
