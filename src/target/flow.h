#ifndef FLOW_H
#define FLOW_H
/*
 * The target's per-flow record — everything the target keeps about a flow, and
 * nothing about the protocol.
 *
 * This is NOT the program's context. Under CR-3 the context is the program's
 * own generated struct and the target does not know what is in it; `ctx` below
 * is a pointer to it and that is the whole of the target's interest.
 *
 * Shape from mTCP's `tcp_stream` minus the transport: the output-interface
 * cache and the per-flow IP id are the two things the donor keeps here that we
 * still need, because they are L3 and L3 is below the boundary.
 */
#include <sys/queue.h>

#include "contract.h"
#include "internal.h"
#include "infra.h"

struct flow {
	flowkey_t	 key;
	void		*ctx;		/* the program's generated context */

	/* §24: the application names this flow by this, and keeps its own
	 * state in its own table. The target never interprets it. */
	uint32_t	 id;

	/* L3 addressing, learned by the target from the packet or the app op
	 * that created the flow. The program never sees an IP address unless
	 * its own events carry one — addressing below the transport is
	 * infrastructure's, and IPOutput's arguments are what need it. */
	uint32_t	 saddr, daddr;
	int		 nif_out;	/* from mTCP sndvar->nif_out: resolve the
					 * route once per flow, not per packet */
	uint8_t		 is_external;
	uint16_t	 ip_id;		/* per-flow counter from 0; ip_out.c:147 */

	/*
	 * BLUEPRINT STORAGE PER (FLOW, CLASS) -- mTCP's shape, where a stream
	 * carries on_control_list, on_ack_list and on_send_list as SEPARATE
	 * flags and sits on several lists at once (tcp_stream.c:486-488
	 * unlinks from all three). A flow appears on every list it has packets
	 * for; it is NOT lifted to the class of its highest pending blueprint,
	 * which was a divergence and is gone.
	 *
	 * One ring per class, each a slice of the per-core pool.
	 */
	struct bp	*ring[MTP_PRIO_CLASSES];
	uint16_t	 ring_head[MTP_PRIO_CLASSES];
	uint16_t	 ring_tail[MTP_PRIO_CLASSES];

	/* the generation list (P5) */
	TAILQ_ENTRY(flow) ready_link;
	uint8_t		 on_ready_list;
	uint32_t	 ready_kinds;	/* bitmask of notify kinds pending */
	struct mtp_data_unit *tx_unit;	/* recorded when the program creates it,
					 * so the target can see its own ring's
					 * occupancy for WRITABLE (D-23) */
	struct mtp_data_unit *rx_unit;	/* recorded when the program creates it,
					 * so the target can re-present READABLE
					 * while bytes remain unread */

	/*
	 * One link and one membership flag PER CLASS: a flow is on every list
	 * it has packets for, as mTCP's is. The guard is per (flow, class) and
	 * stays inside the enqueue helper.
	 */
	TAILQ_ENTRY(flow) gen_link[MTP_PRIO_CLASSES];
	uint8_t		 on_gen[MTP_PRIO_CLASSES];

	/*
	 * CR-E. The application thread buffers payload straight into the ring
	 * and records the EXTENT here; the stack thread invokes the program's
	 * SEND for that extent. The bytes never cross a queue -- only the fact
	 * that they exist -- which is what the donor does (its mtcp_write
	 * copies under the buffer lock and enqueues the stream).
	 */
	uint32_t	 pending_send;	/* bytes buffered, not yet handed over */
	uint8_t		 pending_close;	/* application has closed; stack must act */
	uint8_t		 on_send_q;

	/*
	 * DETACH-THEN-ENQUEUE (DESIGN.md §21.5). The application thread clears
	 * its handle FIRST, then publishes the close; the queue's release/
	 * acquire pair orders the two, so by the time the stack sees the close
	 * the application is already off this flow. The prototype does exactly
	 * this and its ordering comes from the barrier inside the ring, not
	 * from a lock -- there is no lock in either reference here.
	 */
	uint8_t		 app_detached;

	/*
	 * DESTROY IS DEFERRED TO A SAFE POINT, never done inside a program
	 * call. mtp_del_ctx used to free the entry -- and the program context
	 * and both data units inside it -- while still inside
	 * mtp_program_net_input, after which TransportInput dereferenced
	 * f->rx_unit and f->tx_unit through ready_level_check. A confirmed
	 * use-after-free on every connection's close path, invisible because
	 * glibc leaves a just-freed small block intact.
	 */
	uint8_t		 pending_destroy;
	TAILQ_ENTRY(flow) destroy_link;
	uint8_t		 scratch_out[MTP_PRIO_CLASSES];	/* a tgt_bp_new() awaiting commit */
};

/*
 * The blueprint ring is a per-core array with per-flow slices, NOT inline in
 * the flow record. The prototype embeds 1000 x 80 B in every flow — 80 KB each,
 * ~328 MB per core at max_concurrency 4096. A slice of 64 costs ~25 MB per core
 * for the same concurrency. A flow cannot usefully hold more than a burst of
 * blueprints when the drain runs once per iteration.
 *
 * That it is also better for cache is a HYPOTHESIS and untested, and it is a
 * change from the prototype, so it is on the change-one-thing-at-a-time list.
 */
/*
 * PER-CLASS RING DEPTH, SIZED FROM MEASUREMENT.
 *
 * Measured high-water of pending blueprints per flow, per class, under load
 * (c=1 and c=4, reported by SchedReport): class 0 = 2, class 1 = 1, class 2 = 1.
 * The figure does not grow with concurrency, because it is per flow and the
 * drain empties a flow's ring each pass.
 *
 * Uniform depth 64 across three classes was an assumption, not a decision, and
 * cost 162 MB at max_concurrency against 54 MB before the split. Sized here
 * instead:
 *
 *   class 0 (data)  64  -- kept. It is the class that backs up when the
 *                          transmit buffer fills and the drain abandons its
 *                          walk, which the measured figure of 2 does not
 *                          exercise. The existing, tested depth stays.
 *   class 1 (ack)    8  -- measured 1; 8x headroom. Not the data path.
 *   class 2 (ctrl)   8  -- measured 1; 8x headroom. Not the data path.
 *
 * 80 slots per flow at 216 bytes = 17 280 B, so 67.5 MB at 4096 flows rather
 * than 162 MB. mTCP pays none of this -- its lists are intrusive, three link
 * fields per stream -- so this is the cost of our ring design, minimised rather
 * than assumed.
 */
#define BP_RING_DEPTH	64		/* class 0; also the pool slice size */
#define BP_DEPTH_ACK	8
#define BP_DEPTH_CTRL	8

/* Depth of class `c`'s ring. The pool slice is BP_RING_DEPTH for every class
 * so the arithmetic in FlowCreate stays one multiply; the shorter classes
 * simply do not use the tail of their slice. Trading 0.5 MB of address space
 * for not having a variable-stride pool index. */
static inline uint16_t bp_depth(int c)
{
	return c == 0 ? BP_RING_DEPTH
	     : c == 1 ? BP_DEPTH_ACK
		      : BP_DEPTH_CTRL;
}

int         FlowPoolInit(struct core_ctx *core);
void        FlowPoolFini(struct core_ctx *core);

struct flow *FlowCreate(struct core_ctx *core, const flowkey_t *key,
			uint32_t saddr, uint32_t daddr);
void         FlowDestroy(struct core_ctx *core, struct flow *f);

#endif /* FLOW_H */
