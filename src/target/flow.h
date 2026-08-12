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

	/* L3 addressing, learned by the target from the packet or the app op
	 * that created the flow. The program never sees an IP address unless
	 * its own events carry one — addressing below the transport is
	 * infrastructure's, and IPOutput's arguments are what need it. */
	uint32_t	 saddr, daddr;
	int		 nif_out;	/* from mTCP sndvar->nif_out: resolve the
					 * route once per flow, not per packet */
	uint8_t		 is_external;
	uint16_t	 ip_id;		/* per-flow counter from 0; ip_out.c:147 */

	/* the blueprint ring: a slice of the per-core pool, head/tail indices */
	struct bp	*ring;
	uint16_t	 ring_head, ring_tail;

	/* the generation list (P5) */
	TAILQ_ENTRY(flow) gen_link;
	uint8_t		 on_gen_list;
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
#define BP_RING_DEPTH	64

int         FlowPoolInit(struct core_ctx *core);
void        FlowPoolFini(struct core_ctx *core);

struct flow *FlowCreate(struct core_ctx *core, const flowkey_t *key,
			uint32_t saddr, uint32_t daddr);
void         FlowDestroy(struct core_ctx *core, struct flow *f);

#endif /* FLOW_H */
