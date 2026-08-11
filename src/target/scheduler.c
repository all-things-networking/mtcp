/*
 * The main loop, and the one call the infrastructure makes upward.
 *
 * Shape from mTCP core.c:771 RunMainLoop (mtcp-donor @7fbb223c), with
 * everything transport-shaped removed. What is left is the part that is the
 * same in both references and that parity depends on: one clock read per
 * iteration, the whole receive burst processed before any packet is formed,
 * then one transmit flush per interface.
 *
 * That ordering is not a detail. Processing the whole burst before forming any
 * packet is what makes acknowledgement coalescing possible at all (P2/P3), and
 * mTCP does the same, so it buys nothing over the donor — but losing it would
 * cost a great deal. It is here now so that it cannot be lost later by
 * accident.
 */
#include <sys/time.h>

#include "infra.h"
#include "upcall.h"
#include "scheduler.h"
/* Nothing here calls the contract yet. Included so that the compiler reads it
 * on every build — a header with no compiler in front of it stops being
 * checkable code and goes back to being prose. */
#include "contract.h"
#include "eth_in.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
/*
 * The infrastructure's upcall: a packet arrived whose IP protocol number is
 * the one the program claims.
 *
 * Increment 1 counts it and drops it. Increment 2 replaces the body with
 * ProgParse() -> one flow-table lookup -> ProgDispatch(), which is P6 with P6's
 * cost fixed: the prototype's dispatcher re-looks-up per flag branch and pays
 * up to four hash lookups per packet. One lookup per packet is the design, and
 * writing the stub as a single function with a single lookup site is how it
 * stays that way.
 */
static uint64_t transport_packets;

/*
 * Per-flow footprint, for the EAL's hugepage reservation (see upcall.h).
 *
 * Increment 1 has no flow record, so this is the donor's four structs added up
 * on this machine rather than a sizeof. It is replaced by the real expression
 * the moment src/target/flow.h exists, and it is wrong to leave it as a literal
 * for longer than that.
 */
const uint32_t TRANSPORT_PER_FLOW_BYTES = 1024;

int
TransportInput(struct core_ctx *core, uint32_t cur_ts, const int ifidx,
	       struct iphdr *iph, int ip_len)
{
	(void)core; (void)cur_ts; (void)ifidx; (void)iph; (void)ip_len;

	transport_packets++;
	return TRUE;
}
/*----------------------------------------------------------------------------*/
void
SchedRun(struct core_ctx *core, uint32_t max_ticks)
{
	struct thread_ctx *ctx = core->ctx;
	struct timeval tv = {0};
	uint32_t ts, ts_start;
	int rx_inf, tx_inf, i;

	gettimeofday(&tv, NULL);
	ts_start = TIMEVAL_TO_TS(&tv);

	while (!ctx->exit && !ctx->done) {
		/* one clock read per iteration; everything below uses it */
		gettimeofday(&tv, NULL);
		ts = TIMEVAL_TO_TS(&tv);
		core->cur_ts = ts;

		for (rx_inf = 0; rx_inf < CONFIG.eths_num; rx_inf++) {
			int recv_cnt = core->iom->recv_pkts(ctx, rx_inf);

			for (i = 0; i < recv_cnt; i++) {
				uint16_t len;
				uint8_t *pktbuf;

				pktbuf = core->iom->get_rptr(ctx, rx_inf, i, &len);
				if (pktbuf != NULL)
					ProcessPacket(core, rx_inf, ts, pktbuf, len);
#ifdef NETSTAT
				else
					core->nstat.rx_errors[rx_inf]++;
#endif
			}
		}

		/* increment 2: timers, then the generation list drain, then the
		 * application queues — all of them between here and the flush,
		 * because a blueprint committed now must reach this burst. */

		for (tx_inf = 0; tx_inf < CONFIG.eths_num; tx_inf++)
			core->iom->send_pkts(ctx, tx_inf);

		core->iom->select(ctx);

		if (max_ticks && (uint32_t)(ts - ts_start) >= max_ticks)
			break;
	}

	/* Both numbers, because they answer different questions. The first says
	 * whether the NIC is giving this process anything at all — with a
	 * bifurcated driver it may not be — and the second says whether the
	 * receive path reaches the layer above. A zero in the first is a
	 * steering problem; a zero in the second with a non-zero first is
	 * ours. */
	TRACE_INFO("CPU %d: out of main loop; %lu packets from the NIC, "
		   "%lu reached the transport.\n", ctx->cpu,
#ifdef NETSTAT
		   (unsigned long)core->nstat.rx_packets[0],
#else
		   0UL,
#endif
		   (unsigned long)transport_packets);
}
