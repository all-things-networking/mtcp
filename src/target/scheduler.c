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
#include "internal.h"
#include "eth_in.h"
#include "flow_table.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
/*
 * The per-core transport state. Hangs off core_ctx->transport, which the
 * infrastructure allocates nothing for and never dereferences.
 *
 * Per core and shared-nothing, deliberately. A file-scope static would be the
 * same mistake the kernel effort's Homa branch makes with its scheduler
 * globals: correct with one stack thread and wrong with two, silently.
 */
struct transport {
	struct flow_table	*flows;
	struct listener_table	*listeners;
};

static struct transport *
tstate(struct core_ctx *core)
{
	return (struct transport *)core->transport;
}

int
TransportCoreInit(struct core_ctx *core)
{
	struct transport *t = calloc(1, sizeof(*t));

	if (!t)
		return -1;
	t->flows = FlowTableCreate();
	t->listeners = ListenerTableCreate();
	if (!t->flows || !t->listeners) {
		FlowTableDestroy(t->flows);
		ListenerTableDestroy(t->listeners);
		free(t);
		return -1;
	}
	core->transport = t;
	return 0;
}

void
TransportCoreFini(struct core_ctx *core)
{
	struct transport *t = tstate(core);

	if (!t)
		return;
	FlowTableDestroy(t->flows);
	ListenerTableDestroy(t->listeners);
	free(t);
	core->transport = NULL;
}

/*----------------------------------------------------------------------------*/
/*
 * The context store, as contract.h declares it (CR-3). These are the generic
 * reference realisation; the compiler will emit typed accessors over the
 * program's own context struct and these become their model, exactly as the
 * kernel effort keeps mtp_ctx_store.c.
 *
 * Single core today, so the store is reached through g_core[0]. That is a
 * placeholder and it is the one line that has to change when a second stack
 * thread exists — flagged rather than left to be discovered.
 */
void *
mtp_new_ctx(const flowkey_t *key, size_t ctx_size)
{
	return FlowTableInsert(tstate(g_core[0])->flows, key, ctx_size);
}

void *
mtp_ctx_lookup(const flowkey_t *key)
{
	return FlowTableLookup(tstate(g_core[0])->flows, key);
}

int
mtp_del_ctx(const flowkey_t *key)
{
	return FlowTableRemove(tstate(g_core[0])->flows, key);
}

/*----------------------------------------------------------------------------*/
/*
 * The infrastructure's upcall: a packet arrived whose IP protocol number is
 * the one the program claims.
 *
 * Counts it and drops it: the program's parser and dispatch do not exist yet.
 * When they do, the body is one call to mtp_program_net_input(), because under
 * v4 the parser, the store accessors and the dispatch are ALL generated and the
 * target does not own a dispatcher. That is a change from our design, which had
 * the target parse, look up and then call one program entry point.
 *
 * LOOKUP COUNT, stated honestly because it is a parity claim. The generated
 * dispatcher does ONE flow-table lookup per packet — against the prototype,
 * whose dispatcher re-looks-up per flag branch and pays up to four. A packet
 * that misses and is a passive open costs TWO: the flow lookup, then the
 * listener lookup. Claiming one everywhere would be wrong, and it is the SYN
 * path, which is once per connection rather than once per packet.
 */
static uint64_t transport_packets;

/*
 * What the receive path did with each packet, by class.
 *
 * mTCP counts packets in and packets in error and nothing between, so a packet
 * that arrives and is then dropped somewhere in eth_in/ip_in is invisible — it
 * looks exactly like a packet that never arrived. That ambiguity cost real time
 * on the first zero-receive result, so the classes are counted here rather than
 * reconstructed from a hex dump later.
 */
static struct {
	uint64_t arp, ipv4, other_ethertype;
	uint64_t ip_to_transport, ip_other_proto;
} rxc;

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
				if (pktbuf != NULL) {
					uint16_t et = (uint16_t)((pktbuf[12] << 8) | pktbuf[13]);

					if (et == 0x0806)
						rxc.arp++;
					else if (et == 0x0800) {
						rxc.ipv4++;
						if (len >= 24 && pktbuf[23] == TRANSPORT_IP_PROTO)
							rxc.ip_to_transport++;
						else
							rxc.ip_other_proto++;
					} else
						rxc.other_ethertype++;

					ProcessPacket(core, rx_inf, ts, pktbuf, len);
				}
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
	TRACE_INFO("CPU %d: rx classes: arp=%lu ipv4=%lu(proto-match=%lu other=%lu) "
		   "other_ethertype=%lu\n", ctx->cpu,
		   (unsigned long)rxc.arp, (unsigned long)rxc.ipv4,
		   (unsigned long)rxc.ip_to_transport,
		   (unsigned long)rxc.ip_other_proto,
		   (unsigned long)rxc.other_ethertype);
}
