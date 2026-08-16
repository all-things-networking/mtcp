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
#include <signal.h>
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
#include "flow.h"
#include "target_core.h"
#include "internal.h"
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
int
TransportCoreInit(struct core_ctx *core)
{
	struct transport *t = calloc(1, sizeof(*t));

	if (!t)
		return -1;
	TAILQ_INIT(&t->ready_list);
	t->flows = FlowTableCreate();
	t->listeners = ListenerTableCreate();
	core->transport = t;
	if (!t->flows || !t->listeners || FlowPoolInit(core) < 0) {
		TransportCoreFini(core);
		return -1;
	}
	return 0;
}

void
TransportCoreFini(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);

	if (!t)
		return;
	FlowPoolFini(core);
	FlowTableDestroy(t->flows);
	ListenerTableDestroy(t->listeners);
	free(t);
	core->transport = NULL;
}

/*
 * READABLE, from the level rather than from an edge.
 *
 * The rx unit holds unread bytes, so the flow belongs on the readiness list —
 * whether it got there by arriving data or by still holding data after a
 * partial read. Both callers are the same question asked at the two moments it
 * can change: bytes went in, and bytes came out.
 *
 * This was the re-insert inside TransportPoll and nothing else, which made the
 * target's "level-triggering" a continuation with no beginning: only a flow
 * ALREADY on the list could ever gain READABLE. It worked solely because a
 * passive open notifies STATE, putting the flow on the list, and the data used
 * to arrive before the application drained that entry. Speed up the poll loop
 * and the entry is gone before the first byte lands — a race the workload had
 * been hiding, not a bug the changes introduced.
 */
static void
ready_raise(struct transport *t, struct flow *f, int kind)
{
	f->ready_kinds |= (1u << kind);
	if (!f->on_ready_list) {
		TAILQ_INSERT_TAIL(&t->ready_list, f, ready_link);
		f->on_ready_list = 1;
	}
	t->notifies[kind & 3]++;
}

static void
ready_level_check(struct transport *t, struct flow *f)
{
	if (f->rx_unit && f->rx_unit->tail_seq > f->rx_unit->head_seq)
		ready_raise(t, f, MTP_NOTIF_READABLE);

	/*
	 * WRITABLE, D-23, and it gets BOTH HALVES for the same reason READABLE
	 * does. want_space is set by the truncated write — the establishment —
	 * and this is the maintenance: while the application is waiting and the
	 * ring has room, the flow keeps being presented. A program that had to
	 * re-issue would be the edge-triggered stall arriving in a second place,
	 * and that argument was settled once already (§17.6a).
	 *
	 * Cleared here rather than by the application, because the target is
	 * what knows the space exists. The application asking again for a ring
	 * that is still full simply re-sets it.
	 */
	if (f->tx_unit && f->tx_unit->want_space && tgt_tx_space(f->tx_unit)) {
		f->tx_unit->want_space = 0;
		ready_raise(t, f, MTP_NOTIF_WRITABLE);
	}
}

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/*
 * The application drains readiness once per iteration. Returns how many flows
 * it wrote, each with the kinds pending on it.
 *
 * This is the target's side of §17.6 and it is OURS: the kernel maps
 * notifications onto socket wakeups because that suits Linux; a single-threaded
 * poller wants a list. The program cannot see which, which is the property that
 * matters.
 */
void *
mtp_ctx_of(flow_t *f)
{
	/*
	 * Also the point at which the target learns which flow is being worked
	 * on OUTSIDE packet dispatch. The program calls this at the top of every
	 * app op that names a flow, so a transmit ring created lazily on a first
	 * write — which happens in the application callback, where there is no
	 * packet being dispatched — still records its owner (D-23).
	 */
	TransportOf(g_core[0])->cur_flow = (struct flow *)f;
	return ((struct flow *)f)->ctx;
}

int
TransportPoll(struct core_ctx *core, struct mtp_ready *out, int max)
{
	struct transport *t = TransportOf(core);
	int n = 0;

	t->polls++;
	while (n < max) {
		struct flow *f = TAILQ_FIRST(&t->ready_list);

		if (!f)
			break;
		TAILQ_REMOVE(&t->ready_list, f, ready_link);
		f->on_ready_list = 0;
		out[n].flow = (flow_t *)f;
		out[n].kinds = f->ready_kinds;
		f->ready_kinds = 0;
		n++;
		t->poll_entries++;

		/*
		 * LEVEL-TRIGGERED, AND IT IS THE TARGET'S. While the unit still
		 * holds unread bytes the flow goes back on the list, so a
		 * partial read cannot lose the remainder.
		 *
		 * Structural rather than conventional: if the program had to
		 * re-issue, a program that forgot would produce the
		 * edge-triggered stall — intermittent, load-dependent, and
		 * presenting as a window-management divergence through
		 * `delivered`. Every program would also implement the same
		 * re-issue identically, which is the signature of something
		 * that belongs here. Rule 4 asks the target not to know
		 * protocols; it does not ask it to be minimal.
		 */
		ready_level_check(t, f);
	}
	return n;
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
	struct core_ctx *core = g_core[0];
	struct transport *t = TransportOf(core);
	struct flow *f;
	void *ctx;
	uint32_t saddr = 0, daddr = 0;

	/* L3 addressing comes from the packet being dispatched, never from the
	 * program: its key is a shape it may not read. */
	if (t->cur_iph) {
		saddr = t->cur_iph->daddr;	/* ours is the packet's dest */
		daddr = t->cur_iph->saddr;
	}

	ctx = FlowTableInsert(t->flows, key, ctx_size);
	if (!ctx)
		return NULL;
	f = FlowCreate(core, key, saddr, daddr);
	if (!f) {
		FlowTableRemove(t->flows, key);
		return NULL;
	}
	f->ctx = ctx;

	/* The compiler places its target handle first in the generated context
	 * struct; the program passes it back to pkt_gen and never looks in. */
	*(flow_t **)ctx = f;
	t->cur_flow = f;	/* for instructions that carry no flow */
	return ctx;
}

void *
mtp_ctx_lookup(const flowkey_t *key)
{
	struct transport *t = TransportOf(g_core[0]);
	void *ctx = FlowTableLookup(t->flows, key);

	if (ctx)
		t->cur_flow = *(struct flow **)ctx;
	return ctx;
}

int
mtp_del_ctx(const flowkey_t *key)
{
	return FlowTableRemove(TransportOf(g_core[0])->flows, key);
}

/*----------------------------------------------------------------------------*/
/*
 * The contract's unit initialiser. It lives here rather than in tx_stream.c
 * because THIS is where the configuration and the per-core context are
 * visible: the ring itself takes its capacity as a parameter and its forced
 * drain as a callback, and depends on neither.
 *
 * The round up to a power of two is at the call site on purpose. off_of() masks
 * with cap-1, and sndbuf is a value from the DONOR'S RUNNING CONFIGURATION, so
 * silently using a different size is a parity change and not merely a buffer
 * change. It says so out loud when it happens.
 */
static void
drain_this_core(void *arg)
{
	struct core_ctx *core = arg;

	TransportOf(core)->forced_drains++;
	tgt_drain(core);
}

void
mtp_new_rx_ordered_data(struct mtp_data_unit *u, uint64_t size)
{
	uint32_t cap = 1;

	struct transport *t = TransportOf(g_core[0]);

	while (cap < (uint32_t)CONFIG.rcvbuf_size)
		cap <<= 1;
	if (tgt_rx_unit_init(u, size, cap, 0) < 0)
		TRACE_ERROR("could not allocate a %u byte receive ring\n", cap);

	/* Record it against the flow being dispatched, so the target can see
	 * its OWN bookkeeping — occupancy — when deciding whether to re-present
	 * READABLE. The unit's layout is the target's under D-19; this is not
	 * reading program state. */
	if (t->cur_flow)
		t->cur_flow->rx_unit = u;
}

void
mtp_new_tx_ordered_data(struct mtp_data_unit *u, uint64_t size)
{
	struct core_ctx *core = g_core[0];	/* single core; see above */
	uint32_t cap = 1;

	while (cap < (uint32_t)CONFIG.sndbuf_size)
		cap <<= 1;
	if (cap != (uint32_t)CONFIG.sndbuf_size)
		TRACE_CONFIG("sndbuf %d is not a power of two; the transmit "
			     "ring uses %u. Set sndbuf to a power of two to "
			     "keep the buffer size the donor is measured "
			     "with.\n", CONFIG.sndbuf_size, cap);

	if (tgt_tx_unit_init(u, size, cap, drain_this_core, core) < 0)
		TRACE_ERROR("could not allocate a %u byte transmit ring\n", cap);

	/* the flow this ring belongs to, so a short write can name who to wake
	 * (D-23). Same recording as the receive side, for the same reason. */
	if (TransportOf(core)->cur_flow) {
		TransportOf(core)->cur_flow->tx_unit = u;
		u->owner = TransportOf(core)->cur_flow;
	}
}

/*----------------------------------------------------------------------------*/
/*
 * mtp_notify — the program tells the application something happened; the target
 * decides how to deliver it.
 *
 * The kernel maps each kind onto sk_data_ready and friends. Ours will map them
 * onto the epoll shim, which does not exist yet, so for now the kinds are
 * counted and the last one is kept. That is enough for the handshake — a
 * completed passive open raises STATE and nothing is waiting on it — and it is
 * a placeholder that is honest about being one rather than a silent no-op.
 */
int
mtp_notify(flow_t *f, const struct mtp_notif *msg)
{
	struct transport *t = TransportOf(g_core[0]);

	(void)f;
	t->notifies[msg->kind & 3]++;

	/*
	 * COALESCED: a flow already on the list gains the kind and does not gain
	 * an entry. The program issues a notification per merge, so without this
	 * the list would grow once per received segment.
	 *
	 * Level-triggering is the PROGRAM's: it re-issues while unread bytes
	 * remain. The target only coalesces and delivers — it does not inspect
	 * the unit to decide, which would be the target reading program state.
	 */
	f->ready_kinds |= (1u << (msg->kind & 3));
	if (!f->on_ready_list) {
		TAILQ_INSERT_TAIL(&t->ready_list, f, ready_link);
		f->on_ready_list = 1;
	}
	return 0;
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
	/* D-22: csum_seen says the hardware answered at all, which is a
	 * different fact from the count of frames it condemned. Without the
	 * first, a zero in the second reads as "no corruption" when it may mean
	 * "nothing was ever checked". */
	uint64_t csum_bad;
	int      csum_seen;
} rxc;

/*----------------------------------------------------------------------------*/
/*
 * D-22 — should this frame be dropped for a failed layer-4 checksum?
 *
 * THE DONOR WOULD ACCEPT IT. Its only reader of the flag is inside `#if 0` and
 * its software fallback is switched off by a capability test that succeeds on
 * this NIC, so a corrupt segment with an intact header reaches its application.
 * We diverge deliberately, and the divergence is unobservable under rule 1:
 * it can only be seen on a frame that fails its checksum, which does not occur
 * on a clean link, so no packet count, size, acknowledgement or trajectory
 * differs. Recorded as D-22, and the reason lives with the decision.
 *
 * Nothing here names a protocol: the question is "did the hardware verify the
 * layer-4 payload checksum", which is a property of the offload, not of TCP.
 */
static int
rx_csum_rejects(struct core_ctx *core, int ifidx, int index)
{
	int verdict;

	if (!core->iom->rx_csum_verdict)
		return 0;
	verdict = core->iom->rx_csum_verdict(core->ctx, ifidx, index);
	if (verdict == 1)
		rxc.csum_seen = 1;

	/*
	 * THE INJECTOR. This check can never fire in normal operation, which
	 * puts it on the dormant list with the standing expectation that
	 * something latent sits underneath. MTP_CORRUPT_NTH_RX=n condemns every
	 * nth frame the hardware passed, so the drop path is demonstrated
	 * rather than assumed — the analogue of MTP_DROP_NTH_DATA, and built
	 * with the mechanism rather than after it.
	 */
	if (verdict == 1) {
		const char *n = getenv("MTP_CORRUPT_NTH_RX");

		if (n && atoi(n) > 0) {
			static uint64_t seen;

			if (++seen % (uint64_t)atoi(n) == 0) {
				fprintf(stderr, "MTP_CORRUPT_NTH_RX: condemning "
					"frame %lu — the transport must never "
					"see it\n", (unsigned long)seen);
				return 1;
			}
		}
	}
	/*
	 * REQUIRE A POSITIVE VERDICT — do not merely avoid a negative one.
	 * MEASURED, because the reading and the measurement disagreed here.
	 *
	 * B's trace said mlx4 sets only the GOOD bits and never BAD; the first
	 * implementation therefore mapped "neither" to "the hardware did not
	 * answer" and trusted the frame. A real corrupt SYN put on the wire by
	 * tools/corrupt_sender.py came back with l4 flags of exactly 0x0 while
	 * its uncorrupted twin came back 0x100 (GOOD) — so on this driver
	 * ABSENCE OF GOOD IS THE ONLY REPRESENTATION OF BAD, and a check that
	 * waits for an explicit condemnation waits for ever. Both SYNs were
	 * answered. The trap has a second side and only the wire showed it.
	 *
	 * Which is why this is applied ONLY to frames carrying the program's
	 * own IP protocol. A frame the device did not parse for layer 4 — ARP,
	 * ICMP — reports the same 0x0, and a rule reading that as corruption
	 * would drop address resolution and take the node off the network. The
	 * scope is the caller's, in the classification, where the protocol
	 * match has already been made.
	 */
	return verdict != 1;
}

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
	const uint8_t *l4 = (const uint8_t *)iph + (iph->ihl << 2);
	uint16_t l4_len = (uint16_t)(ip_len - (iph->ihl << 2));

	(void)ifidx;

	transport_packets++;

	/* The packet being dispatched, so a context created during it can be
	 * given its L3 addressing. The program's key is a shape the target may
	 * not read and an address is below the transport boundary. */
	TransportOf(core)->cur_iph = iph;
	mtp_program_net_input(l4, l4_len, iph, cur_ts);
	/* the edge: whatever the program merged is now readable */
	if (TransportOf(core)->cur_flow)
		ready_level_check(TransportOf(core), TransportOf(core)->cur_flow);
	TransportOf(core)->cur_iph = NULL;
	TransportOf(core)->cur_flow = NULL;

	return TRUE;
}
/*----------------------------------------------------------------------------*/
volatile sig_atomic_t SchedStopRequested;

/*
 * ONE iteration of the loop, exposed so the APPLICATION can drive the target
 * instead of the target driving the application. The mTCP compatibility shim
 * needs that inversion: epserver owns its own event loop and calls
 * mtcp_epoll_wait, which pumps the target once (DESIGN.md §20).
 *
 * SchedRun is now this in a while loop, so there is ONE body and the two entry
 * points cannot drift apart. A second copy of the receive/app/drain order
 * would be the "one site of a kind" defect the standing rules name.
 *
 * No protocol identity here or in the name: rule 4 is unaffected.
 */
void
SchedStep(struct core_ctx *core,
	  void (*app)(struct core_ctx *, uint32_t now, void *), void *app_arg)
{
	struct thread_ctx *ctx = core->ctx;
	struct timeval tv = {0};
	uint32_t ts;
	int rx_inf, tx_inf, i;


		/* one clock read per iteration; everything below uses it */
		gettimeofday(&tv, NULL);
		ts = TIMEVAL_TO_TS(&tv);
		core->cur_ts = ts;

		for (rx_inf = 0; rx_inf < CONFIG.eths_num; rx_inf++) {
			int recv_cnt = core->iom->recv_pkts(ctx, rx_inf);

			for (i = 0; i < recv_cnt; i++) {
				uint16_t len;
				uint8_t *pktbuf;
				int drop_csum = 0;

				pktbuf = core->iom->get_rptr(ctx, rx_inf, i, &len);
				if (pktbuf != NULL) {
					uint16_t et = (uint16_t)((pktbuf[12] << 8) | pktbuf[13]);

					if (et == 0x0806)
						rxc.arp++;
					else if (et == 0x0800) {
						rxc.ipv4++;
						if (len >= 24 && pktbuf[23] == TRANSPORT_IP_PROTO) {
							rxc.ip_to_transport++;
							/* D-22: judged only here.
							 * See rx_csum_rejects. */
							drop_csum = rx_csum_rejects(
								core, rx_inf, i);
						} else
							rxc.ip_other_proto++;
					} else
						rxc.other_ethertype++;

					if (drop_csum)
						rxc.csum_bad++;
					else
						ProcessPacket(core, rx_inf, ts,
							      pktbuf, len);
				}
#ifdef NETSTAT
				else
					core->nstat.rx_errors[rx_inf]++;
#endif
			}
		}

		/* Timers, then the drain — between the burst and the flush,
		 * because a blueprint committed by either must reach this
		 * burst. mTCP checks its retransmission timers at exactly this
		 * point (core.c:822). */
		/* the application, between the burst and the drain, so what it
		 * writes reaches this iteration's flush */
		/*
		 * The application's publications, taken BEFORE the drain so a
		 * write reaches the wire in this pass rather than the next
		 * (DESIGN.md §21.5 C4). The app callback that used to run here
		 * is gone: that parameter WAS the inline coupling.
		 */
		tgt_sched_take_notifications(core);
		if (app)
			app(core, ts, app_arg);

		TimerTick(ts);
		tgt_drain(core);

		/*
		 * What the burst actually accepted, as against what we handed
		 * it. tx_packets counts frames BUILT inside emit_segment; this
		 * counts frames the driver took. A frame that is built and not
		 * sent is sitting in the transmit buffer, and nothing about
		 * its contents matters until that is ruled out.
		 */
		for (tx_inf = 0; tx_inf < CONFIG.eths_num; tx_inf++) {
			int sent = core->iom->send_pkts(ctx, tx_inf);

			if (sent > 0)
				TransportOf(core)->tx_bursted += sent;
		}

		core->iom->select(ctx);
}

void
SchedRun(struct core_ctx *core, uint32_t max_ticks,
	 void (*app)(struct core_ctx *, uint32_t now, void *), void *app_arg)
{
	struct thread_ctx *ctx = core->ctx;
	struct timeval tv = {0};
	uint32_t ts, ts_start;

	gettimeofday(&tv, NULL);
	ts_start = TIMEVAL_TO_TS(&tv);

	while (!ctx->exit && !ctx->done && !SchedStopRequested) {
		SchedStep(core, app, app_arg);
		gettimeofday(&tv, NULL);
		ts = TIMEVAL_TO_TS(&tv);
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
	{
		struct transport *t = TransportOf(core);

		/* The send path's own account, so "nothing came out" can be
		 * attributed without a rebuild: whether a blueprint was ever
		 * refused, whether the drain ran, and whether a packet was
		 * ever handed to the interface. */
		TRACE_INFO("CPU %d: tx: packets=%lu bytes=%lu drains=%lu "
			   "ring-full=%lu forced-drains=%lu bursted=%lu merges=%lu\n", ctx->cpu,
			   (unsigned long)t->tx_packets,
			   (unsigned long)t->tx_bytes,
			   (unsigned long)t->ring_drain_calls,
			   (unsigned long)t->bp_full,
			   (unsigned long)t->forced_drains,
			   (unsigned long)t->tx_bursted,
			   (unsigned long)t->merges);
	TRACE_INFO("CPU %d: frames handed down = %lu counted + %lu suppressed\n",
		   ctx->cpu, (unsigned long)TransportOf(core)->tx_packets,
		   (unsigned long)TransportOf(core)->tx_suppressed);
	TRACE_INFO("CPU %d: payload sizes: zero=%lu full=%lu short=%lu "
		   "(commonest short=%u seen %lu)\n", ctx->cpu,
		   (unsigned long)t->tx_hist_zero,
		   (unsigned long)t->tx_hist_full,
		   (unsigned long)t->tx_hist_short,
		   t->tx_hist_short_mode,
		   (unsigned long)t->tx_hist_short_mode_n);
	TRACE_INFO("CPU %d: blueprints pending per drain: 1=%lu 2=%lu 3=%lu "
		   "4+=%lu  (>1 is what coalescing needs)\n", ctx->cpu,
		   (unsigned long)t->drain_depth[1],
		   (unsigned long)t->drain_depth[2],
		   (unsigned long)t->drain_depth[3],
		   (unsigned long)t->drain_depth[4]);
	TRACE_INFO("CPU %d: receive checksum: hardware verdict available=%s, "
		   "frames dropped as corrupt=%lu%s\n", ctx->cpu,
		   rxc.csum_seen ? "yes" : "NO (frames are trusted)",
		   (unsigned long)rxc.csum_bad,
		   getenv("MTP_CORRUPT_NTH_RX") ? " [INJECTOR ON]" : "");
	TRACE_INFO("CPU %d: readiness: notify readable=%lu writable=%lu "
		   "state=%lu error=%lu; polls=%lu entries returned=%lu\n",
		   ctx->cpu,
		   (unsigned long)TransportOf(core)->notifies[MTP_NOTIF_READABLE],
		   (unsigned long)TransportOf(core)->notifies[MTP_NOTIF_WRITABLE],
		   (unsigned long)TransportOf(core)->notifies[MTP_NOTIF_STATE],
		   (unsigned long)TransportOf(core)->notifies[MTP_NOTIF_ERROR],
		   (unsigned long)TransportOf(core)->polls,
		   (unsigned long)TransportOf(core)->poll_entries);
	{	/* the program's own account of why it emitted nothing */
		void prog_report_refusals(void);

		prog_report_refusals();
		{ void tgt_report_merges(void); tgt_report_merges(); }
	}
	TRACE_INFO("CPU %d: timers fired: %lu\n", ctx->cpu,
		   (unsigned long)TimerFires());
	}
	TRACE_INFO("CPU %d: rx classes: arp=%lu ipv4=%lu(proto-match=%lu other=%lu) "
		   "other_ethertype=%lu\n", ctx->cpu,
		   (unsigned long)rxc.arp, (unsigned long)rxc.ipv4,
		   (unsigned long)rxc.ip_to_transport,
		   (unsigned long)rxc.ip_other_proto,
		   (unsigned long)rxc.other_ethertype);
}
