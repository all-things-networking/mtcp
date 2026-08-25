#define _GNU_SOURCE	/* CPU_SET, pthread_setaffinity_np */
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
#include <pthread.h>
#include <sched.h>
#include <time.h>

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
	t->notifies[kind & 3]++;

	/* Guard inside, as for the generation queue: at most one entry per
	 * flow, which is what makes the queue's flow-count capacity sound. */
	if (f->on_ready_list)
		return;
	f->on_ready_list = 1;

	/*
	 * The application's own list when we ARE the application thread --
	 * which is the level-triggered re-arm from TransportPoll -- and the
	 * cross-thread queue when we are the stack. Neither structure ever has
	 * two writers.
	 */
	if (t->stack_tid != 0 &&
	    t->stack_tid == (uint64_t)(uintptr_t)pthread_self()) {
		t->cross_ready++;
		/*
		 * Wake the application if it is asleep. Read unlocked as a fast
		 * path: if it is about to sleep but has not set the flag, its
		 * own re-check under the lock sees this entry and it does not
		 * sleep at all. The stack takes the lock only to signal, which
		 * is the one place it may briefly block -- as the donor's does.
		 */
		if (fq_enqueue(&t->q_ready, f) != 0) {
			fprintf(stderr, "\n*** READY QUEUE FULL: capacity is "
				"flow count and the membership guard should "
				"make this impossible\n");
			fflush(stderr);
			abort();
		}
		if (t->app_waiting) {
			pthread_mutex_lock(&t->app_lock);
			t->app_wakes++;
			pthread_cond_signal(&t->app_cv);
			pthread_mutex_unlock(&t->app_lock);
		}
		return;
	}
	TAILQ_INSERT_TAIL(&t->ready_list, f, ready_link);
}

/*
 * Sleep until the stack publishes readiness. The donor's discipline: the
 * application does not spin, it blocks, and the thread that creates the work
 * hands the core over.
 *
 * The bounded wait is a SAFETY NET, not the mechanism -- a lost wakeup would
 * otherwise be an unbounded hang, and rule 5 says to treat a hang as a failing
 * test. `app_timeouts` counts how often it fires so we can tell whether it is
 * ever load-bearing; it should be a handful per run and never a rate.
 */
int
TransportWait(struct core_ctx *core, int timeout_ms)
{
	struct transport *t = TransportOf(core);
	struct timespec ts;
	int slept = 0;

	/* Switchable so the 2x2 against sched_yield comes from ONE binary. A
	 * comparison across builds is a second variable, and this week has
	 * twice produced a wrong answer that way. */
	if (MTP_ENV_ON("MTP_NOBLOCK"))
		return 0;

	if (!fq_is_empty(&t->q_ready) || !TAILQ_EMPTY(&t->ready_list))
		return 0;

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_nsec += (timeout_ms > 0 && timeout_ms < 100 ? timeout_ms : 100)
		      * 1000000L;
	if (ts.tv_nsec >= 1000000000L) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000L;
	}

	t->app_state = MTP_APP_WAITING;
	pthread_mutex_lock(&t->app_lock);
	if (fq_is_empty(&t->q_ready) && TAILQ_EMPTY(&t->ready_list)
	    && SchedRunning(core)) {
		t->app_waiting = 1;
		t->app_sleeps++;
		if (pthread_cond_timedwait(&t->app_cv, &t->app_lock, &ts))
			t->app_timeouts++;
		t->app_waiting = 0;
		slept = 1;
	}
	pthread_mutex_unlock(&t->app_lock);
	t->app_state = MTP_APP_RUNNING;
	return slept;
}

/*
 * READINESS IS A TRANSITION, NOT A CONDITION RE-EVALUATED PER POLL.
 * docs/DESIGN-READINESS.md.
 *
 * This replaces ready_level_check, which ran over every dequeued flow and
 * re-raised while the condition still held. mTCP has no such step -- B
 * establishes three producers of EPOLLIN and no fourth, with the bit cleared on
 * delivery and never re-enqueued, so "still readable" is not a condition it can
 * observe. Same observable API, and the old mechanism made one ignored socket
 * cost O(polls) for ever: five stranded flows produced 16.3 million raises
 * against 178 reads (RESULTS 2026-08-17).
 *
 * The three producers now live where their transitions happen -- arrival here,
 * the short read inside the read, registration unchanged -- and nothing
 * re-evaluates.
 */
void
tgt_ready_edge(void *owner, int kind)
{
	struct flow *f = (struct flow *)owner;

	if (f)
		ready_raise(TransportOf(g_core[0]), f, kind);
}

/*
 * REGISTRATION: the third producer, and the one whose absence broke the shim
 * completely when the first two were built.
 *
 * The design note listed three producers and called registration "unchanged" --
 * true of mTCP, false of us, because our shim had no registration edge at all.
 * Under the old poll-time re-evaluation it did not need one: a flow that became
 * readable before the application had a socket for it was simply re-presented
 * on the next poll. With that gone, the event raised before the handover is the
 * only one there will ever be, and it is delivered to a socket that does not
 * exist yet. Every connection stalled holding its unread request.
 *
 * So the application says "I am now interested in this flow", and anything
 * already true is raised once, here.
 */
int
mtp_app_state_read(void)
{
	return TransportOf(g_core[0])->app_state;
}

void
mtp_app_state(int state)
{
	TransportOf(g_core[0])->app_state = (uint8_t)state;
}

void
mtp_ready_arm(flow_t *flow)
{
	struct flow *f = (struct flow *)flow;
	struct transport *t = TransportOf(g_core[0]);

	if (!f)
		return;
	if (f->rx_unit && f->rx_unit->tail_seq > f->rx_unit->head_seq)
		ready_raise(t, f, MTP_NOTIF_READABLE);
	if (f->tx_unit && tgt_tx_space(f->tx_unit)) {
		f->tx_unit->want_space = 0;
		ready_raise(t, f, MTP_NOTIF_WRITABLE);
	}
}

static void
ready_after_input(struct transport *t, struct flow *f)
{
	/* ARRIVAL: the program merged bytes during this packet's dispatch. An
	 * edge, because it is caused by the packet we just processed. */
	if (f->rx_unit && f->rx_unit->tail_seq > f->rx_unit->head_seq)
		ready_raise(t, f, MTP_NOTIF_READABLE);
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

	/* Take what the stack published since the last poll. Application
	 * thread only; the stack never touches ready_list. */
	{
		struct flow *pub;

		while ((pub = fq_dequeue(&t->q_ready)) != NULL)
			if (pub->on_ready_list)
				TAILQ_INSERT_TAIL(&t->ready_list, pub,
						  ready_link);
	}

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
	struct transport *t = TransportOf(g_core[0]);
	/*
	 * FlowOfKey, NOT FlowTableLookup, AND THAT WAS THE BUG. The table returns
	 * the CONTEXT; the flow handle is the first word of it. This function
	 * assigned the context pointer straight into a `struct flow *` -- legal
	 * C, since void* converts to any object pointer without a cast, so
	 * -Wall -Werror had nothing to say. The accessor exists so the
	 * dereference cannot be written wrong again; flow_table.h says why.
	 *
	 * Everything after it then operated on the program's TCP context as
	 * though it were a flow: `pending_destroy = 1` wrote into whatever
	 * tcp_ctx field sits at that offset, TAILQ_INSERT_TAIL wrote two
	 * pointers into it, and FlowDestroy freed `tx_unit`/`rx_unit` read out
	 * of context bytes and asserted on an `app_detached` that was never the
	 * flow's.
	 *
	 * It is why the lifecycle counters could not compose: del_ctx and the
	 * application's detach were reading and writing DIFFERENT OBJECTS, so
	 * each could truthfully report that the other had not happened yet
	 * (del_ctx=113, detach=113, late=0, destroyed=0).
	 */
	struct flow *f = FlowOfKey(t->flows, key);

	/*
	 * MARKS, DOES NOT FREE. This is called from inside a program entry
	 * point, and freeing here frees the program's context and both data
	 * units with it -- after which TransportInput dereferences f->rx_unit
	 * and f->tx_unit through ready_level_check, on every close. That was a
	 * confirmed use-after-free, invisible because a just-freed small block
	 * still reads correctly.
	 *
	 * The stack destroys at the end of its pass instead, when no program
	 * call is on the stack.
	 */
	if (!f) {
		t->n_delctx_miss++;
		return -1;
	}
	t->n_delctx++;
	if (f->proto_done)
		return 0;			/* already said once */
	f->proto_done = 1;

	/*
	 * AND IT ONLY JOINS THE DESTROY LIST ONCE THE APPLICATION HAS LET GO.
	 * The two events are independent and either can come first, so whichever
	 * is second is what queues the flow -- here, or in tgt_app_detach.
	 *
	 * The list is therefore only ever walked to destroy, never to look. The
	 * first version of this put every finished flow on the list and had the
	 * reap skip the ones the application still held, which is correct and
	 * costs a walk of every closed connection on every pass: it measured
	 * ~700 million held-visits in a 13-second run, growing with the number
	 * of connections the run had completed.
	 */
	if (f->app_detached && !f->pending_destroy) {
		f->pending_destroy = 1;
		TAILQ_INSERT_TAIL(&t->destroy_list, f, destroy_link);
	} else if (!f->app_detached) {
		t->awaiting_app++;	/* a GAUGE, not a total: see the report */
	}
	return 0;
}

/*
 * The application has let go. If the protocol had already finished, this is the
 * second of the two events and the flow can now be queued for destruction.
 *
 * Called from the application thread, which is the thread the reap runs on, so
 * the insert needs no more synchronisation than the reap's own removal.
 */
void
tgt_flow_app_detached(struct flow *f)
{
	struct transport *t = TransportOf(g_core[0]);

	t->n_detach++;
	if (f->proto_done && !f->pending_destroy) {
		t->n_detach_late++;
		f->pending_destroy = 1;
		TAILQ_INSERT_TAIL(&t->destroy_list, f, destroy_link);
		t->awaiting_app--;
	}
}

/*
 * D3: re-attempt generation for every flow that asked. Runs on the stack
 * thread, in the same position an inbound packet's chain would have run, so a
 * retried attempt and an event-driven one reach the program identically.
 *
 * The list is TAKEN AND CLEARED first. A flow still blocked asks again from
 * inside its own attempt, so it lands back on the list for the next pass --
 * "retried every pass while blocked" is a fixed point rather than a rule
 * enforced here, and the re-add cannot be walked by the sweep that emptied it.
 */
void
tgt_sched_take_retries(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);
	struct flow *taken[MTP_RETRY_MAX];
	unsigned n = t->retry_n, i;

	if (!n)
		return;
	memcpy(taken, t->retry, n * sizeof(taken[0]));
	t->retry_n = 0;
	for (i = 0; i < n; i++) {
		struct mtp_app_op op;

		taken[i]->on_retry = 0;
		if (!taken[i]->slot_live)
			continue;	/* destroyed since it asked */
		t->retries++;
		memset(&op, 0, sizeof(op));
		op.kind = MTP_APP_SEND;
		op.flow = taken[i];
		op.len = 0;		/* nothing new: attempt what is held */
		op.flags = MTP_OP_PHASE_GENERATE;
		mtp_program_app_op(&op, core->cur_ts);
	}
}

/*
 * End of pass, no program call in flight: now it is safe.
 *
 * DESTRUCTION WAITS FOR BOTH SIDES, and the waiting happens off this list.
 * The program's `del_ctx` says the protocol is finished with the flow;
 * `app_detached` says the application is. Neither implies the other and either
 * can come first, so whichever arrives second is what queues the flow. Nothing
 * reaches this list before both have happened, so the reap never inspects a
 * flow it cannot destroy.
 *
 * WHY THE PAIRING WAS NOT NEEDED BEFORE, which is the whole lesson. Every
 * del_ctx that actually reached here came from LAST_ACK -- the peer closed
 * first, so the application had already closed and detached, and "destroy only
 * after detach" was a property of the ONE path that could get here. The
 * TIME_WAIT path, where WE close first, was passing a zeroed key to del_ctx and
 * silently destroying nothing. Fixing that key turned the second path on and it
 * aborted on the FlowDestroy assertion within one connection.
 *
 * So the assertion did its job exactly as its own comment predicted: "the
 * donor's equivalent safety is emergent -- it destroys in states only reachable
 * after the application has closed -- and a new path into one of those states
 * breaks it silently." The new path was ours.
 */
void
tgt_sched_reap(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);
	struct flow *f;

	while ((f = TAILQ_FIRST(&t->destroy_list)) != NULL) {
		TAILQ_REMOVE(&t->destroy_list, f, destroy_link);
		f->pending_destroy = 0;
		t->n_destroyed++;
		FlowDestroy(core, f);
	}
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

	struct transport *t = TransportOf(core);
	uint64_t before = t->emit_refused;

	t->forced_drains++;
	tgt_drain(core);
	/*
	 * Whether THIS drain reached everything, not whether any drain ever
	 * gave up. tx_flush treats "I called drain" as "the drain happened",
	 * and the buffer-full path makes those two different things.
	 */
	t->forced_drain_gave_up = (t->emit_refused != before);
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
	if (t->cur_flow) {
		t->cur_flow->rx_unit = u;
		/* the flow this stream belongs to, so a SHORT READ can name who
		 * to wake from inside the read itself */
		u->owner = t->cur_flow;
	}
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

	/* Said out loud once per unit: the capacity that will refuse writes,
	 * and the configured value it came from. Rule 1 makes this a parity
	 * parameter, so a run must be able to state it rather than have it
	 * inferred from behaviour. */
	TRACE_CONFIG("transmit ring: %u bytes (sndbuf = %d)\n", cap,
		     CONFIG.sndbuf_size);

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
 * mtp_pkt_gen_orphan — a packet for a flow that does not exist.
 *
 * The offload offset is the program's, exactly as it is on the flow path: the
 * target computes a sum over a header whose shape it does not know.
 */
int
mtp_pkt_gen_orphan(uint32_t local_ip, uint32_t remote_ip,
		   const void *hdr, uint16_t hdr_len, int offload)
{
	return tgt_pkt_gen_orphan(g_core[0], local_ip, remote_ip, hdr, hdr_len,
				  offload, PROG_L4_CSUM_OFFSET);
}

/*----------------------------------------------------------------------------*/
/*
 * mtp_retry — the program asks for its generation to be attempted again on the
 * next pass. contract.h says why the PROGRAM has to ask and the target cannot
 * decide: only the program knows it has something unsent.
 */
void
mtp_retry(flow_t *f)
{
	struct transport *t = TransportOf(g_core[0]);

	if (!f || f->on_retry)
		return;			/* the flag makes duplicates impossible */
	if (t->retry_n >= MTP_RETRY_MAX)
		return;			/* bounded. One entry per flow means a
					 * live membership flag already makes
					 * this unreachable; it is here so that
					 * stays true if the flag ever is not */
	f->on_retry = 1;
	t->retry[t->retry_n++] = f;
}

/*
 * mtp_notify — the program tells the application something happened; the target
 * decides how to deliver it.
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
		ready_after_input(TransportOf(core), TransportOf(core)->cur_flow);
	TransportOf(core)->cur_iph = NULL;
	TransportOf(core)->cur_flow = NULL;

	return TRUE;
}
/*----------------------------------------------------------------------------*/
volatile sig_atomic_t SchedStopRequested;
static uint64_t g_gap_hist[10], g_gap_sum, g_gap_sq, g_gap_n, g_gap_max;
static uint64_t g_rx_hist[8], g_rx_n, g_rx_pkts;

/*
 * Ask the stack thread to finish. Needed because tearing down a context joins
 * that thread, and nothing else ever set the flag -- so the shim's shutdown
 * blocked in pthread_join until the harness sent SIGKILL, which is why the
 * shimmed arm never printed an epilogue and carried no counters.
 */
void
SchedStop(void)
{
	SchedStopRequested = 1;
}

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
	/*
	 * STATIC, because SchedStep is called ONCE PER ITERATION from the outer
	 * loop -- these were locals, so `iters` was always 0 and `t_prev_us`
	 * always 0. The inter-poll histogram recorded nothing at all, and the
	 * every-1024th sampler ran on every pass instead. One stack thread, so
	 * a static is the right scope; a local was simply the wrong one.
	 */
	static uint64_t iters, t_prev_us;
	struct transport *t_of = TransportOf(core);
	int rx_inf, tx_inf, i;


		/* one clock read per iteration; everything below uses it */
		gettimeofday(&tv, NULL);
		ts = TIMEVAL_TO_TS(&tv);
		core->cur_ts = ts;
		core->cur_us = (uint64_t)tv.tv_sec * 1000000u
			     + (uint64_t)tv.tv_usec;

		/*
		 * INTER-POLL INTERVAL. An acknowledgement lands at a moment the
		 * stack did not choose, so what it waits for is not the MEAN
		 * gap but the LENGTH-BIASED one: a random instant is more
		 * likely to fall inside a long gap than a short one. The
		 * expected wait is sum(gap^2) / (2 * sum(gap)), and a mean of
		 * gaps would understate it by exactly the factor the tail
		 * contributes -- which is the quantity in question.
		 */
		if (t_prev_us) {
			uint64_t gap = core->cur_us - t_prev_us;
			unsigned b;
			uint64_t lim;

			for (b = 0, lim = 2; b < 9 && gap >= lim; b++, lim *= 4)
				;
			g_gap_hist[b]++;
			g_gap_sum += gap;
			g_gap_sq += gap * gap;
			g_gap_n++;
			if (gap > g_gap_max)
				g_gap_max = gap;
		}
		t_prev_us = core->cur_us;

		/* Time-weighted, so the mean does not depend on when the
		 * program happens to be busy. Every 1024th iteration. */
		if ((iters & 1023) == 0 && prog_sample_inflight)
			prog_sample_inflight(core->cur_us);
		iters++;

		for (rx_inf = 0; rx_inf < CONFIG.eths_num; rx_inf++) {
			int recv_cnt = core->iom->recv_pkts(ctx, rx_inf);
			{
				/* A large burst means its FIRST packet waited
				 * the whole preceding gap. */
				unsigned b = 0;
				int v = recv_cnt;

				while (b < 7 && v) { b++; v >>= 1; }
				g_rx_hist[b]++;
				g_rx_n++;
				g_rx_pkts += (uint64_t)(recv_cnt > 0 ? recv_cnt : 0);
			}

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
		/* CR-E: extents the application buffered, handed to the
		 * program HERE -- on the stack thread -- before the drain. */
		tgt_sched_take_sends(core);
		tgt_sched_take_notifications(core);
		if (app)
			app(core, ts, app_arg);

		TimerTick(ts);
		/*
		 * D3: THE PER-ITERATION RETRY, before the drain so anything it
		 * generates leaves in this pass rather than the next.
		 */
		tgt_sched_take_retries(core);
		tgt_drain(core);

		/* nothing from the program is on the stack here */
		tgt_sched_reap(core);

		/*
		 * What the burst actually accepted, as against what we handed
		 * it. tx_packets counts frames BUILT inside emit_segment; this
		 * counts frames the driver took. A frame that is built and not
		 * sent is sitting in the transmit buffer, and nothing about
		 * its contents matters until that is ruled out.
		 */
		for (tx_inf = 0; tx_inf < CONFIG.eths_num; tx_inf++) {
			if (t_of->staged && t_of->stage_first_us) {
				struct timeval tv2;
				uint64_t now2, gap;
				unsigned b, d;

				gettimeofday(&tv2, NULL);
				now2 = (uint64_t)tv2.tv_sec * 1000000u
				     + (uint64_t)tv2.tv_usec;
				gap = now2 - t_of->stage_first_us;
				for (b = 0; b < 7 && gap >= (1ull << b); b++)
					;
				t_of->stage_hist[b]++;
				t_of->stage_sum += gap;
				t_of->stage_n++;
				if (gap > t_of->stage_max)
					t_of->stage_max = gap;
				for (d = 0; d < 7 && t_of->staged > (1u << d);
				     d++)
					;
				t_of->depth_hist[d]++;
				t_of->staged = 0;
			}
			int sent = core->iom->send_pkts(ctx, tx_inf);

			if (sent > 0)
				TransportOf(core)->tx_bursted += sent;
		}

		core->iom->select(ctx);
}

/*
 * THE TWO THREADS (DESIGN.md §21).
 *
 * Both pinned to ONE core, both spinning, neither ever blocking or yielding --
 * mTCP's shape, matched deliberately rather than improved on. A cleverer
 * arrangement (separate cores, a blocking wait, an adaptive spin) would make
 * our numbers unattributable, because the difference would then include an
 * architecture choice of ours rather than the cost of programmability.
 *
 * The measured consequence, from tools/handoff_bench.c: a synchronous round
 * trip across the boundary on one shared core costs 8.26 ms against a 4004 us
 * slice. NEITHER SIDE MAY EVER WAIT FOR THE OTHER. Both queues are therefore
 * publish-and-continue, and every consumer takes what is there and moves on.
 */
struct sched_thread_arg {
	struct core_ctx	*core;
	uint32_t	 max_ticks;
	int		 cpu;
};

static void
sched_pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set))
		TRACE_ERROR("could not pin to cpu %d\n", cpu);
}

static void *
sched_stack_thread(void *argp)
{
	struct sched_thread_arg *a = argp;
	struct thread_ctx *ctx = a->core->ctx;
	struct timeval tv = {0};
	uint32_t ts, ts_start;

	sched_pin(a->cpu);

	/* Published before the first step, so tgt_sched_enqueue and ready_raise
	 * can tell which side they are on from here onward. */
	TransportOf(a->core)->stack_tid = (uint64_t)(uintptr_t)pthread_self();

	gettimeofday(&tv, NULL);
	ts_start = TIMEVAL_TO_TS(&tv);

	while (!ctx->exit && !ctx->done && !SchedStopRequested) {
		SchedStep(a->core, NULL, NULL);
		gettimeofday(&tv, NULL);
		ts = TIMEVAL_TO_TS(&tv);
		if (a->max_ticks && (uint32_t)(ts - ts_start) >= a->max_ticks)
			break;
	}
	ctx->done = 1;		/* so the application thread stops too */
	return NULL;
}

/*
 * Start the stack on its own thread and return. The caller becomes the
 * application thread and is pinned to the SAME core.
 */
/* For the application thread's own loop: is the stack still running, and what
 * time does it think it is? The application must not reach into core->ctx. */
int
SchedRunning(struct core_ctx *core)
{
	struct thread_ctx *ctx = core->ctx;

	return !ctx->exit && !ctx->done && !SchedStopRequested;
}

uint32_t
SchedNow(struct core_ctx *core)
{
	return core->cur_ts;
}

uint64_t
mtp_now_us(void)
{
	return g_core[0]->cur_us;
}

pthread_t
SchedStartStack(struct core_ctx *core, uint32_t max_ticks, int cpu)
{
	static struct sched_thread_arg arg;
	pthread_t th;

	arg.core = core;
	arg.max_ticks = max_ticks;
	arg.cpu = cpu;

	if (pthread_create(&th, NULL, sched_stack_thread, &arg)) {
		TRACE_ERROR("could not create the stack thread\n");
		return 0;
	}
	/* the application shares the core, as mTCP's application thread does */
	sched_pin(cpu);

	/* Do not proceed until the stack has published its identity, or the
	 * first enqueue could take the same-thread path from the wrong thread
	 * and insert straight into a list the stack owns. */
	while (TransportOf(core)->stack_tid == 0)
		;
	return th;
}

/*
 * End-of-run reporting. Extracted from SchedRun because the application thread
 * now owns the loop and SchedRun is not called at all in the threaded build --
 * every counter in here silently stopped being printed when item 5 landed, and
 * the numbers RESULTS.md is written from went with them.
 */
void
tgt_note_below_wire(uint64_t base, uint32_t len, uint64_t hwm, uint8_t is_rtx)
{
	struct transport *t = TransportOf(g_core[0]);
	static uint32_t shown;

	/*
	 * For a retransmit, committing below the wire is the DEFINITION of the
	 * operation, so that arm of the count is background by construction.
	 * The arm that can indicate a defect is a fresh commit that lies
	 * ENTIRELY below the wire: such a blueprint can contribute no byte the
	 * peer has not seen, so nothing will ever drain it, and its reference
	 * pins the flush forever. A fresh commit that merely STARTS below the
	 * wire still has new bytes at its top and can drain normally.
	 */
	if (is_rtx)
		t->below_wire_rtx++;
	else if (base + len <= hwm)
		t->below_wire_dead++;
	else
		t->below_wire_new++;

	if (base + len <= hwm && !is_rtx && shown++ < 8)
		fprintf(stderr, "BELOW-WIRE-DEAD commit [%llu,%llu) len=%u %s "
			"(wire at %llu, %llu bytes below)\n",
			(unsigned long long)base,
			(unsigned long long)(base + len), len,
			is_rtx ? "RTX" : "new", (unsigned long long)hwm,
			(unsigned long long)(hwm - base));
}

void
tgt_note_overlap(const struct mtp_data_unit *u, uint64_t live_base,
		 uint32_t live_len, uint64_t new_base, uint32_t new_len,
		 uint8_t new_is_rtx, uint8_t expected)
{
	struct transport *t = TransportOf(g_core[0]);
	static uint32_t shown;

	if (expected) {
		t->overlap_merge_ok++;
		return;			/* §18's own mechanism, working */
	}
	if (new_is_rtx)
		t->overlap_rtx++;
	else
		t->overlap_new++;

	/* the first few in full; after that the counters carry it */
	if (shown++ < 5)
		fprintf(stderr, "OVERLAP live [%llu,%llu) len=%u  X  new "
			"[%llu,%llu) len=%u %s\n",
			(unsigned long long)live_base,
			(unsigned long long)(live_base + live_len), live_len,
			(unsigned long long)new_base,
			(unsigned long long)(new_base + new_len), new_len,
			new_is_rtx ? "RTX" : "new");
	(void)u;
}

void
tgt_report_at_fault(void)
{
	struct transport *t = TransportOf(g_core[0]);

	tgt_check_reachable(g_core[0]);
	fprintf(stderr,
		"  forced drains: %llu, of which the LAST one ABANDONED: %s\n"
		"  drains abandoned by an emit_bp refusal, all callers: %llu\n"
		"    of which ARP absent: %llu, no transmit frame: %llu, offload refusal: %llu\n"
		"  UNREACHABLE RINGS seen (ring non-empty, flow unlisted): %llu\n",
		(unsigned long long)t->forced_drains,
		t->forced_drain_gave_up ? "YES" : "no",
		(unsigned long long)t->emit_refused,
		(unsigned long long)t->emit_refused_arp,
		(unsigned long long)t->emit_refused_noframe,
		(unsigned long long)t->emit_refused_offload,
		(unsigned long long)t->unreachable_ring);
	SchedReport(g_core[0]);
}

void
tgt_note_flush_short(uint64_t behind, uint32_t run)
{
	struct transport *t = TransportOf(g_core[0]);

	t->flush_short++;
	t->flush_short_bytes += behind;
	if (run > t->flush_short_run_max)
		t->flush_short_run_max = run;
}

void
tgt_note_flush_past_wire(void)
{
	TransportOf(g_core[0])->flush_past_emitted++;
}

void
SchedReport(struct core_ctx *core)
{
	struct thread_ctx *ctx = core->ctx;

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
		   MTP_ENV_ON("MTP_CORRUPT_NTH_RX") ? " [INJECTOR ON]" : "");
	TRACE_INFO("CPU %d: pending blueprints high-water per class: "
		   "c0=%u/%u c1=%u/%u c2=%u/%u (used/depth)\n", ctx->cpu,
		   TransportOf(core)->ring_hwm[0], bp_depth(0),
		   TransportOf(core)->ring_hwm[1], bp_depth(1),
		   TransportOf(core)->ring_hwm[2], bp_depth(2));

	/* In the CLEAN-run report as well as the fault one: an unreachable ring
	 * is a defect on its own terms, and a run that never faults is exactly
	 * where it would otherwise go unseen. */
	tgt_check_reachable(core);
	{
		static const char *n[10] = { "<2us", "<8us", "<32us", "<128us",
					     "<512us", "<2ms", "<8ms", "<32ms",
					     "<128ms", ">=128ms" };
		int k;

		{
		static const char *sn[8] = { "<1us", "<2us", "<4us", "<8us",
					     "<16us", "<32us", "<64us", ">=64us" };
		static const char *dn[8] = { "1", "2", "<=4", "<=8", "<=16",
					     "<=32", "<=64", ">64" };
		struct transport *tt = TransportOf(core);
		int k;

		TRACE_INFO("CPU %d: STAGING -> device flush: %llu flushes, "
			   "mean %llu us, max %llu us\n", ctx->cpu,
			   (unsigned long long)tt->stage_n,
			   (unsigned long long)(tt->stage_n ? tt->stage_sum / tt->stage_n : 0),
			   (unsigned long long)tt->stage_max);
		for (k = 0; k < 8; k++)
			TRACE_INFO("    %-7s %10llu  %6.2f%%\n", sn[k],
				   (unsigned long long)tt->stage_hist[k],
				   tt->stage_n ? 100.0 * (double)tt->stage_hist[k] / (double)tt->stage_n : 0.0);
		TRACE_INFO("CPU %d: frames staged per flush:\n", ctx->cpu);
		for (k = 0; k < 8; k++)
			TRACE_INFO("    %-7s %10llu  %6.2f%%\n", dn[k],
				   (unsigned long long)tt->depth_hist[k],
				   tt->stage_n ? 100.0 * (double)tt->depth_hist[k] / (double)tt->stage_n : 0.0);
	}
	TRACE_INFO("CPU %d: INTER-POLL gap: %llu samples, mean %llu us, "
			   "LENGTH-BIASED mean %llu us, expected wait %llu us, "
			   "max %llu us\n", ctx->cpu,
			   (unsigned long long)g_gap_n,
			   (unsigned long long)(g_gap_n ? g_gap_sum / g_gap_n : 0),
			   (unsigned long long)(g_gap_sum ? g_gap_sq / g_gap_sum : 0),
			   (unsigned long long)(g_gap_sum ? g_gap_sq / (2 * g_gap_sum) : 0),
			   (unsigned long long)g_gap_max);
		for (k = 0; k < 10; k++)
			TRACE_INFO("    %-8s %10llu  %6.3f%%\n", n[k],
				   (unsigned long long)g_gap_hist[k],
				   g_gap_n ? 100.0 * (double)g_gap_hist[k] / (double)g_gap_n : 0.0);
		TRACE_INFO("CPU %d: receive bursts: %llu polls, %llu packets, "
			   "mean %.2f per poll\n", ctx->cpu,
			   (unsigned long long)g_rx_n,
			   (unsigned long long)g_rx_pkts,
			   g_rx_n ? (double)g_rx_pkts / (double)g_rx_n : 0.0);
	}
	TRACE_INFO("CPU %d: APP SLEEP: slept %llu, woken by the stack %llu, timed out %llu\n",
		   ctx->cpu, (unsigned long long)TransportOf(core)->app_sleeps,
		   (unsigned long long)TransportOf(core)->app_wakes,
		   (unsigned long long)TransportOf(core)->app_timeouts);
	TRACE_INFO("CPU %d: FLUSH SHORTFALLS: %llu flushes, %llu bytes, longest "
		   "consecutive run %u (stall threshold %u)\n", ctx->cpu,
		   (unsigned long long)TransportOf(core)->flush_short,
		   (unsigned long long)TransportOf(core)->flush_short_bytes,
		   TransportOf(core)->flush_short_run_max,
		   MTP_FLUSH_STALL_PASSES);
	TRACE_INFO("CPU %d: EMIT REFUSALS: total=%llu arp=%llu noframe=%llu offload=%llu (drain passes %llu)\n",
		   ctx->cpu, (unsigned long long)TransportOf(core)->emit_refused,
		   (unsigned long long)TransportOf(core)->emit_refused_arp,
		   (unsigned long long)TransportOf(core)->emit_refused_noframe,
		   (unsigned long long)TransportOf(core)->emit_refused_offload,
		   (unsigned long long)TransportOf(core)->drain_pass);
	TRACE_INFO("CPU %d: RELEASE BASE MISMATCHES: %llu\n", ctx->cpu,
		   (unsigned long long)TransportOf(core)->release_base_mismatch);
	TRACE_INFO("CPU %d: UNREACHABLE RINGS (ring non-empty, flow unlisted): %llu\n",
		   ctx->cpu, (unsigned long long)TransportOf(core)->unreachable_ring);
	/*
	 * A GAUGE READ AT EXIT, not a total. It is the number of flows whose
	 * protocol finished and whose application never let go -- so a non-zero
	 * value is a real leak, one context and two ring buffers each, and it
	 * says how many rather than that it happened.
	 */
	TRACE_INFO("CPU %d: LIFECYCLE: del_ctx=%llu (miss %llu) detach=%llu "
		   "(late %llu) destroyed=%llu\n", ctx->cpu,
		   (unsigned long long)TransportOf(core)->n_delctx,
		   (unsigned long long)TransportOf(core)->n_delctx_miss,
		   (unsigned long long)TransportOf(core)->n_detach,
		   (unsigned long long)TransportOf(core)->n_detach_late,
		   (unsigned long long)TransportOf(core)->n_destroyed);
	TRACE_INFO("CPU %d: RETRIES (D3, generation re-attempted next pass): "
		   "%llu\n", ctx->cpu,
		   (unsigned long long)TransportOf(core)->retries);
	TRACE_INFO("CPU %d: FLOWS STILL AWAITING THE APPLICATION AT EXIT "
		   "(protocol finished, never detached): %llu\n", ctx->cpu,
		   (unsigned long long)TransportOf(core)->awaiting_app);
	TRACE_INFO("CPU %d: COMMITS BELOW THE WIRE: rtx=%lu partial=%lu DEAD=%lu\n", ctx->cpu,
		   (unsigned long)TransportOf(core)->below_wire_rtx,
		   (unsigned long)TransportOf(core)->below_wire_new,
		   (unsigned long)TransportOf(core)->below_wire_dead);
	TRACE_INFO("CPU %d: OVERLAPPING COMMITS: rtx=%lu new=%lu "
		   "merge_bad=%lu (merge_ok=%lu, by design)\n", ctx->cpu,
		   (unsigned long)TransportOf(core)->overlap_rtx,
		   (unsigned long)TransportOf(core)->overlap_new,
		   (unsigned long)TransportOf(core)->overlap_merge_bad,
		   (unsigned long)TransportOf(core)->overlap_merge_ok);
	TRACE_INFO("CPU %d: flushes asking past the wire: %lu\n", ctx->cpu,
		   (unsigned long)TransportOf(core)->flush_past_emitted);
	TRACE_INFO("CPU %d: boundary crossings: app->stack send=%lu notify=%lu; "
		   "stack->app ready=%lu\n", ctx->cpu,
		   (unsigned long)TransportOf(core)->cross_send,
		   (unsigned long)TransportOf(core)->cross_notify,
		   (unsigned long)TransportOf(core)->cross_ready);
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
		void prog_report_avail(void);
		void prog_report_rtt(void);
		void prog_report_recv(void);
		void prog_report_acklat(void);
		void prog_report_inflight(void);
		void prog_report_stages(void);

		prog_report_refusals();
		prog_report_avail();
		prog_report_rtt();
		prog_report_recv();
		prog_report_acklat();
		prog_report_inflight();
		prog_report_stages();
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

	SchedReport(core);
}
