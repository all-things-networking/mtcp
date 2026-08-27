/*
 * Flow records, the blueprint ring, the generation list, and pkt_gen.
 *
 * pkt_gen is here rather than in out.c because what it does is put a
 * blueprint in a ring and schedule the flow — it does not build a packet. That
 * happens in the drain, once per main-loop iteration, and the interval between
 * the two is what makes coalescing possible (internal.h §1).
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pthread.h>

#include "flow.h"
#include "fhash.h"
#include "target_core.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
int
FlowPoolInit(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);

	t->flow_pool = calloc(CONFIG.max_concurrency, sizeof(struct flow));
	t->bp_pool = calloc((size_t)CONFIG.max_concurrency * MTP_PRIO_CLASSES
			    * BP_RING_DEPTH,
			    sizeof(struct bp));
	if (!t->flow_pool || !t->bp_pool)
		return -1;

	t->flow_next = 0;

	/* Capacity is flow count -- see the field's comment. No rounding: the
	 * ported queue wraps at capacity rather than masking. */
	if (fq_init(&t->q_notify, (fq_index_t)CONFIG.max_concurrency) < 0)
		return -1;
	pthread_mutex_init(&t->app_lock, NULL);
	pthread_cond_init(&t->app_cv, NULL);
	if (fq_init(&t->q_ready, (fq_index_t)CONFIG.max_concurrency) < 0)
		return -1;
	if (fq_init(&t->q_send, (fq_index_t)CONFIG.max_concurrency) < 0)
		return -1;
	{ int c; for (c = 0; c < MTP_PRIO_CLASSES; c++) TAILQ_INIT(&t->gen_list[c]); }
	TAILQ_INIT(&t->destroy_list);
	return 0;
}

void
FlowPoolFini(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);

	free(t->flow_pool);
	free(t->bp_pool);
	t->flow_pool = NULL;
	t->bp_pool = NULL;
}

/*----------------------------------------------------------------------------*/
/*
 * `saddr`/`daddr` are the LOCAL and REMOTE addresses of this flow, taken from
 * the packet or the application operation that caused it to exist. The target
 * learns them from the infrastructure, never from the program: the program's
 * key is a shape it may not read, and an IP address is L3.
 */
struct flow *
FlowCreate(struct core_ctx *core, const flowkey_t *key,
	   uint32_t saddr, uint32_t daddr)
{
	struct transport *t = TransportOf(core);
	struct flow *f;

	if (t->flow_next >= (uint32_t)CONFIG.max_concurrency) {
		TRACE_ERROR("flow pool exhausted at %d\n", CONFIG.max_concurrency);
		return NULL;
	}

	f = &t->flow_pool[t->flow_next];
	{
		int c;

		for (c = 0; c < MTP_PRIO_CLASSES; c++) {
			f->ring[c] = &t->bp_pool[((size_t)t->flow_next
						  * MTP_PRIO_CLASSES + c)
						 * BP_RING_DEPTH];
			f->ring_head[c] = f->ring_tail[c] = 0;
			f->on_gen[c] = 0;
			f->scratch_out[c] = 0;
		}
	}
	f->slot_live = 1;
	t->flow_next++;

	f->key = *key;
	f->saddr = saddr;
	f->daddr = daddr;
	f->nif_out = -1;
	f->is_external = 0;
	f->ip_id = 0;
	f->pending_send = 0;
	f->pending_close = 0;
	f->app_detached = 0;
	f->pending_destroy = 0;
	f->proto_done = 0;
	f->on_send_q = 0;
	f->ctx = NULL;
	/* §24: the slot index IS the identifier. Slots are not recycled, so it
	 * is unique for the life of the process and cannot be handed to the
	 * application twice for different connections. */
	f->id = t->flow_next - 1;

	return f;
}

void
FlowDestroy(struct core_ctx *core, struct flow *f)
{
	struct transport *t = TransportOf(core);

	{
		int c;

		/*
		 * THE STACK'S LISTS. The comment here used to claim this was
		 * "every list, separately -- DestroyTCPStream unlinks its three
		 * the same way", which was false in the way that matters: these
		 * are three PRIORITY CLASSES of one list-kind, not three
		 * list-kinds. The application's readiness list was not unlinked
		 * at all.
		 */
		for (c = 0; c < MTP_PRIO_CLASSES; c++)
			if (f->on_gen[c]) {
				TAILQ_REMOVE(&t->gen_list[c], f, gen_link[c]);
				f->on_gen[c] = 0;
			}
		/* and the rings, so a destroyed slot cannot look like a flow
		 * with an undrained blueprint to the reachability check */
		for (c = 0; c < MTP_PRIO_CLASSES; c++) {
			f->ring_head[c] = f->ring_tail[c] = 0;
			f->scratch_out[c] = 0;
		}
	}

	/*
	 * THE APPLICATION'S LIST. Missing entirely until now, and the resulting
	 * use-after-free is CROSS-THREAD rather than the single-threaded one
	 * fixed earlier: the stack raises readiness, the program closes, the
	 * reap destroys, and the application thread then dequeues this flow and
	 * dereferences rx_unit. The never-recycled slot keeps the pointer
	 * looking valid, so it does not fault -- it reads freed memory.
	 *
	 * Only the application thread owns ready_list, so the entry can only be
	 * removed here if the destroy runs on that thread. It does: the reap is
	 * deferred to the application's own pass (DestroyFinishedFlows).
	 */
	if (f->on_ready_list) {
		TAILQ_REMOVE(&t->ready_list, f, ready_link);
		f->on_ready_list = 0;
	}
	f->ready_kinds = 0;
	/*
	 * THE ASSERTION AT THE DESTROY SITE, and there is only one destroy site
	 * so that it cannot be forgotten at a second. The donor's equivalent
	 * safety is emergent -- it destroys in states only reachable after the
	 * application has closed -- and B's caveat is that a new path into one
	 * of those states breaks it silently. This is that invariant enforced
	 * rather than relied upon.
	 */
	assert(f->app_detached &&
	       "destroying a flow the application has not detached from");

	/* Both byte-stream buffers, returned here and nowhere else -- which is
	 * where the donor returns its payload chunk too. They were malloc'ed
	 * per flow and never freed at all before this. */
	if (f->tx_unit)
		TxUnitFini(f->tx_unit);
	if (f->rx_unit)
		RxUnitFini(f->rx_unit);
	/* NULLED, so a stale reader faults instead of reading freed bytes. A
	 * dangling pointer that still looks valid is the harder bug. */
	f->tx_unit = NULL;
	f->rx_unit = NULL;
	f->slot_live = 0;

	/*
	 * BEFORE the context goes. Its timer objects are fields inside it, and
	 * the wheel holds pointers to them.
	 */
	if (f->ctx)
		TimerDropCtx(f->ctx);
	FlowTableRemove(t->flows, &f->key);
	/* the flow slot itself is not recycled yet — M1 is one connection.
	 * A free list lands with connection reaping (A3), which M1 excludes. */
}

/*
 * §24. The identifier, and nothing else: the target holds no application state.
 */
uint32_t
mtp_flow_id(flow_t *f)
{
	return f->id;
}

/*----------------------------------------------------------------------------*/
/* P5: one list per core, enqueued idempotently. A flow with nothing to send is
 * not on it and is not walked. */
void
AddtoSendList(flow_t *f, uint32_t prio)
{
	struct transport *t = TransportOf(g_core[0]);
	int c = (int)(prio < MTP_PRIO_CLASSES ? prio : MTP_PRIO_CLASSES - 1);

	/*
	 * THE GUARD IS PER (FLOW, CLASS) and lives here, not at the call sites.
	 * That is what keeps each list bounded by flow count: a flow appears at
	 * most once per list however many packets of that class it generates.
	 * A new producer cannot omit a guard it cannot reach -- the prototype
	 * added one that set the flag without testing it and its capacity
	 * argument silently stopped holding.
	 */
	if (f->on_gen[c])
		return;
	f->on_gen[c] = 1;

	if (t->stack_tid == 0 ||
	    t->stack_tid == (uint64_t)(uintptr_t)pthread_self()) {
		TAILQ_INSERT_TAIL(&t->gen_list[c], f, gen_link[c]);
		return;
	}

	t->cross_notify++;
	if (fq_enqueue(&t->q_notify, f) != 0) {
		fprintf(stderr, "\n*** NOTIFY QUEUE FULL: capacity is flow "
			"count and the membership guard should make this "
			"impossible (DESIGN.md \u00a721.10)\n");
		fflush(stderr);
		abort();
	}
}

/*
 * Move everything the application published into gen_list. Runs on the stack
 * thread, before the drain, so a write published during the previous slice is
 * generated and flushed in this pass.
 *
 * The flag is cleared by the CONSUMER before the flow is processed -- the
 * donor's ordering -- so a write arriving after this point re-enqueues rather
 * than being silently dropped.
 */
/*
 * CR-E: the application's send, from the APPLICATION THREAD.
 *
 * Copies straight into the flow's transmit ring and returns what was accepted,
 * synchronously -- the shape mtcp_write has, where CopyFromUser runs under the
 * buffer lock and the operation that crosses names the stream rather than the
 * bytes. Nothing waits for the stack: a short return is back-pressure and the
 * application retries when the flow is writable.
 *
 * The extent is accumulated on the flow and the flow is published. The STACK
 * thread then invokes the program's SEND for it, which is what keeps packet
 * generation -- and therefore send_next, cwnd and snd_base -- on one thread.
 * Doing that generation here instead is the race this whole change removes.
 */
int
mtp_app_send(flow_t *f, const void *buf, uint32_t len)
{
	struct mtp_app_op op;
	struct mtp_tx_addr addr;
	int wrote;

	if (!f || !f->tx_unit)
		return -1;

	/*
	 * D6: THE PROGRAM TAKES THE BYTES, and the target does not take them
	 * first. This used to call mtp_add_tx_data itself and publish, so by the
	 * time the program's handler ran on the stack thread the bytes were
	 * already copied and its `add_tx_data` was bookkeeping after the fact --
	 * an instruction that was not what caused the effect.
	 *
	 * Now the record half of the chain runs here, synchronously, on the
	 * calling thread, and issues the instruction that does the copy. The
	 * generate half still runs on the stack thread; see MTP_OP_PHASE_*.
	 */
	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_SEND;
	op.flow = f;
	addr.base = buf;
	addr.len = len;
	op.data = addr;
	op.len = len;
	op.flags = MTP_OP_PHASE_RECORD;
	wrote = mtp_program_app_op(&op, 0);
	if (wrote <= 0)
		return wrote;

	f->pending_send += (uint32_t)wrote;
	PublishAppOp(f);
	return wrote;
}

/*
 * CR-E, close half. The application has no more to send. Like SEND, this must
 * not generate on the application thread -- gen_fin builds a blueprint and
 * touches send_next, which is the stack's. Publish; the stack acts.
 */
int
mtp_app_close(flow_t *f)
{
	if (!f)
		return -1;

	/*
	 * DETACH FIRST, PUBLISH SECOND. The application is done with this flow
	 * before anything tells the stack so; the publish below is the release
	 * that makes the detach visible. Reversing these two lines reintroduces
	 * the window in which the stack can destroy a flow the application is
	 * still holding.
	 */
	f->app_detached = 1;
	f->pending_close = 1;
	PublishAppOp(f);
	/*
	 * The second of the two events, if the protocol finished first: this is
	 * what queues the flow for destruction in that ordering. A no-op in the
	 * other, where del_ctx has yet to run and will do the queueing itself.
	 */
	FlowAppDetached(f);
	return 0;
}

/* One entry per flow however many operations are pending on it. */
void
PublishAppOp(flow_t *f)
{
	struct transport *t = TransportOf(g_core[0]);

	if (!f->on_send_q) {
		f->on_send_q = 1;
		if (t->stack_tid == 0 ||
		    t->stack_tid == (uint64_t)(uintptr_t)pthread_self()) {
			/*
			 * Single-threaded, or the stack itself: hand this flow
			 * over now. NOT take_sends() -- that drains the queue,
			 * and this flow was never put in it.
			 */
			DeliverSend(g_core[0], f);
			return;
		} else if (t->cross_send++, fq_enqueue(&t->q_send, f) != 0) {
			fprintf(stderr, "\n*** SEND QUEUE FULL: capacity is "
				"flow count and the membership guard should "
				"make this impossible\n");
			fflush(stderr);
			abort();
		}
	}
}

/*
 * Stack thread: hand each published extent to the program. Runs before the
 * drain, so bytes the application buffered during the previous slice are
 * generated and flushed in this pass.
 */
void
HandleApplicationCalls(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);
	struct flow *f;

	while ((f = fq_dequeue(&t->q_send)) != NULL)
		DeliverSend(core, f);
}

/* One flow's pending extent, handed to the program as CR-E's SEND. */
void
DeliverSend(struct core_ctx *core, struct flow *f)
{
	struct mtp_app_op op;
	uint32_t len = f->pending_send;

	f->pending_send = 0;
	f->on_send_q = 0;

	if (len) {
		memset(&op, 0, sizeof(op));
		op.kind = MTP_APP_SEND;
		op.flow = f;
		op.len = len;	/* CR-E: an EXTENT already in the ring */
		op.flags = MTP_OP_PHASE_GENERATE;
		mtp_program_app_op(&op, core->cur_ts);
	}

	/* Close AFTER the extent, so the FIN is generated behind the data the
	 * application wrote before closing rather than ahead of it. */
	if (f->pending_close) {
		f->pending_close = 0;
		memset(&op, 0, sizeof(op));
		op.kind = MTP_APP_CLOSE;
		op.flow = f;
		mtp_program_app_op(&op, core->cur_ts);
	}
}

void
HandleApplicationNotifications(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);
	struct flow *f;

	while ((f = fq_dequeue(&t->q_notify)) != NULL) {
		/*
		 * One flag, meaning "pending: on the list OR in the queue". The
		 * producer's test-and-set means at most one of those is true,
		 * so this cannot double-insert; the drain clears it when the
		 * flow is finished with.
		 */
		{
			int c;

			/* The queue says "this flow has work"; which lists it
			 * belongs on is read from its per-class flags. */
			for (c = 0; c < MTP_PRIO_CLASSES; c++)
				if (f->on_gen[c])
					TAILQ_INSERT_TAIL(&t->gen_list[c], f,
							  gen_link[c]);
		}
	}
}

/*----------------------------------------------------------------------------*/
/*
 * THE REACHABILITY INVARIANT: if a class's ring is non-empty, the flow must be
 * on that class's gen_list, or the drain will never walk it.
 *
 * Membership is PER CLASS, so a flow can be on class 0's list and absent from
 * class 2's. A blueprint committed into an unlisted class would sit at
 * seg 0/0 for ever holding its payload reference, while the flow still looks
 * reachable and the drain still completes -- which fits every survivor of this
 * week's eliminations.
 *
 * A property, not a state dump: it can fire in a run that never faults, and an
 * unreachable ring is a defect whether or not a flush trips over it.
 */
void
CheckReachable(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);
	uint32_t i;
	int c;

	/*
	 * AN INJECTOR, because a check that has never been shown to fire is
	 * indistinguishable from one that cannot -- the merge counter and the
	 * unwired refusal counter both read zero for exactly that reason.
	 * Enabling this makes the next live flow with a non-empty ring look
	 * unlisted, which must produce a report.
	 */
	if (MTP_ENV_ON("MTP_INJECT_UNREACHABLE") && !t->unreachable_ring) {
		t->unreachable_ring++;
		fprintf(stderr, "\n*** UNREACHABLE RING (INJECTED): the check "
			"can fire\n");
	}

	for (i = 0; i < t->flow_next; i++) {
		struct flow *f = &t->flow_pool[i];

		/* Destroyed slots are still in the pool -- flow_next only ever
		 * increments -- and a destroyed flow keeps whatever ring
		 * indices it died with. Scanning them reported every one as
		 * unreachable the moment churn existed. */
		if (!f->slot_live)
			continue;

		for (c = 0; c < MTP_PRIO_CLASSES; c++) {
			if (f->ring_head[c] == f->ring_tail[c] || f->on_gen[c])
				continue;
			if (t->unreachable_ring++ == 0)
				fprintf(stderr,
					"\n*** UNREACHABLE RING: flow %u class "
					"%d head=%u tail=%u -- committed but "
					"the flow is on no list for it\n", i, c,
					f->ring_head[c], f->ring_tail[c]);
		}
	}
}

/*----------------------------------------------------------------------------*/
static inline uint16_t ring_next(uint16_t i, int c)
{
	return (uint16_t)((i + 1) % bp_depth(c));
}

struct bp *
BlueprintNew(flow_t *f, int c)
{
	/* A SCRATCH SLOT: the one past the tail. Not in the ring, not drained,
	 * holding no live payload reference until commit. Returns NULL when the
	 * ring is full and every caller checks — the prototype has twelve call
	 * sites and not one does. */
	if (ring_next(f->ring_tail[c], c) == f->ring_head[c])
		return NULL;

	/* Two BlueprintNew() with no commit between them is a contract violation,
	 * not a silent overwrite: the second would hand back the same scratch
	 * slot and the first caller's header would vanish under it. Cheap to
	 * assert, and otherwise it surfaces as a corrupted packet weeks later. */
	assert(!f->scratch_out[c]);
	f->scratch_out[c] = 1;

	return &f->ring[c][f->ring_tail[c]];
}

struct bp *
BlueprintLast(flow_t *f, int c)
{
	uint16_t last;

	if (f->ring_head[c] == f->ring_tail[c])
		return NULL;
	last = (uint16_t)((f->ring_tail[c] + bp_depth(c) - 1) % bp_depth(c));
	return &f->ring[c][last];
}

void
BlueprintCommit(flow_t *f, struct bp *bp)
{
	int c = (int)(bp->prio < MTP_PRIO_CLASSES ? bp->prio
						  : MTP_PRIO_CLASSES - 1);

	assert(bp == &f->ring[c][f->ring_tail[c]]);
	f->scratch_out[c] = 0;
	f->ring_tail[c] = ring_next(f->ring_tail[c], c);
	{
		struct transport *t = TransportOf(g_core[0]);
		uint32_t n = (uint32_t)((f->ring_tail[c] + bp_depth(c)
					 - f->ring_head[c]) % bp_depth(c));

		if (n > t->ring_hwm[c])
			t->ring_hwm[c] = n;
	}
	AddtoSendList(f, bp->prio);
}

/*----------------------------------------------------------------------------*/
/*
 * The nine outcomes of a coalesce attempt. Reported at exit alongside the send
 * decision's refusal reasons and the receive path's stages.
 */
enum { MRG_OK, MRG_UNCLASSIFIED, MRG_NO_PENDING, MRG_CLASS, MRG_KEY,
       MRG_SCRATCH, MRG_NEW_NOPAY, MRG_PENDING_NOPAY, MRG_NONCONTIG,
       MRG_REF_FAIL, MRG__N };
static uint64_t g_mrg[MRG__N];

void
ReportMerges(void)
{
	static const char *n[MRG__N] = {
		"MERGED", "program said no", "nothing pending", "class differs",
		"key differs", "scratch_out set", "arriving has no payload",
		"PENDING has no payload", "not contiguous", "ref failed" };
	int i;

	for (i = 0; i < MRG__N; i++)
		fprintf(stderr, "coalesce     %-24s %llu\n", n[i],
			(unsigned long long)g_mrg[i]);
}

/*
 * mtp_pkt_gen — the contract's packet-generation instruction.
 *
 * A program may rely on the packet being transmitted with the payload as it
 * stands now. It may not rely on when: this appends a blueprint and returns,
 * and the drain runs once per main-loop iteration.
 */
int
mtp_pkt_gen(flow_t *f, const void *hdr, uint16_t hdr_len,
	    const struct mtp_tx_payload *payload,
	    uint32_t mss, uint32_t prio, uint32_t offload, uint32_t rtx)
{
	uint16_t keep_off = 0, keep_len = 0;
	/* storage is per (flow, class); coalescing only ever merges within one */
	const int pc = (int)(prio < MTP_PRIO_CLASSES ? prio
						     : MTP_PRIO_CLASSES - 1);
	/* the program function that issued this pkt_gen, for the fault dump */
	const void *issuer = __builtin_return_address(0);
	struct bp *bp;
	uint8_t cls = 0;
	uint32_t key = 0;
	bool inherit = false;

	/*
	 * COALESCING (P2, D-06). Merge with the last pending blueprint when the
	 * program says the two are mergeable. This is the first time the true
	 * ring and coalescing have existed together anywhere: both sibling
	 * branches carrying the Appendix D ring have data merging switched off,
	 * so the combination the paper values at 21 against 15.22 Gbps has
	 * never actually run.
	 *
	 * WHETHER two blueprints are adjacent is the target's business — it
	 * depends on batch boundaries. WHAT a merged one contains is the
	 * program's, or packet content is target-determined.
	 */
	mtp_program_coalesce(hdr, hdr_len, &cls, &key, &inherit,
			     &keep_off, &keep_len);
	if (!cls)
		g_mrg[MRG_UNCLASSIFIED]++;
	if (cls) {
		struct bp *last = BlueprintLast(f, pc);

		/*
		 * WHY A MERGE DID NOT HAPPEN, counted per branch. The same
		 * instrument that answered the send decision and the receive
		 * path immediately, pointed at a third site.
		 *
		 * Evaluated alongside the real conditions rather than replacing
		 * them: counting must not be able to change what the code does,
		 * and this block is the only place the predicates are written
		 * twice — a cost paid deliberately so the merge logic below is
		 * untouched.
		 *
		 * NINE branches, not four. The distinction that matters is
		 * between "the arriving blueprint has no payload" and "the
		 * PENDING one has none": four zero-payload emissions occur per
		 * transfer — SYN-ACK, ack of data, ack of FIN, our FIN — and any
		 * of them pending when a data blueprint arrives produces
		 * adjacency that MUST decline, because a merge needs payload on
		 * both sides. That is correct behaviour, not a puzzle.
		 */
		if (!last)
			g_mrg[MRG_NO_PENDING]++;
		else if (last->coalesce_class != cls)
			g_mrg[MRG_CLASS]++;
		else if (last->coalesce_key != key)
			g_mrg[MRG_KEY]++;
		else if (f->scratch_out[pc])
			g_mrg[MRG_SCRATCH]++;
		else if (!payload || !payload->len)
			g_mrg[MRG_NEW_NOPAY]++;
		else if (!last->payload.len)
			g_mrg[MRG_PENDING_NOPAY]++;
		else if (payload->off != last->base_seq + last->payload.len)
			g_mrg[MRG_NONCONTIG]++;

		if (last && last->coalesce_class == cls &&
		    last->coalesce_key == key && !f->scratch_out[pc]) {
			uint64_t end = last->base_seq + last->payload.len;

			/* contiguous only: a gap would silently fabricate
			 * payload the program never asked to send */
			if (payload && payload->len && last->payload.len &&
			    payload->off == end) {
				payref_t ext;
				/* the base the take is about to use, kept
				 * because base_seq may be rewritten below */
				const uint64_t took_at = last->base_seq;

				/* ONE call: TxRef TAKES a reference, so
				 * asking twice to count the failure would
				 * double-reference on success. */
				int reffed = TxRef(payload->u,
						last->base_seq,
						last->payload.len + payload->len,
						&ext, REF_SITE_MERGE_TAKE,
						last, issuer, (uint8_t)rtx);

				if (reffed != 0)
					g_mrg[MRG_REF_FAIL]++;
				if (reffed == 0) {
					/* the SUPERSEDED reference, named: it is
					 * not the oldest, which is the whole
					 * reason release is by identity */
					TxRefRelease(last->unit,
							   last->base_seq,
							   REF_SITE_MERGE_REL,
							   last, issuer, 0);
					last->payload = ext;
					/* the NEWER header: stale ack, window
					 * or echo on a merged segment is what
					 * building this on the wrong axis
					 * would produce */
					if (MTP_ENV_ON("MTP_TRACE_EV")) {
						/* the exact question: whose
						 * sequence does the merged
						 * segment carry? */
						uint32_t oldseq, newseq;

						memcpy(&oldseq, last->hdr + 4, 4);
						memcpy(&newseq, hdr + 4, 4);
						fprintf(stderr,
							"EV mergehdr old_seq=%u new_seq=%u "
							"old_base=%llu new_base=%llu inherit=%d\n",
							ntohl(oldseq), ntohl(newseq),
							(unsigned long long)last->base_seq,
							(unsigned long long)payload->off,
							inherit);
					}
					/*
					 * The newer header, EXCEPT the range
					 * the program says belongs to the
					 * payload. A blanket copy carried the
					 * newer sequence number onto older
					 * bytes: the peer stored them at the
					 * later offset, nothing arrived for the
					 * gap, and a retransmission followed at
					 * this base. One field, three symptoms.
					 */
					{
						uint8_t keep[8];
						uint16_t kl = keep_len;

						if (inherit && kl &&
						    keep_off + kl <= hdr_len &&
						    kl <= sizeof(keep))
							memcpy(keep, last->hdr + keep_off, kl);
						else
							kl = 0;
						memcpy(last->hdr, hdr, hdr_len);
						if (kl)
							memcpy(last->hdr + keep_off, keep, kl);
					}
					last->hdr_len = hdr_len;
					last->ref_base = took_at;
					if (!inherit)
						last->base_seq = payload->off;
					TransportOf(g_core[0])->merges++;
					g_mrg[MRG_OK]++;
					if (MTP_ENV_ON("MTP_TRACE_EV"))
						fprintf(stderr,
							"EV merge base=%llu len=%u\n",
							(unsigned long long)last->base_seq,
							(unsigned)(ext.len));
					return 0;
				}
			}
		}
	}

	bp = BlueprintNew(f, pc);

	if (!bp) {
		TransportOf(g_core[0])->bp_full++;
		return -1;		/* ring full: the program declines to
					 * emit and the flow stays schedulable */
	}
	assert(hdr_len <= PROG_HDR_MAX);

	memset(bp, 0, sizeof(*bp));
	memcpy(bp->hdr, hdr, hdr_len);
	bp->hdr_len = hdr_len;
	bp->seg_size = (uint16_t)mss;
	bp->prio = prio;
	bp->offload = offload;
	/*
	 * Where the NIC writes the transport checksum, from the program's
	 * header layout. Never setting this left it zero, so the pseudo-header
	 * seed landed on the FIRST TWO BYTES of the header — the source port —
	 * and every frame went out with a checksum where its source port
	 * should be. The header was built correctly and corrupted afterwards,
	 * which is why both probes read 9999 and the wire read 5201.
	 */
	bp->offload_csum_off = PROG_L4_CSUM_OFFSET;
	bp->coalesce_class = cls;
	bp->coalesce_key = key;
	bp->inherit_base = inherit;

	if (payload && payload->len) {
		bp->base_seq = payload->off;
		/* resolve now, dereference at the drain — P1. The reference
		 * stays valid until the program flushes this range, which is
		 * the guarantee that makes deferral safe (internal.h §3). */
		if (TxRef(payload->u, payload->off, payload->len,
			       &bp->payload, REF_SITE_COMMIT, bp, issuer,
			       (uint8_t)rtx) < 0) {
			f->scratch_out[pc] = 0;	/* abandoned, not committed */
			return -1;
		}
		bp->unit = payload->u;
		bp->ref_base = payload->off;
	}

	BlueprintCommit(f, bp);
	return 0;
}

/*
 * Segmentation progress of the blueprints on this flow, printed only from the
 * reference-fault dump. The question it exists to answer: did the drain stop
 * PART-WAY through a blueprint because the transmit buffer filled? If so
 * seg_off is between 0 and the payload length and seg_idx is below seg_count,
 * and the fault is back-pressure being treated as fatal rather than a
 * corruption. If every blueprint is untouched, that candidate is dead.
 */
void
DumpFlowBlueprints(void *owner, uint64_t base)
{
	struct flow *f = (struct flow *)owner;
	int c;

	if (!f) { fprintf(stderr, "  (no owner flow recorded)\n"); return; }

	/* every class, because storage is per (flow, class) and the blueprint
	 * holding the minimum can be in any of them */
	for (c = 0; c < MTP_PRIO_CLASSES; c++) {
		uint16_t i;

		if (f->ring_head[c] == f->ring_tail[c])
			continue;
		fprintf(stderr, "  blueprints, class %d (head=%u tail=%u), "
			"drain is on pass %llu:\n",
			c, f->ring_head[c], f->ring_tail[c],
			(unsigned long long)TransportOf(g_core[0])->drain_pass);
		for (i = f->ring_head[c]; i != f->ring_tail[c];
		     i = (uint16_t)((i + 1) % bp_depth(c))) {
			struct bp *b = &f->ring[c][i];

			fprintf(stderr,
				"    [%2u] base=%llu paylen=%u seg %u/%u "
				"seg_off=%u last_visit=%llu%s%s\n", i,
				(unsigned long long)b->base_seq,
				b->payload.len, b->seg_idx, b->seg_count,
				b->seg_off,
				(unsigned long long)b->last_visit_pass,
				/* separates NEVER VISITED from visited and
				 * unable to complete: different faults */
				b->last_visit_pass ? ""
						   : "  <- NEVER VISITED",
				b->base_seq == base ? "   <- HOLDS THE MINIMUM"
						    : "");
		}
	}
}
