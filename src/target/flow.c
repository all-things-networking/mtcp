/*
 * Flow records, the blueprint ring, the generation list, and pkt_gen.
 *
 * pkt_gen is here rather than in emit.c because what it does is put a
 * blueprint in a ring and schedule the flow — it does not build a packet. That
 * happens in the drain, once per main-loop iteration, and the interval between
 * the two is what makes coalescing possible (internal.h §1).
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pthread.h>

#include "flow.h"
#include "flow_table.h"
#include "target_core.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
int
FlowPoolInit(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);

	t->flow_pool = calloc(CONFIG.max_concurrency, sizeof(struct flow));
	t->bp_pool = calloc((size_t)CONFIG.max_concurrency * BP_RING_DEPTH,
			    sizeof(struct bp));
	if (!t->flow_pool || !t->bp_pool)
		return -1;

	t->flow_next = 0;

	/* Capacity is flow count -- see the field's comment. Rounded up to a
	 * power of two because the ring masks. */
	{
		uint32_t cap = 1;

		while (cap < (uint32_t)CONFIG.max_concurrency)
			cap <<= 1;
		t->q_notify_slots = calloc(cap, sizeof(*t->q_notify_slots));
		if (!t->q_notify_slots ||
		    !spsc_init(&t->q_notify, t->q_notify_slots, cap))
			return -1;
	}
	TAILQ_INIT(&t->gen_list);
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
	f->ring = &t->bp_pool[(size_t)t->flow_next * BP_RING_DEPTH];
	t->flow_next++;

	f->key = *key;
	f->saddr = saddr;
	f->daddr = daddr;
	f->nif_out = -1;
	f->is_external = 0;
	f->ip_id = 0;
	f->ring_head = f->ring_tail = 0;
	f->on_gen_list = 0;
	f->ctx = NULL;
	/* §19: zeroed here, so the application's first look at a new flow
	 * sees all-zero and needs no separate "flow began" event. */
	memset(f->app_state, 0, sizeof(f->app_state));

	return f;
}

void
FlowDestroy(struct core_ctx *core, struct flow *f)
{
	struct transport *t = TransportOf(core);

	if (f->on_gen_list) {
		TAILQ_REMOVE(&t->gen_list, f, gen_link);
		f->on_gen_list = 0;
	}
	FlowTableRemove(t->flows, &f->key);
	/* §19: the application's block dies with the flow. Poisoned rather than
	 * merely left, so that an application still holding this flow reads
	 * something obviously wrong instead of its own last-known-good state —
	 * the failure this whole mechanism exists to prevent is precisely a
	 * plausible-looking stale value. */
	memset(f->app_state, 0xA5, sizeof(f->app_state));
	/* the flow slot itself is not recycled yet — M1 is one connection.
	 * A free list lands with connection reaping (A3), which M1 excludes. */
}

/*
 * §19. The target hands the block back and never looks inside it. No length is
 * returned: the size is a compile-time constant the application asserts
 * against, so a mismatch is a build failure rather than a runtime check.
 */
void *
mtp_flow_app_state(flow_t *f)
{
	return f->app_state;
}

/*----------------------------------------------------------------------------*/
/* P5: one list per core, enqueued idempotently. A flow with nothing to send is
 * not on it and is not walked. */
void
tgt_sched_enqueue(flow_t *f)
{
	struct transport *t = TransportOf(g_core[0]);
	struct spsc_slot slot;

	/*
	 * THE GUARD IS HERE, not at the call sites, and it is what makes the
	 * ring's flow-count capacity sound (§21.10). Test-and-set: a flow
	 * already pending enqueues nothing, however many times it is written.
	 */
	if (f->on_gen_list)
		return;
	f->on_gen_list = 1;

	/*
	 * Same thread as the stack: insert directly, so a flow enqueued while
	 * handling a packet is drained in the SAME pass. Routing it through the
	 * ring would cost it an iteration and lose the single-pass property.
	 */
	if (t->stack_tid == 0 ||
	    t->stack_tid == (uint64_t)(uintptr_t)pthread_self()) {
		TAILQ_INSERT_TAIL(&t->gen_list, f, gen_link);
		return;
	}

	/* The application thread. Publish; the stack thread moves it across. */
	slot.a = (uint64_t)(uintptr_t)f;
	slot.b = 0;
	if (spsc_push_n(&t->q_notify, &slot, 1) != 1) {
		/*
		 * Structurally impossible: capacity is max_concurrency and the
		 * flag above means each flow occupies at most one slot. If it
		 * ever happens the capacity argument has been broken by a new
		 * producer, which is exactly the prototype's defect -- so it is
		 * loud rather than a discarded return value.
		 */
		fprintf(stderr, "\n*** NOTIFY RING FULL: capacity is flow count "
			"and the membership flag should make this impossible "
			"(DESIGN.md \u00a721.10)\n");
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
void
tgt_sched_take_notifications(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);
	struct spsc_slot got[64];
	uint32_t n, i;

	while ((n = spsc_pop_n(&t->q_notify, got, 64)) > 0)
		for (i = 0; i < n; i++) {
			struct flow *f = (struct flow *)(uintptr_t)got[i].a;

			/*
			 * One flag, meaning "pending: on the list OR in the
			 * ring". The producer's test-and-set means at most one
			 * of those is true, so this cannot double-insert; the
			 * drain clears it when the flow is finished with.
			 */
			if (f->on_gen_list)
				TAILQ_INSERT_TAIL(&t->gen_list, f, gen_link);
		}
}

/*----------------------------------------------------------------------------*/
static inline uint16_t ring_next(uint16_t i) { return (uint16_t)((i + 1) % BP_RING_DEPTH); }

struct bp *
tgt_bp_new(flow_t *f)
{
	/* A SCRATCH SLOT: the one past the tail. Not in the ring, not drained,
	 * holding no live payload reference until commit. Returns NULL when the
	 * ring is full and every caller checks — the prototype has twelve call
	 * sites and not one does. */
	if (ring_next(f->ring_tail) == f->ring_head)
		return NULL;

	/* Two tgt_bp_new() with no commit between them is a contract violation,
	 * not a silent overwrite: the second would hand back the same scratch
	 * slot and the first caller's header would vanish under it. Cheap to
	 * assert, and otherwise it surfaces as a corrupted packet weeks later. */
	assert(!f->scratch_out);
	f->scratch_out = 1;

	return &f->ring[f->ring_tail];
}

struct bp *
tgt_bp_last(flow_t *f)
{
	uint16_t last;

	if (f->ring_head == f->ring_tail)
		return NULL;
	last = (uint16_t)((f->ring_tail + BP_RING_DEPTH - 1) % BP_RING_DEPTH);
	return &f->ring[last];
}

void
tgt_bp_commit(flow_t *f, struct bp *bp)
{
	assert(bp == &f->ring[f->ring_tail]);
	f->scratch_out = 0;
	f->ring_tail = ring_next(f->ring_tail);
	tgt_sched_enqueue(f);
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
tgt_report_merges(void)
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
	    uint32_t mss, uint32_t prio, uint32_t offload)
{
	uint16_t keep_off = 0, keep_len = 0;
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
		struct bp *last = tgt_bp_last(f);

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
		else if (f->scratch_out)
			g_mrg[MRG_SCRATCH]++;
		else if (!payload || !payload->len)
			g_mrg[MRG_NEW_NOPAY]++;
		else if (!last->payload.len)
			g_mrg[MRG_PENDING_NOPAY]++;
		else if (payload->off != last->base_seq + last->payload.len)
			g_mrg[MRG_NONCONTIG]++;

		if (last && last->coalesce_class == cls &&
		    last->coalesce_key == key && !f->scratch_out) {
			uint64_t end = last->base_seq + last->payload.len;

			/* contiguous only: a gap would silently fabricate
			 * payload the program never asked to send */
			if (payload && payload->len && last->payload.len &&
			    payload->off == end) {
				payref_t ext;

				/* ONE call: tgt_tx_ref TAKES a reference, so
				 * asking twice to count the failure would
				 * double-reference on success. */
				int reffed = tgt_tx_ref(payload->u,
						last->base_seq,
						last->payload.len + payload->len,
						&ext);

				if (reffed != 0)
					g_mrg[MRG_REF_FAIL]++;
				if (reffed == 0) {
					/* the SUPERSEDED reference, named: it is
					 * not the oldest, which is the whole
					 * reason release is by identity */
					tgt_tx_ref_release(last->unit,
							   last->base_seq);
					last->payload = ext;
					/* the NEWER header: stale ack, window
					 * or echo on a merged segment is what
					 * building this on the wrong axis
					 * would produce */
					if (getenv("MTP_TRACE_EV")) {
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
					if (!inherit)
						last->base_seq = payload->off;
					TransportOf(g_core[0])->merges++;
					g_mrg[MRG_OK]++;
					if (getenv("MTP_TRACE_EV"))
						fprintf(stderr,
							"EV merge base=%llu len=%u\n",
							(unsigned long long)last->base_seq,
							(unsigned)(ext.len));
					return 0;
				}
			}
		}
	}

	bp = tgt_bp_new(f);

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
		if (tgt_tx_ref(payload->u, payload->off, payload->len,
			       &bp->payload) < 0) {
			f->scratch_out = 0;	/* abandoned, not committed */
			return -1;
		}
		bp->unit = payload->u;
	}

	tgt_bp_commit(f, bp);
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
tgt_dump_flow_bps(void *owner, uint64_t base)
{
	struct flow *f = (struct flow *)owner;
	uint16_t i;

	if (!f) { fprintf(stderr, "  (no owner flow recorded)\n"); return; }

	fprintf(stderr, "  blueprints on this flow (ring head=%u tail=%u):\n",
		f->ring_head, f->ring_tail);
	for (i = f->ring_head; i != f->ring_tail; i = (uint16_t)((i + 1) % BP_RING_DEPTH)) {
		struct bp *b = &f->ring[i];

		fprintf(stderr,
			"    [%2u] base=%llu paylen=%u seg %u/%u seg_off=%u%s\n",
			i, (unsigned long long)b->base_seq, b->payload.len,
			b->seg_idx, b->seg_count, b->seg_off,
			b->base_seq == base ? "   <- HOLDS THE MINIMUM" : "");
	}
}
