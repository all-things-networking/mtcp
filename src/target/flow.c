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
	/* the flow slot itself is not recycled yet — M1 is one connection.
	 * A free list lands with connection reaping (A3), which M1 excludes. */
}

/*----------------------------------------------------------------------------*/
/* P5: one list per core, enqueued idempotently. A flow with nothing to send is
 * not on it and is not walked. */
void
tgt_sched_enqueue(flow_t *f)
{
	struct transport *t = TransportOf(g_core[0]);

	if (f->on_gen_list)
		return;
	TAILQ_INSERT_TAIL(&t->gen_list, f, gen_link);
	f->on_gen_list = 1;
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
	mtp_program_coalesce(hdr, hdr_len, &cls, &key, &inherit);
	if (cls) {
		struct bp *last = tgt_bp_last(f);

		if (last && last->coalesce_class == cls &&
		    last->coalesce_key == key && !f->scratch_out) {
			uint64_t end = last->base_seq + last->payload.len;

			/* contiguous only: a gap would silently fabricate
			 * payload the program never asked to send */
			if (payload && payload->len && last->payload.len &&
			    payload->off == end) {
				payref_t ext;

				if (tgt_tx_ref(payload->u, last->base_seq,
					       last->payload.len + payload->len,
					       &ext) == 0) {
					tgt_tx_ref_release(last->unit);
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
					memcpy(last->hdr, hdr, hdr_len);
					last->hdr_len = hdr_len;
					if (!inherit)
						last->base_seq = payload->off;
					TransportOf(g_core[0])->merges++;
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
