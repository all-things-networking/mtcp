/*
 * The drain: blueprints out of the ring, packets onto the wire.
 *
 * Runs once per main-loop iteration, after the whole receive burst has been
 * processed. That ordering is what makes acknowledgement coalescing possible,
 * and both references have it.
 *
 * ONE EMISSION PATH. A non-segmented blueprint is a one-segment blueprint. The
 * prototype has the whole block twice — once for the segmented case and once
 * for the not — and the two drifted apart; there is only one here so they
 * cannot.
 */
#include <string.h>
#include <assert.h>

#include "flow.h"
#include "target_core.h"
#include "eth_out.h"
#include "ip_out.h"
#include "io_module.h"
#include "debug.h"

static inline uint16_t ring_next(uint16_t i)
{
	return (uint16_t)((i + 1) % BP_RING_DEPTH);
}

/*----------------------------------------------------------------------------*/
/*
 * One segment. Returns 0, or -1 when the interface's transmit buffer is full,
 * which is a retry rather than an error.
 */
static int
emit_segment(struct core_ctx *core, struct flow *f, struct bp *bp,
	     uint32_t seg_off, uint16_t seg_len)
{
	struct transport *t = TransportOf(core);
	uint16_t l4len = (uint16_t)(bp->hdr_len + seg_len);
	uint8_t *l4;

	/* IPOutput resolves the route once per flow (the nif_out cache) and
	 * returns NULL if the destination is not in the ARP table, having
	 * queued an ARP request. mTCP retries the packet later and so do we:
	 * the blueprint stays in the ring. */
	l4 = IPOutput(core, &f->nif_out, &f->is_external, f->saddr, f->daddr,
		      TRANSPORT_IP_PROTO, f->ip_id, (uint8_t)bp->prio, l4len);
	if (!l4)
		return -1;
	f->ip_id++;			/* per-flow counter from 0; ip_out.c:147 */

	memcpy(l4, bp->hdr, bp->hdr_len);

	/*
	 * Per-segment fixup. The program's generated seg rules evolve whichever
	 * header field the recurrence names; the target passes the view and
	 * knows no field. Skipped for a one-segment blueprint, which is what
	 * the whole of the handshake and every pure acknowledgement is.
	 */
	if (bp->seg_count > 1) {
		struct mtp_seg_view v = {
			.hdr = l4,
			.prev_hdr = bp->prev_hdr_valid ? bp->prev_hdr : NULL,
			.prev_paylen = bp->prev_paylen,
			.seg_idx = bp->seg_idx,
			.n_segs = bp->seg_count,
		};

		mtp_program_segment(&v);
		memcpy(bp->prev_hdr, l4, bp->hdr_len);
		bp->prev_hdr_valid = 1;
		bp->prev_paylen = seg_len;
	}

	if (seg_len) {
		const payref_t *p = &bp->payload;
		uint8_t *dst = l4 + bp->hdr_len;

		/* the true ring: a payload may straddle the end, and the wrap
		 * is carried in the blueprint's own snapshot so the emitter
		 * never touches the stream */
		if (!p->wraps || seg_off + seg_len <= (uint32_t)(p->wrap_at_seq - bp->base_seq)) {
			memcpy(dst, p->data + seg_off, seg_len);
		} else {
			uint32_t first = (uint32_t)(p->wrap_at_seq - bp->base_seq) - seg_off;

			memcpy(dst, p->data + seg_off, first);
			memcpy(dst + first, p->wrap_data, seg_len - first);
		}
	}

	/*
	 * Ask the NIC for the transport checksum. The offsets come from the
	 * program — the header length from the blueprint, the checksum field's
	 * position from a generated constant — so this layer computes a sum
	 * over a header whose shape it does not know.
	 */
	if (bp->offload && core->iom->dev_ioctl) {
		struct l4_csum_req req = {
			.iph = (struct iphdr *)(l4 - IP_HEADER_LEN),
			.l4_hdr_len = bp->hdr_len,
			.l4_csum_offset = (uint16_t)bp->offload_csum_off,
		};

		core->iom->dev_ioctl(core->ctx, f->nif_out,
				     PKT_TX_L3L4_CSUM, &req);
	}

	t->tx_packets++;
	t->tx_bytes += l4len + IP_HEADER_LEN + ETHERNET_HEADER_LEN;
	return 0;
}

/*----------------------------------------------------------------------------*/
static int
emit_bp(struct core_ctx *core, struct flow *f, struct bp *bp)
{
	uint32_t total = bp->payload.len;
	uint16_t mss = bp->seg_size;

	/* one path: a non-segmented blueprint is a one-segment blueprint */
	if (!mss || total <= mss) {
		bp->seg_count = 1;
		bp->seg_idx = 0;
		return emit_segment(core, f, bp, 0, (uint16_t)total);
	}

	bp->seg_count = (uint32_t)((total + mss - 1) / mss);
	while (bp->seg_off < total) {
		uint16_t len = (uint16_t)(total - bp->seg_off < mss
					  ? total - bp->seg_off : mss);

		if (emit_segment(core, f, bp, bp->seg_off, len) < 0)
			return -1;	/* rewound: seg_off is where we stopped */
		bp->seg_off += len;
		bp->seg_idx++;
	}
	return 0;
}

/*
 * Liveness ends when the LAST byte of the blueprint is in an mbuf, so the
 * release is here — once per blueprint, after emit_bp has succeeded — and not
 * inside emit_segment.
 *
 * A blueprint with no payload took no reference and releases none. Getting
 * that backwards would decrement a count nobody incremented, which the FIFO in
 * tx_stream.c would then read as the wrong oldest base.
 */
static void
release_bp(struct bp *bp)
{
	if (bp->payload.len && bp->unit)
		tgt_tx_ref_release(bp->unit);
}

/*----------------------------------------------------------------------------*/
void
tgt_drain(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);
	struct flow *f, *tmp;

	t->ring_drain_calls++;

	TAILQ_FOREACH_SAFE(f, &t->gen_list, gen_link, tmp) {
		while (f->ring_head != f->ring_tail) {
			struct bp *bp = &f->ring[f->ring_head];

			if (emit_bp(core, f, bp) < 0) {
				/*
				 * The transmit buffer is full. Leave this flow
				 * on the list with its partially consumed
				 * blueprint rewound (seg_off is where we
				 * stopped) and ABANDON THE REST OF THE WALK
				 * for this iteration, so the burst can flush.
				 *
				 * Abandoning the remaining flows rather than
				 * skipping this one is deliberate: a full
				 * interface buffer has no room for the next
				 * flow either, so continuing would be a walk
				 * that fails once per flow. The flow keeps its
				 * place at the head, which is the
				 * re-insertion.
				 *
				 * This matches the prototype exactly, checked
				 * against the code rather than remembered:
				 * MTP_PacketGenList (mtp_net.c:840-847 @
				 * eac02d19) does TAILQ_INSERT_HEAD and then
				 * `break`, with the comment "since there is no
				 * available write buffer, break". Its
				 * skip-and-continue branch at :848-854 is dead
				 * code — SendMTPPackets never returns the -1
				 * that would reach it.
				 *
				 * Inherited with it, and worth knowing: an ARP
				 * miss also makes IPOutput return NULL
				 * (ip_out.c:123-135) and is indistinguishable
				 * here, so one unresolved destination stalls
				 * the whole walk for an iteration. True of the
				 * prototype too. Acceptable at M1's single
				 * connection; it is on the list for the
				 * multi-flow work, where it is a
				 * head-of-line block with a 1 s ARP retry
				 * behind it.
				 */
				return;
			}
			release_bp(bp);
			bp->seg_off = 0;
			bp->prev_hdr_valid = 0;
			f->ring_head = ring_next(f->ring_head);
		}

		TAILQ_REMOVE(&t->gen_list, f, gen_link);
		f->on_gen_list = 0;
	}
}
