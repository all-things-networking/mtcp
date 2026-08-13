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
#include <stdio.h>
#include <stdlib.h>
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
 * Dump the frame we just built, at the moment we hand it over.
 *
 * Inert unless MTP_DUMP_TX is set, and capped, so an instrumented binary is
 * safe to benchmark — the same discipline D-03 imposes on the references.
 *
 * This exists because a kernel-side capture cannot see this target's traffic in
 * either direction: with a bifurcated driver, packets steered to the DPDK queue
 * never reach the netdev tcpdump attaches to. The peer's capture is the only
 * wire view, and it cannot show a frame that was addressed somewhere the peer
 * is not. This can.
 */
static void
dump_tx(const uint8_t *eth, uint16_t total)
{
	static int budget = -1;
	uint16_t i;

	if (budget < 0) {
		const char *e = getenv("MTP_DUMP_TX");

		budget = e ? atoi(e) : 0;
	}
	if (budget <= 0)
		return;
	budget--;

	fprintf(stderr, "TX %u bytes:", total);
	for (i = 0; i < total; i++)
		fprintf(stderr, "%s%02x", (i % 16) ? " " : "\n  ", eth[i]);
	fprintf(stderr, "\n  dst_mac=%02x:%02x:%02x:%02x:%02x:%02x "
		"src_mac=%02x:%02x:%02x:%02x:%02x:%02x ethertype=%02x%02x\n",
		eth[0], eth[1], eth[2], eth[3], eth[4], eth[5],
		eth[6], eth[7], eth[8], eth[9], eth[10], eth[11],
		eth[12], eth[13]);
	fprintf(stderr, "  saddr=%u.%u.%u.%u daddr=%u.%u.%u.%u proto=%u "
		"sport=%u dport=%u flags=0x%02x\n",
		eth[26], eth[27], eth[28], eth[29],
		eth[30], eth[31], eth[32], eth[33], eth[23],
		(eth[34] << 8) | eth[35], (eth[36] << 8) | eth[37], eth[47]);
}

/*----------------------------------------------------------------------------*/
/*
 * Deliberately lose one transmitted segment, once.
 *
 * The retransmission timer is the first mechanism in this target whose ABSENCE
 * is invisible in a clean run. Everything before it failed loudly when wrong: a
 * missing SYN-ACK, a malformed header, a stalled teardown. A timer that never
 * fires looks exactly like a timer that was never needed, on a link that loses
 * nothing — and the effective RTO here is ~3 ms against a round trip of at most
 * 0.229 ms, so waiting does not produce one either. It has to be provoked.
 *
 * Provoking it from the SERVER rather than with `tc` on the client is
 * deliberate: the loss is then deterministic, it is a known segment index
 * rather than a probability, and it does not touch the peer's stack — so what
 * the peer does afterwards is its ordinary behaviour and not an artefact of the
 * apparatus.
 *
 * Inert unless MTP_DROP_NTH is set, and it fires once per process. D-03's
 * discipline for instrumentation on a reference applies to us as well: an
 * instrumented binary must be safe to benchmark unenabled.
 */
static int
drop_this_one(uint16_t seg_len)
{
	static int nth = -1;
	static int seen;

	/*
	 * DATA-carrying only, and the name says so. The first version counted
	 * every transmitted segment, so MTP_DROP_NTH=5 dropped a pure
	 * acknowledgement and the transfer completed — a knob that was exactly
	 * what it said and not what its reader assumed, which is the defect
	 * this week keeps producing. Dropping an acknowledgement makes no hole;
	 * only losing data does.
	 */
	if (!seg_len)
		return 0;

	if (nth < 0) {
		const char *e = getenv("MTP_DROP_NTH_DATA");

		nth = e ? atoi(e) : 0;
	}
	if (!nth)
		return 0;
	if (++seen != nth)
		return 0;

	fprintf(stderr, "MTP_DROP_NTH_DATA: dropping data segment %d (%u bytes) "
		"— the peer cannot acknowledge past it until we retransmit\n",
		nth, seg_len);
	return 1;
}

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

		/*
		 * LOUD. dev_ioctl returns -1 when the NIC does not advertise
		 * the capability, and ignoring that means the packet leaves
		 * with whatever the program left in the checksum field — a
		 * silent-drop default of exactly the kind we said we would not
		 * inherit, and one that looks like a packet that never left.
		 */
		if (core->iom->dev_ioctl(core->ctx, f->nif_out,
					 PKT_TX_L3L4_CSUM, &req) < 0) {
			TRACE_ERROR("the NIC refused the transport-checksum "
				    "offload this packet asked for; it would "
				    "go out unsummed and be dropped by the "
				    "peer, so it is not sent\n");
			return -1;
		}
	}

	/* Dropped AFTER the frame is fully built, so everything upstream —
	 * header, fixup, payload copy, checksum request — runs exactly as it
	 * would have. Only the wire misses it. */
	if (drop_this_one(seg_len)) {
		t->tx_dropped_for_test++;
		return 0;
	}

	dump_tx(l4 - IP_HEADER_LEN - ETHERNET_HEADER_LEN,
		(uint16_t)(l4len + IP_HEADER_LEN + ETHERNET_HEADER_LEN));

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

	/*
	 * A blueprint the emitter does not know how to segment must be LOUD.
	 * The prototype silently drops one whose segmentation-rule group is
	 * anything but 1 — the head advances, nothing is emitted, no error
	 * (mtp_net.c:500-506 and :635 on 55056faf). Latent there because only
	 * group 1 is ever set, which is exactly the kind of default that stops
	 * being latent the day a second rule exists.
	 */
	if (total && !mss) {
		TRACE_ERROR("blueprint of %u payload bytes with no segment "
			    "size: dropping it would be silent, so this is "
			    "the error instead\n", total);
		assert(0);
		return 0;
	}

	/* one path: a non-segmented blueprint is a one-segment blueprint */
	if (!mss || total <= mss) {
		bp->seg_count = 1;
		bp->seg_idx = 0;
		return emit_segment(core, f, bp, 0, (uint16_t)total);
	}

	/*
	 * THE CURSOR IS LOAD-BEARING, NOT A STYLE CHOICE. Do not "simplify" it
	 * into the prototype's shape.
	 *
	 * On a partial drain the prototype REWRITES THE BLUEPRINT IN PLACE —
	 * new seq, reduced len, advanced data pointer — and leaves it at the
	 * head (mtp_net.c:522-529 on mina-mtp 55056faf). That is only safe
	 * there because its send buffer is not a true ring: the retained raw
	 * pointer stays valid across the break.
	 *
	 * Ours IS a true ring, so an advanced raw pointer can be on the wrong
	 * side of a wrap by the time the drain resumes. This is the SIXTH
	 * piece in differences.md §0a — added by D after the table had been
	 * read as complete, and the only one of the six that quic-mtp had not
	 * already solved. Read §0a rather than this comment for the argument.
	 * The
	 * blueprint therefore stays immutable and the progress lives in
	 * seg_off, which is an offset and cannot go stale. Rewriting in place
	 * here would look correct and would fail on the first wrap.
	 */
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
				 * PROVISIONAL — do not settle this without the
				 * checkpoint. Rule 2 names per-flow scheduling
				 * as needing a written design and a yes, and
				 * this is that.
				 *
				 * It matches the PROTOTYPE: MTP_PacketGenList
				 * does TAILQ_INSERT_HEAD then `break`, with
				 * the comment "since there is no available
				 * write buffer, break" (mtp_net.c:803-810 on
				 * mina-mtp 55056faf — the unmodified
				 * prototype; the same text sits at :840-847 on
				 * mtp-dpdk-clean, and that is the branch we
				 * were warned not to attribute decisions to).
				 *
				 * It does NOT match the DONOR, and that is the
				 * open question. mTCP runs three lists with
				 * three policies: control inserts at the HEAD
				 * and breaks, data inserts at the TAIL and
				 * breaks, and ACKs do not stop the walk at
				 * all. We have one gen_list and one policy, so
				 * this is a trajectory-level parity
				 * difference — and it fires on
				 * transmit-buffer-full, which a 64-mbuf burst
				 * hits constantly, not on some rare path.
				 *
				 * Not an ARP question. B established that mTCP
				 * collapses four distinct NULL conditions into
				 * one bare NULL and then into a single -2, so
				 * failing to tell an ARP miss from a full
				 * buffer is shared inherited debt rather than
				 * a divergence.
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
