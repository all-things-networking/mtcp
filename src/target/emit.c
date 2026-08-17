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
#include "prog_params.h"
#include "debug.h"

static inline uint16_t ring_next(uint16_t i, int c)
{
	return (uint16_t)((i + 1) % bp_depth(c));
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
/* Resolved once rather than per segment: this is the hottest path in the
 * target and a getenv() here would dominate it. -1 = not yet resolved. */
static int g_trace_seg = -1;

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

	/*
	 * Dropped BEFORE the frame is staged, and that placement is the whole
	 * point. The first version checked after the frame was built — which
	 * reads better, because header, fixup, payload copy and checksum all
	 * run — but by then IPOutput has already claimed a slot in the
	 * interface's transmit buffer and returning early does not unstage it.
	 * The segment went out anyway. The knob logged a drop, the wire showed
	 * an unbroken sequence space, and the retransmission timer correctly
	 * did nothing while appearing not to work.
	 *
	 * Fourth time this week the apparatus lied rather than the code. The
	 * trade is real — this no longer exercises the build path for the
	 * dropped segment — and a correct instrument that tests less is worth
	 * more than a thorough one that reports fiction.
	 */
	if (drop_this_one(seg_len)) {
		/*
		 * A LOST SEGMENT STILL HAPPENED. The per-segment fixup is a
		 * RECURRENCE over the previous segment's header, so skipping it
		 * leaves prev_hdr stale and the NEXT segment takes the dropped
		 * one's sequence number while carrying its own payload — the
		 * peer then stores good data at the wrong offset, shifted by
		 * exactly one segment, with the sequence space still contiguous
		 * and the length still right.
		 *
		 * That is what the corruption was, and it was the instrument
		 * rather than the transport: three hypotheses about the
		 * retransmit path all died because the retransmit path was
		 * fine. So the drop advances the bookkeeping exactly as a
		 * transmission would and only the wire misses it — which is
		 * what the comment claimed the first time and did not do.
		 */
		if (bp->seg_count > 1) {
			uint8_t scratch[PROG_HDR_MAX];
			struct mtp_seg_view v = {
				.hdr = scratch,
				.prev_hdr = bp->prev_hdr_valid ? bp->prev_hdr : NULL,
				.prev_paylen = bp->prev_paylen,
				.seg_idx = bp->seg_idx,
				.n_segs = bp->seg_count,
			};

			memcpy(scratch, bp->hdr, bp->hdr_len);
			mtp_program_segment(&v);
			memcpy(bp->prev_hdr, scratch, bp->hdr_len);
			bp->prev_hdr_valid = 1;
			bp->prev_paylen = seg_len;
		}
		t->tx_dropped_for_test++;
		t->tx_suppressed++;
		return 0;
	}

	/* IPOutput resolves the route once per flow (the nif_out cache) and
	 * returns NULL if the destination is not in the ARP table, having
	 * queued an ARP request. mTCP retries the packet later and so do we:
	 * the blueprint stays in the ring. */
	/*
	 * TOS IS ALWAYS ZERO, as the donor's is. `bp->prio` used to be passed
	 * here, which made one field mean two things -- a scheduling hint and a
	 * header byte -- and put a value on the wire the donor never sets:
	 * `iph->tos = 0` unconditionally at ip_out.c:74 and :145, and its
	 * IPOutput takes no tos argument at all.
	 *
	 * Latent while every pkt_gen site passed prio = 0. It would have
	 * stopped being latent the moment the scheduler gave the classes
	 * distinct values -- a wire divergence appearing as a side effect of
	 * building something else, which is the kind that ships without anyone
	 * deciding. `prio` now reaches the drain and nothing else.
	 */
	l4 = IPOutput(core, &f->nif_out, &f->is_external, f->saddr, f->daddr,
		      TRANSPORT_IP_PROTO, f->ip_id, 0 /* tos */, l4len);
	if (!l4) {
		/* counted so "frames handed down" is reconstructible as
		 * tx_packets + tx_suppressed. The donor counts at
		 * SendTCPPacket, BEFORE any driver-level outcome; our counter
		 * sits after this point, so without this the two totals are
		 * not the same set and the difference has the sign of the gap
		 * we are trying to measure. */
		t->tx_suppressed++;
		/*
		 * BY THE REAL CAUSE. Calling all of this a "route miss" repeated
		 * the mistake it was built to fix: IPOutput has two unrelated
		 * NULL returns and the name came from the first branch in the
		 * comment above, not from a measurement.
		 */
		if (core->last_ipout_fail == IPOUT_NO_ARP)
			t->emit_refused_arp++;
		else
			t->emit_refused_noframe++;
		return -1;
	}
	f->ip_id++;			/* per-flow counter from 0; ip_out.c:147 */

	/* The wire's own high-water, in stream space. Set here because this is
	 * the last point at which a segment can still fail to go out. */
	if (bp->unit) {
		uint64_t end = bp->base_seq + seg_off + seg_len;

		if (end > bp->unit->emitted_hwm)
			bp->unit->emitted_hwm = end;
	}

	/*
	 * Per-segment state at the moment of emission, for the junction defect
	 * (RESULTS 2026-08-15). Placed BEFORE the fixup below, because that
	 * fixup OVERWRITES prev_paylen — logging after it would report the value
	 * this segment stores, not the value this segment inherited, and the
	 * inherited one is the whole question.
	 *
	 * Logs every field regardless of which reading it supports: blueprint
	 * and flow identity to see interleaving, seg_* to locate the junction,
	 * the inherited prev_* because a wrong LENGTH displaces payload without
	 * any header byte being involved, and the payload snapshot because the
	 * corruption is in payload. Deliberately not built around one candidate.
	 */
	if (g_trace_seg < 0)
		g_trace_seg = MTP_ENV_ON("MTP_TRACE_SEG") ? 1 : 0;
	if (g_trace_seg) {
		fprintf(stderr,
			"SEG bp=%p flow=%p base=%llu off=%u len=%u idx=%u/%u "
			"prev_valid=%u prev_paylen=%u pay=%p paylen=%u wraps=%d\n",
			(void *)bp, (void *)f,
			(unsigned long long)(bp->base_seq + seg_off),
			seg_off, seg_len, bp->seg_idx, bp->seg_count,
			bp->prev_hdr_valid, bp->prev_paylen,
			(void *)bp->payload.data, bp->payload.len,
			bp->payload.wraps ? 1 : 0);
	}

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
		/*
		 * THREE CASES, NOT TWO. A blueprint's payload may lie entirely
		 * before the ring's wrap, straddle it, or lie entirely AFTER
		 * it — and the third is a real case as soon as one blueprint
		 * is segmented into pieces, because only the first pieces are
		 * before the wrap.
		 *
		 * It was missing, and the arithmetic did not fail safe: the
		 * straddle branch computes `first` as (wrap - base) - seg_off,
		 * which UNDERFLOWS for a segment starting past the wrap and
		 * asks memcpy for about four gigabytes.
		 *
		 * Nothing had ever reached it. A 256 KB ring serving a 64 KB
		 * object never wraps at all, so `wraps` was false on every
		 * blueprint ever emitted here; the 1 MB object made the ring
		 * wrap for the first time.
		 */
		uint32_t wrap_off = p->wraps
			? (uint32_t)(p->wrap_at_seq - bp->base_seq) : 0;

		if (!p->wraps || seg_off + seg_len <= wrap_off) {
			memcpy(dst, p->data + seg_off, seg_len);
		} else if (seg_off >= wrap_off) {
			memcpy(dst, p->wrap_data + (seg_off - wrap_off), seg_len);
		} else {
			uint32_t first = wrap_off - seg_off;

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
			t->emit_refused_offload++;
			return -1;
		}
	}

	dump_tx(l4 - IP_HEADER_LEN - ETHERNET_HEADER_LEN,
		(uint16_t)(l4len + IP_HEADER_LEN + ETHERNET_HEADER_LEN));

	/*
	 * Payload-size histogram. The donor's shape is 99.75% full-size with
	 * one short tail per connection (B, bench/results/2026-08-13-donor-
	 * segmentation), so a second mode here names a segmentation bug in one
	 * run rather than an argument.
	 */
	if (seg_len == 0)
		t->tx_hist_zero++;
	else if (seg_len >= PARITY_MSS_PAYLOAD)
		t->tx_hist_full++;
	else {
		t->tx_hist_short++;
		if (t->tx_hist_short_mode == 0 || seg_len == t->tx_hist_short_mode) {
			t->tx_hist_short_mode = seg_len;
			t->tx_hist_short_mode_n++;
		}
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
	if (!bp->payload.len || !bp->unit)
		return;

	/*
	 * MEASURED, NOT FIXED, on purpose: the release still uses base_seq, so
	 * this run reports the existing code's behaviour rather than a change's.
	 * A mismatch means the release is naming a base the take never used.
	 */
	if (bp->ref_base != bp->base_seq) {
		struct transport *t = TransportOf(g_core[0]);

		if (t->release_base_mismatch++ == 0)
			fprintf(stderr,
				"\n*** RELEASE BASE MISMATCH: taken at %llu, "
				"releasing %llu (delta %+lld), paylen=%u\n",
				(unsigned long long)bp->ref_base,
				(unsigned long long)bp->base_seq,
				(long long)((int64_t)bp->base_seq
					    - (int64_t)bp->ref_base),
				bp->payload.len);
	}
	tgt_tx_ref_release(bp->unit, bp->base_seq, REF_SITE_DRAIN_REL, bp,
			   NULL, 0);
}

/*----------------------------------------------------------------------------*/
void
tgt_drain(struct core_ctx *core)
{
	struct transport *t = TransportOf(core);
	struct flow *f, *tmp;
	int c;

	/* Which pass we are on, so a blueprint can record the last one that
	 * reached it. The reachability invariant proves the ring is on the
	 * list; it does not prove the walk got to this entry. */
	t->drain_pass++;

	t->ring_drain_calls++;

	/*
	 * THE MERGE INJECTOR — MTP_MERGE_HOLD=n.
	 *
	 * Coalescing needs two blueprints pending in one drain, which needs two
	 * send decisions between drains, which a natural workload produces only
	 * when acknowledgements arrive in a burst. So it fired 1-5 times in a
	 * megabyte and never at all at 64 KB, and after the sequence-field fix
	 * it stopped firing entirely — leaving the mechanism SHOWN NOT FIRING
	 * rather than SHOWN WORKING.
	 *
	 * Holding the drain for n iterations lets blueprints accumulate, so
	 * adjacency is produced deliberately instead of waited for. Same
	 * argument as MTP_DROP_NTH_DATA and the checksum corrupter: a mechanism
	 * that cannot be made to run cannot be shown to work.
	 *
	 * BOUNDED, because rule 5 treats a hang as a failing test: the hold
	 * releases after n iterations whatever happened, so the worst case is
	 * delayed transmission and never a stall.
	 */
	{
		static int hold = -1;
		static uint32_t held;

		if (hold < 0) {
			const char *e = getenv("MTP_MERGE_HOLD");

			hold = e ? atoi(e) : 0;
		}
		/*
		 * Counted in ITERATIONS, not drains-to-skip: the poll loop runs
		 * about 5x10^7 times a second while acknowledgements arrive
		 * microseconds apart, so "skip n drains" is nanoseconds and
		 * stacks up nothing. n is therefore scaled to span real time —
		 * n=100 is roughly 2 microseconds of holding, which is the
		 * order an acknowledgement gap actually has.
		 */
		if (hold > 0) {
			if (++held % (uint32_t)(hold * 100))
				return;		/* let the next send stack up */
		}
	}

	/*
	 * How many blueprints were pending when the drain ran.
	 *
	 * Coalescing merges BLUEPRINTS, and one send decision produces one
	 * blueprint, so two pending in a single iteration requires two send
	 * decisions in one iteration — which requires two acknowledgements in
	 * one receive burst. That is the whole of whether P2 can fire, and it
	 * is countable rather than arguable.
	 */
	for (c = MTP_PRIO_CLASSES - 1; c >= 0; c--)
	TAILQ_FOREACH(f, &t->gen_list[c], gen_link[c]) {
		uint32_t n = (uint32_t)((f->ring_tail[c] + bp_depth(c)
					 - f->ring_head[c]) % bp_depth(c));

		if (n < 4)
			t->drain_depth[n]++;
		else
			t->drain_depth[4]++;
	}

	/*
	 * HIGHEST CLASS FIRST (D-17). The target does not know what any class
	 * means -- the program stated it at pkt_gen -- it only drains higher
	 * before lower. A flow sits at its highest pending class, so this
	 * orders across flows, and within a flow the ring order is the
	 * program's own sequencing.
	 */
	for (c = MTP_PRIO_CLASSES - 1; c >= 0; c--)
	TAILQ_FOREACH_SAFE(f, &t->gen_list[c], gen_link[c], tmp) {
		while (f->ring_head[c] != f->ring_tail[c]) {
			struct bp *bp = &f->ring[c][f->ring_head[c]];

			bp->last_visit_pass = t->drain_pass;
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
				 * all. Priority is the program's, so
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
				 *
				 * COUNTED HERE, at the return itself. The
				 * previous attempt anchored on a comment line
				 * that was not the end of the comment, matched
				 * nothing, and left the counter reading zero
				 * for three sets of runs -- which was then
				 * read as "this path is never taken". A
				 * counter that is never incremented is
				 * indistinguishable from a path never taken.
				 */
				t->emit_refused++;
				return;
			}
			release_bp(bp);
			bp->seg_off = 0;
			bp->prev_hdr_valid = 0;
			f->ring_head[c] = ring_next(f->ring_head[c], c);
		}

		TAILQ_REMOVE(&t->gen_list[c], f, gen_link[c]);
		f->on_gen[c] = 0;
	}

	/*
	 * After a COMPLETE walk only: the early return above leaves flows
	 * listed on purpose, so checking there would report back-pressure as a
	 * defect.
	 *
	 * SAMPLED, NOT EVERY PASS. The drain runs tens of millions of times a
	 * minute and this is O(flows x classes) over the whole pool, which perf
	 * measured at 17.2% of the server's cycles -- the single largest
	 * consumer, larger than the receive path (RESULTS 2026-08-17). An
	 * unreachable ring is a PERMANENT state: once a flow's ring is orphaned
	 * nothing puts it back, so a check every 1024 passes finds it just as
	 * surely, a few microseconds later, for a thousandth of the cost.
	 */
	/* The sampling interval is switchable at runtime so the cost of the
	 * check can be measured against itself in one binary -- the question
	 * "was the server CPU-bound" needs both arms and a rebuild between them
	 * is a second variable. */
	if ((t->drain_pass & (MTP_ENV_ON("MTP_INVARIANT_EVERY_PASS") ? 0 : 1023))
	    == 0)
		tgt_check_reachable(core);
}
