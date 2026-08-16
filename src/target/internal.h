#ifndef INTERNAL_H
#define INTERNAL_H
/*
 * How this target realises the instruction set. NOT contract surface.
 *
 * No `.mtp` program sees anything in this file, no generated code includes it,
 * and nothing here appears in MTP_LANG. That is the test (docs/DECISIONS.md
 * D-16): if a program sees it, it is in contract.h and it conforms to v4; if it
 * does not, it is here and it is ours.
 *
 * And it should be ours. The kernel target stays close to its donor, Linux —
 * skbs, page refcounts, GSO, the socket layer. This one stays close to ours,
 * mTCP, and under rule 1 that is mandatory: the whole effort exists to measure
 * the cost of programmability against mTCP on the same target, so anywhere the
 * plumbing differs from the donor's for no reason is a difference that lands in
 * a measurement and cannot be attributed.
 *
 * The substance below is docs/DESIGN.md §§2.5, 2.6, 4.2, 4.3 — P1 through P4,
 * the true ring, and the release clamp. None of it changed when we conformed to
 * v4, because none of it was ever language.
 */
#include <stdint.h>
#include <stdbool.h>

#include "contract.h"
#include "prog_params.h"

/* Forward-declared rather than including infra.h: the ring and the blueprint
 * must not reach the DPDK layer, or the parts of the target that could be
 * tested without a NIC stop being testable. */
struct core_ctx;	/* PROG_HDR_MAX — the ring is sized from the program's
				 * largest header, which is a compile-time shape */

/*============================================================================*
 * 1. Why packet generation is deferred here and immediate there
 *============================================================================*/
/*
 * mtp_pkt_gen() promises a program that the packet will be transmitted with the
 * payload as it stands at the call. It does not promise when, and the two
 * targets differ:
 *
 *   kernel  builds a super-skb inside the call, gathering the payload range out
 *           of the unit's frag pages by BUMPING PAGE REFCOUNTS, and hands it to
 *           the stack. The reference is a page reference, so retiring bytes
 *           from the unit afterwards cannot invalidate anything in flight.
 *
 *   here    appends a BLUEPRINT to a per-flow ring and returns. Once per main
 *           loop iteration the ring is drained: adjacent blueprints coalesce,
 *           long payloads segment, headers are fixed up per segment, bytes are
 *           copied into mbufs, and the burst goes out.
 *
 * The deferral is not an optimisation we chose to add. It IS mTCP's shape, and
 * the interval between committing a blueprint and draining it is exactly what
 * blueprint coalescing needs to exist at all — the mechanism the paper values
 * at 21 against 15.22 Gbps. A target that transmitted inside pkt_gen would have
 * nothing to coalesce and would not be measuring the thing.
 *
 * The consequence is CR-A. A DPDK blueprint holds a payload reference across an
 * interval in which mtp_tx_flush_and_notify may run, and there is no refcount
 * anywhere. §3 below is what replaces the kernel's page reference.
 */

/*============================================================================*
 * 2. The blueprint and its ring (DESIGN §2.5, §2.6, §4.2)
 *============================================================================*/

/*
 * A payload reference, RESOLVED at blueprint creation and dereferenced at the
 * drain. This is P1, and it is why the send buffer's lock is off the generation
 * path: the drain reads `data`, `len`, `wraps`, `wrap_at_seq` and `wrap_data`
 * out of the blueprint's own snapshot and never touches the stream's head,
 * tail, len or base. There is no field the drain reads that another thread can
 * be halfway through writing, so there is nothing for a lock to protect.
 *
 * `wraps` exists because the send buffer is a TRUE RING — mTCP re-linearises
 * with a memmove and this target does not, so a payload can straddle the end.
 * Carrying the wrap in the snapshot is what lets the emitter split the copy
 * without going back to the stream.
 */
typedef struct {
	const uint8_t	*data;
	uint32_t	 len;
	bool		 wraps;
	uint64_t	 wrap_at_seq;
	const uint8_t	*wrap_data;
} payref_t;

/*
 * Resolve [seq, seq+len) in a transmit unit. Exactly one copy of the two-branch
 * pointer computation that appears nine times across two of the prototype's
 * sibling branches — start already past the end (recompute near the base,
 * wraps = false), and start valid but payload runs off the end (wraps = true).
 *
 * Returns <0 AND LEAVES *out UNTOUCHED if the range is not wholly inside the
 * live range. Returning a plausible pointer near the base is precisely how the
 * out-of-bounds case in the sweep happens.
 */
/*
 * Initialise a transmit unit's storage.
 *
 * The capacity is a PARAMETER, not a global. The ring reading CONFIG was the
 * coupling: a byte ring has no business knowing a configuration system exists,
 * and the caller reading it makes the round-up-to-a-power-of-two decision
 * visible at the call site instead of buried three frames down.
 */
int tgt_tx_unit_init(struct mtp_data_unit *u, uint64_t size, uint32_t cap,
		     void (*drain)(void *), void *drain_arg);

/* The receive unit's base is a sequence number, not zero: the peer's ISN + 1.
 * Passing it here is the bridge, so nothing downstream has to convert. */
int tgt_rx_unit_init(struct mtp_data_unit *u, uint64_t size, uint32_t cap,
		     uint64_t base);

uint32_t tgt_tx_space(const struct mtp_data_unit *u);
int tgt_tx_ref(struct mtp_data_unit *u, uint64_t seq, uint32_t len,
	       payref_t *out);

/* Liveness ends here: called once per blueprint by the drain, after its LAST
 * segment has been copied into an mbuf. Not per segment.
 *
 * `base` names WHICH reference is being released. Release is by identity, not
 * by position, so no ordering between callers is required and a new release
 * site cannot reintroduce DESIGN.md §18's corruption. */
void tgt_tx_ref_release(struct mtp_data_unit *u, uint64_t base);

/* Debug only, on the assertion's failing path: print the blueprints of `owner`
 * with their segmentation progress. Lives in flow.c so tx_stream.c need not
 * reach into the flow's blueprint ring.
 *
 * WEAK, because the unit tests link tx_stream.c without flow.c and a debug
 * dump must not decide what a test binary contains. Absent, the call is
 * skipped and the rest of the dump still prints. */
__attribute__((weak)) void tgt_dump_flow_bps(void *owner, uint64_t base);

/* Debug only, on the same failing path: the PROGRAM's own terms for this flow.
 * The target prints none of them and interprets none of them -- it asks, the
 * program answers. Weak for the same reason as above. */
__attribute__((weak)) void prog_dump_flow_state(void *owner);

struct bp {
	/* The earliest byte this blueprint will transmit. Used for two things,
	 * both the target's own business: deriving each segment's offset, and
	 * clamping release (§3). Homa's offset and TCP's sequence number are the
	 * same monotone counter as far as those two uses go. */
	uint64_t	base_seq;

	payref_t	payload;
	struct mtp_data_unit *unit;	/* the payload's unit, so the drain can
					 * end the reference's liveness */

	uint16_t	seg_size;	/* 0 = do not segment */

	/* Coalescing. The target decides WHETHER two adjacent blueprints merge —
	 * it depends on batch boundaries, which are a target property. What a
	 * merged blueprint CONTAINS has to be the program's, or packet content
	 * is target-determined and the design law is broken. v4 has no way to
	 * declare that; until it does (CR-B) these come from a generated table
	 * and the gap is recorded rather than papered over.
	 *
	 * The axis is base_seq inheritance, not header age. The prototype's data
	 * merge keeps the older sequence and payload pointer and takes the NEWER
	 * ack, window and timestamp; building it the other way puts a stale
	 * cumulative ACK and a stale echo on every merged segment. */
	uint8_t		coalesce_class;	/* 0 = never merge */
	uint32_t	coalesce_key;	/* compared for equality only */
	bool		inherit_base;

	uint32_t	prio;		/* from pkt_gen, passed through to the outer header */
	uint32_t	offload;	/* non-zero: ask the NIC for the L4 sum */
	uint16_t	offload_csum_off; /* where the sum goes, from the program */

	uint16_t	hdr_len;
	uint8_t		hdr[PROG_HDR_MAX];

	/*
	 * Drain-time scratch. Lives in the blueprint rather than on the stack
	 * because a drain can stop half way — the transmit buffer fills — and
	 * has to resume at the same segment on the next iteration.
	 */
	uint32_t	seg_off;	/* bytes of payload already emitted */
	uint32_t	seg_idx;
	uint32_t	seg_count;
	uint8_t		prev_hdr_valid;
	uint16_t	prev_paylen;
	uint8_t		prev_hdr[PROG_HDR_MAX];
};

/*
 * LIFECYCLE. Allocate and commit do not compose by accident and getting it
 * wrong is a deadlock, not a leak:
 *
 *   - tgt_bp_new() returns a SCRATCH SLOT. Not in the ring, not drained, holds
 *     NO live payload reference. A processor that returns without committing
 *     abandons it and the next tgt_bp_new() reuses it.
 *   - tgt_bp_commit() is what makes a blueprint exist: it enters the ring, it
 *     becomes drainable, and its payload reference becomes LIVE.
 *   - liveness ENDS when the drain has copied the last byte into an mbuf.
 *   - two tgt_bp_new() with no commit between them is a contract violation and
 *     a debug build asserts. Not a silent overwrite.
 *
 * Counting allocations as live instead deadlocks: pending never falls, the
 * application-facing send window reaches zero, and the app thread blocks in
 * add_tx_data for ever.
 *
 * A blueprint with payload.len == 0 holds no reference, so a pure ACK carrying
 * a low counter does not pin a stream for no reason.
 *
 * tgt_bp_new() RETURNS NULL when the ring is full and every caller checks. The
 * prototype has twelve call sites and none checks, so a full ring is a null
 * dereference there; here the emitter declines and the flow stays schedulable.
 */
struct bp *tgt_bp_new(flow_t *f);
struct bp *tgt_bp_last(flow_t *f);
void       tgt_bp_commit(flow_t *f, struct bp *bp);

/*============================================================================*
 * 3. Payload lifetime — an ASSERTION, not a clamp
 *============================================================================*/
/*
 * N-A, answered by the lead 2026-08-12:
 *
 *   "The payload reference is referring to some part of the send buffer. It
 *    will stay valid until the program asks the target to flush the send buffer
 *    with the respective tx_flush_and_notify instruction."
 *
 * So the guarantee is PROGRAM-CONTROLLED. A reference handed to pkt_gen stays
 * valid until the program flushes that range, and the target must not move a
 * unit's head for any other reason — which ours does not, because the head
 * moves only on tx_flush_and_notify. This was never a language gap; we failed
 * to read it out of the language we had.
 *
 * The two targets satisfy it by different routes. The kernel resolves inside
 * pkt_gen and takes page refcounts, so the question never arises. We defer to a
 * batched drain, and THIS GUARANTEE IS WHAT MAKES THE DEFERRAL SAFE.
 *
 * WHAT THAT CHANGES. This was written as a mechanism: the target would silently
 * refuse to advance the head past the oldest live blueprint. Under the answer
 * above that is wrong, because it declines a tx_flush_and_notify the program
 * legitimately issued — and the program is ALWAYS legitimate here. Validity
 * ends when the program flushes; the program flushing IS what ends it. There is
 * no way for a program to be in violation and no program model enters into it.
 *
 * SO THE PROBLEM IS ENTIRELY OURS. Because we defer packet generation to a
 * batched drain, at the moment the program flushes we may still be holding that
 * reference in an undrained blueprint. WE NEED THE REFERENCE TO LIVE LONGER
 * THAN THE CONTRACT PROMISES. The kernel never meets this because the packet is
 * gone before pkt_gen returns.
 *
 * The fix is unchanged: before honouring a flush that would cross a live
 * reference, DRAIN. Nothing is declined, no instruction changes meaning, and
 * the cost is one forced early drain in a rare case — which does cut a
 * coalescing run short, so it goes on the list of things to count.
 *
 * What the bookkeeping is for, then, is not catching a bad program. It is
 * catching US: after the drain there must be no live reference into the flushed
 * range, and tgt_tx_assert_flushable() checks that our own drain-before-flush
 * actually ran. A firing assertion means a bug in this file, not in the .mtp.
 *
 * (An earlier version of this comment said the guarantee placed an obligation
 * on the program that the program could not discharge, because it cannot see
 * the ring. That was wrong and the lead caught it. It is worth leaving the
 * correction visible: the failure mode was turning "our implementation has a
 * problem" into "the abstraction has a gap", which is a flattering direction to
 * be wrong in and therefore one to check twice.)
 *
 * IS OUR PROGRAM ABLE TO TRIP IT? Analysed, not assumed — and the answer
 * differs by milestone, which is why it is written here rather than in a
 * commit message.
 *
 * A correct TCP program mostly cannot: it flushes up to send_una and references
 * from send_una onward, so the reference sits AT the head and a flush never
 * crosses it (C established this).
 *
 * The reachable case is a queued retransmission whose original is acknowledged
 * before the retransmission drains. Whether it is reachable turns entirely on
 * where retransmissions are generated relative to the receive burst:
 *
 *   M1: NOT REACHABLE. The only retransmission source is the RTO, and timers
 *       fire after the whole receive burst is processed and immediately before
 *       the drain (§4). No tx_flush_and_notify can run between the commit and
 *       the drain — the application thread appends, it does not flush.
 *
 *   M2: REACHABLE, as soon as fast retransmit lands. Three duplicate ACKs at
 *       packet k of a burst commit a retransmission blueprint; a cumulative ACK
 *       at packet k+1..63 of the SAME burst then covers that range and the ack
 *       processor flushes it. The blueprint is still in the ring. That is an
 *       ordinary reordering-recovery pattern, not a corner case.
 *
 * THE FIX IS TARGET-SIDE because the problem is target-side: the program did
 * nothing wrong by flushing a range it had acknowledged. We drain first.
 *
 * The test for it is named and specified and CANNOT RUN YET: there is no send
 * path in increment 1. It is the first test the send path owes.
 */

/*============================================================================*
 * 4. Scheduling (DESIGN §3)
 *============================================================================*/
/*
 * One gen_list per core; tgt_bp_commit enqueues the flow idempotently. A flow
 * with nothing to send is not on the list and is not walked — the prototype's
 * decision, preserved. mTCP's control/ACK/data triad, its rotation and its
 * break on the first blocked flow are not reproduced.
 *
 * When a flow cannot progress:
 *   - blocked by window or congestion: it never got a blueprint, so it is not
 *     on the list. Re-woken by an ack, an app write or a timer. Nothing spins.
 *   - TX mbufs exhausted: re-inserted at the HEAD, the partially consumed
 *     blueprint rewound, and the walk breaks so the burst can flush. From the
 *     prototype, and correct.
 *   - ring full: tgt_bp_new returns NULL, the program declines, the flow stays
 *     schedulable.
 */
void     TimerTick(uint32_t now);
uint64_t TimerFires(void);

void tgt_sched_enqueue(flow_t *f);
void tgt_drain(struct core_ctx *core);

#endif /* INTERNAL_H */
