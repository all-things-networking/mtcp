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
#include "infra.h"
#include "prog_params.h"	/* PROG_HDR_MAX — the ring is sized from the program's
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
int tgt_tx_ref(struct mtp_data_unit *u, uint64_t seq, uint32_t len,
	       payref_t *out);

struct bp {
	/* The earliest byte this blueprint will transmit. Used for two things,
	 * both the target's own business: deriving each segment's offset, and
	 * clamping release (§3). Homa's offset and TCP's sequence number are the
	 * same monotone counter as far as those two uses go. */
	uint64_t	base_seq;

	payref_t	payload;

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
	uint32_t	offload;

	uint16_t	hdr_len;
	uint8_t		hdr[PROG_HDR_MAX];
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
 * 3. The release clamp — what replaces the kernel's page refcount
 *============================================================================*/
/*
 * mTCP is safe not because of its buffer but because NO POINTER INTO THE BUFFER
 * OUTLIVES A LOCK HOLD: it re-derives the pointer and copies from it inside one
 * hold of write_lock. P1 takes the lock off the generation path, so that
 * property has to be REPLACED rather than re-added. Three things together do
 * it:
 *
 *   1. the drain reads nothing but the blueprint's own snapshot (P1, above);
 *   2. bytes never move — the true ring removes the memmove;
 *   3. RELEASE-CLAMPING: mtp_tx_flush_and_notify will not advance a unit's head
 *      past the oldest live blueprint that references it, where live means
 *      committed and not yet fully drained, and where a zero-length payload
 *      holds no reference.
 *
 * The kernel gets the same guarantee for free because its payload reference is
 * a page refcount taken inside pkt_gen. Ours has to be enforced, because our
 * reference is a raw pointer into a ring whose head moves. Same invariant, two
 * realisations — which is the argument for CR-A: the contract states neither,
 * and a program cannot tell the difference, but a target that assumed the
 * kernel's discipline and deferred like ours would corrupt payloads.
 *
 * Liveness is tracked PER UNIT, not per flow-ring, so a blueprint built while
 * dispatching one flow still pins the unit of the flow it names.
 *
 * The clamp records a counter and a debug build asserts it did not bite. If it
 * bites regularly the program is releasing too eagerly, and that is worth
 * knowing rather than hiding.
 */
uint64_t tgt_clamp_count(void);

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
void tgt_sched_enqueue(flow_t *f);
void tgt_drain(struct core_ctx *core);

#endif /* INTERNAL_H */
