#ifndef CONTRACT_H
#define CONTRACT_H
/*
 * THE CONTRACT — every symbol that crosses the target/program boundary, in
 * both directions, and nothing else.
 *
 * docs/DESIGN.md §2, approved at Checkpoint 2 (docs/DECISIONS.md D-08). This
 * header is that section written so a compiler can check it.
 *
 * The whole thing follows from one sentence (§2.1):
 *
 *     The target may know that a packet has a header, a payload and a length.
 *     It may not know what any header field means.
 *
 * Every place the prototype's boundary leaked is a place that sentence was
 * broken — a generation list that destroyed TIME_WAIT flows, a receive
 * dispatcher that read flag bits, a blueprint header with seven named options.
 * So: parsing, option handling, header serialisation, per-segment fixup and
 * checksums are all program-side symbols the target *calls*, and they are the
 * last five declarations in this file.
 *
 * Rule 4 lives here too. No name below may identify a protocol, and none does.
 * The only downward include in the tree is the one immediately following: the
 * compiler emits the program's sizes, the target allocates from them, and
 * rebuilding for another protocol is expected and allowed.
 *
 * src/program/ includes THIS FILE AND NOTHING ELSE from the target. There is no
 * ->sndbuf->head here, and that is the point: §2.4b's read accessors exist
 * because MTP has none, and their absence is what made the prototype reach past
 * the boundary in the first place.
 */
#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>	/* struct iphdr, for the checksum callback */

#include "prog_params.h"	/* PROG_*: the program's compile-time sizes */

/*============================================================================*
 * 1. The objects the two sides share
 *============================================================================*/

/* A flow — one context, in the paper's language. Opaque to the program: it
 * reaches its own per-flow state through TgtCtxState() and everything else
 * through an instruction. */
typedef struct flow flow_t;

/* A blueprint under construction. See §5 below for what is in one. */
typedef struct bp bp_t;

/* A handle to one byte stream of one flow. Not a pointer: a (flow, index)
 * pair, so that a context can declare however many streams its protocol needs
 * without a single instruction signature widening. That widening is exactly
 * what happened to the prototype when QUIC-Lite needed two (F7). */
typedef struct { flow_t *f; uint16_t idx; } bufid_t;

/* Milliseconds, from the one clock read per main-loop iteration. Both
 * references do it that way and it is parity-relevant, so every timestamp
 * within one iteration is the same number (§3.5). */
typedef uint32_t tick_t;

/*
 * The flow key is `flowkey_t`, and it is DEFINED BY THE PROGRAM, in the header
 * included above. The target names the type, stores it, hands it to the
 * program's hash and compare, and never reads a field or assumes a size.
 *
 * docs/DECISIONS.md D-11. C's B1: Homa keys on the four-tuple plus an RPC id,
 * and many concurrent RPCs share one four-tuple — that is the point of Homa. A
 * struct fixed in target source would have to grow a field for a protocol,
 * which is exactly the QUIC-Lite failure this design exists to avoid.
 *
 * The alternative considered and rejected was an opaque byte array with the
 * program supplying hash and compare through a pointer, which would have put an
 * indirect call on the receive path — the path §2.2 was optimising by cutting
 * four lookups to one. That trade was false. Which key a build uses varies per
 * protocol and is FIXED WITHIN a protocol, so it is a compile-time shape:
 * nothing has to be discovered while packets are arriving. Target source stays
 * identical across protocol builds, the generated header differs, and a TCP
 * build costs what mTCP costs.
 */

/*============================================================================*
 * 2. Events (§2.2)
 *============================================================================*/
/*
 * An event is a value, not an allocation: the program's parser writes into an
 * array the target supplies. PROG_EVENT_MAX is the program's, because only the
 * program knows how large its largest event is — and the target never looks
 * inside one. It carries the bytes back to ProgDispatch() untouched.
 */
typedef struct { uint8_t bytes[PROG_EVENT_MAX]; } ev_t;

/*============================================================================*
 * 3. Instructions — context lifecycle (§2.4a)
 *============================================================================*/

/*
 * Create a context. The program's per-flow state is PROG_CTX_SIZE bytes that
 * the target allocates AND ZEROES — G12. That gap is an implementation
 * artefact rather than a protocol difference, but it is the likeliest source of
 * run-to-run nondeterminism in the prototype, and zeroing here costs nothing.
 *
 * `size_class` is Homa's per-message sizing arriving early (F8b). One byte now
 * against a widened signature later.
 */
flow_t *TgtCtxNew(const flowkey_t *k, uint16_t nstreams_tx, uint16_t nstreams_rx,
		  uint8_t size_class);
void    TgtCtxDestroy(flow_t *f);
void   *TgtCtxState(flow_t *f);

/*
 * The program's state ABOVE the flow: PROG_GLOBAL_SIZE bytes per core,
 * allocated and zeroed by the target, opaque to it. Returns NULL when the
 * program declares no such state, which is TCP's answer and costs a build with
 * PROG_GLOBAL_SIZE == 0 exactly nothing.
 *
 * C's B2 and B4, and it turns out they are one thing. Homa's grant scheduler is
 * a host-wide byte budget and a cross-flow ranking, and its grant round is a
 * state machine spread over up to nine packet arrivals for different flows.
 * Neither fits in a per-flow context or a per-packet scratchpad — but neither
 * needs a new lifetime either, because Homa's own implementation already keeps
 * both in one header of file-scope statics, round state included.
 *
 * Why the target hands it out rather than the program declaring a static: a
 * static is shared by every stack thread, which is wrong the moment there is
 * more than one core, and memory is the target's under §2.8 rule 1. Per core,
 * shared-nothing, like everything else here.
 *
 * This also answers the objection to J2 — that a declarable epilogue is only
 * useful if it can carry state across packets. It can; this is where.
 */
void   *TgtGlobalState(void);

/*============================================================================*
 * 4. Instructions — byte streams (§2.4b)
 *============================================================================*/
/*
 * The abstraction that failed in both directions in the prototype's siblings:
 * QUIC-Lite hard-wired two buffers and widened the target's signatures with a
 * stream id; Homa replaced the pair with a buffer-manager pointer. Both are the
 * same failure — the buffer was a *field of the flow*, so a protocol wanting a
 * different number or kind of buffer had to change the target. Here a context
 * declares how many it has and nothing else moves. (J5; never been built.)
 */

/* --- write side: the paper's data instructions --------------------------- */
bufid_t TgtTxNew(flow_t *f, uint64_t base_seq, uint8_t size_class);
int     TgtTxAppend(bufid_t b, const void *src, uint32_t len);	/* app thread */
void    TgtTxRelease(bufid_t b, uint64_t upto);
bufid_t TgtRxNew(flow_t *f, uint64_t base_seq, uint8_t size_class);
int     TgtRxPut(bufid_t b, uint64_t seq, const void *src, uint32_t len);
int     TgtRxDeliver(bufid_t b, void *dst, uint32_t len);	/* app thread */

/* --- read side: MTP has none, and that hole is why the prototype leaked --- */
/*
 * Not an optional addition. Every send decision needs to know how many bytes
 * are buffered and unsent; every window advertisement needs to know how full
 * the receive buffer is. With no way to ask, reaching into sndvar->sndbuf->len
 * was the only option, and once that was done the write-side instructions were
 * dead weight. So these six are the precondition for the data instructions
 * being usable at all.
 */
uint64_t TgtTxBase(bufid_t b);		/* first unreleased sequence */
uint32_t TgtTxPending(bufid_t b);	/* buffered bytes */
uint64_t TgtRxBase(bufid_t b);		/* sequence of the stream's first byte */
uint64_t TgtRxContigEnd(bufid_t b);	/* end of the in-order prefix */
uint64_t TgtRxDelivered(bufid_t b);	/* what the application has taken */
uint32_t TgtRxCapacity(bufid_t b);
uint32_t TgtRxFree(bufid_t b);		/* capacity - (contig_end - delivered) */
/*
 * TgtRxBase() is here because TgtRxContigEnd() alone is not enough (C's B8).
 * A protocol whose completion test is "have I received the whole message" needs
 * the LENGTH of the in-order prefix, and the two differ by the stream's base —
 * which for Homa is the offset of the first packet to arrive, not zero. The
 * write side had TgtTxBase() and the read side did not, and the asymmetry would
 * have pushed the program back into target internals, which is exactly how the
 * prototype's data instructions died.
 *
 * TgtRxFree() is NOT the advertised window, and a processor that answers every
 * packet with it will diverge from the donor in the first RTT of every
 * connection (§7.2). The donor holds the window as a per-flow variable
 * initialised to a constant and recomputes it from the buffer at exactly two
 * moments. That rule is the program's; this query is only how it asks.
 */

/*
 * Resolve [seq, seq+len) in a transmit stream to a payload reference (§4.2
 * piece 5 — nine copies of this pointer arithmetic across two of the
 * prototype's siblings become this one call).
 *
 * Returns 0 on success. Returns <0 AND LEAVES *out UNTOUCHED if the range is
 * not wholly inside the live range: that is a program error, not something to
 * paper over. Returning a plausible pointer near the base is precisely how the
 * out-of-bounds case in the sweep happens. A debug build asserts.
 */
typedef struct {
	const uint8_t *data;
	uint32_t       len;
	bool           wraps;		/* the ring is a true ring: no memmove */
	uint64_t       wrap_at_seq;
	const uint8_t *wrap_data;
} payref_t;

int TgtTxRef(bufid_t b, uint64_t seq, uint32_t len, payref_t *out);

/*
 * LOCKING (J9) — stated here because a reader of an accessor above cannot see
 * that it is protected and must be told where the protection lives.
 *
 * NONE of the accessors lock. The target acquires a stream's lock lazily on
 * first access within a dispatch and releases it when the dispatch ends: at
 * most one acquire/release pair per stream per packet. Fewer than the
 * prototype's two per received ACK, and fewer than the donor's.
 *
 * The cost is that the lock is held across a whole event list rather than
 * around each touch, so the application thread can block for the duration of
 * one chain. That is the same shape as the donor holding write_lock across a
 * window of packets, so it is not a regression — but that it does not show is a
 * HYPOTHESIS, and time-in-lock is counted from the first measured run.
 *
 * Making the accessors lock instead would be the mistake, and it is worth being
 * precise about why: the cost driver is the number of lock transitions per
 * packet, which is a target scheduling decision. A boundary of six accessors
 * costs what one direct reach costs, provided the target owns the acquire.
 */

/*============================================================================*
 * 5. Instructions — packet generation (§2.4c, §2.5)
 *============================================================================*/

struct bp {
	/* Sequence of payload byte 0. Target-visible ONLY as an opaque monotone
	 * counter, used for exactly two things that are the target's own
	 * business: deriving each segment's offset within the blueprint, and
	 * clamping byte-stream release. Homa's offset and TCP's sequence number
	 * are the same counter as far as those two uses go. */
	uint64_t  base_seq;

	payref_t  payload;

	uint16_t  seg_size;		/* 0 = do not segment */
	uint8_t   seg_rule_group;	/* which fixup rule the segments take */

	/* Coalescing (§2.6, J3). The target decides WHETHER two adjacent
	 * blueprints merge — it depends on batch boundaries, which are a target
	 * property and cannot be otherwise. The program decides WHAT a merged
	 * blueprint contains, by declaring the class. 0 = never merge.
	 * `coalesce_key` is compared for equality and never interpreted. */
	uint8_t   coalesce_class;
	uint32_t  coalesce_key;

	/*
	 * A per-packet class for the OUTER header — the one below the
	 * transport, which the program does not serialise and cannot reach.
	 * Handed to the infrastructure as-is and written to the IP TOS byte;
	 * zero means "as the donor does it", which is what TCP wants.
	 *
	 * C's B10. Homa is a priority-queueing protocol and its priority is per
	 * packet, decided by the grant. §2.1's principle covers the L4 header
	 * via the opaque image below, but the TOS byte is in the IP header,
	 * which is infrastructure, so there was no route at all from a program
	 * decision to the wire. The prototype's Homa branch cut that route by
	 * adding `uint8_t prio` to the blueprint and IPOutputWTos to the IP
	 * layer — protocol-shaped holes with protocol-neutral names, which is
	 * the class of leak no name grep will ever catch.
	 *
	 * One byte, no parsing, and a DSCP value is not a protocol name.
	 */
	uint8_t   outer_class;

	/* The header, as an opaque image the program already serialised. Not a
	 * struct with named fields and not an option API: those are the two
	 * things that did not survive Homa in the prototype's design. */
	uint16_t  hdr_len;
	uint8_t   hdr[PROG_HDR_MAX];
};

/*
 * LIFECYCLE — allocate and commit do not compose by accident, and getting this
 * wrong is a deadlock, not a leak. Stated exactly (§2.4c):
 *
 *   - TgtBpNew() returns a SCRATCH SLOT. It is not in the ring, it is not
 *     drained, and it holds NO live payload reference. A processor that
 *     returns without committing simply abandons it and the next TgtBpNew()
 *     reuses it.
 *   - TgtBpCommit() is what makes a blueprint exist: it enters the ring, it
 *     becomes drainable, and its payload reference becomes LIVE for the
 *     release clamp.
 *   - Liveness ENDS when the drain has copied the blueprint's last byte into
 *     an mbuf.
 *   - Two TgtBpNew() calls with no commit between them is a contract
 *     violation, and a debug build asserts. It is not a silent overwrite.
 *
 * Counting allocations as live instead would deadlock: pending never falls, the
 * application-facing send window reaches zero, and the application thread
 * blocks in TgtTxAppend() for ever.
 *
 * A blueprint whose payload.len == 0 holds no reference at all, so a pure
 * acknowledgement carrying a low counter does not pin a stream for no reason.
 *
 * TgtBpNew() RETURNS NULL when the ring is full, and every caller checks it.
 * The prototype has twelve call sites and not one checks, so a full ring is a
 * null dereference there. Here the program declines to emit and the flow stays
 * schedulable.
 *
 * `f` NEED NOT BE THE FLOW BEING DISPATCHED. C's B9: Homa processes a packet
 * belonging to one RPC and emits a grant addressed to another, chosen by its
 * scheduler. The prototype's Homa branch did this by smuggling a flow pointer
 * INTO the blueprint — `struct tcp_stream *cur_stream`, with the comment
 * "TODO: make this more elegant" — and having the target dereference it. No new
 * instruction is needed here: TgtBpNew() and TgtBpCommit() already name the
 * flow, and the commit schedules the flow it names, which is the one that has
 * to be scheduled. What was missing was anyone saying so, so it is said.
 *
 * Two consequences, both real:
 *   - the release clamp tracks liveness PER STREAM, not per flow-ring, so a
 *     blueprint built while dispatching X still pins Y's head;
 *   - the lock a dispatch holds is per stream, so touching a second flow's
 *     stream takes a second lock. That is a second acquire per dispatch for a
 *     protocol that does this, and it is worth counting when one exists.
 *
 * TgtBpNewGlobal() remains the no-context form, for a packet answering a flow
 * that does not exist (F8a, G4). "Global" meant "any flow" in the prototype;
 * here it means "no flow", and the two are now separate.
 */
bp_t *TgtBpNew(flow_t *f);
bp_t *TgtBpLast(flow_t *f);		/* the coalescing candidate, or NULL */
void  TgtBpCommit(flow_t *f, bp_t *bp);	/* seals it; schedules the flow (P5) */
bp_t *TgtBpNewGlobal(void);		/* per-core ring, no flow (F8a, G4) */

/*============================================================================*
 * 6. Instructions — timers (§2.4d) and notification (§2.4e)
 *============================================================================*/
/*
 * Timer ids are program-declared and the target keeps PROG_TIMER_COUNT slots
 * per flow. One per-core hashed wheel holds them all, so nothing assumes that
 * arm order is expiry order — which is false for a retransmission timer under
 * backoff, and is the ordering bug the prototype's per-timer lists carry.
 */
void TgtTimerStart(flow_t *f, uint8_t id, uint32_t ticks);
void TgtTimerRestart(flow_t *f, uint8_t id, uint32_t ticks);
void TgtTimerCancel(flow_t *f, uint8_t id);

/*
 * Typed, because mTCP raises three distinct kinds of readiness and whether the
 * subscription is level- or edge-triggered decides which of them fires. MTP's
 * single notify(msg) loses that distinction.
 */
typedef enum {
	NOTIFY_READY_READ,
	NOTIFY_READY_WRITE,
	NOTIFY_ERROR,
	NOTIFY_ACCEPTABLE,
} notify_kind_t;

void TgtNotify(flow_t *f, notify_kind_t k);

/*============================================================================*
 * 7. The other direction — the five symbols the compiler emits (§2.8 rule 4)
 *============================================================================*/
/*
 * The target calls into the program through these and nothing else. They are
 * declared here and nowhere else, so the set is countable — and the count has
 * grown from the design's five to seven, because the flow key became the
 * program's (D-11) and brought its hash and compare with it. Countable is the
 * property that matters; five was never the property.
 */

/*
 * Parse one L4 payload into events. Writes at most `max` events and the flow
 * key; returns the number written, or <0 to drop.
 *
 * Two defects in the prototype's parser must not reappear here, recorded
 * because moving the parser into the program is exactly what makes them easy to
 * re-create: its receive-option struct is an uninitialised stack local and its
 * extractor only ever sets valid=TRUE, so an ABSENT option reads stack garbage;
 * and the end-of-option-list kind falls into a default branch that moves the
 * index backwards and does not terminate. Both get a unit test before a packet
 * is parsed on hardware.
 */
int ProgParse(const uint8_t *l4, uint16_t len, flowkey_t *key,
	      ev_t *out, int max);

/*
 * Run one packet's event list to completion against one flow. `f` is NULL when
 * the flow lookup missed and the program declared the event class as one that
 * may run without a context — the only processors that may then emit, and only
 * through TgtBpNewGlobal().
 *
 * The scratchpad's lifetime is this whole list, not one event (J2), so that
 * once-per-packet work — validation, timeout-list refresh, acknowledgement
 * accounting — has one home instead of being duplicated per event.
 *
 * Two things the design left unsaid, and C found both by writing Homa against
 * it:
 *
 *   - THE PROGRAM MAY HOLD A flow_t, for the duration of one dispatch, and pass
 *     it between processors in the same chain — in the scratchpad, or as an
 *     argument. §2.8 rule 1 says the program never allocates and never frees;
 *     it does not forbid holding. Homa needs it: the processor that creates a
 *     context is not the one that registers it (C's B5). A held flow_t is valid
 *     until the dispatch returns, and no longer.
 *
 *   - THE PROGRAM MAY ROUTE INTERNALLY. Homa picks among three chains partly on
 *     per-flow state that only the program can read, and ProgParse() sees the
 *     packet alone (C's B6). So chain selection is inside this call, which is
 *     what a compiler would emit anyway.
 */
void ProgDispatch(flow_t *f, tick_t now, const ev_t *evs, int n);

/*
 * Patch one segment's header image in place, during the drain. For TCP this
 * writes a sequence number and sometimes clears a flag: a handful of stores.
 * For Homa it writes an offset. The target's source contains no field name.
 *
 * Costs one indirect call per transmitted packet, which at -O0 is a real call.
 * That it does not show is a HYPOTHESIS. The rejected alternative is a
 * declarative patch table the target interprets — fewer calls, but then the
 * target contains a small interpreter for header layouts, which is knowledge
 * about packet shape creeping back in. If this measures badly the patch table
 * is the fallback and the change is local to the emitter.
 */
void ProgSegFixup(uint8_t *hdr, uint16_t hdr_len, uint8_t seg_rule_group,
		  uint32_t seg_index, uint64_t seg_base_seq, uint16_t seg_len);

/*
 * Checksums are program-side because a pseudo-header layout is protocol
 * knowledge — and because `#define TCP_CALCULATE_CHECKSUM` in target source is
 * the rule-4 violation the reference tree actually has.
 *
 * ProgCsumOffloadKind() names what the NIC should be asked to do, in the
 * infrastructure's own vocabulary (PKT_TX_*), so the target can hand it to the
 * PMD without knowing what is being summed.
 */
int ProgCsumVerify(const struct iphdr *iph, const uint8_t *l4, uint16_t len);
int ProgCsumOffloadKind(void);

/*
 * Hash and compare for the program's flow key. Direct calls to generated
 * symbols, not pointers: mTCP's own flow table calls HashFlow and EqualFlow the
 * same way, so this is the donor's cost and not a new one.
 *
 * Note this makes SEVEN generated symbols where §2.8 rule 4 says five. The
 * count in the design was written before the key became the program's.
 */
unsigned int ProgKeyHash(const flowkey_t *k);
int          ProgKeyEqual(const flowkey_t *a, const flowkey_t *b);

/*============================================================================*
 * 8. The absence register — what is missing, and whose problem it is
 *============================================================================*/
/*
 * MTP is positive-only: a program can say what it does and cannot say what it
 * does not. The one rule this effort runs under turns on exactly that — "if one
 * stack is missing a mechanism the other has, the two are not running the same
 * protocol" — so a contract that cannot be audited against a checklist cannot
 * be used to check that rule by inspection. This is the checklist, for the
 * contract itself.
 *
 * All of it comes from C writing Homa's MTP program against this file
 * (docs/DECISIONS.md D-09; docs/phase-d/programs/homa.mtp.notes.md). C's
 * headline was "the contract survives the packet layer and not the scheduler".
 *
 * That reading is now revised, and the revision matters:
 *
 *     IF SOMETHING VARIES PER PROTOCOL BUT IS FIXED WITHIN A PROTOCOL, IT IS A
 *     COMPILE-TIME SHAPE, NOT A RUNTIME DECISION. REACH FOR GENERATION BEFORE
 *     INDIRECTION.
 *
 * The charter licensed this all along — rule 4 says rebuilding everything per
 * protocol is expected, and the test is a diff of target source between two
 * protocol builds, not a shared binary — and the paper says the same for the
 * XDP target, where the compiler generates the parser and the dispatcher rather
 * than the target branching at runtime.
 *
 * Applying it to C's five, one at a time and checked rather than assumed:
 *
 * ---- dissolved: compile-time shapes, and the contract now carries them ------
 *
 *   B1  the flow key. CLOSED, D-11. Program-defined type, compiled in, no
 *       indirection, target source unchanged across builds. See §1 above.
 *
 *   B2  state above the flow. CLOSED by TgtGlobalState() (§3 above), which is
 *       two lines and exactly parallel to TgtCtxState. Whether a protocol has
 *       cross-flow state, and how much, is fixed per protocol.
 *
 *   B4  the decision round that outlives the packet. CLOSED, and it turned out
 *       not to need a third scratchpad lifetime at all: Homa's own round state
 *       (MTP_granting_idx, MTP_finish_grant_choose) already sits among its
 *       file-scope globals, so B4 is B2 wearing a second hat. Checked against
 *       C's citations rather than assumed.
 *
 * ---- dissolved: a COMPILER gap, and no contract change at all ---------------
 *
 *   B3  ordered collections. Which indices a protocol keeps is fixed per
 *       protocol, and a generated index lives entirely in the program,
 *       operating on the program's own state. The target needs nothing — the
 *       reason it looked like a contract problem is that Homa's implementation
 *       had no other option than an ad-hoc target instruction (CreateHomaCtx),
 *       which is a missing language feature, not a missing instruction.
 *
 *       One thing the contract does owe it, and now states: the program owns
 *       context destruction (§2.8 rule 2), so a program-held index can be
 *       maintained without the target destroying a flow out from under it. That
 *       is what makes a program-side collection of flow_t safe, together with
 *       the rule in §7 that a program may hold a flow_t.
 *
 * ---- NOT dissolved: genuine holes, and generation does not reach them -------
 *
 *   B11 transmit ordering. The POLICY is fixed per protocol — TCP FIFO, Homa
 *       SRPT — so the declaration is a shape. The MECHANISM is not reached by
 *       that, because the ordered structure is the target's own (§3.2's
 *       gen_list) and rule 4 requires target SOURCE to be identical across
 *       builds. So the choices are: always use an ordered structure and key it
 *       from the program, which makes TCP pay for an insert it does not need on
 *       a path parity is measured on; or generate part of the scheduler, which
 *       moves the target/program boundary rather than filling a hole in it.
 *       A design question, still open, and not an omission to patch.
 *       (Homa's own tree wants SRPT and does not implement it, so nothing is
 *       blocked on it today.)
 *
 *   B7  a socket owning many flows. The count is a shape and could be
 *       generated. What cannot be is the application-facing half: Homa needs
 *       mtcp_epoll_wait to say WHICH flow, and its branch grew a fifth
 *       parameter on AddEpollEvent to do it. The applications are the donor's,
 *       unmodified, because rule 1 says the workload must be the same workload
 *       — so this is where protocol independence and parity pull against each
 *       other directly. Neither generation nor an instruction resolves that;
 *       a decision does.
 *
 *   B9  a blueprint addressed to a different flow than the one being
 *       dispatched. Genuinely dynamic within one protocol — the flow is chosen
 *       by the scheduler at runtime, so it is a value and not a shape. Handled,
 *       in §5 above.
 *
 * So the position is: of C's five scheduler breakages, three are compile-time
 * shapes (two now closed in this file, one purely the compiler's), and two are
 * real. "The contract does not survive the scheduler" is closer to "the
 * COMPILER does not exist yet", which is a much better place to be and is what
 * the paper claims.
 *
 * Limits of the evidence, so nobody reads a clean result where there is no
 * test: the Homa branch C read has no timers, no retransmission and no pacer,
 * and it never coalesces. So §3.5's timing wheel and §2.6's merge semantics are
 * untested by it, and anything about loss response is untested by it. And none
 * of the above has been compiled for a second protocol, which is the only test
 * rule 4 actually specifies.
 */

#endif /* CONTRACT_H */
