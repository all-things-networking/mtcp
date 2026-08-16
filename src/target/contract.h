#ifndef CONTRACT_H
#define CONTRACT_H
/*
 * THE CONTRACT — the MTP instruction set as a program sees it, and the symbols
 * the compiler emits. Nothing else.
 *
 * ===========================================================================
 *  CONFORMS TO MTP CONTRACT v4 — minmit/MTP-kernel-test @0699822f
 *  docs/MTP_LANG.md (FROZEN v4) and docs/CONTRACT_CHANGES.md (CR-1..CR-7).
 *  docs/DECISIONS.md D-15, D-16.
 * ===========================================================================
 *
 * The paper claims ONE compiler front-end with two code-generation back-ends.
 * One front-end means one language, so this file is not a design of ours — it
 * is the v4 language rendered in the types this target uses. Where we had
 * invented a parallel dialect (our own key declaration, our own timer ids, our
 * own priority field, our own dispatch entry point, our own context block), the
 * dialect is gone and v4's form is here.
 *
 * WHAT THIS FILE IS NOT. It is not how any of it is realised. The kernel target
 * stays close to its donor, Linux; this one stays close to ours, mTCP, and rule
 * 1 makes that mandatory rather than a preference. So the operand types below
 * are ours, and everything about buffering, merging, draining and transmitting
 * lives in internal.h, which no program includes and no program can see.
 *
 * THE TEST, when it is not obvious which side something belongs on:
 *
 *     DOES A .mtp PROGRAM SEE IT?
 *     Yes -> here, and it conforms.  No -> internal.h, and it is ours.
 *
 * src/program/ includes THIS FILE AND NOTHING ELSE from the target.
 */
#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>

#include "prog_types.h"		/* compiler output: the flow id, context, events */

/* The target's handle for one flow. Opaque to the program, which obtains it
 * from get_flow_id()/the context and passes it back. */
typedef struct flow flow_t;

/*============================================================================*
 * 1. Data units (MTP_LANG §2, §8; CONTRACT_CHANGES Q3)
 *============================================================================*/
/*
 * One in-order data unit, TX or RX. The generalisation of TCP's single byte
 * stream: TCP declares one of each per flow with size == MTP_SIZE_INF, Homa one
 * per message with size == the message length, QUIC one per stream. The SAME
 * instruction serves all three, parameterised by `size` as data.
 *
 * That is the paper's form and v4's, and it is strictly better than the
 * handle-plus-index scheme we had invented: a unit handle is embedded in the
 * COMPILER-GENERATED context, so a context has exactly as many as its protocol
 * needs and no target signature ever widens. This is what dissolves F7 — the
 * abstraction that failed in both directions in the prototype's siblings —
 * without a `bufid_t` and without a stream count on context creation.
 *
 * The fields here are the unit's logical extent. How the bytes are actually
 * held is internal.h's business and is where this target differs from the
 * kernel's most.
 */
#define MTP_SIZE_INF	(~0ULL)		/* unbounded byte stream */

/*
 * A COMPLETE type, and the generated context embeds one by value (D-19). CR-3's
 * context store assumes that — the kernel target's `mtp_data_unit.h` is a
 * public struct and its generated context declares `struct mtp_data_unit tx;`
 * — and declaring it opaque here forced the program to hold a pointer to
 * storage no instruction allocates. The initialiser initialises; it does not
 * allocate.
 *
 * ONLY THE BOUNDARY CONFORMS. The FIELDS BELOW ARE OURS and are not the kernel
 * target's: it holds an sk_buff_head and an rb_root because that suits Linux;
 * this holds a true ring because that is the donor's shape and what §7.2's
 * numbers rest on. Two targets, one boundary, different realisations — do not
 * "conform" the contents to the kernel's, they are not contract.
 *
 * The program may not read or write a field of this struct. It is complete so
 * the context can embed it, not so the program can reach into it; access is
 * through the instructions and nothing else, and tools/check_wiring.sh enforces
 * that on src/program/.
 */
#define MTP_MAX_LIVE_REFS	64	/* == the blueprint ring depth */

/* Power of two: the log wraps and keeps the most recent events. */
#define MTP_REF_LOG	32

enum ref_site {
	REF_SITE_COMMIT,	/* pkt_gen taking a reference for a new blueprint */
	REF_SITE_MERGE_TAKE,	/* coalescing taking the wider reference */
	REF_SITE_MERGE_REL,	/* coalescing dropping the superseded one */
	REF_SITE_DRAIN_REL,	/* the drain, after a blueprint's last segment */
	REF_SITE__N
};

struct mtp_data_unit {
	uint8_t		*buf;
	uint32_t	 cap;		/* a power of two: the ring's wrap mask */
	uint64_t	 size;		/* MTP_SIZE_INF, or a message length */

	uint64_t	 head_seq;	/* first byte still held */
	uint64_t	 tail_seq;	/* one past the last byte held */

	/* Bases of every committed-and-undrained blueprint referencing this
	 * unit — internal.h §3. UNORDERED, and a multiset: entries may repeat,
	 * and nothing reads a position. The head/tail pair that used to index
	 * this is gone with the bug it caused (DESIGN.md §18); the minimum is
	 * computed on demand instead of being tracked. */
	uint64_t	 ref_base[MTP_MAX_LIVE_REFS];
	uint32_t	 live_refs;

	/*
	 * REFERENCE HISTORY -- the missing observable.
	 *
	 * Five fault dumps have shown the STATE at the moment of failure and
	 * none has shown the SEQUENCE that produced it. Two invariants hold
	 * across all five and neither has narrowed anything: the oldest live
	 * reference sits exactly at head_seq, and the unit is within a few KB
	 * of full. Neither says how the reference got there.
	 *
	 * Every take and every release is recorded here in order, with the
	 * base, the blueprint and the call site. Two stores on paths that
	 * already do more than that, and nothing at all until the fault fires.
	 */
	struct ref_event {
		uint64_t base;
		uint32_t len;		/* so RANGES are visible, not inferred */
		const void *bp;
		uint8_t	 op;		/* 0 = take, 1 = release */
		uint8_t	 site;		/* enum ref_site */
		uint32_t live_after;
		/*
		 * WHO issued the pkt_gen, as a return address -- resolved with
		 * addr2line rather than threaded through the contract as a
		 * parameter. "What overlaps" was in the history already; "who
		 * committed them" is one field away.
		 */
		const void *caller;
	}		 ref_log[MTP_REF_LOG];
	uint32_t	 ref_log_n;	/* total events; & (MTP_REF_LOG-1) indexes */

	/*
	 * THE HIGHEST STREAM POSITION ACTUALLY PUT ON THE WIRE.
	 *
	 * Distinct from the program's send_next, which advances when a
	 * blueprint is GENERATED rather than when it is EMITTED -- so send_next
	 * runs ahead of the wire by the undrained backlog. Any guard that
	 * compares an acknowledgement against send_next cannot see an
	 * acknowledgement that is past the wire but short of send_next, which
	 * is exactly the case in question.
	 */
	uint64_t	 emitted_hwm;

	/*
	 * SPSC OWNERSHIP, CHECKED RATHER THAN INTENDED (DESIGN.md §21.7).
	 *
	 * NOT debug-only. The configuration we measure is the configuration
	 * that must carry the check: a check absent from the build that
	 * produces numbers turns "we replaced a lock with a check" into "we
	 * removed a lock", in the only build that runs at load and so the only
	 * one where a wrong-thread write would first appear.
	 *
	 * We use head_seq/tail_seq as an ownership boundary instead of the
	 * donor's per-stream spinlock, which is correct ONLY while each index
	 * has exactly one writer: the application advances the tail, the stack
	 * advances the head, and nothing else writes either.
	 *
	 * That is true today by grep -- one write site each, one caller each,
	 * retransmission read-only, and no compaction anywhere. It is not
	 * enforced by anything, and it is precisely the class of invariant this
	 * project has been bleeding from. First writer records itself; every
	 * later write asserts it is the same thread. A path added later that
	 * violates the precondition fails loudly instead of corrupting a
	 * stream, which is the whole argument for diverging from the lock.
	 */
	uint64_t	 w_tail_tid, w_head_tid;

	/* How the unit forces a drain when a flush would cross a live
	 * reference (internal.h §3). A callback rather than a reach into the
	 * per-core state, so the ring depends on nothing above it — which is
	 * also what lets it be tested without a NIC. */
	void		(*drain)(void *arg);
	void		 *drain_arg;
	uint8_t		 established;	/* receive side: the base is known */

	/*
	 * Transmit side, for WRITABLE. `owner` is the flow this unit belongs
	 * to, so a short write can name the flow that must be woken; the
	 * program never sees either field, as it never sees any field here.
	 */
	void		*owner;
	uint8_t		 want_space;	/* a write was refused or truncated */
};

/* A reference to application data to be transmitted. The kernel target uses an
 * iov_iter because that is what its socket layer already carries; ours is a
 * plain extent, because mTCP's write path is a copy into the send buffer. */
struct mtp_tx_addr {
	const void	*base;
	uint32_t	 len;
};

/* A reference to received payload. In the kernel this is {skb, off}; here it
 * points into the receive burst's mbuf and is valid until dispatch returns. */
struct mtp_rx_addr {
	const uint8_t	*data;
	uint32_t	 len;
};

/* data(uid, off, len) — the payload a pkt_gen draws from a TX unit. A HANDLE
 * AND A RANGE, not a resolved pointer: resolution is the target's business and
 * the two targets do it at different moments. See CR-A in the conflict report. */
struct mtp_tx_payload {
	struct mtp_data_unit	*u;
	uint64_t		 off;
	uint32_t		 len;
};

void mtp_new_tx_ordered_data(struct mtp_data_unit *u, uint64_t size);
int  mtp_add_tx_data(struct mtp_data_unit *u, struct mtp_tx_addr addr, uint32_t len);
int  mtp_tx_flush_and_notify(struct mtp_data_unit *u, uint32_t len);

void mtp_new_rx_ordered_data(struct mtp_data_unit *u, uint64_t size);
int  mtp_add_rx_data_seg(struct mtp_data_unit *u, struct mtp_rx_addr addr,
			 uint32_t len, uint64_t offset);
/*
 * Deliver the next `len` in-order bytes to the application and notify.
 * RETURNS THE BYTE COUNT ACTUALLY DELIVERED, which is load-bearing: it is the
 * only way a program learns that the application drained, and §7.2's
 * advertised-window rule is written on it. See prog_params.h.
 */
int  mtp_rx_flush_and_notify(struct mtp_data_unit *u, uint32_t len,
			     struct mtp_rx_addr addr);

/*
 * WE HAD A READ SIDE HERE AND IT IS WITHDRAWN.
 *
 * Seven accessors — tx_base, tx_pending, rx_base, rx_contig_end, rx_delivered,
 * rx_capacity, rx_free — argued for at length on the grounds that MTP's lack of
 * one is what killed the prototype's data instructions. The kernel's tcp.mtp
 * needs none of them: it keeps send_una, send_next, write_end, recv_next and
 * the window in its own context and mirrors the byte counts as it issues
 * instructions. A working program demonstrating the need away is better
 * evidence than our reasoning for it, so the reasoning was wrong.
 *
 * Withdrawing them also removes J9 entirely. No accessors, no question about
 * where a stream lock is taken, no "one acquire per dispatch", no time-in-lock
 * counter. The cheapest thing in the design turned out to be the thing that
 * did not need to exist.
 */

/*============================================================================*
 * 2. Packet generation (MTP_LANG §5, §8)
 *============================================================================*/
/*
 * Generate and transmit packet(s).
 *
 *   hdr/hdr_len : the transport header, already filled by generated code from
 *                 its typed `pkt_bp` blueprint. The target sees BYTES. There is
 *                 no runtime blueprint type, no named header field and no
 *                 option API — those are the three things that did not survive
 *                 Homa in the prototype's design.
 *   payload     : data(unit, off, len).
 *   mss         : split threshold; a payload longer than this is segmented.
 *   prio        : scheduling hint. DATA, not protocol identity — and the reason
 *                 the `outer_class` byte we added for Homa's per-packet
 *                 priority is gone: v4 has had `prio` since v1.
 *   offload     : checksum/segmentation offload requests, set by the compiler
 *                 from the blueprint's `checksum16_t` fields, in place of a
 *                 runtime computed-field interpreter.
 *
 * SEMANTICS A PROGRAM MAY RELY ON: the packet will be transmitted, its payload
 * will be the bytes at [off, off+len) of the unit as they stand when this is
 * called, and segments will carry the fields the seg rules assign.
 *
 * SEMANTICS A PROGRAM MAY NOT RELY ON: when. The kernel target builds an skb
 * and hands it to the stack inside this call. This target appends a blueprint
 * to a per-flow ring and drains, coalesces and segments once per loop
 * iteration, because that is mTCP's shape and because the deferral is what the
 * paper's 21-vs-15.22 Gbps coalescing result measures. Both are conforming.
 * The difference is invisible here and lives entirely in internal.h.
 */
int mtp_pkt_gen(flow_t *f, const void *hdr, uint16_t hdr_len,
		const struct mtp_tx_payload *payload,
		uint32_t mss, uint32_t prio, uint32_t offload);

/*============================================================================*
 * 3. Segmentation rules (MTP_LANG §6, CR-1)
 *============================================================================*/
/*
 * `seg_rule <id>(x) [ Blueprint::field, first, mid, last ]` — when one pkt_gen
 * yields N packets, set `field` to `first` in packet 0, `mid` in the middle
 * N-2 (a recurrence over the previous packet), and `last` in packet N-1.
 *
 * The compiler emits first/mid/last as functions; the target calls the right
 * one per segment. Deliberately NOT reduced to a fixed operator — the lead
 * decision on the kernel side was to keep the paper's full generality, and it
 * is what lets Homa advance a segment index and a byte offset independently.
 * Our earlier flat callback with a `seg_rule_group` selector was a weaker
 * version of this and is gone.
 *
 * CR-1 moved rule application off the pkt_gen path. The kernel applies them at
 * the GSO split; we apply them in the drain, which is our segmentation point.
 * The rule form is the contract; the place is the target's.
 */
struct mtp_seg_rule;

struct mtp_seg_view {
	void		*hdr;		/* this segment's header, mutable */
	const void	*prev_hdr;	/* previous segment's header; NULL for seg 0 */
	uint32_t	 prev_paylen;
	uint32_t	 seg_idx;
	uint32_t	 n_segs;
};

typedef void (*mtp_seg_fn)(const struct mtp_seg_rule *r,
			   const struct mtp_seg_view *v);

struct mtp_seg_rule {
	mtp_seg_fn	first;
	mtp_seg_fn	mid;
	mtp_seg_fn	last;	/* NULL => reuse mid */
	uint64_t	arg;	/* the rule's (x), captured by the generated factory */
};

/*============================================================================*
 * 4. Timers (MTP_LANG §4, §8; CR-2, CR-6)
 *============================================================================*/
/*
 * A timer is an OBJECT the program embeds in its context, bound at declaration
 * to the event its expiry raises: `timer_t rto -> tcp_timeout;`. On expiry the
 * target raises that event and it flows through dispatch like any other.
 *
 * We had numeric timer ids indexing a fixed per-flow slot array. That is
 * exactly the `tid` array CR-2 removed, with the reasoning already written
 * down: which timers a flow has is known at compile time, so the compiler
 * emits one object and one callback per declared timer and the cap disappears.
 * Our timing wheel survives untouched behind these two calls — it is how, not
 * what.
 *
 * `ns` is nanoseconds, as v4 has it. mTCP's clock is a 1 ms tick read once per
 * loop iteration and every timestamp in an iteration is that one value; the
 * target quantises to it. That is a parity property of the donor, not a
 * contract question.
 */
/*
 * A timer OBJECT the program embeds in its context (CR-2), bound at
 * declaration to the event its expiry raises (CR-6). Complete for the same
 * reason the data unit is (D-19): the generated context embeds one by value.
 *
 * As with the data unit, only the BOUNDARY conforms. The fields are ours — a
 * deadline and a wheel link, because the realisation is the donor's hashed
 * timing wheel. The kernel target uses an hrtimer because that suits Linux.
 */
struct mtp_timer {
	uint32_t	 deadline;	/* in ticks; 0 = not armed */
	uint8_t		 armed;
	uint8_t		 id;		/* which of the program's timers this is */
	struct mtp_timer *wnext;	/* the wheel bucket's chain */
	void		 *ctx;		/* the program's context, for the callback */
};

int mtp_timer_start(struct mtp_timer *t, uint64_t ns);
int mtp_timer_stop(struct mtp_timer *t);

/*============================================================================*
 * 5. Contexts (MTP_LANG §4, §9; CR-3)
 *============================================================================*/
/*
 * The context IS the program's generated struct — not an opaque block of
 * PROG_CTX_SIZE bytes the target hands out, which is what we had. CR-3: for
 * each program the id type and the context struct are fixed, so the compiler
 * emits a typed store and typed accessors and the runtime indirection goes
 * away. The generated accessors are `<prog>_ctx_new(key)` / `_lookup` / `_del`;
 * what follows is the generic mechanism they are modelled on and call.
 *
 * Granularity — per-flow, shared, or global — is declared in `deploy`, not
 * here (MTP_LANG §4, paper §4.1). THAT is where cross-flow state comes from,
 * and it is why the `TgtGlobalState()` we added for Homa's grant scheduler is
 * gone: the language has had it since v1 and we re-derived a worse version.
 *
 * The store is keyed on the RAW BYTES of the generated flow id, whose shape the
 * program declares and whose value its parser constructs. No hash or compare
 * callback: `flow_id <name> : (uint32, uint32, uint16, uint16)` names the shape
 * only, the compiler packs it, and the target hashes sizeof(flowkey_t) bytes.
 */
void *mtp_new_ctx(const flowkey_t *key, size_t ctx_size);
void *mtp_ctx_lookup(const flowkey_t *key);
int   mtp_del_ctx(const flowkey_t *key);

/*
 * The program's context for a flow handle the APPLICATION holds — the inverse
 * of the handle the target places in the generated context at creation.
 *
 * Needed because an application operation arrives naming a flow, not a key: the
 * app got its handle from readiness and has no business constructing a flow id.
 * Protocol-neutral: it returns the opaque block the program declared.
 */
/*
 * PER-FLOW IDENTIFIER (DESIGN.md §24, lead ruling 3).
 *
 * A small, stable integer naming this flow, as mTCP's socket_map gives the
 * application a socket id. The application keeps its per-connection state in
 * ITS OWN table indexed by this -- exactly as `epserver` does -- so nothing of
 * the application's lives inside our flow record.
 *
 * This replaces a 128-byte opaque block the target carried for the application.
 * The block existed because an application cannot key a table on a pointer
 * whose lifetime the target owns; the identifier solves that, which is what
 * mTCP's design was doing all along.
 *
 * STABILITY IS THE CONTRACT: an id is not reused while any application table
 * may still hold it. Flow slots are not recycled today (flow.c), so an id is
 * unique for the life of the process; when recycling lands, reuse must wait
 * until the application can no longer be holding the id.
 */
uint32_t mtp_flow_id(flow_t *f);

/*
 * CR-E. The application's send: copies into the flow's transmit ring and
 * returns what was accepted, synchronously. The bytes do not cross the thread
 * boundary -- only the fact of them -- and the program's SEND then names an
 * EXTENT rather than a pointer. A short return is back-pressure, not an error.
 */
int mtp_app_send(flow_t *f, const void *buf, uint32_t len);

/* CR-E, close half: publishes; the stack generates the FIN. */
int mtp_app_close(flow_t *f);

/*
 * TRANSMIT PRIORITY CLASSES (D-17).
 *
 * The target provides three classes and drains the highest first. It attaches
 * NO MEANING to them: they are integers, and which packet takes which class is
 * the PROGRAM's decision, stated at `pkt_gen` in the `prio` argument.
 *
 * That is what keeps rule 4: a target that knew "class 2 is control" would have
 * put the protocol back inside the target, and would still produce the right
 * order on the wire -- which is why the acceptance test has a second half that
 * inspects the target's source for exactly that.
 */
#define MTP_PRIO_CLASSES 3

void *mtp_ctx_of(flow_t *f);

/*============================================================================*
 * 6. Scheduling and notification (MTP_LANG §8)
 *============================================================================*/
int mtp_set_queue_rate(uint32_t qid, uint64_t rate_bps);
int mtp_set_queue_prio(uint32_t qid, uint32_t prio);

enum mtp_notif_kind {
	MTP_NOTIF_READABLE,	/* data available */
	MTP_NOTIF_WRITABLE,	/* space available */
	MTP_NOTIF_STATE,	/* connection state changed */
	MTP_NOTIF_ERROR,
};

struct mtp_notif {
	uint32_t	kind;
	int32_t		err;
};

int mtp_notify(flow_t *f, const struct mtp_notif *msg);

/*============================================================================*
 * 7. The application interface (MTP_LANG §7a, CR-7)
 *============================================================================*/
/*
 * The application side is symmetric to the network side. A packet parser maps a
 * wire format the target supports into the program's events; an APP PARSER maps
 * the operations of an application interface the target supports into the
 * program's events. `app_parser socket { send -> sock_send; ... }`.
 *
 * There is no built-in "send" event. The program decides which of its events a
 * socket op produces and builds its flow id there — which is what makes the
 * tx-side id identical to the one the rx parser builds, with no protocol
 * knowledge in the target.
 *
 * This is C's B7, solved, and better than anything we had: our design carried
 * the donor's socket API shim with no route from an app call to an event at
 * all. The ops are neutral — a general inet endpoint plus a data handle. The
 * kernel puts a `struct msghdr *` in the handle; ours is an mtp_tx_addr,
 * because the handle's type is realisation and the schema is the contract.
 *
 * A NOTE WE WITHDREW. We read §7a's remark that a stream socket's `recv` is
 * runtime-served as a rule narrower than parity allows. It is not a rule: an
 * app op is an event like any other, and a program binds the ops it needs. Our
 * program binds `recv` because it needs the application-drain event to
 * recompute the advertised window at the donor's second recompute point — see
 * prog_app.c. Nothing about the language changes.
 */
/*
 * SEND takes a named flow, and that is CR-7 rather than a stretch of it. The
 * schema is the target's and the mapping into events is the program's, so
 * "send on this connection" is the app interface doing what it says. It is
 * recorded here because it is the ONE contract-level change the HTTP work
 * needed: DESIGN.md §17.6b's layering test held on everything else, and a test
 * that held with one exception is only worth citing if the exception is
 * written down next to the thing it changed.
 *
 * SEND with no flow remains the pre-posted object of a one-shot server, which
 * is how the first connection was served before an application could name one.
 */
enum mtp_app_op_kind {
	MTP_APP_SEND = 1,
	MTP_APP_RECV,
	MTP_APP_CONNECT,
	MTP_APP_BIND,
	MTP_APP_CLOSE,	/* the APPLICATION's send path, not the connection:
			 * D-20 is per-path, so a peer FIN does not imply this
			 * and our FIN waits for it. DESIGN.md §17.6c. */
	/* Additions to the kernel target's set. CR-7 makes the schema the
	 * target's, and a passive-open protocol needs both. DESIGN.md §17.1. */
	MTP_APP_LISTEN,
	MTP_APP_ACCEPT,
};

struct mtp_endpoint {		/* network byte order */
	uint32_t	ip;
	uint16_t	port;
};

struct mtp_app_op {
	enum mtp_app_op_kind	kind;
	flow_t			*flow;	/* RECV/SEND/CLOSE on an accepted flow;
					 * the handle the app got from readiness */
	struct mtp_endpoint	local;
	struct mtp_endpoint	remote;
	struct mtp_tx_addr	data;	/* SEND: the application's bytes */
	uint32_t		len;
	uint32_t		flags;
};

/*============================================================================*
 * 8. What the compiler emits, and what the target calls
 *============================================================================*/
/*
 * Dispatch is a STATIC SWITCH the compiler emits, calling event processors
 * directly — not a runtime entry point taking an event array, which is what we
 * had. The only indirect call is one per program, at demux. So the target calls
 * exactly three generated symbols, and every call below is direct.
 *
 * The flow id is `flowkey_t`, defined in prog_types.h from the program's
 * `flow_id` declaration. The target names the type, stores it, and hashes its
 * bytes; it never reads a field, and there are no field names to read — the
 * declaration is shape-only, and the PARSER canonicalises direction so an
 * inbound packet and an outbound app op resolve the same context. That last
 * part is protocol logic and the compiler has no business doing it.
 */

/* One received L4 payload -> parse, look up, dispatch, run to completion. */
int  mtp_program_net_input(const uint8_t *l4, uint16_t len,
			   const struct iphdr *iph, uint32_t now_ms);

/* One application-interface operation -> app parser -> dispatch. */
int  mtp_program_app_op(const struct mtp_app_op *op, uint32_t now_ms);

/* One timer expiry -> the bound event -> dispatch. */
void mtp_program_timer(struct mtp_timer *t, uint32_t now_ms);

/*
 * Per-segment header fixup, at the target's segmentation point.
 *
 * CR-1 took the seg rules off the pkt_gen path: they are baked into generated
 * code that the target calls once per produced segment. The kernel calls it at
 * the GSO split; we call it in the drain. One generated symbol, the rules
 * inside it, and the target passing a view of the segment and knowing no field.
 */
void mtp_program_segment(const struct mtp_seg_view *v);

/*
 * May two adjacent pending packets be merged, and what does the merge keep?
 *
 * A STOPGAP, and it is N-B. v4 has no way to declare merge semantics, so
 * without this the target would decide what a merged packet CONTAINS — and
 * then packet content is target-determined and the design law is broken. This
 * keeps the decision in generated code until the language can express it.
 *
 * `class` 0 means never merge. Two pending packets merge only if their classes
 * are equal and non-zero and their keys are equal; the key is compared and
 * never interpreted. `inherit_base` says whether the merged packet keeps the
 * OLDER contribution's sequence origin.
 *
 * The axis is base inheritance, NOT header age: the prototype's data merge
 * keeps the older sequence and payload pointer and takes the NEWER
 * acknowledgement, window and timestamp. Building it the other way puts a stale
 * cumulative acknowledgement and a stale echo on every merged segment.
 */
/*
 * A MERGE IS NOT "ONE HEADER WINS", and reading it that way is what went wrong:
 * the header that describes the RECEIVER'S state moves forward, and the field
 * that describes THIS SEGMENT'S OWN PAYLOAD does not. Acknowledgement, window
 * and timestamp echo are the former; the sequence number is the latter, and it
 * travels in the same header, which is how a blanket copy took it along.
 *
 * `keep_off`/`keep_len` name the byte range of the header that belongs to the
 * payload and must be taken from the OLDER contribution when the base is
 * inherited. The program names a RANGE rather than a field so the target stays
 * protocol-blind: it copies bytes it has been told about and never learns what
 * they mean (rule 4). keep_len 0 means take the whole newer header.
 */
void mtp_program_coalesce(const uint8_t *hdr, uint16_t hdr_len,
			  uint8_t *class, uint32_t *key, bool *inherit_base,
			  uint16_t *keep_off, uint16_t *keep_len);

/* The IP protocol number this program answers to. */
extern const uint8_t TRANSPORT_IP_PROTO;

/*============================================================================*
 * 9. The absence register — what is missing, and whose problem it is
 *============================================================================*/
/*
 * MTP is positive-only: a program can say what it does and cannot say what it
 * does not. The rule this effort runs under turns on exactly that, so the
 * contract needs its own checklist.
 *
 * From C writing Homa against our earlier draft (D-09), re-sorted after reading
 * v4. Most of it was us not knowing the language:
 *
 *   B1  flow key         CLOSED by CR-5 — shape-only alias, parser builds the
 *                        value and canonicalises direction. Our version named
 *                        semantic fields, which is the form the lead rejected.
 *   B2  state above the  CLOSED by context granularity in `deploy`
 *       flow             (per-flow / shared / global).
 *   B4  round outliving  CLOSED with B2. Homa's round state is already among
 *       the packet        its globals, so it never needed a third lifetime.
 *   B7  socket owning    CLOSED by CR-7.
 *       many flows
 *   B9  emitting for     Expressible: pkt_gen names the flow.
 *       another flow
 *   B10 per-packet       CLOSED — `prio` on pkt_gen, since v1.
 *       priority
 *
 * Still open, and each is a change request rather than an omission to patch:
 *
 *   B3  ordered collections. A compiler gap, not a contract one: a generated
 *       index lives in the program on the program's own state, and the target
 *       needs nothing. `list<T>` is in MTP_LANG §2 but Homa's five operations
 *       (successor on a composite key, min by a different key than the sort
 *       key, remove-returning-the-element) are beyond `.add()` and indexing.
 *
 *   B11 transmit ordering. `set_queue_prio` is queue-level; Homa wants SRPT
 *       ordering of flows by a per-flow key. Not the same thing.
 *
 * And raised by this target, recorded in docs/LANGUAGE-NEEDS.md. Nothing is
 * filed into the kernel repository; the lead mediates.
 *
 *   N-A  CLOSED 2026-08-12, and it was never a language gap. The lead: the
 *        payload reference stays valid until the program flushes that range
 *        with tx_flush_and_notify. So the guarantee is PROGRAM-CONTROLLED and
 *        the language already implied it — we failed to read it out. The two
 *        targets satisfy it by different routes, and for this one it is what
 *        makes deferring packet generation to a batched drain safe. The
 *        residual difficulty is OURS, not the language's: deferral means we may
 *        still hold a reference when the program flushes, so we need it to live
 *        longer than the contract promises and we drain to get that. See
 *        internal.h §3.
 *   N-B  declarable merge semantics, without which packet CONTENT is
 *        target-determined and the design law is broken.
 *   N-C  scratchpad lifetime across one packet's event list.
 *   N-D  support for CR-4 (now_ns), which parity needs because mTCP's RTO is a
 *        live estimator with no floor and no ceiling.
 *
 * Limits of the evidence: the Homa branch C read has no timers, no
 * retransmission and no pacer, and never coalesces. And nothing here has been
 * compiled for a second protocol, which is the only test rule 4 specifies.
 */

#endif /* CONTRACT_H */
