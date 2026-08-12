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

struct mtp_data_unit;			/* opaque; see internal.h */

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
struct mtp_timer;			/* opaque; embedded in the generated context */

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
enum mtp_app_op_kind {
	MTP_APP_SEND = 1,
	MTP_APP_RECV,
	MTP_APP_CONNECT,
	MTP_APP_BIND,
	MTP_APP_CLOSE,
};

struct mtp_endpoint {		/* network byte order */
	uint32_t	ip;
	uint16_t	port;
};

struct mtp_app_op {
	enum mtp_app_op_kind	kind;
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
 *        makes deferring packet generation to a batched drain safe. Our target
 *        now ASSERTS the program's compliance rather than enforcing it; see
 *        internal.h §3 for why the difference matters.
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
