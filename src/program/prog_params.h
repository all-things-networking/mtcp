#ifndef PROG_PARAMS_H
#define PROG_PARAMS_H
/*
 * Compiler output: this program's compile-time sizes and its parity parameter
 * freeze. Hand-written today in the form `mtpc` would emit.
 *
 * Rule 4 permits protocol identity HERE and nowhere else. Rebuilding the tree
 * for another protocol is expected; what is forbidden is the target or the
 * infrastructure knowing which protocol it was built for.
 *
 * Conforms to MTP contract v4. Every value below is from the DONOR'S RUNNING
 * CONFIGURATION (rule 1) rather than from a standard or from memory, and the
 * ones that look like bugs are reproduced on purpose with the reason attached.
 */
#include <stdint.h>

#include "prog_types.h"

/* Largest serialised header image a blueprint carries: 20 bytes of fixed header
 * plus at most 20 bytes of options on a SYN. */
#define PROG_HDR_MAX		64

/*============================================================================*
 * The advertised window — a RULE, not a number
 *============================================================================*/
/*
 * Written out here because the target's read accessors were withdrawn (see
 * contract.h §1), and this is the one place that withdrawal could have taken
 * something parity needs with it. It does not. The rule is expressible from
 * state the program already holds, and writing it out is how we know.
 *
 * WHAT THE DONOR DOES. `rcv_wnd` is a per-flow VARIABLE initialised to
 * TCP_INITIAL_WINDOW = 14600 (tcp_stream.c:325), recomputed from the buffer at
 * exactly two points and at no others:
 *
 *   1. when received payload is merged in order   (tcp_in.c:659)
 *   2. when the application drains the buffer     (api.c:1141)
 *
 * and the recomputed value is `rcvbuf->size - merged_len`, where merged_len is
 * the in-order bytes held but not yet taken by the application.
 *
 * The wire sequence that produces, and which the M1b calibration observed:
 *
 *   14600  unscaled, on the SYN and SYN-ACK   (scaling is not yet in effect)
 *   14592  on every non-SYN until the first payload arrives
 *          (the field carries 14600 >> 7 = 114, which the peer reads as 14592)
 *    2048  = 262144 >> 7, once payload has been merged and drained
 *
 * WHY THIS IS NOT tgt_rx_free(). A target that answers every packet with the
 * buffer's free space advertises 2048 from the first ACK and NEVER EMITS 14592
 * at all — a divergence in the first RTT of every connection, on the most
 * parity-visible number there is, with no protocol logic wrong anywhere. What
 * is frozen is WHEN the value is recomputed, not the value.
 *
 * HOW IT IS EXPRESSED WITH NO ACCESSOR. Both quantities are already the
 * program's own state:
 *
 *   recv_next   the program advances it when a segment merges in order — it is
 *               the same variable the cumulative ACK is built from
 *   delivered   the program accumulates the RETURN VALUE of
 *               mtp_rx_flush_and_notify(), which is the byte count actually
 *               handed to the application
 *
 * so  merged_len == recv_next - delivered,  and the rule is
 *
 *   rcv_wnd = PARITY_RCVBUF_SIZE - (recv_next - delivered)
 *
 * recomputed at the donor's two points and nowhere else. The wire field is
 * `rcv_wnd` unscaled on a SYN, and `rcv_wnd >> PARITY_WSCALE` on everything
 * else.
 *
 * WHERE POINT 2 COMES FROM. It fires when the APPLICATION drains, so the
 * program needs an event for that, so it BINDS `recv` in its app_parser
 * (prog_app.c). No language change is involved and none was needed: an app op
 * is an event like any other and a program binds the ops it needs. We briefly
 * read §7a's remark about stream sockets as a rule restricting that; it is a
 * description of the example program, and the reading is withdrawn.
 */
/*
 * The donor's running configuration: tcp_timewait = 0. Zero is a real value
 * here and not "unset" — D-24: the state must be ENTERED AND LEFT even at zero,
 * because it is the place the final acknowledgement is owed from.
 */
#define PARITY_TIMEWAIT_MS	0

/* D-25 piece 2: the donor probes a closed window at 500 ms since the last
 * acknowledgement it SENT, with no backoff. */
#define PARITY_PROBE_MS		500

#define PARITY_RCVBUF_SIZE	262144	/* the donor's running rcvbuf */
#define PARITY_INITIAL_WINDOW	14600	/* tcp_stream.c:325 */
#define PARITY_WSCALE		7	/* sent always */

/*============================================================================*
 * The rest of the parity freeze (docs/DESIGN.md §7.2)
 *============================================================================*/
#define PARITY_MSS_ADVERTISED	1460
/*
 * The 1460-versus-1448 asymmetry is REPRODUCED, not tidied. The send
 * decision's bail threshold is the full segment size while a segment's payload
 * is that minus twelve bytes of options, so the donor defers segments it could
 * have filled. It looks like an oversight and it is parity.
 *
 * Note also what the donor does NOT do: there is no Nagle and no "wait for a
 * full segment". The only gate is the window, so a short buffered write goes
 * out immediately at an application write boundary. Short segments in a trace
 * are therefore expected on both sides, not evidence of a defect here.
 */
#define PARITY_MSS_PAYLOAD	1448	/* mss - CalculateOptionLength(ACK), computed
					 * inline at tcp_out.c:566. There is no
					 * `eff_mss` in the donor to grep for. */
#define PARITY_ISN		0	/* always. REPRODUCE, DO NOT CORRECT. */
/*
 * TWO segments, not ten. TCP_INIT_CWND is 2 in the donor; the INIT_CWND_PKTS 10
 * in another header belongs to the token bucket and is unrelated. Taking that
 * one would be a five-fold error in the opening trajectory, and it sits in
 * plain sight under a name that looks right. (B, 2026-08-13.)
 */
#define PARITY_INIT_CWND	2920	/* 2 * MSS */
#define PARITY_SSTHRESH_ACTIVE	14600	/* MSS * 10 */
#define PARITY_DUPACK_THRESH	3
#define PARITY_INITIAL_RTO_MS	500
#define PARITY_MAX_RTX		16
#define PARITY_MAX_SYN_RETRY	7	/* SYN_SENT only; timer.c:267-269 */

/*
 * D-01. mTCP never assigns ssthresh on the passive-open path, so the server —
 * the machine under test — runs with ssthresh == 0 and has no slow start at
 * all. Reproduced, because rule 1 says parameters come from the donor's running
 * configuration and not from a standard.
 *
 * The flag gates three assignments as ONE UNIT, and the reason is subtle: only
 * ssthresh has a live consequence today, but snd_wl1's divergence is masked
 * *conditional on* the ISN freeze above. Lift the ISN to a random value and
 * snd_wl1 activates silently, with nothing in the diff pointing at the ISN
 * change that caused it.
 */
#define PARITY_OPENING_TRAJECTORY	1
#define PARITY_SSTHRESH_PASSIVE		0

/*
 * Never set. Tested at tcp_out.c:172,265 and passed by no caller. Recorded
 * because the program now builds the header, so a flag bit can diverge with no
 * protocol logic wrong.
 */
#define PARITY_SET_PSH		0

/* Where the transport checksum sits within this program's header. The target
 * asks the NIC to compute it and needs the offset; it never learns what is
 * being summed. */
#define PROG_L4_CSUM_OFFSET	16

/* There is no RTO floor and no RTO ceiling in the donor. Effective RTO here is
 * ~3 ms — MEASURED, docs/RESULTS.md 2026-08-07, not assumed. Reproducing this
 * needs a clock the language does not yet expose; see CR-4, which we support
 * for this reason. */
#define PARITY_RTO_MIN_MS	0
#define PARITY_RTO_MAX_MS	0

/*
 * The most connections one listener will hold awaiting accept. The donor sizes
 * its accept queue from the application's backlog argument at listen() time;
 * ours is a compile-time bound because the program's context is a struct the
 * compiler emits, and `pending_cap` below it is the RUNTIME bound the
 * application actually asked for. Exceeding the compile-time one is a program
 * that under-declared its own concurrency, not a connection to drop.
 */
#define PROG_MAX_BACKLOG 128

/* tcp_in.c:417 -- the donor acts on the third duplicate and only the third. */
#define PARITY_DUP_ACK_THRESH 3

/*
 * The donor's connection-idle timeout, from the RUNNING CONFIGURATION rather
 * than a standard: conf/aqua/upcheck.conf says `tcp_timeout = 30`, and
 * config.c:618-621 converts it to ticks. A connection with no activity for this
 * long is closed and the application is told with an ERROR, not a clean close.
 */
#define PARITY_IDLE_MS 30000u

#endif /* PROG_PARAMS_H */
