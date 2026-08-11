#ifndef PROG_PARAMS_H
#define PROG_PARAMS_H

#include <stdint.h>
/*
 * The program's compile-time sizes, and later its parity parameter freeze.
 *
 * This is compiler output. Today it is hand-written in the form a compiler
 * would emit, because the compiler comes after the target works — but nothing
 * outside src/program/ may assume that, and nothing here is shared with the
 * target beyond the four sizes below, which the target needs in order to
 * allocate.
 *
 * Rule 4 permits protocol identity HERE and nowhere else. Rebuilding the whole
 * tree for another protocol is expected; what is forbidden is the target or the
 * infrastructure knowing which protocol it was built for.
 *
 * Increment 1 declares only the sizes and the IP protocol number, because
 * increment 1 has no processors. docs/DESIGN.md §7.2 is the parameter freeze
 * that lands here next, every value taken from the donor's running
 * configuration rather than from a standard.
 */

/*
 * THE FLOW KEY (docs/DECISIONS.md D-11).
 *
 * A program-defined type, compiled straight into the target. TCP always keys on
 * a four-tuple; Homa always keys on a four-tuple plus an RPC id. Which one it is
 * varies per protocol and is fixed within a protocol, so it is a compile-time
 * shape and not a runtime decision — the target's source names the type and
 * never its fields or its size, and a TCP build costs exactly what mTCP costs,
 * with no wider key and nothing indirect on the receive path.
 *
 * Network byte order, as it came off the wire.
 */
typedef struct {
	uint32_t local_ip, remote_ip;
	uint16_t local_port, remote_port;
} flowkey_t;

/* Largest event the parser emits. The target carries events as opaque bytes,
 * so this is purely an allocation size. */
#define PROG_EVENT_MAX		64

/* Per-flow program state. The target allocates it and zeroes it (G12). */
#define PROG_CTX_SIZE		512

/* Largest serialised header image a blueprint carries. 20 bytes of fixed
 * header plus at most 20 bytes of options on a SYN. */
#define PROG_HDR_MAX		64

/* Timer slots per flow. */
#define PROG_TIMER_COUNT	4

/*
 * Per-core program state, above the flow. Zero means the protocol has none,
 * which is TCP's answer.
 *
 * Homa's is a host-wide byte budget and two ordered indices over RPCs, and the
 * state of a grant round that spans up to nine packet arrivals. Its own
 * implementation keeps all of it in one header of file-scope statics — which is
 * a correctness bug the moment there is more than one stack thread, and is why
 * the target hands this out per core rather than leaving the program to declare
 * a static.
 */
#define PROG_GLOBAL_SIZE	0

#endif /* PROG_PARAMS_H */
