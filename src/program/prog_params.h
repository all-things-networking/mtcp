#ifndef PROG_PARAMS_H
#define PROG_PARAMS_H
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

#endif /* PROG_PARAMS_H */
