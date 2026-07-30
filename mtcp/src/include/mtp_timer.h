#ifndef MTP_TIMER_H
#define MTP_TIMER_H
/* Per-flow timer facility.
 *
 * Division of labour, per the MTP model: *which* timers a protocol keeps, how
 * long each runs and what happens when one fires is protocol logic and lives in
 * the MTP program. Maintaining them -- arming, cancelling, checking expiry and
 * running the right event processor when one expires -- is target mechanism,
 * and that is all this header describes.
 *
 * The target previously collapsed every timer onto one slot per flow, so
 * `timer_start_instr(<name>, ...)` lost the name and a protocol could only ever
 * have a single timer in flight. Anything needing a second one (connection
 * reaping, TIME_WAIT) had to be commented out in the target, which is why flows
 * leaked. A flow now carries one slot per declared timer.
 */
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Program-derived. One entry per timer_t the MTP program declares; the
 * compiler emits this block. Hand-written for now, and must be kept in step
 * with the declarations in the .mtp program.
 * ------------------------------------------------------------------------- */
enum {
	MTP_TIMER_ACK_TIMEOUT = 0,
	MTP_TIMER_TIMEWAIT,
	MTP_TIMER_IDLE,
	MTP_TIMER_CNT
};

/* Durations the program specifies for those timers, in mtcp ticks (ms). */
#define MTP_TIMEWAIT_TICKS   2000   /* 2MSL */
#define MTP_IDLE_TICKS      30000   /* reap a flow that has gone quiet */

/* ------------------------------- mechanism ------------------------------- */
struct mtp_timer {
	uint32_t deadline;      /* tick at which this timer fires */
	uint8_t  armed;
};

#endif /* MTP_TIMER_H */
