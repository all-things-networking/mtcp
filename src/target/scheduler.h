#ifndef SCHEDULER_H
#define SCHEDULER_H
/*
 * The target's main loop.
 *
 * Increment 1 builds the shape and none of the content: read a burst, hand
 * every packet down the infrastructure's receive path, flush the transmit
 * burst, take the clock once. The generation list, the timing wheel, the
 * application queues and run-to-completion dispatch are increment 2, and each
 * has a place marked below.
 *
 * The clock is read once per iteration and every timestamp in the stack for
 * that iteration is that one value. Both references do this and it is
 * parity-relevant, so it is here from the first version rather than added when
 * something needs it (docs/DESIGN.md §3.5).
 *
 * Named `scheduler` and not `sched` — the design calls the file sched.c — for a
 * dull but real reason: this directory is on the include path, and a header
 * called sched.h shadows the system <sched.h> that pthread.h pulls in. The
 * failure is a wall of errors inside libc headers that says nothing about the
 * cause.
 */
#include "infra.h"
#include "contract.h"

/* Runs until the context is asked to stop (SIGINT, or `ctx->exit`), or until
 * `max_ticks` milliseconds have passed if `max_ticks` is non-zero. The bound
 * exists because rule 5 says a hang is a failing test: a bring-up check that
 * cannot end on its own is a bring-up check that takes the node off the
 * network when it goes wrong. */
/* `app` runs once per iteration, after the receive burst and before the drain —
 * the single-threaded poller shape both references have. NULL for an
 * application that only needs the stack to run. */
void SchedRun(struct core_ctx *core, uint32_t max_ticks,
	      void (*app)(struct core_ctx *, uint32_t now, void *),
	      void *app_arg);

/* The per-core transport state — the flow table and the listener table. Set up
 * before the loop runs and torn down after it. */
/* One ready flow, as the application sees it. The handle is opaque. */
struct mtp_ready {
	flow_t   *flow;
	uint32_t  kinds;	/* 1 << enum mtp_notif_kind */
};

int  TransportPoll(struct core_ctx *core, struct mtp_ready *out, int max);

int  TransportCoreInit(struct core_ctx *core);
void TransportCoreFini(struct core_ctx *core);

#endif /* SCHEDULER_H */
