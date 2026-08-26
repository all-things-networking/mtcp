/*
 * What the off-testbed build needs from the target's packet path, and only
 * that.
 *
 * TESTABLE in the Makefile is deliberately "off-testbed sources only: no
 * infra, so no DPDK". prog_app.c is in that set, and sock_recv there calls
 * mtp_retry -- which lives in scheduler.c, which needs DPDK. So the whole
 * suite stopped LINKING the moment the window-reopen was routed through a
 * retry, and five tests silently became un-runnable on the orchestrator.
 *
 * A stub rather than moving mtp_retry: the tests here exercise the buffers
 * and the flow table, none of which care whether a retry was requested. What
 * they need is for the reference to resolve.
 *
 * If a test ever needs to ASSERT that a retry was asked for, this is where
 * the count goes -- not a mock somewhere else.
 */
#include "contract.h"

unsigned long mtp_stub_retries;

void
mtp_retry(flow_t *f)
{
	(void)f;
	mtp_stub_retries++;
}
