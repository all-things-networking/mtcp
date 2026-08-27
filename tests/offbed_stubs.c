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
#include <stddef.h>

#include "contract.h"

unsigned long mtp_stub_retries;

void
mtp_retry(flow_t *f)
{
	(void)f;
	mtp_stub_retries++;
}

/*
 * THE GENERATED PROGRAM NEEDS TWELVE MORE, and the reason is a file-layout
 * consequence rather than anything about the program.
 *
 * The hand-written program put the window rule in prog_app.c, which is a small
 * self-contained file, so TESTABLE could name it alone. The compiler splits by
 * ORIGIN instead -- op-parsers to prog_app.c, everything else to prog_proto.c
 * -- so the suite now links the whole program, and the whole program reaches
 * every instruction it can issue. All twelve live in scheduler.c, flow.c or
 * timer.c, which need DPDK.
 *
 * NONE OF THEM IS REACHED by any test here: the five suites exercise the
 * buffers, the flow table and the window rule, and the only instruction on
 * those paths is the retry above. They exist so the reference resolves. If a
 * test ever needs to assert one was issued, the count goes here.
 */
unsigned long mtp_stub_pkt_gen, mtp_stub_notify, mtp_stub_timer_start;

int  mtp_pkt_gen(flow_t *f, const void *h, uint16_t hl,
		 const struct mtp_tx_payload *p, uint32_t mss, uint32_t prio,
		 uint32_t off, uint32_t rtx)
{ (void)f; (void)h; (void)hl; (void)p; (void)mss; (void)prio; (void)off;
  (void)rtx; mtp_stub_pkt_gen++; return 0; }

int  mtp_pkt_gen_orphan(uint32_t l, uint32_t r, const void *h, uint16_t hl,
			int off)
{ (void)l; (void)r; (void)h; (void)hl; (void)off; return 0; }


void *mtp_new_ctx(const flowkey_t *k, size_t n) { (void)k; (void)n; return NULL; }
void *mtp_ctx_lookup(const flowkey_t *k)        { (void)k; return NULL; }
int   mtp_del_ctx(const flowkey_t *k)           { (void)k; return 0; }
void *mtp_ctx_of(flow_t *f)                     { (void)f; return NULL; }
void  mtp_ctx_addrs(flow_t *f, uint32_t l, uint32_t r) { (void)f; (void)l; (void)r; }

int  mtp_notify(flow_t *f, const struct mtp_notif *m)
{ (void)f; (void)m; mtp_stub_notify++; return 0; }

int  mtp_timer_start(struct mtp_timer *t, uint64_t ns)
{ (void)t; (void)ns; mtp_stub_timer_start++; return 0; }
int  mtp_timer_stop(struct mtp_timer *t) { (void)t; return 0; }

void mtp_new_tx_ordered_data(struct mtp_data_unit *u, uint64_t n) { (void)u; (void)n; }
void mtp_new_rx_ordered_data(struct mtp_data_unit *u, uint64_t n) { (void)u; (void)n; }

/* the app-interface bridge; the tests never resolve a real flow */
flow_t *mtp_flow_of(const flowkey_t *fid) { (void)fid; return NULL; }
