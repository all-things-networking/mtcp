/*
 * mtcp_shim — run the donor's `epserver`, unmodified, on our target.
 *
 * WHY (DESIGN.md §20): in a stack comparison only the stack may differ. Running
 * our `tcpserver` against the donor's `epserver` and calling the result a stack
 * comparison already cost a response-header confound and two days chasing an
 * application bug (`g_sent`) through the transport. With the same application
 * on both sides, the application is a constant.
 *
 * WHERE: apps/, deliberately. The rule-4 diff covers src/target/ and the
 * compiler; those may contain no protocol identity. An application may name
 * whatever protocol it likes — our tcpserver already holds the only HTTP in the
 * tree on the same reasoning. NOTHING in src/target/ gains an mtcp_ symbol.
 *
 * TYPES ARE NOT REDECLARED. We include the pinned donor's own headers, so
 * `struct mtcp_conf`'s layout is not matched, it IS the same. A redeclaration
 * that drifted would fail silently, which is the one failure mode this file
 * cannot be allowed to have.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the reference's own declarations — read, never edited */
#include "mtcp_api.h"
#include "mtcp_epoll.h"

#include "contract.h"
#include "scheduler.h"
#include "target_core.h"

#define SHIM_MAX_SOCK	4096
#define SHIM_LISTENER	1	/* fixed id; epserver compares against it */

/*
 * The socket table. epserver indexes `struct server_vars` BY SOCKET ID, so ids
 * must be small, stable and unique for the connection's life — this shim owns
 * that namespace.
 */
struct shim_sock {
	flow_t	*flow;		/* NULL = free, or the listener */
	uint32_t interest;	/* what epoll_ctl last asked for */
	uint32_t ready;		/* what the target reported this iteration */
	uint8_t	 in_use;
	uint8_t	 is_listener;
};

/*
 * Per-flow, in the TARGET's block (DESIGN.md §19) rather than in a side table
 * keyed on the flow pointer. The shim does not own that pointer's lifetime; a
 * recycled slot would hand it one it had seen before, belonging to a different
 * connection, silently. The target zeroes this on create and poisons it on
 * destroy, so `sockid == 0` means "not ours yet" and the poison is not a
 * plausible id.
 */
struct shim_flow_state {
	int sockid;
};

static struct shim_sock	 g_sock[SHIM_MAX_SOCK];
static struct core_ctx	*g_shim_core;
static struct mtcp_conf	 g_conf;

static struct shim_flow_state *
fstate(flow_t *f)
{
	return (struct shim_flow_state *)mtp_flow_app_state(f);
}

static int
sock_alloc(flow_t *flow)
{
	int i;

	for (i = SHIM_LISTENER + 1; i < SHIM_MAX_SOCK; i++) {
		if (g_sock[i].in_use)
			continue;
		g_sock[i].in_use = 1;
		g_sock[i].flow = flow;
		g_sock[i].interest = 0;
		g_sock[i].is_listener = 0;
		if (flow)
			fstate(flow)->sockid = i;
		return i;
	}
	errno = EMFILE;
	return -1;
}

/*----------------------------------------------------------------------------*/
/* Setup. mtcp_init does what tcpserver's main() does before its loop. */

int
mtcp_init(const char *config_file)
{
	(void)config_file;	/* our config is loaded by the harness */
	memset(g_sock, 0, sizeof(g_sock));
	return 0;
}

void mtcp_destroy(void) { }

int
mtcp_getconf(struct mtcp_conf *conf)
{
	*conf = g_conf;
	return 0;
}

int
mtcp_setconf(const struct mtcp_conf *conf)
{
	/*
	 * REFUSED, NOT WARNED. epserver is written for -N cores and we run one.
	 * A shim that appears to support multi-core and silently runs a single
	 * core is the "two arms that were never distinct" shape at
	 * configuration level: every number it produced would be labelled with
	 * a core count it did not have.
	 */
	if (conf->num_cores > 1) {
		fprintf(stderr, "mtcp_shim: num_cores=%d requested; this target "
			"runs ONE core. Refusing rather than silently running "
			"one and reporting %d.\n",
			conf->num_cores, conf->num_cores);
		exit(1);
	}
	g_conf = *conf;
	return 0;
}

mctx_t
mtcp_create_context(int cpu)
{
	(void)cpu;
	return (mctx_t)g_shim_core;
}

void mtcp_destroy_context(mctx_t mctx) { (void)mctx; }
int  mtcp_core_affinitize(int cpu)     { (void)cpu; return 0; }
int  mtcp_setsock_nonblock(mctx_t m, int s) { (void)m; (void)s; return 0; }

/*----------------------------------------------------------------------------*/
/* Listener. */

int
mtcp_socket(mctx_t mctx, int domain, int type, int protocol)
{
	(void)mctx; (void)domain; (void)type; (void)protocol;
	g_sock[SHIM_LISTENER].in_use = 1;
	g_sock[SHIM_LISTENER].is_listener = 1;
	g_sock[SHIM_LISTENER].flow = NULL;
	return SHIM_LISTENER;
}

int
mtcp_bind(mctx_t mctx, int sockid, const struct sockaddr *addr, socklen_t len)
{
	struct mtp_app_op op;
	const struct sockaddr_in *in = (const struct sockaddr_in *)addr;

	(void)mctx; (void)sockid; (void)len;
	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_BIND;
	op.local.ip = in->sin_addr.s_addr;
	op.local.port = in->sin_port;
	return mtp_program_app_op(&op, 0) < 0 ? -1 : 0;
}

int
mtcp_listen(mctx_t mctx, int sockid, int backlog)
{
	struct mtp_app_op op;

	(void)mctx; (void)sockid; (void)backlog;
	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_LISTEN;
	return mtp_program_app_op(&op, 0) < 0 ? -1 : 0;
}

/*----------------------------------------------------------------------------*/
/*
 * Accept. Our target has no explicit accept: a new flow simply appears in the
 * readiness list. The shim turns that into the donor's shape — the listener
 * reports EPOLLIN while flows are waiting, and accept() hands one over and
 * gives it an id.
 */
#define SHIM_PENDING 64
static flow_t *g_pending[SHIM_PENDING];
static int	g_pend_head, g_pend_tail;

static void
pending_push(flow_t *f)
{
	int next = (g_pend_tail + 1) % SHIM_PENDING;

	if (next == g_pend_head)
		return;			/* full: the flow waits for a later poll */
	g_pending[g_pend_tail] = f;
	g_pend_tail = next;
}

int
mtcp_accept(mctx_t mctx, int sockid, struct sockaddr *addr, socklen_t *addrlen)
{
	flow_t *f;

	(void)mctx; (void)sockid; (void)addr; (void)addrlen;
	if (g_pend_head == g_pend_tail) {
		errno = EAGAIN;
		return -1;
	}
	f = g_pending[g_pend_head];
	g_pend_head = (g_pend_head + 1) % SHIM_PENDING;
	return sock_alloc(f);
}

/*----------------------------------------------------------------------------*/
/* Data. Our short-write semantics already match the donor's: a partial return
 * is backpressure, not an error, and the application retries on WRITABLE. */

ssize_t
mtcp_read(mctx_t mctx, int sockid, char *buf, size_t len)
{
	struct mtp_app_op op;
	int got;

	(void)mctx;
	if (sockid <= 0 || sockid >= SHIM_MAX_SOCK || !g_sock[sockid].flow)
		return -1;
	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_RECV;
	op.flow = g_sock[sockid].flow;
	op.data.base = (uint8_t *)buf;
	op.data.len = (uint32_t)len;
	op.len = (uint32_t)len;
	got = mtp_program_app_op(&op, g_shim_core ? g_shim_core->cur_ts : 0);
	if (got > 0)
		return got;
	errno = EAGAIN;
	return -1;
}

ssize_t
mtcp_write(mctx_t mctx, int sockid, const char *buf, size_t len)
{
	struct mtp_app_op op;
	int wrote;

	(void)mctx;
	if (sockid <= 0 || sockid >= SHIM_MAX_SOCK || !g_sock[sockid].flow)
		return -1;
	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_SEND;
	op.flow = g_sock[sockid].flow;
	op.data.base = (uint8_t *)(uintptr_t)buf;
	op.data.len = (uint32_t)len;
	op.len = (uint32_t)len;
	wrote = mtp_program_app_op(&op, g_shim_core ? g_shim_core->cur_ts : 0);
	if (wrote > 0)
		return wrote;
	errno = EAGAIN;
	return -1;
}

int
mtcp_close(mctx_t mctx, int sockid)
{
	struct mtp_app_op op;

	(void)mctx;
	if (sockid <= 0 || sockid >= SHIM_MAX_SOCK)
		return -1;
	if (g_sock[sockid].flow) {
		memset(&op, 0, sizeof(op));
		op.kind = MTP_APP_CLOSE;
		op.flow = g_sock[sockid].flow;
		mtp_program_app_op(&op, g_shim_core ? g_shim_core->cur_ts : 0);
	}
	memset(&g_sock[sockid], 0, sizeof(g_sock[sockid]));
	return 0;
}

/*
 * DIVERGENCE, recorded in DESIGN-CLOSE.md §6: we have no reset path, so there
 * is never an error to report. epserver has an error branch that can be taken
 * on the donor and can never be taken here. Stubbed loudly in the record
 * rather than silently in the code.
 */
int
mtcp_getsockopt(mctx_t mctx, int sockid, int level, int optname,
		void *optval, socklen_t *optlen)
{
	(void)mctx; (void)sockid; (void)level; (void)optname;
	if (optval && optlen && *optlen >= (socklen_t)sizeof(int))
		*(int *)optval = 0;
	return 0;
}

/*----------------------------------------------------------------------------*/
/*
 * The event loop — the only part of this file with real semantics.
 *
 * epserver is LEVEL-TRIGGERED: it never sets MTCP_EPOLLET and re-arms interest
 * with CTL_MOD. Our readiness is already level-checked at both edges
 * (ready_level_check, §17.6), so the two line up rather than needing emulation.
 */
int
mtcp_epoll_create(mctx_t mctx, int size) { (void)mctx; (void)size; return 1; }

int
mtcp_epoll_ctl(mctx_t mctx, int epid, int op, int sockid,
	       struct mtcp_epoll_event *event)
{
	(void)mctx; (void)epid;
	if (sockid < 0 || sockid >= SHIM_MAX_SOCK)
		return -1;
	switch (op) {
	case MTCP_EPOLL_CTL_ADD:
	case MTCP_EPOLL_CTL_MOD:
		g_sock[sockid].interest = event ? event->events : 0;
		return 0;
	case MTCP_EPOLL_CTL_DEL:
		g_sock[sockid].interest = 0;
		return 0;
	default:
		return -1;
	}
}

/*
 * Collect one target iteration's readiness. Called from inside SchedStep, which
 * mtcp_epoll_wait pumps — so the application's loop is the target's clock. That
 * is our inline-stack design surfacing at the API boundary, not an artefact of
 * the shim, and it is on the parity register as a behavioural difference from
 * the donor (RESULTS 2026-08-15).
 */
static void
shim_app_cb(struct core_ctx *core, uint32_t now, void *arg)
{
	struct mtp_ready ready[64];
	int n, i;

	(void)now;
	(void)arg;
	n = TransportPoll(core, ready, 64);
	for (i = 0; i < n; i++) {
		flow_t *f = ready[i].flow;
		int sid = fstate(f)->sockid;

		/* No id yet, so this is a connection the application has not
		 * accepted. Our target has no accept call; the donor's shape is
		 * that the listener becomes readable, so queue it there. */
		if (sid <= 0 || sid >= SHIM_MAX_SOCK || g_sock[sid].flow != f) {
			pending_push(f);
			continue;
		}

		if (ready[i].kinds & (1u << MTP_NOTIF_READABLE))
			g_sock[sid].ready |= MTCP_EPOLLIN;
		if (ready[i].kinds & (1u << MTP_NOTIF_WRITABLE))
			g_sock[sid].ready |= MTCP_EPOLLOUT;
	}
}

/*
 * POLLS, never blocks. epserver passes -1 meaning "block until something
 * happens"; our target busy-polls, so we run one iteration and report what is
 * ready, returning 0 when nothing is. Verified against the pinned source before
 * relying on it: epserver treats only a NEGATIVE return as an error, so a zero
 * simply spins its loop — which is what the donor's application does anyway
 * while its stack thread runs.
 */
int
mtcp_epoll_wait(mctx_t mctx, int epid, struct mtcp_epoll_event *events,
		int maxevents, int timeout)
{
	int i, n = 0;

	(void)mctx; (void)epid; (void)timeout;

	for (i = 0; i < SHIM_MAX_SOCK; i++)
		g_sock[i].ready = 0;

	SchedStep(g_shim_core, shim_app_cb, NULL);

	/* The listener first: epserver checks for it by socket id and accepts
	 * everything queued before looking at the rest. */
	if (g_pend_head != g_pend_tail && n < maxevents &&
	    (g_sock[SHIM_LISTENER].interest & MTCP_EPOLLIN)) {
		events[n].events = MTCP_EPOLLIN;
		events[n].data.sockid = SHIM_LISTENER;
		n++;
	}

	for (i = SHIM_LISTENER + 1; i < SHIM_MAX_SOCK && n < maxevents; i++) {
		uint32_t hit;

		if (!g_sock[i].in_use)
			continue;
		/* level-triggered: report only what was asked for */
		hit = g_sock[i].ready & g_sock[i].interest;
		if (!hit)
			continue;
		events[n].events = hit;
		events[n].data.sockid = i;
		n++;
	}
	return n;
}

/* The target's core, handed over by whatever brings the process up. */
void
mtcp_shim_set_core(struct core_ctx *core)
{
	g_shim_core = core;
}
