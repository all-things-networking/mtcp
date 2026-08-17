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
#include <execinfo.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the reference's own declarations — read, never edited */
#include "mtcp_api.h"
#include "mtcp_epoll.h"

#include "contract.h"
#include "scheduler.h"
#include "infra.h"
#include "bringup.h"	/* InfraInit, InfraCoreCreate -- WITHOUT this the
				 * compiler assumes InfraCoreCreate returns int and
				 * sign-extends the pointer, which segfaults on the
				 * first dereference and looks like a target bug */
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
 * The shim's own flow->socket table, indexed by the flow's identifier
 * (DESIGN.md §24, ruling 3). Not keyed on the flow pointer: the shim does not
 * own that pointer's lifetime, and a recycled slot would hand it one it had
 * seen before belonging to a different connection.
 */
struct shim_flow_state {
	int sockid;
	/*
	 * Already queued for accept. Without it a flow that becomes readable
	 * before the application accepts it is pushed on EVERY poll, is then
	 * accepted more than once, and sock_alloc repoints fstate->sockid at
	 * the newest socket -- while the application is still polling the
	 * first. Readiness is then filed against a socket nobody watches, the
	 * request is never read, and the level-triggered re-arm re-presents the
	 * flow for the rest of its life. Five such flows cost more than half
	 * this arm's throughput (RESULTS 2026-08-17).
	 */
	uint8_t pending;
};

static struct shim_flow_state g_flow[SHIM_MAX_SOCK];
static uint64_t g_pend_dropped, g_pend_dedup;
static uint64_t g_wr_calls, g_wr_asked, g_wr_got, g_wr_short, g_wr_refused;
static uint64_t g_wr_ringfull, g_wr_noflow;
static struct shim_sock	 g_sock[SHIM_MAX_SOCK];
static struct core_ctx	*g_shim_core;
static pthread_t	 g_shim_stack;
static struct mtcp_conf	 g_conf;

static struct shim_flow_state *
fstate(flow_t *f)
{
	uint32_t id = mtp_flow_id(f);

	if (id >= SHIM_MAX_SOCK) {
		fprintf(stderr, "mtcp_shim: flow id %u exceeds %d\n",
			id, SHIM_MAX_SOCK);
		abort();
	}
	return &g_flow[id];
}

static int shim_collect_ready(void);

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

/*
 * BRING THE TARGET UP. epserver calls this once, before anything else, and
 * everything the reference does afterwards assumes a working stack -- so the
 * sequence tcpserver's main() performs before its loop happens here instead.
 *
 * A stub that returned 0 would link, and would fail to serve. That is the
 * arm-that-was-never-demonstrated failure, so this is exercised by a run that
 * delivers an object and checks its checksum, not by the binary existing.
 */
/*
 * A crash here is a failing test, and one that leaves no evidence costs a run
 * to reproduce -- the reference has no handler of its own and setsid'd output
 * goes nowhere. Same handler tcpserver installs, for the same reason.
 */
static void
shim_fatal(int sig)
{
	void *bt[32];
	int n = backtrace(bt, 32);

	fprintf(stderr, "\n*** mtcp_shim: FATAL signal %d — stack follows ***\n",
		sig);
	fflush(stderr);
	backtrace_symbols_fd(bt, n, fileno(stderr));
	_exit(128 + sig);
}

int
mtcp_init(const char *config_file)
{
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = shim_fatal;
		sigaction(SIGSEGV, &sa, NULL);
		sigaction(SIGBUS, &sa, NULL);
		sigaction(SIGABRT, &sa, NULL);
	}
	memset(g_sock, 0, sizeof(g_sock));
	memset(g_flow, 0, sizeof(g_flow));

	if (InfraInit(config_file) < 0) {
		fprintf(stderr, "mtcp_shim: InfraInit(%s) failed\n",
			config_file ? config_file : "(null)");
		return -1;
	}
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

/*
 * Plain sigaction: no target involvement, and the reference expects the
 * previous handler back. epserver uses it to install its SIGINT handler.
 */
mtcp_sighandler_t
mtcp_register_signal(int signum, mtcp_sighandler_t handler)
{
	struct sigaction sa, old;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(signum, &sa, &old))
		return NULL;
	return old.sa_handler;
}

/*
 * The per-core context, and where the stack thread starts. epserver creates one
 * per core; we refuse more than one at setconf, so this runs once.
 */
mctx_t
mtcp_create_context(int cpu)
{
	g_shim_core = InfraCoreCreate(cpu);
	if (!g_shim_core || TransportCoreInit(g_shim_core) < 0) {
		fprintf(stderr, "mtcp_shim: cpu %d failed to come up\n", cpu);
		return NULL;
	}

	/*
	 * Two threads, one core, as everywhere else. epserver's thread becomes
	 * the application; the stack gets its own. Runs until SIGINT, so no
	 * tick limit.
	 */
	g_shim_stack = SchedStartStack(g_shim_core, 0, cpu);
	return (mctx_t)g_shim_core;
}

void
mtcp_destroy_context(mctx_t mctx)
{
	(void)mctx;
	/* Stop it before joining it. Without this the join never returns and
	 * the process dies on SIGKILL with no report. */
	SchedStop();
	if (g_shim_stack) {
		pthread_join(g_shim_stack, NULL);
		g_shim_stack = 0;
	}
	if (g_shim_core)
		SchedReport(g_shim_core);	/* the loop is ours, so is the report */
	fprintf(stderr, "shim write: %llu calls, asked %llu, got %llu (%.1f%%), "
		"%llu short, %llu refused (%llu ring full, %llu no flow); "
		"mean asked %llu, mean got %llu\n",
		(unsigned long long)g_wr_calls,
		(unsigned long long)g_wr_asked,
		(unsigned long long)g_wr_got,
		g_wr_asked ? 100.0 * (double)g_wr_got / (double)g_wr_asked : 0.0,
		(unsigned long long)g_wr_short,
		(unsigned long long)g_wr_refused,
		(unsigned long long)g_wr_ringfull,
		(unsigned long long)g_wr_noflow,
		(unsigned long long)(g_wr_calls ? g_wr_asked / g_wr_calls : 0),
		(unsigned long long)(g_wr_calls ? g_wr_got / g_wr_calls : 0));
	fprintf(stderr, "shim accept queue: %llu duplicate pushes suppressed, "
		"%llu dropped for want of a slot\n",
		(unsigned long long)g_pend_dedup,
		(unsigned long long)g_pend_dropped);
}
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
	struct shim_flow_state *st = fstate(f);

	/* AT MOST ONCE. The guard is here rather than at the call site for the
	 * same reason the target's membership guards are: a second producer
	 * cannot omit a guard it cannot reach. */
	if (st->sockid > 0 || st->pending) {
		g_pend_dedup++;
		return;
	}
	if (next == g_pend_head) {
		/* Was a silent return. With the dedup above this needs one
		 * slot per unaccepted flow, so reaching it means the
		 * application has stopped accepting -- which is worth saying,
		 * not swallowing. */
		g_pend_dropped++;
		return;
	}
	st->pending = 1;
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
	fstate(f)->pending = 0;
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
	int wrote;

	(void)mctx;
	if (sockid <= 0 || sockid >= SHIM_MAX_SOCK || !g_sock[sockid].flow)
		return -1;
	/* CR-E: copies into the flow's ring on THIS thread and returns what was
	 * accepted; the stack invokes the program's SEND for the extent. */
	mtp_app_state(MTP_APP_IN_WRITE);
	wrote = mtp_app_send(g_sock[sockid].flow, buf, (uint32_t)len);
	mtp_app_state(MTP_APP_RUNNING);

	/*
	 * IS THE APPLICATION WRITING LESS, OR ARE WE ACCEPTING LESS?
	 *
	 * epserver moves 39-40 KB per writable event against tcpserver's 65 KB
	 * (RESULTS 2026-08-17). That is either how epserver chunks -- its
	 * business -- or a short return from here cutting it off, which is
	 * ours. The two are indistinguishable from the byte total alone and
	 * separated by what each call ASKS for against what it GETS.
	 */
	g_wr_calls++;
	g_wr_asked += (uint64_t)len;
	if (wrote > 0) {
		g_wr_got += (uint64_t)wrote;
		if ((size_t)wrote < len)
			g_wr_short++;
		return wrote;
	}
	/*
	 * BY CAUSE. "Refused" merged two unrelated outcomes: a full transmit
	 * ring, which is back-pressure and expected, and a missing flow or
	 * unit, which is a defect. One counter cannot say which capacity ran
	 * out, and this project has twice compared the wrong one because a
	 * single code covered two conditions.
	 */
	if (wrote == 0)
		g_wr_ringfull++;
	else
		g_wr_noflow++;
	g_wr_refused++;
	errno = EAGAIN;
	return -1;
}

int
mtcp_close(mctx_t mctx, int sockid)
{
	(void)mctx;
	if (sockid <= 0 || sockid >= SHIM_MAX_SOCK)
		return -1;
	/* CR-E: detaches, then publishes; the stack generates the FIN. */
	if (g_sock[sockid].flow)
		mtp_app_close(g_sock[sockid].flow);
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
		/* The registration edge. epserver adds interest to a socket it
		 * has just accepted, and the request that arrived before the
		 * accept is already sitting in the stream. */
		if (g_sock[sockid].flow)
			mtp_ready_arm(g_sock[sockid].flow);
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
/* Returns how many readiness entries it took, so the caller can tell "nothing
 * happened" from "something happened and was filed into g_sock". Returning void
 * is what made the blocking version sleep on top of work it had just collected:
 * the caller tested its own output counter, which is zero at that point by
 * construction. */
static int
shim_collect_ready(void)
{
	struct mtp_ready ready[64];
	int n, i;

	n = TransportPoll(g_shim_core, ready, 64);
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
	return n;
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
	int i, n = 0, got;

	(void)mctx; (void)epid;

	for (i = 0; i < SHIM_MAX_SOCK; i++)
		g_sock[i].ready = 0;

	/*
	 * DOES NOT PUMP THE TARGET. It used to call SchedStep here, which made
	 * the application's loop the stack's clock -- our inline design showing
	 * through the API. The stack now runs on its own thread, so this only
	 * TAKES what is already there and returns, including nothing.
	 *
	 * That is also what acquires the single-pass property for the shim.
	 * With the stack pumped from here, epserver's mtcp_write landed AFTER
	 * drain and send had run for that pass, so every write waited a further
	 * iteration. With the stack always running, a write reaches the ring
	 * and is drained by the pass already in flight.
	 */
	got = shim_collect_ready();

	/*
	 * BLOCK WHEN THERE IS NOTHING, as the donor does. mTCP's
	 * mtcp_epoll_wait with a negative timeout goes to pthread_cond_wait
	 * with no spin first, and its stack thread wakes it -- 15 695
	 * voluntary context switches a second on the donor's application
	 * thread against 0 on its stack thread (B, 2026-08-17).
	 *
	 * Returning immediately with nothing was our shim approximating that
	 * call rather than matching it. On one core with a stack thread that
	 * never blocks, the two threads then alternate only on preemption, at
	 * a 4 ms slice instead of the donor's 63.7 us -- which cost four
	 * fifths of our throughput.
	 */
	if (got == 0 && timeout != 0 && g_pend_head == g_pend_tail) {
		TransportWait(g_shim_core, timeout);
		shim_collect_ready();
	}

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
