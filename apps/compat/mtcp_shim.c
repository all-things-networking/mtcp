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
	uint8_t on_rdy;		/* already on g_rdy this pass; keeps it duplicate-free */
	flow_t	*flow;		/* NULL = free, or the listener */
	uint32_t interest;	/* what epoll_ctl last asked for */
	uint32_t ready;		/* what the target reported this iteration */
	uint8_t	 in_use;
	int	 next_free;	/* free-list link; valid only while !in_use */
	uint8_t	 is_listener;
};

/*
 * The shim's own flow->socket table, indexed by the flow's identifier
 * (DESIGN.md §24, ruling 3). Not keyed on the flow pointer: the shim does not
 * own that pointer's lifetime, and a recycled slot would hand it one it had
 * seen before belonging to a different connection.
 */
/*
 * The sockets with readiness set THIS pass. Replaces two O(SHIM_MAX_SOCK)
 * walks per call: one to clear every flag and one to find the few that were
 * set. Measured 2026-08-17: mtcp_epoll_wait was 25.58% of the whole process --
 * two thirds of the application thread -- doing 8192 slot visits per call to
 * service at most 8 live sockets, 7.2 billion visits in one run, 0.098% of
 * them useful. mTCP's own path is not O(registered sockets); we added that.
 */
static int     g_rdy[SHIM_MAX_SOCK];
static int     g_sock_free = -1;	/* head of the free socket list */
static int     g_rdy_n;

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
};

static struct shim_flow_state g_flow[SHIM_MAX_SOCK];
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
	int i = g_sock_free;

	/*
	 * A FREE LIST, NOT A SEARCH. This was a linear walk of the whole table
	 * looking for a clear `in_use` -- the same shape as the readiness scan
	 * that turned out to be 25.58% of the process (RESULTS 2026-08-17).
	 *
	 * It is COLD, once per accept, and this buys nothing measurable. It is
	 * changed because leaving one instance of a shape in place after
	 * removing the other is how the next person learns it is acceptable.
	 */
	if (i < 0) {
		errno = EMFILE;
		return -1;
	}
	g_sock_free = g_sock[i].next_free;
	g_sock[i].in_use = 1;
	g_sock[i].flow = flow;
	g_sock[i].interest = 0;
	g_sock[i].is_listener = 0;
	if (flow)
		fstate(flow)->sockid = i;
	return i;
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
	{
		int i;

		/* descending, so ids are handed out ascending */
		g_sock_free = -1;
		for (i = SHIM_MAX_SOCK - 1; i > SHIM_LISTENER; i--) {
			g_sock[i].next_free = g_sock_free;
			g_sock_free = i;
		}
	}

	/*
	 * THE CORE COUNT COMES FROM setconf, NOT ONLY FROM THE CONF FILE.
	 *
	 * The donor takes it from the command line -- epwget's -N, via
	 * mtcp_getconf / mtcp_setconf -- and its own client configuration on
	 * this testbed carries no `num_cores` line at all. Ours read the conf
	 * only, so CONFIG.num_cores stayed 0, the EAL coremask came out 0, and
	 * the client died with "No lcores in coremask: [0]" before reaching any
	 * of the stack.
	 *
	 * Applied BEFORE InfraInit so the conf file can still override it, which
	 * is the donor's precedence: the file is the deployment and the flag is
	 * the request.
	 */
	if (g_conf.num_cores > 0)
		CONFIG.num_cores = g_conf.num_cores;

	if (InfraInit(config_file) < 0) {
		fprintf(stderr, "mtcp_shim: InfraInit(%s) failed\n",
			config_file ? config_file : "(null)");
		return -1;
	}

	/*
	 * THREE BOUNDS THAT MUST AGREE, AND NOTHING USED TO CHECK.
	 *
	 * SHIM_MAX_SOCK sizes g_sock, g_flow and g_rdy here; the target sizes
	 * its flow and blueprint pools from CONFIG.max_concurrency
	 * (flow.c:26-37). THE THIRD USED TO BE SHIM_PENDING, bounding an accept
	 * backlog this layer had no business owning; the program's
	 * PROG_MAX_BACKLOG and the application's own listen() argument bound it
	 * now. Today the remaining two happen to fit because the conf says
	 * 4096 -- a defensive constant that silently agrees is worse than one
	 * that disagrees, because it teaches you it is safe.
	 *
	 * fstate() indexes g_flow by the target's flow id, so if the conf ever
	 * exceeds SHIM_MAX_SOCK the failure is an abort inside fstate on a
	 * perfectly valid flow, long after the cause. Fail here instead, where
	 * the number that is wrong is on the screen.
	 */
	if (CONFIG.max_concurrency > SHIM_MAX_SOCK) {
		fprintf(stderr, "mtcp_shim: max_concurrency %d exceeds "
			"SHIM_MAX_SOCK %d -- the shim's socket and flow tables "
			"are indexed by flow id and would be overrun\n",
			CONFIG.max_concurrency, SHIM_MAX_SOCK);
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
	/* The shim's accept queue and its two counters are gone: the backlog is
	 * the listen context's, and overflow is a SYN the PROGRAM drops. */
}
int  mtcp_core_affinitize(int cpu)     { (void)cpu; return 0; }
int  mtcp_setsock_nonblock(mctx_t m, int s) { (void)m; (void)s; return 0; }

/*----------------------------------------------------------------------------*/
/* Listener. */

int
mtcp_socket(mctx_t mctx, int domain, int type, int protocol)
{
	(void)mctx; (void)domain; (void)type; (void)protocol;
	/*
	 * THE FIRST SOCKET IS THE LISTENER'S FIXED ID, and every one after it
	 * is allocated. epserver compares a ready socket against SHIM_LISTENER
	 * to decide whether to accept, so that id has to be the one its listener
	 * gets -- and it makes exactly one socket before accepting anything.
	 *
	 * A CLIENT MAKES MANY. epwget calls socket() once per connection, and
	 * returning the same id each time gave every connection the same entry.
	 * The listening branch is kept rather than special-cased away because
	 * one application depends on it and the other does not care which id it
	 * gets.
	 */
	if (!g_sock[SHIM_LISTENER].in_use) {
		g_sock[SHIM_LISTENER].in_use = 1;
		g_sock[SHIM_LISTENER].is_listener = 1;
		g_sock[SHIM_LISTENER].flow = NULL;
		return SHIM_LISTENER;
	}
	return sock_alloc(NULL);	/* a client socket; connect gives it a flow */
}

/*
 * THE BOUND ENDPOINT, REMEMBERED BY THE SHIM. The donor's API names a listener
 * by socket id; the target's op schema names one by endpoint, because a context
 * is found by the key the program builds. Bridging the two is exactly what this
 * layer is for, and it means bind's address has to survive until listen.
 *
 * One entry, because SHIM_LISTENER is one socket. If the shim ever grows a
 * second listening socket this becomes a field of g_sock, not a second global.
 */
static struct mtp_endpoint g_bound;

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
	g_bound = op.local;
	return mtp_program_app_op(&op, 0) < 0 ? -1 : 0;
}

int
mtcp_listen(mctx_t mctx, int sockid, int backlog)
{
	struct mtp_app_op op;

	(void)mctx; (void)sockid;
	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_LISTEN;
	/* WHICH endpoint starts answering, and HOW MANY it may hold. Both were
	 * discarded here: the program had one listener and no backlog, so
	 * neither had anywhere to go. */
	op.local = g_bound;
	op.len = backlog > 0 ? (uint32_t)backlog : 0;
	if (mtp_program_app_op(&op, 0) < 0)
		return -1;
	/* The LISTENING endpoint's handle, so readiness on it can be recognised
	 * as this socket's. It is a context like any other and has a flow. */
	g_sock[SHIM_LISTENER].flow = op.flow;
	return 0;
}

/*----------------------------------------------------------------------------*/
/*
 * Connect, and the local port.
 *
 * THE CLIENT APPLICATION DOES NOT CHANGE. This is the donor's own epwget,
 * unmodified, and the only thing different underneath is the stack -- which is
 * the whole point of comparisons 2 and 3 in docs/TEST-MATRIX.md.
 *
 * WHO PICKS THE LOCAL PORT is DEFERRED.md B4 and still undecided. The donor
 * allocates from a per-core address pool in mtcp_connect and fails EAGAIN when
 * exhausted; here the shim picks, which is what B4 records as the interim
 * position. It is protocol policy in TCP and not obviously so in general, so it
 * does not belong in the program by default and it certainly does not belong in
 * the target.
 *
 * The range is the donor's ephemeral range and the walk is linear from the last
 * one handed out, which is not the donor's hash-based allocation. Two clients
 * on one host would collide; one does not.
 */
static uint32_t g_local_ip;
static uint16_t g_next_port = 32768;

int
mtcp_init_rss(mctx_t mctx, in_addr_t saddr_base, int num_addr,
	      in_addr_t daddr, in_addr_t dport)
{
	(void)mctx; (void)num_addr; (void)daddr; (void)dport;
	/*
	 * epwget PASSES INADDR_ANY. `saddr` in epwget.c is set once, to
	 * INADDR_ANY, and never assigned again -- so taking the argument
	 * literally sent every SYN from 0.0.0.0, which the peer drops and which
	 * no reply can return to. The donor resolves it through its per-core
	 * address pool, which is built from the interface's own address.
	 *
	 * Ours is the interface address directly. The pool is the port walk in
	 * mtcp_connect; there is one interface and one core.
	 */
	g_local_ip = saddr_base;
	if (g_local_ip == INADDR_ANY && CONFIG.eths_num > 0)
		g_local_ip = CONFIG.eths[0].ip_addr;
	return 0;
}

int
mtcp_connect(mctx_t mctx, int sockid, const struct sockaddr *addr,
	     socklen_t addrlen)
{
	const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
	struct mtp_app_op op;

	(void)mctx; (void)addrlen;
	if (sockid <= 0 || sockid >= SHIM_MAX_SOCK || !g_sock[sockid].in_use)
		return -1;

	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_CONNECT;
	op.local.ip = g_local_ip;
	op.local.port = htons(g_next_port++);
	if (g_next_port == 0)
		g_next_port = 32768;
	op.remote.ip = in->sin_addr.s_addr;
	op.remote.port = in->sin_port;

	if (mtp_program_app_op(&op, g_shim_core ? g_shim_core->cur_ts : 0) < 0
	    || !op.flow) {
		errno = EAGAIN;
		return -1;
	}
	g_sock[sockid].flow = op.flow;
	fstate(op.flow)->sockid = sockid;

	/*
	 * EINPROGRESS, which is what epwget expects: it sets the socket
	 * non-blocking and treats anything else as a failure. The connection
	 * completes when the SYN-ACK arrives and the program raises WRITABLE,
	 * which is the donor's RaiseWriteEvent.
	 */
	errno = EINPROGRESS;
	return -1;
}

/*----------------------------------------------------------------------------*/
/*
 * Accept.
 *
 * THE QUEUE MOVED INTO THE PROGRAM. This layer used to keep its own -- a
 * SHIM_PENDING ring of 64, filled from readiness for any flow with no socket id
 * yet -- because the target had no accept call. That put the accept BACKLOG,
 * which is protocol state, in the compatibility layer: `pending_cap` had
 * nowhere to live, so a SYN arriving with a full queue had nothing to be
 * dropped against and the overflow was a shim counter.
 *
 * Now `app_accept` is an event, the listen context owns `pending` and
 * `pending_cap`, and this is what it always should have been: a translation of
 * one call into one operation.
 */
int
mtcp_accept(mctx_t mctx, int sockid, struct sockaddr *addr, socklen_t *addrlen)
{
	struct mtp_app_op op;

	(void)mctx; (void)sockid; (void)addr; (void)addrlen;
	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_ACCEPT;
	op.local = g_bound;		/* which listener; the op names it */
	if (mtp_program_app_op(&op, 0) < 0 || !op.flow) {
		errno = EAGAIN;
		return -1;
	}
	return sock_alloc(op.flow);
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
	/* after the memset, or it would be zeroed away */
	if (sockid != SHIM_LISTENER) {
		g_sock[sockid].next_free = g_sock_free;
		g_sock_free = sockid;
	}
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

		/*
		 * THE LISTENING ENDPOINT. The program raises READABLE on the
		 * listen context when a handshake completes (D9, and the
		 * donor's shape), so this is "a connection is waiting" and it
		 * belongs to SHIM_LISTENER.
		 */
		if (f == g_sock[SHIM_LISTENER].flow) {
			g_sock[SHIM_LISTENER].ready |= MTCP_EPOLLIN;
			continue;
		}
		/* Not the listener and no socket id: a flow the application has
		 * not accepted and cannot be told about. It stays queued in the
		 * program until accept() takes it. */
		if (sid <= 0 || sid >= SHIM_MAX_SOCK || g_sock[sid].flow != f)
			continue;

		if (ready[i].kinds & (1u << MTP_NOTIF_READABLE))
			g_sock[sid].ready |= MTCP_EPOLLIN;
		if (ready[i].kinds & (1u << MTP_NOTIF_WRITABLE))
			g_sock[sid].ready |= MTCP_EPOLLOUT;
		/* one entry per socket per pass; the flag is the guard */
		if (g_sock[sid].ready && !g_sock[sid].on_rdy
		    && g_rdy_n < SHIM_MAX_SOCK) {
			g_sock[sid].on_rdy = 1;
			g_rdy[g_rdy_n++] = sid;
		}
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
	int i, k, n = 0, got;

	(void)mctx; (void)epid;

	/* Clear only what was set last pass -- g_rdy names exactly those. */
	for (i = 0; i < g_rdy_n; i++) {
		g_sock[g_rdy[i]].ready = 0;
		g_sock[g_rdy[i]].on_rdy = 0;
	}
	g_rdy_n = 0;

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
	if (got == 0 && timeout != 0 && !g_sock[SHIM_LISTENER].ready) {
		TransportWait(g_shim_core, timeout);
		shim_collect_ready();
	}

	/* The listener first: epserver checks for it by socket id and accepts
	 * everything queued before looking at the rest. */
	if ((g_sock[SHIM_LISTENER].ready & MTCP_EPOLLIN) && n < maxevents &&
	    (g_sock[SHIM_LISTENER].interest & MTCP_EPOLLIN)) {
		events[n].events = MTCP_EPOLLIN;
		events[n].data.sockid = SHIM_LISTENER;
		n++;
		/* Level-triggering is the PROGRAM's: proc_accept re-raises
		 * while its queue is non-empty, so clearing here cannot lose a
		 * waiting connection. */
		g_sock[SHIM_LISTENER].ready &= ~(uint32_t)MTCP_EPOLLIN;
	}

	for (k = 0; k < g_rdy_n && n < maxevents; k++) {
		uint32_t hit;

		i = g_rdy[k];
		if (i == SHIM_LISTENER || !g_sock[i].in_use)
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
