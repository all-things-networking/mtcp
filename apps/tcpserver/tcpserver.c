/*
 * tcpserver — bind, listen, and serve one fixed object.
 *
 * The embryo of what M1d compares against mTCP's epserver, and deliberately
 * separate from upcheck. upcheck's whole worth is that it is small enough to
 * trust when nothing else works: it answers "is the NIC alive", and it stops
 * being able to answer that the moment it carries a socket API.
 *
 * Everything the application does goes through the app interface as an
 * operation (CR-7), never by reaching into a target table. That is the point:
 * an app op is how the program learns its own endpoint and builds the same flow
 * id the packet parser builds.
 */
#include <execinfo.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "infra.h"
#include "bringup.h"
#include "scheduler.h"
#include "contract.h"
#include "scheduler.h"

/*
 * The application, run once per iteration by SchedRun. Drains readiness and
 * reads. This is the first time the inbound direction reaches an application in
 * this target, so the three mechanisms underneath it — the flush instruction's
 * return, `delivered`, and the window rule's second recompute point — all run
 * here for the first time.
 *
 * The bytes are reported rather than trusted: what the application received is
 * printed, so a wrong return from the flush shows as wrong CONTENT rather than
 * as a number that merely looks plausible.
 */
/*
 * SELF-DESCRIBING: every 4-byte word holds its own offset, so any wrong byte
 * says where it came from rather than only that something is wrong.
 */
/*
 * The object served on a GET. Read from a file rather than generated here:
 * both arms must serve THE SAME BYTES, not the same recipe, or an object
 * difference is indistinguishable from a transport difference. bench/gen_object.py
 * writes it once on the shared mount and records its checksum.
 *
 * A built-in generator is kept for the smoke path only, where nothing is being
 * compared against anything.
 */
static uint8_t *g_obj;
static size_t   g_obj_len;

/*
 * Header plus body, built once. The response is identical for every request, so
 * building it per request would put a memcpy of the whole object on the serving
 * path and measure our own memory bandwidth as though it were transport cost.
 */
static uint8_t *g_resp;
static size_t   g_resp_len;

/*
 * WRITE_CHUNK — 8192, WHICH IS A PARITY VALUE AND NOT A BUFFER SIZE.
 *
 * epserver writes in 8192-byte chunks and loops until the write is refused
 * (epserver.c:30; B, 2026-08-13). The write pattern INTERLEAVES WITH THE DRAIN,
 * and that interleaving is what B measured when establishing that the donor
 * packs at 99.75% full segments. A different chunk size here would present as a
 * SEGMENTATION difference between the two arms — which is one of the things the
 * comparison exists to measure, so it would be a harness artefact wearing the
 * costume of a result.
 */
#define WRITE_CHUNK	8192

static size_t g_sent;		/* how much of the response has been accepted */

/*
 * Write until refused, exactly as epserver does. A short return is not an
 * error: it is backpressure, and the remainder goes when WRITABLE says so.
 */
static void
pump(flow_t *flow, uint32_t now)
{
	while (g_sent < g_resp_len) {
		struct mtp_app_op snd;
		size_t want = g_resp_len - g_sent;
		int wrote;

		if (want > WRITE_CHUNK)
			want = WRITE_CHUNK;

		memset(&snd, 0, sizeof(snd));
		snd.kind = MTP_APP_SEND;
		snd.flow = flow;
		snd.data.base = g_resp + g_sent;
		snd.data.len = want;
		snd.len = want;
		wrote = mtp_program_app_op(&snd, now);
		if (wrote <= 0)
			return;		/* refused: wait for WRITABLE */
		g_sent += (size_t)wrote;
		if ((size_t)wrote < want)
			return;		/* truncated: same */
	}

	{
		struct mtp_app_op cl;

		memset(&cl, 0, sizeof(cl));
		cl.kind = MTP_APP_CLOSE;
		cl.flow = flow;
		mtp_program_app_op(&cl, now);
		fprintf(stderr, "tcpserver: served %zu bytes\n", g_resp_len);
	}
}

static void
serve(struct core_ctx *core, uint32_t now, void *arg)
{
	struct mtp_ready ready[16];
	int n, i;

	(void)arg;
	n = TransportPoll(core, ready, 16);

	for (i = 0; i < n; i++) {
		static uint8_t buf[2048];
		struct mtp_app_op op;
		int got;

		/*
		 * D-23: the ring refused the rest of the object and the target
		 * is telling us there is room again. The application retries;
		 * the target does not absorb.
		 */
		if (ready[i].kinds & (1u << MTP_NOTIF_WRITABLE))
			pump(ready[i].flow, now);

		if (!(ready[i].kinds & (1u << MTP_NOTIF_READABLE)))
			continue;

		memset(&op, 0, sizeof(op));
		op.kind = MTP_APP_RECV;
		op.flow = ready[i].flow;
		op.data.base = buf;
		op.data.len = sizeof(buf) - 1;
		op.len = sizeof(buf) - 1;

		got = mtp_program_app_op(&op, now);
		if (got <= 0)
			continue;
		buf[got] = 0;

		/*
		 * Answer a GET. This is the ONLY place HTTP appears in this
		 * tree: it is the application's, exactly as it is the donor's
		 * (epserver parses the request and writes the header in its
		 * app). Nothing in src/target/ or the .mtp changed to make this
		 * work — DESIGN.md §17.1's layering test, and it held.
		 */
		if (!strncmp((char *)buf, "GET ", 4)) {
			g_sent = 0;
			fprintf(stderr, "tcpserver: answering \"%.20s\" with "
				"%zu bytes\n", (char *)buf, g_resp_len);
			pump(ready[i].flow, now);
		}
	}
}

/*
 * A crash here is a failing test (rule 5), and a failing test that leaves no
 * evidence costs a run to reproduce. Ubuntu routes cores to apport, so nothing
 * lands beside the binary; this prints the stack at the moment of the fault
 * instead, which is what one actually wants from a core anyway.
 */
static void
on_stop(int sig)
{
	(void)sig;
	SchedStopRequested = 1;
	/*
	 * write(2) and NOT fprintf. A signal handler may call only
	 * async-signal-safe functions; fprintf takes the stream lock, and this
	 * server prints a stat line every second, so the lock is contended by
	 * construction. The handler would deadlock, hang to the runner's
	 * timeout, and be force-killed — indistinguishable from the symptom it
	 * was added to diagnose.
	 */
	write(2, "STOP-HANDLER-RAN\n", 17);
}

static void
on_fatal(int sig)
{
	void *fr[32];
	int n = backtrace(fr, 32);

	fprintf(stderr, "\n*** FATAL signal %d — stack follows ***\n", sig);
	fflush(stderr);
	backtrace_symbols_fd(fr, n, 2);
	_exit(128 + sig);
}

int
main(int argc, char **argv)
{
	/*
	 * On an ALTERNATE STACK, which is the whole point: the first crash here
	 * produced no handler output at all, and a handler that cannot run is
	 * itself evidence — it means the ordinary stack was gone.
	 */
	{
		static char altstack[SIGSTKSZ * 4];
		stack_t ss = { .ss_sp = altstack, .ss_size = sizeof(altstack) };
		struct sigaction sa;

		sigaltstack(&ss, NULL);
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_fatal;
		sa.sa_flags = SA_ONSTACK;
		sigaction(SIGSEGV, &sa, NULL);
		sigaction(SIGABRT, &sa, NULL);
		sigaction(SIGBUS, &sa, NULL);

		/*
		 * SIGINT/SIGTERM end the run loop rather than the process, so
		 * the summary after SchedRun still prints. The runners stop a
		 * server with SIGINT and then SIGKILL; without this the
		 * counters are never reported and the transfer looks
		 * unmeasured. Our side of a defect the donor has too.
		 */
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_stop;
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
	}

	const char *conf = "tcpserver.conf";
	const char *bind_ip = NULL;
	const char *objpath = NULL;
	uint16_t port = 80;
	uint32_t ms = 0;
	int have_ms = 0, cpu = 0, i;
	struct core_ctx *core;
	struct mtp_app_op op;
	uint32_t ip;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-f") && i + 1 < argc)
			conf = argv[++i];
		else if (!strcmp(argv[i], "-s") && i + 1 < argc)
			bind_ip = argv[++i];
		else if (!strcmp(argv[i], "-p") && i + 1 < argc)
			port = (uint16_t)atoi(argv[++i]);
		else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
			ms = (uint32_t)atoi(argv[++i]);
			have_ms = 1;
		} else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
			objpath = argv[++i];
		} else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
			cpu = atoi(argv[++i]);
		} else {
			fprintf(stderr,
				"usage: %s -s <ip> -t <ms> [-p port] [-f conf] [-c cpu]\n"
				"       [-o object-file]  the shared object; without it a\n"
				"                         64 KB one is generated, which is\n"
				"                         a SMOKE object and not comparable\n"
				"       -t 0 runs until SIGINT\n", argv[0]);
			return 2;
		}
	}

	/*
	 * -s is not optional. mTCP's epserver segfaults in inet_addr(NULL)
	 * without it, and because the driver is bifurcated the KERNEL then
	 * still owns the data NIC and resets every SYN — which reads as "the
	 * server reset my connections" rather than "the server is not
	 * running". It cost a smoke run once already. Fail here instead.
	 */
	if (!bind_ip || !have_ms) {
		fprintf(stderr, "tcpserver: -s <ip> and -t <ms> are both required\n");
		return 2;
	}
	if (inet_pton(AF_INET, bind_ip, &ip) != 1) {
		fprintf(stderr, "tcpserver: %s is not an address\n", bind_ip);
		return 2;
	}

	if (InfraInit(conf) < 0)
		return 1;

	core = InfraCoreCreate(cpu);
	if (!core || TransportCoreInit(core) < 0) {
		fprintf(stderr, "tcpserver: cpu %d failed to come up\n", cpu);
		return 1;
	}

	memset(&op, 0, sizeof(op));
	op.kind = MTP_APP_BIND;
	op.local.ip = ip;
	op.local.port = htons(port);
	if (mtp_program_app_op(&op, 0) < 0) {
		fprintf(stderr, "tcpserver: the program does not bind `bind`\n");
		return 1;
	}
	op.kind = MTP_APP_LISTEN;
	if (mtp_program_app_op(&op, 0) < 0) {
		fprintf(stderr, "tcpserver: the program does not bind `listen`\n");
		return 1;
	}

	/* post the object to serve. One fixed object, as epserver serves one
	 * file, which is what M1d compares against. */
	if (objpath) {
		/*
		 * THE SHARED OBJECT. Read, not generated: both arms serve the
		 * same bytes from the same file on the shared mount, so a
		 * difference in what arrives cannot be a difference in what was
		 * served. bench/gen_object.py wrote it and recorded its
		 * checksum; this prints the length so the run log says which
		 * object it served without anyone having to infer it.
		 */
		FILE *f = fopen(objpath, "rb");
		long n;

		if (!f) {
			fprintf(stderr, "tcpserver: cannot open %s\n", objpath);
			return 1;
		}
		fseek(f, 0, SEEK_END);
		n = ftell(f);
		fseek(f, 0, SEEK_SET);
		if (n <= 0 || !(g_obj = malloc((size_t)n)) ||
		    fread(g_obj, 1, (size_t)n, f) != (size_t)n) {
			fprintf(stderr, "tcpserver: cannot read %s\n", objpath);
			return 1;
		}
		fclose(f);
		g_obj_len = (size_t)n;
		fprintf(stderr, "tcpserver: serving %zu bytes from %s\n",
			g_obj_len, objpath);
	} else {
		/*
		 * THE SMOKE OBJECT, and it is not comparable with anything.
		 * Self-describing — every 4-byte word holds its own offset, so
		 * a shifted copy announces its shift and stale data announces
		 * which region it came from — but generated here rather than
		 * shared, so it is for bring-up only.
		 */
		size_t i;

		g_obj_len = 65536;
		g_obj = malloc(g_obj_len);
		if (!g_obj)
			return 1;
		for (i = 0; i + 4 <= g_obj_len; i += 4) {
			uint32_t w = (uint32_t)i;

			memcpy(g_obj + i, &w, 4);
		}
		fprintf(stderr, "tcpserver: no -o; generating a %zu byte SMOKE "
			"object (not comparable across arms)\n", g_obj_len);
	}

	{
		int hdr;

		g_resp = malloc(g_obj_len + 256);
		if (!g_resp)
			return 1;
		/*
		 * THE DONOR'S RESPONSE HEADER, field for field — epserver.c:273.
		 *
		 * Rule 1 makes the donor the reference at the application layer
		 * too, and the two responses were not the same size: 145 bytes
		 * against our 63. That is 82 bytes per connection of extra data
		 * on the donor's wire for the same object, which confounded the
		 * byte comparison outright and about one frame of the
		 * frame comparison. Invisible to every check we had, because the
		 * delivered-content check compares the OBJECT and the frame
		 * counters do not look at contents.
		 *
		 * Byte-identity is not achievable: the donor stamps a Date. But
		 * strftime "%a, %d %b %Y %X GMT" is fixed-width at 29
		 * characters, so the LENGTH is constant at 145 and the two
		 * responses differ only in timestamp digits — which is where
		 * the donor differs from itself run to run. That is the ceiling.
		 *
		 * The literals name a protocol. This is application code under
		 * apps/, not target infrastructure, so rule 4's diff test is
		 * unaffected — do not "fix" it.
		 */
		char date[64];
		time_t now_t = time(NULL);

		strftime(date, sizeof(date), "%a, %d %b %Y %X GMT",
			 gmtime(&now_t));
		hdr = snprintf((char *)g_resp, 256,
			       "HTTP/1.1 200 OK\r\n"
			       "Date: %s\r\n"
			       "Server: Webserver on Middlebox TCP (Ubuntu)\r\n"
			       "Content-Length: %zu\r\n"
			       "Connection: Close\r\n\r\n", date, g_obj_len);
		memcpy(g_resp + hdr, g_obj, g_obj_len);
		g_resp_len = (size_t)hdr + g_obj_len;
		/* the header as bytes, so it can be DIFFED against the donor's
		 * rather than compared by length — equal length is not equal
		 * bytes (PLAN.md §3, second instance). */
		fprintf(stderr, "tcpserver: response header %d bytes: |%.*s|\n",
			hdr, hdr, (char *)g_resp);
	}

	fprintf(stderr, "tcpserver: listening on %s:%u; RUN WINDOW OPENS NOW, ",
		bind_ip, port);
	if (ms)
		fprintf(stderr, "%u ms\n", ms);
	else
		fprintf(stderr, "until SIGINT\n");

	SchedRun(core, ms, serve, NULL);

	TransportCoreFini(core);
	InfraCoreDestroy(core);
	InfraDestroy();

	fprintf(stderr, "tcpserver: RUN WINDOW CLOSED; clean exit\n");
	return 0;
}
