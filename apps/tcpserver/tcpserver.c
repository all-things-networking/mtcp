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
			struct mtp_app_op snd;

			memset(&snd, 0, sizeof(snd));
			snd.kind = MTP_APP_SEND;
			snd.flow = ready[i].flow;
			snd.data.base = g_resp;
			snd.data.len = g_resp_len;
			snd.len = g_resp_len;
			mtp_program_app_op(&snd, now);

			/* Connection: close — say so to the transport too */
			memset(&snd, 0, sizeof(snd));
			snd.kind = MTP_APP_CLOSE;
			snd.flow = ready[i].flow;
			mtp_program_app_op(&snd, now);

			fprintf(stderr, "tcpserver: served %zu bytes for "
				"\"%.20s\"\n", g_resp_len, (char *)buf);
		}
	}
}

int
main(int argc, char **argv)
{
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

		g_resp = malloc(g_obj_len + 128);
		if (!g_resp)
			return 1;
		hdr = snprintf((char *)g_resp, 128,
			       "HTTP/1.1 200 OK\r\n"
			       "Content-Length: %zu\r\n"
			       "Connection: close\r\n\r\n", g_obj_len);
		memcpy(g_resp + hdr, g_obj, g_obj_len);
		g_resp_len = (size_t)hdr + g_obj_len;
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
