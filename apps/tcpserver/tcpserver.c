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

int
main(int argc, char **argv)
{
	const char *conf = "tcpserver.conf";
	const char *bind_ip = NULL;
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
		} else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
			cpu = atoi(argv[++i]);
		} else {
			fprintf(stderr,
				"usage: %s -s <ip> -t <ms> [-p port] [-f conf] [-c cpu]\n"
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

	fprintf(stderr, "tcpserver: listening on %s:%u; RUN WINDOW OPENS NOW, ",
		bind_ip, port);
	if (ms)
		fprintf(stderr, "%u ms\n", ms);
	else
		fprintf(stderr, "until SIGINT\n");

	SchedRun(core, ms);

	TransportCoreFini(core);
	InfraCoreDestroy(core);
	InfraDestroy();

	fprintf(stderr, "tcpserver: RUN WINDOW CLOSED; clean exit\n");
	return 0;
}
