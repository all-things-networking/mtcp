/*
 * upcheck — bring the target up on the NIC, run the loop, put it down again.
 *
 * There is no transport yet, so there is nothing to ask it to do. What this
 * proves is the thing that is expensive to discover later: that the seeded
 * plumbing initialises, that DPDK claims the configured interface, that the
 * receive path reaches the target's upcall, and that the process exits without
 * leaving hugepages or an EAL socket behind.
 *
 * With `-a <ip>` it also emits one ARP request and waits for the reply. That is
 * not decoration. A check that only listens cannot tell a broken transmit path
 * from a quiet network, and on a bifurcated driver — where the kernel keeps the
 * interface and the PMD receives only what its steering rules match — it cannot
 * tell "nothing was sent to us" from "nothing is being steered to us" either.
 * One request and one reply distinguishes all four, using only seeded code.
 *
 * It runs for a bounded time by default. Rule 5: a hang is a failing test, and
 * a bring-up check that cannot end on its own is one that takes the node off
 * the network when it goes wrong.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "infra.h"
#include "bringup.h"
#include "scheduler.h"
#include "flow_table.h"
#include "arp.h"
#include "config.h"

int
main(int argc, char **argv)
{
	const char *conf = "upcheck.conf";
	/*
	 * No default. Every failing run of the zero-receive investigation
	 * started upcheck with the old 2000 ms default and sent traffic seconds
	 * later, after it had already exited — which produced a clean "ARP
	 * arrives, IPv4 never does" signature, because -a probes at startup and
	 * lands inside the window while everything else lands outside it. Two
	 * days of a bug that did not exist. -t is now mandatory.
	 */
	uint32_t ms = 0;
	int have_ms = 0;
	struct core_ctx *core;
	uint32_t arp_target = 0;
	int cpu = 0;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-f") && i + 1 < argc)
			conf = argv[++i];
		else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
			ms = (uint32_t)atoi(argv[++i]);
			have_ms = 1;
		}
		else if (!strcmp(argv[i], "-c") && i + 1 < argc)
			cpu = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-a") && i + 1 < argc)
			ParseIPAddress(&arp_target, argv[++i]);
		else {
			fprintf(stderr,
				"usage: %s -t <ms> [-f conf] [-c cpu] [-a peer-ip]\n"
				"       -t is REQUIRED; -t 0 runs until SIGINT\n"
				"       -a sends one ARP request for peer-ip\n",
				argv[0]);
			return 2;
		}
	}

	if (!have_ms) {
		fprintf(stderr, "upcheck: -t <ms> is required. Traffic sent "
			"outside the run window looks exactly like traffic "
			"that never arrived.\n");
		return 2;
	}

	if (InfraInit(conf) < 0) {
		fprintf(stderr, "upcheck: initialisation failed\n");
		return 1;
	}

	core = InfraCoreCreate(cpu);
	if (!core) {
		fprintf(stderr, "upcheck: cpu %d failed to come up\n", cpu);
		return 1;
	}

	if (TransportCoreInit(core) < 0) {
		fprintf(stderr, "upcheck: transport state allocation failed\n");
		return 1;
	}

	if (ms)
		fprintf(stderr, "upcheck: cpu %d up on %d interface(s); "
			"RUN WINDOW OPENS NOW, %u ms\n", cpu, CONFIG.eths_num, ms);
	else
		fprintf(stderr, "upcheck: cpu %d up on %d interface(s); "
			"RUN WINDOW OPENS NOW, until SIGINT\n",
			cpu, CONFIG.eths_num);

	if (arp_target) {
		/* cur_ts is normally taken once per loop iteration; the loop has
		 * not started, so seed it. ARP's retry timer reads it. */
		core->cur_ts = 0;
		RequestARP(core, arp_target, 0, core->cur_ts);
		fprintf(stderr, "upcheck: ARP request queued for %u.%u.%u.%u\n",
			((uint8_t *)&arp_target)[0], ((uint8_t *)&arp_target)[1],
			((uint8_t *)&arp_target)[2], ((uint8_t *)&arp_target)[3]);
	}

	SchedRun(core, ms, NULL, NULL);

	TransportCoreFini(core);
	InfraCoreDestroy(core);
	InfraDestroy();

	fprintf(stderr, "upcheck: RUN WINDOW CLOSED after %u ms; clean exit\n", ms);
	return 0;
}
