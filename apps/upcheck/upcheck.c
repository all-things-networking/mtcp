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
#include "arp.h"
#include "config.h"

int
main(int argc, char **argv)
{
	const char *conf = "upcheck.conf";
	uint32_t ms = 2000;
	struct core_ctx *core;
	uint32_t arp_target = 0;
	int cpu = 0;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-f") && i + 1 < argc)
			conf = argv[++i];
		else if (!strcmp(argv[i], "-t") && i + 1 < argc)
			ms = (uint32_t)atoi(argv[++i]);
		else if (!strcmp(argv[i], "-c") && i + 1 < argc)
			cpu = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-a") && i + 1 < argc)
			ParseIPAddress(&arp_target, argv[++i]);
		else {
			fprintf(stderr,
				"usage: %s [-f conf] [-t ms] [-c cpu] [-a peer-ip]\n"
				"       -t 0 runs until SIGINT\n"
				"       -a sends one ARP request for peer-ip\n",
				argv[0]);
			return 2;
		}
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

	fprintf(stderr, "upcheck: cpu %d up on %d interface(s); running %u ms\n",
		cpu, CONFIG.eths_num, ms);

	if (arp_target) {
		/* cur_ts is normally taken once per loop iteration; the loop has
		 * not started, so seed it. ARP's retry timer reads it. */
		core->cur_ts = 0;
		RequestARP(core, arp_target, 0, core->cur_ts);
		fprintf(stderr, "upcheck: ARP request queued for %u.%u.%u.%u\n",
			((uint8_t *)&arp_target)[0], ((uint8_t *)&arp_target)[1],
			((uint8_t *)&arp_target)[2], ((uint8_t *)&arp_target)[3]);
	}

	SchedRun(core, ms);

	InfraCoreDestroy(core);
	InfraDestroy();

	fprintf(stderr, "upcheck: clean exit\n");
	return 0;
}
