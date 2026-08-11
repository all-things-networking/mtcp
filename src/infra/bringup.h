#ifndef BRINGUP_H
#define BRINGUP_H
/*
 * Bringing the machine up and putting it back down: configuration, the address
 * pools, the routing and ARP tables, the I/O module, and one per-core context
 * attached to the NIC.
 *
 * mTCP does all of this in core.c, interleaved with creating the flow pools,
 * the socket map, the send queues and the RTO store. Only the first half is
 * infrastructure. The second half is the transport's and lives in src/target/.
 *
 * Provenance is per function, in bringup.c. This file is not seeded: pulling a
 * quarter of a 1700-line file across as a deletion diff would be less readable
 * than writing the quarter and naming where each piece came from, and rule 3
 * ranks readability with correctness.
 */
#include "infra.h"

/* Process-wide. Reads the configuration file, builds the interface, routing
 * and ARP tables, and loads the I/O module (which for DPDK is where
 * rte_eal_init() happens). Returns 0, or -1 with the reason already logged. */
int InfraInit(const char *config_file);

/* Per core, on the thread that will run it — it affinitizes itself first, so
 * that everything allocated afterwards is local memory. Attaches the NIC
 * queues for this core. Returns NULL on failure. */
struct core_ctx *InfraCoreCreate(int cpu);

void InfraCoreDestroy(struct core_ctx *core);
void InfraDestroy(void);

#endif /* BRINGUP_H */
