#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Bring-up and teardown. Every step here is mTCP's, in mTCP's order, with the
 * transport's steps removed; the donor is mtcp-donor @7fbb223c and the line
 * numbers below are its core.c.
 *
 * The order is not arbitrary and is worth preserving as it stands: the address
 * pools are built from the interface list, the routing table is read after the
 * interfaces exist, and the I/O module is loaded last because loading it is
 * what calls rte_eal_init(), which wants the core mask the configuration just
 * produced.
 */
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>

#include "infra.h"
#include "bringup.h"
#include "cpu.h"
#include "config.h"
#include "arp.h"
#include "debug.h"
#ifndef DISABLE_DPDK
#include <rte_ethdev.h>	/* the port's own counters, at teardown — see below */
#endif

#define LOG_FILE_NAME "log"
#define MAX_FILE_NAME 1024

/* g_core, CONFIG and ap are defined in config.c, where the donor defines them
 * and where their defaults live. */
static struct thread_ctx *g_tctx[MAX_CPUS] = {0};

/*----------------------------------------------------------------------------*/
/* from mTCP core.c:94 HandleSignal, reduced to what one core needs: ask the
 * loop to stop. mTCP's version also counts repeated SIGINTs and hands the
 * signal to an application handler; neither exists yet. */
static void
HandleSignal(int signum)
{
	int i;

	for (i = 0; i < MAX_CPUS; i++) {
		if (g_tctx[i])
			g_tctx[i]->exit = TRUE;
	}
	(void)signum;
}
/*----------------------------------------------------------------------------*/
/* from mTCP core.c:1600 mtcp_init */
int
InfraInit(const char *config_file)
{
	int i;
	int ret;

	num_cpus = (CONFIG.num_cores == 0) ? GetNumCPUs() : CONFIG.num_cores;
	assert(num_cpus >= 1);

	if (num_cpus > MAX_CPUS) {
		TRACE_ERROR("Cannot run with more than %d cores; %d requested.\n",
			    MAX_CPUS, num_cpus);
		return -1;
	}

	for (i = 0; i < num_cpus; i++)
		g_core[i] = NULL;

	ret = LoadConfiguration(config_file);
	if (ret) {
		TRACE_CONFIG("Error occured while loading configuration.\n");
		return -1;
	}
	PrintConfiguration();

	for (i = 0; i < CONFIG.eths_num; i++) {
		ap[i] = CreateAddressPool(CONFIG.eths[i].ip_addr, 1);
		if (!ap[i]) {
			TRACE_CONFIG("Error occured while create address pool[%d]\n", i);
			return -1;
		}
	}

	PrintInterfaceInfo();

	ret = SetRoutingTable();
	if (ret) {
		TRACE_CONFIG("Error occured while loading routing table.\n");
		return -1;
	}
	PrintRoutingTable();

	LoadARPTable();
	PrintARPTable();

	if (signal(SIGINT, HandleSignal) == SIG_ERR) {
		perror("signal, SIGINT");
		return -1;
	}

	/* load system-wide io module specs — rte_eal_init() is in here */
	current_iomodule_func->load_module();

	return 0;
}
/*----------------------------------------------------------------------------*/
/*
 * from mTCP core.c:1171 MTCPRunThread and core.c:922 InitializeMTCPManager,
 * keeping the infrastructure half of each: affinitize, allocate, open the log,
 * take the I/O handle, attach the device.
 *
 * mTCP runs this on a thread it creates, and on DPDK it has to reach into
 * rte's private lcore_config to do so. Here the caller is already the thread
 * that will run the loop, so none of that is needed. The application thread —
 * and with it the second half of mTCP's arrangement — arrives with the socket
 * API, not before.
 */
struct core_ctx *
InfraCoreCreate(int cpu)
{
	struct core_ctx *core;
	struct thread_ctx *ctx;
	char log_name[MAX_FILE_NAME];
	int working;

	core_affinitize(cpu);

	/* after affinitization, so that this is local memory */
	ctx = calloc(1, sizeof(*ctx));
	core = calloc(1, sizeof(*core));
	if (!ctx || !core) {
		perror("calloc");
		free(ctx);
		free(core);
		return NULL;
	}

	ctx->cpu = cpu;
	ctx->thread = pthread_self();
	ctx->core = core;
	core->ctx = ctx;

	snprintf(log_name, MAX_FILE_NAME, LOG_FILE_NAME"_%d", cpu);
	core->log_fp = fopen(log_name, "w");
	if (!core->log_fp) {
		perror("fopen");
		goto fail;
	}
	/* core->logger and core->w_buffer stay NULL: mTCP's asynchronous log
	 * thread is only started when one of the DBG* macros is compiled in,
	 * and none is. flush_log_data() tolerates NULL; thread_printf() does
	 * not, and is only reachable from the packet dumpers. */

	g_core[cpu] = core;
	g_tctx[cpu] = ctx;

	core->iom = current_iomodule_func;
	core->iom->init_handle(ctx);

	mlockall(MCL_CURRENT);

	working = core->iom->link_devices(ctx);	/* core.c:146 AttachDevice */
	if (working != 0) {
		TRACE_ERROR("Failed to attach device on cpu %d.\n", cpu);
		goto fail;
	}

	TRACE_INFO("CPU %d: initialization finished.\n", cpu);
	return core;

fail:
	g_core[cpu] = NULL;
	g_tctx[cpu] = NULL;
	if (core->log_fp)
		fclose(core->log_fp);
	free(core);
	free(ctx);
	return NULL;
}
/*----------------------------------------------------------------------------*/
/*
 * What the PORT counted, as against what we counted.
 *
 * These two numbers answer different questions and confusing them costs hours.
 * `nstat` says how many packets this stack took off the receive queue; this
 * says how many the NIC accepted and how many it dropped before we got there.
 * A zero here and a zero there means the packets never reached the port. A
 * non-zero here and a zero there means we are not draining the queue we think
 * we are.
 *
 * mTCP has no equivalent — it reports only its own counters — which is why the
 * first zero-receive result in this tree could not be attributed by reading the
 * log. It is cheap and it runs once, at teardown.
 */
static void
ReportPortCounters(void)
{
#ifndef DISABLE_DPDK
	int i;

	for (i = 0; i < CONFIG.eths_num; i++) {
		struct rte_eth_stats st;
		uint16_t portid = CONFIG.eths[i].ifindex;

		if (rte_eth_stats_get(portid, &st) != 0)
			continue;
		TRACE_INFO("port %u (%s): promisc=%d allmulti=%d "
			   "ipackets=%lu ibytes=%lu imissed=%lu "
			   "ierrors=%lu rx_nombuf=%lu opackets=%lu\n",
			   portid, CONFIG.eths[i].dev_name,
			   rte_eth_promiscuous_get(portid),
			   rte_eth_allmulticast_get(portid),
			   (unsigned long)st.ipackets, (unsigned long)st.ibytes,
			   (unsigned long)st.imissed, (unsigned long)st.ierrors,
			   (unsigned long)st.rx_nombuf,
			   (unsigned long)st.opackets);
	}
#endif
}
/*----------------------------------------------------------------------------*/
void
InfraCoreDestroy(struct core_ctx *core)
{
	struct thread_ctx *ctx = core->ctx;

	ReportPortCounters();

	core->iom->destroy_handle(ctx);		/* from mTCP core.c:1524 */

	if (core->log_fp)
		fclose(core->log_fp);

	g_core[ctx->cpu] = NULL;
	g_tctx[ctx->cpu] = NULL;
	free(core);
	free(ctx);
}
/*----------------------------------------------------------------------------*/
/* from mTCP core.c:1679 mtcp_destroy, minus the thread joins — there are no
 * threads to join yet. */
void
InfraDestroy(void)
{
	int i;

	for (i = 0; i < CONFIG.eths_num; i++)
		DestroyAddressPool(ap[i]);

#ifndef DISABLE_DPDK
	mpz_clear(CONFIG._cpumask);
#endif
}
