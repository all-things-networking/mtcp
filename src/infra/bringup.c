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
void
InfraCoreDestroy(struct core_ctx *core)
{
	struct thread_ctx *ctx = core->ctx;

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
