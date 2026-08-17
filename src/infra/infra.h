#ifndef INFRA_H
#define INFRA_H
/*
 * The infrastructure layer's central header — what mTCP's mtcp.h is, minus the
 * transport.
 *
 * Written for this target rather than seeded, because mtcp.h is the file where
 * the donor's layering breaks down: one struct holds the NIC handle, the log
 * buffers, the flow table, the send queues, the RTO store and the epoll state.
 * DESIGN.md §1.1 draws a line under the transport, and this header is that
 * line. Everything here is below it; nothing here knows what a connection is.
 *
 * Structures kept verbatim from mTCP mtcp-donor @7fbb223c mtcp/src/include/mtcp.h
 * are marked. Keeping their field order and spelling is not sentiment: the
 * seeded .c files below read them, and a `diff` against the donor is supposed
 * to stay readable (docs/DECISIONS.md D-07).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>
#ifndef DISABLE_DPDK
#include <gmp.h>
#endif
#include <linux/if_ether.h>	/* ETH_ALEN */

#ifndef TRUE
#define TRUE (1)
#endif
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef ERROR
#define ERROR (-1)
#endif

/* from mTCP io_engine/include/ps.h. The PacketShader headers are not carried —
 * this target has one I/O module — but the donor's device and ring ceilings
 * are, because they size arrays the seeded code indexes. */
#define MAX_DEVICES			16
#define MAX_RINGS			64

/* from mTCP mtcp.h. Header lengths below the transport only; the L4 header is
 * the program's business and its length is not a constant here. */
#define ETHERNET_HEADER_LEN		14  // sizeof(struct ethhdr)
#define IP_HEADER_LEN			20  // sizeof(struct iphdr)

#define MAX_PKT_SIZE			(2*1024)
#define ETH_NUM				MAX_DEVICES

#define PROMISCUOUS_MODE		TRUE

#ifndef MAX_CPUS
#define MAX_CPUS			16
#endif

#ifdef NETSTAT
#define NETSTAT_PERTHREAD		TRUE
#define NETSTAT_TOTAL			TRUE
#endif /* NETSTAT */

/* included here rather than at the top because they size arrays from the
 * ceilings above — mTCP gets away with the other order only because ps.h is
 * included first everywhere */
#include "memory_mgt.h"
#include "logger.h"
#include "stat.h"
#include "io_module.h"
#include "addr_pool.h"

/* from mTCP tcp_util.h, renamed for rule 4 — it is a comparison of numbers on a
 * circle, and nothing about it is a transport protocol. arp.c uses it on
 * timestamps, which is the clearest evidence the donor's name was wrong. */
#define SEQ_LT(a,b)			((int32_t)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)			((int32_t)((a)-(b)) <= 0)
#define SEQ_GT(a,b)			((int32_t)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)			((int32_t)((a)-(b)) >= 0)

/*
 * The clock, from mTCP tcp_in.h:46-62. Pure unit conversion — it sits in the
 * donor's TCP header only because that is where somebody put it, and every one
 * of these names is protocol-free.
 *
 * HZ = 1000 is the tick, and it is parity-relevant: the donor's timers are
 * measured in these ticks and its retransmission timeout has neither a floor
 * nor a ceiling, so the tick size is what bounds it from below.
 */
#define HZ				1000
#define TIME_TICK			(1000000/HZ)		// in us
#define TIMEVAL_TO_TS(t)		(uint32_t)((t)->tv_sec * HZ +	\
					((t)->tv_usec / TIME_TICK))

#define TS_TO_USEC(t)			((t) * TIME_TICK)
#define TS_TO_MSEC(t)			(TS_TO_USEC(t) / 1000)
#define USEC_TO_TS(t)			((t) / TIME_TICK)
#define MSEC_TO_TS(t)			(USEC_TO_TS((t) * 1000))
#define SEC_TO_TS(t)			(t * HZ)

#define SEC_TO_USEC(t)			((t) * 1000000)
#define SEC_TO_MSEC(t)			((t) * 1000)
#define MSEC_TO_USEC(t)			((t) * 1000)
#define USEC_TO_SEC(t)			((t) / 1000000)

/* add macro if it is not defined in /usr/include/sys/queue.h */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	     (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	     (var) = (tvar))
#endif
/*----------------------------------------------------------------------------*/
/* from mTCP mtcp.h — unchanged */
struct eth_table
{
	char dev_name[128];
	int ifindex;
	int stat_print;
	unsigned char haddr[ETH_ALEN];
	uint32_t netmask;
	uint32_t ip_addr;
};
/*----------------------------------------------------------------------------*/
struct route_table
{
	uint32_t daddr;
	uint32_t mask;
	uint32_t masked;
	int prefix;
	int nif;
};
/*----------------------------------------------------------------------------*/
struct arp_entry
{
	uint32_t ip;
	int8_t prefix;
	uint32_t ip_mask;
	uint32_t ip_masked;
	unsigned char haddr[ETH_ALEN];
};
/*----------------------------------------------------------------------------*/
struct arp_table
{
	struct arp_entry *entry;
	struct arp_entry *gateway;
	int entries;
};
/*----------------------------------------------------------------------------*/
/* from mTCP mtcp.h `struct mtcp_config`, with the transport's keys removed.
 *
 * The donor kept tcp_timeout and tcp_timewait here. They are protocol
 * parameters, not machine configuration, so under rule 4 and DESIGN.md §7.2
 * they belong to the program: config.c hands any key it does not recognise to
 * ProgConfigKey(). Buffer sizes stay, because the target sizes its own
 * mempools from them before any program runs.
 */
struct infra_config
{
	/* network interface config */
	struct eth_table *eths;
	int *nif_to_eidx; // mapping physic port indexes to that of the configured port-list
	int eths_num;

	/* route config */
	struct route_table *rtable;		// routing table
	struct route_table *gateway;
	int routes;						// # of entries

	/* arp config */
	struct arp_table arp;

	int num_cores;
	int num_mem_ch;
	int max_concurrency;
#ifndef DISABLE_DPDK
	mpz_t _cpumask;
#endif

	int max_num_buffers;
	int rcvbuf_size;
	int sndbuf_size;

	/* adding multi-process support */
	uint8_t multi_process;
	uint8_t multi_process_is_master;
};
/*----------------------------------------------------------------------------*/
/* from mTCP mtcp.h `struct mtcp_thread_context`, minus the transport's queue
 * locks. This is the handle the I/O module is given; it must stay the type
 * io_module.h names, or the seeded PMD glue does not compile. */
struct thread_ctx
{
	int cpu;
	pthread_t thread;
	uint8_t done:1,
		exit:1,
		interrupt:1;

	struct core_ctx *core;

	void *io_private_context;
};
typedef struct thread_ctx *thread_ctx_t;
/*----------------------------------------------------------------------------*/
/*
 * The per-core stack instance, below the transport.
 *
 * mTCP's `struct mtcp_manager` is this plus the whole of TCP. What is left when
 * the transport is taken out is: the NIC, the clock, the log, and the counters.
 * The transport hangs off `transport`, which infrastructure allocates nothing
 * for, frees nothing of, and never dereferences.
 */
struct core_ctx
{
	struct thread_ctx *ctx;
	struct io_module_func *iom;

	/* read once per main-loop iteration and used for every timestamp in the
	 * stack for that iteration — a parity-relevant property of both
	 * references (DESIGN.md §3.5, mTCP core.c:790). */
	uint32_t cur_ts;

	/* the same instant in microseconds, from the same gettimeofday: cur_ts
	 * is 1 ms ticks and cannot separate a 100 us round trip from a 28 ms one */
	uint64_t cur_us;

	/*
	 * Why the last IPOutput returned NULL. It has TWO unrelated NULL
	 * returns -- an ARP miss, which is a lookup that should succeed on a
	 * configured peer, and EthernetOutput refusing, which is the transmit
	 * buffer being full and is ordinary back-pressure. The caller cannot
	 * tell them apart from the return value, and collapsing them is the
	 * inherited debt B identified in the donor. One field, so the caller
	 * can count them separately.
	 */
	enum { IPOUT_OK = 0, IPOUT_NO_ARP, IPOUT_NO_FRAME } last_ipout_fail;

	/* variables related to logger */
	int sp_fd;
	log_thread_context *logger;
	log_buff *w_buffer;
	FILE *log_fp;

	/* statistics — from mTCP mtcp.h, same fields, so the per-second
	 * `[ ALL ]` line the measurement procedure reads stays the donor's */
	struct bcast_stat bstat;
	struct timeout_stat tstat;
#ifdef NETSTAT
	struct net_stat nstat;
	struct net_stat p_nstat;
	uint32_t p_nstat_ts;

	struct run_stat runstat;
	struct run_stat p_runstat;

	struct time_stat rtstat;
#endif /* NETSTAT */

	/* the layer above. Opaque here, by construction. */
	void *transport;
};
typedef struct core_ctx *core_ctx_t;
/*----------------------------------------------------------------------------*/
extern struct core_ctx *g_core[MAX_CPUS];
extern struct infra_config CONFIG;
extern addr_pool_t ap[ETH_NUM];
/*----------------------------------------------------------------------------*/
#endif /* INFRA_H */
