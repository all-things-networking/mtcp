#ifndef IO_MODULE_H
#define IO_MODULE_H
/*----------------------------------------------------------------------------*/
/* for type def'ns */
#include <stdint.h>
#include <netinet/ip.h>
/* for ps lib funcs */
#ifndef DISABLE_DPDK
/* for dpdk/onvm big ints */
#include <gmp.h>
#endif
/*----------------------------------------------------------------------------*/
/**
 * Declaration to soothe down the warnings 
 */
struct thread_ctx;
/**
 * io_module_funcs - contains template for the various 10Gbps pkt I/O
 *                 - libraries that can be adopted.
 *
 *		   load_module()    : Used to set system-wide I/O module 
 *				      initialization.
 *
 *                 init_handle()    : Used to initialize the driver library
 *                                  : Also use the context to create/initialize
 *                                  : a private packet I/O data structures.
 *
 *                 link_devices()   : Used to add link(s) to the core stack.
 *				      Returns 0 on success; -1 on failure.
 *
 *		   release_pkt()    : release the packet if mTCP does not need
 *				      to process it (e.g. non-IPv4, non-TCP pkts).
 *
 *		   get_wptr()	    : retrieve the next empty pkt buffer for the 
 * 				      application for packet writing. Returns
 *				      ptr to pkt buffer.
 *
 *		   send_pkts()	    : transmit batch of packets via interface 
 * 				      idx (=nif). 
 *				      Returns 0 on success; -1 on failure
 *
 *		   get_rptr()	    : retrieve next pkt for application for
 *				      packet read.
 *				      Returns ptr to pkt buffer.
 *			       
 *		   recv_pkts()	    : recieve batch of packets from the interface, 
 *				      ifidx.
 *				      Returns no. of packets that are read from
 *				      the iface.
 *
 *		   select()	    : for blocking I/O
 *
 *		   destroy_handle() : free up resources allocated during 
 * 				      init_handle(). Normally called during 
 *				      process termination.
 *
 *                 dev_ioctl()      : contains submodules for select drivers
 *		   
 */
typedef struct io_module_func {
	void	  (*load_module)(void);
	void      (*init_handle)(struct thread_ctx *ctx);
	int32_t   (*link_devices)(struct thread_ctx *ctx);
	void      (*release_pkt)(struct thread_ctx *ctx, int ifidx, unsigned char *pkt_data, int len);
	uint8_t * (*get_wptr)(struct thread_ctx *ctx, int ifidx, uint16_t len);
	int32_t   (*send_pkts)(struct thread_ctx *ctx, int nif);
	uint8_t * (*get_rptr)(struct thread_ctx *ctx, int ifidx, int index, uint16_t *len);
	int32_t   (*recv_pkts)(struct thread_ctx *ctx, int ifidx);
	int32_t	  (*select)(struct thread_ctx *ctx);
	void	  (*destroy_handle)(struct thread_ctx *ctx);
	int32_t	  (*dev_ioctl)(struct thread_ctx *ctx, int nif, int cmd, void *argp);
} io_module_func __attribute__((aligned(__WORDSIZE)));
/*----------------------------------------------------------------------------*/
/* set I/O module context */
int SetNetEnv(char *port_list, char *port_stat_list);

/* retrive device-specific endian type */
int FetchEndianType();
/*----------------------------------------------------------------------------*/
/* ptr to the `running' I/O module context */
extern io_module_func *current_iomodule_func;

/*
 * What a transmit-checksum offload request has to say when the L4 header is
 * opaque.
 *
 * mTCP casts to `struct tcphdr` inside the PMD glue to find the checksum field
 * and the header length. That is protocol knowledge two layers below the
 * transport, and it is the sharpest instance of the thing rule 4 exists to
 * prevent — a name grep would not have caught it, because `tcph->doff` names no
 * protocol. Here the two numbers arrive as offsets: the target knows the header
 * length because the blueprint carries it, and the program declares where its
 * checksum field sits.
 */
struct l4_csum_req {
	struct iphdr *iph;
	uint16_t l4_hdr_len;		/* bytes, from the blueprint */
	uint16_t l4_csum_offset;	/* of the 16-bit field, within the L4 header */
};

/* dev_ioctl related macros */
#define PKT_TX_IP_CSUM          0x01
#define PKT_TX_L4_CSUM         0x02
#define PKT_RX_L4_LROSEG	0x03
#define PKT_TX_L3L4_CSUM	0x04
#define PKT_RX_IP_CSUM		0x05
#define PKT_RX_L4_CSUM		0x06
#define PKT_TX_L3L4_CSUM_PEEK	0x07
#define DRV_NAME		0x08

/* registered dpdk context — the only I/O module this target carries. mTCP also
 * registers psio, netmap and onvm here; all three are compiled out of the
 * donor's own build (its Makefile sets PS=0 NETMAP=0 ONVM=0), so nothing that
 * has ever been measured is lost by not carrying them. */
extern io_module_func dpdk_module_func;

/* check I/O module access permissions */
int
CheckIOModuleAccessPermissions();

/* Macro to assign IO module */
#define AssignIOModule(m) {						\
		if (!strcmp(m, "dpdk"))					\
			current_iomodule_func = &dpdk_module_func;	\
		else							\
			assert(0);					\
	}
/*----------------------------------------------------------------------------*/
#endif /* IO_MODULE_H */
