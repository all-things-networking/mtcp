#ifndef SOCKET_H
#define SOCKET_H

#include "mtcp_api.h"
#include "mtcp_epoll.h"

#include "mtp_params.h"

/*----------------------------------------------------------------------------*/
enum socket_opts
{
	MTCP_NONBLOCK		= 0x01,
	MTCP_ADDR_BIND		= 0x02, 
};
/*----------------------------------------------------------------------------*/
struct socket_map
{
	int id;
	int socktype;
	uint32_t opts;

	struct sockaddr_in saddr;

	union {
		struct tcp_stream *stream;
		struct mtp_listen_ctx *listen_ctx;	// MTP specific
		struct tcp_listener *listener;
		struct mtcp_epoll *ep;
		struct pipe *pp;
	};

	// MTP specific
	struct tcp_stream* rpcs[MTP_HOMA_MAX_RPC];
	uint32_t max_oustanding_rpc; //TODO: implement
	uint32_t cur_rpcs;

	uint32_t epoll;			/* registered events */
	uint32_t events[MTP_HOMA_MAX_RPC];		/* available events */
	mtcp_epoll_data_t ep_data;

	TAILQ_ENTRY (socket_map) free_smap_link;

};
/*----------------------------------------------------------------------------*/
typedef struct socket_map * socket_map_t;
/*----------------------------------------------------------------------------*/
socket_map_t 
AllocateSocket(mctx_t mctx, int socktype, int need_lock);
/*----------------------------------------------------------------------------*/
void 
FreeSocket(mctx_t mctx, int sockid, int need_lock); 
/*----------------------------------------------------------------------------*/
socket_map_t 
GetSocket(mctx_t mctx, int sockid);
/*----------------------------------------------------------------------------*/
int32_t 
GetNextRPCInd(mtcp_manager_t mtcp, int sockid);
/*----------------------------------------------------------------------------*/
struct tcp_listener
{
	int sockid;
	socket_map_t socket;

	int backlog;
	stream_queue_t acceptq;
	
	pthread_mutex_t accept_lock;
	pthread_cond_t accept_cond;

	TAILQ_ENTRY(tcp_listener) he_link;	/* hash table entry link */
};

// Wrapper structure for the MTP accept result queue
struct accept_res {
    struct tcp_stream *stream;
    TAILQ_ENTRY(accept_res) link;
};

// Accept result (connection) queue definition
TAILQ_HEAD(conn_queue, accept_res);

// Mark for compiler to generate this part and insert to the end of socket.h (add this context to mtp_ctx.h instead?)
struct mtp_listen_ctx {
    uint32_t local_ip;
    uint32_t local_port;
    uint8_t state;
    
	/* TAILQ of tcp_stream* */
    struct conn_queue pending;  // pending connections
	uint32_t pending_cap;

	// Target-specific fields
	uint32_t pending_len;
	socket_map_t socket;
    pthread_mutex_t accept_lock;
	pthread_cond_t accept_cond;
	TAILQ_ENTRY(mtp_listen_ctx) he_link;	/* hash table entry link */
};

/*----------------------------------------------------------------------------*/

#endif /* SOCKET_H */
