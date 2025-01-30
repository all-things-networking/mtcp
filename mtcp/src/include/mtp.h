#ifndef MTP_H
#define MTP_H

#include <netinet/ip.h>

#include "mtcp.h"
#include "tcp_stream.h"

#define MTP_NO_EVENT -1
#define MTP_SYN 0

typedef struct scratchpad_decl {
	uint8_t change_cwnd;
	uint8_t skip_ack_eps;
} scratchpad;

int 
MTP_recv_chain(mtcp_manager_t mtcp, tcp_stream *cur_stream,
                char* buf, int len, socket_map_t socket);

void 
MTP_ProcessSendEvents(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh);

int
MTP_ProcessTransportPacket(struct mtcp_manager *mtcp, uint32_t cur_ts, const int ifidx,
					const struct iphdr* iph, int ip_len);


#endif
