#ifndef MTP_H
#define MTP_H

#include <netinet/ip.h>

#include "mtcp.h"

#define MTP_NO_EVENT -1
#define MTP_SYN 0

int
MTP_ProcessTransportPacket(struct mtcp_manager *mtcp, uint32_t cur_ts, const int ifidx,
					const struct iphdr* iph, int ip_len);


#endif
