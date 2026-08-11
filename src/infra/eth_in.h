#ifndef ETH_IN_H
#define ETH_IN_H

#include "infra.h"

int
ProcessPacket(core_ctx_t core, const int ifidx, 
		uint32_t cur_ts, unsigned char *pkt_data, int len);

#endif /* ETH_IN_H */
