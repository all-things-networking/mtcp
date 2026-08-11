#ifndef IP_IN_H
#define IP_IN_H

#include "infra.h"
#include "ip_csum.h"	/* mTCP gets ip_fast_csum from ps.h, which is not carried */

int
ProcessIPv4Packet(core_ctx_t core, uint32_t cur_ts, 
				  const int ifidx, unsigned char* pkt_data, int len);

#endif /* IP_IN_H */
