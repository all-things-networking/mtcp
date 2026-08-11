#ifndef ETH_OUT_H
#define ETH_OUT_H

#include <stdint.h>

#include "infra.h"

#define MAX_SEND_PCK_CHUNK 64

uint8_t *
EthernetOutput(struct core_ctx *core, uint16_t h_proto, 
		int nif, unsigned char* dst_haddr, uint16_t iplen);

#endif /* ETH_OUT_H */
