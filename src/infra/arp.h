#ifndef ARP_H
#define ARP_H

#define MAX_ARPENTRY 1024

int 
InitARPTable();

unsigned char * 
GetHWaddr(uint32_t ip);

unsigned char *
GetDestinationHWaddr(uint32_t dip, uint8_t is_gateway);

void 
RequestARP(core_ctx_t core, uint32_t ip, int nif, uint32_t cur_ts);

int 
ProcessARPPacket(core_ctx_t core, uint32_t cur_ts,
		const int ifidx, unsigned char* pkt_data, int len);

void 
ARPTimer(core_ctx_t core, uint32_t cur_ts);

void 
PrintARPTable();

#endif /* ARP_H */
