#include <string.h>
#include <netinet/ip.h>

#include "ip_in.h"
#include "upcall.h"
#include "debug.h"
#include "icmp.h"


#define ETH_P_IP_FRAG   0xF800
#define ETH_P_IPV6_FRAG 0xF6DD

/*----------------------------------------------------------------------------*/
inline int 
ProcessIPv4Packet(core_ctx_t core, uint32_t cur_ts, 
				  const int ifidx, unsigned char* pkt_data, int len)
{
	/* check and process IPv4 packets */
	struct iphdr* iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	int ip_len = ntohs(iph->tot_len);
	int rc = -1;

	/* drop the packet shorter than ip header */
	if (ip_len < sizeof(struct iphdr))
		return ERROR;

#ifndef DISABLE_HWCSUM
	if (core->iom->dev_ioctl != NULL)
		rc = core->iom->dev_ioctl(core->ctx, ifidx, PKT_RX_IP_CSUM, iph);
	if (rc == -1 && ip_fast_csum(iph, iph->ihl))
		return ERROR;
#else
	UNUSED(rc);
	if (ip_fast_csum(iph, iph->ihl))
		return ERROR;
#endif

#if !PROMISCUOUS_MODE
	/* if not promiscuous mode, drop if the destination is not myself */
	if (iph->daddr != CONFIG.eths[ifidx].ip_addr)
		//DumpIPPacketToFile(stderr, iph, ip_len);
		return TRUE;
#endif

	// see if the version is correct
	if (iph->version != 0x4 ) {
		core->iom->release_pkt(core->ctx, ifidx, pkt_data, len);
		return FALSE;
	}
	
	/* mTCP switches on IPPROTO_TCP here, which is where its IP layer stops
	 * being an IP layer. The number comes from the program instead; the
	 * switch becomes an if because a case label needs a constant
	 * expression and this one is resolved at link time. */
	if (iph->protocol == TRANSPORT_IP_PROTO)
		return TransportInput(core, cur_ts, ifidx, iph, ip_len);
	if (iph->protocol == IPPROTO_ICMP)
		return ProcessICMPPacket(core, iph, ip_len);

	/* currently drop other protocols */
	return FALSE;
}
/*----------------------------------------------------------------------------*/
