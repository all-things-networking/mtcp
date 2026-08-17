#include "ip_out.h"
#include "upcall.h"
#include "ip_in.h"
#include "eth_out.h"
#include "arp.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
inline int
GetOutputInterface(uint32_t daddr, uint8_t *is_external)
{
	int nif = -1;
	int i;
	int prefix = 0;

	*is_external = 0;
	/* Longest prefix matching */
	for (i = 0; i < CONFIG.routes; i++) {
		if ((daddr & CONFIG.rtable[i].mask) == CONFIG.rtable[i].masked) {
			if (CONFIG.rtable[i].prefix > prefix) {
				nif = CONFIG.rtable[i].nif;
				prefix = CONFIG.rtable[i].prefix;
			} else if (CONFIG.gateway) {
				*is_external = 1;
				nif = (CONFIG.gateway)->nif;
			}
			break;
		}
	}

	if (nif < 0) {
		uint8_t *da = (uint8_t *)&daddr;
		TRACE_ERROR("[WARNING] No route to %u.%u.%u.%u\n", 
				da[0], da[1], da[2], da[3]);
		assert(0);
	}
	
	return nif;
}
/*----------------------------------------------------------------------------*/
uint8_t *
IPOutputStandalone(struct core_ctx *core, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t payloadlen)
{
	struct iphdr *iph;
	int nif;
	unsigned char * haddr, is_external;
	int rc = -1;

	nif = GetOutputInterface(daddr, &is_external);
	if (nif < 0)
		return NULL;

	haddr = GetDestinationHWaddr(daddr, is_external);
	if (!haddr) {
#if 0
		uint8_t *da = (uint8_t *)&daddr;
		TRACE_INFO("[WARNING] The destination IP %u.%u.%u.%u "
				"is not in ARP table!\n",
				da[0], da[1], da[2], da[3]);
#endif
		RequestARP(core, (is_external) ? ((CONFIG.gateway)->daddr) : daddr,
			   nif, core->cur_ts);
		return NULL;
	}
	
	iph = (struct iphdr *)EthernetOutput(core, 
			ETH_P_IP, nif, haddr, payloadlen + IP_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(IP_HEADER_LEN + payloadlen);
	iph->id = htons(ip_id);
	iph->frag_off = htons(IP_DF);	// no fragmentation
	iph->ttl = 64;
	iph->protocol = protocol;
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->check = 0;

#ifndef DISABLE_HWCSUM	
        if (core->iom->dev_ioctl != NULL) {
		if (iph->protocol == TRANSPORT_IP_PROTO)
			rc = core->iom->dev_ioctl(core->ctx, nif, PKT_TX_L3L4_CSUM_PEEK, iph);
		else if (iph->protocol == IPPROTO_ICMP)
			rc = core->iom->dev_ioctl(core->ctx, nif, PKT_TX_IP_CSUM, iph);
	}
	/* otherwise calculate IP checksum in S/W */
	if (rc == -1)
		iph->check = ip_fast_csum(iph, iph->ihl);
#else
	UNUSED(rc);
	iph->check = ip_fast_csum(iph, iph->ihl);
#endif

	return (uint8_t *)(iph + 1);
}
/*----------------------------------------------------------------------------*/
uint8_t *
IPOutput(struct core_ctx *core, int *nif_out, uint8_t *is_external,
	 uint32_t saddr, uint32_t daddr, uint8_t protocol,
	 uint16_t ip_id, uint8_t tos, uint16_t payloadlen)
{
	struct iphdr *iph;
	int nif;
	unsigned char *haddr;
	int rc = -1;

	if (*nif_out >= 0) {
		nif = *nif_out;
	} else {
		nif = GetOutputInterface(daddr, is_external);
		*nif_out = nif;
	}

	haddr = GetDestinationHWaddr(daddr, *is_external);
	if (!haddr) {
		/* if not found in the arp table, send arp request and return NULL.
		 * the caller retries sending the packet later */
		RequestARP(core, (*is_external) ? (CONFIG.gateway)->daddr : daddr,
			   nif, core->cur_ts);
		core->last_ipout_fail = IPOUT_NO_ARP;
		return NULL;
	}

	iph = (struct iphdr *)EthernetOutput(core, ETH_P_IP,
			nif, haddr, payloadlen + IP_HEADER_LEN);
	if (!iph) {
		core->last_ipout_fail = IPOUT_NO_FRAME;
		return NULL;
	}

	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;
	iph->tos = tos;			/* the blueprint's outer class; 0 = mTCP */
	iph->tot_len = htons(IP_HEADER_LEN + payloadlen);
	iph->id = htons(ip_id);
	iph->frag_off = htons(0x4000);	// no fragmentation
	iph->ttl = 64;
	iph->protocol = protocol;
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->check = 0;

#ifndef DISABLE_HWCSUM
	/* offload IP checkum if possible */
	if (core->iom->dev_ioctl != NULL) {
		if (iph->protocol == TRANSPORT_IP_PROTO)
			rc = core->iom->dev_ioctl(core->ctx, nif, PKT_TX_L3L4_CSUM_PEEK, iph);
		else if (iph->protocol == IPPROTO_ICMP)
			rc = core->iom->dev_ioctl(core->ctx, nif, PKT_TX_IP_CSUM, iph);
	}
	/* otherwise calculate IP checksum in S/W */
	if (rc == -1)
		iph->check = ip_fast_csum(iph, iph->ihl);
#else
	UNUSED(rc);
	iph->check = ip_fast_csum(iph, iph->ihl);
#endif
	return (uint8_t *)(iph + 1);
}
