#include "mtp.h"

#include <linux/tcp.h>

#include "tcp_stream.h"
#include "fhash.h"

/*----------------------------------------------------------------------------*/
static inline int 
FilterSYNPacket(mtcp_manager_t mtcp, uint32_t ip, uint16_t port)
{
	struct sockaddr_in *addr;
	struct tcp_listener *listener;

	/* TODO: This listening logic should be revised */

	/* if not the address we want, drop */
	listener = (struct tcp_listener *)ListenerHTSearch(mtcp->listeners, &port);
	if (listener == NULL)	return FALSE;

	addr = &listener->socket->saddr;

	if (addr->sin_port == port) {
		if (addr->sin_addr.s_addr != INADDR_ANY) {
			if (ip == addr->sin_addr.s_addr) {
				return TRUE;
			}
			return FALSE;
		} else {
			int i;

			for (i = 0; i < CONFIG.eths_num; i++) {
				if (ip == CONFIG.eths[i].ip_addr) {
					return TRUE;
				}
			}
			return FALSE;
		}
	}

	return FALSE;
}

/*----------------------------------------------------------------------------*/
static inline tcp_stream *
CreateNewFlowHTEntry(mtcp_manager_t mtcp, uint32_t cur_ts, const struct iphdr *iph, 
		int ip_len, const struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		int payloadlen, uint16_t window)
{
	tcp_stream *cur_stream;
	int ret; 
	
	if (tcph->syn && !tcph->ack) {
		/* handle the SYN */
		ret = FilterSYNPacket(mtcp, iph->daddr, tcph->dest);
		if (!ret) {
			TRACE_DBG("Refusing SYN packet.\n");
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);

			return NULL;
		}

		/* now accept the connection */
		cur_stream = HandlePassiveOpen(mtcp, 
				cur_ts, iph, tcph, seq, window);
		if (!cur_stream) {
			TRACE_DBG("Not available space in flow pool.\n");
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);

			return NULL;
		}

		return cur_stream;
	} else if (tcph->rst) {
		TRACE_DBG("Reset packet comes\n");
#ifdef DBGMSG
		DumpIPPacket(mtcp, iph, ip_len);
#endif
		/* for the reset packet, just discard */
		return NULL;
	} else {
		TRACE_DBG("Weird packet comes.\n");
#ifdef DBGMSG
		DumpIPPacket(mtcp, iph, ip_len);
#endif
		/* TODO: for else, discard and send a RST */
		/* if the ACK bit is off, respond with seq 0: 
		   <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
		   else (ACK bit is on):
		   <SEQ=SEG.ACK><CTL=RST>
		   */
		if (tcph->ack) {
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					ack_seq, 0, 0, TCP_FLAG_RST, NULL, 0, cur_ts, 0);
		} else {
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);
		}
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/
int
MTP_ProcessTransportPacket(mtcp_manager_t mtcp, 
		 uint32_t cur_ts, const int ifidx, const struct iphdr *iph, int ip_len)
{
	// MTP: maps to extract in the parser
	struct tcphdr* tcph = (struct tcphdr *) ((u_char *)iph + (iph->ihl << 2));
	uint8_t *payload    = (uint8_t *)tcph + (tcph->doff << 2);
	int payloadlen = ip_len - (payload - (u_char *)iph);


	tcp_stream s_stream;
	tcp_stream *cur_stream = NULL;
	//uint32_t seq = ntohl(tcph->seq);
	//uint32_t ack_seq = ntohl(tcph->ack_seq);
	//uint16_t window = ntohs(tcph->window);
	//uint16_t check;
	//int ret;
	//int rc = -1;

	/* TBA to MTP: Check ip packet invalidation */	
	if (ip_len < ((iph->ihl + tcph->doff) << 2))
		return ERROR;

	// TBA to MTP: checksum validation
#if VERIFY_RX_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx,
					  PKT_RX_TCP_CSUM, NULL);
#endif
	if (rc == -1) {
		check = TCPCalcChecksum((uint16_t *)tcph, 
					(tcph->doff << 2) + payloadlen, iph->saddr, iph->daddr);
		if (check) {
			TRACE_DBG("Checksum Error: Original: 0x%04x, calculated: 0x%04x\n", 
				  tcph->check, TCPCalcChecksum((uint16_t *)tcph, 
				  (tcph->doff << 2) + payloadlen, iph->saddr, iph->daddr));
			tcph->check = 0;
			return ERROR;
		}
	}
#endif

#if defined(NETSTAT) && defined(ENABLELRO)
	mtcp->nstat.rx_gdptbytes += payloadlen;
#endif /* NETSTAT */

	// MTP: maps to flow id generation in parser
	s_stream.saddr = iph->daddr;
	s_stream.sport = tcph->dest;
	s_stream.daddr = iph->saddr;
	s_stream.dport = tcph->source;

	if (!(cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream))) {
		/* not found in flow table */
		cur_stream = CreateNewFlowHTEntry(mtcp, cur_ts, iph, ip_len, tcph, 
				seq, ack_seq, payloadlen, window);
		if (!cur_stream)
			return TRUE;
	}

	/*
	// Validate sequence. if not valid, ignore the packet
	if (cur_stream->state > TCP_ST_SYN_RCVD) {
		ret = ValidateSequence(mtcp, cur_stream, 
				cur_ts, tcph, seq, ack_seq, payloadlen);
		if (!ret) {
			TRACE_DBG("Stream %d: Unexpected sequence: %u, expected: %u\n",
					cur_stream->id, seq, cur_stream->rcv_nxt);
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
#ifdef DUMP_STREAM
			DumpStream(mtcp, cur_stream);
#endif
			return TRUE;
		}
	}

	// Update receive window size
	if (tcph->syn) {
		cur_stream->sndvar->peer_wnd = window;
	} else {
		cur_stream->sndvar->peer_wnd = 
				(uint32_t)window << cur_stream->sndvar->wscale_peer;
	}
				
	cur_stream->last_active_ts = cur_ts;
	UpdateTimeoutList(mtcp, cur_stream);

	// Process RST: process here only if state > TCP_ST_SYN_SENT
	if (tcph->rst) {
		cur_stream->have_reset = TRUE;
		if (cur_stream->state > TCP_ST_SYN_SENT) {
			if (ProcessRST(mtcp, cur_stream, ack_seq)) {
				return TRUE;
			}
		}
	}

	
	switch (cur_stream->state) {
	case TCP_ST_LISTEN:
		Handle_TCP_ST_LISTEN(mtcp, cur_ts, cur_stream, tcph);
		break;

	case TCP_ST_SYN_SENT:
		Handle_TCP_ST_SYN_SENT(mtcp, cur_ts, cur_stream, iph, tcph, 
				seq, ack_seq, payloadlen, window);
		break;

	case TCP_ST_SYN_RCVD:
		// SYN retransmit implies our SYN/ACK was lost. Resend 
		if (tcph->syn && seq == cur_stream->rcvvar->irs)
			Handle_TCP_ST_LISTEN(mtcp, cur_ts, cur_stream, tcph);
		else {
			Handle_TCP_ST_SYN_RCVD(mtcp, cur_ts, cur_stream, tcph, ack_seq);
			if (payloadlen > 0 && cur_stream->state == TCP_ST_ESTABLISHED) {
				Handle_TCP_ST_ESTABLISHED(mtcp, cur_ts, cur_stream, tcph,
							  seq, ack_seq, payload,
							  payloadlen, window);
			}
		}
		break;

	case TCP_ST_ESTABLISHED:
		Handle_TCP_ST_ESTABLISHED(mtcp, cur_ts, cur_stream, tcph, 
				seq, ack_seq, payload, payloadlen, window);
		break;

	case TCP_ST_CLOSE_WAIT:
		Handle_TCP_ST_CLOSE_WAIT(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payloadlen, window);
		break;

	case TCP_ST_LAST_ACK:
		Handle_TCP_ST_LAST_ACK(mtcp, cur_ts, iph, ip_len, cur_stream, tcph, 
				seq, ack_seq, payloadlen, window);
		break;
	
	case TCP_ST_FIN_WAIT_1:
		Handle_TCP_ST_FIN_WAIT_1(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payload, payloadlen, window);
		break;

	case TCP_ST_FIN_WAIT_2:
		Handle_TCP_ST_FIN_WAIT_2(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq, 
				payload, payloadlen, window);
		break;

	case TCP_ST_CLOSING:
		Handle_TCP_ST_CLOSING(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payloadlen, window);
		break;

	case TCP_ST_TIME_WAIT:
		// the only thing that can arrive in this state is a retransmission 
		//   of the remote FIN. Acknowledge it, and restart the 2 MSL timeout 
		if (cur_stream->on_timewait_list) {
			RemoveFromTimewaitList(mtcp, cur_stream);
			AddtoTimewaitList(mtcp, cur_stream, cur_ts);
		}
		AddtoControlList(mtcp, cur_stream, cur_ts);
		break;

	case TCP_ST_CLOSED:
		break;

	}
	*/
	return TRUE;
}
