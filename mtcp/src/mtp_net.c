#include "mtp_net.h"
#include "mtp_ep.h"
#include "fhash.h"
#include "debug.h"
#include "tcp_out.h"
#include "tcp_util.h"
#include "timer.h"

// Helper functions
/*----------------------------------------------------------------------------*/
static inline int HandleMissingCtx(mtcp_manager_t mtcp, 
	const struct iphdr *iph, struct tcphdr* tcph,
	uint32_t seq, int payloadlen, uint32_t cur_ts) {
	// TODO? This can be considered as processor for an "error" event
    TRACE_DBG("Refusing packet: context not found.\n");
	SendTCPPacketStandalone(mtcp, 
		iph->daddr, tcph->dest, iph->saddr, tcph->source, 
		0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
		NULL, 0, cur_ts, 0);
	return TRUE;
}

/*----------------------------------------------------------------------------*/
static inline int ValidatePacketHeader(mtcp_manager_t mtcp, const int ifidx,  
	const struct iphdr *iph, int ip_len, struct tcphdr* tcph) {
	// IP validation
	if (ip_len < ((iph->ihl + tcph->doff) << 2))
		return ERROR;

	// Checksum validation
#if VERIFY_RX_CHECKSUM
	int rc = 0;
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx, PKT_RX_TCP_CSUM, NULL);
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

	return 0;
}

/*----------------------------------------------------------------------------*/
// Copied from tcp_in.c
static inline int ValidateSequence(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, 
	struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, int payloadlen)
{
	/* Protect Against Wrapped Sequence number (PAWS) */
	if (!tcph->rst && cur_stream->saw_timestamp) {
		struct tcp_timestamp ts;
		
		if (!ParseTCPTimestamp(cur_stream, &ts, 
				(uint8_t *)tcph + TCP_HEADER_LEN, 
				(tcph->doff << 2) - TCP_HEADER_LEN)) {
			/* if there is no timestamp */
			/* TODO: implement here */
			TRACE_DBG("No timestamp found.\n");
			return FALSE;
		}

		/* RFC1323: if SEG.TSval < TS.Recent, drop and send ack */
		if (TCP_SEQ_LT(ts.ts_val, cur_stream->rcvvar->ts_recent)) {
			/* TODO: ts_recent should be invalidated 
					 before timestamp wraparound for long idle flow */
			TRACE_DBG("PAWS Detect wrong timestamp. "
					"seq: %u, ts_val: %u, prev: %u\n", 
					seq, ts.ts_val, cur_stream->rcvvar->ts_recent);
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
			return FALSE;
		} else {
			/* valid timestamp */
			if (TCP_SEQ_GT(ts.ts_val, cur_stream->rcvvar->ts_recent)) {
				TRACE_TSTAMP("Timestamp update. cur: %u, prior: %u "
					"(time diff: %uus)\n", 
					ts.ts_val, cur_stream->rcvvar->ts_recent, 
					TS_TO_USEC(cur_ts - cur_stream->rcvvar->ts_last_ts_upd));
				cur_stream->rcvvar->ts_last_ts_upd = cur_ts;
			}

			cur_stream->rcvvar->ts_recent = ts.ts_val;
			cur_stream->rcvvar->ts_lastack_rcvd = ts.ts_ref;
		}
	}

	/* TCP sequence validation */
	if (!TCP_SEQ_BETWEEN(seq + payloadlen, cur_stream->rcv_nxt, 
				cur_stream->rcv_nxt + cur_stream->rcvvar->rcv_wnd)) {

		/* if RST bit is set, ignore the segment */
		if (tcph->rst)
			return FALSE;

		if (cur_stream->state == TCP_ST_ESTABLISHED) {
			/* check if it is to get window advertisement */
			if (seq + 1 == cur_stream->rcv_nxt) {
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
				return FALSE;

			}

			if (TCP_SEQ_LEQ(seq, cur_stream->rcv_nxt)) {
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
			} else {
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
			}
		} else {
			if (cur_stream->state == TCP_ST_TIME_WAIT) {
				TRACE_DBG("Stream %d: tw expire update to %u\n", 
						cur_stream->id, cur_stream->rcvvar->ts_tw_expire);
				AddtoTimewaitList(mtcp, cur_stream, cur_ts);
			}
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
		return FALSE;
	}

	return TRUE;
}


/***********************************************
 MTP net interface
 ***********************************************/
// Net RX 
int MTP_ProcessTransportPacket(mtcp_manager_t mtcp, 
	uint32_t cur_ts, const int ifidx, const struct iphdr *iph, int ip_len) 
{
	/* RX parser(parse_net_packet) + incoming net events' "dispatcher"
	   incoming net events are "created" from parsing, and dispatched to eps directly
	   following a "run-to-completion model" */
	
	// MTP: maps to extract in the parser
	struct tcphdr* tcph = (struct tcphdr *) ((u_char *)iph + (iph->ihl << 2));
	uint8_t *payload    = (uint8_t *)tcph + (tcph->doff << 2);

	int payloadlen = ip_len - (payload - (u_char *)iph);
    bool is_syn = tcph->syn;
    bool is_ack = tcph->ack;
	uint32_t seq = ntohl(tcph->seq);
	uint32_t ack_seq = ntohl(tcph->ack_seq);
	uint16_t window = ntohs(tcph->window);
	uint32_t local_ip = iph->daddr;
    uint16_t local_port = tcph->dest;
	uint32_t remote_ip = iph->saddr;
	uint16_t remote_port = tcph->source;

	// TBA to MTP: validate header
	int ret = ValidatePacketHeader(mtcp, ifidx, iph, ip_len, tcph);
	if (ret != 0) return TRUE;

#if defined(NETSTAT) && defined(ENABLELRO)
	mtcp->nstat.rx_gdptbytes += payloadlen;
#endif /* NETSTAT */

    // MTP: maps to SYN event
    if (is_syn && !is_ack){
		// Listen context lookup
        struct mtp_listen_ctx *listen_ctx = 
			(struct mtp_listen_ctx *)ListenerHTSearch(mtcp->listeners, &local_port);
        if (listen_ctx == NULL) {
            return HandleMissingCtx(mtcp, iph, tcph, seq, payloadlen, cur_ts);
        }           

        MtpSynChain(mtcp, cur_ts, iph->saddr, tcph->source, seq, window, 
			local_ip, local_port, tcph, listen_ctx);
        return 0;
    }
	
	// MTP: maps to flow id generation in parser
	tcp_stream s_stream;
    s_stream.saddr = local_ip;
	s_stream.sport = local_port;
	s_stream.daddr = remote_ip;
	s_stream.dport = remote_port;

    // Context lookup
	tcp_stream *cur_stream = NULL;
	if (!(cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream))) {
        return HandleMissingCtx(mtcp, iph, tcph, seq, payloadlen, cur_ts);
    }

	// TBA to MTP: validate sequence
	ret = ValidateSequence(mtcp, cur_stream, cur_ts, tcph, seq, ack_seq, payloadlen);
	if (ret == 0) return TRUE;

	// TBA to MTP?: update peer window
	cur_stream->sndvar->peer_wnd = (uint32_t)window << cur_stream->sndvar->wscale_peer;

	// MTP TODO: SYN_ACK event

	// MTP: maps to DATA event
	if (payloadlen > 0){
		MtpDataChain(mtcp, cur_ts, seq, payload, payloadlen, cur_stream);
    } 
	
	// MTP: maps to ACK event
	if (is_ack){
        MtpAckChain(mtcp, cur_ts, tcph, seq, ack_seq, payloadlen, window, cur_stream);
    }
	
	return TRUE;
}

// Net TX
// MTP Note: the SEND event is not fully inline with MTP's tcp code because
//           data len is not in it and the data is already copied
//           and recorded in the flow context (tcp_stream) before getting here.
void MTP_ProcessSendEvents(mtcp_manager_t mtcp, struct mtcp_sender *sender, 
	uint32_t cur_ts, int thresh) 
{
	tcp_stream *cur_stream, *next, *last;

	// Loop through flows and send data
	int cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->send_list);
	last = TAILQ_LAST(&sender->send_list, send_head);

	while (cur_stream) {
		if (++cnt > thresh) break;

		TRACE_LOOP("Inside send loop. cnt: %u, stream: %d\n", 
			cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->send_link);

		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		if (cur_stream->sndvar->on_send_list) {
            int ret = MtpSendChain(mtcp, cur_ts, cur_stream); 
			if (ret < 0) {
				// No available write buffer, retry sending later and break
				TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
				break;
			} else {
				cur_stream->sndvar->on_send_list = FALSE;
				sender->send_list_cnt--;
				// MTP TODO: the ret value is the number of packets sent.
				// decrease ack_cnt for the piggybacked acks
			}
		}

		if (cur_stream == last) break;
		cur_stream = next;
	}
}