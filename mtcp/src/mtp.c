#include "mtp.h"

#include <linux/tcp.h>


#include "tcp_stream.h"
#include "tcp_ring_buffer.h"
#include "fhash.h"
#include "debug.h"
#include "ip_out.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))
#define TCP_CALCULATE_CHECKSUM      TRUE
#define TCP_MAX_WINDOW 65535

/*----------------------------------------------------------------------------*/
static inline uint16_t
CalculateOptionLength(uint8_t flags)
{
	uint16_t optlen = 0;

	if (flags & TCP_FLAG_SYN) {
		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK) {
			optlen += TCP_OPT_SACK_LEN + 2;
		}
#endif
	}

	assert(optlen % 4 == 0);

	return optlen;
}
/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPTimestamp(tcp_stream *cur_stream, uint8_t *tcpopt, uint32_t cur_ts)
{
	uint32_t *ts = (uint32_t *)(tcpopt + 2);

	tcpopt[0] = TCP_OPT_TIMESTAMP;
	tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(cur_stream->rcvvar->ts_recent);
}
/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPOptions(tcp_stream *cur_stream, uint32_t cur_ts, 
		uint8_t flags, uint8_t *tcpopt, uint16_t optlen)
{
	int i = 0;

	if (flags & TCP_FLAG_SYN) {
		uint16_t mss;

		/* MSS option */
		mss = cur_stream->sndvar->mss;
		tcpopt[i++] = TCP_OPT_MSS;
		tcpopt[i++] = TCP_OPT_MSS_LEN;
		tcpopt[i++] = mss >> 8;
		tcpopt[i++] = mss % 256;

		/* SACK permit */
#if TCP_OPT_SACK_ENABLED
#if !TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
		tcpopt[i++] = TCP_OPT_SACK_PERMIT;
		tcpopt[i++] = TCP_OPT_SACK_PERMIT_LEN;
		TRACE_SACK("Local SACK permited.\n");
#endif /* TCP_OPT_SACK_ENABLED */

		/* Timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		/* Window scale */
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_WSCALE;
		tcpopt[i++] = TCP_OPT_WSCALE_LEN;
		tcpopt[i++] = cur_stream->sndvar->wscale_mine;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_OPT_SACK) {
			// i += GenerateSACKOption(cur_stream, tcpopt + i);
		}
#endif
	}

	assert (i == optlen);
}

/*----------------------------------------------------------------------------*/
// adapted from SendTCPPacket in tcp_out
int
SendMTPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		      uint32_t cur_ts, uint8_t flags, 
              uint32_t seq, uint32_t ack, 
              uint16_t window,
              uint8_t *payload, uint16_t payloadlen)
{
	struct tcphdr *tcph;
    uint16_t optlen;
	int rc = -1;

    // MTP TODO: add them to MTP program
    optlen = CalculateOptionLength(flags);
    if (payloadlen + optlen > cur_stream->sndvar->mss) {
        TRACE_ERROR("Payload size exceeds MSS\n");
        return ERROR;
    }

    tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream,
            TCP_HEADER_LEN + optlen + payloadlen);
    if (tcph == NULL) {
        return -2;
    }
    memset(tcph, 0, TCP_HEADER_LEN + optlen);

	
	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
	tcph->window = htons(window);

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
        // MTP TODO: check these
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		//UpdateTimeoutList(mtcp, cur_stream);
	}

    // MTP TODO: zero window
    /*
	// if the advertised window is 0, we need to advertise again later 
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}
    */

    // MTP TODO: move out of here
    GenerateTCPOptions(cur_stream, cur_ts, flags,
            (uint8_t *)tcph + TCP_HEADER_LEN, optlen);

    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;

	// copy payload if exist
    if (payloadlen > 0) {
        memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
        mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
    }

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
    if (mtcp->iom->dev_ioctl != NULL)
        rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
                      PKT_TX_TCPIP_CSUM, NULL);
#endif
    if (rc == -1)
        tcph->check = TCPCalcChecksum((uint16_t *)tcph,
                          TCP_HEADER_LEN + optlen + payloadlen,
                          cur_stream->saddr, cur_stream->daddr);
#endif

		
	return 0;
}

/*----------------------------------------------------------------------------*/
static inline void syn_chain(mtcp_manager_t mtcp, uint32_t cur_ts,
                             uint32_t remote_ip, uint16_t remote_port, 
                             uint32_t init_seq, uint16_t rwnd,
                             uint32_t local_ip, uint16_t local_port){
   
    // MTP TODO:
    // Have to check if we already sent it and get here again
    // to retransmit. See tcp_in.c, ProcessTCPPacket, case TCP_ST_SYN_RCVD
 
    // MTP new_ctx instruction
    tcp_stream *cur_stream = NULL;

	/* create new stream and add to flow hash table */
    // MTP TODO: some variables like send_una are already 
    //           initialized in here. Should move them out
    //           into the chain at some point
	cur_stream = CreateTCPStream(mtcp, NULL, MTCP_SOCK_STREAM, 
			local_ip, local_port, remote_ip, remote_port);
	if (!cur_stream) {
		TRACE_ERROR("INFO: Could not allocate tcp_stream!\n");
	}
	cur_stream->sndvar->cwnd = 1;
	cur_stream->sndvar->peer_wnd = rwnd;
	cur_stream->rcvvar->irs = init_seq;
	cur_stream->rcv_nxt = (cur_stream->rcvvar->irs + 1);
    // MTP TODO: I think we need to add a state variable in context to MTP code
    cur_stream->state = TCP_ST_SYN_RCVD;
   
    // MTP pkt gen instruction
    uint32_t window32 = cur_stream->rcvvar->rcv_wnd;
	uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);

    SendMTPPacket(mtcp, cur_stream, cur_ts,
                            TCP_FLAG_SYN | TCP_FLAG_ACK, 
                            cur_stream->sndvar->iss, //seq
                            init_seq + 1, //ack
                            advertised_window, //window
                            NULL, 0);

    // MTP TODO: what if there are not buffers available?
    //if (ret == -2){
        // not enough space in mbuffs
    //} 
}

/*----------------------------------------------------------------------------*/
static inline void ack_chain(mtcp_manager_t mtcp, tcp_stream* cur_stream,
                             uint32_t cur_ts,
                            uint32_t ack_seq){ 

    // "establish" the connection if not established
    struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int ret;

    if (cur_stream->state == TCP_ST_SYN_RCVD){

	    /* check if ACK of SYN */
		if (ack_seq != sndvar->iss + 1) {
			CTRACE_ERROR("Stream %d (TCP_ST_SYN_RCVD): "
					"weird ack_seq: %u, iss: %u\n", 
					cur_stream->id, ack_seq, sndvar->iss);
			TRACE_DBG("Stream %d (TCP_ST_SYN_RCVD): "
					"weird ack_seq: %u, iss: %u\n", 
					cur_stream->id, ack_seq, sndvar->iss);
			return;
		}

		struct tcp_listener *listener;
		uint32_t prior_cwnd;
	
		sndvar->snd_una++;
		cur_stream->snd_nxt = ack_seq;
		prior_cwnd = sndvar->cwnd;
		sndvar->cwnd = ((prior_cwnd == 1)? 
				(sndvar->mss * TCP_INIT_CWND): sndvar->mss);
		TRACE_DBG("sync_recvd: updating cwnd from %u to %u\n", prior_cwnd, sndvar->cwnd);
		
		sndvar->nrtx = 0;
		//cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
		//RemoveFromRTOList(mtcp, cur_stream);

		cur_stream->state = TCP_ST_ESTABLISHED;
		TRACE_STATE("Stream %d: TCP_ST_ESTABLISHED\n", cur_stream->id);

        // ************* MTP TODO: Start of mTCP app interface
		/* update listening socket */
		listener = (struct tcp_listener *)ListenerHTSearch(mtcp->listeners, &cur_stream->sport);

		ret = StreamEnqueue(listener->acceptq, cur_stream);
		if (ret < 0) {
			TRACE_ERROR("Stream %d: Failed to enqueue to "
					"the listen backlog!\n", cur_stream->id);
			cur_stream->close_reason = TCP_NOT_ACCEPTED;
			cur_stream->state = TCP_ST_CLOSED;
			TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", cur_stream->id);
			//AddtoControlList(mtcp, cur_stream, cur_ts);
		}
		//TRACE_DBG("Stream %d inserted into acceptq.\n", cur_stream->id);
		//if (CONFIG.tcp_timeout > 0)
		//	AddtoTimeoutList(mtcp, cur_stream);

		/* raise an event to the listening socket */
		if (listener->socket && (listener->socket->epoll & MTCP_EPOLLIN)) {
			AddEpollEvent(mtcp->ep, 
					MTCP_EVENT_QUEUE, listener->socket, MTCP_EPOLLIN);
		}
        // ************** End of mTCP app interface
    }
    /*
    // MTP TODO: syn ack retransmit
    else {
		TRACE_DBG("Stream %d (TCP_ST_SYN_RCVD): No ACK.\n", 
				cur_stream->id);
		// retransmit SYN/ACK 
		cur_stream->snd_nxt = sndvar->iss;
		AddtoControlList(mtcp, cur_stream, cur_ts);
	} 
    */   

}


/*----------------------------------------------------------------------------*/
// MTP TODO: what should we do if there are errors? Maybe the target should 
//           hold off on more events for that flow so that it can roll back the context.
//           also should modify this to have the available buffer (for "infinite inorder data units") as input
inline void data_net_ep(mtcp_manager_t mtcp, tcp_stream* cur_stream, uint32_t cur_ts, 
                       uint32_t seq, uint8_t *payload, int payloadlen){
    struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	uint32_t prev_rcv_nxt;
    uint32_t last_rcvd_seq = seq + payloadlen;
	int ret;

	/* if seq and segment length is lower than rcv_nxt, ignore and send ack */
	if (TCP_SEQ_LT(last_rcvd_seq, cur_stream->rcv_nxt)) {
		return;
	}
	/* if payload exceeds receiving buffer, drop and send ack */
	if (TCP_SEQ_GT(last_rcvd_seq, cur_stream->rcv_nxt + rcvvar->rcv_wnd)) {
		return;
	}

    // MTP: this is new_inorder_data, rcvbuf is the "id"
	/* allocate receive buffer if not exist */
	if (!rcvvar->rcvbuf) {
		rcvvar->rcvbuf = RBInit(mtcp->rbm_rcv, rcvvar->irs + 1);
        // MTP TODO: this should raise an error event that comes back
        //           to be processed according to the MTP program
		if (!rcvvar->rcvbuf) {
			TRACE_ERROR("Stream %d: Failed to allocate receive buffer.\n", 
					cur_stream->id);
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream);

			return;
		}
	}

	if (SBUF_LOCK(&rcvvar->read_lock)) {
		if (errno == EDEADLK)
			perror("ProcessTCPPayload: read_lock blocked\n");
		assert(0);
	}

	prev_rcv_nxt = cur_stream->rcv_nxt;
    // MTP: also does rwnd.set() 
	ret = RBPut(mtcp->rbm_rcv, 
			rcvvar->rcvbuf, payload, (uint32_t)payloadlen, seq);
	if (ret < 0) {
		TRACE_ERROR("Cannot merge payload. reason: %d\n", ret);
	}

    /*
	// discard the buffer if the state is FIN_WAIT_1 or FIN_WAIT_2, 
	//   meaning that the connection is already closed by the application 
	if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2) {
		RBRemove(mtcp->rbm_rcv, 
				rcvvar->rcvbuf, rcvvar->rcvbuf->merged_len, AT_MTCP);
	}
    */

    // MTP: rwnd.first_unset()
	cur_stream->rcv_nxt = rcvvar->rcvbuf->head_seq + rcvvar->rcvbuf->merged_len;
    // MTP TODO: refactor this one
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	SBUF_UNLOCK(&rcvvar->read_lock);

	if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, prev_rcv_nxt)) {
		/* There are some lost packets */
		return;
	}

    //***************** start of mTCP app interface

	TRACE_EPOLL("Stream %d data arrived. "
			"len: %d, ET: %u, IN: %u, OUT: %u\n", 
			cur_stream->id, payloadlen, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLET : 0, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLIN : 0, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLOUT : 0);

	if (cur_stream->state == TCP_ST_ESTABLISHED) {
		RaiseReadEvent(mtcp, cur_stream);
	}
    //***************** end of mTCP app interface
}


/*----------------------------------------------------------------------------*/
inline int send_chain(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
    if (cur_stream->state != TCP_ST_ESTABLISHED) return 0;

	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	uint8_t *data;
	uint32_t pkt_len;
	int len;
	uint32_t seq = 0;
	int remaining_window;
	int packets = 0;
	
	if (!sndvar->sndbuf) {
		TRACE_ERROR("Stream %d: No send buffer available.\n", cur_stream->id);
		assert(0);
		return 0;
	}
	
	SBUF_LOCK(&sndvar->write_lock);

	if (sndvar->sndbuf->len == 0) {
		packets = 0;
        SBUF_UNLOCK(&sndvar->write_lock);
        return 0;
	}

    // MTP TODO: sanity checks in FlushTCPSendingBuffer
    remaining_window = MIN(sndvar->cwnd, sndvar->peer_wnd)
			               - (seq - sndvar->snd_una);


    seq = cur_stream->snd_nxt;
    data = sndvar->sndbuf->head + (seq - sndvar->sndbuf->head_seq);
	len = sndvar->sndbuf->len - (seq - sndvar->sndbuf->head_seq);
    if (len == 0) {
        SBUF_UNLOCK(&sndvar->write_lock);
        return 0;
    }
    if (remaining_window <= 0) {
        SBUF_UNLOCK(&sndvar->write_lock);
        return -1;
    }
    
    /* payload size limited by remaining window space */
    len = MIN(len, remaining_window);

    uint32_t ack_seq = cur_stream->rcv_nxt;
    uint8_t wscale = cur_stream->sndvar->wscale_mine;
    uint32_t window32 = cur_stream->rcvvar->rcv_wnd >> wscale;  
    uint16_t window = (uint16_t)MIN(window32, TCP_MAX_WINDOW);
    // MTP: seq, data, and len are part of the packet bp with segmentation
    // MTP: this would be the segmentation logic
    /* payload size limited by TCP MSS */
    int ret = 0;
	while (len > 0) {
		pkt_len = MIN(len, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));
        ret = SendMTPPacket(mtcp, cur_stream, 
		              cur_ts, TCP_FLAG_ACK,
                      seq, ack_seq,
                      window, 
                      data, pkt_len); 

        printf("packet info: %d, %d, %d\n", pkt_len, seq, ret);
        if (packets == 1){
            break;
        }
        if (ret < 0){
            break;
        }
        else{
            len -= pkt_len;
            seq += pkt_len;
            data += pkt_len;
            packets++;
            if (len <= 0) break;
        }
	}

    SBUF_UNLOCK(&sndvar->write_lock);
	return ret;	
}

/*----------------------------------------------------------------------------*/
// MTP TODO: the event is not fully inline with MTP's tcp code because
//           data len is not in it and the data is already copied
//           and recorded in the flow context (tcp_stream) before getting here.
inline void 
MTP_ProcessSendEvents(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
    
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	// Send data 
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->send_list);
	last = TAILQ_LAST(&sender->send_list, send_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside send loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->send_link);

		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		if (cur_stream->sndvar->on_send_list) {
			ret = 0;

			// Send data here
            ret = send_chain(mtcp, cur_stream, cur_ts); 

            // MTP TODO: This is where we should properly implement our pkt generation
            //           interface
			if (ret < 0) {
				TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
				// since there is no available write buffer, break 
				break;

			} else {
				cur_stream->sndvar->on_send_list = FALSE;
				sender->send_list_cnt--;
				// MTP TODO: the ret value is the number of packets sent.
				// decrease ack_cnt for the piggybacked acks
			}
		} else {
			TRACE_ERROR("Stream %d: not on send list.\n", cur_stream->id);
#ifdef DUMP_STREAM
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}
    return;
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

    //int event_type = MTP_NO_EVENT;

    bool is_syn = tcph->syn;
    bool is_ack = tcph->ack;
	uint32_t seq = ntohl(tcph->seq);
	uint32_t ack_seq = ntohl(tcph->ack_seq);
	uint16_t window = ntohs(tcph->window);
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

    // MTP parsing and event processing: I think for the
    // mTCP target, it makes sense to call event processing
    // right when net events are generated through parsing

    // MTP_SYN
    if (is_syn && !is_ack){
        //event_type = MTP_SYN;

        // MTP: look up listen flow id
        uint32_t local_ip = iph->daddr;
        uint16_t local_port = tcph->dest;
        struct tcp_listener *listener;
        /* if not the address we want, drop */
        listener = (struct tcp_listener *)ListenerHTSearch(mtcp->listeners, &local_port);
        if (listener == NULL) {
            printf("MTP: listen context not found\n");
            TRACE_DBG("Refusing SYN packet.\n");
            #ifdef DBGMSG
                DumpIPPacket(mtcp, iph, ip_len);
            #endif
            // MTP TODO: generate an "error" event to be processed this way
            /*    SendTCPPacketStandalone(mtcp, 
                        iph->daddr, tcph->dest, iph->saddr, tcph->source, 
                        0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
                        NULL, 0, cur_ts, 0);

                return NULL;
            */
            return 0;
         }           

        // MTP TODO: cur_ts in events by default or explicity?
        // parser "returns" event and dispatcher calls the event processing chain
        syn_chain(mtcp, cur_ts, iph->saddr, tcph->source, seq, window, local_ip, local_port);
        return 0;
    }
   
    // Other net events 
    
	tcp_stream s_stream;
	tcp_stream *cur_stream = NULL;
	
	// MTP: maps to flow id generation in parser
    s_stream.saddr = iph->daddr;
	s_stream.sport = tcph->dest;
	s_stream.daddr = iph->saddr;
	s_stream.dport = tcph->source;

    
	if (!(cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream))) {
        printf("MTP: flow context not found\n");
        return 0;
    }

    if (is_ack){
        // event_type = MTP_ACK;
        ack_chain(mtcp, cur_stream, cur_ts, ack_seq);
    }

    if (payloadlen > 0){
        data_net_ep(mtcp, cur_stream, cur_ts, seq, payload, payloadlen);
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
