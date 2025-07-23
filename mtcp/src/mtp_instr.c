#include "mtp_instr.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "debug.h"
#include "ip_out.h"
#include "timer.h"

#define MIN(a, b) ((a)<(b)?(a):(b))
#define TCP_CALCULATE_CHECKSUM      TRUE

/***********************************************
 MTP pkt_gen_instr
 
 Funcion & helper functions for packet generation
 instruction
 ***********************************************/

/*----------------------------------------------------------------------------*/
inline struct mtcp_sender *
MTP_GetSender(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	if (cur_stream->sndvar->nif_out < 0) {
		return mtcp->g_sender;
	}

	int eidx = CONFIG.nif_to_eidx[cur_stream->sndvar->nif_out];
	if (eidx < 0 || eidx >= CONFIG.eths_num) {
		TRACE_ERROR("(NEVER HAPPEN) Failed to find appropriate sender.\n");
		return NULL;
	}

	return mtcp->n_sender[eidx];
}

/*----------------------------------------------------------------------------*/
inline void 
AddtoGenList(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
    if (!cur_stream->sndvar->on_gen_list) {
        struct mtcp_sender *sender = MTP_GetSender(mtcp, cur_stream);
        assert(sender != NULL);

        cur_stream->sndvar->on_gen_list = TRUE;
        TAILQ_INSERT_TAIL(&sender->gen_list, cur_stream, sndvar->gen_link);
        sender->gen_list_cnt++;
        TRACE_DBG("Stream %u: added to gen list (cnt: %d)\n", 
        		cur_stream->id, sender->gen_list_cnt);
		printf("add to gen list\n");
		return;
    }
	printf("already on gen list\n");
}

/*----------------------------------------------------------------------------*/
bool
BPBuffer_isfull(tcp_stream *cur_stream){
    uint32_t head = cur_stream->sndvar->mtp_bps_head;
    uint32_t tail = cur_stream->sndvar->mtp_bps_tail;
    uint32_t size = MTP_PER_FLOW_BP_CNT; 

    uint32_t next_tail = (tail + 1) % size;
    
    return (next_tail == head);
}

/*----------------------------------------------------------------------------*/
mtp_bp* GetFreeBP(struct tcp_stream *cur_stream){
    if (BPBuffer_isfull(cur_stream)){
        //MTP TODO: gotta fix this
        printf("BP buffer is full!\n");
        return NULL;
    }

    uint32_t bp_tail = cur_stream->sndvar->mtp_bps_tail;
    mtp_bp* new_bp = cur_stream->sndvar->mtp_bps + bp_tail;
    cur_stream->sndvar->mtp_bps_tail = (bp_tail + 1) % MTP_PER_FLOW_BP_CNT;
    return new_bp;
}


uint16_t CalculateOptionLength(uint8_t flags)
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

static inline void GenerateTCPTimestamp(tcp_stream *cur_stream, uint8_t *tcpopt, uint32_t cur_ts)
{
	uint32_t *ts = (uint32_t *)(tcpopt + 2);

	tcpopt[0] = TCP_OPT_TIMESTAMP;
	tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(cur_stream->rcvvar->ts_recent);
}

static inline void GenerateTCPOptions(tcp_stream *cur_stream, uint32_t cur_ts, 
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

// Adapted from SendTCPPacket in tcp_out
int SendMTPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
	uint32_t cur_ts, uint8_t flags, uint32_t seq, uint32_t ack, 
    uint16_t window, uint8_t *payload, uint16_t payloadlen)
{
	struct tcphdr *tcph;
    uint16_t optlen;

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
	int rc = -1;

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


/***********************************************
 MTP new_ctx_instr
 
 Funcion & helper functions for new context
 instruction
 ***********************************************/
int CreateListenCtx(mtcp_manager_t mtcp, int sockid, int backlog) 
{
	// Check for existing listen context
	if (ListenerHTSearch(mtcp->listeners, &mtcp->smap[sockid].saddr.sin_port)) {
		errno = EADDRINUSE;
		return -1;
	}

	// Init the listen context
	struct mtp_listen_ctx *listener = (struct mtp_listen_ctx *)calloc(1, sizeof(struct mtp_listen_ctx));
	if (!listener) {
		/* errno set from the malloc() */
		return -1;
	}
	listener->socket = &mtcp->smap[sockid];
	listener->local_ip = mtcp->smap[sockid].saddr.sin_addr.s_addr;
	listener->local_port = mtcp->smap[sockid].saddr.sin_port;
    listener->state = 0;	// LISTEN state
    listener->pending_cap = backlog;
	TAILQ_INIT(&listener->pending);

	// Init blocking mechanism variables
	if (pthread_cond_init(&listener->accept_cond, NULL)) {
		perror("pthread_cond_init of ctx->accept_cond\n");
		free(listener);
		return -1;
	}
	if (pthread_mutex_init(&listener->accept_lock, NULL)) {
		perror("pthread_mutex_init of ctx->accept_lock\n");
		free(listener);
		return -1;
	} 
	
	// Attach listen context to socket & store the context
	mtcp->smap[sockid].listen_ctx = listener;
	ListenerHTInsert(mtcp->listeners, listener);

	return 0;
}

tcp_stream* CreateCtx(mtcp_manager_t mtcp, uint32_t cur_ts,
    uint32_t remote_ip, uint32_t local_ip, 
    uint16_t remote_port, uint16_t local_port,
    bool sack_permit, uint16_t mss,
	uint32_t init_seq, uint32_t send_una, uint32_t send_next, 
    uint32_t recv_init_seq, uint32_t recv_next, uint32_t last_flushed,
    uint16_t last_rwnd_remote, uint8_t wscale, uint8_t state) 
{
	// Create new stream and add to flow hash table
	tcp_stream *cur_stream = CreateTCPStream(mtcp, NULL, MTCP_SOCK_STREAM, 
		local_ip, local_port, remote_ip, remote_port);

	cur_stream->sndvar->on_gen_list = FALSE;
    /**
	cur_stream->sndvar->cwnd = 1;
	cur_stream->sndvar->peer_wnd = last_rwnd_size;
	cur_stream->rcvvar->irs = init_seq;
	cur_stream->rcv_nxt = (cur_stream->rcvvar->irs + 1);
	cur_stream->rcvvar->last_flushed_seq = cur_stream->rcvvar->irs;
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
	(tcph->doff << 2) - TCP_HEADER_LEN);
	cur_stream->state = TCP_ST_SYN_RCVD;
    **/

    struct mtp_ctx* mtp = cur_stream->mtp;
    // Setting according to input
    mtp->remote_ip = remote_ip;
    mtp->local_ip = local_ip;
    mtp->remote_port = remote_port;
    mtp->local_port = local_port;
    mtp->sack_permit_remote = sack_permit;
    mtp->SMSS = mss;
    mtp->state = state;
    mtp->init_seq = init_seq;
    mtp->send_una = send_una;
    mtp->send_next = send_next;
    mtp->last_rwnd_remote = last_rwnd_remote;
    mtp->recv_init_seq = recv_init_seq;
    mtp->recv_next = recv_next;
    mtp->wscale_remote = wscale;
    mtp->last_flushed = last_flushed; 

    // Setting defaults
    // MTP TODO: fix this
    mtp->eff_SMSS = mtp->SMSS - (TCP_OPT_TIMESTAMP_LEN + 2); 
    mtp->rwnd_size = 14600;
    mtp->cwnd_size = 1;
    mtp->duplicate_acks = 0;
	mtp->wscale = 7;

	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	if (!rcvvar->rcvbuf) {
		rcvvar->rcvbuf = RBInit(mtcp->rbm_rcv, rcvvar->irs + 1);
		// MTP TODO: this should raise an error event that comes back
		//           to be processed according to the MTP program
		if (!rcvvar->rcvbuf) {
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream);
			return NULL;
		}
	}

	if (!rcvvar->meta_rwnd) {
		rcvvar->meta_rwnd = RBInit(mtcp->rbm_rcv, rcvvar->irs + 1);
		// MTP TODO: this should raise an error event that comes back
		//           to be processed according to the MTP program
		if (!rcvvar->meta_rwnd) {
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream);
			return NULL;
		}
	}

	return cur_stream;
}


/***********************************************
 MTP "buffer" instructions
 ***********************************************/
void TxDataFlush(mtcp_manager_t mtcp, tcp_stream *cur_stream, 
                uint32_t offset, uint32_t len){
	struct tcp_send_vars* sndvar = cur_stream->sndvar;
	
	// if (SBUF_LOCK(&sndvar->write_lock)) {
	// 	if (errno == EDEADLK) perror("ProcessACK: write_lock blocked\n");
	// 	assert(0);
	// }
	
	// MTP TODO: should we change offset and assume you can only continuously flush?
	uint32_t rmlen = len + (offset - sndvar->sndbuf->head_seq);
	// printf("TxDataFlush rmlen:%d\n", rmlen);
	// printf("Before: head ptr: %p, head seq: %d, len: %d\n", sndvar->sndbuf->head, 
	// 		sndvar->sndbuf->head_seq, sndvar->sndbuf->len);
	SBRemove(mtcp->rbm_snd, sndvar->sndbuf, rmlen);
	// printf("After: head ptr: %p, head seq: %d, len: %d\n", sndvar->sndbuf->head, 
	// 		sndvar->sndbuf->head_seq, sndvar->sndbuf->len);
	
	sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;

	// MTP TODO: How is this modeled in MTP, if at all?
	RaiseWriteEvent(mtcp, cur_stream);
	// SBUF_UNLOCK(&sndvar->write_lock);				
}


//  Funcion to flush data to and notify app
int FlushAndNotify(mtcp_manager_t mtcp, tcp_stream *cur_stream, char *buf, int len, socket_map_t socket)
{
	// Flush part (modified from mTCP CopyToUser)
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	int copylen = MIN((cur_stream->rcv_nxt - rcvvar->last_flushed_seq - 1), len);
	if (copylen <= 0) {
		errno = EAGAIN;
		return -1;
	}

	uint32_t prev_rcv_wnd = rcvvar->rcv_wnd;

	// Copy data to user buffer and remove it from receiving buffer
	memcpy(buf, rcvvar->rcvbuf->head, copylen);
	RBRemove(mtcp->rbm_rcv, rcvvar->rcvbuf, copylen, AT_APP);
	rcvvar->last_flushed_seq += copylen;
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	// Advertise newly freed receive buffer
	if (cur_stream->need_wnd_adv) {
		if (rcvvar->rcv_wnd > cur_stream->sndvar->eff_mss) {
			if (!cur_stream->sndvar->on_ackq) {
				SQ_LOCK(&mtcp->ctx->ackq_lock);
				cur_stream->sndvar->on_ackq = TRUE;
				StreamEnqueue(mtcp->ackq, cur_stream); /* this always success */
				SQ_UNLOCK(&mtcp->ctx->ackq_lock);
				cur_stream->need_wnd_adv = FALSE;
				mtcp->wakeup_flag = TRUE;
			}
		}
	}
	UNUSED(prev_rcv_wnd);

	// Notify part (modified from mtcp_recv)
	bool event_remaining = FALSE;
	if (socket->epoll & MTCP_EPOLLIN) {
		if (!(socket->epoll & MTCP_EPOLLET) && rcvvar->rcvbuf->merged_len > 0) {
			event_remaining = TRUE;
		}
	}

    // If waiting for close, notify it if no remaining data
	if (cur_stream->state == TCP_ST_CLOSE_WAIT && 
	    rcvvar->rcvbuf->merged_len == 0 && copylen > 0) {
		event_remaining = TRUE;
	}
	
	// SBUF_LOCK is in mtcp_recv
	SBUF_UNLOCK(&rcvvar->read_lock);
	
	if (event_remaining) {
		if (socket->epoll) {
			AddEpollEvent(mtcp->ep, USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLIN);
#if BLOCKING_SUPPORT
		} else if (!(socket->opts & MTCP_NONBLOCK)) {
			if (!cur_stream->on_rcv_br_list) {
				cur_stream->on_rcv_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->rcv_br_list, cur_stream, rcvvar->rcv_br_link);
				mtcp->rcv_br_list_cnt++;
			}
#endif
		}
	}

	return copylen;
}


/***********************************************
 MTP timer_instr
 
 Operations for the "retransmission" timer
 Modified from UpdateRetransmissionTimer
 ***********************************************/
void TimerStart(mtcp_manager_t mtcp, tcp_stream *stream, uint32_t cur_ts) {
    stream->sndvar->ts_rto = cur_ts + stream->sndvar->rto;
    AddtoRTOList(mtcp, stream);
}

void TimerCancel(mtcp_manager_t mtcp, tcp_stream *stream) {
	if (stream->on_rto_idx >= 0) {
        RemoveFromRTOList(mtcp, stream);
    }
    stream->sndvar->ts_rto = 0;
}

void TimerRestart(mtcp_manager_t mtcp, tcp_stream *stream, uint32_t cur_ts) {
	TimerCancel(mtcp, stream);
    TimerStart(mtcp, stream, cur_ts);
}
