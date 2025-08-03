#include "mtp_instr.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "debug.h"
#include "ip_out.h"
#include "timer.h"
#include "mtp_seq.h"

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
		// printf("add to gen list\n");
		return;
    }
	// printf("already on gen list\n");
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
	mtp->ssthresh = mtp->SMSS * 10;
    mtp->duplicate_acks = 0;
	mtp->wscale = 7;
	mtp->num_rtx = 0;
	mtp->max_num_rtx = 0;
	mtp->closed = FALSE;
	mtp->fin_sent = FALSE;
	mtp->final_seq = 0;

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

	struct mtp_ctx *ctx = cur_stream->mtp;
	if (!ctx->meta_rwnd) {
		ctx->meta_rwnd = RBInit(mtcp->rbm_rcv, rcvvar->irs + 1);
		// MTP TODO: this should raise an error event that comes back
		//           to be processed according to the MTP program
		if (!ctx->meta_rwnd) {
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream);
			return NULL;
		}
	}

	return cur_stream;
}

void
DestroyCtx(mtcp_manager_t mtcp, tcp_stream *stream, uint16_t sport)
{
	struct sockaddr_in addr;
	int bound_addr = FALSE;
	uint8_t *sa, *da;
	int ret;

	sa = (uint8_t *)&stream->saddr;
	da = (uint8_t *)&stream->daddr;

	if (stream->sndvar->sndbuf) {
		TRACE_FSTAT("Stream %d: send buffer "
				"cum_len: %lu, len: %u\n", stream->id, 
				stream->sndvar->sndbuf->cum_len, 
				stream->sndvar->sndbuf->len);
	}
	if (stream->rcvvar->rcvbuf) {
		TRACE_FSTAT("Stream %d: recv buffer "
				"cum_len: %lu, merged_len: %u, last_len: %u\n", stream->id, 
				stream->rcvvar->rcvbuf->cum_len, 
				stream->rcvvar->rcvbuf->merged_len, 
				stream->rcvvar->rcvbuf->last_len);
	}

	if (stream->is_bound_addr) {
		bound_addr = TRUE;
		addr.sin_addr.s_addr = stream->saddr;
		addr.sin_port = sport;
	}

	RemoveFromControlList(mtcp, stream);
	RemoveFromSendList(mtcp, stream);
	RemoveFromACKList(mtcp, stream);
	
	if (stream->on_rto_idx >= 0)
		RemoveFromRTOList(mtcp, stream);
 	
	if (stream->on_timewait_list)
		RemoveFromTimewaitList(mtcp, stream);

	if (CONFIG.tcp_timeout > 0)
		RemoveFromTimeoutList(mtcp, stream);

	SBUF_LOCK_DESTROY(&stream->rcvvar->read_lock);
	SBUF_LOCK_DESTROY(&stream->sndvar->write_lock);

	assert(stream->on_hash_table == TRUE);
	
	/* free ring buffers */
	if (stream->sndvar->sndbuf) {
		SBFree(mtcp->rbm_snd, stream->sndvar->sndbuf);
		stream->sndvar->sndbuf = NULL;
	}
	if (stream->rcvvar->rcvbuf) {
		RBFree(mtcp->rbm_rcv, stream->rcvvar->rcvbuf);
		stream->rcvvar->rcvbuf = NULL;
	}

	pthread_mutex_lock(&mtcp->ctx->flow_pool_lock);

	/* remove from flow hash table */
	StreamHTRemove(mtcp->tcp_flow_table, stream);
	stream->on_hash_table = FALSE;
	
	mtcp->flow_cnt--;

    #ifdef USE_MTP
	MPFreeChunk(mtcp->mtp_pool, stream->mtp);
    #endif
	MPFreeChunk(mtcp->rv_pool, stream->rcvvar);
	MPFreeChunk(mtcp->sv_pool, stream->sndvar);
	MPFreeChunk(mtcp->flow_pool, stream);
	pthread_mutex_unlock(&mtcp->ctx->flow_pool_lock);

	if (bound_addr) {
		if (mtcp->ap) {
			ret = FreeAddress(mtcp->ap, &addr);
		} else {
			uint8_t is_external;
			int nif = GetOutputInterface(addr.sin_addr.s_addr, &is_external);
			if (nif < 0) {
				TRACE_ERROR("nif is negative!\n");
				ret = -1;
			} else {
			        int eidx = CONFIG.nif_to_eidx[nif];
				ret = FreeAddress(ap[eidx], &addr);
			}
			UNUSED(is_external);
		}
		if (ret < 0) {
			TRACE_ERROR("(NEVER HAPPEN) Failed to free address.\n");
		}
	}
	UNUSED(da);
	UNUSED(sa);
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
	uint32_t rmlen = len + MTP_SEQ_SUB(offset, sndvar->sndbuf->head_seq, sndvar->sndbuf->head_seq);
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
int FlushAndNotify(mtcp_manager_t mtcp, socket_map_t socket, 
				   tcp_stream* cur_stream, char *buf, int len)
{
	// Flush part (modified from mTCP CopyToUser)
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	if (len <= 0) {
		errno = EAGAIN;
		return -1;
	}

	// Copy data to user buffer and remove it from receiving buffer
	memcpy(buf, rcvvar->rcvbuf->head, len);
	RBRemove(mtcp->rbm_rcv, rcvvar->rcvbuf, len, AT_APP);

	return len;
}


/***********************************************
 MTP timer_instr
 
 Operations for the "retransmission" timer
 Modified from UpdateRetransmissionTimer
 ***********************************************/
void TimerStart(mtcp_manager_t mtcp, tcp_stream *stream, uint32_t cur_ts) {
    stream->sndvar->ts_rto = cur_ts + stream->sndvar->rto;
	printf("TimerStart: stream %u, ts_rto: %u, rto %u, cur_ts: %d\n", stream->id, 
		stream->sndvar->ts_rto, stream->sndvar->rto, cur_ts);
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
