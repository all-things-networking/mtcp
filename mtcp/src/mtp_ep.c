#include "mtp_ep.h"

#include <linux/tcp.h>

#include "tcp_in.h"
#include "tcp_out.h"
#include "timer.h"
#include "tcp_stream.h"
#include "fhash.h"
#include "debug.h"
#include "ip_out.h"
#include "tcp_util.h"
#include "socket.h"
#include "mtp_instr.h"
#include "mtp_net.h"
#include "mtp_seq.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

// Intermediate output
typedef struct scratchpad_decl {
	uint8_t type_pkt;
    bool complete;
    bool new_state;
    bool needs_schedule;
    bool dup_data_pkt;
    uint32_t last_bytes_remaining;
    bool last_grant;
    bool send_fifo_rpc;
} scratchpad;

tcp_stream* MtpHomaSendReqChainPart1(mtcp_manager_t mtcp, uint32_t cur_ts, char* buf,
		                      size_t msg_len, uint16_t srcport, uint16_t dest_port,
							  uint32_t dest_ip, socket_map_t socket){
	
	// Check if we can send more RPCs
	if (socket->cur_rpcs == socket->max_oustanding_rpc){
        // TODO: raise error
        return NULL;
    }

    int32_t rpc_ind = GetNextRPCInd(mtcp, socket->id);
	if (rpc_ind < 0){
		printf("Error getting RPC ID\n");
		return NULL;
	}
	// Successfully got an rpc_id
	// Increment the count of current outstanding RPCs
	socket->cur_rpcs += 1;
	uint32_t rpc_id = rpc_ind;

    uint16_t init_seq = 0;
    
	// TODO: Have to adjust send buff size based on message size
	struct tcp_send_buffer* sndbuf = SBInit(mtcp->rbm_snd, init_seq);

	if (!sndbuf) {
		/* notification may not required due to -1 return */
		errno = ENOMEM;
		printf("Error creating send buffer\n");
		return NULL;
	}

	int ret = SBPut(mtcp->rbm_snd, sndbuf, buf, msg_len);

	assert(ret == msg_len);
	if (ret <= 0) {
		TRACE_ERROR("SBPut failed. reason: %d (sndlen: %lu, len: %u\n", 
				ret, msg_len, sndbuf->len);
		errno = EAGAIN;
		return NULL;
	}
    
    uint32_t granted = MTP_HOMA_UNSCHED_BYTES;
    if (msg_len < granted) granted = msg_len;

    uint32_t birth = cur_ts;

	uint32_t last_seq = granted/MTP_HOMA_MSS;
	if (granted % MTP_HOMA_MSS) last_seq++;

	printf("Creating stream with srcip %u, sport %u, destip %u, destport %u, rpcid %u\n",
			socket->saddr.sin_addr.s_addr, srcport,
			dest_ip, dest_port,
			rpc_id);

	tcp_stream *cur_stream = CreateHomaCtx(mtcp, cur_ts, rpc_id,
									        socket->saddr.sin_addr.s_addr, srcport,
									        dest_ip, dest_port,
											rpc_id,
											init_seq,
											last_seq,
											MTP_HOMA_RPC_OUTGOING,
											msg_len,
											granted,
											granted,
											birth,
											true, 0, 0, 0,
											msg_len - granted);

	if (cur_stream){
		cur_stream->sndvar->sndbuf = sndbuf;
		cur_stream->socket = socket;
	}
	else{
		printf("Error creating Homa context\n");
		SBFree(mtcp->rbm_snd, sndbuf);
		errno = ENOMEM;
	}
	return cur_stream;

 }

 void MtpHomaSendReqChainPart2(mtcp_manager_t mtcp, uint32_t cur_ts, 
							   uint32_t ev_src_port, uint16_t ev_dest_port, uint32_t ev_msg_len,
							   uint32_t ev_init_seq, uint32_t rpc_id, uint32_t granted, 
							   uint32_t birth, tcp_stream *cur_stream){
	bool single_packet = ev_msg_len <= MTP_HOMA_MSS;
    uint8_t prio;

    if (single_packet){
        prio = (HOMA_MAX_PRIORITIES - 1) << 5;
    }
    else {
        // TODO: read the get_prio function in homa.h, called from XDP_EGRESS
    }

    mtp_bp *bp = GetFreeBP(cur_stream);	
	memset(&(bp->hdr), 0, MTP_HOMA_COMMON_HSIZE + MTP_HOMA_DATA_HSIZE);

    bp->hdr.src_port = htons(ev_src_port);
    bp->hdr.dest_port = htons(ev_dest_port);
    // bp->hdr.doff = (MTP_HOMA_COMMON_HSIZE + sizeof(struct homa_data_hdr) - sizeof(struct data_segment)) >> 2;
	bp->hdr.doff = (MTP_HOMA_COMMON_HSIZE + MTP_HOMA_DATA_HSIZE) >> 2;
    bp->hdr.type = MTP_HOMA_DATA;
    bp->hdr.seq = ev_init_seq;
    bp->hdr.sender_id = rpc_id;

	bp->hdr.data.message_length = ev_msg_len;
    bp->hdr.data.incoming = ev_msg_len;
    if (!single_packet) {
        bp->hdr.data.incoming = granted;
    }
    bp->hdr.data.cutoff_version = 0;
	bp->hdr.data.seg.offset = 0;

    bp->hdr.data.seg.ack.rpcid = 0;
    bp->hdr.data.seg.ack.sport = 0;
    bp->hdr.data.seg.ack.dport = 0;

    bp->prio = prio;
    
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	uint8_t *data = sndvar->sndbuf->head + ev_init_seq - sndvar->sndbuf->head_seq;
	bp->payload.data = data;
	bp->payload.len = granted;
	bp->payload.needs_segmentation = TRUE;
	bp->payload.seg_size = MTP_HOMA_MSS;
	bp->payload.seg_rule_group_id = 1; 

	AddtoGenList(mtcp, cur_stream, cur_ts);	
	
    // set queue priority (see pacing.h)
    // the scheduling policy should be setup once at the beginning

    uint32_t bytes_remaining = ev_msg_len - granted;
	cur_stream->homa_tx_prio_bytes_remaining = bytes_remaining;
	cur_stream->homa_tx_prio_rpcid = rpc_id;
	cur_stream->homa_tx_prio_local_port = ev_src_port;
	cur_stream->homa_tx_prio_birth = birth;

 }

void MtpHomaNoHomaCtxChain (mtcp_manager_t mtcp, uint32_t cur_ts,
							uint32_t ev_seq,
							uint32_t ev_message_length,
    						uint32_t ev_incoming,
    						uint8_t ev_retransmit,
							uint32_t ev_offset,
							uint32_t ev_segment_length,
							uint32_t ev_rpcid,
							uint16_t ev_sport,
							uint16_t ev_dport,
							bool ev_single_packet,
							uint32_t ev_local_ip,
							uint32_t ev_remote_ip,
							uint8_t* hold_addr,
							socket_map_t socket){

	scratchpad scratch;
	// first_req_pkt_ep

    uint8_t state = MTP_HOMA_RPC_INCOMING;
    if (ev_single_packet) state = MTP_HOMA_RPC_IN_SERVICE;

    uint16_t expected_segment_cnt = ev_message_length/MTP_HOMA_MSS;
	if (ev_message_length % MTP_HOMA_MSS) expected_segment_cnt++;

    // sliding_wnd rcvd_seqs(0, expected_segment_cnt);
    // rcvd_seqs.set(ev.seq);
	
	printf("Entering first_req_pkt_ep\n");
	int32_t rpc_ind = GetNextRPCInd(mtcp, socket->id);
	if (rpc_ind < 0){
		printf("Error getting RPC ID\n");
		return;
	}

	printf("Got rpc_ind: %d\n", rpc_ind);

	tcp_stream *cur_stream = CreateHomaCtx(mtcp, cur_ts, rpc_ind,
										     ev_local_ip, 
											 ev_dport,
										     ev_remote_ip, 
											 ev_sport,
											 ev_rpcid, 
											 0, //init_seq
											 0, // last_seq
											 state, 
											 ev_message_length,
											 0, // cur_offset
											 0, //cc_granted 
											 cur_ts,
											 FALSE,  //is_client
											 ev_seq, //recv_init_seq
											 expected_segment_cnt, 
											 ev_incoming,
											 (ev_message_length - ev_segment_length) // cc_bytes_remaining
											);

	if (cur_stream == NULL){
		printf("Error creating Homa context in first_req_pkt_ep\n");
		return;
	}

	printf("Created Homa context in first_req_pkt_ep\n");

	socket->rpcs[rpc_ind] = cur_stream;
	cur_stream->socket = socket;

    scratch.complete = ev_single_packet;
    scratch.new_state = true;
    scratch.needs_schedule = ev_message_length > ev_incoming;
    scratch.last_bytes_remaining = (ev_message_length - ev_segment_length);
    MTP_total_incoming += ev_incoming - ev_segment_length;

	printf("Allocating ring buffer in first_req_pkt_ep\n");
	// TODO: figure out size...
	struct tcp_ring_buffer *rcv_buff = RBInit(mtcp->rbm_rcv, ev_offset);
	if (!rcv_buff) {
		printf("Error creating ring buffer\n");
		return;
	}

	printf("Putting data in ring buffer in first_req_pkt_ep\n");

	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	rcvvar->rcvbuf = rcv_buff;

	RBPut(mtcp->rbm_rcv, rcvvar->rcvbuf, hold_addr, ev_segment_length, ev_offset);

	printf("Done with first_req_pkt_ep\n");
    if (scratch.complete) {
		printf("Raising read event in first_req_pkt_ep\n");
		RaiseReadEvent(mtcp, cur_stream);
    }
}
/********************************************************************* */
#define TCP_MAX_WINDOW 65535

// Helper functions
/*----------------------------------------------------------------------------*/
static inline void EstimateRTT(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t mrtt)
{
	/* This function should be called for not retransmitted packets */
	/* TODO: determine tcp_rto_min */
#define TCP_RTO_MIN 0
	long m = mrtt;
	uint32_t tcp_rto_min = TCP_RTO_MIN;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	if (m == 0) {
		m = 1;
	}
	if (rcvvar->srtt != 0) {
		/* rtt = 7/8 rtt + 1/8 new */
		m -= (rcvvar->srtt >> 3);
		rcvvar->srtt += m;
		if (m < 0) {
			m = -m;
			m -= (rcvvar->mdev >> 2);
			if (m > 0) {
				m >>= 3;
			}
		} else {
			m -= (rcvvar->mdev >> 2);
		}
		rcvvar->mdev += m;
		if (rcvvar->mdev > rcvvar->mdev_max) {
			rcvvar->mdev_max = rcvvar->mdev;
			if (rcvvar->mdev_max > rcvvar->rttvar) {
				rcvvar->rttvar = rcvvar->mdev_max;
			}
		}
		// if (TCP_SEQ_GT(cur_stream->mtp->send_una, rcvvar->rtt_seq)) {
		// 	if (rcvvar->mdev_max < rcvvar->rttvar) {
		// 		rcvvar->rttvar -= (rcvvar->rttvar - rcvvar->mdev_max) >> 2;
		// 	}
		// 	rcvvar->rtt_seq = cur_stream->mtp->send_next;
		// 	rcvvar->mdev_max = tcp_rto_min;
		// }
	} else {
		/* fresh measurement */
		rcvvar->srtt = m << 3;
		rcvvar->mdev = m << 1;
		rcvvar->mdev_max = rcvvar->rttvar = MAX(rcvvar->mdev, tcp_rto_min);
		// rcvvar->rtt_seq = cur_stream->mtp->send_next;
	}

	TRACE_RTT("mrtt: %u (%uus), srtt: %u (%ums), mdev: %u, mdev_max: %u, "
			"rttvar: %u, rtt_seq: %u\n", mrtt, mrtt * TIME_TICK, 
			rcvvar->srtt, TS_TO_MSEC((rcvvar->srtt) >> 3), rcvvar->mdev, 
			rcvvar->mdev_max, rcvvar->rttvar, rcvvar->rtt_seq);
}


/***********************************************
 MTP Event Processors
 
 EPs are static and used only by MTP EP chains
 They have 1-to-1 mappings to mtp code
 They should be generated by the MTP compiler
 ***********************************************/
static inline void send_ep(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream *cur_stream)
{
	// struct tcp_send_vars *sndvar = cur_stream->sndvar;

	/*
    if (cur_stream->mtp->state != MTP_TCP_ESTABLISHED_ST) return;

	struct mtp_ctx *ctx = cur_stream->mtp;
	
	// MTP_PRINT("send_ep before grabbing lock\n");
	SBUF_LOCK(&sndvar->write_lock);
	// MTP_PRINT("send_ep after grabbing lock\n");

	// MTP_PRINT("in send ep\n");
	if (!sndvar->sndbuf || sndvar->sndbuf->len == 0) {
        SBUF_UNLOCK(&sndvar->write_lock);
        return;
	}

	// MTP: maps to bytes_to_send
	int data_rest = sndvar->sndbuf->len - 
					MTP_SEQ_SUB(ctx->send_next, sndvar->sndbuf->head_seq, 
								sndvar->sndbuf->head_seq);
	int window_avail = MIN(ctx->cwnd_size, ctx->last_rwnd_remote) - 
					   MTP_SEQ_SUB(ctx->send_next, ctx->send_una, ctx->send_una);

    int bytes_to_send = MIN(data_rest, window_avail);

	MTP_PRINT("****************************\n");
	MTP_PRINT("Stream %u in send ep\n", cur_stream->id);
	MTP_PRINT("send_ep cwnd_size: %u, last_rwnd_remote: %u, "
			"send_next: %u, send_una: %u\n", 
			ctx->cwnd_size, ctx->last_rwnd_remote, ctx->send_next, 
			ctx->send_una);
	MTP_PRINT("send_ep bytes to send: %d, data_rest: %d, window_avail: %d\n", 
			bytes_to_send, data_rest, window_avail);

	if (bytes_to_send <= 0) {
		// MTP_PRINT("send_ep before releasing lock\n");
		SBUF_UNLOCK(&sndvar->write_lock);
		// MTP_PRINT("send_ep after releasing lock\n");
        return;
	}

	MTP_PRINT("send_ep bytes to send: %d\n", bytes_to_send);
	// MTP: maps to packet blueprint creation
	
	mtp_bp* bp;
	bool data_merging = FALSE;
	bool ack_merging = FALSE;

	if (!BPBuffer_isempty(cur_stream)){
		mtp_bp* last_bp = GetLastBP(cur_stream);
		uint32_t next_sched_byte = ntohl(last_bp->hdr.seq) + last_bp->payload.len;
		if (last_bp->payload.len > 0 && 
			ctx->send_next == next_sched_byte){
			MTP_PRINT("merging, prev blueprint is:");
			print_MTP_bp(last_bp);
			bp = last_bp;
			data_merging = TRUE;
		}
		else if (last_bp->payload.len == 0 &&
				 last_bp->hdr.ack == TRUE &&
				 last_bp->hdr.fin == FALSE &&
				 last_bp->hdr.syn == FALSE) {
		    MTP_PRINT("merging, prev blueprint is:");
			print_MTP_bp(last_bp);
			bp = last_bp;
			ack_merging = TRUE;
		}
	}

	if (!data_merging && !ack_merging){
		bp = GetFreeBP(cur_stream);	
	} 
	MTP_PRINT("got bp\n");
	MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
    
	if (!data_merging && !ack_merging){
    	memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));
	}

    bp->hdr.source = cur_stream->mtp->local_port;
    bp->hdr.dest = cur_stream->mtp->remote_port;

	if (!data_merging){
    	bp->hdr.seq = htonl(ctx->send_next);
	}

	MTP_PRINT("Seq in send_ep: %u\n", ntohl(bp->hdr.seq));
    bp->hdr.ack_seq = htonl(ctx->recv_next);

    bp->hdr.syn = FALSE;
    bp->hdr.ack = TRUE;

    // options to calculate data offset
   
    // MTP TODO: SACK? 
#if TCP_OPT_SACK_ENABLED
    MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
#endif

    MTP_set_opt_nop(&(bp->opts.nop1));
    MTP_set_opt_nop(&(bp->opts.nop2));

    // MTP TODO: Timestamp
    MTP_set_opt_timestamp(&(bp->opts.timestamp),
                            htonl(cur_ts),
                            htonl(ctx->ts_recent));
    
   
    // MTP TODO: would the MTP program do the length 
    //           calculation itself?
    uint16_t optlen = MTP_CalculateOptionLength(bp);
    bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

    // MTP TODO: wscale on local
	uint8_t wscale = ctx->wscale;
    uint32_t window32 = ctx->rwnd_size >> wscale;  
	// MTP TODO: fix this
    uint16_t advertised_window = (uint16_t)MIN(window32, TCP_MAX_WINDOW);
    bp->hdr.window = htons(advertised_window);
	if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

    // Payload
    // MTP TODO: fix snbuf
	if (!data_merging){
		uint8_t *data = sndvar->sndbuf->head + MTP_SEQ_SUB(ctx->send_next,
														sndvar->sndbuf->head_seq,
														sndvar->sndbuf->head_seq);
		bp->payload.data = data;
	}

	if (data_merging){
    	bp->payload.len += bytes_to_send;
	}
	else {
		bp->payload.len = bytes_to_send;
	}

	if (bp->payload.len > ctx->eff_SMSS){
		bp->payload.needs_segmentation = TRUE;
		bp->payload.seg_size = ctx->eff_SMSS;
		bp->payload.seg_rule_group_id = 1; 
	}

    AddtoGenList(mtcp, cur_stream, cur_ts);	

	// MTP_PRINT("preprared bp:\n");
	// print_MTP_bp(bp);
	// MTP_PRINT("head ptr: %p, head seq: %d, len: %d\n", sndvar->sndbuf->head, 
	// 		sndvar->sndbuf->head_seq, sndvar->sndbuf->len);

	// MTP TODO: implement + for MTP_SEQ
	ctx->send_next += bytes_to_send;

	MTP_PRINT("send next: %u\n", ctx->send_next);

	// MTP TODO: map to timer event with event input
	TimerStart(mtcp, cur_stream, cur_ts);

	// MTP_PRINT("send_ep before releasing lock\n");
	SBUF_UNLOCK(&sndvar->write_lock);
	// MTP_PRINT("send_ep after releasing lock\n");
	return;
	*/
}

static inline int receive_ep(mtcp_manager_t mtcp, socket_map_t socket, 
								bool non_block, char *ev_buf, int ev_data_size, 
								tcp_stream *cur_stream)
{
	/*
	struct mtp_ctx* ctx = cur_stream->mtp;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	if (ctx->state == MTP_TCP_CLOSE_WAIT_ST) {
		if (!rcvvar->rcvbuf)
			return 0;
		
		if (rcvvar->rcvbuf->merged_len == 0)
			return 0;
	}
	
	// return EAGAIN if no receive buffer
	if (non_block) {
		if (!rcvvar->rcvbuf || rcvvar->rcvbuf->merged_len == 0) {
			errno = EAGAIN;
			return -1;
		}
	}

	MTP_PRINT("receive_ep: ev_data_sizse: %d, "
			"cur_stream->mtp->recv_next: %u, "
			"cur_stream->mtp->last_flushed: %u\n", 
			ev_data_size, ctx->recv_next, ctx->last_flushed);

	uint32_t data_avail = MTP_SEQ_SUB(ctx->recv_next, 
									 ctx->last_flushed, 
									 ctx->last_flushed) - 1;
    if (data_avail > ev_data_size){
        data_avail = ev_data_size;
    }

	MTP_PRINT("data_avail: %u\n", data_avail);

	int ret = FlushAndNotify(mtcp, socket, cur_stream, ev_buf, data_avail);
    
    ctx->last_flushed += data_avail;
	ctx->rwnd_size = cur_stream->rcvvar->rcvbuf->size - (MTP_SEQ_SUB(ctx->recv_next, 
																	ctx->last_flushed, 
																	ctx->last_flushed) - 1);
	
	// MTP TODO: I think this has race conditions
	
	if (socket->epoll & MTCP_EPOLLIN) {
		if (!(socket->epoll & MTCP_EPOLLET) && ctx->recv_next > ctx->last_flushed + 1) {
			if (socket->epoll) {
				AddEpollEvent(mtcp->ep, USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLIN);
			}
		}
	}

	return ret;
	// TODO: send ack when window becomes non zero after being zero (part 2)
	*/
	return 0;
}


static inline void conn_ack_ep ( mtcp_manager_t mtcp, int32_t cur_ts, uint32_t ev_ack_seq, 
        uint32_t ev_seq, tcp_stream* cur_stream, scratchpad* scratch){

	// MTP_PRINT("----------------------------- Ack: %u\n", ev_ack_seq);

	/*
	struct mtp_ctx *ctx = cur_stream->mtp;

    if (ctx->state == MTP_TCP_SYNACK_SENT_ST &&
        ev_ack_seq == ctx->init_seq + 1){
        ctx->state = MTP_TCP_ESTABLISHED_ST;
        ctx->send_una += 1;
        ctx->send_next = ev_ack_seq;
        ctx->last_ack = ev_ack_seq;

        if (ctx->cwnd_size == 1){
            ctx->cwnd_size = 2 * ctx->SMSS;
        }
        else {
            ctx->cwnd_size = ctx->SMSS;
        }

		ctx->lwu_seq = ev_seq;
		ctx->lwu_ack = ev_ack_seq;
        scratch->skip_ack_eps = TRUE;
		// MTP TODO: timer
        TimerCancel(mtcp, cur_stream);

        // MTP TODO: Raise an event to the listening socket
		struct mtp_listen_ctx *listen_ctx = 
			(struct mtp_listen_ctx *)ListenerHTSearch(mtcp->listeners, &cur_stream->sport);
		if (listen_ctx->socket && (listen_ctx->socket->epoll & MTCP_EPOLLIN)) {
			AddEpollEvent(mtcp->ep, MTCP_EVENT_QUEUE, listen_ctx->socket, MTCP_EPOLLIN);
		}
    }
    else {
        scratch->skip_ack_eps = FALSE;
		// MTP_PRINT("conn_ack, no skip: lwu_seq: %u, lwu_ack: %u, rwindow: %u\n", cur_stream->mtp->lwu_seq,
		// 							   cur_stream->mtp->lwu_ack,
		// 							   cur_stream->mtp->last_rwnd_remote);
    }

	*/
}

static inline void rto_ep( mtcp_manager_t mtcp, int32_t cur_ts, uint32_t ev_ack_seq, 
    tcp_stream* cur_stream, scratchpad* scratch)
{
    // if (scratch->skip_ack_eps) return;

	// if (cur_stream->mtp->state != MTP_TCP_ESTABLISHED_ST) return;
	/*
    struct mtp_ctx* ctx = cur_stream->mtp;
	if (ctx->state == MTP_TCP_FIN_WAIT_1_ST || 
		ctx->state == MTP_TCP_FIN_WAIT_2_ST ||
		ctx->state == MTP_TCP_CLOSING_ST || 
		ctx->state == MTP_TCP_CLOSE_WAIT_ST || 
		ctx->state == MTP_TCP_LAST_ACK_ST) {
		if (ctx->fin_sent && ev_ack_seq == ctx->final_seq + 1) {
			ev_ack_seq--;
		}
	}
	
    if(MTP_SEQ_LT(ev_ack_seq, ctx->send_una, ctx->send_una) || 
	   MTP_SEQ_LT(ctx->send_next, ev_ack_seq, ctx->send_una)) {
		scratch->skip_ack_eps = TRUE;
		return;
	}
    
	// MTP TODO: make consistent with MTP
    // Set RTO, using RTT calculation logic from mTCP
	uint32_t rmlen = MTP_SEQ_SUB(ev_ack_seq, ctx->send_una, ctx->send_una);
	if (rmlen > 0){
		struct tcp_send_vars *sndvar = cur_stream->sndvar;
		struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
		uint32_t rtt = cur_ts - rcvvar->ts_lastack_rcvd;
		// printf("Stream %u, rtt: %u, last_ack_ts:%u\n", 
		// 		cur_stream->id, rtt, rcvvar->ts_lastack_rcvd);
		EstimateRTT(mtcp, cur_stream, rtt);
		#ifndef MTP_FIXED_RTO
		sndvar->rto = (rcvvar->srtt >> 3) + rcvvar->rttvar;
		#else
		sndvar->rto = 3;
		#endif
	}
	*/
}

static inline void fast_retr_rec_ep(mtcp_manager_t mtcp, uint32_t cur_ts, 
								    uint32_t ev_ack_seq, tcp_stream* cur_stream, 
									scratchpad* scratch)
{
	// if(scratch->skip_ack_eps) return;
	// if (cur_stream->mtp->state != MTP_TCP_ESTABLISHED_ST) return;

	/*
    struct mtp_ctx* ctx = cur_stream->mtp;
	if (ctx->state == MTP_TCP_FIN_WAIT_1_ST || 
		ctx->state == MTP_TCP_FIN_WAIT_2_ST ||
		ctx->state == MTP_TCP_CLOSING_ST || 
		ctx->state == MTP_TCP_CLOSE_WAIT_ST || 
		ctx->state == MTP_TCP_LAST_ACK_ST) {
		if (ctx->fin_sent && ev_ack_seq == ctx->final_seq + 1) {
			ev_ack_seq--;
		}
	}

	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	SBUF_LOCK(&sndvar->write_lock);
	uint32_t data_rest =  sndvar->sndbuf->len - 
					      MTP_SEQ_SUB(ctx->send_next, sndvar->sndbuf->head_seq,
									  sndvar->sndbuf->head_seq);
	SBUF_UNLOCK(&sndvar->write_lock);

	scratch->expecting_ack = TRUE;
	if (data_rest == 0 && ctx->send_una == ctx->send_next) {
		scratch->expecting_ack = FALSE;
		return;
	}

	scratch->change_cwnd = 1;

	// MTP_PRINT("fast_retr BEFORE: cwnd:%u, ssthresh:%u\n", ctx->cwnd_size, ctx->ssthresh);
	if(ev_ack_seq == ctx->last_ack) {
		ctx->duplicate_acks = ctx->duplicate_acks + 1;

		scratch->change_cwnd = 0;

		if(ctx->duplicate_acks == 1) {
			ctx->flightsize_dupl = MTP_SEQ_SUB(ctx->send_next, 
											   ctx->send_una, 
											   ctx->send_una);
		}

		if(ctx->duplicate_acks == 3) {
			// MTP congestion window resize
            uint32_t opt1 = ctx->flightsize_dupl/2;
            uint32_t opt2 = 2 * ctx->SMSS;
            if (opt1 >= opt2) ctx->ssthresh = opt1;
            else ctx->ssthresh = opt2;
			
            ctx->cwnd_size = ctx->ssthresh + ctx->SMSS;
		}

		if(ctx->duplicate_acks != 3) {
			ctx->cwnd_size += ctx->SMSS;
		}
	} else {
		if(ctx->duplicate_acks >= 3) {
			ctx->cwnd_size = ctx->ssthresh;
		}
		ctx->duplicate_acks = 0;
		ctx->last_ack = ev_ack_seq;
	}
	// MTP_PRINT("fast_retr AFTER: cwnd:%u, ssthresh:%u\n", ctx->cwnd_size, ctx->ssthresh);
	*/
}

static inline void slows_congc_ep(mtcp_manager_t mtcp, uint32_t cur_ts, uint32_t ev_ack_seq, 
	tcp_stream* cur_stream, scratchpad* scratch)
{
	// if(scratch->skip_ack_eps) return;
	/*
	// if (cur_stream->mtp->state != MTP_TCP_ESTABLISHED_ST) return;
    struct mtp_ctx *ctx = cur_stream->mtp;

	if (ctx->state == MTP_TCP_FIN_WAIT_1_ST || 
		ctx->state == MTP_TCP_FIN_WAIT_2_ST ||
		ctx->state == MTP_TCP_CLOSING_ST || 
		ctx->state == MTP_TCP_CLOSE_WAIT_ST || 
		ctx->state == MTP_TCP_LAST_ACK_ST) {
		if (ctx->fin_sent && ev_ack_seq == ctx->final_seq + 1) {
			ev_ack_seq--;
		}
	}

	if (!scratch->expecting_ack) return;

	// MTP_PRINT("before DIV\n");
	// MTP_PRINT("slows_cong BEFORE: cwnd:%u\n", ctx->cwnd_size);
	if(scratch->change_cwnd) {
		uint32_t rmlen = MTP_SEQ_SUB(ev_ack_seq, ctx->send_una, ctx->send_una);
		// MTP_PRINT("rmlen: %u, eff_SMSS: %u\n", rmlen, ctx->eff_SMSS);
		uint16_t packets = rmlen / ctx->eff_SMSS;
		// MTP_PRINT("after\n");
		if (packets * ctx->eff_SMSS > rmlen) {
			packets++;
		}

		if (ctx->cwnd_size < ctx->ssthresh) {
			ctx->cwnd_size += (ctx->SMSS * packets);
		} else {
			// MTP_PRINT("SMSS: %u, cwnd: %u\n", ctx->SMSS, ctx->cwnd_size);
			uint32_t add_cwnd = packets * ctx->SMSS * ctx->SMSS / ctx->cwnd_size;
			// MTP_PRINT("after\n");
			ctx->cwnd_size += add_cwnd;
		}
	}
	// MTP_PRINT("after DIV\n");
	// MTP_PRINT("slows_cong AFTER: cwnd:%u\n", ctx->cwnd_size);
	*/
}

static inline void ack_net_ep(mtcp_manager_t mtcp, uint32_t cur_ts, uint32_t ev_ack_seq, 
	uint32_t ev_window, uint32_t ev_seq, tcp_stream* cur_stream, scratchpad* scratch)
{
	// MTP TODO: do wscale properly?
	// if(scratch->skip_ack_eps) return;

	/*
	struct mtp_ctx *ctx = cur_stream->mtp;
	
	if (ctx->state == MTP_TCP_FIN_WAIT_1_ST || 
		ctx->state == MTP_TCP_FIN_WAIT_2_ST ||
		ctx->state == MTP_TCP_CLOSING_ST || 
		ctx->state == MTP_TCP_CLOSE_WAIT_ST || 
		ctx->state == MTP_TCP_LAST_ACK_ST) {
		if (ctx->fin_sent && ev_ack_seq == ctx->final_seq + 1) {
			ev_ack_seq--;
		}
	}
	
	// if (cur_stream->mtp->state != MTP_TCP_ESTABLISHED_ST) return;


	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	
	// MTP_PRINT("ack_net_ep before grabbing lock\n");
	SBUF_LOCK(&sndvar->write_lock);
	// MTP_PRINT("ack_net_ep after grabbing lock\n");

	// Update window
	// MTP_PRINT("ev_window: %u, wscale_remote: %u\n", ev_window, ctx->wscale_remote);
	uint32_t rwindow = ev_window << ctx->wscale_remote;
	// MTP_PRINT("rwindow: %u\n", rwindow);
    // MTP TODO: sequence comparisons
    if (MTP_SEQ_LT(ctx->lwu_seq, ev_seq, ctx->send_una) ||
        (ctx->lwu_seq == ev_seq && MTP_SEQ_LT(ctx->lwu_ack, ev_ack_seq, ctx->send_una)) ||
        (ctx->lwu_ack == ev_ack_seq && rwindow > ctx->last_rwnd_remote)){
        uint32_t rwindow_prev = ctx->last_rwnd_remote;
		// MTP_PRINT("ack_net_ep, before: lwu_seq: %u, lwu_ack: %u, rwindow: %u\n", cur_stream->mtp->lwu_seq,
		// 							   cur_stream->mtp->lwu_ack,
		// 							   cur_stream->mtp->last_rwnd_remote);
        ctx->last_rwnd_remote = rwindow;
        ctx->lwu_seq = ev_seq;
        ctx->lwu_ack = ev_ack_seq;
		// MTP_PRINT("ack_net_ep, after: lwu_seq: %u, lwu_ack: %u, rwindow: %u\n", cur_stream->mtp->lwu_seq,
		// 							   cur_stream->mtp->lwu_ack,
		// 							   cur_stream->mtp->last_rwnd_remote);
        if (rwindow_prev < MTP_SEQ_SUB(ctx->send_next, ctx->send_una, ctx->send_una) &&
            ctx->last_rwnd_remote >= MTP_SEQ_SUB(ctx->send_next, ctx->send_una, ctx->send_una)){
            // This is kinda "notify" in MTP
			MTP_PRINT("rwnd opened up\n");
            RaiseWriteEvent(mtcp, cur_stream);
        }
    }
 
    // MTP TODO: fix sndbuf->len	
	uint32_t data_rest =  sndvar->sndbuf->len - 
					      MTP_SEQ_SUB(ctx->send_next, sndvar->sndbuf->head_seq,
									  sndvar->sndbuf->head_seq);

	// MTP_PRINT("ack_net_ep: data_rest: %d, ev_ack_seq: %u, send_next: %u, len: %d, head_seq:%d\n", 
	// 		data_rest, ev_ack_seq, ctx->send_next, sndvar->sndbuf->len, sndvar->sndbuf->head_seq);

	if (data_rest == 0 && ev_ack_seq == ctx->send_next) {
		SBUF_UNLOCK(&sndvar->write_lock);
		if (ctx->state != MTP_TCP_FIN_WAIT_1_ST &&
		    ctx->state != MTP_TCP_CLOSING_ST) {
			TimerCancel(mtcp, cur_stream);
			MTP_PRINT("THIS CASE\n");
			// MTP_PRINT("ack_net_ep before releasing lock\n");
		}
		else {
			// Send FIN
			mtp_bp* bp = GetFreeBP(cur_stream);

			// MTP_PRINT("got bp\n");
			// MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
			
			memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));

			bp->hdr.source = cur_stream->mtp->local_port;
			bp->hdr.dest = cur_stream->mtp->remote_port;
			bp->hdr.seq = htonl(ctx->final_seq);
			// MTP_PRINT("Seq ack_ep: %u\n", ntohl(bp->hdr.seq));
			bp->hdr.ack_seq = htonl(ctx->recv_next);

			bp->hdr.syn = FALSE;
			bp->hdr.ack = TRUE;
			bp->hdr.fin = TRUE;

			// options to calculate data offset

			// MTP TODO: SACK? 
		#if TCP_OPT_SACK_ENABLED
			MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
		#endif

			MTP_set_opt_nop(&(bp->opts.nop1));
			MTP_set_opt_nop(&(bp->opts.nop2));

			// MTP TODO: Timestamp
			MTP_set_opt_timestamp(&(bp->opts.timestamp),
									htonl(cur_ts),
									htonl(ctx->ts_recent));
			

			// MTP TODO: would the MTP program do the length 
			//           calculation itself?
			uint16_t optlen = MTP_CalculateOptionLength(bp);
			bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

			// MTP TODO: wscale on local
			uint32_t window32 = ctx->rwnd_size >> ctx->wscale;
			uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
			bp->hdr.window = htons(advertised_window);
			if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

			// Payload
			// MTP TODO: fix snbuf
			bp->payload.data = NULL;
			bp->payload.len = 0;
			bp->payload.needs_segmentation = FALSE;

			AddtoGenList(mtcp, cur_stream, cur_ts);
		} 	
		// MTP_PRINT("ack_net_ep after releasing lock\n");
		return;
	}

	uint32_t effective_window = ctx->cwnd_size;
    if (ctx->last_rwnd_remote < effective_window){
        effective_window = ctx->last_rwnd_remote;
    }
	
	MTP_PRINT("ack_net_ep: cwnd: %d, rwnd: %d\n", ctx->cwnd_size, ctx->last_rwnd_remote);
    uint32_t bytes_to_send = 0;

	if(ctx->duplicate_acks == 3) {
		bytes_to_send = ctx->eff_SMSS;
        if (bytes_to_send > effective_window){
            bytes_to_send = effective_window;
        }
		if (bytes_to_send > data_rest){
			bytes_to_send = data_rest;
		}

        // MTP TODO: check that size + options is not more than MSS
        mtp_bp* bp = GetFreeBP(cur_stream);
		// MTP_PRINT("dup ack got bp\n");
		// MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
        
        memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));

        bp->hdr.source = ctx->local_port;
        bp->hdr.dest = ctx->remote_port;
        bp->hdr.seq = htonl(ctx->send_una);
		// MTP_PRINT("dup ack Seq: %u\n", ntohl(bp->hdr.seq));
        bp->hdr.ack_seq = htonl(ctx->recv_next);

        bp->hdr.syn = FALSE;
        bp->hdr.ack = TRUE;

        // options to calculate data offset
       
        // MTP TODO: SACK? 
    #if TCP_OPT_SACK_ENABLED
        MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
    #endif

        MTP_set_opt_nop(&(bp->opts.nop1));
        MTP_set_opt_nop(&(bp->opts.nop2));

        // MTP TODO: Timestamp
        MTP_set_opt_timestamp(&(bp->opts.timestamp),
                                htonl(cur_ts),
                                htonl(ctx->ts_recent));
        
       
        // MTP TODO: would the MTP program do the length 
        //           calculation itself?
        uint16_t optlen = MTP_CalculateOptionLength(bp);
        bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

        // MTP TODO: wscale on local
        uint8_t wscale = ctx->wscale;
    	uint32_t window32 = ctx->rwnd_size >> wscale;  
		// MTP TODO: fix this
    	uint16_t advertised_window = (uint16_t)MIN(window32, TCP_MAX_WINDOW);
        bp->hdr.window = htons(advertised_window);
		if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

        // Payload
        // MTP TODO: fix snbuf
		uint8_t *data = sndvar->sndbuf->head + MTP_SEQ_SUB(ctx->send_una,
														   sndvar->sndbuf->head_seq,
														   sndvar->sndbuf->head_seq);
        bp->payload.data = data;
        bp->payload.len = bytes_to_send;
        bp->payload.needs_segmentation = FALSE;

        AddtoGenList(mtcp, cur_stream, cur_ts);

		// MTP_PRINT("dup ack prepared bp:\n");
		// print_MTP_bp(bp);
		// MTP_PRINT("dup ack head ptr: %p, head seq: %d, len: %d, snd wnd: %d\n", sndvar->sndbuf->head, 
		// 		sndvar->sndbuf->head_seq, sndvar->sndbuf->len, sndvar->snd_wnd);
		
		// MTP_PRINT("ack_net_ep before releasing lock\n");
		SBUF_UNLOCK(&sndvar->write_lock);
		// MTP_PRINT("ack_net_ep after releasing lock\n");
		return;
	}

	// Continue sending if window is available and there's remaining data in sending buffer
	uint32_t window_avail = 0;
	uint32_t window_end_exclusive = ev_ack_seq + effective_window;
	MTP_PRINT("ack_net_ep: window_end_exclusive: %u, send_next: %u, send_una: %u\n", 
			window_end_exclusive, ctx->send_next, ctx->send_una);
	if (MTP_SEQ_GT(window_end_exclusive, ctx->send_next, ctx->send_una)) 
		window_avail = MTP_SEQ_SUB(window_end_exclusive, ctx->send_next,
								   ctx->send_una);

	if (window_avail == 0)
		bytes_to_send = 0;
	else {
        if (data_rest < window_avail) bytes_to_send = data_rest;
        else bytes_to_send = window_avail;
    }

	// MTP TODO: check bytes to send is not zero
	MTP_PRINT("ack_net_ep: window_avail: %u, bytes to send: %d\n", 
						window_avail, bytes_to_send);

	if (bytes_to_send > 0) {

		mtp_bp* bp;
		bool merging = FALSE;

		if (!BPBuffer_isempty(cur_stream)){
			mtp_bp* last_bp = GetLastBP(cur_stream);
			uint32_t next_sched_byte = ntohl(last_bp->hdr.seq) + last_bp->payload.len;
			if (last_bp->payload.len > 0 && 
				ctx->send_next == next_sched_byte){
				MTP_PRINT("merging, prev blueprint is:\n");
				print_MTP_bp(last_bp);
				bp = last_bp;
				merging = TRUE;
			}
		}

		if (!merging){
			bp = GetFreeBP(cur_stream);	
		}
		MTP_PRINT("got bp\n");
		MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
		
		if (!merging){
			memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));
		}

		bp->hdr.source = cur_stream->mtp->local_port;
		bp->hdr.dest = cur_stream->mtp->remote_port;

		if (!merging){
			bp->hdr.seq = htonl(ctx->send_next);
		}
		MTP_PRINT("Seq: %u\n", ntohl(bp->hdr.seq));

		// MTP_PRINT("Seq ack_ep: %u\n", ntohl(bp->hdr.seq));
		bp->hdr.ack_seq = htonl(ctx->recv_next);

		bp->hdr.syn = FALSE;
		bp->hdr.ack = TRUE;

		// options to calculate data offset
	
		// MTP TODO: SACK? 
	#if TCP_OPT_SACK_ENABLED
		MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
	#endif

		MTP_set_opt_nop(&(bp->opts.nop1));
		MTP_set_opt_nop(&(bp->opts.nop2));

		// MTP TODO: Timestamp
		MTP_set_opt_timestamp(&(bp->opts.timestamp),
								htonl(cur_ts),
								htonl(ctx->ts_recent));
		
	
		// MTP TODO: would the MTP program do the length 
		//           calculation itself?
		uint16_t optlen = MTP_CalculateOptionLength(bp);
		bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

		// MTP TODO: wscale on local
		uint32_t window32 = cur_stream->mtp->rwnd_size >> cur_stream->mtp->wscale;
		uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
		bp->hdr.window = htons(advertised_window);
		if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

		// Payload
		// MTP TODO: fix snbuf
		if (!merging){
			uint8_t *data = sndvar->sndbuf->head + MTP_SEQ_SUB(ctx->send_next,
															sndvar->sndbuf->head_seq,
															sndvar->sndbuf->head_seq);
			bp->payload.data = data;
		}

		if (merging){
			bp->payload.len += bytes_to_send;
		}
		else {
			bp->payload.len = bytes_to_send;
		}


		if (bp->payload.len > ctx->eff_SMSS){
			bp->payload.needs_segmentation = TRUE;
			bp->payload.seg_size = ctx->eff_SMSS;
			bp->payload.seg_rule_group_id = 1; 
		} 

		AddtoGenList(mtcp, cur_stream, cur_ts);	

		// MTP_PRINT("prepared bp:\n");
		// print_MTP_bp(bp);
		// MTP_PRINT("head ptr: %p, head seq: %d, len: %d, snd_wnd: %d\n", sndvar->sndbuf->head, 
		// 		sndvar->sndbuf->head_seq, sndvar->sndbuf->len, sndvar->snd_wnd);

		ctx->send_next = ctx->send_next + bytes_to_send;
		// MTP_PRINT("ack_ep send next: %u\n", ctx->send_next);
	}

	// Remove acked sequence from sending buffer
	// This step is kinda target dependent (depending on the implementation of sending buffer)
	uint32_t rmlen = MTP_SEQ_SUB(ev_ack_seq, ctx->send_una, ctx->send_una);
	// MTP_PRINT("ack_net_ep: rmlen: %u, send_una: %u, ev_ack_seq: %u\n", 
	// 		rmlen, ctx->send_una, ev_ack_seq);
	if(rmlen > 0) {
		// MTP_PRINT("Removing %d bytes\n", rmlen);
		//uint32_t offset = MTP_SEQ_SUB(ctx->send_una, ctx->init_seq, ctx->init_seq);
		uint32_t offset = ctx->send_una;
		TxDataFlush(mtcp, cur_stream, offset, rmlen);
		// MTP_PRINT("head ptr: %p, head seq: %d, len: %d, snd_wnd: %d\n", sndvar->sndbuf->head, 
			// sndvar->sndbuf->head_seq, sndvar->sndbuf->len, sndvar->snd_wnd);
		ctx->send_una = ev_ack_seq;
		ctx->num_rtx = 0;
	}

	// MTP TODO: match the mtp file in creating right "event" on timeout
	TimerRestart(mtcp, cur_stream, cur_ts);
	// MTP_PRINT("ack_net_ep before releasing lock\n");
	SBUF_UNLOCK(&sndvar->write_lock);
	// MTP_PRINT("ack_net_ep after releasing lock\n");
	*/
}

static inline void fin_ack_ep(mtcp_manager_t mtcp, uint32_t cur_ts, 
		uint32_t ev_ack_seq, tcp_stream *cur_stream, scratchpad *scratch)
{
	/*
	MTP_PRINT("----------------------------- fin_ack_ep: %u\n", ev_ack_seq);
	MTP_PRINT("cur_stream->mtp->state: %d\n", cur_stream->mtp->state);
	struct mtp_ctx *ctx = cur_stream->mtp;
	if ((ctx->state != MTP_TCP_FIN_WAIT_1_ST) &&
	    (ctx->state != MTP_TCP_CLOSING_ST) &&
		(ctx->state != MTP_TCP_LAST_ACK_ST)) return;

	MTP_PRINT("in fin_ack_ep: ev_ack_seq: %u, final_seq: %u, fin_sent:%d\n", 
			ev_ack_seq, ctx->final_seq, ctx->fin_sent);

	if (cur_stream->socket){
		MTP_PRINT("socket id: %d\n", cur_stream->socket->id);
	}
	
	if (ctx->fin_sent && 
		ev_ack_seq == ctx->final_seq + 1) {
		ctx->send_una = ev_ack_seq;
		if (MTP_SEQ_GT(ev_ack_seq, ctx->send_next, ctx->send_una)) {
			TRACE_DBG("Stream %d: update snd_nxt to %u\n", 
					cur_stream->id, ev_ack_seq);
			MTP_PRINT("I think this is not supposed to happen\n");
			ctx->send_next = ev_ack_seq;
		}
		
		ctx->num_rtx = 0;
		TimerCancel(mtcp, cur_stream);
		if (ctx->state == MTP_TCP_FIN_WAIT_1_ST){
			ctx->state = MTP_TCP_FIN_WAIT_2_ST;
			MTP_PRINT("fin_ack_ep: state changed to FIN_WAIT_2\n");
		}
		else if (ctx->state == MTP_TCP_CLOSING_ST){
			ctx->state = MTP_TCP_TIME_WAIT_ST;
			// MTP TODO: do we need this?
			// MTP TODO: fix
			ctx->state = MTP_TCP_CLOSED_ST;
			DestroyCtx(mtcp, cur_stream, ctx->local_port);
			MTP_PRINT("fin_ack_ep: state changed to CLOSED\n");
			//AddtoTimewaitList(mtcp, cur_stream, cur_ts);
		}
		else if (ctx->state == MTP_TCP_LAST_ACK_ST){
			ctx->state = MTP_TCP_CLOSED_ST;
			DestroyCtx(mtcp, cur_stream, ctx->local_port);
			MTP_PRINT("fin_ack_ep: state changed to CLOSED\n");
		}
	}
	*/
}

static inline void data_net_ep(mtcp_manager_t mtcp, uint32_t cur_ts, uint32_t ev_seq, uint8_t *ev_payload,
    int ev_payloadlen, tcp_stream* cur_stream)
{
	/*
	struct mtp_ctx *ctx = cur_stream->mtp;
	if (ctx->state == MTP_TCP_CLOSE_WAIT_ST) return;
    struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
    uint32_t last_rcvd_seq = ev_seq + ev_payloadlen;

	// MTP TODO?: new ordered data


	MTP_PRINT("data_net_ep: ev_seq: %u, ev_payloadlen: %d, last_rcvd_seq: %u, ctx->rwnd_size: %u\n", 
			ev_seq, ev_payloadlen, last_rcvd_seq, ctx->rwnd_size);
	MTP_PRINT("MTP_SEQ_GT(last_rcvd_seq, ctx->recv_next + ctx->rwnd_size, ctx->recv_init_seq): %d\n", 
			MTP_SEQ_GT(last_rcvd_seq, ctx->recv_next + ctx->rwnd_size, ctx->recv_init_seq));
	MTP_PRINT("data_net_ep: MTP_SEQ_LT(last_rcvd_seq, ctx->recv_next, ctx->recv_init_seq): %d\n", 
			MTP_SEQ_LT(last_rcvd_seq, ctx->recv_next, ctx->recv_init_seq));
	// if seq and segment length is lower than rcv_nxt or exceeds buffer, ignore and send ack
	if (MTP_SEQ_LT(last_rcvd_seq, ctx->recv_next, ctx->recv_init_seq) ||
		MTP_SEQ_GT(last_rcvd_seq, ctx->recv_next + ctx->rwnd_size, ctx->recv_init_seq)) {
		return;
	}

	// if (!rcvvar->rcvbuf) {
	// 	rcvvar->rcvbuf = RBInit(mtcp->rbm_rcv, ctx->recv_init_seq);
	// 	ctx->meta_rwnd = RBInit(mtcp->rbm_rcv, ctx->recv_init_seq);
	// 	if (!rcvvar->rcvbuf || !ctx->meta_rwnd) {
	// 		MTP_PRINT("Stream %d: Failed to allocate receive buffer.\n", 
	// 				cur_stream->id);
	// 		cur_stream->state = TCP_ST_CLOSED;
	// 		cur_stream->close_reason = TCP_NO_MEM;
	// 		RaiseErrorEvent(mtcp, cur_stream);

	// 		return;
	// 	}
	// }

	MTP_PRINT("Grabbing lock in data_net_ep\n");
	if (SBUF_LOCK(&rcvvar->read_lock)) {
		if (errno == EDEADLK) perror("ProcessTCPPayload: read_lock blocked\n");
		assert(0);
	}

	// MTP TODO: this needs to be optimized
	// MtpWndPut(mtcp->rbm_rcv, ctx->meta_rwnd, ev_payload, ev_payloadlen, ev_seq);
	// MtpWndSlide(mtcp->rbm_rcv, ctx->meta_rwnd, AT_MTCP);
	// ctx->recv_next = ctx->meta_rwnd->head_seq;

    RBPut(mtcp->rbm_rcv, rcvvar->rcvbuf, ev_payload, ev_payloadlen, ev_seq);
	MTP_PRINT("recv buffer merged len: %u\n", rcvvar->rcvbuf->merged_len);
	MTP_PRINT("my calculated merged len: %u, recv_next: %u, last_flushed: %u\n", 
			MTP_SEQ_SUB(ctx->recv_next, ctx->last_flushed, ctx->last_flushed) - 1, 
			ctx->recv_next, ctx->last_flushed);
	ctx->recv_next = rcvvar->rcvbuf->head_seq + rcvvar->rcvbuf->merged_len;

	if (ctx->state == MTP_TCP_FIN_WAIT_1_ST || 
		ctx->state == MTP_TCP_FIN_WAIT_2_ST) {
			// MTP TODO: integrate with MTP. Do we even need to do this?
		RBRemove(mtcp->rbm_rcv, 
				rcvvar->rcvbuf, 
				MTP_SEQ_SUB(ctx->recv_next, ctx->last_flushed, ctx->last_flushed) - 1, 
				AT_MTCP);
	}

	SBUF_UNLOCK(&rcvvar->read_lock);

	if (ctx->state == MTP_TCP_ESTABLISHED_ST) {
		// "add_data_seg" instruction
		MTP_PRINT("data_net_ep: raising read event\n");
		RaiseReadEvent(mtcp, cur_stream);
	}
		*/
}

inline void send_ack_ep(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream *cur_stream)
{
/*
	struct mtp_ctx *ctx = cur_stream->mtp;

	if (ctx->state == MTP_TCP_CLOSE_WAIT_ST) return;

	if (ctx->state == MTP_TCP_ESTABLISHED_ST &&
		ctx->fin_received &&
	    ctx->final_seq_remote == ctx->recv_next) {
		MTP_PRINT("data_net_ep: final_seq_remote: %u, recv_next: %u\n", 
				ctx->final_seq_remote, ctx->recv_next);
		ctx->state = MTP_TCP_CLOSE_WAIT_ST;
		ctx->recv_next += 1;
		MTP_PRINT("data_net_ep: raising read event for fin\n");
		RaiseReadEvent(mtcp, cur_stream);
	}


    struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	ctx->rwnd_size = rcvvar->rcvbuf->size - (MTP_SEQ_SUB(ctx->recv_next,
														ctx->last_flushed,
														ctx->last_flushed) - 1);

	mtp_bp* bp;													
	bool merging = FALSE;

	if (!BPBuffer_isempty(cur_stream)){
		mtp_bp* last_bp = GetLastBP(cur_stream);
		if (last_bp->payload.len == 0 &&
			last_bp->hdr.ack == TRUE &&
			last_bp->hdr.fin == FALSE) {
			MTP_PRINT("merging, prev blueprint is:\n");
			print_MTP_bp(last_bp);
			bp = last_bp;
			merging = TRUE;
		}
	}	
	
	if (!merging){
		bp = GetFreeBP(cur_stream);
	}

	// MTP_PRINT("got bp\n");
	// MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
	
	memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));

	bp->hdr.source = cur_stream->mtp->local_port;
	bp->hdr.dest = cur_stream->mtp->remote_port;
	bp->hdr.seq = htonl(ctx->send_next);
	// MTP_PRINT("Seq ack_ep: %u\n", ntohl(bp->hdr.seq));
	bp->hdr.ack_seq = htonl(ctx->recv_next);

	bp->hdr.syn = FALSE;
	bp->hdr.ack = TRUE;

	// options to calculate data offset

	// MTP TODO: SACK? 
#if TCP_OPT_SACK_ENABLED
	MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
#endif

	MTP_set_opt_nop(&(bp->opts.nop1));
	MTP_set_opt_nop(&(bp->opts.nop2));

	// MTP TODO: Timestamp
	MTP_set_opt_timestamp(&(bp->opts.timestamp),
							htonl(cur_ts),
							htonl(ctx->ts_recent));
	

	// MTP TODO: would the MTP program do the length 
	//           calculation itself?
	uint16_t optlen = MTP_CalculateOptionLength(bp);
	bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

	// MTP TODO: wscale on local
	uint32_t window32 = ctx->rwnd_size >> ctx->wscale;
	uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
	bp->hdr.window = htons(advertised_window);
	if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

	// Payload
	// MTP TODO: fix snbuf
	bp->payload.data = NULL;
	bp->payload.len = 0;
	bp->payload.needs_segmentation = FALSE;

	AddtoGenList(mtcp, cur_stream, cur_ts);
	*/
    
}

static inline int listen_ep(mtcp_manager_t mtcp, int sockid, int backlog) 
{
	return CreateListenCtx(mtcp, sockid, backlog);
}

static inline struct accept_res* accept_ep(mctx_t mctx, mtcp_manager_t mtcp,
	struct sockaddr *addr, socklen_t *addrlen, bool non_block, struct mtp_listen_ctx *ctx) 
{
	// Wait until a client request to connect
	pthread_mutex_lock(&ctx->accept_lock);
	if (TAILQ_EMPTY(&ctx->pending)) {
		if (non_block) {
			MTP_PRINT("accept_ep: non-blocking mode, no pending connections\n");
			pthread_mutex_unlock(&ctx->accept_lock);
			MTP_PRINT("accept_ep: errno set to EAGAIN\n");
			errno = EAGAIN;
			MTP_PRINT("accept_ep: returning NULL\n");
			return NULL;
		}
		else{
			MTP_PRINT("accept_ep: blocking mode, waiting for connections\n");
			pthread_cond_wait(&ctx->accept_cond, &ctx->accept_lock);// check lock
			if (mtcp->ctx->done || mtcp->ctx->exit) {
				pthread_mutex_unlock(&ctx->accept_lock);
				errno = EINTR;
				return NULL;
			}
		}
	}

	MTP_PRINT("accept_ep: pending connections available, proceeding\n");
	struct accept_res *res = TAILQ_FIRST(&ctx->pending);
	TAILQ_REMOVE(&ctx->pending, res, link);
	ctx->pending_len--;
	pthread_mutex_unlock(&ctx->accept_lock);

	// Return res, let target (api) do the following socket allocation
	return res;
}


void timeout_ep(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream* cur_stream){
	/*
	struct mtp_ctx *ctx = cur_stream->mtp;
	// MTP_PRINT("Stream %d Timeout. cwnd: %u, ssthresh: %u\n", 
	// 		cur_stream->id, ctx->cwnd_size, ctx->ssthresh);
	MTP_PRINT("Stream %d, port:%u, Timeout. rto: %u, tx_rto:%u, cur_ts: %u\n", 
			cur_stream->id, cur_stream->mtp->remote_port, cur_stream->sndvar->rto, 
			cur_stream->sndvar->ts_rto, cur_ts);			

	// count number of retransmissions
	if (ctx->num_rtx < MTP_TCP_MAX_RTX) {
		ctx->num_rtx = ctx->num_rtx + 1;
	} else {
		// if it exceeds the threshold, destroy and notify to application
		// MTP_PRINT("Stream %d: Exceed MAX_RTX\n", cur_stream->id);
		
	}
	if (ctx->num_rtx > ctx->max_num_rtx) {
		ctx->max_num_rtx = ctx->num_rtx;
	}
	
	uint8_t backoff;
	// update rto timestamp
	if (ctx->state >= MTP_TCP_ESTABLISHED_ST) {
		backoff = MIN(ctx->num_rtx, MTP_TCP_MAX_BACKOFF);

		uint32_t rto_prev;
		rto_prev = cur_stream->sndvar->rto;
		#ifndef MTP_FIXED_RTO
		cur_stream->sndvar->rto = ((cur_stream->rcvvar->srtt >> 3) + 
				cur_stream->rcvvar->rttvar) << backoff;
		#else
		cur_stream->sndvar->rto = rto_prev << backoff;
		#endif
		if (cur_stream->sndvar->rto <= 0) {
			// MTP_PRINT("Stream %d current rto: %u, prev: %u, state: %s\n", 
					// cur_stream->id, cur_stream->sndvar->rto, rto_prev, 
					// TCPStateToString(cur_stream));
			cur_stream->sndvar->rto = rto_prev;
		}
	} else if (ctx->state >= MTP_TCP_SYN_SENT_ST) {
		// if there is no rtt measured, update rto based on the previous one
		if (ctx->num_rtx < MTP_TCP_MAX_BACKOFF) {
			cur_stream->sndvar->rto <<= 1;
		}
	}
	//cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;

	// reduce congestion window and ssthresh 
	ctx->ssthresh = MIN(ctx->cwnd_size, ctx->last_rwnd_remote) / 2;
	if (ctx->ssthresh < (2 * ctx->SMSS)) {
		ctx->ssthresh = ctx->SMSS * 2;
	}
	ctx->cwnd_size = ctx->SMSS;
	
	// Retransmission
	// MTP TODO: add cases for other states
	
	if (ctx->state == MTP_TCP_ESTABLISHED_ST ||
		ctx->state == MTP_TCP_FIN_WAIT_1_ST ||
		ctx->state == MTP_TCP_CLOSING_ST) {
		
		struct tcp_send_vars *sndvar = cur_stream->sndvar;

		SBUF_LOCK(&sndvar->write_lock);
        // MTP TODO: check that size + options is not more than MSS
        uint32_t data_rest =  sndvar->sndbuf->len - 
					      MTP_SEQ_SUB(ctx->send_una, sndvar->sndbuf->head_seq,
									  sndvar->sndbuf->head_seq);

		uint32_t effective_window = ctx->cwnd_size;
		if (ctx->last_rwnd_remote < effective_window){
			effective_window = ctx->last_rwnd_remote;
		}
		
		uint32_t bytes_to_send = effective_window;
		if (data_rest < effective_window) bytes_to_send = data_rest;
		
		// MTP TODO: check bytes to send is not zero
		// MTP_PRINT("ack_net_ep: bytes to send: %d\n", bytes_to_send);

		// assert(bytes_to_send > 0);
		bool send_fin_again = FALSE;
		if (bytes_to_send == 0 && ctx->fin_sent) {
			if(ctx->send_next == ctx->final_seq &&
				   ctx->send_una == ctx->final_seq) send_fin_again = TRUE;
		}

		mtp_bp* bp = GetFreeBP(cur_stream);

		// MTP_PRINT("got bp\n");
		// MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
		
		memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));

		bp->hdr.source = cur_stream->mtp->local_port;
		bp->hdr.dest = cur_stream->mtp->remote_port;
		bp->hdr.seq = htonl(ctx->send_una);
		// MTP_PRINT("Seq ack_ep: %u\n", ntohl(bp->hdr.seq));
		bp->hdr.ack_seq = htonl(ctx->recv_next);

		bp->hdr.syn = FALSE;
		bp->hdr.ack = TRUE;
		bp->hdr.fin = send_fin_again;

		// options to calculate data offset
	
		// MTP TODO: SACK? 
	#if TCP_OPT_SACK_ENABLED
		MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
	#endif

		MTP_set_opt_nop(&(bp->opts.nop1));
		MTP_set_opt_nop(&(bp->opts.nop2));

		// MTP TODO: Timestamp
		MTP_set_opt_timestamp(&(bp->opts.timestamp),
								htonl(cur_ts),
								htonl(ctx->ts_recent));
		
	
		// MTP TODO: would the MTP program do the length 
		//           calculation itself?
		uint16_t optlen = MTP_CalculateOptionLength(bp);
		bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

		// MTP TODO: wscale on local
		uint32_t window32 = cur_stream->mtp->rwnd_size >> cur_stream->mtp->wscale;
		uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
		bp->hdr.window = htons(advertised_window);
		if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

		// Payload
		// MTP TODO: fix snbuf
		uint8_t *data = sndvar->sndbuf->head + MTP_SEQ_SUB(ctx->send_una,
														sndvar->sndbuf->head_seq,
														sndvar->sndbuf->head_seq);
		bp->payload.data = data;
		bp->payload.len = bytes_to_send;
		bp->payload.needs_segmentation = TRUE;
		bp->payload.seg_size = ctx->eff_SMSS;
		bp->payload.seg_rule_group_id = 1; 

		AddtoGenList(mtcp, cur_stream, cur_ts);	
		
			
		// MTP_PRINT("ack_net_ep before releasing lock\n");
		TimerRestart(mtcp, cur_stream, cur_ts);
		
		SBUF_UNLOCK(&sndvar->write_lock);
		// MTP_PRINT("ack_net_ep after releasing lock\n");
	}
		*/
}

/***********************************************
 MTP Event Processor Chains
 
 EP chinas are globally exposed
 They implement parts for dispatcher in MTP code
 ***********************************************/
void MtpSendChain(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream *cur_stream)
{
	// MTP_PRINT("Calling send chain\n");
    send_ep(mtcp, cur_ts, cur_stream);
}

int MtpReceiveChainPart1(mtcp_manager_t mtcp, socket_map_t socket, 
					bool non_block, char *ev_buf, int ev_data_size, 
					tcp_stream *cur_stream)
{
	return receive_ep(mtcp, socket, non_block, ev_buf, ev_data_size, cur_stream);
}

void MtpReceiveChainPart2(mtcp_manager_t mtcp, uint32_t cur_ts, 
						 tcp_stream *cur_stream)
{
	/*
	struct mtp_ctx* ctx = cur_stream->mtp;
	if (ctx->adv_zero_wnd) {
		// MTP TODO: integrate with MTP
		ctx->adv_zero_wnd = FALSE;
		mtp_bp* bp = GetFreeBP(cur_stream);

		// MTP_PRINT("got bp\n");
		// MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
		
		memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));

		bp->hdr.source = cur_stream->mtp->local_port;
		bp->hdr.dest = cur_stream->mtp->remote_port;
		bp->hdr.seq = htonl(ctx->send_next);
		// MTP_PRINT("Seq ack_ep: %u\n", ntohl(bp->hdr.seq));
		bp->hdr.ack_seq = htonl(ctx->recv_next);

		bp->hdr.syn = FALSE;
		bp->hdr.ack = TRUE;

		// options to calculate data offset

		// MTP TODO: SACK? 
	#if TCP_OPT_SACK_ENABLED
		MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
	#endif

		MTP_set_opt_nop(&(bp->opts.nop1));
		MTP_set_opt_nop(&(bp->opts.nop2));

		// MTP TODO: Timestamp
		MTP_set_opt_timestamp(&(bp->opts.timestamp),
								htonl(cur_ts),
								htonl(ctx->ts_recent));
		

		// MTP TODO: would the MTP program do the length 
		//           calculation itself?
		uint16_t optlen = MTP_CalculateOptionLength(bp);
		bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

		// MTP TODO: wscale on local
		uint32_t window32 = ctx->rwnd_size >> ctx->wscale;
		uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
		bp->hdr.window = htons(advertised_window);
		if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

		// Payload
		// MTP TODO: fix snbuf
		bp->payload.data = NULL;
		bp->payload.len = 0;
		bp->payload.needs_segmentation = FALSE;

		AddtoGenList(mtcp, cur_stream, cur_ts);
	}
	*/
}


void MtpDataChain(mtcp_manager_t mtcp, uint32_t cur_ts, uint32_t seq, uint8_t *payload, 
	int payloadlen, tcp_stream *cur_stream)
{
	data_net_ep(mtcp, cur_ts, seq, payload, payloadlen, cur_stream);
    send_ack_ep(mtcp, cur_ts, cur_stream);
}

int MtpListenChain(mtcp_manager_t mtcp, int sockid, int backlog)
{
	return listen_ep(mtcp, sockid, backlog);
}

struct accept_res* MtpAcceptChain(mctx_t mctx, mtcp_manager_t mtcp, struct sockaddr *addr, 
	socklen_t *addrlen, bool non_block, struct mtp_listen_ctx *ctx) 
{
	return accept_ep(mctx, mtcp, addr, addrlen, non_block, ctx);
}


tcp_stream* MtpConnectChainPart1(mtcp_manager_t mtcp, uint32_t cur_ts,
					 uint32_t ev_local_ip, uint32_t ev_remote_ip, 
					 uint16_t ev_local_port, uint16_t ev_remote_port){
	
	// MTP TODO: do rand init seq
	// uint32_t init_seq = rand_r(&next_seed) % TCP_MAX_SEQ;
	uint32_t init_seq = 0;	

	tcp_stream *cur_stream = CreateCtx(mtcp, cur_ts, 
                                      ev_remote_ip, ev_local_ip, 
                                      ev_remote_port, ev_local_port,
                                      false, 1460, 
                                      init_seq, init_seq, init_seq + 1,
                                      0, 0, 0, 0, 0,
                                      MTP_TCP_SYN_SENT_ST);
	MTP_PRINT("Created stream with saddr: %u, daddr: %u, sport: %u, dport: %u\n",
			cur_stream->saddr, cur_stream->daddr,
			cur_stream->sport, cur_stream->dport);

	// cur_stream->sndvar->sndbuf = SBInit(mtcp->rbm_snd, cur_stream->mtp->init_seq + 1);
	if (!cur_stream->sndvar->sndbuf) {
		cur_stream->close_reason = TCP_NO_MEM;
		/* notification may not required due to -1 return */
		errno = ENOMEM;
		return NULL;
	}
	return cur_stream;
}
	
void MtpConnectChainPart2(mtcp_manager_t mtcp, uint32_t cur_ts,
					 uint32_t ev_local_ip, uint32_t ev_remote_ip, 
					 uint16_t ev_local_port, uint16_t ev_remote_port, 
					 tcp_stream *cur_stream){	
	
	mtp_bp* bp = GetFreeBP(cur_stream);

	// MTP_PRINT("got bp\n");
	// MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
    
    memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr));

	/*
	struct mtp_ctx *ctx = cur_stream->mtp;
	bp->hdr.source = ctx->local_port;
	bp->hdr.dest = ctx->remote_port;
	// MTP TODO: technically, should be the variable in Part1
    bp->hdr.seq = htonl(ctx->init_seq);
    bp->hdr.syn = TRUE;
    bp->hdr.ack = FALSE;

    // options to calculate data offset
    // MSS
    MTP_set_opt_mss(&(bp->opts.mss), cur_stream->mtp->SMSS);
   
    // MTP TODO: SACK? 
#if TCP_OPT_SACK_ENABLED
    MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
#endif

    MTP_set_opt_nop(&(bp->opts.nop1));
    MTP_set_opt_nop(&(bp->opts.nop2));

    // MTP TODO: Timestamp
    MTP_set_opt_timestamp(&(bp->opts.timestamp),
                            htonl(cur_ts),
                            htonl(ctx->ts_recent));
    
    // MTP TODO: Window scale
    MTP_set_opt_nop(&(bp->opts.nop3));
    MTP_set_opt_wscale(&(bp->opts.wscale), cur_stream->mtp->wscale);
   
    // MTP TODO: would the MTP program do the length 
    //           calculation itself?
    uint16_t optlen = MTP_CalculateOptionLength(bp);
    bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

    uint32_t window32 = cur_stream->mtp->rwnd_size >> cur_stream->mtp->wscale;
	uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
	bp->hdr.window = htons(advertised_window);
	if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

    // Payload
    bp->payload.data = NULL;
    bp->payload.len = 0;
    bp->payload.needs_segmentation = FALSE;

    AddtoGenList(mtcp, cur_stream, cur_ts);
	*/
}

void MtpTimeoutChain(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream* cur_stream){
	timeout_ep(mtcp, cur_ts, cur_stream);
}

void MtpCloseChain(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream* cur_stream){
	/*
	struct mtp_ctx *ctx = cur_stream->mtp;

	ctx->closed = TRUE;

	if (ctx->state == MTP_TCP_CLOSED_ST) {
		MTP_PRINT("Stream %d at TCP_ST_CLOSED. destroying the stream.\n", 
				cur_stream->id);
		DestroyCtx(mtcp, cur_stream, ctx->local_port);
		return;

	} else if (ctx->state == MTP_TCP_SYN_SENT_ST) {
#if 1
		DestroyCtx(mtcp, cur_stream, ctx->local_port);
#endif
		return;

	} else if (ctx->state != MTP_TCP_ESTABLISHED_ST && 
			ctx->state != MTP_TCP_CLOSE_WAIT_ST) {
		TRACE_API("Stream %d at bad state\n", 
				cur_stream->id);
		errno = EBADF;
		return;
	}

	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	if (sndvar->sndbuf) {
		ctx->final_seq = sndvar->sndbuf->head_seq + sndvar->sndbuf->len;
	} else {
		ctx->final_seq = ctx->send_next;
	}

	// if (CONFIG.tcp_timeout > 0)
	// 	RemoveFromTimeoutList(mtcp, cur_stream);

	if (ctx->state == MTP_TCP_ESTABLISHED_ST) {
		ctx->state = MTP_TCP_FIN_WAIT_1_ST;
	} else if (ctx->state == MTP_TCP_CLOSE_WAIT_ST) {
		ctx->state = MTP_TCP_LAST_ACK_ST;
	}
	// SEND FIN
	ctx->fin_sent = TRUE;

	mtp_bp* bp = GetFreeBP(cur_stream);

	// MTP_PRINT("got bp\n");
	// MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
	
	memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));

	bp->hdr.source = cur_stream->mtp->local_port;
	bp->hdr.dest = cur_stream->mtp->remote_port;
	bp->hdr.seq = htonl(ctx->final_seq);
	// MTP_PRINT("Seq ack_ep: %u\n", ntohl(bp->hdr.seq));
	bp->hdr.ack_seq = htonl(ctx->recv_next);

	bp->hdr.syn = FALSE;
	bp->hdr.ack = TRUE;
	bp->hdr.fin = TRUE;

	// options to calculate data offset

	// MTP TODO: SACK? 
#if TCP_OPT_SACK_ENABLED
	MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
#endif

	MTP_set_opt_nop(&(bp->opts.nop1));
	MTP_set_opt_nop(&(bp->opts.nop2));

	// MTP TODO: Timestamp
	MTP_set_opt_timestamp(&(bp->opts.timestamp),
							htonl(cur_ts),
							htonl(ctx->ts_recent));
	

	// MTP TODO: would the MTP program do the length 
	//           calculation itself?
	uint16_t optlen = MTP_CalculateOptionLength(bp);
	bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

	// MTP TODO: wscale on local
	uint32_t window32 = ctx->rwnd_size >> ctx->wscale;
	uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
	bp->hdr.window = htons(advertised_window);
	if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

	// Payload
	// MTP TODO: fix snbuf
	bp->payload.data = NULL;
	bp->payload.len = 0;
	bp->payload.needs_segmentation = FALSE;

	AddtoGenList(mtcp, cur_stream, cur_ts);
	*/
}

void MtpFinChain(mtcp_manager_t mtcp, uint32_t cur_ts,
				 uint32_t ev_seq, uint32_t ev_payloadlen, 
				 tcp_stream* cur_stream){
	
	/*
    struct mtp_ctx *ctx = cur_stream->mtp;

	bool send_ack = FALSE;

	ctx->fin_received = TRUE;
	ctx->final_seq_remote = ev_seq + ev_payloadlen;

	if (ctx->state == MTP_TCP_ESTABLISHED_ST) send_ack = TRUE;

	MTP_PRINT("ev_seq: %u, ev_payload_len: %u, recv_next: %u\n",
			ev_seq, ev_payloadlen, ctx->recv_next);

	if (ctx->final_seq_remote == ctx->recv_next){
		ctx->recv_next = ctx->recv_next + 1;
		
		if (ctx->state == MTP_TCP_ESTABLISHED_ST){
				ctx->state = MTP_TCP_CLOSE_WAIT_ST;
				MTP_PRINT("Stream %d: TCP_ST_CLOSE_WAIT\n", cur_stream->id);
				// notify FIN to application
				RaiseReadEvent(mtcp, cur_stream);
		}

		else if (ctx->state == MTP_TCP_FIN_WAIT_1_ST) {
			ctx->state = MTP_TCP_CLOSING_ST;
			send_ack = TRUE;
			MTP_PRINT("Stream %d: TCP_ST_CLOSING\n", cur_stream->id);

		} else if (ctx->state == MTP_TCP_FIN_WAIT_2_ST) {
			send_ack = TRUE;
			ctx->state = MTP_TCP_TIME_WAIT_ST;
			MTP_PRINT("Stream %d: TCP_ST_TIME_WAIT\n", cur_stream->id);
			//AddtoTimewaitList(mtcp, cur_stream, cur_ts);
		}
	}
	if (send_ack)
	{
		mtp_bp* bp = GetFreeBP(cur_stream);

		// MTP_PRINT("got bp\n");
		// MTP_PRINT("index: %u\n", cur_stream->sndvar->mtp_bps_tail);
		
		memset(&(bp->hdr), 0, sizeof(struct mtp_bp_hdr) + sizeof(struct mtp_bp_options));

		bp->hdr.fin = FALSE; 
		if (ctx->state == MTP_TCP_CLOSING_ST){
			if ((ctx->fin_sent && ctx->send_next == ctx->final_seq) ||
				(!ctx->fin_sent)){
					bp->hdr.fin = TRUE;
					ctx->fin_sent = TRUE;
			}
		}

		bp->hdr.source = cur_stream->mtp->local_port;
		bp->hdr.dest = cur_stream->mtp->remote_port;
		bp->hdr.seq = htonl(ctx->send_next);
		if (bp->hdr.fin){
			bp->hdr.seq = htonl(ctx->final_seq);
		}
		// MTP_PRINT("Seq ack_ep: %u\n", ntohl(bp->hdr.seq));
		bp->hdr.ack_seq = htonl(ctx->recv_next);

		bp->hdr.syn = FALSE;
		bp->hdr.ack = TRUE;

		// options to calculate data offset

		// MTP TODO: SACK? 
	#if TCP_OPT_SACK_ENABLED
		MTP_PRINT("ERROR:SACK Not supported in MTP TCP\n");
	#endif

		MTP_set_opt_nop(&(bp->opts.nop1));
		MTP_set_opt_nop(&(bp->opts.nop2));

		// MTP TODO: Timestamp
		MTP_set_opt_timestamp(&(bp->opts.timestamp),
								htonl(cur_ts),
								htonl(ctx->ts_recent));
		

		// MTP TODO: would the MTP program do the length 
		//           calculation itself?
		uint16_t optlen = MTP_CalculateOptionLength(bp);
		bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

		// MTP TODO: wscale on local
		uint32_t window32 = ctx->rwnd_size >> ctx->wscale;
		uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
		bp->hdr.window = htons(advertised_window);
		if (advertised_window == 0) ctx->adv_zero_wnd = TRUE;

		// Payload
		// MTP TODO: fix snbuf
		bp->payload.data = NULL;
		bp->payload.len = 0;
		bp->payload.needs_segmentation = FALSE;

		AddtoGenList(mtcp, cur_stream, cur_ts);

	}
		*/
}
