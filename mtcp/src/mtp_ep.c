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

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))
#define TCP_MAX_WINDOW 65535

// Intermediate output
typedef struct scratchpad_decl {
	uint8_t change_cwnd;
	uint8_t skip_ack_eps;
} scratchpad;


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
		if (TCP_SEQ_GT(cur_stream->sndvar->snd_una, rcvvar->rtt_seq)) {
			if (rcvvar->mdev_max < rcvvar->rttvar) {
				rcvvar->rttvar -= (rcvvar->rttvar - rcvvar->mdev_max) >> 2;
			}
			rcvvar->rtt_seq = cur_stream->snd_nxt;
			rcvvar->mdev_max = tcp_rto_min;
		}
	} else {
		/* fresh measurement */
		rcvvar->srtt = m << 3;
		rcvvar->mdev = m << 1;
		rcvvar->mdev_max = rcvvar->rttvar = MAX(rcvvar->mdev, tcp_rto_min);
		rcvvar->rtt_seq = cur_stream->snd_nxt;
	}

	TRACE_RTT("mrtt: %u (%uus), srtt: %u (%ums), mdev: %u, mdev_max: %u, "
			"rttvar: %u, rtt_seq: %u\n", mrtt, mrtt * TIME_TICK, 
			rcvvar->srtt, TS_TO_MSEC((rcvvar->srtt) >> 3), rcvvar->mdev, 
			rcvvar->mdev_max, rcvvar->rttvar, rcvvar->rtt_seq);
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
 MTP Event Processors
 
 EPs are static and used only by MTP EP chains
 They have 1-to-1 mappings to mtp code
 They should be generated by the MTP compiler
 ***********************************************/
static inline int send_ep(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream *cur_stream)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;

    if (cur_stream->state != TCP_ST_ESTABLISHED) return 0;
	
	SBUF_LOCK(&sndvar->write_lock);
	if (!sndvar->sndbuf || sndvar->sndbuf->len == 0) {
        SBUF_UNLOCK(&sndvar->write_lock);
        return 0;
	}

	// MTP: maps to bytes_to_send
	int data_rest = sndvar->sndbuf->len - (cur_stream->snd_nxt - sndvar->sndbuf->head_seq);
	int window_avail = MIN(sndvar->cwnd, sndvar->peer_wnd) - (cur_stream->snd_nxt - sndvar->snd_una);
    int bytes_to_send = MIN(data_rest, window_avail);
	if (bytes_to_send <= 0) {
		SBUF_UNLOCK(&sndvar->write_lock);
        return 0;
	}

	// MTP: maps to packet blueprint creation
	int seq = cur_stream->snd_nxt;
	uint8_t *data = sndvar->sndbuf->head + (seq - sndvar->sndbuf->head_seq);
	uint32_t ack_seq = cur_stream->rcv_nxt;
    uint8_t wscale = cur_stream->sndvar->wscale_mine;
    uint32_t window32 = cur_stream->rcvvar->rcv_wnd >> wscale;  
    uint16_t window = (uint16_t)MIN(window32, TCP_MAX_WINDOW);

	// MTP: maps to segmentation logic
	// Segment payload size limited by TCP MSS
	int ret = 0;
	int pkt_len = 0;
	while (bytes_to_send > 0) {
		pkt_len = MIN(bytes_to_send, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));
		ret = SendMTPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK,
			seq, ack_seq, window, data, pkt_len); 

		if (ret < 0){
			break;
		} else{
			bytes_to_send -= pkt_len;
			seq += pkt_len;
			data += pkt_len;
			cur_stream->snd_nxt += pkt_len;
		}
	}

    SBUF_UNLOCK(&sndvar->write_lock);

	// MTP: maps to timer event
	TimerStart(mtcp, cur_stream, cur_ts);

	return ret;
}

static inline void rto_ep( mtcp_manager_t mtcp, int32_t cur_ts, uint32_t ack_seq, 
    tcp_stream* cur_stream, scratchpad* scratch)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	if (cur_stream->state != TCP_ST_ESTABLISHED) return;

	scratch->skip_ack_eps = 0;

	if(ack_seq < sndvar->snd_una || cur_stream->snd_nxt < ack_seq) {
		scratch->skip_ack_eps = 1;
		return;
	}

	// Set RTO, using RTT calculation logic from mTCP
	uint32_t rtt = cur_ts - rcvvar->ts_lastack_rcvd;
	EstimateRTT(mtcp, cur_stream, rtt);
	sndvar->rto = (rcvvar->srtt >> 3) + rcvvar->rttvar;
}

static inline void fast_retr_rec_ep(mtcp_manager_t mtcp, uint32_t cur_ts, uint32_t ack_seq, 
    tcp_stream* cur_stream, scratchpad* scratch)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	if (cur_stream->state != TCP_ST_ESTABLISHED) return;

	if(scratch->skip_ack_eps)
		return;

	scratch->change_cwnd = 1;

	if(ack_seq == rcvvar->last_ack_seq) {
		rcvvar->dup_acks++;

		scratch->change_cwnd = 0;

		if(rcvvar->dup_acks == 1) {
			rcvvar->flightsize_dupl = cur_stream->snd_nxt - sndvar->snd_una;
		}

		if(rcvvar->dup_acks == 3) {
			// MTP congestion window resize
			sndvar->ssthresh = MAX(rcvvar->flightsize_dupl / 2, 2 * MSS);
			sndvar->cwnd = sndvar->ssthresh + 1 * MSS;
		}

		if(rcvvar->dup_acks != 3) {
			sndvar->cwnd += MSS;
		}
	} else {
		if(rcvvar->dup_acks > 0) {
			sndvar->cwnd = sndvar->ssthresh;
		}
		rcvvar->dup_acks = 0;
		rcvvar->last_ack_seq = ack_seq;
	}
}

static inline void slows_congc_ep(mtcp_manager_t mtcp, uint32_t cur_ts, uint32_t ack_seq, 
	tcp_stream* cur_stream, scratchpad* scratch)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;

	if (cur_stream->state != TCP_ST_ESTABLISHED) return;

	if(scratch->skip_ack_eps)
		return;

	if(scratch->change_cwnd) {
		uint32_t rmlen = ack_seq - sndvar->snd_una;
		uint16_t packets = rmlen / sndvar->eff_mss;
		if (packets * sndvar->eff_mss > rmlen) {
			packets++;
		}

		if (sndvar->cwnd < sndvar->ssthresh) {
			sndvar->cwnd += (sndvar->mss * packets);
		} else {
			uint32_t add_cwnd = packets * sndvar->mss * sndvar->mss / sndvar->cwnd;
			sndvar->cwnd += add_cwnd;
		}
	}
}

static inline void ack_net_ep(mtcp_manager_t mtcp, uint32_t cur_ts, uint32_t ack_seq, 
	uint32_t window, tcp_stream* cur_stream, scratchpad* scratch)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	if (cur_stream->state != TCP_ST_ESTABLISHED) return;

	if(scratch->skip_ack_eps) {
		return;
	}

	// Update window
	uint32_t rwindow = window << sndvar->wscale_peer;
	uint32_t seq = rcvvar->last_ack_seq;
	if (TCP_SEQ_LT(rcvvar->snd_wl1, seq) ||
		(rcvvar->snd_wl1 == seq && TCP_SEQ_LT(rcvvar->snd_wl2, ack_seq)) ||
		(rcvvar->snd_wl2 == ack_seq && rwindow > sndvar->peer_wnd)) {
		uint32_t rwindow_prev = sndvar->peer_wnd;
		sndvar->peer_wnd = rwindow;
		rcvvar->snd_wl1 = seq;
		rcvvar->snd_wl2 = ack_seq;
		if (rwindow_prev < cur_stream->snd_nxt - sndvar->snd_una && 
			sndvar->peer_wnd >= cur_stream->snd_nxt - sndvar->snd_una) {
			// This is kinda "notify" instruction in MTP
			RaiseWriteEvent(mtcp, cur_stream);
		}
	}
	
	uint32_t data_rest = sndvar->snd_una + sndvar->sndbuf->len - cur_stream->snd_nxt;
	if (data_rest == 0 && ack_seq == cur_stream->snd_nxt) {
		TimerCancel(mtcp, cur_stream);
		return;
	}

	uint32_t effective_window = MIN(sndvar->cwnd, sndvar->peer_wnd);
	uint32_t bytes_to_send = 0;

	if(rcvvar->dup_acks == 3) {
		SBUF_LOCK(&sndvar->write_lock);

		bytes_to_send = sndvar->eff_mss;
		bytes_to_send = MIN(effective_window, bytes_to_send);

		seq = sndvar->snd_una;
		uint8_t *data = sndvar->sndbuf->head + (seq - sndvar->snd_una);

		SendMTPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, seq, cur_stream->rcv_nxt, 
			effective_window, data, bytes_to_send);
		
		SBUF_UNLOCK(&sndvar->write_lock);
		return;
	}

	// Continue sending if window is available and there's remaining data in sending buffer
	uint32_t window_avail = 0;
	if (sndvar->snd_una + effective_window > cur_stream->snd_nxt) 
		window_avail = sndvar->snd_una + effective_window - cur_stream->snd_nxt;

	if (window_avail == 0)
		bytes_to_send = 0;
	else
		bytes_to_send = MIN(data_rest, window_avail);

	// MTP: maps to segmenting data
	seq = cur_stream->snd_nxt;
	int32_t ack_num = cur_stream->rcv_nxt;
	uint8_t *data = sndvar->sndbuf->head + (seq - sndvar->snd_una);
	int ret = 0;
	SBUF_LOCK(&sndvar->write_lock);
	while (bytes_to_send > 0) {
		int32_t pkt_len = MIN(bytes_to_send, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));

		ret = SendMTPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK,
            seq, ack_num, effective_window, data, pkt_len);

		if (ret < 0){
			break;
		} else {
			bytes_to_send -= pkt_len;
			seq += pkt_len;
			data += pkt_len;
			cur_stream->snd_nxt += pkt_len;
		}
	}
	SBUF_UNLOCK(&sndvar->write_lock);

	// Remove acked sequence from sending buffer
	// This step is kinda target dependent (depending on the implementation of sending buffer)
	uint32_t rmlen = ack_seq - sndvar->snd_una;
	if(rmlen > 0) {
		if (SBUF_LOCK(&sndvar->write_lock)) {
			if (errno == EDEADLK) perror("ProcessACK: write_lock blocked\n");
			assert(0);
		}
		SBRemove(mtcp->rbm_snd, sndvar->sndbuf, rmlen);
		sndvar->snd_una = ack_seq;
		sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;

		RaiseWriteEvent(mtcp, cur_stream);
		SBUF_UNLOCK(&sndvar->write_lock);
	}

	TimerRestart(mtcp, cur_stream, cur_ts);
}

static inline void data_net_ep(mtcp_manager_t mtcp, uint32_t cur_ts, uint32_t seq, uint8_t *payload,
    int payloadlen, tcp_stream* cur_stream)
{
    struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
    uint32_t last_rcvd_seq = seq + payloadlen;

	// MTP TODO?: new ordered data

	// if seq and segment length is lower than rcv_nxt or exceeds buffer, ignore and send ack
	if (TCP_SEQ_LT(last_rcvd_seq, cur_stream->rcv_nxt) ||
		TCP_SEQ_GT(last_rcvd_seq, cur_stream->rcv_nxt + rcvvar->rcv_wnd)) {
		return;
	}

	if (SBUF_LOCK(&rcvvar->read_lock)) {
		if (errno == EDEADLK) perror("ProcessTCPPayload: read_lock blocked\n");
		assert(0);
	}

    RBPut(mtcp->rbm_rcv, rcvvar->meta_rwnd, payload, (uint32_t)payloadlen, seq);
	cur_stream->rcv_nxt = rcvvar->meta_rwnd->head_seq + rcvvar->meta_rwnd->merged_len;
    RBRemove(mtcp->rbm_rcv, rcvvar->meta_rwnd, rcvvar->meta_rwnd->merged_len, AT_APP);
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - (cur_stream->rcv_nxt - 1 - cur_stream->rcvvar->last_flushed_seq);

	SBUF_UNLOCK(&rcvvar->read_lock);

	if (cur_stream->state == TCP_ST_ESTABLISHED) {
		// "add_data_seg" instruction
		RaiseReadEvent(mtcp, cur_stream);
	}
}

inline void send_ack_ep(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream *cur_stream)
{
    uint32_t seq = cur_stream->snd_nxt;
    uint32_t ack = cur_stream->rcv_nxt;
    uint32_t window32 = cur_stream->rcvvar->rcv_wnd;
    uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
    SendMTPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, 
        seq, ack, advertised_window, NULL, 0);
}

static inline int listen_ep(mtcp_manager_t mtcp, int sockid, int backlog) 
{
	return CreateListenCtx(mtcp, sockid, backlog);
}

static inline struct accept_res* accept_ep(mctx_t mctx, mtcp_manager_t mtcp,
	struct sockaddr *addr, socklen_t *addrlen, struct mtp_listen_ctx *ctx) 
{
	// Wait until a client request to connect
	pthread_mutex_lock(&ctx->accept_lock);
	if (TAILQ_EMPTY(&ctx->pending)) {
		pthread_cond_wait(&ctx->accept_cond, &ctx->accept_lock);// check lock
		if (mtcp->ctx->done || mtcp->ctx->exit) {
			pthread_mutex_unlock(&ctx->accept_lock);
			errno = EINTR;
			return NULL;
		}
	}
	struct accept_res *res = TAILQ_FIRST(&ctx->pending);
	TAILQ_REMOVE(&ctx->pending, res, link);
	ctx->pending_len--;
	pthread_mutex_unlock(&ctx->accept_lock);

	if (ctx->state == 0)
		ctx->state = 1;

	// Return res, let target (api) do the following socket allocation
	return res;
}

static inline void syn_ep(mtcp_manager_t mtcp, uint32_t cur_ts,
	uint32_t remote_ip, uint16_t remote_port, uint32_t init_seq, uint16_t rwnd,
	uint32_t local_ip, uint16_t local_port, struct tcphdr* tcph,
	struct mtp_listen_ctx *ctx)
{
	if (ctx->state != 0) return;

	// MTP new_ctx instruction
	tcp_stream *cur_stream = CreateCtx(mtcp, local_ip, local_port,
		remote_ip, remote_port, init_seq, rwnd, cur_ts, tcph);
	if (cur_stream == NULL) return;

	// Add stream to the listen context
	// Note: since mTCP's accept_res struct includes flow context, we insert
	//		new accept_res after context creation
	if (ctx->pending_len < ctx->pending_cap) {
		struct accept_res *acc = malloc(sizeof(*acc));
		acc->stream = cur_stream;
		TAILQ_INSERT_TAIL(&ctx->pending, acc, link);
		ctx->pending_len++;
	} else {
		// Error handling
		cur_stream->state = TCP_ST_CLOSED;
		cur_stream->close_reason = TCP_NOT_ACCEPTED;
		return;
	}

	// MTP pkt gen
	uint32_t window32 = cur_stream->rcvvar->rcv_wnd;
	uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);

	SendMTPPacket(mtcp, cur_stream, cur_ts,
		TCP_FLAG_SYN | TCP_FLAG_ACK, 
		cur_stream->sndvar->iss, //seq
		init_seq + 1, //ack
		advertised_window, //window
		NULL, 0);
}


/***********************************************
 MTP Event Processor Chains
 
 EP chinas are globally exposed
 They implement parts for dispatcher in MTP code
 ***********************************************/
int MtpSendChain(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream *cur_stream)
{
    return send_ep(mtcp, cur_ts, cur_stream);
}

void MtpAckChain(mtcp_manager_t mtcp, uint32_t cur_ts, struct tcphdr* tcph, uint32_t seq, 
	uint32_t ack_seq, int payloadlen, uint32_t window, tcp_stream* cur_stream)
{
    struct tcp_send_vars *sndvar = cur_stream->sndvar;

    if (cur_stream->state == TCP_ST_SYN_RCVD){
	    // check if ACK of SYN
		if (ack_seq != sndvar->iss + 1) {
			CTRACE_ERROR("Stream %d (TCP_ST_SYN_RCVD): "
					"weird ack_seq: %u, iss: %u\n", 
					cur_stream->id, ack_seq, sndvar->iss);
			return;
		}

		RemoveFromRTOList(mtcp, cur_stream);
	
		uint32_t prior_cwnd = sndvar->cwnd;
		sndvar->snd_una++;
		cur_stream->snd_nxt = ack_seq;
		sndvar->cwnd = ((prior_cwnd == 1) ? (sndvar->mss * TCP_INIT_CWND): sndvar->mss);
		cur_stream->state = TCP_ST_ESTABLISHED;

        // Update listening socket
		struct mtp_listen_ctx *listen_ctx = 
			(struct mtp_listen_ctx *)ListenerHTSearch(mtcp->listeners, &cur_stream->sport);
		if (&listen_ctx->pending_len < &listen_ctx->pending_cap) {
			struct accept_res *acc = malloc(sizeof(*acc));
			acc->stream = cur_stream;
			TAILQ_INSERT_TAIL(&listen_ctx->pending, acc, link);
		} else {
			// Fail to accept connection
			cur_stream->close_reason = TCP_NOT_ACCEPTED;
			cur_stream->state = TCP_ST_CLOSED;
		}

		// Raise an event to the listening socket
		if (listen_ctx->socket && (listen_ctx->socket->epoll & MTCP_EPOLLIN)) {
			AddEpollEvent(mtcp->ep, MTCP_EVENT_QUEUE, listen_ctx->socket, MTCP_EPOLLIN);
		}
    } else if(cur_stream->state == TCP_ST_ESTABLISHED) {
		scratchpad scratch;
		rto_ep(mtcp, cur_ts, ack_seq, cur_stream, &scratch);
		fast_retr_rec_ep(mtcp, cur_ts, ack_seq, cur_stream, &scratch);
		slows_congc_ep(mtcp, cur_ts, ack_seq, cur_stream, &scratch);
		ack_net_ep(mtcp, cur_ts, ack_seq, window, cur_stream, &scratch);
    }
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
	socklen_t *addrlen, struct mtp_listen_ctx *ctx) 
{
	return accept_ep(mctx, mtcp, addr, addrlen, ctx);
}

void MtpSynChain(mtcp_manager_t mtcp, uint32_t cur_ts,
	uint32_t remote_ip, uint16_t remote_port, uint32_t init_seq, uint16_t rwnd,
	uint32_t local_ip, uint16_t local_port, struct tcphdr* tcph, struct mtp_listen_ctx *ctx) 
{
	syn_ep(mtcp, cur_ts, remote_ip, remote_port, init_seq, rwnd, local_ip, local_port, tcph, ctx);
}


/***********************************************
 MTP net interfaces (RX & TX)
 ***********************************************/
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