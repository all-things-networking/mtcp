#include "mtp.h"

#include <linux/tcp.h>

#include "tcp_in.h"
#include "tcp_out.h"
#include "timer.h"
#include "tcp_stream.h"
#include "fhash.h"
#include "debug.h"
#include "ip_out.h"
#include "tcp_util.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))
#define TCP_CALCULATE_CHECKSUM      TRUE
#define TCP_MAX_WINDOW 65535

static inline uint16_t
MTP_CalculateOptionLength(mtp_bp* bp){
    uint16_t res = 0;
    struct mtp_bp_options *opts = &(bp->opts);
    if (opts->mss.valid){
        res += opts->mss.len;
    }
    if (opts->sack_permit.valid){
        res += opts->sack_permit.len;
    }
    if (opts->nop1.valid){
        res += opts->nop1.len;
    }
    if (opts->nop2.valid){
        res += opts->nop2.len;
    }
    if (opts->timestamp.valid){
        res += opts->timestamp.len;
    }
    if (opts->nop3.valid){
        res += opts->nop3.len;
    }
    if (opts->wscale.valid){
        res += opts->wscale.len;
    }
    return res;
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoGenList(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
    if (!cur_stream->sndvar->on_gen_list) {
        struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
        assert(sender != NULL);

        cur_stream->sndvar->on_gen_list = TRUE;
        TAILQ_INSERT_TAIL(&sender->gen_list, cur_stream, sndvar->gen_link);
        sender->gen_list_cnt++;
        TRACE_DBG("Stream %u: added to gen list (cnt: %d)\n", 
        		cur_stream->id, sender->gen_list_cnt);
    }
}

/*----------------------------------------------------------------------------*/
void 
AdvanceBPListHead(tcp_stream *cur_stream, int advance){
    cur_stream->mtp_bps_head = (cur_stream->mtp_bps_head + advance) % MTP_PER_FLOW_BP_CNT;
}
/*----------------------------------------------------------------------------*/
// adapted from SendTCPPacket in tcp_out
int
SendMTPPackets(struct mtcp_manager *mtcp, 
               tcp_stream *cur_stream, 
		       uint32_t cur_ts){
{
    unsigned int sent = 0;
    unsigned int err = 0;
    for (unsigned int i = cur_stream->mtp_bps_head;
         i != cur_stream->mtp_bps_tail;
         i = (i + 1) % MTP_PER_FLOW_BP_CNT){
        
        mtp_bp* bp = &(cur_stream->mtp_bps[i]);
        uint16_t openlen = MTP_CalculateOptionLength(bp);
        uint16_t payloadLen = 0;
        if (bp->payload.data != NULL){
            payloadLen = bp->payload.len;
        }
        if (bp->payloadLen + optlen > cur_stream->sndvar->mss){
            TRACE_ERROR("Payload size exceeds MSS\n");
            err += 1;
            continue; 
        }

        struct mtp_bp_hdr *mtph;
        mtph = (struct mtp_bp_hdr *)IPOutput(mtcp, cur_stream,
                MTP_HEADER_LEN + optlen + payloadlen);
        if (mtph == NULL) {
            AdvanceBPListHead(cur_stream, sent + err);
            return -2;
        }

        memcpy((uint8_t *)mtph, bp->hdr, MTP_HEADER_LEN);

        // options
        // MTP TODO: this can be further generalized
        int i = 0;
        uint8_t *buff_opts = (uint8_t*)mtph + MTP_HEADER_LEN;
        struct mtp_bp_options *bp_opts = &(bp->opts);

        if (bp_opts->mss.valid){
            buff_opts[i++] = bp_opts->mss.kind;
            buff_opts[i++] = bp_opts->mss.len;
            buff_opts[i++] = bp_opts->mss.value >> 8;
            buff_opts[i++] = bp_opts->mss.value % 256;
        }
        
        if (bp_opts->sack_permit.valid){
            buff_opts[i++] = bp_opts->sack_permit.kind;
            buff_opts[i++] = bp_opts->sack_permit.len;
        }    
   
        if (bp_opts->nop1.valid){
            buff_opts[i++] = bp_opts->nop1.kind;
        }
        if (bp_opts->nop2.valid){
            buff_opts[i++] = bp_opts->nop2.kind;
        }

        if (bp_opts->timestamp.valid){
            buff_opts[i++] = bp_opts->timestamp.kind;
            buff_opts[i++] = bp_opts->timestamp.len;
            uint32_t *tmp = (uint32_t *)(buff_opts[i]);
            tmp[0] = bp_opts->timestamp.value1;
            tmp[1] = bp_opts->timestamp.value2;
            i += 8;
        }
        
        if (bp_opts->nop3.valid){
            buff_opts[i++] = bp_opts->nop3.kind;
        }
 
        if (bp_opts->wscale.valid){
            buff_opts[i++] = bp_opts->wscale.kind;
            buff_opts[i++] = bp_opts->wscale.len;
            buff_opts[i++] = bp_opts->wscale.value;
        }

        assert (i % 4 == 0);
        assert (i == optlen);

        // copy payload if exist
        if (bp->payload.data != NULL) {
            memcpy((uint8_t *)mtph + MTP_HEADER_LEN + optlen, bp->payload.data, payloadlen);
            #if defined(NETSTAT) && defined(ENABLELRO)
            mtcp->nstat.tx_gdptbytes += payloadlen;
            #endif /* NETSTAT */
        } 

        // MTP TODO: checksum is TCP specific
        int rc = -1
        #if TCP_CALCULATE_CHECKSUM
        #ifndef DISABLE_HWCSUM
        if (mtcp->iom->dev_ioctl != NULL)
            rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
                          PKT_TX_TCPIP_CSUM, NULL);
        #endif
        //printf("Test 6");

        if (rc == -1)
            mtph->check = TCPCalcChecksum((uint16_t *)mtph,
                              MTP_HEADER_LEN + optlen + payloadlen,
                              cur_stream->saddr, cur_stream->daddr);
        #endif
   
    }

    AdvanceBPListHead(cur_stream, sent + err);
    return 0; 
    // MTP TODO: check these
		//cur_stream->sndvar->ts_lastack_sent = cur_ts;
		//cur_stream->last_active_ts = cur_ts;
		//UpdateTimeoutList(mtcp, cur_stream);
    // MTP TODO: zero window
    /*
	// if the advertised window is 0, we need to advertise again later 
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}
    */
    // MTP TODO: check this
    // Note: added this for retransmit
	//if(payloadlen > 0) {
		/* update retransmission timer if have payload */
		//cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		//AddtoRTOList(mtcp, cur_stream);
	//}
}


/*----------------------------------------------------------------------------*/
int 
MTP_PacketGenList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh){
    tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	thresh = MIN(thresh, sender->control_list_cnt);

	/* Send packets */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->gen_list);
	last = TAILQ_LAST(&sender->gen_list, gen_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside gen loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->gen_link);

		TAILQ_REMOVE(&sender->gen_list, cur_stream, sndvar->gen_link);
		sender->gen_list_cnt--;

		if (cur_stream->sndvar->on_gen_list) {
			cur_stream->sndvar->on_gen_list = FALSE;
			TRACE_DBG("Stream %u: Sending packets\n", cur_stream->id);
			ret = SendMTPPackets(mtcp, cur_stream, cur_ts);
			if (ret == -2) {
				TAILQ_INSERT_HEAD(&sender->gen_list, 
						cur_stream, sndvar->gen_link);
				cur_stream->sndvar->on_gen_list = TRUE;
				sender->gen_list_cnt++;
				/* since there is no available write buffer, break */
				break;
			} else if (ret < 0) {
				/* try again after handling other streams */
				TAILQ_INSERT_TAIL(&sender->gen_list,
						  cur_stream, sndvar->gen_link);
				cur_stream->sndvar->on_gen_list = TRUE;
				sender->control_list_cnt++;
			}
		} else {
			TRACE_ERROR("Stream %d: not on gen list.\n", cur_stream->id);
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;

}

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
EstimateRTT(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t mrtt)
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
// Copied from tcp_in.c
static inline int
ValidateSequence(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, 
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
#if 0
				TRACE_DBG("Window update request. (seq: %u, rcv_wnd: %u)\n", 
						seq, cur_stream->rcvvar->rcv_wnd);
#endif
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

/*----------------------------------------------------------------------------*/
bool
BPBuffer_isfull(tcp_stream *cur_stream){
    uint32_t head = cur_stream->mtp_bps_head;
    uint32_t tail = cur_stream->mtp_bps_tail;
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

    uint32_t bp_tail = cur_stream->mtp_bps_tail;
    mtp_bp* new_bp = cur_stream->mtp_bps + bp_tail;
    cur_stream->mtp_bps_tail = (cur_stream->mtp_bps_tail + 1) % cur_stream->mtp_bps_size;
    return new_bp;
}

/*----------------------------------------------------------------------------*/
// adapted from SendTCPPacket in tcp_out
int
GenPacketBP(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		      uint32_t cur_ts, uint8_t flags, 
              uint32_t seq, uint32_t ack, 
              uint16_t window,
              struct tcp_opt_mss, struct tcp_opt_timstamp,
              struct tcp_opt_wscale, struct tcp_opt_sack_permit, 
              uint8_t *payload, uint16_t payloadlen)
{

   	
    uint16_t optlen;
	int rc = -1;

    // MTP TODO: add them to MTP program
    optlen = MTPCalculateOptionLength(tcp_opt_mss, tcp_opt_timestamp,
                                      tcp_opt_wscale, tcp_opt_sack_permit);


    if (payloadlen + optlen > cur_stream->sndvar->mss) {
        TRACE_ERROR("Payload size exceeds MSS\n");
        return ERROR;
    }

    memset(new_bp->hdr, 0, sizeof(mtp_bp_hdr) + optlen);

	new_bp->hdr.source = cur_stream->sport;
	new_bp->hdr.dest = cur_stream->dport;
    new_bp->hdr.seq = htonl(seq);
    new_bp->hdr.ack_seq = htonl(ack);
	new_bp->hdr.window = htons(window);

	if (flags & TCP_FLAG_SYN) {
		new_bp->syn = TRUE;
	}

	if (flags & TCP_FLAG_ACK) {
		new_bp->ack = TRUE;
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
	//printf("Test 3");

    // MTP TODO: move out of here
    GenerateTCPOptions(cur_stream, cur_ts, flags,
            (uint8_t *)tcph + TCP_HEADER_LEN, optlen);

	//printf("Test 4");

    new_bp->doff = (TCP_HEADER_LEN + optlen) >> 2;

	// copy payload if exist
    if (payloadlen > 0) {
        memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
        mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
    }

	//printf("Test 5");

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
    if (mtcp->iom->dev_ioctl != NULL)
        rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
                      PKT_TX_TCPIP_CSUM, NULL);
#endif
	//printf("Test 6");

    if (rc == -1)
        tcph->check = TCPCalcChecksum((uint16_t *)tcph,
                          TCP_HEADER_LEN + optlen + payloadlen,
                          cur_stream->saddr, cur_stream->daddr);
#endif

	//printf("Test 7\n");
		
	// Note: added this for retransmit
	if(payloadlen > 0) {
		/* update retransmission timer if have payload */
		//cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		//AddtoRTOList(mtcp, cur_stream);
	}

	return 0;
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
	//printf("\nTest -3");
	struct tcphdr *tcph;
    uint16_t optlen;
	int rc = -1;

	//printf("Test -2");

    // MTP TODO: add them to MTP program
    optlen = CalculateOptionLength(flags);

	//printf("Test -1");

    if (payloadlen + optlen > cur_stream->sndvar->mss) {
        TRACE_ERROR("Payload size exceeds MSS\n");
        return ERROR;
    }
	//printf("Test 0");

    tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream,
            TCP_HEADER_LEN + optlen + payloadlen);
    if (tcph == NULL) {
        return -2;
    }
	//printf("Test 1");
    memset(tcph, 0, TCP_HEADER_LEN + optlen);

	//printf("Test 2");
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
	//printf("Test 3");

    // MTP TODO: move out of here
    GenerateTCPOptions(cur_stream, cur_ts, flags,
            (uint8_t *)tcph + TCP_HEADER_LEN, optlen);

	//printf("Test 4");

    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;

	// copy payload if exist
    if (payloadlen > 0) {
        memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
        mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
    }

	//printf("Test 5");

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
    if (mtcp->iom->dev_ioctl != NULL)
        rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
                      PKT_TX_TCPIP_CSUM, NULL);
#endif
	//printf("Test 6");

    if (rc == -1)
        tcph->check = TCPCalcChecksum((uint16_t *)tcph,
                          TCP_HEADER_LEN + optlen + payloadlen,
                          cur_stream->saddr, cur_stream->daddr);
#endif

	//printf("Test 7\n");
		
	// Note: added this for retransmit
	if(payloadlen > 0) {
		/* update retransmission timer if have payload */
		//cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		//AddtoRTOList(mtcp, cur_stream);
	}

	return 0;
}

/*----------------------------------------------------------------------------*/
inline int 
MTP_PacketGenList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	/* Instantiate and send packets from blueprints */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->gen_list);
	last = TAILQ_LAST(&sender->gen_list, gen_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside send loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->send_link);

		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		if (cur_stream->sndvar->on_send_list) {
			ret = 0;

			/* Send data here */
			/* Only can send data when ESTABLISHED or CLOSE_WAIT */
			if (cur_stream->state == TCP_ST_ESTABLISHED) {
				if (cur_stream->sndvar->on_control_list) {
					/* delay sending data after until on_control_list becomes off */
					//TRACE_DBG("Stream %u: delay sending data.\n", cur_stream->id);
					ret = -1;
				} else {
                    //FIXME: TMP COMMENT
					//ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
                    ret = 0;
				}
			} else if (cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_LAST_ACK) {
				//FIXME: TMP COMMENT
                //ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
                ret = 0;
			} else {
				TRACE_DBG("Stream %d: on_send_list at state %s\n", 
						cur_stream->id, TCPStateToString(cur_stream));
#if DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}

			if (ret < 0) {
				TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
				/* since there is no available write buffer, break */
				break;

			} else {
				cur_stream->sndvar->on_send_list = FALSE;
				sender->send_list_cnt--;
				/* the ret value is the number of packets sent. */
				/* decrease ack_cnt for the piggybacked acks */
#if ACK_PIGGYBACK
				if (cur_stream->sndvar->ack_cnt > 0) {
					if (cur_stream->sndvar->ack_cnt > ret) {
						cur_stream->sndvar->ack_cnt -= ret;
					} else {
						cur_stream->sndvar->ack_cnt = 0;
					}
				}
#endif
#if 1
				if (cur_stream->control_list_waiting) {
					if (!cur_stream->sndvar->on_ack_list) {
						cur_stream->control_list_waiting = FALSE;
						AddtoControlList(mtcp, cur_stream, cur_ts);
					}
				}
#endif
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

	return cnt;
}
/*----------------------------------------------------------------------------*/
static inline void syn_chain(mtcp_manager_t mtcp, uint32_t cur_ts,
                             uint32_t remote_ip, uint16_t remote_port, 
                             uint32_t init_seq, uint16_t rwnd,
                             uint32_t local_ip, uint16_t local_port,
							 struct tcphdr* tcph){
   
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
    cur_stream->rcvvar->last_flushed_seq = cur_stream->rcvvar->irs;
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
			(tcph->doff << 2) - TCP_HEADER_LEN);
    // MTP TODO: I think we need to add a state variable in context to MTP code
    cur_stream->state = TCP_ST_SYN_RCVD;
  
    struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
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

    if (!rcvvar->meta_rwnd) {
		rcvvar->meta_rwnd = RBInit(mtcp->rbm_rcv, rcvvar->irs + 1);
        // MTP TODO: this should raise an error event that comes back
        //           to be processed according to the MTP program
		if (!rcvvar->meta_rwnd) {
			TRACE_ERROR("Stream %d: Failed to allocate meta_rwnd.\n", 
					cur_stream->id);
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream);
			return;
		}
    }

    // MTP pkt gen instruction
    // MTP TODO: check that size + options is not more than MSS
   
    mtp_bp* bp = GetFreeBP(cur_stream);
    
    memset(bp->hdr, 0, sizeof(mtp_bp_hdr));

	bp->hdr.source = cur_stream->sport;
	bp->hdr.dest = cur_stream->dport;
    bp->hdr.seq = htonl(cur_stream->sndvar->iss);
    bp->hdr.ack_seq = htonl(init_seq + 1);

    bp->hdr.syn = TRUE;
    bp->hdr.ack = TRUE;

    // options to calculate data offset
    // MSS
    bp->opts.mss.valid = TRUE;
    bp->opts.mss.value = cur_stream->sndvar->mss;
   
    // MTP TODO: SACK? 
#if TCP_OPT_SACK_ENABLED
    printf("ERROR:SACK Not supported in MTP TCP\n");
#endif

    // Timestamp
    bp->opts.timestamp.valid = TRUE;
    bp->opts.timestamp.value1 = htonl(cur_ts);
    bp->opts.timestamp.value2 = htonl(cur_stream->rcvvar->ts_recent); 

    // Window scale
    bp->opts.nop3.valid = TRUE;
    bp->opts.wscale.valid = TRUE;
    bp->opts.wscale.value = cur_stream->sndvar->wscale_mine;

    uint16_t optlen = MTP_CalculateOptionLength(bp);
    bp->hdr.doff = (MTP_HEADER_LEN + optlen) >> 2;

    uint32_t window32 = cur_stream->rcvvar->rcv_wnd;
	uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
	bp->hdr.window = htons(advertised_window);

    // Payload
    bp->payload.data = NULL;
    bp->payload.len = 0;

    AddtoGenList(mtcp, cur_stream, cur_ts);
}

/*----------------------------------------------------------------------------*/

static inline void rto_ep(mtcp_manager_t mtcp, tcp_stream* cur_stream,
                             uint32_t cur_ts,
                            uint32_t ack_seq, scratchpad* scratch){
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	scratch->skip_ack_eps = 0;

	if(ack_seq < sndvar->snd_una || cur_stream->snd_nxt < ack_seq) {
		scratch->skip_ack_eps = 1;
		TRACE_DBG("Stream %d (%s): invalid acknolegement. "
			"ack_seq: %u, possible min_ack_seq: %u, possible max_ack_seq: %u\n",
			cur_stream->id, TCPStateToString(cur_stream), ack_seq, 
			sndvar->snd_una, cur_stream->snd_nxt);
		return;
	}

	// Set RTO, using RTT calculation logic from mTCP
	uint32_t round_tt = cur_ts - rcvvar->ts_lastack_rcvd;
	EstimateRTT(mtcp, cur_stream, round_tt);
	sndvar->rto = (rcvvar->srtt >> 3) + rcvvar->rttvar;
}


static inline void fast_retr_rec_ep(mtcp_manager_t mtcp, tcp_stream* cur_stream,
                             uint32_t cur_ts,
                            uint32_t ack_seq, scratchpad* scratch){
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

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
			// Necessary updates for mTCP
			/* count number of retransmissions */
			/*if (sndvar->nrtx < TCP_MAX_RTX) {
				sndvar->nrtx++;
			} else {
				TRACE_DBG("Exceed MAX_RTX.\n");
			}*/

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

static inline void slows_congc_ep(mtcp_manager_t mtcp, tcp_stream* cur_stream,
                             uint32_t cur_ts,
                            uint32_t ack_seq, scratchpad* scratch){
	struct tcp_send_vars *sndvar = cur_stream->sndvar;

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

static inline void ack_net_ep(mtcp_manager_t mtcp, tcp_stream* cur_stream,
                             uint32_t cur_ts,
                            uint32_t ack_seq, scratchpad* scratch, uint32_t window){

	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	//uint32_t SMSS = 1460;
	//uint32_t EFF_SMSS = 1448;

	if(scratch->skip_ack_eps) {
		return;
	}

	/* Update window */
	uint32_t rwindow = window << sndvar->wscale_peer;
	uint32_t seq = rcvvar->last_ack_seq;
	if (TCP_SEQ_LT(rcvvar->snd_wl1, seq) ||
			(rcvvar->snd_wl1 == seq && 
			TCP_SEQ_LT(rcvvar->snd_wl2, ack_seq)) ||
			(rcvvar->snd_wl2 == ack_seq && 
			rwindow > sndvar->peer_wnd)) {
		uint32_t rwindow_prev = sndvar->peer_wnd;
		sndvar->peer_wnd = rwindow;
		rcvvar->snd_wl1 = seq;
		rcvvar->snd_wl2 = ack_seq;
		if (rwindow_prev < cur_stream->snd_nxt - sndvar->snd_una && 
				sndvar->peer_wnd >= cur_stream->snd_nxt - sndvar->snd_una) {
			TRACE_CLWND("%u Broadcasting client window update! "
					"ack_seq: %u, peer_wnd: %u (before: %u), "
					"(snd_nxt - snd_una: %u)\n", 
					cur_stream->id, ack_seq, sndvar->peer_wnd, rwindow_prev, 
					cur_stream->snd_nxt - sndvar->snd_una);
			// This is the "notify" instruction in MTP
			RaiseWriteEvent(mtcp, cur_stream);
		}
	}
	
	uint32_t data_rest = sndvar->snd_una + sndvar->sndbuf->len - cur_stream->snd_nxt;

	uint32_t effective_window = MIN(sndvar->cwnd, sndvar->peer_wnd);

	uint32_t bytes_to_send = 0;

	if(rcvvar->dup_acks == 3) {
		SBUF_LOCK(&sndvar->write_lock);

		bytes_to_send = sndvar->eff_mss;
		bytes_to_send = MIN(effective_window, bytes_to_send);

		seq = sndvar->snd_una;
		bytes_to_send = MIN(sndvar->sndbuf->len - (seq - sndvar->snd_una),
							bytes_to_send);
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

	// MTP unseg data
	int32_t len = bytes_to_send;
	seq = cur_stream->snd_nxt;
	int32_t ack_num = cur_stream->rcv_nxt;
	uint8_t *data = sndvar->sndbuf->head + (seq - sndvar->snd_una);
	int ret = 0;
	SBUF_LOCK(&sndvar->write_lock);
	while (len > 0) {
		int32_t pkt_len = MIN(len, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));

		ret = SendMTPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK,
                      		seq, ack_num, effective_window, data, pkt_len);

		if (ret < 0){
			break;
		} else {
			len -= pkt_len;
			seq += pkt_len;
			data += pkt_len;
			cur_stream->snd_nxt += pkt_len;
			if (len <= 0) break;
		}
	}
	SBUF_UNLOCK(&sndvar->write_lock);

	// Remove acked sequence from sending buffer
	// This step is kinda target dependent (depending on the implementation of sending buffer)
	uint32_t rmlen = ack_seq - sndvar->snd_una;
	if(rmlen > 0) {
		if (SBUF_LOCK(&sndvar->write_lock)) {
			if (errno == EDEADLK)
				perror("ProcessACK: write_lock blocked\n");
			assert(0);
		}
		SBRemove(mtcp->rbm_snd, sndvar->sndbuf, rmlen);
		sndvar->snd_una = ack_seq;
		sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;

		RaiseWriteEvent(mtcp, cur_stream);

		SBUF_UNLOCK(&sndvar->write_lock);
	}

	UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
}


static inline void ack_chain(mtcp_manager_t mtcp, uint32_t cur_ts, tcp_stream* cur_stream,
			struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq, int payloadlen,
			uint32_t window){

/*static inline void ack_chain(mtcp_manager_t mtcp, tcp_stream* cur_stream,
                             uint32_t cur_ts,
                            uint32_t ack_seq, uint32_t rwnd){ */

    // "establish" the connection if not established
    struct tcp_send_vars *sndvar = cur_stream->sndvar;
	//struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
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
		
		//sndvar->nrtx = 0;
		//cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
		RemoveFromRTOList(mtcp, cur_stream);

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
    } else if(cur_stream->state == TCP_ST_ESTABLISHED) {
		scratchpad scratch;
		rto_ep(mtcp, cur_stream, cur_ts, ack_seq, &scratch);
		fast_retr_rec_ep(mtcp, cur_stream, cur_ts, ack_seq, &scratch);
		slows_congc_ep(mtcp, cur_stream, cur_ts, ack_seq, &scratch);
		ack_net_ep(mtcp, cur_stream, cur_ts, ack_seq, &scratch, window);
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
	//uint32_t prev_rcv_nxt;
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

    // MTP: this is new_inorder_data, rcvbuf is the "id", moved to syn_chain
	// allocate receive buffer if not exist 
	/*if (!rcvvar->rcvbuf) {
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
	}*/

	if (SBUF_LOCK(&rcvvar->read_lock)) {
		if (errno == EDEADLK)
			perror("ProcessTCPPayload: read_lock blocked\n");
		assert(0);
	}

	//prev_rcv_nxt = cur_stream->rcv_nxt;
    // MTP window set()
    // MTP TODO: refactor meta_rwnd to have its own class
    //           that's not keeping the data
    RBPut(mtcp->rbm_rcv, 
		  rcvvar->meta_rwnd, payload, (uint32_t)payloadlen, seq);

    // MTP: rwnd.first_unset()
	cur_stream->rcv_nxt = rcvvar->meta_rwnd->head_seq + rcvvar->meta_rwnd->merged_len;

    // MTP: move window forward, not sure this is ok in this context because they change different
    //      fragment queues based on AT_APP and AT_MTCP
    RBRemove(mtcp->rbm_rcv, rcvvar->meta_rwnd, rcvvar->meta_rwnd->merged_len, AT_APP);

	// MTP: assuming rcvbuf->size is coming in as input to the chain
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - (cur_stream->rcv_nxt - 1 - cur_stream->rcvvar->last_flushed_seq);

    /*
	// discard the buffer if the state is FIN_WAIT_1 or FIN_WAIT_2, 
	//   meaning that the connection is already closed by the application 
	if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2) {
		RBRemove(mtcp->rbm_rcv, 
				rcvvar->rcvbuf, rcvvar->rcvbuf->merged_len, AT_MTCP);
	}
    */

    // MTP add_data_seg instruction
    ret = RBPut(mtcp->rbm_rcv, 
			rcvvar->rcvbuf, payload, (uint32_t)payloadlen, seq);

	if (ret < 0) {
		TRACE_ERROR("Cannot merge payload. reason: %d\n", ret);
	}
	SBUF_UNLOCK(&rcvvar->read_lock);

	// MTP TODO: should look into this later
    /*if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, prev_rcv_nxt)) {
		// There are some lost packets 
		return;
	}
    */

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

inline void send_ack_ep(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts){
    uint32_t seq = cur_stream->snd_nxt;
    uint32_t ack = cur_stream->rcv_nxt;
    uint32_t window32 = cur_stream->rcvvar->rcv_wnd;
    uint16_t advertised_window = MIN(window32, TCP_MAX_WINDOW);
    SendMTPPacket(mtcp, cur_stream,
                  cur_ts, TCP_FLAG_ACK, 
                  seq, ack, advertised_window,
                  NULL, 0);
}

/*----------------------------------------------------------------------------*/
// This is the chain of event processors when an incoming app event is processed
// It should include one event processor called flush_and_notify
// flush_and_notify flushes in-order packet data to the application, and notify the
// application about it.
inline int
MTP_recv_chain(mtcp_manager_t mtcp, tcp_stream *cur_stream, char *buf, int len, socket_map_t socket)
{
	// MTP flush_and_notify - flush part
	/* Modified from mTCP CopyToUser */
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	uint32_t prev_rcv_wnd;
	int copylen;

	copylen = MIN((cur_stream->rcv_nxt - rcvvar->last_flushed_seq - 1), len);
	if (copylen <= 0) {
		errno = EAGAIN;
		return -1;
	}

	prev_rcv_wnd = rcvvar->rcv_wnd;
	/* Copy data to user buffer and remove it from receiving buffer */
	memcpy(buf, rcvvar->rcvbuf->head, copylen);
	RBRemove(mtcp->rbm_rcv, rcvvar->rcvbuf, copylen, AT_APP);
	rcvvar->last_flushed_seq += copylen;
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	/* Advertise newly freed receive buffer */
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

	// MTP flush_and_notify - notify part
	/* Modified from mtcp_recv */
	bool event_remaining = FALSE;
        /* if there are remaining payload, generate EPOLLIN */
	/* (may due to insufficient user buffer) */
	if (socket->epoll & MTCP_EPOLLIN) {
		if (!(socket->epoll & MTCP_EPOLLET) && rcvvar->rcvbuf->merged_len > 0) {
			event_remaining = TRUE;
		}
	}
        /* if waiting for close, notify it if no remaining data */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT && 
	    rcvvar->rcvbuf->merged_len == 0 && copylen > 0) {
		event_remaining = TRUE;
	}
	
	SBUF_UNLOCK(&rcvvar->read_lock);
	
	if (event_remaining) {
		if (socket->epoll) {
			AddEpollEvent(mtcp->ep, 
				      USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLIN);
#if BLOCKING_SUPPORT
		} else if (!(socket->opts & MTCP_NONBLOCK)) {
			if (!cur_stream->on_rcv_br_list) {
				cur_stream->on_rcv_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->rcv_br_list, 
						  cur_stream, rcvvar->rcv_br_link);
				mtcp->rcv_br_list_cnt++;
			}
#endif
		}
	}

	return copylen;
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

	seq = cur_stream->snd_nxt;
    // MTP TODO: sanity checks in FlushTCPSendingBuffer
    remaining_window = MIN(sndvar->cwnd, sndvar->peer_wnd)
			               - (seq - sndvar->snd_una);


    //seq = cur_stream->snd_nxt;
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
	// Adding this statement to increase snd_nxt
            //cur_stream->snd_nxt += pkt_len;
	while (len > 0) {
		pkt_len = MIN(len, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));

		ret = SendMTPPacket(mtcp, cur_stream, 
			cur_ts, TCP_FLAG_ACK,
			seq, ack_seq, window, 
			data, pkt_len); 

		if (ret < 0){
				break;
		} else{
			len -= pkt_len;
			seq += pkt_len;
			data += pkt_len;
			cur_stream->snd_nxt += pkt_len;
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
            ret = send_chain(mtcp, cur_stream, cur_ts); 

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
    // TODO: change to parse mtp_bp?
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
	int ret;
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
            SendTCPPacketStandalone(mtcp, 
				iph->daddr, tcph->dest, iph->saddr, tcph->source, 
				0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
				NULL, 0, cur_ts, 0);
            return TRUE;
        }           

		// Setup connection
        // MTP TODO: cur_ts in events by default or explicity?
        // parser "returns" event and dispatcher calls the event processing chain
        syn_chain(mtcp, cur_ts, iph->saddr, tcph->source, seq, window, local_ip, local_port, tcph);
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
		SendTCPPacketStandalone(mtcp, 
			iph->daddr, tcph->dest, iph->saddr, tcph->source, 
			0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
			NULL, 0, cur_ts, 0);
        return 0;
    }

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

	// Update peer window
	cur_stream->sndvar->peer_wnd = 
		(uint32_t)window << cur_stream->sndvar->wscale_peer;

	if (payloadlen > 0){
        data_net_ep(mtcp, cur_stream, cur_ts, seq, payload, payloadlen);
        send_ack_ep(mtcp, cur_stream, cur_ts);
    } 
	
	if (is_ack){
        // event_type = MTP_ACK;
        ack_chain(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq, payloadlen, window);
    }
	/*

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
