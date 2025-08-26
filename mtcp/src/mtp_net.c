#include "mtp_net.h"
#include "mtp_ep.h"
#include "fhash.h"
#include "debug.h"
#include "tcp_out.h"
#include "tcp_util.h"
#include "timer.h"
#include "ip_out.h"
#include "mtp_instr.h"

#define TCP_CALCULATE_CHECKSUM      TRUE
#define VERIFY_RX_CHECKSUM          TRUE

// Helper functions
/*----------------------------------------------------------------------------*/
static inline void HandleMissingCtx(mtcp_manager_t mtcp, 
	const struct iphdr *iph, struct mtp_bp_hdr* mtph,
    int payloadlen, uint32_t cur_ts) {
	// TODO? This can be considered as processor for an "error" event
    TRACE_DBG("Refusing packet: context not found.\n");
    MTP_PRINT("Refusing packet: listen context not found.\n");
    /*
	SendTCPPacketStandalone(mtcp, 
		iph->daddr, tcph->dest, iph->saddr, tcph->source, 
		0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
		NULL, 0, cur_ts, 0);
	return TRUE;
    */
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

	// MTP - Compiler-Start: extract
    // maps to extract in the parser
    printf("ip_len: %d\n", ip_len);
    struct mtp_bp_hdr *mtph = (struct mtp_bp_hdr *) ((u_char *)iph + (iph->ihl << 2));
    // MTP TODO: add this after changing tcp_stream because that one keeps it in network order
    //mtph->dest = ntohs(mtph->dest);
	//mtph->source = ntohs(mtph->source);
    // MTP TODO: parse options
    
    struct mtp_bp_payload payload;
    if (mtph->type == MTP_HOMA_DATA){
	    payload.data = (uint8_t *)mtph + (MTP_HOMA_COMMON_HSIZE + MTP_HOMA_DATA_HSIZE);
        payload.len = ip_len - (payload.data - (u_char *)iph);
    }
    else {
        payload.data = NULL;
        payload.len = 0;
    }
    // MTP - Compiler-End: extract

    printf("ack.rpcid: %x, ack.srcport: %x, ack.destport: %x\n",
                           mtph->data.seg.ack.rpcid,
                           mtph->data.seg.ack.sport,
                           mtph->data.seg.ack.dport);

    struct mtp_bp tmp_bp;
    tmp_bp.hdr = *mtph;
    tmp_bp.payload = payload;
    MTP_PRINT("---------------------------------\n");
    MTP_PRINT("Received MTP packet:\n");
    print_MTP_bp(&tmp_bp);


    // if (ip_len < ((iph->ihl + mtph->doff) << 2)) return MTP_ERROR;
    // int ret = MTP_ValidateChecksum(mtcp, ifidx, iph, ip_len, mtph, payload.len);
    // if (ret != 0) return MTP_ERROR;
    
    // MTP - Combining dispatcher, context look up, and event chain

    // MTP: maps to SYN event
    
	
	// MTP: maps to flow id generation in parser
	// tcp_stream s_stream;
    // s_stream.saddr = iph->daddr;
	// s_stream.sport = mtph->dest;
	// s_stream.daddr = iph->saddr;
	// s_stream.dport = mtph->source;

    // if (mtph->syn && mtph->ack){
    //     uint32_t ev_init_seq = mtph->seq;
    //     uint32_t ev_ack_seq = mtph->ack_seq;
    //     uint16_t ev_rwnd_size = mtph->window;
    //     bool ev_sack_permit = mtp_opt.sack_permit.valid;
    //     bool ev_wscale_valid = mtp_opt.wscale.valid;
    //     uint8_t ev_wscale = mtp_opt.wscale.value;
    //     bool ev_mss_valid = mtp_opt.mss.valid;
    //     uint16_t ev_mss = mtp_opt.mss.value;
    //     struct tcp_opt_timestamp* ev_ts = &(mtp_opt.timestamp);

    //     tcp_stream *cur_stream = NULL;
	//     if (!(cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream))) {
    //         MTP_PRINT("SYNACK: No context\n");
    //         return -1;
    //         // MTP TODO: return HandleMissingCtx(mtcp, iph, tcph, seq, payload.len, cur_ts);
    //     }

    //     MtpSyNAckChain(mtcp, cur_ts, 
    //                    ev_init_seq, ev_ack_seq,
    //                    ev_rwnd_size, ev_sack_permit, ev_mss_valid, ev_mss, 
    //                    ev_wscale_valid, ev_wscale, ev_ts, cur_stream);
    //     return 0;
    // }

    // Context lookup
    /*
	tcp_stream *cur_stream = NULL;
	if (!(cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream))) {
        // MTP TODO: return HandleMissingCtx(mtcp, iph, tcph, seq, payload.len, cur_ts);
    }

	// TBA to MTP: validate sequence
	// MTP TODO: ret = ValidateSequence(mtcp, cur_stream, cur_ts, tcph, seq, ack_seq, payload.len);
	// MTP TODO: if (ret == 0) return TRUE;

	// TBA to MTP?: update peer window
	cur_stream->sndvar->peer_wnd = (uint32_t)window << cur_stream->sndvar->wscale_peer;

	// MTP TODO: SYN_ACK event

	// MTP: maps to DATA event
	if (payload.len > 0){
		MtpDataChain(mtcp, cur_ts, seq, payload.data, payload.len, cur_stream);
    } 
	
	// MTP: maps to ACK event
	if (is_ack){
        MtpAckChain(mtcp, cur_ts, mtph, seq, ack_seq, payload.len, window, cur_stream);
    }
    */
	
	return TRUE;
}

// Net TX
// MTP Note: the SEND event is not fully inline with MTP's tcp code because
//           data len is not in it and the data is already copied
//           and recorded in the flow context (tcp_stream) before getting here.
// MTP TODO: this doesn't quite work well at this point, because it is not actually sending packets
void MTP_ProcessSendEvents(mtcp_manager_t mtcp, struct mtcp_sender *sender, 
	uint32_t cur_ts, int thresh) 
{
    MTP_PRINT("Inside MTP_ProcessSendEvents\n");
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
            MtpSendChain(mtcp, cur_ts, cur_stream); 
            cur_stream->sndvar->on_send_list = FALSE;
            sender->send_list_cnt--;
		}

		if (cur_stream == last) break;
		cur_stream = next;
	}
}

/***********************************************
 MTP Net TX
***********************************************/
/*----------------------------------------------------------------------------*/
void 
AdvanceBPListHead(tcp_stream *cur_stream, int advance){ 
    int cur_head = cur_stream->sndvar->mtp_bps_head; 
    cur_stream->sndvar->mtp_bps_head = (cur_head + advance) % MTP_PER_FLOW_BP_CNT;
}
/*----------------------------------------------------------------------------*/
// adapted from SendTCPPacket in tcp_out
int
SendMTPPackets(struct mtcp_manager *mtcp, 
               tcp_stream *cur_stream, 
		       uint32_t cur_ts){   

    // MTP_PRINT("in SendMTPPackets\n");
    unsigned int sent = 0;
    unsigned int err = 0;
    // MTP_PRINT("bp list head: %u, bp list tail: %u\n", cur_stream->sndvar->mtp_bps_head,
    //                                                cur_stream->sndvar->mtp_bps_tail);
    for (unsigned int i = cur_stream->sndvar->mtp_bps_head;
         i != cur_stream->sndvar->mtp_bps_tail;
         i = (i + 1) % MTP_PER_FLOW_BP_CNT){
        
        // MTP_PRINT("bp index: %d\n", i);
        
        mtp_bp* bp = &(cur_stream->sndvar->mtp_bps[i]);
        
        // MTP_PRINT("bp @ index %u:\n", i);
        MTP_PRINT("---------------------------------\n");
        MTP_PRINT("Sending MTP packet:\n");
        print_MTP_bp(bp);

        if (bp->payload.needs_segmentation){
            assert(bp->payload.data != NULL);
            uint32_t bytes_to_send = bp->payload.len;
            uint8_t *data_ptr = bp->payload.data;

            // MTP_PRINT("1 sending, here\n");

            if (bp->payload.seg_rule_group_id == 1){
                uint32_t seq = bp->hdr.seq;
                uint32_t seg_offset = bp->hdr.data.seg.offset;
                uint32_t seg_size = bp->payload.seg_size;

                while (bytes_to_send > 0) {
                    // MTP_PRINT("sending, here: %d\n", bytes_to_send);

                    int32_t pkt_len = MIN(seg_size, bytes_to_send);

                    // MTP_PRINT("pkt_len: %d\n", pkt_len);

                    // Send the next packet
                    struct mtp_bp_hdr *mtph;
                    // TODO: technically, we should check the 
                    //.       packet type.
                    uint32_t hdr_len = MTP_HOMA_COMMON_HSIZE + MTP_HOMA_DATA_HSIZE;
                    // TODO: add UDP header
                    mtph = (struct mtp_bp_hdr *)IPOutputWTos(mtcp, cur_stream,
                            hdr_len + pkt_len, bp->prio);
                    if (mtph == NULL) {
                        bp->hdr.seq = seq;
                        bp->hdr.data.seg.offset = seg_offset;
                        bp->payload.len = bytes_to_send;
                        bp->payload.data = data_ptr;
                        
                        AdvanceBPListHead(cur_stream, sent + err);
                        
                        MTP_PRINT("ran out midway\n");
                        return -2;
                    }

                    // MTP_PRINT("got packet memory\n");

                    memcpy((uint8_t *)mtph, &(bp->hdr), hdr_len);
                    printf("ack.rpcid: %u, ack.srcport: %u, ack.destport: %u\n",
                           mtph->data.seg.ack.rpcid,
                           mtph->data.seg.ack.sport,
                           mtph->data.seg.ack.dport);

                    // MTP_PRINT("copied the header\n");

                    mtph->seq = seq;
                    mtph->data.seg.offset = seg_offset;
                    mtph->data.seg.segment_length = pkt_len;
                    printf("mtph->seq: %u, mtph->data.seg.offset: %u, mtph->data.seg.segment_length: %u\n",
                           mtph->seq, mtph->data.seg.offset, mtph->data.seg.segment_length);
                    // MTP_PRINT("Sent Seq 1: %u, size: %u\n", ntohl(mtph->seq), pkt_len);

                    // MTP_PRINT("setup some fields\n");

                    
                    // MTP TODO: do we need to lock here?
                    // copy payload if exist
                    // MTP_PRINT("packet addr:%p\n", (uint8_t *)mtph + MTP_HEADER_LEN + optlen);
                    // MTP_PRINT("data pointer: %p\n", data_ptr);
                    memcpy((uint8_t *)mtph + hdr_len, data_ptr, pkt_len);
                    #if defined(NETSTAT) && defined(ENABLELRO)
                    mtcp->nstat.tx_gdptbytes += payloadlen;
                    #endif // NETSTAT 
                     
                    // MTP_PRINT("copied payload\n");

                    // MTP TODO: checksum is TCP specific

                    // MTP_PRINT("setup checksum\n");
                    // update for next packet based on segementation rules
                    bytes_to_send -= pkt_len;
                    seq += 1;
                    seg_offset += pkt_len;
                    data_ptr += pkt_len;

                    // MTP_PRINT("moving on\n");
                           
                }
            }
            sent += 1;
        }
        else {
            /*
            uint16_t payloadLen = 0;
            if (bp->payload.data != NULL){
                payloadLen = bp->payload.len;
            }
            // MTP TODO: 
            if (payloadLen + optlen > cur_stream->sndvar->mss){
                TRACE_ERROR("Payload size exceeds MSS\n");
                err += 1;
                continue; 
            }
            struct mtp_bp_hdr *mtph;
            mtph = (struct mtp_bp_hdr *)IPOutput(mtcp, cur_stream,
                    MTP_HEADER_LEN + optlen + payloadLen);
            if (mtph == NULL) {
                
                AdvanceBPListHead(cur_stream, sent + err);
                
                return -2;
            }

            memcpy((uint8_t *)mtph, &(bp->hdr), MTP_HEADER_LEN);

            // MTP_PRINT("Sent Seq 2: %u, size: %u\n", ntohl(mtph->seq), payloadLen);    

            // MTP TODO: this is TCP specific
            mtph->doff = (MTP_HEADER_LEN + optlen) >> 2;

            // MTP TODO: do we need to lock here?
            // copy payload if exist
            if (bp->payload.data != NULL) {
                memcpy((uint8_t *)mtph + MTP_HEADER_LEN + optlen, bp->payload.data, payloadLen);
                #if defined(NETSTAT) && defined(ENABLELRO)
                mtcp->nstat.tx_gdptbytes += payloadlen;
                #endif // NETSTAT 
            } 

            sent += 1;
            */
        }
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

	thresh = MIN(thresh, sender->gen_list_cnt);

    // MTP_PRINT("in packet gen list\n");
	/* Send packets */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->gen_list);
	last = TAILQ_LAST(&sender->gen_list, gen_head);
	while (cur_stream) {
		if (++cnt > thresh) break;

        // MTP_PRINT("Inside gen loop. cnt: %u, stream: %d\n", 
				// cnt, cur_stream->id);
		TRACE_LOOP("Inside gen loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->gen_link);

		TAILQ_REMOVE(&sender->gen_list, cur_stream, sndvar->gen_link);
		sender->gen_list_cnt--;

		if (cur_stream->sndvar->on_gen_list) {
			cur_stream->sndvar->on_gen_list = FALSE;
			TRACE_DBG("Stream %u: Sending packets\n", cur_stream->id);
            // MTP_PRINT("Stream %u: Sending packets\n", cur_stream->id);
			ret = SendMTPPackets(mtcp, cur_stream, cur_ts);
			if (ret == -2) {
				TAILQ_INSERT_HEAD(&sender->gen_list, 
						cur_stream, sndvar->gen_link);
				cur_stream->sndvar->on_gen_list = TRUE;
				sender->gen_list_cnt++;
				/* since there is no available write buffer, break */
				break;
			} 
            else if (ret < 0) {
				/* try again after handling other streams */
				TAILQ_INSERT_TAIL(&sender->gen_list,
						  cur_stream, sndvar->gen_link);
				cur_stream->sndvar->on_gen_list = TRUE;
				sender->gen_list_cnt++;
			}
            else {
                /* successfully sent packets */
                // MTP TODO: fix
                // if (cur_stream->mtp->state == MTP_TCP_TIME_WAIT_ST){
                //     cur_stream->mtp->state = MTP_TCP_CLOSED_ST;
                //     MTP_PRINT("Stream %d: MTP TCP closed.\n", cur_stream->id);
                //     DestroyCtx(mtcp, cur_stream, cur_stream->mtp->local_port);
                // }
            }
		} 
        else {
			TRACE_ERROR("Stream %d: not on gen list.\n", cur_stream->id);
		}

		if (cur_stream == last) break;
		cur_stream = next;
	}

	return cnt;

}


