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

    struct mtp_bp tmp_bp;
    tmp_bp.hdr = *mtph;
    tmp_bp.payload = payload;
    MTP_PRINT("---------------------------------\n");
    MTP_PRINT("Received MTP packet:\n");
    print_MTP_bp(&tmp_bp);


    // if (ip_len < ((iph->ihl + mtph->doff) << 2)) return MTP_ERROR;
    
    // MTP - Combining dispatcher, context look up, and event chain

    // MTP: maps to SYN event
    
	
	// MTP: maps to flow id generation in parser
	tcp_stream s_stream;
    s_stream.saddr = iph->daddr;
	s_stream.sport = mtph->dest_port;
	s_stream.daddr = iph->saddr;
	s_stream.dport = mtph->src_port;
    s_stream.rpc_id = mtph->sender_id;

    tcp_stream *cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream);

    if (!cur_stream && mtph->type == MTP_HOMA_DATA) {
        uint32_t ev_seq = mtph->seq;
        uint32_t ev_message_length = mtph->data.message_length;
        uint32_t ev_incoming = mtph->data.incoming;
        uint8_t ev_retransmit = mtph->data.retransmit;
        uint32_t ev_offset = mtph->data.seg.offset;
        uint32_t ev_segment_length = mtph->data.seg.segment_length;
        uint32_t ev_rpcid = mtph->sender_id;
        uint16_t ev_sport = mtph->src_port;
        uint16_t ev_dport = mtph->dest_port;
        bool single_packet = ev_message_length == ev_segment_length;
        uint32_t ev_remote_ip = iph->saddr;
        uint32_t ev_local_ip = iph->daddr;
        uint8_t* ev_hold_addr = payload.data;

        // TODO: iterate over smap (CONFIG.max_concurrency)
        //       to find the right socket to associate with this packet
        //       for server, it is only going to be one socket
        socket_map_t socket = NULL;

        for (int i = 0; i < CONFIG.max_concurrency; i++){
            if (mtcp->smap[i].saddr.sin_addr.s_addr == iph->daddr &&
                mtcp->smap[i].saddr.sin_port == mtph->dest_port){
                // found the right socket
                socket = &mtcp->smap[i];
                break;
            }
        }

        if (socket == NULL){
            printf("Error: no socket found for incoming packet\n");
        }
        else {
            printf("Found socket for incoming packet: id %d\n", socket->id);
        }

        MtpHomaNoHomaCtxChain(mtcp, cur_ts, 
                            ev_seq,
                            ev_message_length,
                            ev_incoming,
                            ev_retransmit,
                            ev_offset,
                            ev_segment_length,
                            ev_rpcid,
                            ev_sport,
                            ev_dport,
                            single_packet,
                            ev_local_ip,
                            ev_remote_ip,
                            ev_hold_addr,
                            socket);
    }

    else if (mtph->type == MTP_HOMA_DATA){
        uint32_t ev_seq = mtph->seq;
        uint32_t ev_message_length = mtph->data.message_length;
        uint32_t ev_incoming = mtph->data.incoming;
        uint8_t ev_retransmit = mtph->data.retransmit;
        uint32_t ev_offset = mtph->data.seg.offset;
        uint32_t ev_segment_length = mtph->data.seg.segment_length;
        uint32_t ev_rpcid = mtph->sender_id;
        uint16_t ev_sport = mtph->src_port;
        uint16_t ev_dport = mtph->dest_port;
        bool single_packet = ev_message_length == ev_segment_length;
        uint32_t ev_remote_ip = iph->saddr;
        uint32_t ev_local_ip = iph->daddr;
        uint8_t* ev_hold_addr = payload.data;

        if (cur_stream->mtp->rpc_is_client){
            // this is a client stream, so this is a response packet
            MtpHomaRecvdRespChain(mtcp, cur_ts, 
                            ev_seq,
                            ev_message_length,
                            ev_incoming,
                            ev_retransmit,
                            ev_offset,
                            ev_segment_length,
                            ev_rpcid,
                            ev_sport,
                            ev_dport,
                            single_packet,
                            ev_local_ip,
                            ev_remote_ip,
                            ev_hold_addr,
                            cur_stream);
        }
        else {
            MtpHomaRecvdReqChain(mtcp, cur_ts, 
                            ev_seq,
                            ev_message_length,
                            ev_incoming,
                            ev_retransmit,
                            ev_offset,
                            ev_segment_length,
                            ev_rpcid,
                            ev_sport,
                            ev_dport,
                            single_packet,
                            ev_local_ip,
                            ev_remote_ip,
                            ev_hold_addr,
                            cur_stream);
        }
    }

    else if (mtph->type == MTP_HOMA_GRANT){
        uint32_t ev_offset = mtph->grant.offset;
        uint32_t ev_priority = mtph->grant.priority;
        MtpHomaRecvdGrantChain(mtcp, cur_ts, ev_offset, ev_priority, 
			                    cur_stream);
    }
    

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

                    // MTP_PRINT("copied the header\n");

                    mtph->seq = seq;
                    mtph->data.seg.offset = seg_offset;
                    mtph->data.seg.segment_length = pkt_len;
                    // printf("mtph->seq: %u, mtph->data.seg.offset: %u, mtph->data.seg.segment_length: %u\n",
                    //        mtph->seq, mtph->data.seg.offset, mtph->data.seg.segment_length);
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

#ifdef MTP_ARRAY_GEN_LIST 
/*----------------------------------------------------------------------------*/
int 
MTP_PacketGenList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh){
    tcp_stream *cur_stream;
	int cnt = 0;
	int ret;

    // TODO: 
    //       1. decide how to sort
    //       based on whether it is a FIFO round
    //       or a highest prio round
    //       2. make sure that if cur_stream->on_gen_list
    //       is false, it ends up at the end of the array
    //       and I think we shoud start removing from the 
    //       end of the array? So we can add to it easily later
    //       and not have to sort again
    //       3. see the part in pacing.h (303ish) where
    //        priority is updated if not all are transmitted. I think 
    //        I'll be fine though because of the array.
    //       4. When next_round == 0, I need to find the highest prio.
    //          when do_fifo = true, I need to find the one with the lowest birth
    //          otherwise, I have to find "next" based on priority.
    //          if I have done highest prio, that means just going in order,
    //          so no need to sort again. 
    //          if I have done do_fifo, I may need to sort, find its index, and
    //           then go back from that.
    //          Or, I can just do find_ge, and not sort at all? The
    //          not sorting can be just for fifo, becuase maybe it doesn't happen
    //         that often (every 200), and anyway gone after next_round == 0 


	thresh = MIN(thresh, sender->gen_list_cnt);

    // MTP_PRINT("in packet gen list\n");
	/* Send packets */

    uint32_t org_size = sender->gen_list_cnt;
    while (cnt < thresh){
        uint32_t ind = org_size - 1 - cnt;
        cur_stream = sender->gen_arr[ind];

        sender->gen_list_cnt--;
        if (cur_stream->sndvar->on_gen_list){
            cur_stream->sndvar->on_gen_list = FALSE;
            TRACE_DBG("Stream %u: Sending packets\n", cur_stream->id);
            // MTP_PRINT("Stream %u: Sending packets\n", cur_stream->id);
            ret = SendMTPPackets(mtcp, cur_stream, cur_ts);
            if (ret == -2) {
                cur_stream->sndvar->on_gen_list = TRUE;
                sender->gen_list_cnt++;
                /* since there is no available write buffer, break */
                break;
            } 
            else {
                cnt++;
            }
        }
        else {
            cnt++;
			TRACE_ERROR("Stream %d: not on gen list.\n", cur_stream->id);
		}
    }
    return cnt;
}

#else 
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

#endif

/*----------------------------------------------------------------------------*/
void 
AdvanceGBPListHead(mtcp_manager_t mtcp, int advance){ 
    int cur_head = mtcp->g_mtp_bps_head; 
    mtcp->g_mtp_bps_head = (cur_head + advance) % MTP_PER_FLOW_BP_CNT;
}

/*----------------------------------------------------------------------------*/
int
SendGlobalMTPPackets(struct mtcp_manager *mtcp, uint32_t cur_ts){   

    // MTP_PRINT("in SendMTPPackets\n");
    unsigned int sent = 0;
    unsigned int err = 0;
    // MTP_PRINT("bp list head: %u, bp list tail: %u\n", cur_stream->sndvar->mtp_bps_head,
    //                                                cur_stream->sndvar->mtp_bps_tail);
    for (unsigned int i = mtcp->g_mtp_bps_head;
         i != mtcp->g_mtp_bps_tail;
         i = (i + 1) % MTP_PER_FLOW_BP_CNT){
        
        // MTP_PRINT("bp index: %d\n", i);
        
        mtp_bp* bp = &(mtcp->g_mtp_bps[i]);
        
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
                    mtph = (struct mtp_bp_hdr *)IPOutputWTos(mtcp, bp->cur_stream,
                            hdr_len + pkt_len, bp->prio);
                    if (mtph == NULL) {
                        bp->hdr.seq = seq;
                        bp->hdr.data.seg.offset = seg_offset;
                        bp->payload.len = bytes_to_send;
                        bp->payload.data = data_ptr;
                        
                        AdvanceGBPListHead(mtcp, sent + err);
                        
                        MTP_PRINT("ran out midway\n");
                        return -2;
                    }

                    // MTP_PRINT("got packet memory\n");

                    memcpy((uint8_t *)mtph, &(bp->hdr), hdr_len);

                    // MTP_PRINT("copied the header\n");

                    mtph->seq = seq;
                    mtph->data.seg.offset = seg_offset;
                    mtph->data.seg.segment_length = pkt_len;
                    // printf("mtph->seq: %u, mtph->data.seg.offset: %u, mtph->data.seg.segment_length: %u\n",
                    //        mtph->seq, mtph->data.seg.offset, mtph->data.seg.segment_length);
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
            
            uint16_t pkt_len = 0;
            if (bp->payload.data != NULL){
                pkt_len = bp->payload.len;
            }
            
            uint32_t hdr_len = 0;
            if(bp->hdr.type == MTP_HOMA_DATA) {
                hdr_len = MTP_HOMA_COMMON_HSIZE + MTP_HOMA_DATA_HSIZE;
            }
            else if (bp->hdr.type == MTP_HOMA_GRANT){
                hdr_len = MTP_HOMA_COMMON_HSIZE + MTP_HOMA_GRANT_HSIZE;
            }

            
            struct mtp_bp_hdr *mtph;
            mtph = (struct mtp_bp_hdr *)IPOutputWTos(mtcp, bp->cur_stream,
                            hdr_len + pkt_len, bp->prio);
            if (mtph == NULL) {
                
                AdvanceGBPListHead(mtcp, sent + err);
                
                return -2;
            }

            memcpy((uint8_t *)mtph, &(bp->hdr), hdr_len);

            // MTP_PRINT("Sent Seq 2: %u, size: %u\n", ntohl(mtph->seq), payloadLen);    

            if (bp->hdr.type == MTP_HOMA_DATA){
                // MTP TODO: finish this.
                //  until then, send all data packets with segmentation
            }

            sent += 1;
            
        }
    }
    
    
    AdvanceGBPListHead(mtcp, sent + err);
    
    return 0; 
}

int 
MTP_GlobalPacketGen(mtcp_manager_t mtcp, uint32_t cur_ts, int thresh){
	int cnt = 0;
	int ret;

	/* Send packets */
	cnt = 0;
	while (1) {
		if (++cnt > thresh) break;
        ret = SendGlobalMTPPackets(mtcp, cur_ts);
        if (ret == -2){
            // no available buffer
            break;
        }
    }

    return cnt;
}

