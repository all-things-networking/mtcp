#include "mtp_net.h"
#include "mtp_ep.h"
#include "fhash.h"
#include "debug.h"
#include "tcp_out.h"
#include "tcp_util.h"
#include "timer.h"
#include "ip_out.h"

#define TCP_CALCULATE_CHECKSUM      TRUE
#define VERIFY_RX_CHECKSUM          TRUE

// Helper functions
/*----------------------------------------------------------------------------*/
static inline void HandleMissingCtx(mtcp_manager_t mtcp, 
	const struct iphdr *iph, struct mtp_bp_hdr* mtph,
    int payloadlen, uint32_t cur_ts) {
	// TODO? This can be considered as processor for an "error" event
    TRACE_DBG("Refusing packet: context not found.\n");
    printf("Refusing packet: listen context not found.\n");
    /*
	SendTCPPacketStandalone(mtcp, 
		iph->daddr, tcph->dest, iph->saddr, tcph->source, 
		0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
		NULL, 0, cur_ts, 0);
	return TRUE;
    */
}

/*----------------------------------------------------------------------------*/
// MTP TODO: make protocol independent, like P4
static inline int MTP_ValidateChecksum(mtcp_manager_t mtcp, const int ifidx,  
	const struct iphdr *iph, int ip_len, struct mtp_bp_hdr* mtph, uint16_t payloadlen) {
	
    // Checksum validation
#if VERIFY_RX_CHECKSUM
	int rc = 0;
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx, PKT_RX_TCP_CSUM, NULL);
#endif
	if (rc == -1) {
		uint16_t check = TCPCalcChecksum((uint16_t *)mtph, 
			             (mtph->doff << 2) + payloadlen, iph->saddr, iph->daddr);
		if (check) {
			TRACE_DBG("Checksum Error: Original: 0x%04x, calculated: 0x%04x\n", 
				mtph->check, TCPCalcChecksum((uint16_t *)mtph, 
				(mtph->doff << 2) + payloadlen, iph->saddr, iph->daddr));
			mtph->check = 0;
			return MTP_ERROR;
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

void 
MTPExtractOptions(uint8_t *buff,
                  struct mtp_bp_options *opts,
                  int sel_len,
                  int len)
{
	int i;

	for (i = 0; i < len; ) {
        // MTP TODO: need to generalize for sel_len > 1
        uint8_t opttype = *(buff + i);
        i++;
        for (int j = 0; j < sel_len - 1; j++){
            opttype = (opttype << 8) + *(buff + i);
            i++;
        }

        if (opttype == MTP_TCP_OPT_MSS){
            i++; // for len
            uint16_t mss = *(buff + i) << 8;
            i++;
            mss += *(buff + i);
            i++;
            MTP_set_opt_mss(&(opts->mss), mss); 
        }

        else if (opttype == MTP_TCP_OPT_SACK_PERMIT){
            i++; // for len
            MTP_set_opt_sack_permit(&(opts->sack_permit));
        }      

        else if (opttype == MTP_TCP_OPT_NOP) continue;

        else if (opttype == MTP_TCP_OPT_TIMESTAMP){
            i++; // for len
            uint32_t t1 = ntohl(*(uint32_t *)(buff + i));
            i += 4;
            uint32_t t2 = ntohl(*(uint32_t *)(buff + i));
            i += 4;
            MTP_set_opt_timestamp(&(opts->timestamp), t1, t2); 
        }

        else if (opttype == MTP_TCP_OPT_WSCALE){
            i++; // for len
            uint8_t wscale = *(buff + i);
            i++;
            MTP_set_opt_wscale(&(opts->wscale), wscale);
        } 

        else {
            // MTP TODO: parse option default;
            uint8_t len = *(buff + i);
            i++;
            i += len - 2;
        }
/* 
		opt = *(tcpopt + i++);
		
		if (opt == TCP_OPT_END) {	// end of option field
			break;
		} else if (opt == TCP_OPT_NOP) {	// no option
			continue;
		} else {

			optlen = *(tcpopt + i++);
			if (i + optlen - 2 > len) {
				break;
			}

			if (opt == TCP_OPT_MSS) {
				cur_stream->sndvar->mss = *(tcpopt + i++) << 8;
				cur_stream->sndvar->mss += *(tcpopt + i++);
				cur_stream->sndvar->eff_mss = cur_stream->sndvar->mss;
#if TCP_OPT_TIMESTAMP_ENABLED
				cur_stream->sndvar->eff_mss -= (TCP_OPT_TIMESTAMP_LEN + 2);
#endif
			} else if (opt == TCP_OPT_WSCALE) {
				cur_stream->sndvar->wscale_peer = *(tcpopt + i++);
			} else if (opt == TCP_OPT_SACK_PERMIT) {
				cur_stream->sack_permit = TRUE;
				TRACE_SACK("Remote SACK permited.\n");
			} else if (opt == TCP_OPT_TIMESTAMP) {
				TRACE_TSTAMP("Saw peer timestamp!\n");
				cur_stream->saw_timestamp = TRUE;
				cur_stream->rcvvar->ts_recent = ntohl(*(uint32_t *)(tcpopt + i));
				cur_stream->rcvvar->ts_last_ts_upd = cur_ts;
				i += 8;
			} else {
				// not handle
				i += optlen - 2;
			}
		} */
	}
}

// Net RX 
int MTP_ProcessTransportPacket(mtcp_manager_t mtcp, 
	uint32_t cur_ts, const int ifidx, const struct iphdr *iph, int ip_len) 
{
	/* RX parser(parse_net_packet) + incoming net events' "dispatcher"
	   incoming net events are "created" from parsing, and dispatched to eps directly
	   following a "run-to-completion model" */

	// MTP - Compiler-Start: extract
    // maps to extract in the parser
    struct mtp_bp_hdr *mtph = (struct mtp_bp_hdr *) ((u_char *)iph + (iph->ihl << 2));
    mtph->seq = ntohl(mtph->seq);
	mtph->ack_seq = ntohl(mtph->ack_seq);
    mtph->window = ntohs(mtph->window);
    // MTP TODO: add this after changing tcp_stream because that one keeps it in network order
    //mtph->dest = ntohs(mtph->dest);
	//mtph->source = ntohs(mtph->source);
    // MTP TODO: parse options
    struct mtp_bp_options mtp_opt;
    uint8_t *opt_buff = (uint8_t*) mtph + 20;
    int opt_len = (mtph->doff - 5) * 4; 
    MTPExtractOptions(opt_buff, &mtp_opt, 1, opt_len); 
	//struct tcphdr* tcph = (struct tcphdr *) ((u_char *)iph + (iph->ihl << 2));
    struct mtp_bp_payload payload;
	payload.data = (uint8_t *)mtph + (mtph->doff << 2);
    payload.len = ip_len - (payload.data - (u_char *)iph); 
    // MTP - Compiler-End: extract

    if (ip_len < ((iph->ihl + mtph->doff) << 2)) return MTP_ERROR;
    int ret = MTP_ValidateChecksum(mtcp, ifidx, iph, ip_len, mtph, payload.len);
    if (ret != 0) return MTP_ERROR;

    // MTP - Combining dispatcher, context look up, and event chain

    // MTP: maps to SYN event
    if (mtph->syn && !mtph->ack){
        uint32_t remote_ip = iph->saddr;
        uint16_t remote_port = mtph->source;
        uint32_t init_seq = mtph->seq;
        uint16_t rwnd_size = mtph->window;
        bool sack_permit = mtp_opt.sack_permit.valid;
        bool mss_valid = mtp_opt.mss.valid;
        uint16_t mss = mtp_opt.mss.value;
        bool wscale_valid = mtp_opt.wscale.valid;
        uint8_t wscale = mtp_opt.mss.value;
        
        // MTP TODO: change key to include IP
        // MTP TODO: separate out  flow id construction
		// Listen context lookup
        struct mtp_listen_ctx *listen_ctx = 
			(struct mtp_listen_ctx *)ListenerHTSearch(mtcp->listeners, &(mtph->dest));
        if (listen_ctx == NULL) {
            HandleMissingCtx(mtcp, iph, mtph, payload.len, cur_ts);
        }           

        MtpSynChain(mtcp, cur_ts, remote_ip, remote_port, 
                    init_seq, rwnd_size, sack_permit,
                    mss_valid, mss, wscale_valid, wscale, 
                    listen_ctx);
        return 0;
    }

    	
	// MTP: maps to flow id generation in parser
	tcp_stream s_stream;
    s_stream.saddr = iph->daddr;
	s_stream.sport = mtph->dest;
	s_stream.daddr = iph->saddr;
	s_stream.dport = mtph->source;

    //if (mtph->syn && mtph->ack){
    //    return 0;
    //}

    //if (payload.len > 0){
    //}

    if (mtph->ack){

        uint32_t ev_ack_seq = mtph->ack_seq;
        uint16_t ev_rwnd_size = mtph->window;
        uint32_t ev_seq = mtph->seq;
 
        // Context lookup
        tcp_stream *cur_stream = NULL;
	    if (!(cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream))) {
            printf("No context\n");
            return -1;
            // MTP TODO: return HandleMissingCtx(mtcp, iph, tcph, seq, payload.len, cur_ts);
        }
        
        MtpAckChain(mtcp, cur_ts, ev_ack_seq, ev_rwnd_size, ev_seq, cur_stream);
    } 

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
    printf("Inside MTP_ProcessSendEvents\n");
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

    unsigned int sent = 0;
    unsigned int err = 0;
    for (unsigned int i = cur_stream->sndvar->mtp_bps_head;
         i != cur_stream->sndvar->mtp_bps_tail;
         i = (i + 1) % MTP_PER_FLOW_BP_CNT){
        
        // printf("bp index: %d\n", i);
        
        mtp_bp* bp = &(cur_stream->sndvar->mtp_bps[i]);
        
        // printf("dequeued bp:");
        // print_MTP_bp(bp);

        uint16_t optlen = MTP_CalculateOptionLength(bp);

        if (bp->payload.needs_segmentation){
            uint32_t bytes_to_send = bp->payload.len;
            uint8_t *data_ptr = bp->payload.data;

            // printf("SENDMTPPackets: before grabbing the lock\n");
            // SBUF_LOCK(&cur_stream->sndvar->write_lock);
            // printf("SENDMTPPackets: after grabbing the lock\n");

            // printf("1 sending, here\n");

            if (bp->payload.seg_rule_group_id == 1){
                uint32_t seq = ntohl(bp->hdr.seq);
                uint32_t seg_size = bp->payload.seg_size;

                while (bytes_to_send > 0) {
                    // printf("sending, here: %d\n", bytes_to_send);

                    int32_t pkt_len = MIN(seg_size, bytes_to_send);

                    // printf("pkt_len: %d\n", pkt_len);

                    // Send the next packet
                    struct mtp_bp_hdr *mtph;
                    mtph = (struct mtp_bp_hdr *)IPOutput(mtcp, cur_stream,
                            MTP_HEADER_LEN + optlen + pkt_len);
                    if (mtph == NULL) {
                        bp->hdr.seq = htonl(seq);
                        bp->payload.data = data_ptr;
                        // AdvanceBPListHead(cur_stream, sent + err);
                        // SBUF_UNLOCK(&cur_stream->sndvar->write_lock);
                        // printf("ran out midway\n");
                        return -2;
                    }

                    // printf("got packet memory\n");

                    memcpy((uint8_t *)mtph, &(bp->hdr), MTP_HEADER_LEN);

                    // printf("copied the header\n");

                    mtph->seq = htonl(seq);

                    // MTP TODO: this is TCP specific
                    mtph->doff = (MTP_HEADER_LEN + optlen) >> 2;

                    // printf("setup some fields\n");

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
                        uint8_t* val_start = &buff_opts[i];
                        uint32_t *tmp = (uint32_t *)(val_start);
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

                    // printf("setup options\n");
                    // MTP TODO: this is TCP specific?
                    assert (i % 4 == 0);
                    assert (i == optlen); 

                    // MTP TODO: do we need to lock here?
                    // copy payload if exist
                    // printf("packet addr:%p\n", (uint8_t *)mtph + MTP_HEADER_LEN + optlen);
                    // printf("data pointer: %p\n", data_ptr);
                    memcpy((uint8_t *)mtph + MTP_HEADER_LEN + optlen, data_ptr, pkt_len);
                    #if defined(NETSTAT) && defined(ENABLELRO)
                    mtcp->nstat.tx_gdptbytes += payloadlen;
                    #endif // NETSTAT 
                     
                    // printf("copied payload\n");

                    // MTP TODO: checksum is TCP specific
                    int rc = -1;
                    #if TCP_CALCULATE_CHECKSUM
                    #ifndef DISABLE_HWCSUM
                    if (mtcp->iom->dev_ioctl != NULL){
                        rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
                                    PKT_TX_TCPIP_CSUM, NULL);
                    }
                    #endif
                    //printf("Test 6");

                    if (rc == -1){
                        mtph->check = TCPCalcChecksum((uint16_t *)mtph,
                                        MTP_HEADER_LEN + optlen + pkt_len,
                                        cur_stream->saddr, cur_stream->daddr);
                    }
                    #endif

                    // printf("setup checksum\n");
                    // update for next packet based on segementation rules
                    bytes_to_send -= pkt_len;
                    seq += pkt_len;
                    data_ptr += pkt_len;

                    // printf("moving on\n");
                           
                }
            }
            sent += 1;
        }
        else {
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
                // AdvanceBPListHead(cur_stream, sent + err);
                // SBUF_UNLOCK(&cur_stream->sndvar->write_lock);
                return -2;
            }

            memcpy((uint8_t *)mtph, &(bp->hdr), MTP_HEADER_LEN);

            // MTP TODO: this is TCP specific
            mtph->doff = (MTP_HEADER_LEN + optlen) >> 2;

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
                uint8_t* val_start = &buff_opts[i];
                uint32_t *tmp = (uint32_t *)(val_start);
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

            // MTP TODO: this is TCP specific?
            assert (i % 4 == 0);
            assert (i == optlen); 

            // MTP TODO: do we need to lock here?
            // copy payload if exist
            if (bp->payload.data != NULL) {
                memcpy((uint8_t *)mtph + MTP_HEADER_LEN + optlen, bp->payload.data, payloadLen);
                #if defined(NETSTAT) && defined(ENABLELRO)
                mtcp->nstat.tx_gdptbytes += payloadlen;
                #endif // NETSTAT 
            } 

            // MTP TODO: checksum is TCP specific
            int rc = -1;
            #if TCP_CALCULATE_CHECKSUM
            #ifndef DISABLE_HWCSUM
            if (mtcp->iom->dev_ioctl != NULL){
                rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
                            PKT_TX_TCPIP_CSUM, NULL);
            }
            #endif
            //printf("Test 6");

            if (rc == -1){
                mtph->check = TCPCalcChecksum((uint16_t *)mtph,
                                MTP_HEADER_LEN + optlen + payloadLen,
                                cur_stream->saddr, cur_stream->daddr);
            }
            #endif

            sent += 1;
        }
    }
    
        /*
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
        */
        
    
    AdvanceBPListHead(cur_stream, sent + err);
    // SBUF_UNLOCK(&cur_stream->sndvar->write_lock);
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

	/* Send packets */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->gen_list);
	last = TAILQ_LAST(&sender->gen_list, gen_head);
	while (cur_stream) {
		if (++cnt > thresh) break;

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
			} 
            else if (ret < 0) {
				/* try again after handling other streams */
				TAILQ_INSERT_TAIL(&sender->gen_list,
						  cur_stream, sndvar->gen_link);
				cur_stream->sndvar->on_gen_list = TRUE;
				sender->gen_list_cnt++;
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


