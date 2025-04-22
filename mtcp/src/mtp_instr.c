#include "mtp_instr.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "debug.h"
#include "ip_out.h"

/***********************************************
 MTP pkt_gen_instr
 
 Funcion & helper functions for packet generation
 instruction
 ***********************************************/
/*----------------------------------------------------------------------------*/
uint16_t
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
		
	// Note: added this for retransmit
	if(payloadlen > 0) {
		/* update retransmission timer if have payload */
		//cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		//AddtoRTOList(mtcp, cur_stream);
	}

	return 0;
}



/***********************************************
 MTP new_ctx_instr
 
 Funcion & helper functions for new context
 instruction
 ***********************************************/
/*----------------------------------------------------------------------------*/
int
CreateListenCtx(mtcp_manager_t mtcp, int sockid, int backlog) {
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