#include "mtp_bp.h"
#include <stdio.h>
#include <netinet/in.h>

void MTP_set_opt_mss(struct tcp_opt_mss *mss, uint16_t value){
    mss->valid = TRUE;
    mss->kind = 2;
    mss->len = 4;
    mss->value = value;
}

void MTP_set_opt_sack_permit(struct tcp_opt_sack_permit *sack_permit){
    sack_permit->valid = TRUE;
    sack_permit->kind = 4;
    sack_permit->len = 2;
}

void MTP_set_opt_nop(struct tcp_opt_nop *nop){
    nop->valid = TRUE;
    nop->kind = 1;
}

void MTP_set_opt_timestamp(struct tcp_opt_timestamp *ts, uint32_t value1, uint32_t value2){
    ts->valid = TRUE;
    ts->kind = 8;
    ts->len = 10;
    ts->value1 = value1;
    ts->value2 = value2;
}

void MTP_set_opt_wscale(struct tcp_opt_wscale *wscale, uint8_t value){
    wscale->valid = TRUE;
    wscale->kind = 3;
    wscale->len = 3;
    wscale->value = value;
}

uint16_t
MTP_CalculateOptionLength(mtp_bp* bp){
    uint16_t res = 0;
    struct mtp_bp_options *opts = &(bp->opts);
    if (opts->mss.valid){
        res += 4;
    }
    if (opts->sack_permit.valid){
        res += 2;
    }
    if (opts->nop1.valid){
        res += 1;
    }
    if (opts->nop2.valid){
        res += 1;
    }
    if (opts->timestamp.valid){
        res += 10;
    }
    if (opts->nop3.valid){
        res += 1;
    }
    if (opts->wscale.valid){
        res += 3;
    }
    return res;
}

void MTP_hton_bp(struct mtp_bp *bp) {
    bp->hdr.seq = htonl(bp->hdr.seq);
    bp->hdr.ack_seq = htonl(bp->hdr.ack_seq);
    bp->hdr.window = htons(bp->hdr.window);
    bp->hdr.check = 0; // Checksum will be calculated later
    bp->hdr.urg_ptr = htons(bp->hdr.urg_ptr);
}

void MTP_ntoh_bp(struct mtp_bp *bp) {
    bp->hdr.seq = ntohl(bp->hdr.seq);
    bp->hdr.ack_seq = ntohl(bp->hdr.ack_seq);
    bp->hdr.window = ntohs(bp->hdr.window);
    bp->hdr.check = 0; // Checksum will be calculated later
    bp->hdr.urg_ptr = ntohs(bp->hdr.urg_ptr);
}

void print_MTP_bp(struct mtp_bp* bp){  
    printf("*************** MTP BP Header ******************\n");
    printf("Source: %u, Dest: %u, Seq: %u, Ack Seq: %u\n",
           ntohs(bp->hdr.source), ntohs(bp->hdr.dest), ntohl(bp->hdr.seq), ntohl(bp->hdr.ack_seq));
    printf("Header Length: %u\n", bp->hdr.doff * 4);
    printf("Flags: FIN=%d, SYN=%d, RST=%d, PSH=%d, ACK=%d, URG=%d\n",
           bp->hdr.fin, bp->hdr.syn, bp->hdr.rst, bp->hdr.psh,
           bp->hdr.ack, bp->hdr.urg);
    printf("Window: %u, Checksum: %u, Urg Ptr: %u\n",
           ntohs(bp->hdr.window), bp->hdr.check, bp->hdr.urg_ptr);
    
    printf("Options:\n");
    if (bp->opts.mss.valid) {
        printf("MSS: %u\n", bp->opts.mss.value);
    }
    if (bp->opts.sack_permit.valid) {
        printf("SACK Permitted\n");
    }
    if (bp->opts.timestamp.valid) {
        printf("Timestamp: %u/%u\n", bp->opts.timestamp.value1,
               bp->opts.timestamp.value2);
    }
    if (bp->opts.wscale.valid) {
        printf("Window Scale: %u\n", bp->opts.wscale.value);
    }
    
    printf("Payload Length: %u\n", bp->payload.len);
    // if (bp->payload.data) {
    //     printf("Payload Data: ");
    //     for (uint16_t i = 0; i < bp->payload.len; i++) {
    //         printf("%02x ", bp->payload.data[i]);
    //     }
    //     printf("\n");
    // } else {
    //     printf("No Payload Data\n");
    // }
    printf("Payload Data Pointer: %p\n", bp->payload.data);
    printf("Needs Segmentation: %s, Seg Size: %u, Seg Rule Group ID: %u\n",
           bp->payload.needs_segmentation ? "Yes" : "No",
           bp->payload.seg_size, bp->payload.seg_rule_group_id);
    printf("*********************************************\n");
}