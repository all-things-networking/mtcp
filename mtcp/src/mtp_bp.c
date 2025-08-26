#include "mtp_bp.h"
#include <stdio.h>
#include <netinet/in.h>
#include "mtp_params.h" 

#define ENABLE_MTP_PRINT 1

#ifdef ENABLE_MTP_PRINT
#define MTP_PRINT(f, m...) fprintf(stdout, f, ##m)
#else
#define MTP_PRINT(f, m...) (void)0
#endif


/*
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
*/

void print_MTP_bp(struct mtp_bp* bp){ 
    MTP_PRINT("*************** MTP BP Header ******************\n");
    MTP_PRINT("Source: %u, Dest: %u, Seq: %u\n",
           ntohs(bp->hdr.src_port), ntohs(bp->hdr.dest_port), bp->hdr.seq);
    MTP_PRINT("Sender ID: %u\n", bp->hdr.sender_id);
    MTP_PRINT("Type: %u\n", bp->hdr.type);
    
    if (bp->hdr.type == MTP_HOMA_DATA) { // Data Packet
        MTP_PRINT("Message Length: %u, Incoming: %u, Cutoff Version: %u, Retransmit: %u\n",
               bp->hdr.data.message_length, bp->hdr.data.incoming,
               bp->hdr.data.cutoff_version, bp->hdr.data.retransmit);
        MTP_PRINT("Segmentation Offset: %u, Segment Length: %u\n",
               bp->hdr.data.seg.offset, bp->hdr.data.seg.segment_length);
        MTP_PRINT("Homa Ack - RPC ID: %u, Src Port: %u, Dest Port: %u\n",
               bp->hdr.data.seg.ack.rpcid,
               bp->hdr.data.seg.ack.sport,
               bp->hdr.data.seg.ack.dport);
    } 
    // else if (bp->hdr.type == MTP_HOMA_RESEND) { // Resend Packet
    //     MTP_PRINT("Resend Offset: %u, Length: %u, Priority: %u\n",
    //            bp->hdr.resend.offset, bp->hdr.resend.length, bp->hdr.resend.priority);
    // } 
    // else if (bp->hdr.type == MTP_HOMA_GRANT) { // Grant Packet
    //     MTP_PRINT("Grant Offset: %u, Priority: %u, Resend All: %u\n",
    //            bp->hdr.grant.offset, bp->hdr.grant.priority, bp->hdr.grant.resend_all);
    // } 
    else {
        MTP_PRINT("Unknown packet type\n");
    }
    
    MTP_PRINT("Payload Length: %u\n", bp->payload.len);
    MTP_PRINT("Priority: %u\n", bp->prio);
    // if (bp->payload.data) {
    //     MTP_PRINT("Payload Data: ");
    //     for (uint16_t i = 0; i < bp->payload.len; i++) {
    //         MTP_PRINT("%02x ", bp->payload.data[i]);
    //     }
    //     MTP_PRINT("\n");
    // } else {
    //     MTP_PRINT("No Payload Data\n");
    // }
    MTP_PRINT("Payload Data Pointer: %p\n", bp->payload.data);
    MTP_PRINT("Needs Segmentation: %s, Seg Size: %u, Seg Rule Group ID: %u\n",
           bp->payload.needs_segmentation ? "Yes" : "No",
           bp->payload.seg_size, bp->payload.seg_rule_group_id);
    MTP_PRINT("*********************************************\n");
}

void print_MTP_bp_tcp(struct mtp_bp* bp){ 
/* 
    MTP_PRINT("*************** MTP BP Header ******************\n");
    MTP_PRINT("Source: %u, Dest: %u, Seq: %u, Ack Seq: %u\n",
           ntohs(bp->hdr.source), ntohs(bp->hdr.dest), ntohl(bp->hdr.seq), ntohl(bp->hdr.ack_seq));
    MTP_PRINT("Header Length: %u\n", bp->hdr.doff * 4);
    MTP_PRINT("Flags: FIN=%d, SYN=%d, RST=%d, PSH=%d, ACK=%d, URG=%d\n",
           bp->hdr.fin, bp->hdr.syn, bp->hdr.rst, bp->hdr.psh,
           bp->hdr.ack, bp->hdr.urg);
    MTP_PRINT("Window: %u, Checksum: %u, Urg Ptr: %u\n",
           ntohs(bp->hdr.window), bp->hdr.check, bp->hdr.urg_ptr);
    
    MTP_PRINT("Options:\n");
    if (bp->opts.mss.valid) {
        MTP_PRINT("MSS: %u\n", bp->opts.mss.value);
    }
    if (bp->opts.sack_permit.valid) {
        MTP_PRINT("SACK Permitted\n");
    }
    if (bp->opts.timestamp.valid) {
        MTP_PRINT("Timestamp: %u/%u\n", ntohl(bp->opts.timestamp.value1),
               bp->opts.timestamp.value2);
    }
    if (bp->opts.wscale.valid) {
        MTP_PRINT("Window Scale: %u\n", bp->opts.wscale.value);
    }
    
    MTP_PRINT("Payload Length: %u\n", bp->payload.len);
    // if (bp->payload.data) {
    //     MTP_PRINT("Payload Data: ");
    //     for (uint16_t i = 0; i < bp->payload.len; i++) {
    //         MTP_PRINT("%02x ", bp->payload.data[i]);
    //     }
    //     MTP_PRINT("\n");
    // } else {
    //     MTP_PRINT("No Payload Data\n");
    // }
    MTP_PRINT("Payload Data Pointer: %p\n", bp->payload.data);
    MTP_PRINT("Needs Segmentation: %s, Seg Size: %u, Seg Rule Group ID: %u\n",
           bp->payload.needs_segmentation ? "Yes" : "No",
           bp->payload.seg_size, bp->payload.seg_rule_group_id);
    MTP_PRINT("*********************************************\n");
    */
}
