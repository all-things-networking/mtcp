#ifndef MTP_BP_H
#define MTP_BP_H

#include <stdint.h>
#include <stdbool.h>

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

// Should get compiler generated

#define MTP_HEADER_LEN 20

struct homa_ack {
    uint32_t rpcid;
    uint16_t sport;
    uint16_t dport;
};

// 8 + 4 + 8
struct data_segment {
    uint32_t offset;
    uint32_t segment_length;
    struct homa_ack ack;
    // uint32_t ack_rpcid;
    // uint16_t ack_sport;
    // uint16_t ack_dport;
};

// 12
struct homa_data_hdr {
    uint32_t message_length;
    uint32_t incoming;
    uint16_t cutoff_version;
    uint8_t retransmit;
    uint8_t unused1;
    struct data_segment seg;
};

// 9
struct homa_resend_hdr {
    uint32_t offset;
    uint32_t length;
    uint8_t priority;
};

// 6
struct homa_grant_hdr {
    uint32_t offset;
    uint8_t priority;
    uint8_t resend_all;
};

struct mtp_bp_hdr {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t unused1;
    uint32_t unused2;
    uint8_t  doff;
    uint8_t  type;
    uint16_t seq;
    uint16_t checksum;
    uint16_t unused4;
    uint32_t sender_id; 

    union {
        struct homa_data_hdr data;
        struct homa_resend_hdr resend;
        struct homa_grant_hdr grant;
    };
};


struct mtp_bp_payload {
    uint8_t* data;
    uint32_t len;
    bool needs_segmentation;
    uint32_t seg_size;
    uint32_t seg_rule_group_id;
};

struct mtp_bp {
    struct mtp_bp_hdr hdr;
    struct mtp_bp_payload payload;
    uint8_t prio;
    // MTP TODO: add segmentation instructions
};

typedef struct mtp_bp mtp_bp;


void print_MTP_bp(struct mtp_bp* bp);
/*
void MTP_hton_bp(struct mtp_bp *bp);
void MTP_ntoh_bp(struct mtp_bp *bp);
*/

#endif
