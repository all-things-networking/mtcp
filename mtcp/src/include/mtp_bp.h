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

struct mtp_bp_hdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr; 
};

#define MTP_TCP_OPT_MSS 2
struct tcp_opt_mss {
    bool valid;
    uint8_t kind;
    uint8_t len;
    uint16_t value;
};


#define MTP_TCP_OPT_SACK_PERMIT 4
struct tcp_opt_sack_permit {
    bool valid;
    uint8_t kind;
    uint8_t len;
};

#define MTP_TCP_OPT_TIMESTAMP 8
struct tcp_opt_timestamp {
    bool valid;
    uint8_t kind;
    uint8_t len;
    uint32_t value1;
    uint32_t value2;
};

#define MTP_TCP_OPT_WSCALE 3
struct tcp_opt_wscale {
    bool valid;
    uint8_t kind;
    uint8_t len;
    uint8_t value;
};


#define MTP_TCP_OPT_NOP 1
struct tcp_opt_nop {
    bool valid;
    uint8_t kind;
};

// MTP TODO: make this match MTP code
struct mtp_bp_options{
    struct tcp_opt_mss mss; 
    struct tcp_opt_sack_permit sack_permit;
    struct tcp_opt_nop nop1;
    struct tcp_opt_nop nop2;
    struct tcp_opt_timestamp timestamp;
    struct tcp_opt_nop nop3;
    struct tcp_opt_wscale wscale;
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
    struct mtp_bp_options opts;
    struct mtp_bp_payload payload;
    // MTP TODO: add segmentation instructions
};

typedef struct mtp_bp mtp_bp;

// default header values because C doesn't allow 
// initialization during declaration
void MTP_set_opt_mss(struct tcp_opt_mss *mss, uint16_t value);
void MTP_set_opt_sack_permit(struct tcp_opt_sack_permit *sack_permit);
void MTP_set_opt_nop(struct tcp_opt_nop *nop);
void MTP_set_opt_timestamp(struct tcp_opt_timestamp *ts, uint32_t value1, uint32_t value2);
void MTP_set_opt_wscale(struct tcp_opt_wscale *wscale, uint8_t value);
uint16_t MTP_CalculateOptionLength(mtp_bp* bp);

void print_MTP_bp(struct mtp_bp* bp);
void MTP_hton_bp(struct mtp_bp *bp);
void MTP_ntoh_bp(struct mtp_bp *bp);

#endif
