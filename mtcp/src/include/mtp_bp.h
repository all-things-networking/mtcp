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

struct tcp_opt_mss {
    bool valid;
    uint8_t kind;
    uint8_t len;
    uint32_t value;
};

struct tcp_opt_sack_permit {
    bool valid;
    uint8_t kind;
    uint8_t len;
    uint16_t value;
};

struct tcp_opt_timestamp {
    bool valid;
    uint8_t kind;
    uint8_t len;
    uint32_t value1;
    uint32_t value2;
};

struct tcp_opt_wscale {
    bool valid;
    uint8_t kind;
    uint8_t len;
    uint32_t value;
};

struct tcp_opt_nop {
    bool valid;
    uint8_t kind;
    uint8_t len;
};

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
    uint16_t len;
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
void MTP_set_opt_mss(struct tcp_opt_mss *mss, uint32_t value);
void MTP_set_opt_sack_permit(struct tcp_opt_sack_permit *sack_permit, uint16_t value);
void MTP_set_opt_nop(struct tcp_opt_nop *nop);
void MTP_set_opt_timestamp(struct tcp_opt_timestamp *ts, uint32_t value1, uint32_t value2);
void MTP_set_opt_wscale(struct tcp_opt_wscale *wscale, uint32_t value);

#endif
