#ifndef MTP_BP_H
#define MTP_BP_H

// Should get compiler generated

struct mtp_bp_hdr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr; 
};

struct tcp_opt_mss {
    bool valid = false;
    u_int8_t kind = 2;
    u_int8_t len = 4;
    u_int32_t value;
};

struct tcp_opt_timestamp {
    bool valid = false;
    u_int8_t kind = 8;
    u_int8_t len = 10;
    u_int32_t value1;
    u_int32_t value2;
};

struct tcp_opt_wscale {
    bool valid = false;
    u_int8_t kind = 3;
    u_int8_t len = 3;
    u_int32_t value;
};

struct tcp_opt_sack_permit {
    bool valid = false;
    u_int8_t kind = 4;
    u_int8_t len = 2;
    u_int16_t value;
};

struct tcp_opt_nop {
    bool valid = false;
    u_int8_t kind = 1;
    u_int8_t len = 1;
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
    uint8_t* payload;
    uint16_t payloadLen;
};

struct mtp_bp {
    struct mtp_bp_hdr hdr;
    struct mtp_bp_options opts;
    struct mtp_bp_payload payload;
    // MTP TODO: add segmentation instructions
}
typedef struct mtp_bp mtp_bp;

#endif
