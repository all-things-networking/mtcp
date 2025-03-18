#ifndef MTP_BP_H
#define MTP_BP_H

// Should get compiler generated

#define MTP_HEADER_LEN 20

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
    bool valid;
    u_int8_t kind;
    u_int8_t len;
    u_int32_t value;
};

struct tcp_opt_sack_permit {
    bool valid;
    u_int8_t kind;
    u_int8_t len;
    u_int16_t value;
};

struct tcp_opt_timestamp {
    bool valid;
    u_int8_t kind;
    u_int8_t len;
    u_int32_t value1;
    u_int32_t value2;
};

struct tcp_opt_wscale {
    bool valid = false;
    u_int8_t kind = 3;
    u_int8_t len = 3;
    u_int32_t value;
};

struct tcp_opt_nop {
    bool valid;
    u_int8_t kind;
    u_int8_t len;
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
}
typedef struct mtp_bp mtp_bp;

// default header values because C doesn't allow 
// initialization during declaration
void MTP_set_opt_mss(struct tcp_opt_mss *mss, uint32_t value);
void MTP_set_sack_permit(struct tcp_opt_sack_permit *sack_permit, uint16_t value);
void MTP_set_nop(struct tcp_opt_nop *nop);
void MTP_set_timestamp(struct tcp_opt_timestamp *ts, uint32_t value1, uint32_t value2);

#endif
