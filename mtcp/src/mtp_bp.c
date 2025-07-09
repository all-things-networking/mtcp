#include "mtp_bp.h"

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
    wscale->kind = 2;
    wscale->len = 3;
    wscale->value = value;
}


