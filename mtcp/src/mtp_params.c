#include "mtp_params.h"

uint32_t MTP_total_incoming = 0; // MTP specific
int32_t MTP_grant_nonfifo_left = 0;

rpc_info_1 MTP_all_rpcs[MTP_HOMA_MAX_RPC] = {0};

rpc_info_2 MTP_highest_prio_rpcs[MTP_HOMA_MAX_RPC] = {0};

bool MTP_finish_grant_choose = false;

rinfo MTP_ri[MTP_HOMA_OVERCOMMITMENT] = {0};

bool MTP_remove[MTP_HOMA_OVERCOMMITMENT] = {0};

bool MTP_need_grant_fifo = false;

uint32_t MTP_nr_grant_candidate = 0;
uint32_t MTP_nr_grant_ready = 0;

uint32_t MTP_granting_idx = 0;