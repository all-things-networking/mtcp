#ifndef MTP_GLOBAL_H
#define MTP_GLOBAL_H

#include <stdint.h>
#include <stdbool.h>
#include "tcp_stream.h"

// Global Context
extern uint32_t MTP_total_incoming;
extern int32_t MTP_grant_nonfifo_left;

typedef struct rpc_info_1 {
    bool valid;
    uint16_t peer_id;
    uint32_t bytes_remaining;
    uint32_t rpcid;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    uint32_t birth;
    uint32_t incoming;
    uint32_t message_length;
    bool in_prio_list;
    int prio_list_ind;
    // For pkt gen purposes
    // should not be used in eps
    tcp_stream* cur_stream;
} rpc_info_1;

extern rpc_info_1 MTP_all_rpcs[MTP_HOMA_MAX_RPC];


typedef struct rpc_info_2 {
    bool valid;
    uint32_t bytes_remaining;
    uint16_t peer_id;
    uint32_t rpcid;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    uint32_t message_length;
    uint32_t incoming;
    uint32_t fifo_list_ind;
    // For pkt gen purposes
    // should not be used in eps
    tcp_stream* cur_stream;
} rpc_info_2;

extern rpc_info_2 MTP_highest_prio_rpcs[MTP_HOMA_MAX_RPC];

extern bool MTP_finish_grant_choose;

typedef struct rinfo {
    uint16_t peer_id;
    uint32_t rpcid;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    uint32_t newgrant;
    uint8_t priority;
    // For pkt gen purposes
    // should not be used in eps
    tcp_stream* cur_stream;
} rinfo;

extern rinfo MTP_ri[MTP_HOMA_OVERCOMMITMENT];

extern bool MTP_remove[MTP_HOMA_OVERCOMMITMENT];

extern bool MTP_need_grant_fifo;

extern uint32_t MTP_nr_grant_candidate;
extern uint32_t MTP_nr_grant_ready;

typedef struct grant_info {
    uint16_t sport;
    uint16_t dport;
    uint64_t rpcid;
    uint32_t newgrant;
    uint32_t remote_ip;
    uint8_t priority;
    // For pkt gen purposes
    // should not be used in eps
    tcp_stream* cur_stream;
} grant_info;

extern uint32_t MTP_granting_idx;

#endif