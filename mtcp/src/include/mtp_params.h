#ifndef MTP_PARAMS_H
#define MTP_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

#define MTP_BP_BUFFER_FULL_ERROR  -2

#define MTP_PER_FLOW_BP_CNT 1000

// Protocol-specific parameters: Homa
#define MTP_HOMA_MAX_RPC 500
#define MTP_HOMA_UNSCHED_BYTES 60000
#define MTP_HOMA_MSS (1514 - 14 - 20 - 60) // Last is DATA_HDR size
#define MTP_HOMA_MAX_PEER 32

#define MTP_HOMA_RPC_IN_SERVICE 8
#define MTP_HOMA_RPC_INCOMING  6
#define MTP_HOMA_RPC_OUTGOING  5
#define MTP_HOMA_RPC_DEAD  0

#define HOMA_MAX_PRIORITIES 8
#define MTP_HOMA_OVERCOMMITMENT 8
#define MTP_HOMA_GRANT_WND 100000
#define MTP_HOMA_MAX_INCOMING 480000

// #define MTP_HOMA_COMMON_HSIZE 28
// #define MTP_HOMA_DATA_HSIZE 32

#define MTP_HOMA_COMMON_HSIZE 24
#define MTP_HOMA_DATA_HSIZE 28

#define MTP_HOMA_DATA  0x10
#define MTP_HOMA_GRANT  0x11
#define MTP_HOMA_RESEND 0x12
#define MTP_HOMA_UNKNOWN 0x13
#define MTP_HOMA_BUSY 0x14
    // CUTOFFS = 0x15,
    // FREEZE = 0x16,
    // NEED_ACK = 0x17,
    // ACK = 0x18,
    // BOGUS = 0x19,

// Global Context
extern uint32_t MTP_total_incoming; // MTP specific

typedef struct rpc_info_1 {
    bool valid;
    uint16_t peer_id;
    uint32_t bytes_remaining;
    uint32_t rpcid;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    uint32_t birth;
    bool in_prio_list;
    int prio_list_ind;
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
} rpc_info_2;

extern rpc_info_2 MTP_highest_prio_rpcs[MTP_HOMA_MAX_RPC];

extern bool MTP_finish_grant_choose;

typedef struct rinfo {
    uint32_t rpcid;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    uint32_t newgrant;
    uint8_t priority;
} rinfo;

extern rinfo MTP_ri[MTP_HOMA_OVERCOMMITMENT];



// Protocol-specific parameters: TCP

#define MTP_TCP_LISTEN_ST 0
#define MTP_TCP_ACCEPT_ST 1
#define MTP_TCP_SYNACK_SENT_ST 2
#define MTP_TCP_SYN_SENT_ST 3
#define MTP_TCP_ESTABLISHED_ST 5
#define MTP_TCP_CLOSE_WAIT_ST 6
#define MTP_TCP_FIN_WAIT_1_ST 7
#define MTP_TCP_FIN_WAIT_2_ST 8
#define MTP_TCP_CLOSING_ST 9
#define MTP_TCP_LAST_ACK_ST 10
#define MTP_TCP_TIME_WAIT_ST 11
#define MTP_TCP_CLOSED_ST 12

#define MTP_TCP_MAX_RTX 16
#define MTP_TCP_MAX_BACKOFF	7

#endif
