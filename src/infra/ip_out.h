#ifndef IP_OUT_H
#define IP_OUT_H

#include <stdint.h>
#include "infra.h"

extern inline int 
GetOutputInterface(uint32_t daddr, uint8_t *is_external);

void
ForwardIPv4Packet(core_ctx_t core, int nif_in, char *buf, int len);

uint8_t *
IPOutputStandalone(struct core_ctx *core, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t payloadlen);

/*
 * The flow-bound variant. mTCP takes a `tcp_stream *` and reads four fields out
 * of it — the cached output interface, the external flag, the per-flow IP id
 * and the two addresses — and hard-codes IPPROTO_TCP for the header and for the
 * checksum-offload request.
 *
 * Here it takes those fields. Two reasons, and the first one is not taste:
 * IPPROTO_TCP in infrastructure source is a rule-4 violation, and removing it
 * means the protocol number has to arrive from somewhere. Once it is a
 * parameter, so is everything else the stream was carrying, and the IP layer
 * stops needing to know that a flow exists.
 *
 * `nif_out` and `is_external` are the caller's cache — mTCP keeps them in the
 * stream and resolves the route once per flow, which is worth keeping — and are
 * read and written in place.
 *
 * `tos` is the blueprint's outer class. mTCP writes a constant 0 and has no way
 * for anything above to change it; a priority-queueing protocol needs one, and
 * the prototype's Homa branch bolted on a second entry point (IPOutputWTos) to
 * get it. One parameter is cheaper and leaves one function. Pass 0 for the
 * donor's behaviour.
 */
uint8_t *
IPOutput(struct core_ctx *core, int *nif_out, uint8_t *is_external,
	 uint32_t saddr, uint32_t daddr, uint8_t protocol,
	 uint16_t ip_id, uint8_t tos, uint16_t payloadlen);

#endif /* IP_OUT_H */
