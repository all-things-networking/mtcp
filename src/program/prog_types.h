#ifndef PROG_TYPES_H
#define PROG_TYPES_H
/*
 * Compiler output: the types this program's declarations generate.
 *
 * Today it is hand-written in the form `mtpc` would emit, because the compiler
 * comes after the target works (docs/PLAN.md §8). Nothing outside src/program/
 * may assume that. Rule 4 permits protocol identity HERE and nowhere else.
 *
 * Conforms to MTP contract v4 (minmit/MTP-kernel-test, docs/MTP_LANG.md).
 */
#include <stdint.h>

/*
 * From  flow_id tcp_fid : (uint32, uint32, uint16, uint16)
 *
 * SHAPE ONLY. The positional names are the compiler's; they mean nothing here
 * and nothing may read them as though they did. CR-5 is explicit about this,
 * and the lead struck out a proposed form that named loc_ip/rem_ip/loc_port/
 * rem_port precisely because those names only have meaning inside an event.
 * Our first attempt at this named them too.
 *
 * The PARSER constructs the value and canonicalises direction, so an inbound
 * packet and an outbound app op resolve the same context. That is protocol
 * logic; the compiler does not do it and the target must not.
 *
 * The target keys its store on the raw bytes of this struct and never reads a
 * field, so there is no hash or compare callback to supply. Packed, because the
 * key is compared and hashed as bytes and padding would make two equal keys
 * differ.
 */
typedef struct __attribute__((packed)) {
	uint32_t v0;
	uint32_t v1;
	uint16_t v2;
	uint16_t v3;
} flowkey_t;

#endif /* PROG_TYPES_H */
