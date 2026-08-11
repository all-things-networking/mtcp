#ifndef UPCALL_H
#define UPCALL_H
/*
 * Everything the infrastructure layer needs from the layer above it, in one
 * place, so that the direction of the dependency is a fact you can check
 * rather than a convention.
 *
 * Two rules hold here:
 *
 *   - infrastructure calls *up* only through this header. If a seeded .c file
 *     grows a call to something that is not declared here, the layering has
 *     been broken and the compiler says so.
 *   - nothing declared here may name a protocol (rule 4). What the transport
 *     *is* stays behind these names.
 *
 * This is where mTCP's ip_in.c `case IPPROTO_TCP: return ProcessTCPPacket(...)`
 * goes. In the donor that line is what makes the IP layer a TCP stack; here it
 * is a comparison against a number the program supplies and a call the target
 * implements.
 */
#include <stdint.h>
#include <netinet/ip.h>

struct core_ctx;

/*
 * The IP protocol number the transport answers to. Defined by src/program/ —
 * it is the one piece of packet identity the IP layer cannot avoid knowing,
 * and this is how it learns it without naming it.
 *
 * A link-time constant rather than a call because ip_in.c consults it once per
 * received packet, and the donor has a compile-time constant there. A `const`
 * load keeps that path the same shape; a function call would not.
 */
extern const uint8_t TRANSPORT_IP_PROTO;

/*
 * A packet whose IP protocol matched. `iph` points at the IP header inside the
 * NIC's receive buffer and stays valid until the target returns.
 * Returns TRUE/FALSE/ERROR, as everything else on mTCP's receive path does.
 * Implemented by src/target/.
 */
int TransportInput(struct core_ctx *core, uint32_t cur_ts, const int ifidx,
		   struct iphdr *iph, int ip_len);

/*
 * How many bytes of per-flow state the transport wants the EAL to reserve
 * hugepage memory for. Defined by src/target/.
 *
 * mTCP writes `sizeof(struct tcp_stream) + sizeof(struct tcp_recv_vars) +
 * sizeof(struct tcp_send_vars) + sizeof(struct fragment_ctx)` inline in
 * io_module.c — the transport's own structs, named, in the I/O layer. Worth
 * knowing before anyone reads much into this number: the donor computes it and
 * then does not use it, because the `--socket-mem` argument it feeds is inside
 * an `#if 0`. Carried in the same shape anyway, so that turning that `#if 0`
 * back on gives the donor's reservation and not a different one.
 */
extern const uint32_t TRANSPORT_PER_FLOW_BYTES;

/*
 * A configuration key config.c did not recognise. The program owns its own
 * parameters — timeouts above all — and DESIGN.md §7.2 requires them read from
 * configuration rather than compiled in. Return TRUE if the key was consumed.
 * Implemented by src/program/.
 */
int ProgConfigKey(const char *key, const char *value);

#endif /* UPCALL_H */
