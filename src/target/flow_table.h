#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H
/*
 * The context store: the flow table, and the listener table beside it.
 *
 * CR-3 says this is compiler-generated typed code per program, and it will be.
 * Until the compiler exists this is the generic REFERENCE realisation the
 * codegen is modelled on — the same arrangement the kernel effort uses, where
 * `mtp_ctx_store.c` is retained as the reference and drives the selftests. The
 * generated form replaces the byte-wise hash and compare with typed ones over
 * the program's own key struct; nothing above it changes.
 *
 * CR-5 IS THE PART THAT CONSTRAINS THIS FILE. `flow_id <name> : (types…)`
 * declares a SHAPE. So:
 *
 *   - the table is written against `flowkey_t`, which the program defines;
 *   - the target does not name a field of it, does not assume a width, and
 *     does not know how many fields there are. It hashes and compares
 *     sizeof(flowkey_t) BYTES;
 *   - which is why the program's key struct is packed — padding would make two
 *     equal keys differ, and the target has no way to know it should skip it.
 *
 * DIRECTION CANONICALISATION IS NOT HERE, and that is the point the design had
 * no answer for. An inbound packet's (src, dst) and an outbound app op's
 * (local, remote) must resolve the SAME context, and only the program knows
 * which of its event's fields is which. So the parser builds the key already
 * canonical and this file never reorders anything. A target that swapped the
 * halves would be making a protocol decision.
 */
#include <stdint.h>
#include <stddef.h>

#include "contract.h"

/*
 * Shape from mTCP fhash.c @7fbb223c — the chained bucket array, the bucket
 * count, and the walk. Written rather than seeded because the donor's version
 * reaches into `tcp_stream`'s link fields and keys on a hard-coded four-tuple,
 * which is exactly the two things CR-5 and CR-3 take out. docs/DESIGN.md §1.3
 * put it in src/infra/; that was wrong — the flow table is above the transport
 * boundary, and §1.1 of the same document says so.
 */
#define FLOW_TABLE_BINS		131072	/* mTCP's NUM_BINS_FLOWS */
#define LISTENER_TABLE_BINS	1024	/* mTCP's NUM_BINS_LISTENERS */

struct flow_table;
struct listener_table;

struct flow_table *FlowTableCreate(void);
void               FlowTableDestroy(struct flow_table *t);

/*
 * The context store, as contract.h declares it. `ctx_size` comes from the
 * program; the target allocates it zeroed (G12 — the prototype's unzeroed
 * context is the likeliest source of run-to-run nondeterminism) and returns it
 * for generated code to fill.
 */
void *FlowTableInsert(struct flow_table *t, const flowkey_t *key, size_t ctx_size);
void *FlowTableLookup(struct flow_table *t, const flowkey_t *key);
int   FlowTableRemove(struct flow_table *t, const flowkey_t *key);

/*
 * The listener table, keyed on (ip, port) rather than port alone.
 *
 * G8: mTCP matches a listener on port only, so a socket bound to one address
 * answers for every address on the host. Matching on both is the fix, and a
 * miss is a miss — never a null context handed onward, which is how the
 * prototype turns a missed lookup into a crash.
 */
struct listener_table *ListenerTableCreate(void);
void  ListenerTableDestroy(struct listener_table *t);
int   ListenerTableInsert(struct listener_table *t, uint32_t ip, uint16_t port,
			  void *listener);
void *ListenerTableLookup(struct listener_table *t, uint32_t ip, uint16_t port);
int   ListenerTableRemove(struct listener_table *t, uint32_t ip, uint16_t port);

#endif /* FLOW_TABLE_H */
