/*
 * The context store and the listener table. See fhash.h for why this is
 * written against a key SHAPE the program supplies rather than a four-tuple,
 * and for why direction canonicalisation is not here.
 */
#include <stdlib.h>
#include <string.h>

#include "fhash.h"
/* Deliberately no debug.h: it drags in infra.h and therefore DPDK, and this
 * file is one of the few in the target that can be tested off the testbed.
 * Keeping it that way is worth more than TRACE_ macros in a hash table. */

/*
 * A chained bucket, holding the program's context inline after the key. One
 * allocation per flow, so a lookup that hits touches the entry and the context
 * in the same cache line run — mTCP allocates the stream and its send/recv
 * variable blocks separately from three pools and chases two pointers.
 */
struct entry {
	struct entry	*next;
	flowkey_t	 key;
	/* the program's context follows, aligned; ctx_size bytes, zeroed */
};

struct flow_table {
	struct entry	**bin;
	uint32_t	  bins;
	uint32_t	  count;
};

/* The context begins at the next pointer-aligned byte after the entry header. */
static inline void *entry_ctx(struct entry *e)
{
	return (void *)((char *)e + ((sizeof(struct entry) + 15u) & ~15u));
}

/*
 * Hash and compare over the key's BYTES. The program declared a shape; the
 * target neither knows nor needs to know what the bytes mean. When the compiler
 * emits this it emits a typed hash over the actual fields, which is faster and
 * changes nothing above.
 *
 * FNV-1a rather than mTCP's four-word fold, because that fold is written
 * against a four-tuple laid out exactly as mTCP lays one out, and a key of any
 * other shape would collide in patterns nobody chose. Byte-at-a-time over a
 * 12-byte key is ~12 multiply-xors; the donor's is 4 xors and a shift. That is
 * a real cost on the receive path and it is a HYPOTHESIS that it does not show;
 * the generated typed hash removes it, so it is a cost of not having the
 * compiler yet rather than a cost of the design.
 */
static inline uint32_t key_hash(const flowkey_t *k)
{
#ifdef PROG_TYPES_H
	/* The compiler emits one over the slots the program DECLARED, which is
	 * what the paragraph above says should replace this. */
	return prog_key_hash(k);
#else
	const uint8_t *p = (const uint8_t *)k;
	uint32_t h = 2166136261u;
	size_t i;

	for (i = 0; i < sizeof(*k); i++) {
		h ^= p[i];
		h *= 16777619u;
	}
	return h;
#endif
}

static inline int key_equal(const flowkey_t *a, const flowkey_t *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

/*----------------------------------------------------------------------------*/
struct flow_table *
FlowTableCreate(void)
{
	struct flow_table *t = calloc(1, sizeof(*t));

	if (!t)
		return NULL;
	t->bins = FLOW_TABLE_BINS;
	t->bin = calloc(t->bins, sizeof(*t->bin));
	if (!t->bin) {
		free(t);
		return NULL;
	}
	return t;
}

void
FlowTableDestroy(struct flow_table *t)
{
	uint32_t i;

	if (!t)
		return;
	for (i = 0; i < t->bins; i++) {
		struct entry *e = t->bin[i];

		while (e) {
			struct entry *next = e->next;

			free(e);
			e = next;
		}
	}
	free(t->bin);
	free(t);
}

void *
FlowTableInsert(struct flow_table *t, const flowkey_t *key, size_t ctx_size)
{
	uint32_t b = key_hash(key) & (t->bins - 1);
	size_t hdr = (sizeof(struct entry) + 15u) & ~15u;
	struct entry *e;

	/* zeroed, not merely allocated: G12. An uninitialised per-flow context
	 * is the likeliest source of run-to-run nondeterminism in the prototype
	 * and it costs nothing to close here. */
	e = calloc(1, hdr + ctx_size);
	if (!e)
		return NULL;

	e->key = *key;
	e->next = t->bin[b];
	t->bin[b] = e;
	t->count++;

	return entry_ctx(e);
}

void *
FlowTableLookup(struct flow_table *t, const flowkey_t *key)
{
	uint32_t b = key_hash(key) & (t->bins - 1);
	struct entry *e;

	for (e = t->bin[b]; e; e = e->next)
		if (key_equal(&e->key, key))
			return entry_ctx(e);

	return NULL;
}

int
FlowTableRemove(struct flow_table *t, const flowkey_t *key)
{
	uint32_t b = key_hash(key) & (t->bins - 1);
	struct entry **pp;

	for (pp = &t->bin[b]; *pp; pp = &(*pp)->next) {
		if (key_equal(&(*pp)->key, key)) {
			struct entry *e = *pp;

			*pp = e->next;
			free(e);
			t->count--;
			return 0;
		}
	}
	return -1;
}

/*----------------------------------------------------------------------------*/
/*
 * The listener table. Keyed on (ip, port) — G8. mTCP keys on port alone, so a
 * socket bound to one address answers for every address on the host.
 */
struct listener_entry {
	struct listener_entry	*next;
	uint32_t		 ip;
	uint16_t		 port;
	void			*listener;
};

struct listener_table {
	struct listener_entry	**bin;
	uint32_t		  bins;
};

static inline uint32_t listener_hash(uint32_t ip, uint16_t port)
{
	return (ip * 2654435761u) ^ (uint32_t)port * 40503u;
}

struct listener_table *
ListenerTableCreate(void)
{
	struct listener_table *t = calloc(1, sizeof(*t));

	if (!t)
		return NULL;
	t->bins = LISTENER_TABLE_BINS;
	t->bin = calloc(t->bins, sizeof(*t->bin));
	if (!t->bin) {
		free(t);
		return NULL;
	}
	return t;
}

void
ListenerTableDestroy(struct listener_table *t)
{
	uint32_t i;

	if (!t)
		return;
	for (i = 0; i < t->bins; i++) {
		struct listener_entry *e = t->bin[i];

		while (e) {
			struct listener_entry *next = e->next;

			free(e);
			e = next;
		}
	}
	free(t->bin);
	free(t);
}

int
ListenerTableInsert(struct listener_table *t, uint32_t ip, uint16_t port,
		    void *listener)
{
	uint32_t b = listener_hash(ip, port) & (t->bins - 1);
	struct listener_entry *e = calloc(1, sizeof(*e));

	if (!e)
		return -1;
	e->ip = ip;
	e->port = port;
	e->listener = listener;
	e->next = t->bin[b];
	t->bin[b] = e;
	return 0;
}

void *
ListenerTableLookup(struct listener_table *t, uint32_t ip, uint16_t port)
{
	uint32_t b = listener_hash(ip, port) & (t->bins - 1);
	struct listener_entry *e;

	for (e = t->bin[b]; e; e = e->next)
		if (e->port == port && e->ip == ip)
			return e->listener;

	/* A miss is a miss. mTCP's port-only match would find a listener here
	 * for an address it was never bound to; returning NULL and letting the
	 * caller decide is the fix, and the caller must never treat NULL as a
	 * context (G8, and the prototype's HandleMissingCtx crash). */
	return NULL;
}

int
ListenerTableRemove(struct listener_table *t, uint32_t ip, uint16_t port)
{
	uint32_t b = listener_hash(ip, port) & (t->bins - 1);
	struct listener_entry **pp;

	for (pp = &t->bin[b]; *pp; pp = &(*pp)->next) {
		if ((*pp)->port == port && (*pp)->ip == ip) {
			struct listener_entry *e = *pp;

			*pp = e->next;
			free(e);
			return 0;
		}
	}
	return -1;
}
