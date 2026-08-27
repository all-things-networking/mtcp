/*
 * The context store. Needs no NIC and no DPDK.
 *
 * What is worth testing here is not that a hash table works. It is the two
 * things CR-5 constrains and the one thing G8 fixes: that the table works on a
 * key SHAPE it does not understand, that equal keys are equal as bytes, and
 * that a listener bound to one address does not answer for another.
 */
#include <stdio.h>
#include <string.h>

#include "fhash.h"
#include "prog_ctx.h"

static int failures;

#define CHECK(cond, fmt, ...) do {					\
	if (!(cond)) {							\
		printf("  FAIL %s:%d " fmt "\n",			\
		       __func__, __LINE__, ##__VA_ARGS__);		\
		failures++;						\
	}								\
} while (0)

static flowkey_t k(uint32_t a, uint32_t b, uint16_t c, uint16_t d)
{
	flowkey_t key;

	/* zero the whole thing first: the target compares BYTES, so anything
	 * the caller leaves unset is part of the key. The program's key struct
	 * is packed so there is no padding to worry about, and this test would
	 * fail loudly if that stopped being true. */
	memset(&key, 0, sizeof(key));
	key.v0 = a; key.v1 = b; key.v2 = c; key.v3 = d;
	return key;
}

static void
test_insert_lookup_remove(void)
{
	struct flow_table *t = FlowTableCreate();
	flowkey_t a = k(1, 2, 3, 4), b = k(1, 2, 3, 5);
	struct tcp_ctx *ca, *cb;

	CHECK(t != NULL, "table creation failed");
	CHECK(FlowTableLookup(t, &a) == NULL, "empty table returned a context");

	ca = FlowTableInsert(t, &a, sizeof(struct tcp_ctx));
	CHECK(ca != NULL, "insert returned NULL");

	/* G12: the program's context is handed over ZEROED */
	CHECK(ca->recv_next == 0 && ca->delivered == 0 && ca->rcv_wnd == 0,
	      "context was not zeroed on insert");

	ca->recv_next = 0xdeadbeef;
	CHECK(FlowTableLookup(t, &a) == ca, "lookup did not find what was inserted");
	CHECK(((struct tcp_ctx *)FlowTableLookup(t, &a))->recv_next == 0xdeadbeef,
	      "context contents did not survive the round trip");

	/* one field different is a different flow */
	CHECK(FlowTableLookup(t, &b) == NULL, "a near-miss key matched");
	cb = FlowTableInsert(t, &b, sizeof(struct tcp_ctx));
	CHECK(cb != ca, "two distinct keys returned the same context");

	CHECK(FlowTableRemove(t, &a) == 0, "remove of a present key failed");
	CHECK(FlowTableLookup(t, &a) == NULL, "lookup found a removed key");
	CHECK(FlowTableLookup(t, &b) == cb, "removing one key disturbed another");
	CHECK(FlowTableRemove(t, &a) != 0, "remove of an absent key succeeded");

	FlowTableDestroy(t);
}

/*
 * The target hashes and compares the key's bytes and knows nothing else about
 * it. Two keys built the same way must match; the shape is the program's.
 */
static void
test_key_is_bytes(void)
{
	struct flow_table *t = FlowTableCreate();
	flowkey_t a = k(0x0a070009, 0x0a07000c, 1234, 80);
	flowkey_t same = k(0x0a070009, 0x0a07000c, 1234, 80);
	void *c;

	/*
	 * PACKED, not a fixed width. The number was 12 while the program
	 * declared one flow id; a second one adds the discriminator byte that
	 * keeps the two shapes from colliding, so hard-coding the total made
	 * this test fail on a correct change. What the target actually needs is
	 * that there is no PADDING -- it hashes and compares the bytes, and a
	 * padding hole would make two equal keys differ.
	 */
	CHECK(sizeof(flowkey_t) == sizeof(a.kind) + sizeof(a.v0) + sizeof(a.v1)
				 + sizeof(a.v2) + sizeof(a.v3),
	      "key is %zu bytes, more than its fields: it has padding, and two "
	      "equal keys would differ", sizeof(flowkey_t));

	c = FlowTableInsert(t, &a, sizeof(struct tcp_ctx));
	CHECK(FlowTableLookup(t, &same) == c,
	      "an identically-built key did not match");

	FlowTableDestroy(t);
}

/*
 * G8. mTCP matches a listener on port alone, so a socket bound to one address
 * answers for every address on the host.
 */
static void
test_listener_matches_ip_and_port(void)
{
	struct listener_table *t = ListenerTableCreate();
	int marker_a = 1, marker_b = 2;

	ListenerTableInsert(t, 0x0a07000c, 80, &marker_a);

	CHECK(ListenerTableLookup(t, 0x0a07000c, 80) == &marker_a,
	      "bound listener not found");
	CHECK(ListenerTableLookup(t, 0x0a070009, 80) == NULL,
	      "listener answered for an address it was not bound to (G8)");
	CHECK(ListenerTableLookup(t, 0x0a07000c, 81) == NULL,
	      "listener answered for the wrong port");

	ListenerTableInsert(t, 0x0a070009, 80, &marker_b);
	CHECK(ListenerTableLookup(t, 0x0a07000c, 80) == &marker_a,
	      "second bind on the same port disturbed the first");
	CHECK(ListenerTableLookup(t, 0x0a070009, 80) == &marker_b,
	      "second bind on the same port not found");

	ListenerTableDestroy(t);
}

int
main(void)
{
	printf("test_flow_table:\n");
	test_insert_lookup_remove();
	test_key_is_bytes();
	test_listener_matches_ip_and_port();

	printf("%s\n", failures ? "FAILED" : "  all checks passed");
	return failures != 0;
}
