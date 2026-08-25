/*
 * Out-of-order reassembly, in the receive stream.
 *
 * The property under test is that a hole is invisible everywhere except the
 * boundary: bytes past a gap are STORED and are NOT readable, and when the gap
 * fills, one call makes all of it readable at once, in order, and every byte
 * carrying the value its sequence number says it should.
 *
 * Byte-exactness is the point. A boundary that moves correctly while the bytes
 * land at the wrong ring offset passes every sequence-number check and
 * delivers garbage -- and on a clean LAN this path never runs, so the first
 * thing that would notice is a content check on a lossy link. That is the
 * failure this file exists to make impossible.
 *
 * No NIC, no DPDK: runs on the orchestrator.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contract.h"
#include "internal.h"

static int failures;

#define CHECK(cond, fmt, ...) do {					\
	if (!(cond)) {							\
		printf("  FAIL %s:%d " fmt "\n",			\
		       __func__, __LINE__, ##__VA_ARGS__);		\
		failures++;						\
	}								\
} while (0)

#define CAP  4096
#define BASE 1000

/* A byte's value is a function of its sequence number, so a misplaced copy
 * shows up as a wrong value rather than as a length that still adds up. */
static uint8_t
byte_at(uint64_t seq)
{
	return (uint8_t)(seq * 31u + 7u);
}

static void
fill(uint8_t *buf, uint64_t seq, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		buf[i] = byte_at(seq + i);
}

static int
put(struct mtp_data_unit *u, uint64_t seq, uint32_t len)
{
	uint8_t tmp[2048];
	struct mtp_rx_addr a;

	fill(tmp, seq, len);
	a.data = tmp;
	a.len = len;
	return mtp_add_rx_data_seg(u, a, len, seq);
}

/* Read everything readable and verify each byte against its sequence number. */
static uint32_t
drain_and_verify(struct mtp_data_unit *u, uint64_t from)
{
	uint8_t out[CAP];
	uint32_t got, i;

	memset(out, 0, sizeof(out));
	got = (uint32_t)mtp_rx_flush_and_notify(u, CAP,
			(struct mtp_rx_addr){ .data = out, .len = CAP });
	for (i = 0; i < got; i++)
		if (out[i] != byte_at(from + i)) {
			CHECK(0, "byte %u of the drain is %02x, expected %02x "
			      "(sequence %llu)", i, out[i], byte_at(from + i),
			      (unsigned long long)(from + i));
			break;
		}
	return got;
}

static void
setup(struct mtp_data_unit *u)
{
	memset(u, 0, sizeof(*u));
	if (tgt_rx_unit_init(u, MTP_SIZE_INF, CAP, BASE) < 0) {
		printf("  FAIL could not allocate the unit\n");
		exit(1);
	}
}

/* In order, unchanged from before reassembly existed. */
static void
test_in_order(void)
{
	struct mtp_data_unit u;

	setup(&u);
	CHECK(put(&u, BASE, 100) == 100, "store refused");
	CHECK(put(&u, BASE + 100, 100) == 100, "store refused");
	CHECK(drain_and_verify(&u, BASE) == 200, "drained the wrong length");
	tgt_rx_unit_fini(&u);
}

/*
 * A segment past the boundary is STORED AND NOT READABLE. Before this change
 * it was refused outright and the peer had to retransmit everything after the
 * hole.
 */
static void
test_hole_holds_data_back(void)
{
	struct mtp_data_unit u;
	uint32_t got;

	setup(&u);
	CHECK(put(&u, BASE, 100) == 100, "store refused");
	/* BASE+100 .. BASE+200 is lost */
	CHECK(put(&u, BASE + 200, 100) == 100,
	      "a segment past the boundary was refused");
	CHECK(put(&u, BASE + 300, 100) == 100,
	      "a segment past the boundary was refused");

	got = drain_and_verify(&u, BASE);
	CHECK(got == 100, "drained %u bytes, expected 100 -- data past the hole "
	      "must not be readable", got);

	/* the retransmission fills the gap: everything behind it arrives at once */
	CHECK(put(&u, BASE + 100, 100) == 100, "the gap-filling store was refused");
	got = drain_and_verify(&u, BASE + 100);
	CHECK(got == 300, "drained %u bytes after the gap filled, expected 300",
	      got);
	tgt_rx_unit_fini(&u);
}

/* Arriving strictly backwards: nothing is readable until the first segment. */
static void
test_reverse_order(void)
{
	struct mtp_data_unit u;
	int i;

	setup(&u);
	for (i = 9; i >= 1; i--)
		CHECK(put(&u, BASE + i * 100, 100) == 100, "store %d refused", i);
	CHECK(drain_and_verify(&u, BASE) == 0,
	      "something was readable with the first segment still missing");
	CHECK(put(&u, BASE, 100) == 100, "store refused");
	CHECK(drain_and_verify(&u, BASE) == 1000,
	      "the whole run did not become readable at once");
	tgt_rx_unit_fini(&u);
}

/*
 * A retransmission of data already delivered. It must not be an error, must
 * not move the boundary backwards, and must not corrupt what is held: an
 * acknowledgement lost on the way back produces exactly this.
 */
static void
test_duplicate_after_delivery(void)
{
	struct mtp_data_unit u;

	setup(&u);
	CHECK(put(&u, BASE, 200) == 200, "store refused");
	CHECK(drain_and_verify(&u, BASE) == 200, "drained the wrong length");

	CHECK(put(&u, BASE, 200) == 0,
	      "a wholly-delivered retransmission should store nothing");
	CHECK(drain_and_verify(&u, BASE + 200) == 0,
	      "a duplicate made bytes readable twice");

	/* half old, half new: the new half must land and be readable */
	CHECK(put(&u, BASE + 100, 200) == 100,
	      "the fresh half of an overlapping retransmission was not stored");
	CHECK(drain_and_verify(&u, BASE + 200) == 100,
	      "the fresh half did not become readable");
	tgt_rx_unit_fini(&u);
}

/* Overlapping segments, arriving out of order. The union is what is held. */
static void
test_overlap_out_of_order(void)
{
	struct mtp_data_unit u;

	setup(&u);
	CHECK(put(&u, BASE + 300, 200) == 200, "store refused");	/* 300..500 */
	CHECK(put(&u, BASE + 400, 200) == 200, "store refused");	/* 400..600 */
	CHECK(drain_and_verify(&u, BASE) == 0, "readable past a hole");
	CHECK(put(&u, BASE, 300) == 300, "store refused");		/* 0..300 */
	CHECK(drain_and_verify(&u, BASE) == 600,
	      "the union of the overlapping runs was not readable");
	tgt_rx_unit_fini(&u);
}

/* A segment that would overrun the ring is refused, and refusing leaves the
 * unit usable. */
static void
test_overrun_refused(void)
{
	struct mtp_data_unit u;

	setup(&u);
	CHECK(put(&u, BASE + CAP, 100) == -1,
	      "a segment past the ring's capacity was accepted");
	CHECK(put(&u, BASE, 100) == 100, "the unit was unusable after a refusal");
	CHECK(drain_and_verify(&u, BASE) == 100, "drained the wrong length");
	tgt_rx_unit_fini(&u);
}

/* The ring wraps under a hole: the arithmetic that places a byte is the part
 * most likely to be wrong, and only a content check finds it. */
static void
test_wrap_with_hole(void)
{
	struct mtp_data_unit u;
	uint64_t seq = BASE;
	int i;

	setup(&u);
	/* push the boundary most of the way round the ring */
	for (i = 0; i < 3; i++) {
		CHECK(put(&u, seq, 1000) == 1000, "store refused");
		CHECK(drain_and_verify(&u, seq) == 1000, "drained the wrong length");
		seq += 1000;
	}
	/* now leave a hole across the wrap point */
	CHECK(put(&u, seq + 500, 500) == 500, "store past the boundary refused");
	CHECK(drain_and_verify(&u, seq) == 0, "readable past a hole");
	CHECK(put(&u, seq, 500) == 500, "the gap-filling store was refused");
	CHECK(drain_and_verify(&u, seq) == 1000,
	      "the run across the wrap was not readable in one piece");
	tgt_rx_unit_fini(&u);
}

int
main(void)
{
	printf("test_rx_reasm:\n");
	test_in_order();
	test_hole_holds_data_back();
	test_reverse_order();
	test_duplicate_after_delivery();
	test_overlap_out_of_order();
	test_overrun_refused();
	test_wrap_with_hole();
	if (failures) {
		printf("  %d FAILURES\n", failures);
		return 1;
	}
	printf("  all checks passed\n");
	return 0;
}
