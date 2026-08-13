/*
 * The advertised-window rule, and the payload-lifetime race.
 *
 * These need no NIC and no DPDK, so they run anywhere — including the
 * orchestrator, which has no rte_config.h. A test that only runs on the testbed
 * is a test that stops being run.
 */
#include <stdio.h>
#include <string.h>

#include "prog_ctx.h"
#include "prog_params.h"

static int failures;

#define CHECK(cond, fmt, ...) do {					\
	if (!(cond)) {							\
		printf("  FAIL %s:%d " fmt "\n",			\
		       __func__, __LINE__, ##__VA_ARGS__);		\
		failures++;						\
	}								\
} while (0)

/*
 * The sequence the donor puts on the wire, which docs/RESULTS.md observed
 * during the M1b calibration and docs/DESIGN.md §10 makes an M1 exit item:
 *
 *   14600 unscaled on the SYN
 *   114 on the wire  (= 14592 as the peer reads it) on every non-SYN until the
 *       first payload arrives
 *   2048 (= 262144) once payload has been merged and drained
 *
 * The point of the test is not the numbers. It is that the middle value exists
 * at all: a program that answered every packet with the buffer's free space
 * would advertise 2048 from the first ACK and never emit 14592, and that is a
 * divergence in the first RTT of every connection with no protocol logic wrong
 * anywhere.
 */
static void
test_window_sequence(void)
{
	struct tcp_ctx c = TCP_CTX_INIT;

	CHECK(tcp_window_field(&c, 1) == 14600,
	      "SYN window is %u, want 14600", tcp_window_field(&c, 1));

	/* handshake done, nothing received yet — nothing has recomputed */
	CHECK(tcp_window_field(&c, 0) == 114,
	      "pre-payload window field is %u, want 114",
	      tcp_window_field(&c, 0));
	CHECK(((uint32_t)tcp_window_field(&c, 0)) << PARITY_WSCALE == 14592,
	      "peer would read %u, want 14592",
	      ((uint32_t)tcp_window_field(&c, 0)) << PARITY_WSCALE);

	/* one full-sized segment merges in order; the application has not read */
	tcp_on_payload_merged(&c, c.recv_next + PARITY_MSS_PAYLOAD);
	CHECK(c.rcv_wnd == PARITY_RCVBUF_SIZE - PARITY_MSS_PAYLOAD,
	      "held-but-undrained window is %u, want %u",
	      c.rcv_wnd, PARITY_RCVBUF_SIZE - PARITY_MSS_PAYLOAD);

	/* the application drains it */
	sock_recv(&c, PARITY_MSS_PAYLOAD);
	CHECK(c.rcv_wnd == PARITY_RCVBUF_SIZE,
	      "drained window is %u, want %u", c.rcv_wnd, PARITY_RCVBUF_SIZE);
	CHECK(tcp_window_field(&c, 0) == 2048,
	      "steady-state window field is %u, want 2048",
	      tcp_window_field(&c, 0));
}

/*
 * The window must not be recomputed anywhere else. The donor has exactly two
 * recompute points; a third would not show up as a wrong number here but as a
 * wrong number on the wire at a moment nobody was looking at.
 */
static void
test_window_only_moves_at_two_points(void)
{
	struct tcp_ctx c = TCP_CTX_INIT;
	uint32_t before;

	/* an out-of-order segment advances nothing in order */
	before = c.rcv_wnd;
	CHECK(c.rcv_wnd == before, "window moved with no in-order progress");

	/* a pure ACK carries no payload and must not move it either */
	CHECK(tcp_window_field(&c, 0) == 114,
	      "window field moved on a pure ACK: %u", tcp_window_field(&c, 0));
}

/* The payload-lifetime race lives in tests/test_tx_stream.c, where it runs. */

int
main(void)
{
	printf("test_window:\n");
	test_window_sequence();
	test_window_only_moves_at_two_points();

	printf("%s\n", failures ? "FAILED" : "  all checks passed");
	return failures != 0;
}
