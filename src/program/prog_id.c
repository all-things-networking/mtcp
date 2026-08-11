/*
 * The two things the infrastructure needs from the program: which IP protocol
 * number the transport answers to, and what to do with a configuration key the
 * infrastructure did not recognise.
 *
 * Both would be compiler output. Both are here rather than in src/target/ for
 * the same reason: they are the only two places below the transport where
 * protocol identity would otherwise have to be written down, and rule 4 says it
 * may only be written down in src/program/.
 *
 * Increment 1 has no processors, so this is the whole program.
 */
#include <string.h>
#include <stdlib.h>

#include "upcall.h"
#include "prog_params.h"

/* 6 — the protocol whose parity this effort is measured against. Named as a
 * number, not as a symbol, because ip_in.c compares against it and ip_in.c is
 * infrastructure. */
const uint8_t TRANSPORT_IP_PROTO = 6;

/*
 * Protocol timers whose durations come from configuration rather than from a
 * constant (docs/DESIGN.md §7.2, difference report D6). The donor keeps these
 * two keys in its own config struct; here the parser hands them up, because a
 * timeout for a connection is not a property of the machine.
 *
 * Values are unused until the processors exist. They are parsed now so that the
 * configuration file the donor is measured with is the configuration file this
 * target is measured with — an unknown key must not be silently ignored.
 */
int prog_flow_timewait_ms = -1;
int prog_flow_timeout_ms = -1;

int
ProgConfigKey(const char *key, const char *value)
{
	if (strcmp(key, "tcp_timewait") == 0) {
		prog_flow_timewait_ms = atoi(value);
		return 1;
	}
	if (strcmp(key, "tcp_timeout") == 0) {
		prog_flow_timeout_ms = atoi(value);
		return 1;
	}
	return 0;
}
