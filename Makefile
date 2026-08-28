# MTP-DPDK — the whole build, in one committed file.
#
# No autotools. The donor generates mtcp/src/Makefile from a template and then
# tracks the result, so `./configure` leaves a reference branch dirty and a
# build no longer corresponds to a clean checkout of the pinned commit
# (docs/DPDK_HANDOFF.md §4). Nothing here is generated: this file is source,
# `build/` and `bin/` are ignored, and a fresh clone builds with `make`.
#
# The compiler flags are the donor's, deliberately, because docs/DECISIONS.md
# D-02 pins both sides of the comparison to -O0 -DDEBUG and a difference in
# optimisation would sit under every number this effort ever takes. The one
# change is that the DPDK include and link flags come from pkg-config instead
# of being written out, so moving to another testbed is a config change rather
# than an edit.

CC      = gcc

DPDK_CFLAGS := $(shell pkg-config --cflags libdpdk 2>/dev/null)
DPDK_LIBS   := $(shell pkg-config --libs libdpdk 2>/dev/null)
# Only the library and the apps need DPDK. `make test` and `make check`
# deliberately do not, so the gates run on the orchestrator too.
NEEDS_DPDK := $(filter-out test check clean,$(or $(MAKECMDGOALS),all))
ifneq ($(NEEDS_DPDK),)
ifeq ($(DPDK_CFLAGS),)
$(error pkg-config could not find libdpdk. Build on a node with the DPDK \
environment — docs/DPDK_HANDOFF.md §4 — not on the orchestrator)
endif
endif

# from mTCP mtcp/src/Makefile:44-54 @7fbb223c, unchanged. -O0 comes after the
# DPDK flags' -O2 for the same reason it does in the donor: the last one wins.
OPT     = -m64 -Wall -fPIC -fgnu89-inline -Werror
OPT    += -g -O0 -DNETSTAT -DINFO -DDBGERR -DDBGCERR -DDEBUG
OPT    += -D__USRLIB__

# mTCP's Makefile switches these off when the module is not built. This tree
# has one I/O module, so they are unconditional.
OPT    += -DDISABLE_PSIO -DDISABLE_NETMAP

INC     = -Isrc/infra -Isrc/target -Isrc/program
CFLAGS  = $(DPDK_CFLAGS) $(OPT) $(INC)
LIBS    = $(DPDK_LIBS) -lnuma -lpthread -lrt -ldl -lgmp -lm

INFRA_SRCS   := $(wildcard src/infra/*.c)
TARGET_SRCS  := $(wildcard src/target/*.c)
PROGRAM_SRCS := $(wildcard src/program/*.c)
LIB_SRCS     := $(INFRA_SRCS) $(TARGET_SRCS) $(PROGRAM_SRCS)
LIB_OBJS     := $(patsubst %.c,build/%.o,$(LIB_SRCS))

# --start-group around the archive: the target calls generated program symbols
# and the program calls target instructions, so the two reference each other and
# a single pass over the archive misses the second direction. The mutual
# reference is the boundary working as intended, not a layering problem.
LIB  = build/libmtp.a
APPS = bin/upcheck bin/tcpserver

.PHONY: all clean check test
all: $(APPS)

$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	ar rcs $@ $^

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

bin/upcheck: apps/upcheck/upcheck.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -o $@ -Wl,--start-group $(LIB) -Wl,--end-group $(LIBS)

# THE DONOR'S epserver, UNMODIFIED, ON OUR TARGET.
#
# The whole point of the shim: with the same application on both sides, the
# application stops being a variable and only the stack differs. The reference
# source is compiled from its own tree and never edited -- if it stops
# compiling, that is a finding about the shim, not a licence to patch it.
#
# Its own headers are included rather than redeclared, so struct layouts are
# identical by construction rather than by care. The util objects are the
# reference's application-side helpers (HTTP parsing, date parsing), not stack
# code. -w because the reference's warnings are the reference's.
DONOR    := /home/mtahmasb/MTP-pass/MTP-DPDK-donor
DONOR_INC := -I$(DONOR)/mtcp/include -I$(DONOR)/util/include

bin/epserver-shim: apps/compat/mtcp_shim.c $(DONOR)/apps/example/epserver.c $(LIB)
	@mkdir -p $(dir $@) build/compat
	@# The reference is compiled with ITS include path FIRST, so it gets its
	@# own debug.h and not ours -- ours defines TRACE_* in terms of a `core`
	@# the reference does not have. Separate objects, one link.
	$(CC) $(DONOR_INC) -I/usr/local/include -include rte_config.h \
	    -march=native -m64 -w -c $(DONOR)/apps/example/epserver.c \
	    -o build/compat/epserver.o
	$(CC) $(DONOR_INC) -w -c $(DONOR)/util/http_parsing.c -o build/compat/http_parsing.o
	$(CC) $(DONOR_INC) -w -c $(DONOR)/util/netlib.c       -o build/compat/netlib.o
	$(CC) $(DONOR_INC) -w -c $(DONOR)/util/tdate_parse.c  -o build/compat/tdate_parse.o
	@# the shim gets OUR headers first, plus the reference's declarations
	$(CC) $(CFLAGS) $(DONOR_INC) -w -c apps/compat/mtcp_shim.c \
	    -o build/compat/mtcp_shim.o
	$(CC) build/compat/epserver.o build/compat/mtcp_shim.o \
	    build/compat/http_parsing.o build/compat/netlib.o \
	    build/compat/tdate_parse.o -o $@ \
	    -Wl,--start-group $(LIB) -Wl,--end-group $(LIBS)

# THE DONOR'S epwget, UNMODIFIED, ON OUR TARGET -- the client side of the same
# argument bin/epserver-shim makes on the server side. docs/TEST-MATRIX.md
# comparisons 2 and 3 need the load generator to be identical and only the stack
# underneath to change; compiling the reference's own source is how that is
# guaranteed rather than asserted.
bin/epwget-shim: apps/compat/mtcp_shim.c $(DONOR)/apps/example/epwget.c $(LIB)
	@mkdir -p $(dir $@) build/compat
	$(CC) $(DONOR_INC) -I/usr/local/include -include rte_config.h \
	    -march=native -m64 -w -c $(DONOR)/apps/example/epwget.c \
	    -o build/compat/epwget.o
	$(CC) $(DONOR_INC) -w -c $(DONOR)/util/http_parsing.c -o build/compat/http_parsing.o
	$(CC) $(DONOR_INC) -w -c $(DONOR)/util/netlib.c       -o build/compat/netlib.o
	$(CC) $(DONOR_INC) -w -c $(DONOR)/util/tdate_parse.c  -o build/compat/tdate_parse.o
	$(CC) $(CFLAGS) $(DONOR_INC) -w -c apps/compat/mtcp_shim.c \
	    -o build/compat/mtcp_shim.o
	$(CC) build/compat/epwget.o build/compat/mtcp_shim.o \
	    build/compat/http_parsing.o build/compat/netlib.o \
	    build/compat/tdate_parse.o -o $@ \
	    -Wl,--start-group $(LIB) -Wl,--end-group $(LIBS)

bin/tcpserver: apps/tcpserver/tcpserver.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -o $@ -Wl,--start-group $(LIB) -Wl,--end-group $(LIBS)

# Tests that need neither a NIC nor DPDK, so they run on any node — including
# the orchestrator, which has no rte_config.h. A test that only runs on the
# testbed is a test that stops being run.
TEST_SRCS := $(wildcard tests/test_*.c)
TESTS     := $(patsubst tests/%.c,bin/%,$(TEST_SRCS))

# Off-testbed sources only: no infra, so no DPDK. If a test needs the target's
# packet path it belongs somewhere else, and that somewhere does not exist yet.
TESTABLE := src/program/prog_app_parser.c src/program/prog_processor.c \
            src/program/prog_blueprint.c src/program/prog_dispatch.c \
            src/program/prog_net_parser.c \
            src/program/prog_instrument.c \
            src/target/fhash.c src/target/send_buffer.c \
            src/target/window.c src/target/ring_buffer.c

# What those sources reference from the DPDK half. See tests/offbed_stubs.c.
# prog_param.c defines the params (param <type> <name>(default)), which the
# processors read. No DPDK in it.
TESTABLE += src/program/prog_param.c

TESTABLE += tests/offbed_stubs.c

bin/test_%: tests/test_%.c $(TESTABLE)
	@mkdir -p $(dir $@)
	$(CC) -g -O0 -Wall -Werror -Isrc/target -Isrc/program -Isrc/infra $^ -o $@

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

# The gates. A rule with no test is a rule that gets broken quietly.
check: test
	tools/check_rule4.sh
	tools/check_statics.sh
	tools/check_prio_opaque.sh
	tools/check_wiring.sh
	tools/check_infra_provenance.sh

clean:
	rm -rf build bin

-include $(LIB_OBJS:.o=.d)
