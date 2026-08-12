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

LIB  = build/libmtp.a
APPS = bin/upcheck

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
	$(CC) $(CFLAGS) $< -o $@ $(LIB) $(LIBS)

# Tests that need neither a NIC nor DPDK, so they run on any node — including
# the orchestrator, which has no rte_config.h. A test that only runs on the
# testbed is a test that stops being run.
TEST_SRCS := $(wildcard tests/test_*.c)
TESTS     := $(patsubst tests/%.c,bin/%,$(TEST_SRCS))

# Off-testbed sources only: no infra, so no DPDK. If a test needs the target's
# packet path it belongs somewhere else, and that somewhere does not exist yet.
TESTABLE := src/program/prog_app.c src/target/flow_table.c

bin/test_%: tests/test_%.c $(TESTABLE)
	@mkdir -p $(dir $@)
	$(CC) -g -O0 -Wall -Werror -Isrc/target -Isrc/program -Isrc/infra $^ -o $@

test: $(TESTS)
	@for t in $(TESTS); do ./$$t || exit 1; done

# The gates. A rule with no test is a rule that gets broken quietly.
check: test
	tools/check_rule4.sh
	tools/check_infra_provenance.sh

clean:
	rm -rf build bin

-include $(LIB_OBJS:.o=.d)
