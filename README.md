# MTP-DPDK — the rebuild

A userspace DPDK target that runs MTP programs.

This branch **descends from neither reference** (`docs/DECISIONS.md` D-05 in
`minmit/tmp-mtp-pass`). It is an orphan root, like `mtcp-donor` and
`mtp-dpdk-clean`, so `git diff` against either reference stays meaningful.

## The references, which are read and never edited

| | branch | commit |
|---|---|---|
| donor — the behaviour and correctness reference | `mtcp-donor` | `7fbb223c` |
| prototype — a design reference, good and bad | `mtp-dpdk-clean` | `eac02d19` |
| original prototype — attribution only | `mina-mtp` | `55056faf` |
| the Appendix D send buffer | `quic-mtp` | `f1e56fa6` |

## Where the thinking lives

Everything driving this build is in `minmit/tmp-mtp-pass`:

- `CLAUDE.md` — the charter
- `docs/DESIGN.md` — the design, approved at Checkpoint 2 (D-08)
- `docs/PLAN.md` — the plan, and §6.1 the first milestone
- `docs/DECISIONS.md` — decisions taken, and the ones to revisit
- `docs/phase-d/` — the difference report, the sibling sweep, and the MTP
  programs written against each reference
- `docs/RESULTS.md` — every measured number

## Layout

```
src/infra/     below the transport: DPDK, Ethernet, IP, ARP, ICMP, memory,
               config, logging. Seeded from the donor — see PROVENANCE.md
src/target/    flows, buffers, blueprints, scheduling, timers. Protocol-free,
               and identical source across protocol builds. contract.h is the
               target/program boundary
src/program/   compiler output. Per protocol. Today hand-written in the form a
               compiler would emit
apps/          things that run
conf/<site>/   per-testbed configuration
tools/         the gates
```

## Building

On a node with the DPDK environment — **aqua09**, not the orchestrator, which
has no `rte_config.h` (`docs/DPDK_HANDOFF.md` §4):

```
make            # library + apps
make check      # rule 4 and infra provenance
```

No autotools. Everything the build needs is committed; `build/` and `bin/` are
generated and ignored. The compiler flags are the donor's, deliberately
(`docs/DECISIONS.md` D-02), so that no difference in optimisation sits under a
measurement.

## Running

```
mkdir -p /tmp/upcheck && cd /tmp/upcheck
cp -r <repo>/conf/aqua/* . && cp <repo>/bin/upcheck .
sudo ./upcheck -f upcheck.conf -t 2000        # -t 0 runs until SIGINT
```

`upcheck` brings the target up on the NIC, runs the loop for a bounded time and
puts it back down. There is no transport yet; what it proves is that the seeded
plumbing initialises, that DPDK claims the configured interface, and that the
process exits without leaving hugepages or an EAL socket behind.

The bound is not a convenience. Rule 5: a hang is a failing test, and a
bring-up check that cannot end on its own is one that takes the node off the
network when it goes wrong.

## State

Increment 1: the tree, the seeded plumbing, the contract as headers, and a
binary that starts and exits. No protocol behaviour. `src/target/contract.h` is
the thing to read first — it is `docs/DESIGN.md` §2 written so a compiler can
check it.
