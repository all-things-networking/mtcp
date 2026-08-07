# MTP-DPDK — the rebuild

A userspace DPDK target that runs MTP programs, written fresh.

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
- `docs/PLAN.md` — the plan, and §6.1 the first milestone
- `docs/DECISIONS.md` — decisions taken, and the ones to revisit
- `docs/phase-d/` — the difference report, the sibling sweep, the two
  reference MTP programs and the cross-check
- `docs/RESULTS.md` — every measured number

## What this branch does not yet contain

Nothing but this file. **What the target is seeded with is a design decision,
not a default** — whether it starts empty or from the donor's protocol-free
infrastructure sets the structure of everything after it, so it waits for the
design and its checkpoint rather than being settled by whoever cut the branch.
