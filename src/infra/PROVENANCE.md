# Where `src/infra/` came from

Everything in this directory is either **seeded** from mTCP or **written for
this target**. `docs/DECISIONS.md` D-07 in `minmit/tmp-mtp-pass` decided that
the plumbing is inherited and only the transport above it is new, and it
attached two requirements: a reader must be able to tell the two apart without
`git log`, and it must stay possible to `diff` this directory against the donor.

The donor is `mtcp-donor` @ **`7fbb223c`**, read out of this repository's own
object store — no path to anybody's checkout appears in any script.

## The mechanism, which is stronger than a list

`provenance/manifest.tsv` says, per file: which donor file it came from, and the
sha256 of the **residual** — the diff between (the donor file with
`provenance/rename.sed` applied) and the file as it stands here.

- `tools/seed_infra.sh <dir>` produces the derivation.
- `tools/check_infra_provenance.sh` recomputes every residual and fails on any
  that does not match what is recorded. `-v` prints them.
- `tools/record_infra_provenance.sh` re-records, by hand, after a deliberate
  edit.

So "unchanged" is a checked statement, not a claim, and any later edit to
seeded code — including one made by accident, including one made by someone who
did not read this file — fails the gate until a person re-records it and writes
down why. That is what makes *"the difference we measure against mTCP is a
difference in the transport"* something you can test.

`make check` runs it, alongside `tools/check_rule4.sh`.

## `rename.sed` — the only blanket change

Two jobs and no others: rule 4 (a symbol this tree *defines* may not name a
protocol — mTCP's `PKT_TX_TCPIP_CSUM` and `TCP_SEQ_GT` do), and readability
(this is not mTCP, so the per-core stack instance is not `mtcp_manager` and the
flow record is not `tcp_stream`).

The renames are one token per line, so line-for-line correspondence with the
donor survives and a `diff` still reads.

## Written for this target, not seeded

| file | what it is |
|---|---|
| `infra.h` | the infrastructure half of mTCP's `mtcp.h`. That file is where the donor's layering breaks down — one struct holding the NIC handle, the log buffers, the flow table, the send queues, the RTO store and the epoll state — so it is split rather than seeded. Every structure kept from it is marked in place. |
| `bringup.c` / `.h` | the infrastructure quarter of mTCP's 1712-line `core.c`. Pulling the whole file across as a deletion diff would be less readable than writing the quarter and naming where each function came from, and rule 3 ranks readability with correctness. Provenance is per function. |
| `upcall.h` | everything infrastructure needs from the layer above, in one place, so the direction of the dependency is checkable. This is where `case IPPROTO_TCP: return ProcessTCPPacket(...)` went. |
| `ip_csum.h` | a **partial lift**: `ip_fast_csum` from `io_engine/include/ps.h:66-95`, verbatim. The rest of `ps.h` is the PacketShader I/O library, which is not carried, but this is on the packet path so it comes across unchanged. Partial lifts cannot live in the manifest, which works at file granularity; they are listed here instead. |

## Partial lifts

| what | from | where it is now |
|---|---|---|
| `ip_fast_csum` (x86 version) | `io_engine/include/ps.h:66-95` | `ip_csum.h`, verbatim |
| `MAX_DEVICES`, `MAX_RINGS` | `io_engine/include/ps.h:4-5` | `infra.h` |
| the clock macros (`HZ`, `TIME_TICK`, `TIMEVAL_TO_TS`, the unit conversions) | `mtcp/src/include/tcp_in.h:46-62` | `infra.h`. Pure unit conversion; it sits in the donor's TCP header only because that is where somebody put it |
| `SEQ_LT` / `LEQ` / `GT` / `GEQ` | `mtcp/src/include/tcp_in.h:40-43` (as `TCP_SEQ_*`) | `infra.h`. A comparison of numbers on a circle. `arp.c` uses it on timestamps, which is the clearest evidence the donor's name was wrong |
| `INPORT_ANY` | `mtcp/src/include/mtcp_api.h:12` | `addr_pool.h`, which is the only thing that uses it |

## Not carried, and why

| | |
|---|---|
| `netmap_module.c`, `psio_module.c`, `onvm_module.c`, and their arms of `io_module.c` and `config.c` | compiled out of the donor's own build (`PS=0 NETMAP=0 ONVM=0` in its Makefile). Nothing that has ever been measured used them |
| `ccp.c`, `clock.c`, `pacing.c`, `libccp` | same — `CCP=` is empty in the donor's Makefile |
| the `ENABLELRO` segment walk in `dpdk_module.c` | `LRO=0` in the donor's Makefile, and it is one of only two places the PMD glue reads an L4 header |
| the L4 half of `debug.c`'s three packet dumpers | decoding an L4 header is the program's knowledge. `PKTDUMP` is off in every build anyone has measured; the program gets a dump hook when it has something to dump |
| `io_engine/` | one I/O module is carried, so the PacketShader library is not needed. The two things `ps.h` supplied are listed under partial lifts |

## Two donor behaviours changed deliberately, not inherited

**The unbounded transmit retry.** `dpdk_send_pkts` retried `rte_eth_tx_burst` in
a `do { } while (cnt > 0)` with no bound and no timeout, so a NIC that stops
draining spins the core for ever, silently. Rule 5 says treat a hang as a
failing test. Bounded at 1024 attempts against a 64-packet burst — reaching it
means wedged, not busy — with the undelivered packets dropped and counted.

**Fatal errors on the send path, NOT changed, but decided rather than
inherited.** In the donor a missing route is `assert(0)` (`ip_out.c:34`) and
mempool exhaustion is `exit(EXIT_FAILURE)`. Neither is a classifiable failure;
both kill the process. Kept for now, because a target that limps on after
exhausting its mempool produces measurements nobody should trust, and because
changing it would change behaviour the comparison rests on. It is on the debt
list (`docs/DESIGN.md` §17.2) to revisit when the failure signal of D-17 exists
— at that point a mempool exhaustion is a classifiable `BLOCKED(shared)` and
killing the process stops being the only honest option.

## Deferred to increment 2, though they belong in this layer

`eventpoll.c`, `socket.c`, `pipe.c` and the `mtcp_api.h` / `mtcp_epoll.h`
socket-API shim. They are entangled with the socket map and the flow record,
which increment 2 creates, and `eventpoll.c` calls `TCPStateToString` and
`RaisePendingStreamEvents` — both transport-side. Seeding them before the flow
record exists would mean inventing the flow record here, in the wrong increment.

`fhash.c` (the flow table) is deferred for a related reason and will land in
`src/target/`, not here: it reaches into the flow record's link fields, so it is
not below the transport at all. `docs/DESIGN.md` §1.3 places it in `src/infra/`
and §1.1 places the flow table in the target; §1.1 is right.
