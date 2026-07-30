
---

## 2026-07-30 — Multi-timer facility: first surviving build, and a parity number

`mtp-dpdk` @ 18e24ea4 + FIN_WAIT_2 reaper. Untraced, `-c 200`, 35 s, 3 reps.

### Root fix

The MTP program names which timer `timer_start_instr` arms; the target dropped
that argument and had one slot per flow, so TIME_WAIT and connection reaping had
nowhere to live and were commented out — flows leaked until the pool exhausted.
Each declared timer now has its own expiry-ordered list, swept independently
with the donor's early stop intact.

Sharing one list was actively harmful: the donor's list is ordered by
retransmission deadline, so 30 s idle timers on it made the sweep quit before
reaching flows whose RTO was due, silently disabling retransmission (died at
5 s). Per-timer lists fixed it.

### Durations, checked against the donor's running mtcp.conf

| | donor | MTP |
|---|---|---|
| `tcp_timewait` | **0** | was 2000 (invented, not inherited) → **0** |
| `tcp_timeout` | 30 s = 30000 ticks | 30000 ✓ already matched |
| tick | HZ 1000 → 1 ms | ✓ |

### Result

| | mean over run | rate while sending | stalled | bytes/pkt | span |
|---|---|---|---|---|---|
| base | 1.76-2.30 Gbps | 4.17-4.49 | **37-51%** | 1527 | 35 s |
| mtp-old | 3.85-4.18 | 3.66-4.21 | 0% | 1447 | **dies 17-19 s** |
| **mtp-timers** | **2.77-3.74 Gbps** | 3.52-3.67 | 0-17% | 1455-1471 | 31/35/35 s |

**MTP now exceeds the donor on mean throughput** (~3.36 vs ~1.95 Gbps) because
base spends 37-51% of each run stalled in zero-window recovery while MTP barely
stalls. While actually sending, base is ~18% faster (4.3 vs 3.6) — that gap is
the honest cost-of-programmability figure for this workload.

Flows: peak 264 then recede to 255 and hold, against the donor's flat 200.
Bounded and no longer monotonic, but still a residual difference.

### Still open

- Residual 255 vs 200 flows. Suspect the FIN state machine, whose sequence
  compensation is duplicated across four event processors.
- `idle_ep` destroys unconditionally; the donor raises an error event when a
  socket exists and only destroys otherwise.
- `tcp.mtp` does not yet declare these timers or use `destroy_ctx_instr`;
  program and target agree in behaviour, not in source.
- P5 probe and P1a/P1b fill/SWS still parked in `bench/patches/` — they were
  judged against builds that were dying for an unrelated reason and deserve
  re-measurement now that the stack survives a full run.

Raw: `/tmp/reps6/*.txt`.
