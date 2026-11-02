# tcp-sans-io

A `#![no_std]`, zero-allocation, sans-I/O TCP stack in Rust. Designed to live
**in front of an external WireGuard backend** and **behind a foreign-language
async runtime** (C# / Python / Go) via a stable C ABI.

```
┌───────────────────────────┐    ┌───────────────┐    ┌───────────────────┐
│  Host runtime (C# / Py /  │ ↔  │ tcp-sans-io   │ ↔  │  WireGuard tunnel │
│  Go / native), via C ABI  │    │ (Rust cdylib) │    │  (host-supplied)  │
└───────────────────────────┘    └───────────────┘    └───────────────────┘
                                 sans-I/O:
                                 - no syscalls
                                 - no allocations
                                 - no threads
                                 - no panics
```

The stack itself does no I/O. The host:
1. Hands bytes from the WireGuard side into `tcp_inject_packet(..)`.
2. Drains outbound bytes via `tcp_extract_packet(..)`.
3. Calls `tcp_tick(now_ms)` when `tcp_next_deadline(..)` comes due (and
   after `tcp_send`) to drive timers and transmission.
4. Reads/writes application data via `tcp_recv(..)` / `tcp_send(..)`.

## Features (RFC matrix)

The loss-recovery and hardening feature set of a modern Linux TCP, minus
CUBIC/BBR: RACK-TLP is the primary loss detector, PRR paces recovery, SACK
and D-SACK work in both directions, timestamps carry RTT samples and PAWS,
spurious recoveries are undone on D-SACK or timestamp evidence, and the
RFC 5961 / Linux-style defences and lifecycle timers are on by default.
Congestion control is Reno (RFC 5681 + RFC 6937); *Benchmarks* shows what
that costs against Linux CUBIC on lossy long paths.

| Feature | Spec | Status |
|---|---|---|
| State machine, active + passive open, simultaneous open | RFC 9293 | ✅ |
| Half-open replacement (a new SYN recycles a stalled `SYN_RCVD` slot) | — (single-slot listener policy) | ✅ |
| SYN cookies while the half-open slot is busy (a valid cookie ACK takes the slot over); WS / SACK / ECN kept via timestamp bits; key derived from the host secret or set explicitly, surviving one rotation | RFC 4987 | ✅ |
| ISN selection | RFC 6528 | ✅ keyed by `tcp_set_secret` on passive opens (`tcp_listen` requires a secret); host-supplied `iss` on active |
| MSS; MTU / PMTU (`tcp_set_mtu`, `tcp_update_pmtu`, black-hole clamp, probing back up); what a smaller path MTU, or a probe that did not get through, lost is resent without reducing the window | RFC 9293, RFC 1191, RFC 4821 (spirit) | ✅ Linux `tcp_simple_retransmit` |
| Timestamps: RTTM, PAWS (pure ACKs included, but for Linux's exemption of a reordered old ACK), keyed per-connection offset | RFC 7323 §3–5 | ✅ Linux `tcp_paws_discard` / `tcp_disordered_ack` |
| Window Scale | RFC 7323 §2 | ✅ |
| SACK, both directions; receiver holds the whole window out of order; blocks beyond `SND.NXT` or not above `SND.UNA` ignored; blocks on an ACK reordered behind a newer one still count; a receiver that reneges gets max(SRTT/2, 10 ms) before the timeout resends | RFC 2018 | ✅ Linux `tcp_is_sackblock_valid` / `tcp_check_sack_reneging` |
| D-SACK, both directions (drives RACK's reordering window) | RFC 2883, RFC 3708 | ✅ |
| Spurious fast recovery / RTO undone: D-SACKs for every retransmission (an unresolved tail loss probe included), an ACK whose timestamp echo predates the first one (receivers without D-SACK too), or a hole filled before anything was resent; never past an ECN-Echo | RFC 3708, RFC 3522 | ✅ Linux-style (`tcp_try_undo_*`, `tcp_packet_delayed`) |
| RTO with Karn's algorithm; RTO = SRTT + max(4·RTTVAR, 200 ms), SRTT / RTTVAR in fixed point | RFC 6298 | ✅ Linux `tcp_rtt_estimator` / `tcp_set_rto` |
| Slow start / congestion avoidance (byte counting, growth only while cwnd-limited, per round of data); restart after idle halves cwnd per idle RTO; a window left unused for an RTO decays | RFC 5681, RFC 3465, RFC 7661 (spirit) | ✅ Linux `tcp_cwnd_validate` / `tcp_cwnd_restart` |
| Proportional Rate Reduction; each reduction halves `cwnd` (capped by the peer's window), not FlightSize | RFC 6937 | ✅ Linux `tcp_init_cwnd_reduction` / `tcp_cwnd_reduction` |
| Initial window of 10 segments | RFC 6928 | ✅ |
| RACK-TLP: time-based loss detection, tail loss probe (also during an ECN reduction) | RFC 8985 | ✅ primary loss detection |
| Duplicate-ACK fast retransmit (peers without SACK) | RFC 5681 §3.2 | ✅ fallback |
| ECN (ECT(0) on new data; CE echoed only from data segments; ECE → one CWR reduction per window; CWR sent after every reduction, withdrawn if it is undone first) | RFC 3168 | ✅ Linux `tcp_ecn_queue_cwr` / `tcp_ecn_withdraw_cwr` |
| Blind-attack hardening: RST, SYN and ACK checks, rate-limited challenge ACKs | RFC 5961 §3–5, §7 | ✅ |
| Silly-window avoidance, sender and receiver | RFC 9293 §3.8.6.2 | ✅ |
| Nagle in Minshall's variant (a short segment waits only behind an unacknowledged short one); `tcp_set_nodelay` turns it off | RFC 9293 §3.7.4 | ✅ on by default, as Linux |
| PSH on the segment that ends the queued data (and every half window), not on every segment | RFC 9293 §3.9.1 | ✅ as Linux `tcp_mark_push` |
| Window-update rule (SND.WL1 / WL2) | RFC 9293 §3.10.7.4 | ✅ Linux `tcp_may_update_window`: a reordered ACK cannot shrink the window; a forged future WL1 cannot freeze it (nor at the handshake) |
| Zero-window persist probes | RFC 9293 §3.8.6.1 | ✅ Linux-style probe at `SND.UNA − 1`; an owed FIN waits for the window like data; timeouts into a zero window count only while unanswered |
| Delayed ACK: at once for every 2nd segment, more than one MSS unacknowledged, out-of-order data, a hole filled in whole or part, and duplicates; in quickack mode (a connection's first segments, data after an idle RTO, after duplicate or out-of-window data, a new CE mark) for every segment; else 40 ms. A read that empties the receive queue sends an ACK a short or pushed segment earned, unless the connection is interactive | RFC 1122 §4.2.3.2, RFC 5681 §4.2 | ✅ Linux `__tcp_ack_snd_check` / `tcp_enter_quickack_mode` / `tcp_cleanup_rbuf` |
| R2 retransmission limit, USER TIMEOUT, keepalive | RFC 9293 §3.8.3–3.8.4 | ✅ on by default |
| FIN_WAIT_2 timeout | Linux `tcp_fin_timeout` | ✅ 60 s, restarted only by the application reading |
| TIME_WAIT, re-ACK and restart on a retransmitted FIN | RFC 9293 §3.10.7.4 | ✅ 60 s; restarts capped at 120 s after entry |

### Deliberately deferred

| Feature | Spec | Why deferred |
|---|---|---|
| CUBIC (+ HyStart) | RFC 9438 | The main remaining gap: on lossy long paths Linux CUBIC sustains a multiple of Reno's goodput (see *Benchmarks*). Planned as a selectable algorithm. |
| BBR | — | Model-based congestion control; a different architecture. |
| Pacing | — | Bursts are bounded by cwnd and PRR instead. |
| TCP Fast Open | RFC 7413 | Data-in-SYN has a complex security model. |
| MPTCP | RFC 8684 | A different connection model. |

### Deliberately omitted (out of scope)

- IPv6 (the WireGuard backend is the v6-aware layer; we present IPv4 to the
  tunnel).
- Listening on multiple connections per TCB (one connection per TCB — the
  host multiplexes).
- Out-of-band data (`URG`).
- TCP-MD5 / TCP-AO authentication.

### Where it differs from Linux

Linux is the reference wherever a sans-I/O library can follow it. The
known differences:

| Area | tcp-sans-io | Linux | Why |
|---|---|---|---|
| Clock | Milliseconds, from the host | Microseconds (`tcp_mstamp`) | No clock of its own. RACK's reordering window is at least 2 ms and the TLP timeout `max(2·SRTT, 10 ms)` (Linux: `min_RTT/4` in µs and `2·SRTT + 2 ms`), so on sub-millisecond paths loss is declared a little later; and a SACKed retransmission timed at 0 ms against a 1 ms minimum RTT still counts as delivered until the path has shown reordering, where Linux needs no such slack. See *Clock model*. |
| Congestion control | Reno | CUBIC (+ HyStart) | See *Deliberately deferred*. |
| Loss reduction | Halves `min(cwnd, peer window)` | Halves `cwnd` | Slow start may grow `cwnd` to twice a flight the peer's window caps (as in Linux), and halving that would not slow the sender: with a 1 MiB window the first reduction after a slow-start overshoot would be a no-op. |
| Send buffer | Fixed `BUF_CAP` ring, the same size as the largest window it can fill | Autotuned to about twice `cwnd` | Allocation-free. A bulk sender that keeps the peer's window full can drain the ring and send a short segment mid-stream; Nagle then holds the transfer's last short segment behind it for up to an RTT. `close()` (the FIN rides on it) or `set_nodelay(true)` ends a transfer without the wait. |
| SACK on retransmissions | A retransmission keeps its size and carries the blocks only if they fit | Splits the segment to fit them (`__tcp_retransmit_skb`) | No re-segmentation of the retransmission queue. New data segments shrink to carry them, as in Linux, and pure ACKs always do. |
| RST in `CLOSING` / `LAST_ACK` | Reports `ConnectionReset` only if data of ours (beyond the FIN) was undelivered | Always `ECONNRESET` | Everything the application sent arrived, so the stream completed. |
| PAWS reference expiry | 24 days idle (RFC 7323 §5.5) | About 36 minutes (`TCP_PAWS_WRAP`, sized for microsecond timestamps) | Our timestamps are milliseconds, which take 24 days to wrap. |
| Late D-SACK undo | Once an episode has ended, only D-SACKs below its recovery point can undo it | Any D-SACK above `undo_marker` counts | A D-SACK for a later tail loss probe would otherwise undo an earlier, real loss's reduction. |
| Timestamp undo reference | An unresolved tail loss probe keeps it, as a retransmission still in flight | `tcp_any_retrans_done` does not count the probe | The probe's own ACK would otherwise pass for a delayed original's and undo a real loss. |
| Spurious timeout detection | D-SACK and timestamps (Eifel) | Also F-RTO (RFC 5682, on by default) | Timestamps cover it whenever they are negotiated; F-RTO for peers without them is deferred. |
| Timeouts into a zero window | Count toward R2 only while unanswered | Given up once the peer has been silent for 2·`TCP_RTO_MAX` (240 s) | Counted like persist probes; the USER TIMEOUT bounds both. |
| SYN-cookie timestamps | On only if the ACK echoes our SYN-ACK's TSval | On whenever the ACK carries the option | RFC 7323 §3.2: otherwise they were never negotiated. |
| ECN on active opens | Always requested | Requested only with `tcp_ecn=1` (the default, 2, accepts it but does not ask) | Virtual links and modern queues mark rather than drop; a retransmitted SYN falls back without it. |
| USER TIMEOUT, keepalive | On by default (5 min; keepalive after 10 min idle, 4 probes 60 s apart) | Off unless set (`TCP_USER_TIMEOUT`, `SO_KEEPALIVE` with 2 h idle) | A library connection has no process exit to reap it; both can be turned off. |
| FIN_WAIT_2 timeout | 60 s even while the application holds the TCB (restarted by reads; 0 turns it off) | Only for orphaned sockets (`tcp_fin_timeout`) | A sans-I/O TCB cannot tell whether its owner still cares; the host decides. |
| SYN in TIME_WAIT | Challenge ACK (RFC 5961 §4); a new connection takes a new TCB | May reuse the TIME_WAIT for a new connection with higher sequence numbers or timestamps (`tcp_timewait_state_process`) | One connection per TCB; the host demultiplexes new connections. |

## Design constraints

- `#![no_std]`, no heap allocation, no panics, no threads, no syscalls.
- Hot paths use fixed-size ring buffers and are zero-allocation.
- `unwrap`, `expect`, `panic!`, `indexing_slicing` are deny-listed via Clippy
  (see `Cargo.toml`).
- All packet parsing is bounds-checked and returns `Result`; never panics on
  arbitrary input.
- C ABI version is stable (queryable via `tcp_abi_version()`); bump it on
  any breaking change.

### Memory footprint

Per connection, `tcp_handle_size()` is **2,176,976 bytes (≈ 2.08 MiB)** with
default features, or **139,600 bytes (136 KiB)** with `small-buffers`:

- `BUF_CAP` send ring + receive ring (2 × 1 MiB; 2 × 32 KiB with
  `small-buffers`). Out-of-order data is parked inside the receive ring at
  its final offset, so the whole advertised window can be held while a hole
  is repaired at no extra memory cost.
- 48 KiB egress staging ring (32 × `MAX_PACKET`).
- 24 KiB retransmission queue (1024 segment records, plus a 128-byte
  bitmap of the SACKed ones).
- 6 KiB out-of-order range tracker (512 ranges; 384 B / 32 ranges with
  `small-buffers`).
- Under 1 KiB of scalar state.

The 1 MiB default lets the receive window fill typical WAN paths (1 MiB per
RTT ≈ 168 Mbit/s at 50 ms); raise `BUF_CAP` (a power of two) for fatter
pipes or use `small-buffers` for many mostly-idle connections.

`tcp_init` / `Tcb::init_in_place` build the TCB directly in its storage and
need under 32 KiB of the calling thread's stack. `Tcb::new` returns the
whole TCB by value, so pure-Rust callers should box it (or use
`init_in_place`); the repository's `.cargo/config.toml` raises
`RUST_MIN_STACK` for tests that keep TCBs on the stack.

## Connection state machine

The eleven TCP states and every transition the stack can take. The graph is
**implementation-accurate** — its edges are exactly the relation of
`State::debug_transition_allowed()` (`src/state.rs`). Every fuzz target panics
if the live TCB makes a move outside it, and a unit test fails if
`docs/state-machine.dot` draws a different set of edges, so the picture and
the code cannot drift apart.

![TCP connection state machine](docs/state-machine.svg)

Bold purple is the non-textbook **SYN_RCVD → LISTEN** revert: a listener
keeps at most one half-open slot and recycles it after a bounded SYN-ACK
retransmit budget (or an exact RST), rather than leaking it. Green edges are
SYN-cookie promotions: while the slot is busy, other peers get cookie
SYN-ACKs, and a valid cookie ACK establishes directly — from SYN_RCVD by
taking the slot over. Dashed grey edges are aborts (RST / `abort()` /
timeouts). See
[`docs/state-machine.md`](docs/state-machine.md) for a live-rendering Mermaid
copy, the full transition table with code citations, and how to regenerate the
SVG from [`docs/state-machine.dot`](docs/state-machine.dot).

## Extents and bounds

Every data structure in the stack is fixed-capacity — there is no
allocator and nothing grows with peer behaviour. The table lists each
bound, where it lives, and what it caps. **The central invariant is that
every one of these is a *performance* knob, not a *correctness* knob**
(see "Why the bounds are sound" below): exceeding a capacity always
degrades to retransmission or backpressure, never to data loss,
mis-ordering, corruption, a panic, or an unbounded loop.

| Bound | Value | Where | What it limits |
|---|---|---|---|
| `BUF_CAP` | 1 MiB (32 KiB w/ `small-buffers`) | `lib.rs` | Send + receive ring capacity: the receive window, out-of-order storage and the in-flight ceiling per RTT. Power of two; the window-scale shift derives from it (5 at 1 MiB). |
| `MSS` / `MAX_PACKET` | 1460 / 1500 B | `lib.rs` | Largest payload / datagram. `tcp_set_mtu` lowers both (576–1500). |
| `OOO_MAX_RANGES` | 512 (32 w/ `small-buffers`) | `ooo.rs` | Disjoint out-of-order ranges held in the receive ring: one per two full segments of buffer, enough for a full window with every other segment lost. |
| `RTX_QUEUE_CAP` | 1024 | `rtx_queue.rs` | Segments in flight. When full, new data waits for ACKs; nothing is evicted, so every in-flight segment keeps SACK/RACK coverage. |
| `TX_RING_CAP` | 32 | `tx_ring.rs` | Egress packets staged before the host must drain. |
| SACK blocks emitted | ≤ 4 (≤ 3 with timestamps) | `tcb/output.rs` | Bounded by the 40-byte option area. New data segments shrink their payload to carry them (Linux `tcp_current_mss`); a full-sized retransmission carries only what fits. |
| `INITIAL_WINDOW` | 10 × SMSS (14,480 B with timestamps) | `congestion.rs` | RFC 6928 initial cwnd. |
| `MIN_PEER_MSS` | 64 B | `tcb/mod.rs` | Floor on a peer-requested MSS (bounds per-byte header and queue cost). |
| `RTO_MIN` / `RTO_MAX` | 200 ms / 60 s | `tcb/mod.rs` | RTO = SRTT + max(4·RTTVAR, `RTO_MIN`) as Linux, so even a steady path keeps a 200 ms margin; exponential backoff is capped at `RTO_MAX`. |
| TLP PTO floor / delayed ACK / `TIME_WAIT` | 10 ms / 40 ms / 60 s (≤ 120 s) | `tcb/mod.rs` | Probe timeout floor, delayed-ACK timer, 2·MSL; a retransmitted FIN restarts 2·MSL, at most 120 s after entry. |
| `MAX_SYN_RETRIES` / `MAX_SYN_RCVD_RETRIES` | 6 / 5 | `tcb/mod.rs` | SYN retransmissions before an active open fails; SYN-ACK retransmissions before a half-open reverts to `LISTEN`. |
| `MAX_RETRANSMITS` | 10 | `tcb/mod.rs` | RFC 9293 §3.8.3 "R2": consecutive timeouts (data, FIN or unanswered zero-window probes) with no proof of life before abort. |
| USER TIMEOUT | 300 s | `tcb/mod.rs` | Max time with outstanding send work but less than one full segment acknowledged; reaps stalled, zero-window and sub-MSS-trickle peers. A reader acknowledging a full segment per period is live progress, not a stall (see *Threat model*). `set_user_timeout(0)` disables. |
| Keepalive | 600 s idle / 60 s / 4 probes | `tcb/mod.rs` | Reaps a vanished peer on an idle connection: `ESTABLISHED`, or half-closed (`CLOSE_WAIT`, `FIN_WAIT_2`), as in Linux. `set_keepalive(0, …)` disables. |
| FIN_WAIT_2 timeout | 60 s | `tcb/mod.rs` | Time a peer may leave its half open after ACKing our FIN; restarted only when the application reads, never by the peer's data alone. |
| Black-hole MSS clamp / probe | 3, 5 RTOs → 1024, 536 / 10 s … 10 min | `tcb/mod.rs` | Consecutive timeouts of a large segment clamp the MSS; one probe segment at the next larger size (first after 10 s, doubling up to 10 min on failure) restores it once it arrives. |
| Out-of-window reply rate | 1 per 500 ms | `tcb/mod.rs` | Challenge ACKs, dup ACKs for unacceptable segments and RSTs to stray segments, per connection. Exempt: one immediate ACK (D-SACK) per data / FIN segment that could be the peer's own retransmission — acceptable ACK, plus a timestamp when negotiated — since the peer's loss recovery depends on it. |
| Cookie validity | 64–128 s | `tcb/cookie.rs` | Two 64 s buckets, under the current and the previous key (one rotation); 29-bit SipHash MAC (2⁻²⁹ blind forgery per attempt). |

### Why the bounds are sound

The receiver only ever delivers a **contiguous prefix** starting at
`rcv_nxt`, and only ever cumulatively ACKs / SACKs data it is actually
holding. So any byte the stack cannot store is simply never acknowledged,
and the peer retransmits it. Concretely:

- **Out-of-order tracker full** (a 513th disjoint range) → the segment is
  dropped, never SACKed, and resent by the peer. Nothing already SACKed is
  ever discarded (no reneging). The application can never observe a gap.
- **Retransmission queue full** → no new segment is sent until an ACK frees
  a record; recovery state is never lost.
- **`TX_RING_CAP` full** → emit returns "ring full" and bookkeeping
  (`snd_nxt`, FIN state) is not advanced, so nothing is skipped; the host
  drains and ticks again.
- **Receive ring full** (application not reading) → the advertised window
  shrinks to zero, the peer stalls on flow control, and persist probes keep
  the connection alive until the USER TIMEOUT applies.

Shrinking `BUF_CAP` changes throughput, never the bytes the application
sees.

### Out-of-order capacity

Out-of-order bytes are written straight into the receive ring at their
final offset, so the receiver holds everything inside its advertised window
while holes are repaired, as Linux does. Only the number of disjoint ranges
is bounded. 512 covers the worst realistic pattern: a slow-start overshoot
into a tail-drop queue that loses every other segment of a full window. (A
32-range tracker could not; the link simulation in `src/sim_tests.rs`
caught it forcing 66 avoidable retransmissions in a single overshoot.) An arriving
segment costs a binary search, plus an O(ranges) shift of 12-byte records
when a hole closes.

### Termination and resource safety

These bounds also make the stack **DoS-resistant and hang-free** against a
hostile peer:

- **No unbounded loops.** Every loop reachable from `inject_packet` /
  `tick` / `send` is bounded by a fixed-capacity structure, a
  strictly-advancing index, or (for the transmit loop) an explicit
  `loop_budget_exhausted` guard that panics under test/fuzz builds and
  stops gracefully in the shipped build.
- **No busy timers.** After `tick()` at `now`, `tcp_next_deadline()` is
  always later than `now`, so an event-driven host never spins (checked by
  the link simulation on every step).
- **No amplification.** One inbound segment stages at most `TX_RING_CAP`
  packets, and replies to unacceptable segments are rate-limited per
  connection; only a data or FIN segment carrying an acceptable ACK (and a
  timestamp when negotiated) is answered at once, with a single ACK.
- **No state exhaustion inside a TCB.** One half-open per listener TCB
  with a bounded SYN-ACK budget, and stateless SYN cookies for every other
  peer while it is busy; no allocator to drain. (Bounding the *number* of
  TCBs is the host's job.)
- **No information disclosure.** Emitted packets are built in
  zero-initialised scratch with exactly the payload bytes copied;
  `tcp_init` zeroes reused storage; timestamps are offset per connection
  by a keyed hash (with `tcp_set_secret`) so they reveal neither the host
  clock nor a cross-connection correlator.

## Clock model and tick cadence

TCP is **inherently time-dependent**: retransmission (RTO), Tail Loss
Probe (TLP), delayed-ACK, `TIME_WAIT`, zero-window persist probing, and
RACK's reordering window are all driven by elapsed time, not by packets
alone. This stack handles that without owning a clock, threads, or
syscalls: **`now_ms` (`u64` milliseconds) is supplied by the host** on
every `tcp_tick`, `tcp_inject_packet`, `tcp_connect` / `tcp_listen`,
`tcp_close` and `tcp_abort` call. The stack has no other notion of time.

That is the core reason the library is shaped this way. A sans-I/O stack
with an **external clock source** is a pure, deterministic function of
`(inputs, now_ms)` — which is exactly what makes it testable: the
conformance suite steps the clock millisecond-by-millisecond, and the
gVisor chaos harness advances a virtual clock by hand to reproduce loss
and reordering byte-for-byte. The same code path runs in production
against a real monotonic clock. There is no hidden timer thread to mock.

**What drives output.** Responses to inbound packets (ACKs,
retransmissions, newly permitted data) are staged *inline* during
`inject`; `close` stages the FIN and `recv` may stage a window update.
`send` only buffers: the next `tick` (or inbound ACK) turns the bytes into
segments. Timer *expiry* (RTO, TLP, RACK reorder timer, persist,
keepalive, delayed ACK, FIN_WAIT_2, `TIME_WAIT`, USER TIMEOUT) is evaluated
only inside `tick()`.

**When to tick.** `tcp_next_deadline()` (`Tcb::next_deadline`) returns the
absolute `now_ms` at which `tick()` next has timer work, or `UINT64_MAX`
when nothing is armed. An event-driven host sleeps until the earlier of
that deadline and the next datagram, then ticks — idle connections cost
nothing, and after a tick the deadline is always in the future (no
spinning). Also tick right after `send`, after draining a full egress
ring, and after resuming paused egress (`Tcb::set_egress_paused`). Hosts
that cannot track deadlines tick every ~10 ms instead.

**How fast does the clock need to drive?** The timer floors are:

| Timer | Floor | Effect of a coarse/late tick |
|---|---|---|
| RACK reorder window | `min_RTT/4` (× D-SACK multiplier, ≤ SRTT), at least 2 ms | Loss declared slightly later on low-RTT reordering paths. Linux computes `min_RTT/4` in µs; whole milliseconds would make it 0 below a 4 ms RTT, so two ticks are the floor. |
| TLP PTO | `max(2·SRTT, 10 ms)` | Tail-loss probe fires up to one tick late. |
| Delayed ACK | 40 ms | ACK latency rises by up to one tick. |
| RTO | `SRTT + max(4·RTTVAR, 200 ms)`, ≤ 60 s | Negligible: a 10 ms tick is 20× finer than the floor. |
| `TIME_WAIT` | 60 s | Irrelevant to cadence. |

Without deadline tracking, a **~10 ms periodic tick with 1–2 ms of jitter
is adequate** — it matches the TLP floor and is far finer than `RTO_MIN`.
Finer only helps RACK on low-RTT paths, where its window is a few
milliseconds. **Cadence and jitter affect only loss-recovery
latency and ACK timing — never correctness** (per the bounds invariant
above): a coarse or jittery clock makes recovery slower, never wrong.

**Clock requirements.**

- Use a **monotonic, millisecond-resolution** source — `Instant`,
  `clock_gettime(CLOCK_MONOTONIC)`, `QueryPerformanceCounter` — not
  wall-clock. A backward step just postpones timers and a large forward
  jump fires them early; both are harmless but best avoided.
- The recommended driving pattern is **event-driven**: tick with a fresh
  `now_ms` after a batch of injects and sends, and sleep until
  `tcp_next_deadline()` otherwise. Pass the *same* `now_ms` you read for
  that turn into every call in the turn.

## How does it perform?

Measured against Linux on the same emulated paths (next section), as a
sender and as a receiver:

| Path | Result |
|---|---|
| Clean LAN / WAN | Line rate, indistinguishable from Linux. |
| Random loss (0.1–5 %) | Reno-class, as the Mathis model predicts: on a par with or above Linux Reno; at these RTTs Linux CUBIC is in its Reno-friendly region and does little better. |
| Shallow bottleneck buffers | Slightly above Linux Reno, about 10 % below Linux CUBIC. |
| Slow-start exit | Overshoots like Linux Reno (no HyStart): a queue's worth of drops, repaired by SACK + RACK without a timeout. CUBIC's HyStart avoids most of them. |
| Reordering | Learned via D-SACK (via timestamps from receivers that send none); spurious reductions are undone. |
| Virtual links (VMM ring, TUN; sub-ms RTT) | No retransmission, probe or timeout on a clean link; a lost tail is repaired by the probe in milliseconds, not a 200 ms timeout. Throughput over a TUN device is bound by the host's per-packet cost (one syscall per packet in the harness), not the protocol: 10 Gbit/s in simulation. |
| As a receiver | Linux CUBIC reaches the same goodput sending to tcp-sans-io as to Linux. |
| Long fat pipes | Capped by `BUF_CAP` (1 MiB per RTT ≈ 168 Mbit/s at 50 ms) and Reno's linear growth; CUBIC would help here. |

In every measured cell each retransmission repaired a real drop and no RTO
fired. *tcp-sans-io vs smoltcp* below compares it with the most widely
used Rust TCP stack.

## Benchmarks

### Method

`bindings/netem/bench.sh` compares tcp-sans-io with Linux TCP on the
**same path**. Every run builds three network namespaces from scratch: a
sender (tcp-sans-io behind a TUN device, IP-forwarded, or a Linux socket),
a router, and a receiver whose Linux socket measures goodput the same way
for every stack. The router shapes both directions: data gets netem delay
(RTT/2), random loss and a rate-limited bottleneck with a tail-drop queue;
ACKs get the other RTT/2. Each run records goodput (connection established
→ last byte), the sender's retransmitted segments (`tcp_get_stats` /
`TCP_INFO`), the router's drops and the receiver's duplicates (D-SACKs).
Five runs per cell; medians with min–max.

The harness avoids four traps that each distorted an earlier set of
numbers (including this README's previous table):

1. **Shaping the TUN's root qdisc shapes only kernel egress** — for an
   upload that is the ACK path, so "1 % loss" runs had a lossless data
   path (the old 157 MiB/s at 1 % loss).
2. **Linux TCP builds GSO super-packets even with `ethtool -K … gso off`**
   and segments them after the qdisc, so netem drops multi-segment bursts
   as one packet. `gso_max_segs 1` on every veth makes all stacks' packets
   alike.
3. **A qdisc on the sender's own interface reports tail drops to local TCP
   synchronously**, which resends without counting a loss — flattering
   Linux senders. The bottleneck therefore sits on a router.
4. **TUN writes from a thread that migrates between CPUs** land on
   different CPUs' backlogs and can be forwarded out of order — reordering
   no Linux sender sees. The sending endpoint is pinned to one CPU.

Host: AMD Ryzen 9 9950X, Linux 7.3, Ubuntu 26.04. tcp-sans-io uses its
default 1 MiB buffers; Linux uses the host's `tcp_rmem` / `tcp_wmem`.

| Profile | RTT | Bottleneck | Loss | Queue | Transfer |
|---|---|---|---|---|---|
| lan | 1 ms | 1 Gbit/s | 0 | 200 pkts | 512 MiB |
| wan | 40 ms | 100 Mbit/s | 0 | 160 pkts | 128 MiB |
| wan-0.1 | 40 ms | 100 Mbit/s | 0.1 % | 160 pkts | 32 MiB |
| wan-1 | 40 ms | 100 Mbit/s | 1 % | 160 pkts | 8 MiB |
| metro-0.1 | 10 ms | 200 Mbit/s | 0.1 % | 80 pkts | 64 MiB |
| lossy-5 | 20 ms | 50 Mbit/s | 5 % | 80 pkts | 4 MiB |
| shallow | 20 ms | 100 Mbit/s | 0 | 16 pkts | 128 MiB |
| virt (on request) | 0.1 ms | 10 Gbit/s | 0 | 256 pkts | 256 MiB |

### Results

Upload — the compared stack sends to a Linux receiver. Goodput in MiB/s,
median (min–max) of 5 runs; retransmitted segments / router drops, medians.

| Profile | tcp-sans-io | Linux Reno | Linux CUBIC | Retransmits / drops: tcp-sans-io · Reno · CUBIC |
|---|---|---|---|---|
| lan | 113.78 (113.71–113.86) | 113.82 (113.82–113.83) | 113.82 (113.82–113.83) | 230 / 230 · 193 / 193 · 41 / 41 |
| wan | 10.80 (10.80–10.80) | 10.77 (10.77–10.77) | 11.22 (11.21–11.23) | 236 / 236 · 449 / 449 · 20 / 20 |
| wan-0.1 | 1.62 (1.28–2.08) | 1.57 (1.46–2.69) | 1.66 (1.09–2.14) | 197 / 197 · 23 / 23 · 37 / 37 |
| wan-1 | 0.50 (0.45–0.61) | 0.41 (0.36–0.55) | 0.44 (0.40–0.59) | 56 / 57 · 58 / 58 · 55 / 55 |
| metro-0.1 | 5.95 (5.54–6.91) | 5.63 (4.95–6.07) | 5.06 (5.05–5.69) | 278 / 278 · 270 / 270 · 69 / 69 |
| lossy-5 | 0.41 (0.41–0.45) | 0.32 (0.30–0.33) | 0.25 (0.23–0.29) | 152 / 152 · 150 / 150 · 145 / 145 |
| shallow | 9.26 (9.26–9.73) | 9.13 (9.13–9.13) | 10.24 (10.24–10.24) | 160 / 160 · 155 / 155 · 145 / 145 |

Download — Linux CUBIC sends; the compared stack receives (5 runs for
tcp-sans-io; 10 for Linux, 15 on `lan`).

| Profile | tcp-sans-io receiver | Linux receiver | Sender retransmits / drops: to tcp-sans-io · to Linux |
|---|---|---|---|
| lan | 113.79 (113.78–113.80) | 113.79 (113.79–113.80) | 44 / 43 · 43 / 41 |
| wan | 11.17 (11.17–11.17) | 11.19 (11.19–11.19) | 26 / 26 · 20 / 20 |
| wan-0.1 | 1.80 (1.73–1.91) | 1.85 (1.44–2.84) | 46 / 46 · 37 / 37 |
| wan-1 | 0.41 (0.38–0.50) | 0.43 (0.35–0.53) | 58 / 58 · 58 / 58 |
| metro-0.1 | 5.57 (4.95–5.72) | 5.33 (4.50–6.30) | 62 / 62 · 60 / 60 |
| lossy-5 | 0.24 (0.24–0.25) | 0.26 (0.21–0.30) | 159 / 157 · 146 / 146 |
| shallow | 10.25 (10.25–10.25) | 10.23 (10.19–10.36) | 158 / 158 · 145 / 145 |

CPU: the tcp-sans-io endpoint process (stack, cgo, Go runtime and one TUN read/write syscall per packet) used 1.95 CPU-seconds per GiB sent at 1 Gbit/s.

Reading the numbers:

- **Clean paths**: line rate, the same as Linux.
- **Random loss**: Reno-class goodput, at or above Linux Reno. At these
  RTTs Linux CUBIC runs in its Reno-friendly region and is no faster; the
  0.1 % profiles vary most because the first random loss decides when slow
  start ends.
- **Efficiency**: tcp-sans-io's retransmissions match router drops in
  every cell, and no stack needed an RTO. The extra retransmissions in the
  `lan` and `lossy-5` download rows are Linux's; on `lan`, packet captures
  show it reacting to our ACKs being reordered on the harness's TUN path
  (their IP IDs arrive out of order). The same effect on data packets is
  why `bench.sh` pins the sending endpoint to one CPU.
- **Slow-start overshoot**: like Linux Reno, tcp-sans-io (no HyStart)
  overflows the queue once at the end of slow start (`wan`: 236 drops; Reno
  449) and repairs it without a timeout; CUBIC's HyStart exits early
  (20 drops).
- **As a receiver**, tcp-sans-io lets Linux CUBIC reach the same goodput as
  a Linux receiver does.

**Re-check after the Linux-alignment changes** (a reduction now halves
`cwnd` rather than FlightSize; Nagle on), on a different host: WSL2,
Linux 6.6, i9-14900K, both endpoints pinned, 3 runs, upload, MiB/s
(tcp-sans-io · Linux Reno · Linux CUBIC): `wan-1` 0.44 · 0.40 · 0.43,
`lossy-5` 0.36 · 0.30 · 0.26, `metro-0.1` 5.43 · 5.48 · 5.52, `wan-0.1`
1.49 · 1.45 · 1.83; every tcp-sans-io retransmission matched a router drop
and none needed an RTO. On the `virt` profile and the same link at 0 and
1 ms RTT (1000-packet queue), tcp-sans-io sent 224, 99 and 243 MiB/s with
no retransmission, probe or timeout; there the TUN harness (one syscall
per packet) is the bottleneck, not the protocol.

### Before and after the hardening

The same harness driving the pre-hardening library (commit `7dfe00b`),
upload direction (3 runs; 1 run for `wan` and `shallow`, where the old
stack needs minutes):

| Profile | Before: goodput MiB/s | Before: router drops / receiver duplicates | After: goodput MiB/s | After: router drops / receiver duplicates |
|---|---|---|---|---|
| wan | 1.00 | 14314 / 27354 | 10.80 (10.80–10.80) | 236 / 0 |
| wan-0.1 | 1.21 (1.15–1.22) | 449 / 4961 | 1.62 (1.28–2.08) | 197 / 0 |
| wan-1 | 0.33 (0.33–0.41) | 146 / 1251 | 0.50 (0.45–0.61) | 57 / 0 |
| lossy-5 | 0.23 (0.21–0.24) | 312 / 781 | 0.41 (0.41–0.45) | 152 / 0 |
| shallow | 0.67 | 9671 / 24215 | 9.26 (9.26–9.73) | 160 / 0 |

The old stack retransmitted data the receiver already held (tens of
thousands of duplicates) until its own retransmissions overflowed the
queue; a single slow-start overshoot was enough to collapse a clean path.

### Deterministic link simulation

`src/sim_tests.rs` runs two TCBs against each other over a seeded
discrete-event link and asserts efficiency, not just completion
(`cargo test --release --lib sim_tests -- --nocapture` prints one line per
scenario):

| Scenario | Goodput | Retransmits / drops | RTOs | TLPs | Duplicates at receiver |
|---|---|---|---|---|---|
| 50 Mbit/s, 20 ms, 64-packet queue (slow-start overshoot) | 5.73 MB/s (95 % of line rate) | 143 / 143 | 0 | 0 | 0 |
| 1 % random loss, 20 ms | 0.93 MB/s (1.05 × Mathis) | 34 / 34 | 0 | 0 | 0 |
| 1 % random loss, 50 ms | 0.33 MB/s (0.93 × Mathis) | 34 / 34 | 0 | 0 | 0 |
| 0.1 % random loss, 20 ms | 9.50 MB/s | 1 / 1 | 0 | 0 | 0 |
| 40 consecutive packets lost in one window | 9.58 MB/s | 40 / 40 | 0 | 0 | 0 |
| Last 3 of 10 segments lost | repaired in 110 ms | 3 / 3 | 0 | 1 | 0 |
| The same on a virtual link (200 µs RTT) | repaired in 10 ms | 3 / 3 | 0 | 1 | 0 |
| Virtual link (200 µs RTT): 3 of 30 lost, then the first retransmission | repaired in 1 ms | 4 / 4 | 0 | 0 | 0 |
| 2 % reordering (+4 ms), no loss | 5.67 MB/s (94 % of line rate) | 1 / 0 | 0 | 0 | 1 (reduction undone; D-SACK widens RACK's window) |
| The same, receiver sends no D-SACK | 5.66 MB/s (94 % of line rate) | 37 / 0 | 0 | 0 | 36 (each reduction undone via timestamps) |
| Virtual link: 10 Gbit/s, 100 µs RTT, 1 % reordering (+100 µs) | 718.7 MB/s | 2 / 0 | 0 | 0 | 2 |
| The same through a 256-packet queue | 656.5 MB/s | 423 / 421 | 0 | 0 | 2 |
| 20 % ACK loss | 5.43 MB/s | 0 / 0 | 0 | 0 | 0 |
| Both directions, 1 % loss each way | 1.11 MB/s | 9 / 9 | 0 | 0 | 0 |
| Slow reader (500 KB/s) | 0.50 MB/s | 0 / 0 | 0 | 0 | 0 |
| 6 chaos seeds: 2 % loss + 3 % reordering both ways, sequence wrap | 0.97–1.78 MB/s | 101 / 93 (one direction) | 0 | 1 | 7 (reordering) |

The senders keep Nagle on (the default) and do not close, so a transfer's
last short segment can wait about one RTT for the ACK of an earlier one
(see *Where it differs from Linux*); in the 2 % reordering rows that costs
about 1 % of goodput. Each loss halves `cwnd` as in Linux Reno, which is
why random loss tracks the Mathis model.

A virtual link (a VMM's virtio ring or a TUN device) has a sub-millisecond
RTT the millisecond clock cannot resolve. The tail-loss row there is
repaired by the probe in 10 ms, not by a 200 ms timeout, and a lost
retransmission by RACK within the millisecond. Mild reordering costs two
needless retransmissions in 32 MiB, both undone. Through a shallow queue,
each overflow costs one halving, not repeated ones.

### Reproducing

```sh
sudo -v                                   # the script re-execs under sudo
bindings/netem/bench.sh                   # all profiles, 5 runs, both directions
bindings/netem/bench.sh --profiles "wan-1 shallow" --runs 3 --dir up \
    --stacks "tcp-sans-io reno cubic"
bindings/netem/bench.sh --profiles wan-1 --baseline-lib /path/to/old/target/release
```

Requires root, `ip`, `tc` (netem), `ethtool`, `taskset`, Go and Python 3.
Results go to `bindings/netem/results-*.jsonl`; `summarize.py` renders the
tables. `TSB_PCAP=dir` captures each run's packet headers at the receiver;
`TSB_CPU=n` picks the CPU the sending endpoint is pinned to (default 2).

## tcp-sans-io vs smoltcp

[smoltcp](https://github.com/smoltcp-rs/smoltcp) is the most widely used
`no_std` TCP/IP stack in Rust. `bindings/smoltcp-shootout/` drives both
stacks through one sans-I/O adapter, over the same simulated links and
against the same scripted peer, and compares correctness, interoperability,
robustness and performance. Everything but the CPU benchmark runs in
virtual time and is deterministic: the report is identical on Linux and
Windows.

smoltcp 0.14.0 is set up for its best showing: CUBIC (its default once a
controller is compiled in; Reno where noted), timestamps on, 1 MiB socket
buffers (the size of tcp-sans-io's rings) and its largest out-of-order
tracker (32 ranges). Out of the box it has no congestion control, a 4-range
tracker and no timestamps.

| | tcp-sans-io | smoltcp 0.14 |
|---|---|---|
| RFC probes (33) | 32 pass, 1 informational | 20 pass, 6 warnings, 4 failures, 3 informational |
| Interop: 16 cases × 4 client/server pairings | 48 / 48 runs involving it pass | 48 / 48 runs involving it pass |
| 1 M fuzzed segments | no panics, no invariant violations | no panics |
| Goodput as a sender | 1.6–19× smoltcp's with tcp-sans-io receiving, 1.4–19× with smoltcp receiving; near line rate on clean paths, 10 Gbit/s virtual links included | every loss its single fast retransmit cannot repair costs a ≥ 1 s RTO and a go-back-N resend |
| CPU, bulk transfer, one packet per call (Gbit/s per core) | 33.8 sending, 41.3 receiving | 35.8 sending, 36.9 receiving |
| CPU, 64 B request/response (transactions per core-second) | 1.58 M | 1.56 M |
| State per connection besides the data buffers | 78 KiB | 960 B (+ 184 B per interface) |

### RFC probes

A scripted raw peer puts each stack into a state, sends a crafted segment
and checks the reply. ✅ meets the RFC's requirement or recommendation
(for an optional feature: implements it), ⚠️ survives but falls short of
it, ❌ violates it, ℹ️ describes behaviour without a verdict. The
loss-recovery probes model a 10 ms RTT after a 64 KiB warm-up.

| Probe | RFC | tcp-sans-io | smoltcp |
|---|---|---|---|
| **SYN options**: options offered in our SYN | 9293, 7323, 2018 | ✅ MSS 1460, WS 5, SACK, TS | ✅ MSS 1460, WS 5, SACK, TS |
| **SYN-ACK echoes only offered options**: peer offers MSS only | 7323 §2.2, 2018 §2 | ✅ MSS 1460 | ✅ MSS 1460 |
| **declined options unused**: SYN-ACK without TS/SACK: none sent later | 7323 §3.2, 2018 §2 | ✅ | ✅ |
| **peer MSS honoured**: peer MSS 536: data + options ≤ 536 | 9293 §3.7.1, 6691 | ✅ ≤ 536 B | ✅ ≤ 536 B |
| **window scale honoured**: WS 7, window field 4 = 512 B | 7323 §2.3 | ✅ 512 B | ✅ 512 B |
| **simultaneous open**: SYNs cross | 9293 §3.5 (MUST-10) | ✅ | ✅ |
| **blind in-window RST**: RST at RCV.NXT+1000 | 5961 §3 | ✅ challenge ACK | ❌ connection reset by a blind in-window RST |
| **RST at RCV.NXT**: exact RST resets | 9293 §3.10.7.4 | ✅ | ✅ |
| **out-of-window RST**: ignored, no reply | 9293 §3.10.7.4 | ✅ | ✅ |
| **SYN in ESTABLISHED**: challenge ACK, survive | 5961 §4 | ✅ challenge ACK | ⚠️ dropped silently |
| **ACK of unsent data**: data with SEG.ACK > SND.NXT dropped | 9293 §3.10.7.4 | ✅ dropped, ACK sent | ✅ dropped, ACK sent |
| **old ACK, valid data**: SEG.ACK < SND.UNA in window: data kept | 9293 §3.10.7.4, 5961 §5.2 | ✅ | ❌ segment discarded because its ACK field was old |
| **ACK below SND.UNA−MAX.SND.WND**: blind data injection dropped | 5961 §5.2 | ✅ | ✅ |
| **PAWS**: old TSval segment dropped | 7323 §5.3 | ✅ old-timestamp segment dropped | ❌ accepted a segment with an old timestamp (200 B read) |
| **out-of-order holding**: 40 separate ranges, then the holes | 9293 §3.10.7.4 | ✅ held all 40 ranges | ⚠️ held 32 of 40 ranges |
| **SACK blocks**: most recent block first | 2018 §4 | ✅ | ⚠️ older block not repeated |
| **D-SACK**: duplicate reported | 2883 | ✅ yes | ℹ️ no |
| **out-of-order FIN**: EOF only after the hole fills | 9293 §3.10.7.4 | ✅ | ⚠️ FIN discarded: the peer must resend it |
| **immediate ACK for out-of-order data**: dup ACK not delayed | 5681 §4.2 | ✅ immediate | ✅ immediate |
| **ACK every 2nd full segment**: 8 segments, 120 µs apart | 9293 §3.8.6.3, 5681 §4.2 | ✅ 8 ACKs / 8 segments | ✅ 4 ACKs / 8 segments |
| **delayed ACK < 500 ms**: one small segment | 9293 §3.8.6.3 (MUST-40) | ✅ 0 ms | ✅ 10 ms |
| **bad checksum dropped**: flipped payload byte | 9293 §3.1 | ✅ | ✅ |
| **RTO backoff**: intervals between retransmissions | 6298 §5.5 | ✅ TLP 0.2 s, then 0.2, 0.4, 0.8, 1.6 s | ✅ 1.0, 2.0, 4.0, 8.0, 16.0 s |
| **fast retransmit**: 3 dup ACKs: resend before RTO | 5681 §3.2 | ✅ repaired in 10 ms | ✅ repaired in 10 ms |
| **SACK loss recovery**: 3 holes in 20 segments | 6675, 8985 | ✅ 10 ms, 3 resent, 0 needlessly | ⚠️ 1030 ms, 4 resent, 1 needlessly |
| **zero-window probing**: probe, back off, resume | 9293 §3.8.6.1 (MUST-35/36) | ✅ probes after 0.2, 0.4, 0.8, 1.7 s | ✅ probes after 1.0, 2.0, 4.0, 8.0 s |
| **tail loss**: last 3 of 10 lost | 8985 §7 | ✅ repaired in 50 ms, 3 resent | ℹ️ repaired in 1020 ms, 3 resent |
| **gives up on a dead peer**: R2 / user timeout | 9293 §3.8.3 (MUST-20) | ✅ gave up after 230 s | ⚠️ still retransmitting after 30 min |
| **TIME_WAIT re-ACKs FIN**: retransmitted FIN | 9293 §3.10.7.4 | ✅ TIME_WAIT 60 s | ✅ TIME_WAIT 10 s |
| **FIN retransmitted**: unacknowledged FIN | 9293 §3.10.4 | ✅ after 201 ms | ✅ after 1000 ms |
| **send in CLOSE_WAIT**: half-close: data after peer's FIN | 9293 §3.10.4 | ✅ | ✅ |
| **one spoofed SYN**: can a legitimate client still connect? | 4987 | ✅ legitimate client served | ❌ legitimate client refused (no SYN-ACK); still refused 2 min later |
| **ACK to a listener**: RST or silence | 9293 §3.10.7.2 | ℹ️ dropped silently | ℹ️ RST |

smoltcp's failures, each confirmed against its source:

- **Blind in-window RST**: any RST inside the receive window closes the
  connection, so an off-path attacker needs about 2^32 / window guesses
  instead of 2^32.
- **Old ACK, valid data**: a segment whose ACK field is below SND.UNA is
  discarded whole; RFC 9293 ignores only the ACK field. With reordering
  in both directions this throws away data that then has to be resent.
- **PAWS**: timestamps are echoed but never used to reject old segments.
- **One spoofed SYN**: a listening socket holds one half-open connection
  and never times it out, so one SYN from an address that never answers
  pins it; other clients get an RST. tcp-sans-io answers with SYN cookies
  while its half-open slot is busy.

tcp-sans-io's silence towards an ACK sent to a listener is deliberate (no
reflection; see *Threat model*).

### Interop matrix

Each case runs both directions (client → server is the column), verifies
every byte against its generator, and requires EOF on both sides and a
clean CLOSED / TIME_WAIT without an RST (in the abort case the other side
must see the RST and both must be CLOSED within a second). Times run from
ESTABLISHED to the last byte delivered; *rtx* is data segments that
resent sequence space, both directions.

| Case (client → server) | tcp-sans-io → smoltcp | smoltcp → tcp-sans-io | tcp-sans-io → tcp-sans-io | smoltcp → smoltcp |
|---|---|---|---|---|
| **clean**: 1 MiB each way; 10 ms RTT, 100 Mbit/s | ✅ 202 ms · 0 rtx | ✅ 207 ms · 0 rtx | ✅ 134 ms · 0 rtx | ✅ 172 ms · 0 rtx |
| **loss 2%**: 2% random loss both ways | ✅ 1.92 s · 36 rtx | ✅ 1.82 s · 28 rtx | ✅ 825 ms · 26 rtx | ✅ 3.97 s · 42 rtx |
| **reorder 3%**: 3% of packets held back 3 ms, both ways | ✅ 544 ms · 29 rtx | ✅ 696 ms · 24 rtx | ✅ 131 ms · 9 rtx | ✅ 1.99 s · 28 rtx |
| **duplicate 2%**: 2% of packets delivered twice | ✅ 203 ms · 0 rtx | ✅ 206 ms · 0 rtx | ✅ 134 ms · 0 rtx | ✅ 172 ms · 0 rtx |
| **corrupt 1%**: 1% of packets get a flipped byte (checksums must catch it) | ✅ 678 ms · 24 rtx | ✅ 685 ms · 21 rtx | ✅ 599 ms · 11 rtx | ✅ 1.70 s · 26 rtx |
| **kitchen sink**: 1% loss, 1% reorder, 1% duplicate, 0.5% corrupt, both ways | ✅ 1.95 s · 41 rtx | ✅ 869 ms · 32 rtx | ✅ 701 ms · 27 rtx | ✅ 5.28 s · 30 rtx |
| **ACK loss 20%**: 2 MiB upload; 20% of the reverse path lost | ✅ 202 ms · 0 rtx | ✅ 1.87 s · 1 rtx | ✅ 203 ms · 0 rtx | ✅ 3.94 s · 2 rtx |
| **SYN, SYN-ACK lost**: first SYN and first SYN-ACK dropped | ✅ 122 ms · 0 rtx | ✅ 128 ms · 0 rtx | ✅ 32 ms · 0 rtx | ✅ 138 ms · 0 rtx |
| **server MTU 576**: server MSS 536: both directions must honour it | ✅ 84 ms · 0 rtx | ✅ 107 ms · 0 rtx | ✅ 72 ms · 0 rtx | ✅ 99 ms · 0 rtx |
| **slow reader**: 64 KiB buffers; 1 MiB to a 100 KB/s reader (zero windows) | ✅ 10.48 s · 0 rtx | ✅ 10.48 s · 0 rtx | ✅ 10.48 s · 0 rtx | ✅ 10.48 s · 0 rtx |
| **4 KiB smoltcp window**: smoltcp with 4 KiB buffers; 256 KiB each way | ✅ 1.19 s · 0 rtx | ✅ 1.19 s · 0 rtx | ✅ 59 ms · 0 rtx | ✅ 835 ms · 0 rtx |
| **half-close**: 64 KiB request + FIN, then 1 MiB response + FIN | ✅ 177 ms · 0 rtx | ✅ 171 ms · 0 rtx | ✅ 142 ms · 0 rtx | ✅ 253 ms · 0 rtx |
| **simultaneous close**: 64 KiB each way, then both FIN at t=200 ms (FINs cross) | ✅ 122 ms · 0 rtx | ✅ 119 ms · 0 rtx | ✅ 32 ms · 0 rtx | ✅ 77 ms · 0 rtx |
| **sequence wrap**: both ISNs within 1 MiB of 2^32; 2 MiB each way, 1% loss | ✅ 1.16 s · 35 rtx | ✅ 1.13 s · 39 rtx | ✅ 1.10 s · 24 rtx | ✅ 3.46 s · 42 rtx |
| **no timestamps**: smoltcp without its TS generator (its default); 1% loss | ✅ 1.66 s · 19 rtx | ✅ 611 ms · 14 rtx | ✅ 542 ms · 12 rtx | ✅ 1.72 s · 23 rtx |
| **peer aborts**: server aborts (RST) after 256 KiB of a 1 MiB upload | ✅ | ✅ | ✅ | ✅ |

- In the *loss*, *reorder*, *corrupt*, *kitchen sink* and *no
  timestamps* rows the slow direction is smoltcp's: in the mixed pairs
  tcp-sans-io's stream finishes in 0.40–0.85 s, smoltcp's in 0.55–1.96 s.
  smoltcp counts only payload-free duplicate ACKs that leave the window
  unchanged, so the other side's data segments, which carry the same ACK,
  and a window the receiving application opened by reading both reset its
  count; a missed fast retransmit then waits out its 1 s minimum RTO (the
  cells near 2 s).
- **ACK loss**: smoltcp starts with a 2 KB congestion window, so one lost
  ACK early on leaves nothing in flight and it waits out its 1 s minimum
  RTO (twice, here).
- **4 KiB window**: after two full segments a 4 KiB window leaves 1.2 KB.
  tcp-sans-io, like Linux, will not send a sub-MSS segment into it while
  more data is queued (sender SWS avoidance), so it moves 2.9 KB per round
  trip; smoltcp's sender fills the window with a 1.2 KB segment.

### Robustness

The same deterministic stream of hostile segments (random flags, sequence
and ACK numbers near the live ones, malformed and random options, byte
flips with and without repaired checksums, truncation) goes to a listener
and to an established connection of each stack; a connection that ends is
re-established.

| Stack | Segments | Panics | Invariant violations | Connections reset by a fuzzed segment |
|---|---|---|---|---|
| tcp-sans-io | 1000000 | 0 | 0 | 2291 |
| smoltcp | 1000000 | 0 | n/a | 46902 |

The reset counts mostly follow from the RST rule above: smoltcp honours
any in-window RST, tcp-sans-io only one at exactly RCV.NXT.

### Goodput over a simulated link

The profiles of *Benchmarks* in the shootout's discrete-event link (data
path: delay, rate-limited tail-drop queue, loss or reordering; ACK path:
delay only), plus *virt-reorder*, the virtual link with 1 % of packets
0.1 ms late. Upload goodput in Mbit/s, median (min–max) of 5 seeds; the
columns pair a sender with a receiver, so each stack is compared as a
sender against the same receiver and vice versa. The sender keeps its
connection open (a FIN queued behind the data would switch smoltcp's
Nagle off for the rest of the transfer), and with the same seed both
senders meet the same random losses.

| Profile (sender → receiver) | tcp-sans-io → tcp-sans-io | smoltcp → smoltcp | smoltcp/reno → smoltcp/reno | smoltcp → tcp-sans-io | tcp-sans-io → smoltcp |
|---|---|---|---|---|---|
| **lan**: 1 ms, 1000 Mbit/s, 200-pkt queue; 64 MiB | 960.5 | 199.5 | 335.4 | 327.3 | 954.9 |
| **wan**: 40 ms, 100 Mbit/s, 160-pkt queue; 32 MiB | 89.6 | 19.0 | 54.3 | 24.1 | 88.8 |
| **wan-0.1**: 40 ms, 100 Mbit/s, 160-pkt queue, 0.1% loss; 16 MiB | 15.2 (10.9–20.4) | 8.9 (8.4–12.3) | 9.1 (7.0–12.5) | 9.2 (8.3–11.7) | 15.0 (10.9–19.8) |
| **wan-1**: 40 ms, 100 Mbit/s, 160-pkt queue, 1% loss; 4 MiB | 4.3 (3.3–4.6) | 2.6 (1.8–3.5) | 2.5 (1.6–3.0) | 2.5 (1.7–3.3) | 4.3 (3.3–4.6) |
| **metro-0.1**: 10 ms, 200 Mbit/s, 80-pkt queue, 0.1% loss; 32 MiB | 49.0 (41.1–55.0) | 35.6 (22.8–37.4) | 31.5 (25.6–32.4) | 26.5 (25.2–37.8) | 48.8 (41.1–55.0) |
| **lossy-5**: 20 ms, 50 Mbit/s, 80-pkt queue, 5% loss; 2 MiB | 3.0 (2.8–3.2) | 0.3 (0.3–0.4) | 0.3 (0.3–0.4) | 0.4 (0.4–0.5) | 3.0 (2.8–3.2) |
| **shallow**: 20 ms, 100 Mbit/s, 16-pkt queue; 32 MiB | 62.7 | 35.9 | 36.0 | 36.4 | 62.4 |
| **reorder-2**: 20 ms, 50 Mbit/s, 1000-pkt queue, 2% +4 ms reorder; 8 MiB | 46.1 (45.4–46.4) | 6.9 (6.2–7.9) | 6.6 (6.1–6.9) | 7.3 (6.1–7.9) | 45.8 (45.5–46.1) |
| **burst-40**: 20 ms, 100 Mbit/s, 1000-pkt queue, 40 consecutive drops; 4 MiB | 76.7 | 12.0 | 11.9 | 12.3 | 76.6 |
| **virt**: 0.1 ms, 10000 Mbit/s, 256-pkt queue; 64 MiB | 9596.2 | 499.6 | 499.7 | 500.4 | 9531.5 |
| **virt-reorder**: 0.1 ms, 10000 Mbit/s, 256-pkt queue, 1% +0.1 ms reorder; 32 MiB | 8315.3 (8161.1–8644.2) | 953.7 (884.4–987.3) | 927.8 (879.2–946.2) | 1068.0 (885.9–1095.8) | 7729.0 (6446.3–9542.0) |

Retransmitted segments / data segments the link dropped / retransmissions
of data the link had already delivered (medians; a receiver may have
discarded what it was delivered, see below), counted until the wire
settles after delivery (both links idle, nothing unacknowledged; at most
10 s), so late retransmissions, tail-loss probes and timeouts count too:

| Profile | tcp-sans-io → tcp-sans-io | smoltcp → smoltcp | smoltcp/reno → smoltcp/reno | smoltcp → tcp-sans-io | tcp-sans-io → smoltcp |
|---|---|---|---|---|---|
| lan | 290 / 290 / 0 | 458 / 155 / 303 | 422 / 143 / 279 | 454 / 142 / 312 | 511 / 290 / 221 |
| wan | 162 / 162 / 0 | 712 / 239 / 473 | 679 / 228 / 451 | 723 / 231 / 492 | 268 / 172 / 96 |
| wan-0.1 | 172 / 172 / 0 | 167 / 52 / 115 | 17 / 17 / 0 | 193 / 60 / 133 | 277 / 181 / 96 |
| wan-1 | 23 / 23 / 0 | 23 / 23 / 0 | 23 / 23 / 0 | 23 / 23 / 0 | 23 / 23 / 0 |
| metro-0.1 | 104 / 104 / 0 | 385 / 144 / 241 | 385 / 144 / 241 | 478 / 160 / 318 | 120 / 104 / 16 |
| lossy-5 | 78 / 78 / 0 | 84 / 78 / 7 | 84 / 78 / 6 | 90 / 80 / 13 | 78 / 78 / 0 |
| shallow | 26 / 26 / 0 | 34 / 12 / 22 | 37 / 12 / 25 | 34 / 12 / 22 | 26 / 26 / 0 |
| reorder-2 | 1 / 0 / 1 | 29 / 0 / 29 | 31 / 0 / 31 | 31 / 0 / 31 | 34 / 0 / 34 |
| burst-40 | 40 / 40 / 0 | 78 / 40 / 38 | 78 / 40 / 38 | 78 / 40 / 38 | 40 / 40 / 0 |
| virt | 388 / 388 / 0 | 508 / 172 / 336 | 508 / 172 / 336 | 503 / 173 / 330 | 624 / 346 / 278 |
| virt-reorder | 381 / 380 / 1 | 188 / 0 / 188 | 178 / 0 / 178 | 196 / 0 / 196 | 12 / 0 / 12 |

Reading the numbers:

- **smoltcp as a sender** repairs one segment per three duplicate ACKs and
  everything else by timeout: at least 1 s, after which it resends from
  SND.UNA whatever the receiver already holds (the third number, against
  tcp-sans-io's receiver, which keeps everything it is given). On *wan-1*
  and *lossy-5* both senders lose exactly the same segments and resend
  about as many; smoltcp's 1.7× and 10× lower goodput there is time spent
  waiting out timeouts. Even a clean path costs it a timeout when slow
  start overflows the queue.
- **tcp-sans-io as a sender** never resent data its own receiver held,
  apart from the one retransmission that teaches it a path reorders.
  Against smoltcp's receiver it resends data the link did deliver: smoltcp
  keeps at most 32 out-of-order ranges and discards segments beyond them
  (a slow-start overflow leaves hundreds of holes), and it reports one
  SACK block per ACK where RFC 2018 asks for as many as fit.
- **Reordering without D-SACK**: smoltcp never reports a duplicate, so
  tcp-sans-io learns that a "lost" segment was only delayed from the
  timestamp echo instead (RFC 3522 detection, as Linux) and undoes the
  window cut, which keeps *reorder-2* at 46 Mbit/s, as with its own
  receiver. As in Linux, only D-SACKs widen RACK's reordering window
  beyond min_RTT/4, so the 4 ms reordering still costs 34 needless
  retransmissions per 8 MiB against smoltcp's receiver, and one against
  tcp-sans-io's.
- **Virtual links** (*virt*, *virt-reorder*: 0.1 ms RTT, 10 Gbit/s, a
  256-packet queue): both stacks overflow the queue when slow start ends.
  tcp-sans-io repairs that with SACK and RACK and runs at 96 % of the link,
  smoltcp's go-back-N resend after a 1 s timeout holds it to 0.5 Gbit/s.
  Reordering below the millisecond clock's resolution costs tcp-sans-io one
  needless retransmission per 32 MiB; its other retransmissions repair
  queue overflows, each answered by one halving of the window.
- **As receivers** the two are close: with tcp-sans-io sending, smoltcp's
  receiver costs at most 3 % (7 % on *virt-reorder*).

### CPU cost

Wall-clock time inside each stack's calls (send/recv copies, checksums,
protocol work), both endpoints in one thread over a zero-delay in-memory
wire; the wire and the data verification are not counted. Intel Core
i9-14900K, one P-core (`taskset -c 4`), Linux 6.6 (WSL2); median of 7
interleaved runs, ± half the range.

| Bulk transfer, 1 GiB (sender → receiver) | Sender Gbit/s, per packet | Receiver Gbit/s, per packet | ACKs / 100 segments, per packet | Sender Gbit/s, batched | Receiver Gbit/s, batched | ACKs / 100 segments, batched |
|---|---|---|---|---|---|---|
| tcp-sans-io → tcp-sans-io | 35.7 ±3% | 43.6 ±5% | 51 | 35.3 ±3% | 42.9 ±4% | 51 |
| smoltcp → smoltcp | 37.4 ±3% | 38.5 ±3% | 50 | 50.3 ±4% | 53.1 ±4% | 0 |

| 64 B request / 64 B response (client ⇄ server) | Client µs / transaction | Server µs / transaction | Packets / transaction | Transactions per core-second (both ends) |
|---|---|---|---|---|
| tcp-sans-io ⇄ tcp-sans-io | 0.35 ±3% | 0.31 ±4% | 2.00 | 1519603 |
| smoltcp (Nagle off) ⇄ smoltcp (Nagle off) | 0.35 ±2% | 0.28 ±2% | 2.00 | 1587469 |

*Per packet* hands each datagram over and lets the stack act on it before
the next (one read per packet, as from a TUN or WireGuard device);
*batched* hands a side the whole flight and lets it act once. Per packet
both stacks ACK about every second segment; tcp-sans-io costs 5 % more to
send with (its Linux-style loss recovery, RTT estimator and window
validation run on every ACK) and receives 12 % cheaper; a request and
response cost it 4 % more. Batched, smoltcp
answers a whole flight
(up to 1 MiB) with a single ACK: cheaper, but a stretch ACK that would
make the sender burst on a real path. The cross pairs are left out on
purpose: alternating two code bases on one core costs both of them cache
misses.

### Memory per connection

| Per-connection state | Bytes | Of which data buffers |
|---|---|---|
| tcp-sans-io (1 MiB rings) | 2176968 | 2097152 |
| tcp-sans-io (64 KiB rings, `Tcb<65536>`) | 210888 | 131072 |
| smoltcp socket | 960 | caller-supplied |
| smoltcp `Interface` (per interface) | 184 | — |

tcp-sans-io's 78 KiB beyond the rings is the 48 KiB egress staging ring,
the 24 KiB retransmission queue and the 6 KiB out-of-order tracker; smoltcp
keeps no retransmission state (it resends from the send buffer) and
tracks at most 32 out-of-order ranges.

### Reproducing

```sh
cd bindings/smoltcp-shootout
cargo run --release                         # the full report (~40 s)
cargo run --release -- --check              # CI gate: probes, interop, fuzzing (~2 s)
cargo run --release -- --only sim,cpu --quick
taskset -c 4 target/release/shootout --only cpu        # pin for stable CPU numbers
cargo run --release -- --case "loss 2%" --pair smol,ours --trace   # one interop case, every packet
cargo run --release -- --profile reorder-2 --pair ours,smol        # one goodput cell, with stack stats
PROBE_TRACE=1 cargo run --release -- --probe PAWS --stack smol     # one probe, every segment
```

`--check` exits non-zero if any tcp-sans-io probe result is not ✅ (the
informational *ACK to a listener* aside), an interop case involving it
fails, or the fuzzer finds a panic or an invariant violation; smoltcp's
results are reported only. CI runs it on every push, and the
`perf-bench` workflow adds the full report to its summary.

## Building

```sh
cargo build --release --lib       # cdylib + staticlib + rlib
cargo test  --release --lib       # 253 tests: unit, conformance, loopback, property, server, security regressions, link simulation, smoltcp interop
cargo clippy --release --lib --no-deps -- -D warnings
```

The C header is in `include/tcp_sans_io.h` (hand-maintained — keep in sync
with `src/ffi.rs`).

## Bindings

- **C** — `include/tcp_sans_io.h`.
- **C#** — `bindings/csharp/` (`TcpStream.cs`, `Native.cs`, integration test).
- **Python** — `bindings/python/` (ctypes wrapper + unittest suite).
- **Go** — `bindings/gvisor/` (gVisor netstack interop tests),
  `bindings/netem/` (real Linux kernel interop + throughput benchmark),
  `bindings/realworld/` (HTTP/1.1, HTTPS, h2spec, git clone),
  `bindings/wgserver/` (pure-Go raw-packet driver + adversarial stress
  suite over a userspace UDP "WG-shaped" transport — no root, no TUN,
  cross-platform).
- **Rust harness** — `bindings/wgserver-rs/` (standalone server binary
  multiplexing N TCBs on a single UDP socket; depends on the parent
  crate as an rlib).
- **Conformance harness** — `bindings/conformance/` (standalone
  self-loopback certifier; drives two stacks against each other through
  the C ABI over a chaos channel and hash-verifies the transfer — no
  external stack or root needed; `cargo run --release`).
- **smoltcp shootout** — `bindings/smoltcp-shootout/` (tcp-sans-io vs
  smoltcp: RFC probes, interop matrix, fuzzing, goodput and CPU; see
  *tcp-sans-io vs smoltcp*).

All use the host-allocated storage pattern: query
`tcp_handle_size()` / `tcp_handle_align()`, allocate that much memory in the
host, pass the pointer to `tcp_init`. Memory ownership stays with the host.

## Integrating the library

This is a **sans-I/O** stack: it owns the TCP protocol state machine and
*nothing else*. **The host owns the clock, the memory, the datagram
transport, the scheduling, and the application data flow.** The stack
never allocates, never blocks, never spawns a thread, never reads the
clock, and never touches a socket. You drive it; it tells you what bytes
to put on the wire and hands you back the bytes the peer sent.

### What the host must provide

1. **Per-connection storage** — `tcp_handle_size()` bytes at
   `tcp_handle_align()` alignment, owned and freed by you. One block per
   connection (TCB).
2. **A monotonic millisecond clock** — see *Clock model and tick cadence*.
   Read it once per turn; pass the same `now_ms` into every call that turn.
3. **A datagram transport** — something that moves raw IPv4+TCP datagrams
   to/from the peer (a WireGuard tunnel, a UDP socket, a TUN device…).
   The stack hands you complete IP datagrams to send and expects complete
   IP datagrams back.
4. **A driver loop** that pumps the four interaction points (inject /
   tick / extract / send-recv) and ticks when `tcp_next_deadline()` comes
   due (or periodically) **even when idle**.
5. **Secrets and ISNs** — a high-entropy `iss` (RFC 6528) per active open
   from a CSPRNG, never a counter; and a 16-byte CSPRNG secret via
   `tcp_set_secret` (keys timestamp offsets, passive-open ISNs and the
   SYN-cookie key) on every listener — `tcp_listen` fails without one — and
   on anything internet-facing. `tcp_set_cookie_secret` optionally installs
   an explicit, rotatable cookie key (cookies survive one rotation).
6. **The path MTU** — `tcp_set_mtu` before the handshake when the tunnel
   MTU is below 1500 (1420 for a default WireGuard interface), and
   `tcp_update_pmtu` if you receive ICMP "fragmentation needed".
7. **5-tuple demux** — route each inbound datagram to the TCB that owns
   its 4-tuple. The stack rejects mismatches with `NOT_FOR_US`, but you
   shouldn't rely on that for routing N connections. A listener may also
   accept SYNs and cookie ACKs from *other* peers while its half-open slot
   is busy, and its replies are addressed to them: route every outbound
   packet by its own destination address, not by the TCB that emitted it.
8. **Admission control** — a cap on concurrent TCBs (including those in
   `TIME_WAIT`, which hold their storage for 60–120 s) and on half-open
   listeners per source; the stack bounds how long a stalled or vanished
   peer holds a connection, never the count — and never a live peer you
   keep serving (apply application deadlines for those).

### The canonical pump loop

One "turn" of the driver, for an active (client) connection. Server is
identical except you call `tcp_listen` instead of `tcp_connect` and watch
for the `HALF_OPEN` → `ESTABLISHED` transition.

```c
// --- one-time setup ---
if (tcp_selftest() != 0) abort();      // smoke-test linkage/ABI/health first
void* mem = aligned_alloc(tcp_handle_align(), tcp_handle_size());
tcp_init(mem, local_ip, local_port, remote_ip, remote_port,
         csprng_u32(), /*initial_rto_ms=*/1000);
tcp_set_secret(mem, host_secret16);    // 16 CSPRNG bytes, shared host-wide
tcp_set_mtu(mem, 1420);                // e.g. behind a default WireGuard link
tcp_connect(mem, now_ms());            // or tcp_listen(mem, now_ms())

uint8_t pkt[1500];                     // MUST be >= tcp_max_packet()
size_t  n;

// --- per turn: on packet arrival, app activity, or tcp_next_deadline() ---
uint64_t now = now_ms();               // one clock read; reuse all turn

// 1. Feed every inbound datagram, draining responses after each.
for (each datagram d from the wire for this 4-tuple) {
    int rc = tcp_inject_packet(mem, d.buf, d.len, now);
    // rc < 0 for NOT_FOR_US / MALFORMED_PACKET / INVALID_STATE is benign:
    // drop the datagram and continue. (OVERFLOW must never happen.)
    while (tcp_extract_packet(mem, pkt, sizeof pkt, &n) == 0 && n > 0)
        wire_send(pkt, n);             // drain BEFORE the next inject
}

// 2. Application I/O, gated on poll(). NOTE: tcp_send only *buffers* into
//    the send ring — it stages no packets itself; the next tcp_tick (or
//    inbound inject) turns those bytes into segments. tcp_recv copies out.
uint32_t ev = tcp_poll(mem);
if (ev & TCP_EV_WRITABLE) {
    size_t w;
    int rc = tcp_send(mem, app_out, app_out_len, &w);   // rc == WOULD_BLOCK ⇒ ring full, retry later
}
if (ev & TCP_EV_READABLE) {
    size_t r;
    int rc = tcp_recv(mem, app_in, sizeof app_in, &r);  // rc == CONNECTION_CLOSED ⇒ peer EOF
    // (recv may stage a window update; step 3 drains it.)
}

// 3. Drive timers (RTO / TLP / TIME_WAIT / persist / delayed-ACK) AND flush
//    the data just buffered by tcp_send; then drain everything to the wire.
tcp_tick(mem, now);
while (tcp_extract_packet(mem, pkt, sizeof pkt, &n) == 0 && n > 0)
    wire_send(pkt, n);

// 4. Sleep until the next datagram or timer, whichever is first.
uint64_t due = tcp_next_deadline(mem); // UINT64_MAX: no timer armed
wait_for_datagram_or_until(due);       // e.g. epoll_wait(.., due - now_ms())

// --- shutdown ---
tcp_close(mem, now_ms());              // then keep pumping turns until
// tcp_state(mem) == TCP_STATE_CLOSED  (FIN handshake + TIME_WAIT complete);
tcp_destroy(mem);                      // releases what the TCB owns (not mem)
free(mem);                             // you own the memory
```

### The contract — do X, not Z

**MUST**
- Size every `extract_packet` buffer to **≥ `tcp_max_packet()`** (1500). A
  smaller buffer returns `BUFFER_TOO_SMALL` and leaves the packet staged.
- **Drain `extract_packet` in a loop until it returns 0** after every
  `inject_packet`, `tick`, `close` and `recv`. The egress ring holds only
  `TX_RING_CAP` (32) packets; not draining stalls emission. (`send` stages
  nothing itself — it buffers; the next `tick` flushes it.)
- **Tick when `tcp_next_deadline()` comes due**, even when no packets
  arrive (or on a ~10 ms timer) — timers only fire there (see *Clock
  model*).
- Pass a **monotonic, non-decreasing `now_ms`**; use the same value for
  every call within a turn.
- Seed `iss` from a **CSPRNG** (per connection), and install a CSPRNG
  secret with `tcp_set_secret` on every listener (`tcp_listen` returns
  `INVALID_STATE` without one) and on internet-facing TCBs. An explicit
  cookie secret (`tcp_set_cookie_secret`) is optional; rotate it no more
  often than every ~2 minutes (only the previous key is kept).
- **Set the MTU** (`tcp_set_mtu`) to the tunnel's real MTU before the
  handshake — 1420 behind a default WireGuard interface — so no datagram
  needs fragmenting.
- After `tcp_close`, **keep pumping** until `tcp_state` is `CLOSED`; only
  then `tcp_destroy` + free.
- **Bound the number of concurrent TCBs** and refuse/evict past that budget.
  Each TCB is independent and costs `tcp_handle_size()` (~2.08 MiB default,
  136 KiB under `small-buffers`) — including for the 60–120 s it spends in
  `TIME_WAIT`; the per-connection reapers (R2 / USER TIMEOUT / keepalive /
  FIN_WAIT_2, all on by default) bound how long a stalled or vanished peer
  holds a connection, never the aggregate *count* — only the host can do
  that — nor a live peer the application keeps serving. On `PEER_CLOSED` you
  **must** eventually `close`: keepalive reaps an idle `CLOSE_WAIT` only if
  the peer has since vanished, and a live peer keeps it open.

**SHOULD**
- Treat `inject_packet` errors (`NOT_FOR_US`, `MALFORMED_PACKET`,
  `INVALID_STATE`) as *drop-and-continue* — they are normal under a hostile
  or mis-routed wire, not fatal.
- Treat `WOULD_BLOCK` from `send` as backpressure (the send ring is full);
  retry after a later turn drains it. Treat `CONNECTION_CLOSED` from `recv`
  as EOF and `CONNECTION_RESET` as an aborted peer.
- Drive `tick()` *event-driven*: right after a batch of injects or sends,
  and when `tcp_next_deadline()` comes due.
- **Mind Nagle** — on by default, as in Linux: a segment shorter than the
  MSS waits while an earlier short one is unacknowledged. A request /
  response protocol that writes a message in pieces, or must get the end
  of every write out at once, calls `tcp_set_nodelay(h, now_ms, 1)` (Rust
  `Tcb::set_nodelay(true)`) as it would set `TCP_NODELAY`. `tcp_close`
  needs no help: the FIN rides on the last segment and is never held.

**DON'T**
- Don't touch one handle from two threads at once — the stack has **no
  internal locking** (it's single-threaded by design; shard TCBs across
  threads, one owner each). The Python and C# wrappers serialize the calls
  on each handle with a per-handle lock; raw C ABI callers must do so
  themselves.
- Don't `send`/`recv`/`inject`/`tick` after `tcp_destroy`, and don't reuse
  storage without a fresh `tcp_init` (the magic guard will reject it).
- Don't assume `OVERFLOW` (`-9`) is recoverable — it signals an internal
  invariant bug; please file it. It is fuzzed against and should never
  surface.

### `tcp_poll()` event flags

`tcp_poll` is a cheap, allocation-free snapshot you can use instead of
inspecting state directly:

| Flag | Meaning / action |
|---|---|
| `READABLE` | `recv` will return bytes. |
| `WRITABLE` | `send` will accept bytes (Established/CloseWait + ring has room, none of it lent out by the Rust `send_reserve`). |
| `ESTABLISHED` | Handshake complete; bulk data may flow. |
| `PEER_CLOSED` | Peer sent FIN — keep draining `recv`, then `close` your side. |
| `CLOSED` | Fully torn down; safe to `destroy`. After a clean close, bytes the peer sent before its FIN stay readable (`READABLE`) until `recv` drains them and reports EOF. |
| `TX_PENDING` | Egress ring non-empty — you must `extract_packet`. |
| `ERROR` | A terminal error latched; `recv` surfaces the code (`RESET`/`CLOSED`). |
| `LISTENING` / `HALF_OPEN` | Server: in `LISTEN` / mid-handshake (`SYN_RCVD`). |

### Using it from Rust (no FFI)

The same model, via `Tcb` directly — no C ABI, no `unsafe` on your side:

```rust
use tcp_sans_io::{Tcb, TcbConfig, Endpoint, State, MAX_PACKET};

let mut tcb = Tcb::new(TcbConfig {
    local:  Endpoint { ip: local_ip,  port: local_port },
    remote: Endpoint { ip: remote_ip, port: remote_port },
    iss: csprng_u32(),          // RFC 6528
    initial_rto_ms: 1000,
})?;
tcb.set_now(now);
tcb.connect()?;                 // or tcb.listen()?

// per turn:
tcb.set_now(now);
tcb.inject_packet(&datagram)?;  // Err(NotForUs/Malformed) ⇒ drop & continue
if tcb.state() == State::Established {
    let _ = tcb.send(app_out);          // buffers; Err(WouldBlock) ⇒ retry later
    let n = tcb.recv(&mut app_in)?;     // Err(ConnectionClosed) ⇒ EOF
}
tcb.tick()?;                    // fires timers + flushes buffered send data
let mut pkt = [0u8; MAX_PACKET];
loop {
    let n = tcb.extract_packet(&mut pkt)?;
    if n == 0 { break; }
    wire_send(&pkt[..n]);
}
```

`Tcb<const BUF>` is generic over ring capacity (default `BUF_CAP` = 1 MiB).
A `Tcb` is ~2.08 MiB, so build it in place in heap storage
(`Tcb::init_in_place`, as `tcp_init` does) or box it, rather than holding it
as a stack local (or use `small-buffers` for many idle TCBs) — see *Memory
footprint*. Event-driven Rust hosts sleep until `tcb.next_deadline()`.

**Egress back-pressure.** When the host's queue toward the peer is full,
stop pulling instead of leaving segments staged: drain `extract_packet` to
0, then `tcb.set_egress_paused(true)`. While paused the TCB stages nothing
but SYN / RST, so no segment ages in the ring with a stale ACK, window or
timestamp, and the hold is not mistaken for loss (a tail-loss probe waits
until one PTO after the resume instead of being queued behind the data it
probes for). Resume with `set_now`, `set_egress_paused(false)` and a
`tick()`. (Rust API only.)

**Checksum offload and borrowed extraction.** If something downstream
computes TCP checksums (a NIC with TX checksum offload, or a virtio-net guest
that negotiated `VIRTIO_NET_F_GUEST_CSUM` and is handed
`VIRTIO_NET_HDR_F_NEEDS_CSUM` frames), call `tcb.set_tx_csum_offload(true)`.
Segments then carry only the pseudo-header sum in the TCP checksum field
(Linux `CHECKSUM_PARTIAL`: `csum_start` is the TCP header, `csum_offset` is
16), which skips a pass over every payload byte. IPv4 header checksums stay
complete. `tcb.extract_packet_with(|dgram| ...)` lends the staged datagram to
the closure instead of copying it into your buffer. The inbound counterpart is
`inject_packet_l4_csum_trusted`. (Rust API only.)

**Filling the send ring in place.** Instead of receiving into your own buffer
and copying it in with `send`, a host can have its data land in the send
ring: `tcb.send_reserve(max)` lends the ring's free space as two slices (the
second is non-empty only when the space wraps the end of the ring), and
`tcb.send_commit(n)` appends the first `n` bytes to the stream. An
asynchronous host can hand the slices to the OS as the buffers of a socket
receive and commit when it completes: until the commit the TCB never touches
the lent bytes, even if the connection resets meanwhile (the commit then
drops them), and `send` returns `WouldBlock`. Commit, with 0 if need be,
before `reinit` or dropping the TCB. (Rust API only.)

### How do you know you got it right? (canonical conformance)

There is a canonical, executable answer: **drive a hash-verified
bidirectional bulk transfer and check both digests match.** If an
independent TCP — or even a second instance of this stack in loopback —
agrees with you byte-for-byte in *both* directions over a multi-MiB
transfer, your integration (sizing, ordering, draining, clocking, close
sequence) is correct. A single dropped/duplicated/reordered byte from a
driver bug changes the digest.

The easiest path needs **no external stack and no root**: drive two
instances of your own binding against each other through an in-memory
channel that injects loss / reordering / duplication. That single test
exercises your entire integration surface. Two tiers, easiest first:

| Tier | Self-test | What it proves | Reference |
|---|---|---|---|
| 0 | `tcp_selftest()` | Linkage / ABI / calling convention + core health, in one call | built-in |
| 1 | **self-loopback** | *Your* pump loop is correct, under chaos — no external peer | `bindings/conformance/` (`cargo run --release`) |
| 2 | gVisor netstack | Interop with a foreign stack, 1 GiB each way, SHA-256 | `bindings/gvisor/integration_test.go`, `server_integration_test.go` |
| 2 | real Linux kernel (TUN) | Interop with an actual kernel TCP | `bindings/gvisor/tun_test.go`, `tun_server_test.go` |
| 2 | adversarial channel | Survives loss/reorder/dup/corruption/jitter | `bindings/gvisor/chaos_test.go` |

`bindings/conformance/` is the Tier-1 reference: a ~200-line standalone
binary that drives two stacks through the C ABI over a chaos channel and
hash-verifies the transfer, exiting 0/1. Port it into your language's test
suite to self-certify. **`SKILL.md`** at the repo root is a step-by-step
walkthrough of the whole integrate-and-certify process.

A minimal acceptance checklist for a new binding:

- [ ] `tcp_selftest()` returns 0 and `tcp_abi_version()` matches the header.
- [ ] Handshake reaches `ESTABLISHED` against a real peer.
- [ ] Tier-1 self-loopback: ≥ 256 KiB bidirectional, byte-exact, clean close.
- [ ] Tier-1 under loss + reorder + dup still byte-exact.
- [ ] (Recommended) Tier-2 interop: ≥ 1 MiB bidirectional vs a foreign stack.
- [ ] Graceful `close` reaches `CLOSED` on both ends (no leaked handles).
- [ ] A fuzz/property run of your wrapper shows no leaks or panics.

If those pass, you've done all the right things — the digests are the
proof.

## Testing

| Layer | What it covers | Files |
|---|---|---|
| **Property tests** | Wire codec round-trips; checksum integrity; serial-arithmetic; out-of-order reassembly vs a model | `src/property_tests.rs` (proptest, 4096 cases each) |
| **Security regressions** | One test per finding of the public-deployment review: blind injection, RFC 5961 challenge/rate limits, forged zero window, PAWS, timestamp poisoning by a rejected ACK, ACK storms, old-data reflection, listener RSTs, SYN-SENT RST, simultaneous open, half-open replacement, cookie options, keyed timestamps, FIN_WAIT_2, slow-reader / zero-window stalls, no SACKed retransmits, ECE handling, no sequence rewinds, full-window out-of-order, D-SACK (reported and believed), timestamp undo (only of a spurious fast recovery or RTO), forged TSecr, reply gating for unacceptable segments, MTU / PMTU / black-hole, FFI stack use, NULL / zero-length / misaligned FFI arguments. Second review: TS.Recent only after ACK validation, CE on a CWR segment, FIN after the peer's FIN, zero-window probe ACKs, out-of-order data beyond a FIN, FIN_WAIT_2 trickle and TIME_WAIT pinning, keyed listener ISNs, hybrid cookies (option preservation, spoofed-SYN lockout, rotation), black-hole probing. Multi-model audit: tail loss probes (not counted in pipe, answered by a plain duplicate ACK, not postponed by peer data, also during CWR), undo (after a probe, past an ECN-Echo, with nothing resent), RACK's timer in recovery, ACK on read and interactive mode, partial hole fills and overlaps D-SACKed, cwnd growth and validation, the Linux RTT estimator, the RTO after a head retransmission, Nagle and PSH, the handshake's third ACK (window and PAWS), close in SYN_RCVD, RST in CLOSING / LAST_ACK, PAWS on pure ACKs, SACK block validation, reneging, the deadline with a full egress ring | `src/security_tests.rs` |
| **Link simulation** | Two real TCBs over a seeded discrete-event link (bottleneck queue, delay, loss, reordering with and without D-SACK, ACK loss, burst and tail loss, slow reader, chaos with sequence wrap, and 10 Gbit/s virtual links with sub-millisecond RTT, reordering and tail loss). Asserts retransmissions equal drops, goodput vs the Mathis bound, TLP before RTO, one window halving per queue overflow, clean closes, that request/response never waits on a delayed ACK, and that `next_deadline()` never leaves a host spinning | `src/sim_tests.rs` |
| **TCB internals** | R2 / SYN retry limits, keepalive, USER TIMEOUT, lost FIN, TIME_WAIT restart (and no restart by a forged FIN), FIN edge cases (FIN after FIN, out-of-order FIN consumed with one ACK and processed in SEG.SEQ order, ACK carried by a retransmitted FIN), unread data across the final close, byte-exact data after SND.UNA laps back to ISS (4 GiB; release builds), in-place init, liveness oracles, deadline reporting | `src/tcb/tests.rs` |
| **C ABI ownership** | `tcp_destroy` releases the `heap-buffers` rings (counting allocator, own binary): `cargo test --release --features std,heap-buffers --test ffi_heap_buffers` | `tests/ffi_heap_buffers.rs` |
| **Conformance tests** | Exact wire bytes per spec scenario | `src/conformance_tests.rs` |
| **Loopback tests** | End-to-end behavioral tests via in-memory peer | `src/loopback_tests.rs` |
| **Server / adversarial** | LISTEN/SYN_RCVD hardening (secret required, hybrid cookies and key rotation, SYN flood, blind and inexact RST/ACK) | `src/server_tests.rs` |
| **gVisor interop** | Against Google's reference netstack | `bindings/gvisor/*_test.go` |
| **smoltcp interop** | Against smoltcp (the dominant no_std Rust TCP stack, used in embedded). In-memory channel between two userspace stacks — completely independent codebases negotiating options + sequencing data. | `src/smoltcp_interop_tests.rs` |
| **smoltcp shootout** | tcp-sans-io and smoltcp through one harness: 33 RFC probes against a scripted peer, a 16-case impairment matrix in both roles, 1 M fuzzed segments each, goodput over a simulated link and CPU cost (see *tcp-sans-io vs smoltcp*). `--check` gates CI | `bindings/smoltcp-shootout/` |
| **Real Linux TUN** | Against the Linux kernel TCP stack via TUN | `bindings/gvisor/tun_test.go` |
| **Fuzzing** | Codec and full-TCB sessions under libFuzzer with invariant, no-burst and liveness oracles | `fuzz/fuzz_targets/` |
| **Same-path benchmark** | tcp-sans-io vs Linux Reno / CUBIC through one netem-shaped router to the same kernel peer, both directions, retransmissions vs router drops | `bindings/netem/bench.sh` |
| **packetdrill-DSL runner** | Per-packet conformance scripts in packetdrill syntax | `bindings/packetdrill/*.go` + `scripts/*.pkt` |
| **eBPF uprobe observability** | bpftrace uprobes on the cdylib's FFI entry points (counts + latency histograms) | `bindings/bpf/` |
| **perf flamegraphs (CI)** | `perf record` wrapping a same-path benchmark run → `inferno-flamegraph` SVG | `.github/workflows/perf-bench.yml` |
| **Real-world HTTP/curl/wrk** | cdylib hosts an HTTP/1.1 echo server through a TUN; real `curl` + `wrk` exchange messages. Covers GET / POST / 1 MiB bodies, slow uploaders (`--limit-rate`), sequential connections (LISTEN re-arm), wrk load, TIME_WAIT churn (50 sequential), and N-way concurrent connections (10 + 50 parallel TCBs sharing the TUN with port-keyed demux). | `bindings/realworld/http_test.go`, `concurrent_test.go` |
| **Real TLS over the cdylib** | Go's `crypto/tls.Server` wraps a custom `net.Conn` backed by the cdylib + TUN pair; real `curl --insecure` does HTTPS round-trips. Validates TCP behaviour under handshake-sensitive workloads (small writes, half-close timing, MAC-validated bulk transfer) — anything our stack mis-orders or corrupts surfaces as a TLS alert, not silent corruption. | `bindings/realworld/tls_test.go` |
| **h2spec HTTP/2 conformance** | `h2spec` (nghttp2's official HTTP/2 conformance suite) runs all 44 generic tests against an HTTP/2 server hosted on our TCP stack via TLS + ALPN. Each test case is a fresh TCP+TLS+HTTP/2 connection — exercises the LISTEN re-arm cycle at scale plus framing-sensitive H2 traffic. All 44/44 generic tests pass. | `bindings/realworld/h2spec_test.go` |
| **git clone over HTTPS** | Real `git clone https://…/repo.git` against a bare repository served by `http.FileServer` over the cdylib's TLS listener. Exercises chatty HTTP/1.1 traffic (many small pkt-line writes interleaved with variable-length pack/object body reads). End-to-end signal: the cloned working tree's bytes must match the source repo exactly. | `bindings/realworld/git_test.go` |
| **Userspace UDP server stress** | A standalone Rust harness (`bindings/wgserver-rs/`) hosts N TCBs in LISTEN on a single UDP socket. A pure-Go driver (`bindings/wgserver/`) — no cgo, no kernel TUN, no root — runs adversarial scenarios (SYN flood ±cookies, blind RST/ACK, cookie forgery, bare-ACK reflection check, malformed-packet spray, wrong-IP rejection, in-window RST in SYN_RCVD, …) and a 10 000-connection functional scale test (≈ 1.3 GiB with `--features small-buffers`, 100 % success, p99 ≈ 18 ms loopback). | `bindings/wgserver-rs/src/server.rs`, `bindings/wgserver/{scale,adversary}_test.go` |

### packetdrill scripts

The `bindings/packetdrill/` package is a Go-native runner for
packetdrill-style `.pkt` scripts that drives our cdylib instead of the
kernel's POSIX socket layer. Each `.pkt` file becomes a Go subtest.

Currently 17 scripts cover handshake (active + passive), full-options
SYN, Window Scale negotiation, ECN-Setup, IW=10 burst, SACK negotiation,
PRR fast retransmit, RACK selective retransmit (single + multi-block
+ multi-hole receive), TLP probe before RTO, data transfer + pattern
verification, active / passive close, plus TBIT-style RFC compliance
probes (ECN CE → ECE echo, asymmetric WSCALE drop, SACK without
SACK_PERMITTED ignored). Example:

```
--connect 10.0.0.1:49152 10.0.0.2:80
+0     > SEW 0:0(0) win 65535 <mss 1460, wscale 5, sackOK, TS val * ecr 0>
+.005  < S.  0:0(0) ack 1 win 32768 <mss 1460, wscale 7, sackOK, TS val 1 ecr *>
+0     > .   1:1(0) ack 1 <TS val * ecr 1>
--expect_state ESTABLISHED
```

Run all: `cd bindings/packetdrill && go test ./...`

### Perf benchmarking + flamegraphs (manual or PR)

`.github/workflows/perf-bench.yml` runs `bindings/netem/bench.sh` for
one profile (tcp-sans-io, Linux Reno and Linux CUBIC on the same path,
both directions), then one run under `perf record` rendered as a CPU
flamegraph SVG, plus the `bpftrace` uprobe trace described below.
Artifacts (results JSON, flamegraph, uprobe histograms) are uploaded for
offline inspection. Trigger:
manual via `workflow_dispatch` or by a PR touching `src/**`,
`bindings/netem/**`, or `bindings/bpf/**`.

### eBPF observability (`bindings/bpf/`)

`bindings/bpf/scripts/trace_cdylib.bt` is a bpftrace template that
attaches `uprobe` + `uretprobe` to the public FFI entry points
(`tcp_inject_packet`, `tcp_extract_packet`, `tcp_tick`, `tcp_send`,
`tcp_recv`) and emits invocation counts, per-function latency
histograms (log2 nanoseconds), and cumulative byte counts.

Use locally with the bundled runner:

```sh
sudo bindings/bpf/trace.sh target/release/libtcp_sans_io.so \
    -c "bindings/netem/bench.sh --profiles lan --runs 1 --dir up --stacks tcp-sans-io"
```

The companion Go test (build tag `bpftrace`) wraps this and
asserts the expected symbols are observed at non-zero rates,
catching accidental `#[no_mangle]` removals. See
`bindings/bpf/README.md` for the full toolkit.

### Coverage-guided fuzzing (`fuzz/`)

Six `cargo-fuzz` targets: `wire_parse` and `wire_parse_emit_roundtrip`
(the codec), `tcb_inject_sequence` (arbitrary datagram streams into one
TCB), `tcb_client_session` (a scripted peer with state-transition,
sequence-monotonicity, no-burst and liveness oracles) and `tcb_loopback` /
`tcb_loopback_small` (two TCBs over a fuzzer-controlled channel). Each ran
10 minutes clean on this code (≈ 300 M executions for the codec targets,
0.1–1.3 M for the TCB targets):

```sh
cargo +nightly fuzz run tcb_client_session -- -max_total_time=600 -timeout=60
```

### Other canonical suites not (yet) integrated

- **Upstream packetdrill scripts** (Google's Linux TCP test corpus) —
  our DSL runner is compatible in shape but uses `--connect`/`--send`-
  style directives instead of socket syscalls, so existing scripts need
  light adaptation.

## Project layout

```
src/
├── lib.rs               # crate-level constants (BUF_CAP, MSS, MAX_PACKET), host contract
├── error.rs             # TcpError + FFI error codes
├── state.rs             # RFC 9293 state machine enum
├── wire.rs              # IPv4 + TCP codec (parse/emit, options, checksums)
├── ring.rs              # Fixed-capacity byte ring (+ positional writes for out-of-order data)
├── ooo.rs               # Out-of-order range tracker (SACK block generation)
├── rtx_queue.rs         # Per-segment retransmission queue / SACK scoreboard / pipe
├── rack.rs              # RACK-TLP loss detection (RFC 8985), windowed min RTT
├── congestion.rs        # Reno slow start / CA + PRR (RFC 6937), CWR, RTO reduction, undo
├── tx_ring.rs           # Multi-slot egress staging ring (32 packets)
├── tcb/
│   ├── mod.rs           # Tcb struct, public API, timers' deadlines, stats, invariants
│   ├── input.rs         # Segment acceptance (RFC 5961, PAWS), per-state processing, receive path
│   ├── ack.rs           # ACK / SACK / D-SACK processing, loss recovery and undo, window updates
│   ├── output.rs        # Transmission, SWS avoidance, options, windows, emitters
│   ├── timers.rs        # tick(): TLP, RTO, RACK, persist, keepalive, user timeout, ...
│   ├── cookie.rs        # SYN cookies, keyed ISN / timestamp offsets, SipHash-2-4
│   └── tests.rs         # TCB-internal timer / lifecycle tests
├── ffi.rs               # Stable C ABI
├── selftest.rs          # tcp_selftest(): in-process two-stack conformance check
├── loopback_tests.rs    # End-to-end behavioral tests
├── conformance_tests.rs # Per-spec wire-byte assertions
├── server_tests.rs      # Passive-open + adversarial inputs
├── security_tests.rs    # Regression tests for the public-deployment review
├── sim_tests.rs         # Deterministic two-TCB link simulation (efficiency guards)
├── smoltcp_interop_tests.rs # Interop against smoltcp
└── property_tests.rs    # proptest fuzzing

tests/
└── ffi_heap_buffers.rs  # tcp_destroy frees heap-buffers rings (own binary: counting allocator)

bindings/
├── csharp/              # .NET integration test + wrapper
├── python/              # CPython ctypes wrapper + unittest suite
├── gvisor/              # Go: gVisor netstack interop + real-kernel TUN test
├── netem/               # Same-path benchmark: bench.sh (namespaces + netem router),
│                        #   tsbench (Go endpoint over TUN), kernel_peer.py, summarize.py
├── bpf/                 # bpftrace uprobe template + Go test wrapper
│   ├── scripts/         # trace_cdylib.bt template
│   ├── trace.sh         # LIBPATH-substituting runner
│   └── bpftrace_test.go # Go test (build tag: bpftrace)
├── realworld/           # Go: real HTTP/1.1 interop via curl + wrk
│   ├── http_test.go     # Echo handler + 7 curl/wrk scenarios
│   ├── tun.go           # TUN setup helpers
│   └── cdylib.go        # Cgo bridge (with Listen() for passive-open)
├── wgserver-rs/         # Rust: standalone server harness (N TCBs on one UDP socket)
│   ├── Cargo.toml       # Workspace-style sibling crate (path = "../..")
│   └── src/{main,server}.rs
├── smoltcp-shootout/    # Rust: tcp-sans-io vs smoltcp (workspace-ignored sibling crate)
│   └── src/
│       ├── stacks.rs    # One sans-I/O adapter trait over both stacks
│       ├── pkt.rs       # Independent IPv4+TCP codec (wire observer, scripted peer)
│       ├── net.rs       # Seeded discrete-event link + stack-independent wire statistics
│       ├── sim.rs       # Two stacks, two links, two applications, verified streams
│       ├── probes.rs    # RFC probes against a scripted raw peer
│       ├── interop.rs   # Impairment / lifecycle matrix, both roles
│       ├── fuzz.rs      # Deterministic hostile-segment fuzzer (panics, invariants)
│       └── perf.rs      # Simulated-link goodput, CPU cost, memory
├── wgserver/            # Go: pure-Go driver + adversarial / scale stress suite
│   ├── wire.go          # IPv4+TCP encode/decode + checksums (no cgo)
│   ├── transport.go     # UDP socket + central 5-tuple demux
│   ├── miniclient.go    # Minimal stateful TCP client (option matrix)
│   ├── harness.go       # Spawn / wait-ready / shutdown wgserver subprocess
│   ├── scale_test.go    # 1K + 10K connection scale tests
│   └── adversary_test.go # SYN flood ±cookies, blind RST/ACK, forgery, malformed
└── packetdrill/         # Go: packetdrill-DSL runner + .pkt script corpus
    ├── parser.go        # .pkt → AST
    ├── wire.go          # PacketDesc ↔ IPv4+TCP bytes
    ├── matcher.go       # cdylib emission vs PacketDesc
    ├── runner.go        # synthetic clock + pump loop + directives
    ├── symtab.go        # script-relative ↔ real ISN translation
    └── scripts/*.pkt    # test corpus

include/
└── tcp_sans_io.h        # Hand-maintained C header (stable ABI)
```

## Threat model

The stack assumes the host is friendly but the peer — and anyone who can
put packets on the path — is hostile.

- **Connection pinning.** A peer that *stops making progress* cannot hold
  a TCB: R2 (10 unanswered timeouts), USER TIMEOUT (300 s without a full
  segment of progress — defeats zero-window and sub-segment-trickle
  "Sockstress" stalls, which a proof-of-life-based timer cannot), keepalive
  (reaps vanished idle peers) and bounded SYN / SYN-ACK retransmission.
  Once the host has closed and our FIN is acknowledged, the peer cannot
  extend the TCB's life either: FIN_WAIT_2 lasts 60 s unless the
  application keeps reading, and TIME_WAIT at most 120 s however often the
  FIN is re-sent. What is *not* bounded is a live peer making slow but real
  progress while the host keeps the connection — e.g. a reader that
  acknowledges one segment every few minutes holds an ESTABLISHED TCB, or a
  closed one still draining its send buffer, for as long as it keeps that
  up; that is the application's policy to set (idle, total-time or
  minimum-throughput deadlines). The host must also cap the *number* of
  TCBs (including `TIME_WAIT` ones) — see the contract above.
- **Off-path injection (RFC 5961).** Data and FINs need the ACK bit and an
  acceptable sequence; a RST is honoured only at exactly `RCV.NXT` (in
  SYN_RCVD too), a SYN in a synchronized state draws a challenge ACK, and
  ACKs outside `[SND.UNA − MAX.SND.WND, SND.NXT]`, or below what has
  actually been acknowledged (an ACK of bytes never sent, as in Linux), are
  dropped with a challenge ACK — and leave no trace: a segment failing that check cannot
  move TS.Recent (which would let PAWS discard the peer's real data), echo
  CE or count as proof of life. PAWS drops old-timestamp segments, pure
  ACKs too (but for Linux's narrow exemption of a reordered old ACK), so a
  stale or replayed zero-window ACK cannot shrink the send window; the
  handshake's third ACK must pass it as well. The window
  update rule ignores a forged future WL1, and the passive ISN plus
  timestamp offset are keyed per 4-tuple (`tcp_listen` requires
  `tcp_set_secret`), so neither the host clock nor sequence numbers leak.
- **Reflection and ACK storms.** Segments with none of ACK, SYN and RST
  are dropped unanswered. Replies to unacceptable segments (challenge ACKs,
  dup ACKs for out-of-window data, RSTs to stray ACKs or SYN-ACKs) are
  limited to one per 500 ms per connection, each a single header-only packet
  of at most 80 bytes; a SYN-ACK to a listener draws at most one such RST,
  addressed to the segment's source, and a bare ACK that is not a valid
  cookie draws nothing. Only data or a FIN that could be the peer's own
  retransmission — an acceptable ACK and, when negotiated, a timestamp — is
  answered outside that budget (one ACK per segment, with a D-SACK that never
  names sequence space the connection cannot have received), because the
  peer's loss recovery depends on it; a forger must first guess an
  acceptable ACK. On the sending side a D-SACK is believed only for data
  that was actually retransmitted, and RTT samples come from our own send
  times (TSecr only after a retransmission, and never later than it), so
  neither a forged D-SACK nor a forged TSecr can skew loss detection or the
  RTO. TSecr can undo a window reduction (timestamp undo, as Linux) only on
  an ACK that newly acknowledges data during loss recovery: forging one
  already means acknowledging data on the receiver's behalf.
- **SYN floods.** A listener holds one half-open statefully (keeping every
  option) and answers every other SYN with a stateless SYN cookie (29-bit
  SipHash MAC, 64 s buckets, keyed from the host secret unless set
  explicitly) that keeps window scaling, SACK and ECN when the client uses
  timestamps. A valid cookie ACK takes the half-open slot over, so spoofed
  SYNs at any rate cannot lock a listener out, and a cookie survives one
  key rotation.
- **Malformed and adversarial segments.** Every parser path is
  bounds-checked and returns `Result`; peer MSS is floored at 64 B; option
  processing, SACK and D-SACK handling, and out-of-order insertion are
  bounded per segment; a SACK block that reaches past `SND.NXT` or not
  above `SND.UNA` is ignored (Linux `tcp_is_sackblock_valid`), so a forged
  block cannot mark unsent or acknowledged data delivered; nothing SACKed
  is ever retransmitted and nothing received is ever reneged; repeated
  SACK blocks over an already-SACKed
  queue cost a binary search and a bitmap skip, not a walk over every
  segment (≈ 0.1 µs instead of 2 µs per ACK with 1024 segments in flight).
  Fuzz targets under `fuzz/` exercise
  the parser and full TCB sessions — including a hostile multi-peer target
  for listeners and SYN cookies — with invariant and liveness oracles.
- **Host safety.** The C ABI validates handles (magic guard), rejects
  NULL pointers with a length and misaligned storage, accepts NULL for
  zero-length buffers, and builds the TCB in place (no multi-MiB stack
  frame). A Rust panic — which the code is designed never to reach —
  traps (`ud2` / `udf`) instead of spinning or unwinding across the FFI.

Residual risks the host owns: the number of concurrent TCBs and their
memory (≈ 2.08 MiB each by default, held through `TIME_WAIT`), how long a
live but slow peer may hold a connection the application keeps open, CPU
spent per inbound packet (bounded per segment, but proportional to packet
rate), and secret management (keep `tcp_set_secret` secret; rotate an
explicit cookie secret no more often than every ~2 minutes).

## Licence

MIT OR Apache-2.0.
