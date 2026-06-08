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
3. Calls `tcp_tick(now_ms)` periodically to drive timers.
4. Reads/writes application data via `tcp_recv(..)` / `tcp_send(..)`.

## Features (RFC matrix)

The stack lands roughly at **"circa 2017-era Linux TCP"** — equivalent in
algorithmic feature set to Linux 4.x stacks. The only major post-2017
algorithm we don't ship is CUBIC; we use Reno-class congestion control
with PRR and RACK-TLP loss detection.

| Feature | RFC | Year | Status |
|---|---|---|---|
| Base state machine | RFC 9293 (793 update) | 2022 | ✅ |
| Active + passive opens | RFC 9293 | — | ✅ both |
| SYN cookies | RFC 4987 | 2007 | ✅ (optional) |
| MSS option | RFC 9293 | — | ✅ |
| Timestamps + PAWS-lite | RFC 7323 §3 | 2014 | ✅ |
| **Window Scale** | **RFC 7323 §2** | **2014** | ✅ added in this generation |
| SACK_PERMITTED + SACK | RFC 2018 | 1996 | ✅ multi-block, both sides |
| Karn / RFC 6298 RTO | RFC 6298 | 2011 | ✅ |
| Tahoe slow-start / CA | RFC 5681 | 2009 | ✅ |
| **PRR-Reno fast recovery** | **RFC 6937** | **2013** | ✅ added in this generation |
| **IW=10 initial window** | **RFC 6928** | **2013** | ✅ added in this generation |
| **SACK-based selective retransmit** | **RFC 6675** | **2012** | ✅ added in this generation — scoreboard, NextSeg, multi-hole reassembly |
| Persist (zero-window probe) | RFC 1122 §4.2.2.17 | 1989 | ✅ |
| Delayed ACK | RFC 1122 §4.2.3.2 | 1989 | ✅ |
| 2·MSL TIME_WAIT | RFC 793 §3.4 | 1981 | ✅ (60 s) |
| **ECN** | **RFC 3168** | **2001** | ✅ added in this generation |
| **RACK-TLP loss detection** | **RFC 8985 + 8298** | **2021** | ✅ added in this generation — time-based loss + Tail Loss Probe |

### Deliberately deferred (post-2017 modernisations)

| Feature | RFC | Why deferred |
|---|---|---|
| CUBIC congestion control | RFC 9438 (2024) | We use Reno-class (PRR). CUBIC is friendlier on long-fat networks; substantial state-machine change. |
| BBR | (Google, 2016) | Bandwidth-probing CC; orthogonal architecture (model-based, not loss-triggered). |
| TFO (TCP Fast Open) | RFC 7413 | Data-in-SYN; security model is complex. |
| DSACK | RFC 2883 | Refinement on SACK; minor incremental win on top of RFC 6675. |
| MPTCP | RFC 8684 | Different connection model entirely. |

### Deliberately omitted (out of scope)

- IPv6 (the WireGuard backend is the v6-aware layer; we present IPv4 to the
  tunnel).
- Listening on multiple connections per TCB (one connection per TCB — the
  host multiplexes).
- Out-of-band data (`URG`).
- TCP-MD5 / TCP-AO authentication.

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

Per-connection: ~2.15 MiB.

- `BUF_CAP = 1 MiB` send ring + `1 MiB` receive ring.
- 16 KiB out-of-order reassembly arena (4 holes × 4 KiB).
- 24 KiB RACK send-record queue (per-segment metadata for time-based loss detection).
- 48 KiB egress staging ring (32 packet slots × `MAX_PACKET`).
- ~1.5 KiB SYN-cookie secret + various scalar state.

Hosts that need many idle connections can shrink `BUF_CAP` (must be a power
of two) — this is the only knob. The 1 MiB default is chosen so the receive
window is large enough to fill the BDP of typical WAN paths (e.g. 50 ms RTT
at 160 Mbit/s).

The Rust thread stack default (1 MiB on Windows, 8 MiB on Linux) is **too
small** for a Tcb constructed as a stack local — between the 2 MiB rings,
the 24 KiB RACK send-queue, and the 48 KiB egress ring, a Tcb is ~2.15 MiB.
The included `.cargo/config.toml` sets `RUST_MIN_STACK = 33554432` (32 MiB)
for the build/test environment, which comfortably fits multiple Tcbs (e.g.
loopback tests with peer + client) per thread. Production callers route
through the C ABI (`tcp_init`) which writes into host-provided heap
storage, so this only affects pure-Rust users and tests.

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
| `BUF_CAP` | 1 MiB (32 KiB w/ `small-buffers`) | `lib.rs` | Send + receive ring capacity; also the un-scaled receive window = in-flight ceiling per RTT. Power of two; window-scale shift derived from it (5 at 1 MiB). |
| `MSS` / `MAX_PACKET` | 1460 / 1500 B | `lib.rs` | Largest payload / largest emitted datagram. |
| `REASM_CAP` / `MAX_HOLES` / `SLOT_CAP` | 16 KiB / 4 / 4 KiB | `reassembly.rs` | Out-of-order data held while waiting for gaps to fill: at most 4 disjoint runs, 4 KiB each. |
| `SCOREBOARD_CAP` | 16 | `scoreboard.rs` | Sender-side SACK ranges tracked for RFC 6675 retransmit. |
| `SEND_QUEUE_CAP` | 1024 | `send_queue.rs` | In-flight segment records RACK can time-based-loss-detect (≈ `BUF_CAP / MSS` with margin). Oldest evicted on overflow. |
| `TX_RING_CAP` | 32 | `tx_ring.rs` | Egress packets staged per emit burst before the host must drain. |
| SACK blocks emitted | ≤ 4 (≤ 3 with TS) | `tcb.rs` | Bounded by the 40-byte TCP option area. |
| `INITIAL_WINDOW` | 10·MSS (14600 B) | `congestion.rs` | RFC 6928 initial cwnd. |
| `RTO_MIN` / `RTO_MAX` | 200 ms / 60 s | `tcb.rs` | RTO clamp; exponential backoff is capped at `RTO_MAX`. |
| `TLP_MIN_PTO` / `DELAYED_ACK` / `TIME_WAIT` | 10 ms / 40 ms / 60 s | `tcb.rs` | Tail-loss-probe floor, delayed-ACK timer (every 2nd segment), 2·MSL wait. |
| `MAX_SYN_RCVD_RETRIES` | 5 | `tcb.rs` | SYN-ACK retransmits before a half-open reverts to `LISTEN` (one half-open per TCB). |
| Cookie validity | 128 s | `tcb.rs` | `2 × COOKIE_TIME_BUCKET_MS`; MAC truncated to 29 bits (2⁻²⁹ blind forgery). |

### Why the bounds are sound

The receiver only ever delivers a **contiguous prefix** starting at
`rcv_nxt`, and only ever cumulatively ACKs / SACKs data it is actually
holding. So any byte the stack cannot store is simply never acknowledged,
and the peer retransmits it (via RACK/fast-retransmit once the gap is
visible, or the RTO safety net). Concretely:

- **Reassembly overflow** (a 5th simultaneous hole, or a run that
  outgrows its 4 KiB slot) → the un-storable segment is **dropped**, not
  mis-filed. `rcv_nxt` doesn't advance over a gap, the dropped range is
  never SACKed, and the sender resends it. The application can never
  observe a gap or out-of-order bytes.
- **`SEND_QUEUE_CAP` overflow** → the *oldest* record is evicted. That
  segment loses RACK time-based detection but is still covered by RTO, so
  it is recovered, just later.
- **`SCOREBOARD_CAP`** comfortably exceeds the ≤ 4 SACK blocks a
  compliant peer can send (option-space limited); crafted excess is
  merged, never overflowed.
- **`TX_RING_CAP` full** → emit returns "ring full", the caller drains
  and re-ticks; bookkeeping (`snd_nxt`, FIN state) is *not* advanced, so
  nothing is skipped.
- **Receive ring full** (app not draining) → `drain_reassembly` stops and
  the advertised window shrinks toward zero. The peer stalls on flow
  control (correct backpressure), and the zero-window persist timer keeps
  the connection alive.

In other words, shrinking `BUF_CAP` to 32 KiB or `MAX_HOLES` to 1 changes
throughput under loss, never the bytes the application sees.

### What "4 reassembly holes" actually costs

`MAX_HOLES = 4` × `SLOT_CAP = 4 KiB` means the receiver can absorb up to
four disjoint loss gaps (or ~16 KiB of out-of-order data) per window and
recover them in a single RTT via SACK-driven selective retransmit:

- **Light/moderate loss** (the WireGuard-tunnel target): a window rarely
  has more than one or two holes, so 4 is ample and recovery is
  one-RTT — indistinguishable from a 16-hole Linux receiver.
- **Heavy/bursty loss** (> 4 gaps in one window, e.g. a long burst drop):
  the 5th+ gap's data is dropped and re-fetched only after an earlier
  hole drains, so recovery for the excess degrades from "one RTT" toward
  RTO-paced, go-back-N-like behaviour. Throughput drops; **correctness is
  untouched.**
- **`SLOT_CAP = 4 KiB`**: an individual TCP segment (≤ MSS = 1460 B)
  always fits; the cap only limits how large a single *accumulated*
  contiguous out-of-order run can grow before it needs a second slot.

Raising `MAX_HOLES` improves heavy-loss throughput at a linear memory
cost (`MAX_HOLES × SLOT_CAP`) and a small constant per-segment CPU cost
(insert/merge and SACK generation are O(`MAX_HOLES`)). It is a deliberate
footprint-vs-loss-resilience trade, not a correctness decision.

### Termination and resource safety

These bounds are also what make the stack **DoS-resistant and
hang-free** against a hostile peer:

- **No unbounded loops.** Every loop reachable from `inject_packet` /
  `tick` / `send` is bounded by one of: a fixed-capacity array, a
  strictly-advancing index ≤ a slice length (e.g. TCP-option parsing), a
  strictly-decreasing variant (merge passes), or an explicit
  `loop_budget_exhausted` guard on the four invariant-dependent loops
  (send-emit, reassembly drain, SACK `next_seg` / `first_unsacked`).
  Those guards `panic!` under test/fuzz builds (caught immediately) and
  degrade to a graceful stop in the shipped `no_std` build (no CPU-spin
  DoS). See `fuzz/` for the livelock and bounded-output oracles.
- **No amplification.** One inbound segment stages at most a bounded
  burst (≤ `TX_RING_CAP`) before the host must drain; there is no
  reflection multiplier.
- **No state exhaustion.** One half-open per TCB with a 5-retransmit
  budget, or stateless SYN cookies; no allocator to drain.
- **No information disclosure.** Emitted packets are built in
  zero-initialised scratch with headers `fill(0)`'d and exactly the
  payload bytes copied; the egress ring returns exactly the emitted
  length; `tcp_init` writes a fresh, zeroed `Tcb` over reused host
  storage. A peer cannot read uninitialised or prior-connection memory.

## Clock model and tick cadence

TCP is **inherently time-dependent**: retransmission (RTO), Tail Loss
Probe (TLP), delayed-ACK, `TIME_WAIT`, zero-window persist probing, and
RACK's reordering window are all driven by elapsed time, not by packets
alone. This stack handles that without owning a clock, threads, or
syscalls: **`now_ms` (`u64` milliseconds) is supplied by the host** on
every `tcp_tick`, `tcp_inject_packet`, `tcp_send`, `tcp_close`, and
`tcp_abort` call. The stack has no other notion of time.

That is the core reason the library is shaped this way. A sans-I/O stack
with an **external clock source** is a pure, deterministic function of
`(inputs, now_ms)` — which is exactly what makes it testable: the
conformance suite steps the clock millisecond-by-millisecond, and the
gVisor chaos harness advances a virtual clock by hand to reproduce loss
and reordering byte-for-byte. The same code path runs in production
against a real monotonic clock. There is no hidden timer thread to mock.

**What needs a periodic `tick()`.** Responses to events — an ACK or data
segment triggered by an inbound packet, or by an application `send()` —
are emitted *inline* during `inject`/`send`. But timer *expiry* (RTO
retransmit, TLP probe, `TIME_WAIT` reaping, persist probe, a delayed-ACK
that didn't get piggybacked) is evaluated only inside `tick()`. So the
host must call `tcp_tick(now_ms)` **periodically even when no packets are
arriving**, or those timers never fire.

**How fast does the clock need to drive?** The timer floors are:

| Timer | Floor | Effect of a coarse/late tick |
|---|---|---|
| RACK reorder window | `max(SRTT/4, 1 ms)` | Loss declared slightly later on low-RTT reordering paths. |
| TLP PTO | `max(2·SRTT, 10 ms)` | Tail-loss probe fires up to one tick late. |
| Delayed ACK | 40 ms | ACK latency rises by up to one tick. |
| RTO | `200 ms … 60 s` | Negligible: a 10 ms tick is 20× finer than the floor. |
| `TIME_WAIT` | 60 s | Irrelevant to cadence. |

A **~10 ms periodic tick with 1–2 ms of jitter is more than adequate** —
it matches the TLP floor and is far finer than `RTO_MIN`. Driving finer
(1–2 ms) only helps RACK on very-low-RTT LAN paths where `SRTT/4` dips
below 10 ms; on WAN/tunnel paths the reorder window is already ≥ 10 ms,
so 10 ms loses nothing. **Cadence and jitter affect only loss-recovery
latency and ACK timing — never correctness** (per the bounds invariant
above): a coarse or jittery clock makes recovery slower, never wrong.

**Clock requirements.**

- Use a **monotonic, millisecond-resolution** source — `Instant`,
  `clock_gettime(CLOCK_MONOTONIC)`, `QueryPerformanceCounter` — not
  wall-clock. A backward step just postpones timers and a large forward
  jump fires them early; both are harmless but best avoided.
- The recommended driving pattern is **event + periodic**: call `tick()`
  with a fresh `now_ms` right after a batch of injects (so responses are
  clocked correctly) and from a periodic timer at your finest affordable
  cadence (1–10 ms) for the idle case. Pass the *same* `now_ms` you read
  for that turn into every call in the turn.

## How will it perform in 2026?

Honest assessment by path profile (in-process numbers; see *Benchmarks*
below for real-network):

| Path | How we'd do |
|---|---|
| LAN / datacenter, low loss | ✅ Fine. PRR + RFC 6675 + WS + IW=10 give modern-class behavior. |
| Typical Internet WAN (50 ms RTT, 0.1-1 % loss) | ✅ Workable, close to CUBIC for steady-state bulk. RFC 6675 selective retransmit handles multi-loss episodes in one RTT. RACK-TLP catches tail losses without waiting for RTO. |
| Wireless / cellular (1-5 % loss, reordering) | ✅ RACK-TLP handles reordering-prone paths well; reo_wnd grows with SRTT. Without CUBIC the per-ACK growth is slower at very high BDPs. |
| High-BDP (transcontinental 10G) | 🟡 Capped by `BUF_CAP`: ~`1 MiB / RTT` ≈ 160 Mbit/s at 50 ms. Bump `BUF_CAP` to lift the ceiling. CUBIC would help fill the larger pipe faster. |

The remaining algorithmic gap vs. Linux 5.x/6.x is **CUBIC** as the
default CC algorithm. PRR-Reno is adequate at moderate BDPs; CUBIC's
bigger win shows up on long-fat networks where Reno's per-RTT cwnd
increase paces too slowly.

## Benchmarks

End-to-end against the **real Linux kernel TCP stack** via a TUN device +
`tc-netem` for controlled loss/latency. 32 MiB unidirectional transfer
(cdylib sender → kernel listener). Single-core, Linux 7.0 / Ubuntu, on a
fast desktop CPU. See `bindings/netem/bench_test.go`.

### Headline numbers

| Profile | RTT (perceived) | Throughput |
|---|---|---|
| Baseline (no qdisc) | <1 ms | **607 MiB/s** (4.86 Gbit/s) |
| LAN: 1 ms each-way delay | 1 ms | **549 MiB/s** (4.39 Gbit/s) |
| WAN: 25 ms each-way delay | ~25 ms | **32 MiB/s** (255 Mbit/s) |
| High-BDP: 100 ms each-way delay† | ~100 ms | **8 MiB/s** (64 Mbit/s) |
| Lossy: 1% loss + 5 ms delay | ~5 ms | **157 MiB/s** (1.25 Gbit/s) |
| Lossy: 5% loss + 5 ms delay | ~5 ms | **157 MiB/s** (1.25 Gbit/s) |

† requires kernel-side `tcp_rmem` tuned to ≥ 1 MiB initial (see "Tuning"
below); with the default Linux ~87 KiB initial receive buffer the same
profile is bound to ~7 Mbit/s by kernel auto-tuning, not by our stack.

### What this tells you

1. **The cdylib is fast.** Single-core, single-flow, the stack sustains
   ~5 Gbit/s of TCP wire processing — well above what any realistic
   WireGuard tunnel will push at it.
2. **PRR handles loss gracefully.** 1% and 5% loss give *the same*
   throughput (1.25 Gbit/s, ~25% of clean baseline). This is the PRR
   payoff vs Tahoe's "collapse to 1 MSS on every loss event."
3. **Throughput tracks BDP at high RTT.** At 25 ms perceived RTT we hit
   32 MiB/s, close to the `BUF_CAP / RTT` = 40 MiB/s BDP ceiling. At
   100 ms we hit 8 MiB/s, close to 10 MiB/s BDP. **The stack's window
   scaling + 1 MiB BUF_CAP is what makes this possible** — without WS
   we'd cap at 64 KiB / RTT = 640 KiB/s at 100 ms RTT, ~12× worse.
4. **The kernel-side recv buffer matters.** Linux defaults
   `tcp_rmem = 4096 87380 6291456` (4 KiB min, 87 KiB initial, 6 MiB
   max). At 100 ms RTT the kernel's slow auto-tune of the receive
   window is the bottleneck, not us; tuning the initial value to 1 MiB
   lifts throughput 10×.

### Bottleneck analysis (test harness ≠ stack)

An earlier version of the test harness used a dedicated goroutine for
TUN reads + a channel to the main pump. That serialised badly under Go's
scheduler and gave a *misleading* 10 Mbit/s ceiling (the kind of number
that makes you think "1.3 MiB/s, why is this stack so slow?"). Running
under `strace` happened to fix it by forcing context switches at every
syscall, which made the goroutines interleave properly.

**The current harness** inlines non-blocking TUN reads in the main pump
(no goroutine, no channel) and the numbers above are what falls out.
Under `perf stat`: 139 ms CPU time for a 108 ms wall transfer
(≈ 1.3 cores busy), low cache-miss rate, ~640 M instructions per 32 MiB
= ~20 instr/byte. CPU-bound but reasonably so.

The remaining cost is dominated by:
- ~1 cgo crossing per emitted/injected packet (~150 ns each).
- 1 `write(2)` + 1 `read(2)` syscall per packet on the TUN fd (~1 µs each).
- The stack's own per-packet work (parse/emit + state update) is in the
  noise: < 200 ns per packet.

### FFI batching (Phase 8: tx_ring)

The egress staging used to be a single-packet slot (`tx_buf`,
`tx_len`), so `maybe_send_data` could only queue one segment per call
and the host had to do one extract per packet. Concretely, a 32 MiB LAN
transfer drove these FFI call counts (measured via the `bindings/bpf`
uprobes):

| FFI entry point | Before (single-slot) | After (tx_ring) | Change |
|---|---:|---:|---:|
| `tcp_tick` | 23,935 | 1,821 | −92 % |
| `tcp_send` | 22,704 | 1,390 | −94 % |
| `tcp_extract_packet` | 47,115 | 25,351 | −46 % |
| `tcp_inject_packet` | 23,175 | 22,048 | (peer ACK rate; unchanged) |

`maybe_send_data` is now a loop that drains as many segments as cwnd /
PRR-credit / peer-window allow, staging them into a 32-slot `TxRing`
(48 KiB per connection). The host still pops them one at a time via
`tcp_extract_packet`, but a single tick / inject round amortises the
~150 ns cgo crossing across an entire IW=10 burst (or RACK / RFC 6675
fan-out during recovery). LAN throughput moved modestly (~549 MiB/s →
~560 MiB/s) because the harness was already syscall-bound; the bigger
win is that per-connection CPU cost is now sub-linear in segment count,
which matters for multi-connection scaling.

Lifting the ~5 Gbit/s ceiling further would require:
1. Batched FFI (multiple packets per cgo crossing).
2. Or `sendmmsg(2)` / `recvmmsg(2)` for the TUN fd (batch syscalls).
3. Or skipping cgo entirely (e.g. native Rust host).

### Tuning the kernel for high-BDP tests

```sh
sudo sysctl -w net.ipv4.tcp_rmem='4096 1048576 16777216' \
                net.ipv4.tcp_wmem='4096 1048576 16777216'
```

### Reproducing

```sh
cargo build --release --lib
cd bindings/netem
sudo -E env PATH=$PATH go test -v -timeout 300s -run TestNetem_ ./...
```

Requires root for `/dev/net/tun` + `ip(8)` + `tc(8)`. Tests self-skip
otherwise. Sequential runs can race on the listener port being in
`TIME_WAIT`; the easy workaround is one test per `go test -run` invocation
with a short sleep between.

## Building

```sh
cargo build --release --lib       # cdylib + staticlib + rlib
cargo test  --release --lib       # 116 tests (loopback + conformance + property + server + RACK/send-queue/tx-ring units + smoltcp interop)
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
   tick / extract / send-recv) and calls `tick()` **periodically even when
   idle**.
5. **A high-entropy `iss`** (RFC 6528) per connection — derive it from a
   CSPRNG, never a counter. Servers that want stateless SYN-cookie flood
   resistance also pass a 16-byte CSPRNG secret to `tcp_set_cookie_secret`.
6. **5-tuple demux** — route each inbound datagram to the TCB that owns
   its 4-tuple. The stack rejects mismatches with `NOT_FOR_US`, but you
   shouldn't rely on that for routing N connections.

### The canonical pump loop

One "turn" of the driver, for an active (client) connection. Server is
identical except you call `tcp_listen` instead of `tcp_connect` and watch
for the `HALF_OPEN` → `ESTABLISHED` transition.

```c
// --- one-time setup ---
void* mem = aligned_alloc(tcp_handle_align(), tcp_handle_size());
tcp_init(mem, local_ip, local_port, remote_ip, remote_port,
         csprng_u32(), /*initial_rto_ms=*/1000);
tcp_connect(mem, now_ms());            // or tcp_listen(mem, now_ms())

uint8_t pkt[1500];                     // MUST be >= tcp_max_packet()
size_t  n;

// --- per turn (run on packet arrival AND on a ~1-10 ms periodic timer) ---
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
}

// 3. Drive timers (RTO / TLP / TIME_WAIT / persist / delayed-ACK) AND flush
//    the data just buffered by tcp_send; then drain everything to the wire.
tcp_tick(mem, now);
while (tcp_extract_packet(mem, pkt, sizeof pkt, &n) == 0 && n > 0)
    wire_send(pkt, n);

// --- shutdown ---
tcp_close(mem, now_ms());              // then keep pumping turns until
// tcp_state(mem) == TCP_STATE_CLOSED  (FIN handshake + TIME_WAIT complete);
tcp_destroy(mem);                      // flips the magic guard (no free)
free(mem);                             // you own the memory
```

### The contract — do X, not Z

**MUST**
- Size every `extract_packet` buffer to **≥ `tcp_max_packet()`** (1500). A
  smaller buffer returns `BUFFER_TOO_SMALL` and leaves the packet staged.
- **Drain `extract_packet` in a loop until it returns 0** after every
  `inject_packet`, `tick`, and `close`. The egress ring holds only
  `TX_RING_CAP` (32) packets; not draining stalls emission. (`send` stages
  nothing itself — it buffers; the next `tick` flushes it.)
- Call **`tick()` periodically even when no packets arrive** — timers only
  fire there (see *Clock model*).
- Pass a **monotonic, non-decreasing `now_ms`**; use the same value for
  every call within a turn.
- Seed `iss` from a **CSPRNG** (per connection). Servers: cookie secret
  from a CSPRNG too.
- After `tcp_close`, **keep pumping** until `tcp_state` is `CLOSED`; only
  then `tcp_destroy` + free.

**SHOULD**
- Treat `inject_packet` errors (`NOT_FOR_US`, `MALFORMED_PACKET`,
  `INVALID_STATE`) as *drop-and-continue* — they are normal under a hostile
  or mis-routed wire, not fatal.
- Treat `WOULD_BLOCK` from `send` as backpressure (the send ring is full);
  retry after a later turn drains it. Treat `CONNECTION_CLOSED` from `recv`
  as EOF and `CONNECTION_RESET` as an aborted peer.
- Drive `tick()` *event + periodic*: right after a batch of injects, and on
  a 1–10 ms timer for the idle case.

**DON'T**
- Don't touch one handle from two threads at once — the stack has **no
  internal locking** (it's single-threaded by design; shard TCBs across
  threads, one owner each).
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
| `WRITABLE` | `send` will accept bytes (Established/CloseWait + ring has room). |
| `ESTABLISHED` | Handshake complete; bulk data may flow. |
| `PEER_CLOSED` | Peer sent FIN — keep draining `recv`, then `close` your side. |
| `CLOSED` | Fully torn down; safe to `destroy`. |
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
A `Tcb` is ~2.15 MiB, so **box it** (or use the `heap-buffers` feature, or
the `small-buffers` feature for many idle TCBs) rather than holding it as a
stack local — see *Memory footprint*. Pure-Rust callers also need the
larger `RUST_MIN_STACK` from `.cargo/config.toml` for stack-allocated TCBs.

### How do you know you got it right? (canonical conformance)

There is a canonical, executable answer: **drive a hash-verified
bidirectional bulk transfer against a reference TCP and check both
SHA-256 digests match.** If a fresh, independent TCP (the Linux kernel,
gVisor's netstack, or even a second instance of this stack in loopback)
agrees with you byte-for-byte in *both* directions over a multi-MiB
transfer, your integration — sizing, ordering, draining, clocking, close
sequence — is correct. A single dropped/duplicated/reordered byte from a
driver bug changes the digest.

The repo ships these as the reference self-tests; port the one closest to
your transport:

| Self-test | What it proves | File |
|---|---|---|
| **vs gVisor netstack** | 1 GiB each way, SHA-256 verified, client + server | `bindings/gvisor/integration_test.go`, `server_integration_test.go` |
| **vs real Linux kernel (TUN)** | Same, against an actual kernel TCP | `bindings/gvisor/tun_test.go`, `tun_server_test.go` |
| **Adversarial channel** | Survives loss/reorder/dup/corruption/jitter | `bindings/gvisor/chaos_test.go` |
| **Pure-Rust loopback** | Two TCBs talk through an in-memory wire | `src/loopback_tests.rs` |

A minimal acceptance checklist for a new binding:

- [ ] `tcp_abi_version()` matches the header you built against.
- [ ] Handshake reaches `ESTABLISHED` against a real peer.
- [ ] A ≥ 1 MiB bidirectional transfer matches SHA-256 **both ways**.
- [ ] Same transfer over a lossy/reordering channel still matches.
- [ ] Graceful `close` reaches `CLOSED` on both ends (no leaked handles).
- [ ] A fuzz/property run of your wrapper shows no leaks or panics.

If those pass, you've done all the right things — the digests are the
proof.

## Testing

| Layer | What it covers | Files |
|---|---|---|
| **Property tests** | Wire codec round-trips; checksum integrity; serial-arithmetic | `src/property_tests.rs` (proptest, 4096 cases each) |
| **Conformance tests** | Exact wire bytes per spec scenario | `src/conformance_tests.rs` |
| **Loopback tests** | End-to-end behavioral tests via in-memory peer | `src/loopback_tests.rs` |
| **Server / adversarial** | LISTEN/SYN_RCVD hardening (cookies, SYN flood, blind RST/ACK) | `src/server_tests.rs` |
| **gVisor interop** | Against Google's reference netstack | `bindings/gvisor/*_test.go` |
| **smoltcp interop** | Against smoltcp (the dominant no_std Rust TCP stack, used in embedded). In-memory channel between two userspace stacks — completely independent codebases negotiating options + sequencing data. | `src/smoltcp_interop_tests.rs` |
| **Real Linux TUN** | Against the Linux kernel TCP stack via TUN | `bindings/gvisor/tun_test.go` |
| **netem benchmark** | Throughput under controlled loss / delay | `bindings/netem/bench_test.go` |
| **packetdrill-DSL runner** | Per-packet conformance scripts in packetdrill syntax | `bindings/packetdrill/*.go` + `scripts/*.pkt` |
| **eBPF uprobe observability** | bpftrace uprobes on the cdylib's FFI entry points (counts + latency histograms); kernel-side `tcpretrans` comparison during the iperf3 baseline | `bindings/bpf/` |
| **perf flamegraphs (CI)** | `perf record` wrapping the netem benchmark → `inferno-flamegraph` SVG; kernel-TCP iperf3 baseline through netns + veth + netem | `.github/workflows/perf-bench.yml` |
| **Real-world HTTP/curl/wrk** | cdylib hosts an HTTP/1.1 echo server through a TUN; real `curl` + `wrk` exchange messages. Covers GET / POST / 1 MiB bodies, slow uploaders (`--limit-rate`), sequential connections (LISTEN re-arm), wrk load, TIME_WAIT churn (50 sequential), and N-way concurrent connections (10 + 50 parallel TCBs sharing the TUN with port-keyed demux). | `bindings/realworld/http_test.go`, `concurrent_test.go` |
| **Real TLS over the cdylib** | Go's `crypto/tls.Server` wraps a custom `net.Conn` backed by the cdylib + TUN pair; real `curl --insecure` does HTTPS round-trips. Validates TCP behaviour under handshake-sensitive workloads (small writes, half-close timing, MAC-validated bulk transfer) — anything our stack mis-orders or corrupts surfaces as a TLS alert, not silent corruption. | `bindings/realworld/tls_test.go` |
| **h2spec HTTP/2 conformance** | `h2spec` (nghttp2's official HTTP/2 conformance suite) runs all 44 generic tests against an HTTP/2 server hosted on our TCP stack via TLS + ALPN. Each test case is a fresh TCP+TLS+HTTP/2 connection — exercises the LISTEN re-arm cycle at scale plus framing-sensitive H2 traffic. All 44/44 generic tests pass. | `bindings/realworld/h2spec_test.go` |
| **git clone over HTTPS** | Real `git clone https://…/repo.git` against a bare repository served by `http.FileServer` over the cdylib's TLS listener. Exercises chatty HTTP/1.1 traffic (many small pkt-line writes interleaved with variable-length pack/object body reads). End-to-end signal: the cloned working tree's bytes must match the source repo exactly. | `bindings/realworld/git_test.go` |
| **Userspace UDP server stress** | A standalone Rust harness (`bindings/wgserver-rs/`) hosts N TCBs in LISTEN on a single UDP socket. A pure-Go driver (`bindings/wgserver/`) — no cgo, no kernel TUN, no root — runs adversarial scenarios (SYN flood ±cookies, blind RST/ACK, cookie forgery, bare-ACK reflection check, malformed-packet spray, wrong-IP rejection, in-window RST in SYN_RCVD, …) and a 10 000-connection functional scale test (≈ 1.5 GiB RSS with `--features small-buffers`, p99 ≈ 80 ms loopback). | `bindings/wgserver-rs/src/server.rs`, `bindings/wgserver/{scale,adversary}_test.go` |

### packetdrill scripts

The `bindings/packetdrill/` package is a Go-native runner for
packetdrill-style `.pkt` scripts that drives our cdylib instead of the
kernel's POSIX socket layer. Each `.pkt` file becomes a Go subtest.

Currently 17 scripts cover handshake (active + passive), full-options
SYN, Window Scale negotiation, ECN-Setup, IW=10 burst, SACK negotiation,
PRR fast retransmit, RFC 6675 selective retransmit (single + multi-block
+ multi-hole), TLP probe before RTO, data transfer + pattern
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

`.github/workflows/perf-bench.yml` runs the netem suite under `perf
record` and renders a CPU flamegraph SVG. Same workflow also runs a
kernel-TCP iperf3 baseline through a veth + netem with the matching
profile, plus the `bpftrace` uprobe trace described below.
Artifacts (flamegraph, uprobe histograms, iperf3 JSON, kernel
retransmit log) are uploaded for offline inspection. Trigger:
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
    -c "./bindings/netem/netem.test -test.run=^TestNetem_LAN_NoLoss_1msDelay$"
```

The companion Go test (build tag `bpftrace`) wraps this and
asserts the expected symbols are observed at non-zero rates,
catching accidental `#[no_mangle]` removals. The CI workflow uses
`bpfcc-tools`' `tcpretrans` against the kernel iperf3 baseline so
the artifact set has apples-to-apples retransmit counts on both
sides. See `bindings/bpf/README.md` for the full toolkit.

### Other canonical suites not (yet) integrated

- **AFL fuzzing** of `wire::parse` — the entire adversarial surface from
  hostile peers. Cheap to add.
- **Upstream packetdrill scripts** (Google's Linux TCP test corpus) —
  our DSL runner is compatible in shape but uses `--connect`/`--send`-
  style directives instead of socket syscalls, so existing scripts need
  light adaptation.

## Project layout

```
src/
├── lib.rs               # crate-level constants (BUF_CAP, MSS, MAX_PACKET)
├── error.rs             # TcpError + FFI error codes
├── state.rs             # RFC 9293 state machine enum
├── wire.rs              # IPv4 + TCP codec (parse/emit, options, checksums)
├── ring.rs              # Fixed-capacity SPSC byte ring
├── reassembly.rs        # RFC 6675 multi-hole receive reassembler
├── scoreboard.rs        # RFC 6675 sender-side SACK scoreboard + NextSeg
├── congestion.rs        # PRR-Reno + slow-start / CA (was Tahoe)
├── tcb.rs               # The state machine itself (~2 kloc)
├── ffi.rs               # Stable C ABI
├── loopback_tests.rs    # End-to-end behavioral tests
├── conformance_tests.rs # Per-spec wire-byte assertions
├── property_tests.rs    # proptest fuzzing
├── rack.rs              # RACK loss detector (RFC 8985)
├── send_queue.rs        # Per-segment send metadata (RACK / TLP)
├── tx_ring.rs           # Multi-slot egress staging ring (32 packets)
└── server_tests.rs      # Passive-open + adversarial inputs

bindings/
├── csharp/              # .NET integration test + wrapper
├── python/              # CPython ctypes wrapper + unittest suite
├── gvisor/              # Go: gVisor netstack interop + real-kernel TUN test
├── netem/               # Go: TUN + tc-netem throughput benchmark
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

The stack assumes the host is friendly but the peer is hostile.

- **Resource exhaustion**: bounded SYN_RCVD retransmits (default 5),
  optional stateless SYN cookies, no allocator to be drained.
- **Off-path injection**: 5-tuple filter on `inject_packet`; RFC-compliant
  acceptability checks on RST/SYN/ACK; SYN-cookie path is keyed by a
  caller-supplied 128-bit secret (we ship a no_std SipHash-2-4 impl, with
  RFC test vectors).
- **Reflection / amplification**: a bare ACK in `LISTEN` is silently
  dropped (RFC 793 would RST; the spec response would let an attacker use
  us as a reflector), spoofed cookie ACKs face a 1-in-2²⁹ blind-forgery
  rate per attempt.
- **Malformed inputs**: every parser path is bounds-checked + returns
  `Result`; `parse_never_panics` + `parse_never_panics_iplike` proptests
  cover 4096+ cases each per run.

## Licence

MIT OR Apache-2.0.
