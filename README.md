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

The stack lands roughly at **"circa 2013-era TCP"** — equivalent in
algorithmic feature set to Linux 3.x / FreeBSD 9-10 era stacks.

| Feature | RFC | Year | Status |
|---|---|---|---|
| Base state machine | RFC 9293 (793 update) | 2022 | ✅ |
| Active + passive opens | RFC 9293 | — | ✅ both |
| SYN cookies | RFC 4987 | 2007 | ✅ (optional) |
| MSS option | RFC 9293 | — | ✅ |
| Timestamps + PAWS-lite | RFC 7323 §3 | 2014 | ✅ |
| **Window Scale** | **RFC 7323 §2** | **2014** | ✅ added in this generation |
| SACK_PERMITTED + SACK | RFC 2018 | 1996 | ✅ signaling |
| Karn / RFC 6298 RTO | RFC 6298 | 2011 | ✅ |
| Tahoe slow-start / CA | RFC 5681 | 2009 | ✅ |
| **PRR-Reno fast recovery** | **RFC 6937** | **2013** | ✅ added in this generation |
| **IW=10 initial window** | **RFC 6928** | **2013** | ✅ added in this generation |
| Persist (zero-window probe) | RFC 1122 §4.2.2.17 | 1989 | ✅ |
| Delayed ACK | RFC 1122 §4.2.3.2 | 1989 | ✅ |
| 2·MSL TIME_WAIT | RFC 793 §3.4 | 1981 | ✅ (60 s) |
| **ECN** | **RFC 3168** | **2001** | ✅ added in this generation |

### Deliberately deferred (post-2013 modernisations)

| Feature | RFC | Why deferred |
|---|---|---|
| RFC 6675 SACK-based selective retransmit | 2012 | Requires multi-hole receive reassembly + send-side SACK scoreboard. Current single-hole + Tahoe go-back-N still recovers correctly, just less efficiently on multi-loss episodes. ~400-line follow-up. |
| RACK-TLP loss detection | RFC 8985 + 8298 (2021) | Replaces dup-ACK-counting + RTO with time-based loss detection. Would eliminate most spurious-RTO stalls on lossy / reordering paths. ~300-line follow-up. |
| CUBIC congestion control | RFC 9438 (2024) | We use Reno-class (PRR). CUBIC is friendlier on long-fat networks; substantial state-machine change. |
| BBR | (Google, 2016) | Bandwidth-probing CC; orthogonal architecture. |
| TFO (TCP Fast Open) | RFC 7413 | Data-in-SYN; security model is complex. |
| DSACK | RFC 2883 | Refinement on SACK; depends on RFC 6675 landing first. |
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

Per-connection: ~2 MiB.

- `BUF_CAP = 1 MiB` send ring + `1 MiB` receive ring.
- 16 KiB single-hole reassembly buffer.
- ~1.5 KiB IP packet staging + SYN-cookie secret + various scalar state.

Hosts that need many idle connections can shrink `BUF_CAP` (must be a power
of two) — this is the only knob. The 1 MiB default is chosen so the receive
window is large enough to fill the BDP of typical WAN paths (e.g. 50 ms RTT
at 160 Mbit/s).

The Rust thread stack default (1 MiB on Windows, 8 MiB on Linux) is **too
small** for a Tcb constructed as a stack local on Windows. The included
`.cargo/config.toml` sets `RUST_MIN_STACK = 8388608` for the build/test
environment. Production callers route through the C ABI (`tcp_init`) which
writes into host-provided heap storage, so this only affects pure-Rust users
and tests.

## How will it perform in 2026?

Honest assessment by path profile (in-process numbers; see *Benchmarks*
below for real-network):

| Path | How we'd do |
|---|---|
| LAN / datacenter, low loss | ✅ Fine. PRR + SACK signaling + WS + IW=10 give modern-class behavior. |
| Typical Internet WAN (50 ms RTT, 0.1-1 % loss) | 🟡 Workable. Within ~2× of CUBIC for steady-state bulk; without RFC 6675 we lose throughput on multi-loss episodes. |
| Wireless / cellular (1-5 % loss, reordering) | ⚠️ Noticeable degradation. The biggest missing piece is RACK-TLP — every loss episode that confuses dup-ACK heuristics waits a full RTO. |
| High-BDP (transcontinental 10G) | 🟡 Capped by `BUF_CAP`: ~`1 MiB / RTT` ≈ 160 Mbit/s at 50 ms. Bump `BUF_CAP` to lift the ceiling. |

The single biggest remaining win is **RACK-TLP** for lossy paths. Then
**RFC 6675 selective retransmit** for high-loss bulk. Both are tracked above.

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
cargo test  --release --lib       # 83 tests (loopback + conformance + property + server)
cargo clippy --release --lib --no-deps -- -D warnings
```

The C header is in `include/tcp_sans_io.h` (hand-maintained — keep in sync
with `src/ffi.rs`).

## Bindings

- **C** — `include/tcp_sans_io.h`.
- **C#** — `bindings/csharp/` (`TcpStream.cs`, `Native.cs`, integration test).
- **Python** — `bindings/python/` (ctypes wrapper + unittest suite).
- **Go** — `bindings/gvisor/` (gVisor netstack interop tests) and
  `bindings/netem/` (real Linux kernel interop + throughput benchmark).

All use the host-allocated storage pattern: query
`tcp_handle_size()` / `tcp_handle_align()`, allocate that much memory in the
host, pass the pointer to `tcp_init`. Memory ownership stays with the host.

## Testing

| Layer | What it covers | Files |
|---|---|---|
| **Property tests** | Wire codec round-trips; checksum integrity; serial-arithmetic | `src/property_tests.rs` (proptest, 4096 cases each) |
| **Conformance tests** | Exact wire bytes per spec scenario | `src/conformance_tests.rs` |
| **Loopback tests** | End-to-end behavioral tests via in-memory peer | `src/loopback_tests.rs` |
| **Server / adversarial** | LISTEN/SYN_RCVD hardening (cookies, SYN flood, blind RST/ACK) | `src/server_tests.rs` |
| **gVisor interop** | Against Google's reference netstack | `bindings/gvisor/*_test.go` |
| **Real Linux TUN** | Against the Linux kernel TCP stack via TUN | `bindings/gvisor/tun_test.go` |
| **netem benchmark** | Throughput under controlled loss / delay | `bindings/netem/bench_test.go` |
| **packetdrill-DSL runner** | Per-packet conformance scripts in packetdrill syntax | `bindings/packetdrill/*.go` + `scripts/*.pkt` |

### packetdrill scripts

The `bindings/packetdrill/` package is a Go-native runner for
packetdrill-style `.pkt` scripts that drives our cdylib instead of the
kernel's POSIX socket layer. Each `.pkt` file becomes a Go subtest.

Currently 10 scripts cover handshake (active + passive), full-options
SYN, Window Scale negotiation, ECN-Setup, IW=10 burst, SACK negotiation,
PRR fast retransmit, data transfer + pattern verification, and active /
passive close. Example:

```
--connect 10.0.0.1:49152 10.0.0.2:80
+0     > SEW 0:0(0) win 65535 <mss 1460, wscale 5, sackOK, TS val * ecr 0>
+.005  < S.  0:0(0) ack 1 win 32768 <mss 1460, wscale 7, sackOK, TS val 1 ecr *>
+0     > .   1:1(0) ack 1 <TS val * ecr 1>
--expect_state ESTABLISHED
```

Run all: `cd bindings/packetdrill && go test ./...`

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
├── congestion.rs        # PRR-Reno + slow-start / CA (was Tahoe)
├── tcb.rs               # The state machine itself (~2 kloc)
├── ffi.rs               # Stable C ABI
├── loopback_tests.rs    # End-to-end behavioral tests
├── conformance_tests.rs # Per-spec wire-byte assertions
├── property_tests.rs    # proptest fuzzing
└── server_tests.rs      # Passive-open + adversarial inputs

bindings/
├── csharp/              # .NET integration test + wrapper
├── python/              # CPython ctypes wrapper + unittest suite
├── gvisor/              # Go: gVisor netstack interop + real-kernel TUN test
├── netem/               # Go: TUN + tc-netem throughput benchmark
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
