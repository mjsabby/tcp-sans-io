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
- 16 KiB single-hole reassembly buffer.
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
The included `.cargo/config.toml` sets `RUST_MIN_STACK = 16777216` (16 MiB)
for the build/test environment, which comfortably fits multiple Tcbs (e.g.
loopback tests with peer + client) per thread. Production callers route
through the C ABI (`tcp_init`) which writes into host-provided heap
storage, so this only affects pure-Rust users and tests.

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
| **smoltcp interop** | Against smoltcp (the dominant no_std Rust TCP stack, used in embedded). In-memory channel between two userspace stacks — completely independent codebases negotiating options + sequencing data. | `src/smoltcp_interop_tests.rs` |
| **Real Linux TUN** | Against the Linux kernel TCP stack via TUN | `bindings/gvisor/tun_test.go` |
| **netem benchmark** | Throughput under controlled loss / delay | `bindings/netem/bench_test.go` |
| **packetdrill-DSL runner** | Per-packet conformance scripts in packetdrill syntax | `bindings/packetdrill/*.go` + `scripts/*.pkt` |
| **eBPF uprobe observability** | bpftrace uprobes on the cdylib's FFI entry points (counts + latency histograms); kernel-side `tcpretrans` comparison during the iperf3 baseline | `bindings/bpf/` |
| **perf flamegraphs (CI)** | `perf record` wrapping the netem benchmark → `inferno-flamegraph` SVG; kernel-TCP iperf3 baseline through netns + veth + netem | `.github/workflows/perf-bench.yml` |
| **Real-world HTTP/curl/wrk** | cdylib hosts an HTTP/1.1 echo server through a TUN; real `curl` + `wrk` exchange messages. Covers GET / POST / 1 MiB bodies, slow uploaders (`--limit-rate`), sequential connections (LISTEN re-arm), wrk load, TIME_WAIT churn (50 sequential), and N-way concurrent connections (10 + 50 parallel TCBs sharing the TUN with port-keyed demux). | `bindings/realworld/http_test.go`, `concurrent_test.go` |
| **Real TLS over the cdylib** | Go's `crypto/tls.Server` wraps a custom `net.Conn` backed by the cdylib + TUN pair; real `curl --insecure` does HTTPS round-trips. Validates TCP behaviour under handshake-sensitive workloads (small writes, half-close timing, MAC-validated bulk transfer) — anything our stack mis-orders or corrupts surfaces as a TLS alert, not silent corruption. | `bindings/realworld/tls_test.go` |

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
