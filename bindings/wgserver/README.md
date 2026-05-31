# wgserver — Go driver for the userspace TCP server harness

Drives the Rust `wgserver` binary (`bindings/wgserver-rs/`) over a
loopback UDP socket. Encapsulates raw IPv4+TCP packets as UDP
datagrams — a "WireGuard-shaped" transport without the crypto. **No
cgo, no kernel TUN, no root.** Runs on Linux, macOS, and Windows.

The driver implements:

* `wire.go` — pure-Go IPv4 + TCP encoder/decoder with options (MSS,
  WScale, Timestamps, SACK_PERMITTED) and Internet checksums.
* `transport.go` — UDP socket wrapper + central reader goroutine that
  demultiplexes on the inner TCP 5-tuple to per-client bounded
  inboxes.
* `miniclient.go` — minimal stateful TCP client (~300 LoC) doing
  handshake → echo → close with an option matrix (no-opts / TS-only
  / WS+TS / SACK+WS+TS).
* `harness.go` — subprocess management for the Rust binary (build,
  spawn, wait-ready, shutdown via `"shutdown\n"` on stdin).

## Running

The harness auto-builds `wgserver` on the first test invocation. To
skip the build (e.g. when iterating), pre-build once and set
`WGSERVER_NO_BUILD=1`:

```sh
# One-time build (stress profile).
cargo build --release --manifest-path bindings/wgserver-rs/Cargo.toml \
            --features small-buffers

cd bindings/wgserver

# Default suite (~5 s).
go test -v -timeout 120s ./...

# 10000-connection scale test.
STRESS=1 go test -v -timeout 300s -run TestWGServer_10000_Connections ./...

# Slow no-cookies bounded-half-open test (~65 s).
STRESS=1 go test -v -timeout 180s -run TestWGServer_SynFlood_NoCookies ./...

# All STRESS tests.
STRESS=1 go test -v -timeout 300s ./...
```

## Tests

### Scale

| Test                              | Default? | What it asserts                                                  |
| --------------------------------- | -------- | ---------------------------------------------------------------- |
| `TestWGServer_Smoke`              | ✅       | A single mini-client completes echo round-trip.                  |
| `TestWGServer_1000_Connections`   | ✅       | 1 000 parallel mini-clients all succeed; reports latency pcts.   |
| `TestWGServer_10000_Connections`  | `STRESS=1` | 10 000 parallel mini-clients all succeed; reports latency pcts. |

Headline observed numbers on a 32-thread i9-14900K, Windows:

```
scale: 10000/10000 ok (100.00%) in 2.55s; p50=63ms p95=68ms p99=79ms
       max=80ms; rx=50000 tx=50000 dropped=0 mismatch=0
```

### Adversarial

| Test                                       | Default? | What it asserts                                                       |
| ------------------------------------------ | -------- | --------------------------------------------------------------------- |
| `TestWGServer_SynFlood_NoCookies`          | `STRESS=1` | Half-open lifetime is **bounded**: after ~63 s the listener re-arms. |
| `TestWGServer_SynFlood_Cookies`            | ✅       | 20 K forged SYNs + cookies on → server holds no state; legit succeeds. |
| `TestWGServer_BareAck_NoReflection`        | ✅       | Bare ACK in LISTEN emits zero packets (no reflection).                |
| `TestWGServer_Listen_DropsFinSilently`     | ✅       | Bare FIN in LISTEN emits zero packets.                                |
| `TestWGServer_Listen_DropsRstSilently`     | ✅       | Bare RST in LISTEN emits zero packets.                                |
| `TestWGServer_Listen_RstOnSynAck`          | ✅       | SYN+ACK in LISTEN gets exactly one RST (RFC 9293).                    |
| `TestWGServer_BlindRst_Established`        | ✅       | 200 off-path RSTs do not abort an established connection.             |
| `TestWGServer_BlindRst_InWindow_SynRcvd`   | ✅       | In-window RST in SYN_RCVD reverts to LISTEN; legit handshake works.   |
| `TestWGServer_BlindAck_InSynRcvd`          | ✅       | 100 random ACKs in SYN_RCVD do not promote; correct third ACK still works. |
| `TestWGServer_CookieForgery_Rejected`      | ✅       | A forged third-ACK with a guessed cookie never promotes.              |
| `TestWGServer_WrongLocalIP_Rejected`       | ✅       | Packets with wrong destination IP are silently dropped.               |
| `TestWGServer_Malformed_DontWedge`         | ✅       | Spray of truncated / bad-checksum / fragmented / over-long options does not wedge the server. |
| `TestWGServer_SynRetransmit_Idempotent`    | ✅       | Duplicate SYNs in SYN_RCVD do not break the handshake.                |

## Notes on observed behaviors

* **`Listen_RstOnSynAck`** — the cdylib addresses the RST emitted in
  response to a LISTEN-state SYN+ACK to the wildcarded `remote`
  `(0.0.0.0, 0)`. On a real network this is unroutable; in the
  integration test we register a "wildcard" inbox to observe the RST
  byte stream and assert it. The behaviorally critical property is
  that the server stays in LISTEN and emits exactly one packet.
* **`SynFlood_NoCookies`** — single-Tcb-per-port means the FIRST
  forged SYN locks the listener into SYN_RCVD; subsequent SYNs
  (legitimate or otherwise) are rejected until the
  `MAX_SYN_RCVD_RETRIES` (= 5) retransmit budget expires with
  Karn-doubling RTO capped at 60 s — roughly 63 s of unavailability.
  The production defense for fast availability under flood is SYN
  cookies (`--cookies <hex32>`); cookies hold no per-half-open state.

## OS knobs

* For the 10 000-connection test, the harness bumps `SetReadBuffer`
  and `SetWriteBuffer` on its UDP socket to 16 MiB. On Linux, ensure
  `net.core.rmem_max` ≥ 16 MiB if you scale further.
* `GOMAXPROCS` defaults to NumCPU — the central reader goroutine plus
  10 000 mini-client goroutines benefits from many P's.
