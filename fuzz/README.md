# Fuzz harnesses for tcp-sans-io

This sub-crate hosts `cargo-fuzz` targets that exercise the parts of
the stack exposed to adversarial input. The entire surface from a
hostile peer flows through `wire::parse` and then `Tcb::inject_packet`,
so those are the natural targets.

## Targets

| Target | Property checked |
|---|---|
| `wire_parse` | `wire::parse` never panics on any byte sequence. |
| `wire_parse_emit_roundtrip` | For any successfully parsed segment, re-emitting and re-parsing produces the same observable fields (seq, ack, flags, window, MSS / WS / TS / SACK options, payload). |
| `tcb_inject_sequence` | A fresh `Tcb` in `Listen` survives any sequence of arbitrary `inject_packet` calls + clock ticks without panicking, blowing through bounded buffers, or leaving the state machine in an unreachable state. |
| `tcb_client_session` | Drives the **active-open send/retransmit** path (`connect` → scripted SACK-enabled handshake → `send` → fuzzer-chosen cumulative-ACK offsets, SACK blocks, and clock jumps that fire TLP/RTO). Asserts the internal `TcpError::Overflow` invariant code never escapes the API. This is the path the `tcp_tick: -9` TLP partial-ACK bug lived in. |

Both `tcb_*` targets treat a returned `TcpError::Overflow` as a hard
failure: it is an *internal* "a sequence-derived buffer offset/length
went out of range" code that must be unreachable from any inbound packet
or timer tick. Swallowing it (as the original `tcb_inject_sequence` did)
is what let the TLP regression slip past fuzzing.

### Oracles

Beyond "must not panic", the stateful targets assert a battery of
invariants after every operation (`send` / `inject_packet` / `tick` /
`close` / `extract_packet`):

| Oracle | What it catches |
|---|---|
| Internal-error escape | `Overflow` / `BufferTooSmall` (with `MAX_PACKET` buffers) returned across the API — internal "can't happen" codes. |
| `Tcb::debug_validate_invariants()` | `snd_una ≤ snd_nxt ≤ snd_max`; FIN/SYN sequence accounting; outstanding span never exceeds buffered bytes + phantom SYN/FIN; RTO armed only with data in flight; staged packet ≤ `MAX_PACKET`. |
| Emitted-packet parse + tuple | Every packet the stack emits must re-parse, and must be `local → peer` with the expected 4-tuple (no checksum/header/option corruption, no tuple confusion). |
| **Livelock / quiescence** | At a *fixed* clock with nothing injected, the stack must stop emitting within a bounded number of `tick`+drain cycles. A stack that emits forever at one instant is livelocked. |
| **Bounded output** | A single drain may not exceed a hard packet cap (no ACK/output storm). |
| **Monotonic progress** | `snd_una` and `rcv_nxt` (cumulative cursors) may only advance in serial-number space. |
| Legal state transitions | Only RFC 793 edges (`Established → FinWait1`, …); rejects impossible jumps like `Closed → Established`. |
| Bogus-ACK non-mutation | An ACK above `snd_max` must not advance/consume sender state. |
| Duplicate-ACK idempotence | A lone duplicate pure ACK must not move sequence state or drain the send ring. |
| No-loss convergence | A scripted lossless sub-session, after data + FIN are ACKed, must end with an empty send ring, `snd_una == snd_nxt`, and reach `FinWait2`. |

The **infinite-loop** defenses come in two layers, because the two
failure modes are different:

* **Single-call hangs** (a `loop {}` inside one `tick`/`inject_packet`
  that never returns) are caught by libFuzzer's `-timeout` *and* by the
  library's own `loop_budget_exhausted` guards on the send-emit,
  OOO-reassembly-drain, and SACK-scoreboard cursor loops. Those guards
  `panic!` under test/fuzz (`std`) builds and degrade to a graceful stop
  in production `no_std` — so a peer can never wedge the CPU.
* **Cross-call livelocks** (each call returns, but the system never
  settles) are caught by the quiescence oracle above.

Always pass a tight `-timeout` so a hang becomes a crash artifact rather
than a silent wall-clock stall:

## Running locally

```sh
# One-time:
cargo install cargo-fuzz

# Quick smoke (10s). -timeout=10 turns any single-input hang into a crash.
cargo +nightly fuzz run wire_parse -- -max_total_time=10 -timeout=10

# Longer (5 min, common starting corpus):
cargo +nightly fuzz run wire_parse -- -max_total_time=300 -timeout=10

# All stateful targets, 1 min each (heap-backed buffers keep ASAN's stack
# shallow — see the heap-buffers note below).
for t in tcb_inject_sequence tcb_client_session; do
    cargo +nightly fuzz run "$t" -- -max_total_time=60 -timeout=10 -rss_limit_mb=4096
done
```

Crashes land under `fuzz/artifacts/<target>/crash-…`. Minimize with
`cargo +nightly fuzz tmin <target> <crash-file>` and re-run to verify
the minimized input reproduces.

## Seed corpus

`cargo-fuzz` starts from an empty corpus by default. Better seeds = much
faster discovery of edge cases. Drop pre-canned valid TCP segments
under `fuzz/corpus/wire_parse/` (one packet per file) to seed.

## Notes

* Targets require nightly Rust (`libfuzzer-sys` uses unstable
  `#[panic_handler]` integration). The main crate stays stable.
* This sub-crate is intentionally `[workspace]`-ignored so it doesn't
  inherit the parent's `panic = "abort"` setting (libFuzzer needs
  `panic = "unwind"`).
* The fuzz crate enables the `heap-buffers` feature so each `Tcb`'s
  per-direction rings live on the heap. The stateful targets build more
  than one `Tcb` per iteration; with the default inline 1 MiB rings, ASAN
  can stack-overflow before the target body even runs.
* The library's `loop_budget_exhausted` guards only `panic!` when the
  `std` feature (or `cfg(test)`) is active. cargo-fuzz enables `std`
  here, so internal loop-budget violations surface as crashes during
  fuzzing while staying zero-cost / non-panicking in the shipped
  `no_std` cdylib.
* The CI workflow `perf-bench.yml` does NOT run fuzzers — fuzzing is
  an interactive / offline activity. A nightly fuzz GHA cron could be
  added if appetite grows.
