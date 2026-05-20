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

## Running locally

```sh
# One-time:
cargo install cargo-fuzz

# Quick smoke (10s):
cargo +nightly fuzz run wire_parse -- -max_total_time=10

# Longer (5 min, common starting corpus):
cargo +nightly fuzz run wire_parse -- -max_total_time=300

# All three targets, 1 min each:
for t in wire_parse wire_parse_emit_roundtrip tcb_inject_sequence; do
    cargo +nightly fuzz run "$t" -- -max_total_time=60
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
* The CI workflow `perf-bench.yml` does NOT run fuzzers — fuzzing is
  an interactive / offline activity. A nightly fuzz GHA cron could be
  added if appetite grows.
