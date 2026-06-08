---
name: integrate-tcp-sans-io-binding
description: >-
  Step-by-step guide to integrate the tcp-sans-io stack into a new host
  language / transport and prove the integration is correct. Use this when
  writing a new FFI binding, embedding the Rust crate directly, or wiring the
  stack to a new datagram transport (WireGuard, UDP, TUN, SHM). Covers the
  required host responsibilities, the canonical pump loop, and a two-tier
  conformance certification (built-in smoke test, self-loopback hash test,
  optional foreign-stack interop).
---

# Integrating and certifying a tcp-sans-io binding

This skill takes you from "I have the cdylib / rlib" to "my integration is
provably correct." Work the steps in order; each ends with a check you can
run. The authoritative reference is the **Integrating the library**,
**Clock model and tick cadence**, and **Extents and bounds** sections of
`README.md` — read them once before starting.

## Mental model (read first)

The stack owns *only* the TCP protocol state machine. **The host owns the
clock, the memory, the datagram transport, the scheduling, and the
application data flow.** The stack never allocates, blocks, threads, reads
the clock, or touches a socket. You feed it inbound datagrams + a clock and
drain outbound datagrams; it never surprises you with I/O.

## Step 0 — Smoke test the linkage (`tcp_selftest`)

Before writing any pump loop, confirm the library is correctly linked and
healthy from your language:

- FFI: call `tcp_selftest()` → expect `0`. A negative code means the link /
  ABI / calling convention is wrong (or the core is broken); fix that first.
- Also verify `tcp_abi_version()` matches the header you built against, and
  `tcp_max_packet()` returns 1500.

`tcp_selftest` runs two in-process stacks through a byte-exact bidirectional
transfer entirely inside the library — it needs no storage, transport, clock,
or peer. If this fails, nothing downstream can work. (Cost: ~256 KiB of the
calling thread's stack for <1 ms.)

## Step 1 — Provide the five host responsibilities

1. **Storage**: `tcp_handle_size()` bytes at `tcp_handle_align()` alignment,
   one block per connection, owned and freed by you. NOTE: `tcp_init`
   materialises a full ~2.15 MiB `Tcb` (default 1 MiB rings) on the *calling
   thread's stack* — call it from a thread with a few MiB of stack, or build
   the cdylib with the `small-buffers` / `heap-buffers` feature.
2. **A monotonic millisecond clock** (`Instant` / `CLOCK_MONOTONIC` /
   `QueryPerformanceCounter`). Read it once per turn; pass the same `now_ms`
   to every call that turn.
3. **A datagram transport** moving complete IPv4+TCP datagrams to/from the
   peer.
4. **A driver loop** (Step 2) that also calls `tick()` periodically even when
   idle.
5. **A CSPRNG `iss`** per connection (RFC 6528); servers also pass a 16-byte
   CSPRNG secret to `tcp_set_cookie_secret` for stateless SYN-cookie flood
   resistance.

## Step 2 — Implement the canonical pump loop

Port the loop from `README.md` → *Integrating the library* → *The canonical
pump loop*. The non-obvious rules that bindings get wrong:

- Size every `extract_packet` buffer to **≥ `tcp_max_packet()`** (1500).
- **Drain `extract_packet` until it returns 0** after every `inject_packet`,
  `tick`, and `close` (the egress ring holds only 32 packets).
- `tcp_send` only **buffers**; the next `tick` turns it into segments.
- Call `tick()` **periodically even when idle** — RTO / TLP / TIME_WAIT /
  persist / delayed-ACK only fire there. ~10 ms cadence is plenty (matches
  the TLP floor; 20× finer than `RTO_MIN`).
- Treat `NOT_FOR_US` / `MALFORMED_PACKET` from `inject` as drop-and-continue,
  `WOULD_BLOCK` from `send` as backpressure, `CONNECTION_CLOSED` from `recv`
  as EOF.
- After `close`, keep pumping until `tcp_state` is `CLOSED`, then `destroy`.
- One handle is single-threaded — the stack has no internal locking.

## Step 3 — Tier-1 certification: self-loopback hash test (REQUIRED)

This is the canonical "did I do it right?" check, and it needs **no external
stack, no root, no real sockets** — you drive two instances of your own
binding against each other through an in-memory channel that injects loss /
reordering / duplication, and verify a byte-exact bidirectional transfer.

The reference implementation is **`bindings/conformance/`** (Rust). Run it
to see the expected output:

```sh
cd bindings/conformance && cargo run --release
# ... [ OK ] kitchen-sink: 256 KiB each way, digests match
# PASS — integration is conformant.
```

Port its ~200 lines into your language's test suite, using *your* wrapper:

1. Create two handles: client (`tcp_connect`) and server (`tcp_listen`).
2. Each turn: `tick` both with a virtual clock; ferry each side's extracted
   packets through a chaos channel (drop ~1%, dup ~1%, reorder ~1%) into the
   other's `inject_packet`; both `send` a deterministic per-offset byte
   pattern; both `recv` and verify each received byte equals the generator at
   its running offset.
3. When both have sent and received the full transfer, `close` both and pump
   until both reach `CLOSED` / `TIME_WAIT`.
4. **Pass criterion: every received byte matched, both directions, and both
   sides closed cleanly.** A single dropped/duplicated/reordered byte from a
   driver bug changes the result.

Run the clean profile first (no chaos), then the lossy/reorder/dup/combined
profiles. All must pass.

## Step 4 — Tier-2 certification: foreign-stack interop (RECOMMENDED)

Tier 1 proves your driver is self-consistent; Tier 2 proves the stack
interoperates with a *different* TCP. Port (or run) one of:

- `bindings/gvisor/integration_test.go` / `server_integration_test.go` —
  1 GiB each way, SHA-256 verified, against Google's gVisor netstack.
- `bindings/gvisor/tun_test.go` — against the real Linux kernel via TUN
  (needs root + CAP_NET_ADMIN).
- `bindings/gvisor/chaos_test.go` — the same under an adversarial channel.

## Acceptance checklist

- [ ] `tcp_selftest()` returns 0 and `tcp_abi_version()` matches the header.
- [ ] Handshake reaches `ESTABLISHED` against a real peer.
- [ ] Tier-1 self-loopback: ≥ 256 KiB bidirectional, byte-exact, clean close.
- [ ] Tier-1 under loss + reorder + dup still byte-exact.
- [ ] (Recommended) Tier-2 interop: ≥ 1 MiB bidirectional vs a foreign stack.
- [ ] Graceful `close` reaches `CLOSED` on both ends — no leaked handles.
- [ ] A fuzz/property pass of your wrapper shows no leaks or panics.

If those pass, the integration is conformant — the matching digests are the
proof.

## Troubleshooting (symptom → cause)

| Symptom | Likely cause |
|---|---|
| `tcp_selftest()` ≠ 0 / segfault on any call | Wrong struct layout, calling convention, or ABI version mismatch. Recheck the header against `tcp_abi_version()`. |
| Stack overflow inside `tcp_init` | Calling thread stack too small for the ~2.15 MiB `Tcb`; use a bigger stack or `small-buffers`/`heap-buffers`. |
| Handshake never completes | Not draining `extract_packet` to 0, or not delivering the SYN/SYN-ACK both ways, or 5-tuple demux routing to the wrong handle. |
| Transfer stalls mid-stream | Not calling `tick()` periodically (timers never fire), or not draining the egress ring (32-packet cap), or feeding a non-monotonic clock. |
| `recv` returns 0 forever but peer sent data | A gap the receiver is waiting on; ensure you deliver *all* inbound datagrams and keep ticking so retransmits flow. |
| `BUFFER_TOO_SMALL` from `extract_packet` | Extract buffer smaller than `tcp_max_packet()` (1500). |
| `OVERFLOW` (`-9`) from any call | Internal invariant bug — should be impossible; please file it with the input. |
