//! tcp-sans-io
//!
//! Minimal, sans-I/O user-space TCP stack designed to sit in front
//! of an external WireGuard backend and behind a foreign-language async runtime
//! (C# / Python) via a stable C ABI.
//!
//! Both **active** opens (`connect`) and **passive** opens (`listen`) are
//! supported. The passive path implements the canonical RFC 793 server
//! states (LISTEN and SYN_RECEIVED) plus optional RFC 4987 SYN cookies
//! for stateless flood resistance.
//!
//! Design constraints:
//! * `#![no_std]`, no heap allocation, no panics, no threads, no syscalls.
//! * All I/O is performed by the *host* — the stack only ingests/emits buffers.
//! * Hot paths use fixed-size ring buffers and are zero-allocation.
//!
//! # Host safety contract
//!
//! This stack is sans-I/O and **one TCB per connection**: it owns no clock, no
//! sockets, and has no view of aggregate load. Most of its denial-of-service
//! defenses are *timer-driven* (RTO + the RFC 9293 R2 abort, the zero-window
//! USER TIMEOUT, the idle-peer keepalive reap, delayed ACKs) and only work if
//! the host drives them. A host that integrates this library **MUST**:
//!
//! 1. **Advance the clock and tick.** Call [`Tcb::set_now`] with a monotonic
//!    millisecond clock before each [`Tcb::inject_packet`] / [`Tcb::tick`], and
//!    call `tick()` regularly — at least as often as the soonest armed timer
//!    (`debug_next_deadline()` reports it; event-driving off that deadline is
//!    ideal). If the clock stops advancing or `tick()` is not called, **none**
//!    of the timer-based defenses fire: retransmits stall, and zero-window,
//!    stalling, or vanished-idle peers are never reaped. A frozen clock is a
//!    disabled safety net.
//!
//! 2. **Drain the egress ring after every call.** After each `inject_packet`
//!    and `tick`, call [`Tcb::extract_packet`] (buffer ≥ [`MAX_PACKET`])
//!    repeatedly until it returns 0 and transmit those bytes, *before* the next
//!    `inject_packet`. Replies (ACKs, retransmits, keepalive/persist probes)
//!    stage there; an undrained ring silently drops them and can wedge the
//!    connection.
//!
//! 3. **Bound the number of connections.** Only the host can: each TCB is
//!    independent and unaware of the others, and costs ≈ `2 * BUF_CAP` (~2 MiB
//!    by default, ~64 KiB under the `small-buffers` feature). The per-connection
//!    timers bound each connection's *lifetime*, never the aggregate *count*.
//!    Cap concurrent TCBs and refuse/evict past the budget, or an attacker who
//!    merely opens many connections exhausts memory regardless of any
//!    per-connection defense.
//!
//! 4. **Use SYN cookies on untrusted listeners.** Before exposing a listener to
//!    hostile traffic, call [`Tcb::set_cookie_secret`] with 16 bytes from a
//!    CSPRNG and rotate it periodically (old cookies stay valid ~64–128 s after
//!    rotation). Without cookies the stateful path is still flood-bounded (one
//!    half-open per TCB, capped SYN-ACK retransmits); cookies let one listener
//!    absorb a SYN flood holding *zero* per-connection state until the third
//!    ACK validates. A predictable or leaked secret defeats the protection.
//!
//! 5. **Act on lifecycle signals and release the TCB.** Read [`Tcb::poll`] and
//!    react: on `PEER_CLOSED` (peer FIN → `CLOSE_WAIT`) the host **must**
//!    eventually call [`Tcb::close`] — keepalive does *not* probe `CLOSE_WAIT`
//!    (the peer didn't vanish, it closed its half), so an un-closed connection
//!    is pinned until the host acts. On `ERROR` / `CLOSED` (including the
//!    RST-less local aborts from R2 / USER TIMEOUT / keepalive) drop the TCB or
//!    [`Tcb::reinit`] it for reuse; the slot is reclaimed only when the host
//!    releases it.
//!
//! 6. **Don't disable the idle/stall reapers without a replacement.** Keepalive
//!    and the USER TIMEOUT are **on by default** and are what bound an idle or
//!    stalling peer's hold on a TCB. A host that turns either off
//!    ([`Tcb::set_keepalive`]`(0, …)` / [`Tcb::set_user_timeout`]`(0)`) must
//!    provide its own idle/stall reaping or it reopens the memory-pinning DoS.
//!
//! Under `cfg(test)` we let `std` link so we can run a loopback harness that
//! simulates two TCBs talking through an in-memory wire.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(feature = "heap-buffers")]
extern crate alloc;

#[cfg(all(not(test), not(feature = "host_panic_handler"), not(feature = "std")))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// rustc emits DWARF unwind tables for cdylib+linux even with `panic = "abort"`,
// and those tables reference `rust_eh_personality` as a personality routine.
// With abort semantics this routine can never actually be called (panics turn
// into our `#[panic_handler]` above, which spins), but the symbol still has
// to resolve at link time when downstream tooling (e.g. Go's cgo linker)
// links against the cdylib.
//
// The stub below provides that symbol. It must never run; if it ever does,
// the unwinder is being driven on a panic-abort build, which is a bug.
#[cfg(all(
    not(test),
    not(feature = "host_panic_handler"),
    not(feature = "std"),
    target_os = "linux"
))]
#[no_mangle]
extern "C" fn rust_eh_personality() {
    loop {
        core::hint::spin_loop();
    }
}

pub mod congestion;
pub mod error;
pub mod ffi;
pub mod rack;
pub mod reassembly;
pub mod ring;
pub mod scoreboard;
pub mod selftest;
pub mod send_queue;
pub mod state;
pub mod tcb;
pub mod tx_ring;
pub mod wire;

pub use error::TcpError;
pub use state::State;
pub use tcb::{Endpoint, Tcb, TcbConfig};

/// Standard maximum segment size for an Ethernet-class path.
pub const MSS: u16 = 1460;

/// Per-direction ring buffer capacity (must be a power of two).
///
/// Sized for high-bandwidth-delay-product paths: 1 MiB lets a connection
/// fill ~80 ms × 100 Mbit/s before the receive window throttles the
/// sender, vs. ~5 ms × 100 Mbit/s with the legacy 64 KiB. Memory cost
/// is `2 * BUF_CAP` (send + receive) per connection — ~2 MiB.
///
/// Hosts that hold many idle connections may wish to override this; the
/// constant is the only knob.
///
/// The `small-buffers` Cargo feature switches this to 32 KiB, dropping
/// per-Tcb RSS to ~150 KiB so scale harnesses can pack 10K connections
/// into ~1.5 GiB rather than ~21 GiB. Behavior under that build is
/// otherwise identical (handshake, congestion control, RACK, etc.).
#[cfg(not(feature = "small-buffers"))]
pub const BUF_CAP: usize = 1_048_576;
#[cfg(feature = "small-buffers")]
pub const BUF_CAP: usize = 32 * 1024;

/// Single-hole out-of-order reassembly buffer capacity, in bytes.
///
/// Holds at most one contiguous run that arrived ahead of `rcv_nxt`. When
/// the missing segment fills the gap, the held run is drained into the
/// receive ring atomically and the application sees a single contiguous
/// stream — i.e. the receiver doesn't force the sender to retransmit
/// already-arrived bytes.
///
/// 16 KiB is ~11 MSS-sized segments, which covers typical single-drop
/// recovery during slow start. More pathological loss patterns (multiple
/// holes, or an OOO run larger than this buffer) fall back to per-RTO
/// retransmission — no worse than the previous "drop-on-OOO" behaviour.
pub const REASM_CAP: usize = 16 * 1024;

/// Maximum size of a single emitted IP/TCP datagram.
///
/// IPv4 fixed (20) + TCP fixed (20) + MSS (1460) = 1500. With the Timestamps
/// option negotiated, the TCP header grows by 12 bytes but the payload
/// shrinks by the same amount, so the total stays at 1500.
pub const MAX_PACKET: usize = 20 + 20 + MSS as usize;

/// Defensive iteration budget for internal loops whose *termination* depends
/// on invariants that adversarial or buggy input could, in principle,
/// violate (e.g. the send-side emit loop, OOO-reassembly drain, and the
/// SACK-scoreboard cursor scans — all of which advance only while a
/// monotonicity invariant holds).
///
/// Returns `true` once the budget is exhausted, signalling the caller to
/// stop the loop. The semantics differ by build so the same call site both
/// *catches* infinite loops in testing and *survives* them in production:
///
/// * In `test` / `std` builds — which include the coverage-guided fuzz
///   targets — exhaustion **panics** with a precise location, so an internal
///   infinite loop fails loudly and immediately instead of hanging (a hang
///   is the worst fuzzing outcome: no crash artifact, just a timeout).
/// * In the production `no_std` build it returns `true` to break the loop,
///   converting a would-be unbounded spin into a graceful (possibly lossy)
///   stop — denying a remote peer a trivial CPU-exhaustion DoS.
///
/// The bound must be chosen comfortably above the worst legitimate iteration
/// count so it never trips in correct operation.
#[inline(always)]
#[allow(clippy::panic)]
pub(crate) fn loop_budget_exhausted(iters: &mut u32, cap: u32, _what: &str) -> bool {
    *iters = iters.wrapping_add(1);
    if *iters <= cap {
        return false;
    }
    #[cfg(any(test, feature = "std"))]
    {
        panic!("internal loop budget exhausted in {_what} (> {cap} iterations)");
    }
    #[cfg(not(any(test, feature = "std")))]
    {
        true
    }
}

#[cfg(test)]
mod loopback_tests;

#[cfg(test)]
mod conformance_tests;

#[cfg(test)]
mod property_tests;

#[cfg(test)]
mod server_tests;

#[cfg(test)]
mod smoltcp_interop_tests;

#[cfg(test)]
mod loop_budget_tests {
    #![allow(clippy::panic)]
    use super::loop_budget_exhausted;

    /// Within budget the helper returns `false` (keep looping); the call
    /// count maps 1:1 to invocations.
    #[test]
    fn returns_false_until_cap() {
        let mut iters = 0u32;
        for _ in 0..5 {
            assert!(!loop_budget_exhausted(&mut iters, 5, "test"));
        }
        assert_eq!(iters, 5);
    }

    /// In test/std builds, exceeding the budget panics — this is the
    /// behavior that converts an internal infinite loop into an immediate,
    /// located fuzz/test failure instead of a hang.
    #[test]
    #[should_panic(expected = "internal loop budget exhausted")]
    fn panics_past_cap() {
        let mut iters = 0u32;
        for _ in 0..10 {
            let _ = loop_budget_exhausted(&mut iters, 3, "test-loop");
        }
    }
}
