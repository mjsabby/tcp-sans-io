//! tcp-sans-io
//!
//! Minimal, sans-I/O user-space TCP stack designed to sit in front
//! of an external WireGuard backend and behind a foreign-language async runtime
//! (C# / Python) via a stable C ABI.
//!
//! Both **active** opens (`connect`) and **passive** opens (`listen`) are
//! supported. The passive path implements the canonical RFC 793 server
//! states (LISTEN and SYN_RECEIVED) plus RFC 4987 SYN cookies, used while
//! the listener's single half-open slot is busy, for flood resistance.
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
//!    call `tick()` when [`Tcb::next_deadline`] comes due (event-driven), after
//!    [`Tcb::send`], and after draining a full egress ring — or simply every
//!    ~10 ms. If the clock stops advancing or `tick()` is not called, **none**
//!    of the timer-based defenses fire: retransmits stall, and zero-window,
//!    stalling, or vanished-idle peers are never reaped. A frozen clock is a
//!    disabled safety net.
//!
//! 2. **Drain the egress ring after every call.** After each `inject_packet`,
//!    `tick`, `recv` and `close`, call [`Tcb::extract_packet`] (buffer ≥ [`MAX_PACKET`])
//!    repeatedly until it returns 0 and transmit those bytes, *before* the next
//!    `inject_packet`. Replies (ACKs, retransmits, keepalive/persist probes)
//!    stage there; an undrained ring silently drops them and can wedge the
//!    connection.
//!
//! 3. **Bound the number of connections.** Only the host can: each TCB is
//!    independent and unaware of the others, and costs ≈ 2.08 MiB by default
//!    (136 KiB under the `small-buffers` feature) — including the 60–120 s it
//!    spends in `TIME_WAIT`. The per-connection timers bound how long a
//!    *stalled or vanished* peer, or one the host has closed on, holds a
//!    connection — never the aggregate *count*, and never a live peer the host
//!    keeps serving (see 7). Cap concurrent TCBs and refuse/evict past the
//!    budget, or an attacker who merely opens many connections exhausts memory
//!    regardless of any per-connection defense.
//!
//! 4. **Install secrets.** Call [`Tcb::set_secret`] with 16 CSPRNG bytes
//!    (keys timestamp offsets, passive-open ISNs and the SYN-cookie key) on
//!    every listener — [`Tcb::listen`] refuses to run without a secret — and on
//!    internet-facing active opens, and set the path MTU with [`Tcb::set_mtu`]
//!    (1420 behind a default WireGuard interface).
//!
//! 5. **Understand the listener's SYN cookies.** A listener holds one
//!    half-open handshake statefully (keeping every option the client offers)
//!    and answers SYNs with RFC 4987 cookies while that slot is busy; a valid
//!    cookie ACK takes the slot over, so spoofed SYNs cannot lock it. The
//!    cookie key derives from the host secret; [`Tcb::set_cookie_secret`]
//!    installs an explicit one instead. Rotating it keeps the previous key
//!    valid, so cookies survive one rotation (rotate no more often than every
//!    ~2 minutes). A predictable or leaked secret defeats the protection.
//!    Busy-listener replies go to *other* peers than the half-open's: route
//!    every outbound packet by its own destination address, never by the TCB.
//!
//! 6. **Act on lifecycle signals and release the TCB.** Read [`Tcb::poll`] and
//!    react: on `PEER_CLOSED` (peer FIN → `CLOSE_WAIT`) the host **must**
//!    eventually call [`Tcb::close`]. Keepalive reaps an idle `CLOSE_WAIT` only
//!    if the peer has since vanished (the connection then closes, unread bytes
//!    still readable); a live peer keeps answering, so an un-closed connection
//!    stays pinned until the host acts. On `ERROR` / `CLOSED` (including the
//!    RST-less local aborts from R2 / USER TIMEOUT / keepalive) drop the TCB or
//!    [`Tcb::reinit`] it for reuse; the slot is reclaimed only when the host
//!    releases it. After a clean close, first `recv` any bytes the peer sent
//!    before its FIN (`READABLE` stays set until they are drained).
//!
//! 7. **Don't disable the idle/stall reapers without a replacement, and
//!    bound live connections yourself.** Keepalive and the USER TIMEOUT are
//!    **on by default** and are what bound a vanished or *stalled* peer's hold
//!    on a TCB. A host that turns either off ([`Tcb::set_keepalive`]`(0, …)` /
//!    [`Tcb::set_user_timeout`]`(0)`) must provide its own reaping or it
//!    reopens the memory-pinning DoS. Neither bounds a *live* peer that keeps
//!    making slow progress — e.g. a reader acknowledging one segment every few
//!    minutes holds the connection as long as the host keeps it open — so apply
//!    application-level deadlines (idle or total time, minimum throughput)
//!    where that matters. After `close()`, data still queued drains under the
//!    same USER TIMEOUT rule; once our FIN is acknowledged, `FIN_WAIT_2` lasts
//!    60 s unless the application keeps reading, and `TIME_WAIT` at most 120 s
//!    however often the peer re-sends its FIN.
//!
//! Under `cfg(test)` we let `std` link so we can run a loopback harness that
//! simulates two TCBs talking through an in-memory wire.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(feature = "heap-buffers")]
extern crate alloc;

/// Panics are unreachable by construction (Clippy denies `unwrap`/`expect`/
/// `panic!`/indexing; arithmetic is wrapping or saturating). If one ever
/// fires anyway, trap immediately: a crash is visible and restartable,
/// whereas spinning would silently burn a core forever (a CPU DoS).
#[cfg(all(not(test), not(feature = "host_panic_handler"), not(feature = "std")))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    trap()
}

#[cfg(all(not(test), not(feature = "std")))]
#[inline(always)]
fn trap() -> ! {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    // SAFETY: `ud2` raises an invalid-opcode exception; it never returns.
    unsafe {
        core::arch::asm!("ud2", options(noreturn, nomem, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `udf` raises an undefined-instruction exception.
    unsafe {
        core::arch::asm!("udf #0", options(noreturn, nomem, nostack));
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
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
    trap()
}

pub mod congestion;
pub mod error;
pub mod ffi;
pub mod ooo;
pub mod rack;
pub mod ring;
pub mod rtx_queue;
pub mod selftest;
pub mod state;
pub mod tcb;
pub mod tx_ring;
pub mod wire;

pub use error::TcpError;
pub use state::State;
pub use tcb::{Endpoint, Tcb, TcbConfig, TcbStats};

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
mod security_tests;
#[cfg(test)]
mod sim_tests;

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
