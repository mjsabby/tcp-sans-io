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
//! Under `cfg(test)` we let `std` link so we can run a loopback harness that
//! simulates two TCBs talking through an in-memory wire.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
#[cfg(all(not(test), not(feature = "host_panic_handler"), not(feature = "std"), target_os = "linux"))]
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
pub const BUF_CAP: usize = 1_048_576;

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
