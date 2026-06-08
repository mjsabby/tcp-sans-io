//! Built-in self-conformance check.
//!
//! [`self_conformance`] drives two instances of this stack against each
//! other through an in-memory wire and verifies a byte-exact, in-order
//! bidirectional bulk transfer plus a clean four-way close — entirely in
//! process, with no external reference stack, no transport, no clock, and
//! no allocator. It is the lightest possible "is the library healthy and
//! correctly linked?" smoke test, exposed across the FFI as `tcp_selftest`.
//!
//! It is *not* a substitute for interop testing against a foreign stack
//! (gVisor / the Linux kernel) — see `bindings/` and `SKILL.md` — but it
//! catches linkage / ABI / calling-convention mistakes and gross protocol
//! regressions in a single call. The check is deterministic: a failure is
//! always reproducible.
//!
//! Stack cost: two `Tcb<SELFTEST_BUF>` plus small scratch — roughly
//! 256 KiB of stack while running. The host calls this on its own stack
//! (e.g. once at start-up); virtually every platform default (≥ 1 MiB)
//! accommodates it.

use crate::tcb::{Endpoint, Tcb, TcbConfig};
use crate::State;
use crate::MAX_PACKET;

/// Per-direction ring size used by the self-test. 16 KiB keeps the two
/// TCBs cheap on the stack while still exercising window-limited flow,
/// delayed ACKs, and multi-segment bursts.
const SELFTEST_BUF: usize = 16 * 1024;

/// Bytes transferred in each direction. Comfortably more than one window,
/// so the loop exercises ACK-clocked flow control rather than a single
/// burst, but small enough to converge in well under a millisecond.
const SELFTEST_XFER: u32 = 128 * 1024;

/// Result codes returned by [`self_conformance`] (and surfaced verbatim by
/// `tcp_selftest`). `0` is success; every failure is a distinct, stable,
/// negative code so a binding can report *where* the check broke.
pub mod result {
    /// The bidirectional transfer completed and both sides closed cleanly.
    pub const OK: i32 = 0;
    /// A `Tcb` could not be constructed (should be impossible here).
    pub const INIT_FAILED: i32 = -1;
    /// `connect` / `listen` was rejected.
    pub const SETUP_FAILED: i32 = -2;
    /// A received byte did not match the deterministic generator — i.e. the
    /// stack dropped, duplicated, reordered, or corrupted stream data.
    pub const DATA_MISMATCH: i32 = -3;
    /// The transfer did not converge within the iteration budget — a hang,
    /// livelock, or wedged state machine.
    pub const NO_CONVERGENCE: i32 = -4;
    /// `tick` / `extract` / `inject` surfaced an unexpected internal error.
    pub const INTERNAL_ERROR: i32 = -5;
}

#[inline]
fn cfg(iss: u32, local: ([u8; 4], u16), remote: ([u8; 4], u16)) -> TcbConfig {
    TcbConfig {
        local: Endpoint {
            ip: local.0,
            port: local.1,
        },
        remote: Endpoint {
            ip: remote.0,
            port: remote.1,
        },
        iss,
        initial_rto_ms: 1000,
    }
}

/// Deterministic, position-dependent byte generator. A simple
/// multiplicative hash of the stream offset — cheap, no state, and
/// sensitive to any reorder/drop/duplication (each offset maps to a
/// distinct expected byte).
#[inline]
fn pat(stream: u32, offset: u32) -> u8 {
    let x = (stream ^ offset).wrapping_mul(2_654_435_761);
    (x >> 24) as u8
}

/// Run the in-process bidirectional conformance transfer. Returns
/// [`result::OK`] (0) on success or a negative [`result`] code on failure.
///
/// Pure: no I/O, no allocation, no panics. Safe to call from any thread at
/// any time; it operates only on its own stack-local TCBs.
pub fn self_conformance() -> i32 {
    let mut cli: Tcb<SELFTEST_BUF> = match Tcb::new(cfg(
        0x1111_1111,
        ([10, 0, 0, 1], 40000),
        ([10, 0, 0, 2], 80),
    )) {
        Ok(t) => t,
        Err(_) => return result::INIT_FAILED,
    };
    let mut srv: Tcb<SELFTEST_BUF> = match Tcb::new(cfg(
        0x9999_9999,
        ([10, 0, 0, 2], 80),
        ([10, 0, 0, 1], 40000),
    )) {
        Ok(t) => t,
        Err(_) => return result::INIT_FAILED,
    };

    let mut now: u64 = 0;
    cli.set_now(now);
    srv.set_now(now);
    if srv.listen().is_err() || cli.connect().is_err() {
        return result::SETUP_FAILED;
    }

    // Two stream identifiers so each direction has a distinct pattern.
    const CLI_STREAM: u32 = 0x0000_0001;
    const SRV_STREAM: u32 = 0x8000_0001;

    let mut cli_sent: u32 = 0;
    let mut cli_recv: u32 = 0;
    let mut srv_sent: u32 = 0;
    let mut srv_recv: u32 = 0;
    let mut closing = false;

    let mut pkt = [0u8; MAX_PACKET];
    let mut chunk = [0u8; 4096];
    let mut rbuf = [0u8; 4096];

    // Generously bounded: a clean 128 KiB transfer over a 16 KiB window
    // converges in a few thousand iterations. The cap turns any wedge into
    // a deterministic NO_CONVERGENCE rather than a hang.
    for _ in 0..4_000_000u32 {
        now += 1;
        cli.set_now(now);
        srv.set_now(now);
        if cli.tick().is_err() || srv.tick().is_err() {
            return result::INTERNAL_ERROR;
        }

        // Ferry cli -> srv.
        loop {
            let n = match cli.extract_packet(&mut pkt) {
                Ok(n) => n,
                Err(_) => return result::INTERNAL_ERROR,
            };
            if n == 0 {
                break;
            }
            // Inject errors here would mean we emitted a packet our own
            // peer rejects — a real bug.
            if let Some(slice) = pkt.get(..n) {
                let _ = srv.inject_packet(slice);
            }
        }
        // Ferry srv -> cli.
        loop {
            let n = match srv.extract_packet(&mut pkt) {
                Ok(n) => n,
                Err(_) => return result::INTERNAL_ERROR,
            };
            if n == 0 {
                break;
            }
            if let Some(slice) = pkt.get(..n) {
                let _ = cli.inject_packet(slice);
            }
        }

        // Offer more data each way.
        if cli.state() == State::Established && cli_sent < SELFTEST_XFER {
            let take = core::cmp::min(chunk.len() as u32, SELFTEST_XFER - cli_sent) as usize;
            for (i, b) in chunk.iter_mut().take(take).enumerate() {
                *b = pat(CLI_STREAM, cli_sent + i as u32);
            }
            if let Some(src) = chunk.get(..take) {
                if let Ok(w) = cli.send(src) {
                    cli_sent += w as u32;
                }
            }
        }
        if srv.state() == State::Established && srv_sent < SELFTEST_XFER {
            let take = core::cmp::min(chunk.len() as u32, SELFTEST_XFER - srv_sent) as usize;
            for (i, b) in chunk.iter_mut().take(take).enumerate() {
                *b = pat(SRV_STREAM, srv_sent + i as u32);
            }
            if let Some(src) = chunk.get(..take) {
                if let Ok(w) = srv.send(src) {
                    srv_sent += w as u32;
                }
            }
        }

        // Drain + verify each way.
        if let Ok(n) = cli.recv(&mut rbuf) {
            for i in 0..n {
                let expect = pat(SRV_STREAM, cli_recv + i as u32);
                if rbuf.get(i).copied() != Some(expect) {
                    return result::DATA_MISMATCH;
                }
            }
            cli_recv += n as u32;
        }
        if let Ok(n) = srv.recv(&mut rbuf) {
            for i in 0..n {
                let expect = pat(CLI_STREAM, srv_recv + i as u32);
                if rbuf.get(i).copied() != Some(expect) {
                    return result::DATA_MISMATCH;
                }
            }
            srv_recv += n as u32;
        }

        if !closing
            && cli_sent == SELFTEST_XFER
            && cli_recv == SELFTEST_XFER
            && srv_sent == SELFTEST_XFER
            && srv_recv == SELFTEST_XFER
        {
            if cli.close().is_err() || srv.close().is_err() {
                return result::INTERNAL_ERROR;
            }
            closing = true;
        }

        if closing
            && matches!(cli.state(), State::Closed | State::TimeWait)
            && matches!(srv.state(), State::Closed | State::TimeWait)
        {
            return result::OK;
        }
    }

    result::NO_CONVERGENCE
}

#[cfg(test)]
mod tests {
    use super::{result, self_conformance};

    #[test]
    fn self_conformance_passes() {
        assert_eq!(self_conformance(), result::OK);
    }
}
