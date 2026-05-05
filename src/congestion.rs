//! TCP Tahoe AIMD congestion control.
//!
//! Tahoe is the simplest standards-compliant algorithm: on any loss signal
//! (RTO *or* triple duplicate ACK) we collapse `cwnd` to one MSS and re-enter
//! slow-start. There is no fast-recovery phase — the deliberate trade-off the
//! spec calls out in Component 3.

use crate::MSS;

/// Per-connection congestion state. Fits inline in the [`crate::tcb::Tcb`].
#[derive(Debug, Clone, Copy)]
pub struct Tahoe {
    /// Congestion window in bytes.
    pub cwnd: u32,
    /// Slow-start threshold in bytes.
    pub ssthresh: u32,
    /// Count of duplicate ACKs for the current `snd_una`.
    pub dup_acks: u8,
}

impl Tahoe {
    /// Initial state per RFC 5681: `cwnd = 1*MSS`, `ssthresh = receiver window`.
    #[inline]
    pub const fn new(initial_rwnd: u32) -> Self {
        Self {
            cwnd: MSS as u32,
            ssthresh: initial_rwnd,
            dup_acks: 0,
        }
    }

    /// Called for every fresh ACK that advances `snd_una`. `acked` is the
    /// number of newly acknowledged bytes.
    pub fn on_ack(&mut self, acked: u32) {
        self.dup_acks = 0;
        if acked == 0 {
            return;
        }
        let mss = MSS as u32;
        if self.cwnd < self.ssthresh {
            // Slow start: exponential growth, capped at one MSS per ACK.
            self.cwnd = self.cwnd.saturating_add(core::cmp::min(acked, mss));
        } else {
            // Congestion avoidance: roughly +1 MSS per RTT.
            // cwnd += MSS*MSS/cwnd, guarding against div-by-zero.
            let cwnd = core::cmp::max(self.cwnd, 1);
            let inc = mss.saturating_mul(mss) / cwnd;
            self.cwnd = self.cwnd.saturating_add(core::cmp::max(inc, 1));
        }
    }

    /// Called when a duplicate ACK arrives. Returns `true` if the caller
    /// should treat this as a loss event (third dup ACK).
    pub fn on_dup_ack(&mut self) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        self.dup_acks >= 3
    }

    /// Apply a Tahoe loss event: `ssthresh = max(FlightSize/2, 2*MSS)` and
    /// `cwnd = 1*MSS`. Caller is responsible for retransmitting.
    pub fn on_loss(&mut self, flight_size: u32) {
        let mss = MSS as u32;
        let half = flight_size / 2;
        self.ssthresh = core::cmp::max(half, mss.saturating_mul(2));
        self.cwnd = mss;
        self.dup_acks = 0;
    }

    /// Bytes the sender is currently authorised to keep in flight, given the
    /// peer's advertised window.
    #[inline]
    pub fn allowed(&self, peer_wnd: u32) -> u32 {
        core::cmp::min(self.cwnd, peer_wnd)
    }
}
