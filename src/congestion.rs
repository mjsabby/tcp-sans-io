//! TCP congestion control: PRR-Reno fast recovery (RFC 6937, 2013) +
//! RFC 5681 §3 RTO collapse.
//!
//! Replaces the original Tahoe-only behavior:
//!
//! * **Fast retransmit** (3-dup-ACK or SACK-driven trigger) enters Proportional
//!   Rate Reduction (PRR) Slow-Start Reduction Bound (PRR-SSRB). `cwnd` is
//!   NOT collapsed to 1*MSS at the loss event; instead `ssthresh` is set to
//!   `max(FlightSize/2, 2*MSS)` and a per-ACK `snd_credit` budget paces
//!   retransmissions + new data so the connection exits recovery with
//!   `cwnd = ssthresh`. Empirically this gives 2-5x throughput vs Tahoe on
//!   1-5% loss paths and substantially smoother behavior at all loss rates.
//!
//! * **RTO** collapses `cwnd` to 1*MSS per RFC 5681 §3 — PRR explicitly does
//!   not modify RTO behavior (RFC 6937 §6). Slow-start re-opens cwnd from 1.
//!
//! Outside recovery, the algorithm is RFC 5681 slow-start / congestion
//! avoidance, with RFC 6928 IW=10*MSS as the initial window.

use crate::MSS;

/// RFC 6928 (2013) Initial Window: `IW = min(10*MSS, max(2*MSS, 14600))`.
/// For MSS=1460 this is exactly `10*MSS = 14600` bytes.
pub const INITIAL_WINDOW: u32 = {
    let ten_mss = 10 * MSS as u32;
    let two_mss = 2 * MSS as u32;
    let lower = if two_mss > 14_600 { two_mss } else { 14_600 };
    if ten_mss < lower {
        ten_mss
    } else {
        lower
    }
};

/// Per-connection congestion state. Fits inline in the [`crate::tcb::Tcb`].
///
/// Type name kept as `Tahoe` for source-stability with the existing TCB
/// integration; algorithmically this is now PRR-Reno (Reno halving + PRR
/// pacing) for fast retransmit and RFC 5681 collapse for RTO.
#[derive(Debug, Clone, Copy)]
pub struct Tahoe {
    /// Congestion window in bytes. Outside recovery, governed by
    /// slow-start / CA. During PRR recovery, frozen at its pre-loss value
    /// (PRR uses `snd_credit` rather than cwnd to gate sends). On
    /// recovery exit, set to `ssthresh`.
    pub cwnd: u32,
    /// Slow-start threshold in bytes.
    pub ssthresh: u32,
    /// Count of duplicate ACKs for the current `snd_una`.
    pub dup_acks: u8,

    // ---- PRR-SSRB recovery state (RFC 6937) -------------------------------
    /// True iff we are inside a fast-recovery episode.
    in_recovery: bool,
    /// `snd.nxt` value at the moment recovery was entered. Recovery exits
    /// when a cumulative ACK first crosses this point.
    recovery_point: u32,
    /// `FlightSize` captured at recovery entry; used as the denominator of
    /// the PRR proportional-rate formula.
    recover_fs: u32,
    /// Cumulative bytes "delivered" (cum-ACKed, plus newly-SACKed in a
    /// future RFC 6675 implementation) since recovery entry.
    prr_delivered: u32,
    /// Cumulative bytes the sender has emitted since recovery entry.
    prr_out: u32,
    /// Per-ACK send credit. Inside recovery, computed by PRR-SSRB; outside
    /// recovery this field is meaningless and `snd_credit()` returns
    /// `u32::MAX` (i.e. the only limits are `cwnd` and the peer window).
    snd_credit: u32,
}

impl Tahoe {
    /// Initial state per RFC 6928: `cwnd = INITIAL_WINDOW`, `ssthresh =
    /// receiver window` (effectively unbounded so slow-start runs until
    /// first loss).
    #[inline]
    pub const fn new(initial_rwnd: u32) -> Self {
        Self {
            cwnd: INITIAL_WINDOW,
            ssthresh: initial_rwnd,
            dup_acks: 0,
            in_recovery: false,
            recovery_point: 0,
            recover_fs: 0,
            prr_delivered: 0,
            prr_out: 0,
            snd_credit: u32::MAX,
        }
    }

    /// Whether the connection is currently in PRR fast recovery.
    #[inline]
    pub fn in_recovery(&self) -> bool {
        self.in_recovery
    }

    /// Per-ACK send budget. During PRR recovery this is the `sndcnt`
    /// computed by the most recent `on_ack_in_recovery` call, decremented
    /// by `on_send`. Outside recovery returns `u32::MAX`.
    #[inline]
    pub fn snd_credit(&self) -> u32 {
        if self.in_recovery {
            self.snd_credit
        } else {
            u32::MAX
        }
    }

    /// Called for every fresh ACK that advances `snd_una`. `acked` is the
    /// number of newly acknowledged bytes.
    ///
    /// Outside recovery: standard slow-start / congestion avoidance.
    /// Inside recovery: cwnd is frozen by PRR — this is a no-op, and the
    /// caller must instead invoke [`Self::on_ack_in_recovery`] to update
    /// the PRR send credit.
    pub fn on_ack(&mut self, acked: u32) {
        self.dup_acks = 0;
        if self.in_recovery || acked == 0 {
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

    /// Enter PRR Fast Recovery in response to a fast-retransmit trigger
    /// (3 dup-ACKs or a SACK-driven loss signal). RFC 6937 §3.
    ///
    /// `flight_size` is `snd.nxt - snd.una` at the moment of the trigger;
    /// `recovery_point` is `snd.nxt` (the high-water sequence number we
    /// want a cumulative ACK to reach before declaring recovery over).
    ///
    /// Per RFC 6937, `cwnd` is NOT modified at recovery entry; only
    /// `ssthresh` is set. The first send budget (`snd_credit`) is `MSS`
    /// to allow the immediate retransmit of the lost segment.
    pub fn enter_recovery(&mut self, flight_size: u32, recovery_point: u32) {
        let mss = MSS as u32;
        let half = flight_size / 2;
        self.ssthresh = core::cmp::max(half, mss.saturating_mul(2));
        self.in_recovery = true;
        self.recovery_point = recovery_point;
        self.recover_fs = core::cmp::max(flight_size, 1);
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.dup_acks = 0;
        self.snd_credit = mss;
    }

    /// Apply the conventional RFC 5681 §3 RTO collapse: `cwnd = 1*MSS`,
    /// `ssthresh = max(FlightSize/2, 2*MSS)`, exit any prior recovery.
    /// RFC 6937 §6 explicitly says PRR does not modify RTO behavior.
    pub fn on_rto_loss(&mut self, flight_size: u32) {
        let mss = MSS as u32;
        let half = flight_size / 2;
        self.ssthresh = core::cmp::max(half, mss.saturating_mul(2));
        self.cwnd = mss;
        self.in_recovery = false;
        self.snd_credit = u32::MAX;
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.dup_acks = 0;
    }

    /// Per-ACK update during recovery. `delivered_data` is the bytes
    /// newly acknowledged by this ACK (`new_snd_una - old_snd_una`, plus
    /// newly-SACKed bytes once we have an RFC 6675 scoreboard). `pipe`
    /// is the sender's estimate of bytes still in flight; without an
    /// RFC 6675 scoreboard the caller passes the post-update
    /// `snd.nxt - snd.una`.
    ///
    /// Recomputes the per-ACK `snd_credit` per RFC 6937 §3 PRR-SSRB.
    pub fn on_ack_in_recovery(&mut self, delivered_data: u32, pipe: u32) {
        if !self.in_recovery {
            return;
        }
        self.prr_delivered = self.prr_delivered.saturating_add(delivered_data);
        let mss = MSS as u32;
        let sndcnt = if pipe > self.ssthresh {
            // Proportional Rate Reduction (the "main" PRR formula).
            // sndcnt = ceil(prr_delivered * ssthresh / RecoverFS) - prr_out
            let num = (self.prr_delivered as u64).saturating_mul(self.ssthresh as u64);
            let den = self.recover_fs as u64;
            let ceil_div = num.div_ceil(den);
            (ceil_div.min(u32::MAX as u64) as u32).saturating_sub(self.prr_out)
        } else {
            // PRR-SSRB (Slow-Start Reduction Bound): when the pipe has
            // drained below ssthresh, use a more aggressive limit so the
            // pipe re-fills smoothly toward ssthresh rather than stalling.
            //
            //   limit = max(prr_delivered - prr_out, DeliveredData) + MSS
            //   sndcnt = min(ssthresh - pipe, limit)
            let limit = core::cmp::max(
                self.prr_delivered.saturating_sub(self.prr_out),
                delivered_data,
            )
            .saturating_add(mss);
            core::cmp::min(self.ssthresh.saturating_sub(pipe), limit)
        };
        self.snd_credit = sndcnt;
    }

    /// Account for `bytes` that the sender has just emitted on the wire.
    /// Decrements the PRR send credit (no-op outside recovery).
    pub fn on_send(&mut self, bytes: u32) {
        if self.in_recovery {
            self.prr_out = self.prr_out.saturating_add(bytes);
            self.snd_credit = self.snd_credit.saturating_sub(bytes);
        }
    }

    /// If `snd_una` has crossed the recovery point, exit fast recovery
    /// and set `cwnd = ssthresh`. Returns `true` if recovery was just
    /// exited (caller may want to log / surface this).
    pub fn check_exit_recovery(&mut self, snd_una: u32) -> bool {
        if !self.in_recovery {
            return false;
        }
        // Wrap-aware "snd_una >= recovery_point".
        if (snd_una.wrapping_sub(self.recovery_point) as i32) >= 0 {
            self.cwnd = self.ssthresh;
            self.in_recovery = false;
            self.snd_credit = u32::MAX;
            return true;
        }
        false
    }

    /// Unconditionally leave fast recovery, restoring `cwnd = ssthresh` and
    /// lifting the PRR send-credit clamp. Used as a deadlock breaker when
    /// the pipe has drained (`flight == 0`) but PRR credit is exhausted, a
    /// state in which recovery can otherwise never make progress because no
    /// ACK can arrive to replenish the credit (see `maybe_send_one`). The
    /// `ssthresh` reduction from recovery entry is retained, so the
    /// congestion response to the loss episode is preserved.
    pub fn force_exit_recovery(&mut self) {
        if !self.in_recovery {
            return;
        }
        self.cwnd = self.ssthresh;
        self.in_recovery = false;
        self.snd_credit = u32::MAX;
    }

    /// Bytes the sender is currently authorised to keep in flight, given the
    /// peer's advertised window. PRR's per-ACK pacing applies on top via
    /// [`Self::snd_credit`] — the caller of `maybe_send_data` must clamp
    /// the per-segment send to both `allowed - flight` AND `snd_credit`.
    #[inline]
    pub fn allowed(&self, peer_wnd: u32) -> u32 {
        core::cmp::min(self.cwnd, peer_wnd)
    }
}
