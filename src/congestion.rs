//! Congestion control: Reno (RFC 5681) with byte counting, Proportional Rate
//! Reduction (RFC 6937) for fast recovery and ECN/TLP reductions, and the
//! RFC 5681 §3.1 loss window on RTO.
//!
//! Units are bytes. Loss *detection* lives elsewhere (RACK / dup-ACKs mark
//! segments lost in the retransmission queue); this module only decides how
//! much may be in flight. During a reduction episode PRR recomputes
//! `cwnd = pipe + sndcnt` on every ACK so the sender's ordinary
//! "send while `pipe < cwnd`" rule paces retransmissions and new data.
//!
//! A loss-triggered reduction (fast recovery or RTO) is undone if D-SACKs
//! later show that every retransmission of the episode was needless
//! (RFC 3708 detection with an Eifel-style response, as Linux
//! `tcp_try_undo_dsack`): reordering or a delay spike must not cost the
//! window.

/// Congestion-avoidance state (named after Linux's `tcp_ca_state`).
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum CaState {
    /// No reduction in progress.
    #[default]
    Open = 0,
    /// Fast recovery after loss detected by RACK / dup-ACKs (PRR).
    Recovery = 1,
    /// Retransmission timeout: loss window, slow start back to `ssthresh`.
    Loss = 2,
    /// Congestion window reduction without loss (ECN-Echo, repaired tail loss).
    Cwr = 3,
}

/// RFC 6928 initial window for a given MSS: `min(10*MSS, max(2*MSS, 14600))`.
pub const fn initial_window(mss: u32) -> u32 {
    let ten = mss.saturating_mul(10);
    let two = mss.saturating_mul(2);
    let lower = if two > 14_600 { two } else { 14_600 };
    if ten < lower {
        ten
    } else {
        lower
    }
}

/// Default-MSS initial window (1460-byte MSS → 14600 bytes).
pub const INITIAL_WINDOW: u32 = initial_window(crate::MSS as u32);

#[inline]
fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// Reno congestion state.
#[derive(Copy, Clone, Debug)]
pub struct Reno {
    pub cwnd: u32,
    pub ssthresh: u32,
    state: CaState,
    /// `SND.NXT` when the current reduction episode began.
    recovery_point: u32,
    /// Bytes acknowledged toward the next congestion-avoidance increment.
    ca_acc: u32,
    prr_delivered: u64,
    prr_out: u64,
    recover_fs: u32,
    /// Window before the current loss episode, restored on undo.
    prior_cwnd: u32,
    prior_ssthresh: u32,
    /// The episode may still be undone.
    undo_valid: bool,
    /// `SND.UNA` when the episode began; only D-SACKs above it count.
    undo_marker: u32,
    /// Retransmissions of the episode not yet shown needless by a D-SACK.
    undo_retrans: u32,
}

impl Reno {
    pub const fn new(initial_cwnd: u32) -> Self {
        Self {
            cwnd: initial_cwnd,
            ssthresh: u32::MAX / 2,
            state: CaState::Open,
            recovery_point: 0,
            ca_acc: 0,
            prr_delivered: 0,
            prr_out: 0,
            recover_fs: 1,
            prior_cwnd: 0,
            prior_ssthresh: 0,
            undo_valid: false,
            undo_marker: 0,
            undo_retrans: 0,
        }
    }

    #[inline]
    pub fn state(&self) -> CaState {
        self.state
    }

    /// A PRR-paced reduction (fast recovery or CWR) is in progress.
    #[inline]
    pub fn in_reduction(&self) -> bool {
        matches!(self.state, CaState::Recovery | CaState::Cwr)
    }

    /// Fast recovery or RTO recovery is in progress.
    #[inline]
    pub fn in_loss_recovery(&self) -> bool {
        matches!(self.state, CaState::Recovery | CaState::Loss)
    }

    #[inline]
    pub fn recovery_point(&self) -> u32 {
        self.recovery_point
    }

    /// Window growth on an ACK that newly delivered `acked` bytes, outside a
    /// reduction episode. `cwnd_limited` gates growth (RFC 7661 spirit, as
    /// Linux `tcp_is_cwnd_limited`): an application-limited sender must not
    /// inflate a window it is not using.
    pub fn on_ack(&mut self, acked: u32, mss: u32, cwnd_limited: bool) {
        if self.in_reduction() || acked == 0 || !cwnd_limited {
            return;
        }
        let mut acked = acked;
        if self.cwnd < self.ssthresh {
            // Slow start (counts every delivered byte, so stretch ACKs from
            // coalescing receivers still double the window per RTT).
            let inc = acked.min(self.ssthresh - self.cwnd);
            self.cwnd = self.cwnd.saturating_add(inc);
            acked -= inc;
            if acked == 0 {
                return;
            }
        }
        // Congestion avoidance with byte counting: +1 MSS per cwnd delivered.
        self.ca_acc = self.ca_acc.saturating_add(acked);
        let w = self.cwnd.max(mss);
        if self.ca_acc >= w {
            let segs = self.ca_acc / w;
            self.ca_acc -= segs * w;
            self.cwnd = self.cwnd.saturating_add(segs.saturating_mul(mss));
        }
    }

    fn begin_reduction(&mut self, state: CaState, flight: u32, snd_nxt: u32, mss: u32) {
        self.ssthresh = (flight / 2).max(mss.saturating_mul(2));
        self.state = state;
        self.recovery_point = snd_nxt;
        self.recover_fs = flight.max(1);
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.ca_acc = 0;
    }

    /// Remember the window a loss episode starting now could be undone to.
    fn arm_undo(&mut self, snd_una: u32) {
        self.prior_cwnd = self.cwnd;
        self.prior_ssthresh = self.ssthresh;
        self.undo_valid = true;
        self.undo_marker = snd_una;
        self.undo_retrans = 0;
    }

    /// Enter fast recovery (RFC 6937): halve `ssthresh`, pace with PRR.
    pub fn enter_recovery(&mut self, flight: u32, snd_una: u32, snd_nxt: u32, mss: u32) {
        self.arm_undo(snd_una);
        self.begin_reduction(CaState::Recovery, flight, snd_nxt, mss);
    }

    /// Enter CWR (RFC 3168 §6.1.2 ECN response, or RFC 8985 §7.4 repaired
    /// tail loss): the same PRR reduction, but nothing is retransmitted.
    /// Congestion was signalled explicitly, so it is never undone.
    pub fn enter_cwr(&mut self, flight: u32, snd_nxt: u32, mss: u32) {
        self.undo_valid = false;
        self.begin_reduction(CaState::Cwr, flight, snd_nxt, mss);
    }

    /// Upgrade a CWR episode to fast recovery when loss is found during it
    /// (the window was already reduced once for this round trip).
    pub fn cwr_to_recovery(&mut self) {
        if self.state == CaState::Cwr {
            self.state = CaState::Recovery;
        }
    }

    /// Count a retransmission against the current loss episode.
    pub fn on_retransmit(&mut self) {
        if self.undo_valid && self.in_loss_recovery() {
            self.undo_retrans = self.undo_retrans.saturating_add(1);
        }
    }

    /// A D-SACK reported `[start, end)` as received twice. Once every
    /// retransmission of the episode has been reported so, the reduction
    /// was spurious: restore the prior window and leave recovery. Returns
    /// `true` when the episode was undone.
    pub fn on_dsack(&mut self, start: u32, end: u32, mss: u32) -> bool {
        if !self.undo_valid || self.undo_retrans == 0 || !seq_ge(start, self.undo_marker) {
            return false;
        }
        let segs = end.wrapping_sub(start).div_ceil(mss.max(1)).max(1);
        self.undo_retrans = self.undo_retrans.saturating_sub(segs);
        if self.undo_retrans > 0 {
            return false;
        }
        self.cwnd = self.cwnd.max(self.prior_cwnd);
        self.ssthresh = self.ssthresh.max(self.prior_ssthresh);
        if self.in_loss_recovery() {
            self.state = CaState::Open;
        }
        self.ca_acc = 0;
        self.undo_valid = false;
        true
    }

    /// RFC 6937 per-ACK update. `delivered` = bytes newly cumulatively ACKed
    /// or SACKed by this ACK; `pipe` = RFC 6675 in-flight estimate after it.
    /// `safe_ack` = the ACK advanced `SND.UNA` and revealed no new loss
    /// (enables PRR-SSRB's extra segment).
    pub fn prr_update(&mut self, delivered: u32, pipe: u32, mss: u32, safe_ack: bool) {
        if !self.in_reduction() {
            return;
        }
        self.prr_delivered = self.prr_delivered.saturating_add(u64::from(delivered));
        let prr_delivered = i64::try_from(self.prr_delivered).unwrap_or(i64::MAX);
        let prr_out = i64::try_from(self.prr_out).unwrap_or(i64::MAX);
        let sndcnt: i64 = if pipe > self.ssthresh {
            let num = self.prr_delivered.saturating_mul(u64::from(self.ssthresh));
            let ceil = num.div_ceil(u64::from(self.recover_fs.max(1)));
            i64::try_from(ceil)
                .unwrap_or(i64::MAX)
                .saturating_sub(prr_out)
        } else {
            let mut limit = prr_delivered
                .saturating_sub(prr_out)
                .max(i64::from(delivered));
            if safe_ack {
                limit = limit.saturating_add(i64::from(mss));
            }
            limit.min(i64::from(self.ssthresh - pipe))
        };
        let mut sndcnt = sndcnt.max(0);
        // Force the fast retransmission out on the ACK that starts recovery.
        if self.prr_out == 0 && sndcnt == 0 {
            sndcnt = i64::from(mss);
        }
        let c = i64::from(pipe).saturating_add(sndcnt);
        self.cwnd = u32::try_from(c).unwrap_or(u32::MAX).max(mss);
    }

    /// Account bytes put on the wire (PRR `prr_out`).
    pub fn on_send(&mut self, bytes: u32) {
        if self.in_reduction() {
            self.prr_out = self.prr_out.saturating_add(u64::from(bytes));
        }
    }

    /// RFC 5681 §3.1 retransmission timeout. `ssthresh` is only reduced for
    /// the first timeout of an episode (not again while recovering the same
    /// window); `cwnd` collapses to one segment.
    pub fn on_rto(&mut self, flight: u32, snd_una: u32, snd_nxt: u32, mss: u32) {
        let episode_over = seq_ge(snd_una, self.recovery_point);
        if matches!(self.state, CaState::Open | CaState::Cwr) || episode_over {
            if self.state == CaState::Cwr {
                self.undo_valid = false;
            } else {
                self.arm_undo(snd_una);
            }
            self.ssthresh = (flight / 2).max(mss.saturating_mul(2));
        }
        self.cwnd = mss;
        self.ca_acc = 0;
        self.state = CaState::Loss;
        self.recovery_point = snd_nxt;
    }

    /// End the episode once `SND.UNA` passes the recovery point. Returns
    /// `true` if an episode ended on this call.
    pub fn maybe_exit(&mut self, snd_una: u32) -> bool {
        if self.state == CaState::Open || !seq_ge(snd_una, self.recovery_point) {
            return false;
        }
        if self.in_reduction() {
            // RFC 6937: exit with cwnd = ssthresh.
            self.cwnd = self.ssthresh;
        }
        self.state = CaState::Open;
        self.ca_acc = 0;
        true
    }

    /// Idle restart (RFC 5681 §4.1): after an idle period longer than one RTO
    /// the window is reset to the restart window, `min(IW, cwnd)`.
    pub fn on_idle_restart(&mut self, iw: u32) {
        if self.state == CaState::Open {
            self.cwnd = self.cwnd.min(iw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const M: u32 = 1000;

    #[test]
    fn slow_start_counts_bytes_then_avoids_congestion() {
        let mut r = Reno::new(10 * M);
        r.ssthresh = 20 * M;
        r.on_ack(4 * M, M, true); // one stretch ACK
        assert_eq!(r.cwnd, 14 * M);
        r.on_ack(10 * M, M, true); // crosses ssthresh: 6 M of SS, 4 M into CA
        assert_eq!(r.cwnd, 20 * M);
        for _ in 0..16 {
            r.on_ack(M, M, true);
        }
        assert_eq!(r.cwnd, 21 * M, "+1 MSS per cwnd's worth of ACKed bytes");
        r.on_ack(100 * M, M, false);
        assert_eq!(r.cwnd, 21 * M, "no growth while application-limited");
    }

    #[test]
    fn prr_reduces_proportionally_and_exits_at_ssthresh() {
        let mut r = Reno::new(20 * M);
        r.enter_recovery(20 * M, 0, 5000, M);
        assert_eq!(r.ssthresh, 10 * M);
        // First ACK: one segment delivered, pipe still above ssthresh.
        r.prr_update(M, 18 * M, M, false);
        // ceil(1000*10000/20000) - 0 = 500 → one (rounded-up) send allowed.
        assert_eq!(r.cwnd, 18 * M + 500);
        r.on_send(M);
        r.prr_update(M, 17 * M, M, false);
        // ceil(2000*10000/20000) - 1000 = 0, and nothing is forced again.
        assert_eq!(r.cwnd, 17 * M);
        assert!(!r.maybe_exit(4999));
        assert!(r.maybe_exit(5000));
        assert_eq!(r.cwnd, 10 * M);
        assert_eq!(r.state(), CaState::Open);
    }

    #[test]
    fn prr_ssrb_grows_back_toward_ssthresh_when_pipe_is_low() {
        let mut r = Reno::new(20 * M);
        r.enter_recovery(20 * M, 0, 5000, M);
        r.on_send(M);
        r.prr_update(2 * M, 2 * M, M, true);
        // limit = max(2000-1000, 2000) + MSS = 3000; min(ssthresh-pipe=8000, 3000).
        assert_eq!(r.cwnd, 5 * M);
    }

    #[test]
    fn dsack_for_every_retransmission_undoes_the_episode() {
        let mut r = Reno::new(20 * M);
        r.ssthresh = 30 * M;
        r.enter_recovery(20 * M, 1000, 21_000, M);
        r.on_retransmit();
        r.on_retransmit();
        r.prr_update(M, 18 * M, M, false);
        assert!(
            !r.on_dsack(500, 1500, M),
            "below the episode start: ignored"
        );
        assert!(!r.on_dsack(1000, 2000, M), "one of two retransmissions");
        assert!(r.on_dsack(2000, 3000, M), "the last one: undo");
        assert_eq!(
            (r.cwnd, r.ssthresh, r.state()),
            (20 * M, 30 * M, CaState::Open)
        );
        assert!(!r.on_dsack(3000, 4000, M), "nothing left to undo");
    }

    #[test]
    fn late_dsack_undoes_after_recovery_ended_and_rto_too() {
        let mut r = Reno::new(20 * M);
        r.enter_recovery(20 * M, 1000, 21_000, M);
        r.on_retransmit();
        assert!(r.maybe_exit(21_000));
        assert_eq!(r.cwnd, 10 * M);
        r.on_retransmit(); // outside the episode: not counted
        assert!(r.on_dsack(1000, 2000, M));
        assert_eq!(r.cwnd, 20 * M);

        let mut r = Reno::new(40 * M);
        r.on_rto(40 * M, 100, 9000, M);
        r.on_retransmit();
        assert!(r.on_dsack(100, 1100, M), "spurious timeout");
        assert_eq!((r.cwnd, r.state()), (40 * M, CaState::Open));
    }

    #[test]
    fn ecn_reductions_are_never_undone() {
        let mut r = Reno::new(20 * M);
        r.enter_cwr(20 * M, 21_000, M);
        r.cwr_to_recovery();
        r.on_retransmit();
        assert!(!r.on_dsack(0, 1000, M));
        assert_eq!(r.ssthresh, 10 * M);
    }

    #[test]
    fn rto_collapses_window_and_reduces_ssthresh_once_per_episode() {
        let mut r = Reno::new(40 * M);
        r.on_rto(40 * M, 100, 9000, M);
        assert_eq!((r.cwnd, r.ssthresh, r.state()), (M, 20 * M, CaState::Loss));
        r.on_rto(40 * M, 100, 9000, M); // backoff of the same episode
        assert_eq!(r.ssthresh, 20 * M, "not halved again");
        assert!(r.maybe_exit(9000));
        assert_eq!(r.cwnd, M, "slow start continues after RTO recovery");
    }

    #[test]
    fn initial_window_follows_rfc6928() {
        assert_eq!(initial_window(1460), 14_600);
        assert_eq!(initial_window(536), 5_360);
        assert_eq!(initial_window(9000), 18_000);
    }
}
