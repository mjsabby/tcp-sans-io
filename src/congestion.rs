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
//! A loss-triggered reduction (fast recovery or RTO) is undone once it is
//! shown to be spurious, with an Eifel-style response: reordering or a
//! delay spike must not cost the window. The evidence is either D-SACKs
//! for every retransmission of the episode (RFC 3708, as Linux
//! `tcp_try_undo_dsack`) or an ACK echoing a timestamp from before the
//! episode's first retransmission, so an original transmission filled the
//! hole (Eifel detection, RFC 3522, as Linux `tcp_packet_delayed`). The
//! latter also covers receivers that never send D-SACKs.

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

/// What a loss episode starting now inherits from earlier retransmissions.
#[derive(Copy, Clone, Debug, Default)]
pub struct UndoSeed {
    /// A retransmission may still fill a hole (Linux
    /// `tcp_any_retrans_done`): its send time stays the timestamp-undo
    /// reference.
    pub retx_outstanding: bool,
    /// Retransmissions in flight, counting an unresolved tail loss probe:
    /// a D-SACK undo needs each shown needless too (Linux `tcp_init_undo`).
    pub retrans_in_flight: u32,
}

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
    /// Host clock (ms, truncated like our TSvals) of the first
    /// retransmission that may still fill a hole (Linux `retrans_stamp`):
    /// an ACK echoing an earlier TSval was triggered by an original.
    first_retx_ms: Option<u32>,
    /// The current Loss episode may be shown spurious by F-RTO's test
    /// (Linux `tp->frto`): it began with a timeout from the Open or CWR
    /// state, or repeats one no ACK of new data has answered.
    frto: bool,
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
            first_retx_ms: None,
            frto: false,
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

    /// The window a reduction halves: `cwnd`, as Linux
    /// (`tcp_reno_ssthresh`), capped by the largest window the peer has
    /// offered. Not RFC 5681's FlightSize: with SACK that also counts data
    /// the receiver holds above a hole, and RACK waits out its reordering
    /// window (≥ 2 ms with a millisecond clock) before declaring a loss
    /// while a fast sender keeps filling the peer's window past the hole, so
    /// FlightSize/2 could stay above what the path holds and every episode
    /// overflowed the queue again. The cap keeps RFC 5681's reason for
    /// FlightSize: slow start may grow `cwnd` to twice a flight the peer's
    /// window limits, and half of that would not slow the sender at all.
    /// The largest window, not the current one: a reader that is briefly
    /// behind must not deepen the reduction.
    fn reduction_window(&self, peer_wnd: u32) -> u32 {
        self.cwnd.min(peer_wnd)
    }

    /// Linux `tcp_init_cwnd_reduction`: halve the window in use (see
    /// [`Self::reduction_window`]), which PRR then scales by (Linux
    /// `prior_cwnd`).
    fn begin_reduction(&mut self, state: CaState, snd_nxt: u32, mss: u32, peer_wnd: u32) {
        let window = self.reduction_window(peer_wnd);
        self.ssthresh = (window / 2).max(mss.saturating_mul(2));
        self.recover_fs = window.max(self.ssthresh);
        self.state = state;
        self.recovery_point = snd_nxt;
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.ca_acc = 0;
    }

    /// Remember the window a loss episode starting now could be undone to
    /// (Linux saves `tcp_current_ssthresh`).
    /// The episode's first retransmission starts the timestamp-undo clock
    /// unless an earlier retransmission may still fill a hole, whose send
    /// time then stays the reference (Linux `tcp_retrans_stamp_cleanup`);
    /// retransmissions still in flight must be shown needless by D-SACKs
    /// too (Linux `tcp_init_undo`).
    fn arm_undo(&mut self, snd_una: u32, seed: UndoSeed) {
        self.prior_cwnd = self.cwnd;
        self.prior_ssthresh = self.current_ssthresh();
        self.undo_valid = true;
        self.undo_marker = snd_una;
        self.undo_retrans = seed.retrans_in_flight;
        if !seed.retx_outstanding {
            self.first_retx_ms = None;
        }
    }

    /// Enter fast recovery (RFC 6937): halve `ssthresh`, pace with PRR.
    /// `peer_wnd`: the largest window the peer has offered (see
    /// [`Self::reduction_window`]).
    pub fn enter_recovery(
        &mut self,
        snd_una: u32,
        snd_nxt: u32,
        mss: u32,
        seed: UndoSeed,
        peer_wnd: u32,
    ) {
        self.arm_undo(snd_una, seed);
        self.begin_reduction(CaState::Recovery, snd_nxt, mss, peer_wnd);
    }

    /// Enter CWR (RFC 3168 §6.1.2 ECN response, or RFC 8985 §7.4 repaired
    /// tail loss): the same PRR reduction, but nothing is retransmitted.
    /// Congestion was signalled explicitly, so it is never undone.
    pub fn enter_cwr(&mut self, snd_nxt: u32, mss: u32, peer_wnd: u32) {
        self.undo_valid = false;
        self.begin_reduction(CaState::Cwr, snd_nxt, mss, peer_wnd);
    }

    /// Linux `tcp_simple_retransmit`: segments were lost to their size (a
    /// smaller path MTU, a path-MTU probe that did not get through), not to
    /// congestion. Resend them in the Loss state, which holds off fast
    /// recovery and probes until `SND.NXT` is acknowledged, without
    /// reducing the window: `ssthresh` becomes at least ¾ of `cwnd`, which
    /// stands, and there is nothing to undo. A timeout before the episode
    /// ends still reduces ([`Self::on_rto`]).
    pub fn enter_simple_loss(&mut self, snd_nxt: u32) {
        if self.state == CaState::Loss {
            return;
        }
        self.ssthresh = self.current_ssthresh();
        self.prior_cwnd = 0;
        self.prior_ssthresh = 0;
        self.undo_valid = false;
        self.frto = false;
        self.state = CaState::Loss;
        self.recovery_point = snd_nxt;
    }

    /// RFC 8985 §7.4.2 (Linux `tcp_process_tlp_ack`): a tail loss probe
    /// repaired a loss. The reduction is entered and ended at once:
    /// `cwnd = ssthresh`, congestion avoidance counting afresh.
    pub fn on_tlp_repair(&mut self, mss: u32, peer_wnd: u32) {
        self.ssthresh = (self.reduction_window(peer_wnd) / 2).max(mss.saturating_mul(2));
        self.cwnd = self.ssthresh;
        self.ca_acc = 0;
    }

    /// Upgrade a CWR episode to fast recovery when loss is found during it
    /// (the window was already reduced once for this round trip). The
    /// recovery point moves to `snd_nxt` (RFC 6675 `RecoveryPoint =
    /// HighData`); Linux keeps the CWR's, which, while CWR is held at it,
    /// ends recovery on the next ACK and reduces again for the same loss.
    pub fn cwr_to_recovery(&mut self, snd_nxt: u32) {
        if self.state == CaState::Cwr {
            self.state = CaState::Recovery;
            self.recovery_point = snd_nxt;
        }
    }

    /// A retransmission left at `now_ms`: count it against the current
    /// loss episode, and start the timestamp-undo clock if not running.
    pub fn on_retransmit(&mut self, now_ms: u64) {
        if self.first_retx_ms.is_none() {
            self.first_retx_ms = Some(now_ms as u32);
        }
        if self.undo_valid && self.in_loss_recovery() {
            self.undo_retrans = self.undo_retrans.saturating_add(1);
        }
    }

    /// Linux `tcp_packet_delayed`, during an undoable loss episode: was the
    /// hole an ACK just filled filled by an original transmission? Yes if
    /// it echoes `tsecr_ms` (its TSecr mapped back onto the host clock)
    /// from before the episode's first retransmission (Eifel detection,
    /// RFC 3522) — or if nothing has been retransmitted yet (a
    /// retransmission held back by a full egress ring), except for a
    /// NewReno episode's final ACK, which its retransmission may have
    /// earned.
    pub fn packet_delayed(&self, tsecr_ms: Option<u32>, snd_una: u32, sack: bool) -> bool {
        if !self.undo_valid || !self.in_loss_recovery() {
            return false;
        }
        match self.first_retx_ms {
            Some(t) => tsecr_ms.is_some_and(|e| (e.wrapping_sub(t) as i32) < 0),
            None => sack || !seq_ge(snd_una, self.recovery_point),
        }
    }

    /// F-RTO's test may still show the current timeout spurious (see
    /// [`Self::on_rto`]); the caller checks for acknowledged originals.
    pub fn frto_undo_possible(&self) -> bool {
        self.frto && self.undo_valid && self.state == CaState::Loss
    }

    /// F-RTO is over for this timeout: the loss was real, or its test
    /// cannot run (Linux `tp->frto = 0`).
    pub fn frto_off(&mut self) {
        self.frto = false;
    }

    /// ECN-Echo during a loss episode: the reduction is required, so an
    /// undo may end the episode but must not restore the window (Linux
    /// `tcp_fastretrans_alert`: `if (ece_ack) tp->prior_ssthresh = 0`).
    pub fn keep_reduction(&mut self) {
        self.prior_cwnd = 0;
        self.prior_ssthresh = 0;
    }

    /// No retransmission is left that could still fill a hole: outside a
    /// loss episode, forget the first-retransmission time (Linux
    /// `tcp_try_to_open`), so the next retransmission (a tail loss probe,
    /// say) starts a fresh clock. A stale one would hide later spurious
    /// episodes and, 2^31 ms on, wrap into false ones.
    pub fn on_retransmissions_settled(&mut self) {
        if !self.in_loss_recovery() {
            self.first_retx_ms = None;
        }
    }

    /// The episode was spurious: restore the window from before it and
    /// leave loss recovery (Linux `tcp_undo_cwnd_reduction`).
    pub fn undo(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd);
        self.ssthresh = self.ssthresh.max(self.prior_ssthresh);
        if self.in_loss_recovery() {
            self.state = CaState::Open;
        }
        self.ca_acc = 0;
        self.undo_valid = false;
    }

    /// A D-SACK reported `[start, end)` as received twice. Once every
    /// retransmission of the episode has been reported so, the reduction
    /// was spurious: restore the prior window and leave recovery. Returns
    /// `true` when the episode was undone.
    pub fn on_dsack(&mut self, start: u32, end: u32, mss: u32) -> bool {
        if !self.undo_valid || self.undo_retrans == 0 || !seq_ge(start, self.undo_marker) {
            return false;
        }
        // Once the episode is over, only its own retransmissions (below its
        // recovery point) can still show it spurious: a D-SACK for a later
        // one, such as a tail loss probe, says nothing about it.
        if self.state == CaState::Open && !seq_ge(self.recovery_point, end) {
            return false;
        }
        let segs = end.wrapping_sub(start).div_ceil(mss.max(1)).max(1);
        self.undo_retrans = self.undo_retrans.saturating_sub(segs);
        if self.undo_retrans > 0 {
            return false;
        }
        self.undo();
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

    /// RFC 5681 §3.1 retransmission timeout; `cwnd` collapses to one
    /// segment. As Linux `tcp_enter_loss`, `ssthresh` is reduced unless the
    /// timeout falls inside a fast-recovery or ECN episode, or `repeat`s a
    /// timeout no ACK of new data has answered since (a backoff of the same
    /// loss). `seed`: see [`Self::arm_undo`].
    pub fn on_rto(
        &mut self,
        snd_una: u32,
        snd_nxt: u32,
        mss: u32,
        seed: UndoSeed,
        peer_wnd: u32,
        repeat: bool,
    ) {
        let episode_over = seq_ge(snd_una, self.recovery_point);
        let reduce = match self.state {
            CaState::Open => true,
            CaState::Loss => episode_over || !repeat,
            CaState::Recovery | CaState::Cwr => episode_over,
        };
        // Linux `tcp_enter_loss`: F-RTO for a timeout from a calm state, or
        // a repeated one (a timeout in fast recovery has resent data already).
        self.frto = matches!(self.state, CaState::Open | CaState::Cwr) || repeat;
        if reduce {
            self.arm_undo(snd_una, seed);
            self.ssthresh = (self.reduction_window(peer_wnd) / 2).max(mss.saturating_mul(2));
        } else if self.state == CaState::Cwr {
            self.undo_valid = false;
        }
        self.cwnd = mss;
        self.ca_acc = 0;
        self.state = CaState::Loss;
        self.recovery_point = snd_nxt;
    }

    /// End the episode once `SND.UNA` passes the recovery point. Returns
    /// `true` if an episode ended on this call. CWR is held until something
    /// beyond it is ACKed, so the CWR flag has reached the receiver and a
    /// late ECN-Echo for the same marks cannot reduce again (Linux
    /// `tcp_fastretrans_alert`).
    pub fn maybe_exit(&mut self, snd_una: u32) -> bool {
        if self.state == CaState::Open || !seq_ge(snd_una, self.recovery_point) {
            return false;
        }
        if self.state == CaState::Cwr && snd_una == self.recovery_point {
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

    /// Restart after idle (Linux `tcp_cwnd_restart`, RFC 5681 §4.1 in
    /// spirit): after `idle_ms` without sending (more than an RTO), keep
    /// ¾ of the window as `ssthresh` and halve `cwnd` once per further RTO
    /// idle, down to the restart window `min(IW, cwnd)`.
    pub fn on_idle_restart(&mut self, iw: u32, idle_ms: u64, rto_ms: u32) {
        if self.state != CaState::Open {
            return;
        }
        self.ssthresh = self.current_ssthresh();
        let restart = iw.min(self.cwnd);
        let rto = u64::from(rto_ms.max(1));
        let mut cwnd = self.cwnd;
        let mut left = idle_ms;
        while left > rto && cwnd > restart {
            left -= rto;
            cwnd >>= 1;
        }
        self.cwnd = cwnd.max(restart);
    }

    /// The sender used less than its window for an RTO (Linux
    /// `tcp_cwnd_application_limited`, RFC 7661 in spirit): shrink `cwnd`
    /// halfway to what it used (at least IW), keeping ¾ of it as
    /// `ssthresh`, so a stale large window is not burst out later.
    pub fn on_application_limited(&mut self, iw: u32, used: u32) {
        if self.state != CaState::Open {
            return;
        }
        let used = used.max(iw);
        if used < self.cwnd {
            self.ssthresh = self.current_ssthresh();
            self.cwnd = (self.cwnd + used) / 2;
        }
    }

    /// Linux `tcp_current_ssthresh`: outside a reduction, at least ¾ of
    /// `cwnd`.
    fn current_ssthresh(&self) -> u32 {
        if self.in_reduction() {
            self.ssthresh
        } else {
            self.ssthresh
                .max((self.cwnd >> 1).saturating_add(self.cwnd >> 2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const M: u32 = 1000;
    const KEEP_STAMP: UndoSeed = UndoSeed {
        retx_outstanding: true,
        retrans_in_flight: 0,
    };

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
        r.enter_recovery(0, 5000, M, UndoSeed::default(), u32::MAX);
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
        r.enter_recovery(0, 5000, M, UndoSeed::default(), u32::MAX);
        r.on_send(M);
        r.prr_update(2 * M, 2 * M, M, true);
        // limit = max(2000-1000, 2000) + MSS = 3000; min(ssthresh-pipe=8000, 3000).
        assert_eq!(r.cwnd, 5 * M);
    }

    #[test]
    fn dsack_for_every_retransmission_undoes_the_episode() {
        let mut r = Reno::new(20 * M);
        r.ssthresh = 30 * M;
        r.enter_recovery(1000, 21_000, M, UndoSeed::default(), u32::MAX);
        r.on_retransmit(0);
        r.on_retransmit(0);
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
        r.enter_recovery(1000, 21_000, M, UndoSeed::default(), u32::MAX);
        r.on_retransmit(0);
        assert!(r.maybe_exit(21_000));
        assert_eq!(r.cwnd, 10 * M);
        r.on_retransmit(0); // outside the episode: not counted
        assert!(r.on_dsack(1000, 2000, M));
        assert_eq!(r.cwnd, 20 * M);

        let mut r = Reno::new(40 * M);
        r.on_rto(100, 9000, M, UndoSeed::default(), u32::MAX, false);
        r.on_retransmit(0);
        assert!(r.on_dsack(100, 1100, M), "spurious timeout");
        assert_eq!((r.cwnd, r.state()), (40 * M, CaState::Open));
    }

    #[test]
    fn ecn_reductions_are_never_undone() {
        let mut r = Reno::new(20 * M);
        r.enter_cwr(21_000, M, u32::MAX);
        r.cwr_to_recovery(22_000);
        assert_eq!(
            r.recovery_point(),
            22_000,
            "RFC 6675: RecoveryPoint = HighData"
        );
        r.on_retransmit(50);
        assert!(!r.on_dsack(0, 1000, M));
        assert!(!r.packet_delayed(Some(10), 0, true));
        assert_eq!(r.ssthresh, 10 * M);

        // ECN-Echo during a loss episode: an undo still ends the episode,
        // but the window stays reduced.
        let mut r = Reno::new(20 * M);
        r.enter_recovery(1000, 21_000, M, UndoSeed::default(), u32::MAX);
        r.on_retransmit(50);
        r.prr_update(M, 18 * M, M, false);
        let reduced = r.cwnd;
        r.keep_reduction();
        assert!(r.on_dsack(1000, 2000, M));
        assert_eq!(
            (r.cwnd, r.ssthresh, r.state()),
            (reduced, 10 * M, CaState::Open)
        );
    }

    #[test]
    fn retransmissions_in_flight_at_the_start_need_dsacks_too() {
        let mut r = Reno::new(20 * M);
        let seed = UndoSeed {
            retx_outstanding: true,
            retrans_in_flight: 1, // say, a tail loss probe
        };
        r.enter_recovery(1000, 21_000, M, seed, u32::MAX);
        r.on_retransmit(0);
        assert!(!r.on_dsack(2000, 3000, M), "the episode's own: not enough");
        assert!(r.on_dsack(9000, 10_000, M), "and the probe's: undo");
    }

    #[test]
    fn echo_from_before_the_first_retransmission_shows_a_delay() {
        let mut r = Reno::new(20 * M);
        let delayed = |r: &Reno, echo: u32| r.packet_delayed(Some(echo), 1000, true);
        r.enter_recovery(1000, 21_000, M, UndoSeed::default(), u32::MAX);
        assert!(delayed(&r, 90), "nothing resent yet: an original filled it");
        assert!(
            !r.packet_delayed(None, 21_000, false),
            "except a NewReno episode's last ACK"
        );
        r.on_retransmit(100);
        r.on_retransmit(105);
        assert!(!delayed(&r, 100), "echoes a retransmission");
        assert!(!r.packet_delayed(None, 1000, true), "no echo, no proof");
        assert!(delayed(&r, 99));
        r.undo();
        assert_eq!((r.cwnd, r.state()), (20 * M, CaState::Open));
        assert!(!delayed(&r, 99), "nothing left to undo");

        // An episode that starts while an earlier retransmission may still
        // fill a hole keeps that retransmission's send time: its echo must
        // not pass for an original's.
        r.enter_recovery(5000, 25_000, M, KEEP_STAMP, u32::MAX);
        r.on_retransmit(300);
        r.on_retransmissions_settled(); // still recovering: kept
        assert!(!delayed(&r, 200));
        assert!(delayed(&r, 99));
        // Otherwise the episode's own first retransmission is the reference,
        // across the wrap of the 32-bit timestamp clock.
        r.on_rto(25_000, 30_000, M, UndoSeed::default(), u32::MAX, false);
        r.on_retransmit((1u64 << 32) + 10);
        r.on_retransmit((1u64 << 32) + 20);
        assert!(delayed(&r, u32::MAX - 5));
        assert!(!delayed(&r, 10));
    }

    #[test]
    fn reduction_halves_cwnd_capped_by_the_peer_window() {
        // Slow start grew cwnd past the peer's window: halve what the window
        // let it send, and let PRR scale by the same.
        let mut r = Reno::new(40 * M);
        r.enter_recovery(0, 20_000, M, UndoSeed::default(), 16 * M);
        assert_eq!(r.ssthresh, 8 * M);
        r.prr_update(2 * M, 14 * M, M, false);
        // ceil(2000 * 8000 / 16000) = 1000 more than pipe.
        assert_eq!(r.cwnd, 15 * M);
        let mut r = Reno::new(40 * M);
        r.on_rto(0, 20_000, M, UndoSeed::default(), 16 * M, false);
        assert_eq!(r.ssthresh, 8 * M);
    }

    #[test]
    fn rto_collapses_window_and_reduces_ssthresh_once_per_unanswered_timeout() {
        let mut r = Reno::new(40 * M);
        r.on_rto(100, 9000, M, UndoSeed::default(), u32::MAX, false);
        assert_eq!((r.cwnd, r.ssthresh, r.state()), (M, 20 * M, CaState::Loss));
        r.on_rto(100, 9000, M, KEEP_STAMP, u32::MAX, true); // backoff of the same loss
        assert_eq!(r.ssthresh, 20 * M, "not halved again");
        // An ACK of new data answered it: a later timeout is a new loss
        // (Linux `tcp_enter_loss`, Loss without RTO retransmissions).
        r.cwnd = 8 * M;
        r.on_rto(3000, 9000, M, KEEP_STAMP, u32::MAX, false);
        assert_eq!((r.cwnd, r.ssthresh), (M, 4 * M));
        assert!(r.maybe_exit(9000));
        assert_eq!(r.cwnd, M, "slow start continues after RTO recovery");
    }

    #[test]
    fn simple_loss_keeps_the_window_but_a_timeout_in_it_reduces() {
        let mut r = Reno::new(40 * M);
        r.ssthresh = 20 * M;
        r.enter_simple_loss(9000);
        assert_eq!(
            (r.cwnd, r.ssthresh, r.state()),
            (40 * M, 30 * M, CaState::Loss)
        );
        assert!(!r.packet_delayed(None, 100, true), "nothing to undo");
        r.on_ack(40 * M, M, true);
        assert_eq!(r.cwnd, 41 * M, "the window keeps growing");
        r.on_rto(100, 9000, M, UndoSeed::default(), u32::MAX, false);
        assert_eq!((r.cwnd, r.ssthresh), (M, 41 * M / 2));
    }

    #[test]
    fn tlp_repair_halves_the_window_and_counts_avoidance_afresh() {
        let mut r = Reno::new(20 * M);
        r.ssthresh = 10 * M;
        r.on_ack(19 * M, M, true); // most of a window toward the next MSS
        r.on_tlp_repair(M, u32::MAX);
        assert_eq!((r.cwnd, r.ssthresh), (10 * M, 10 * M));
        r.on_ack(5 * M, M, true);
        assert_eq!(r.cwnd, 10 * M, "credit from before the reduction counted");
    }

    #[test]
    fn initial_window_follows_rfc6928() {
        assert_eq!(initial_window(1460), 14_600);
        assert_eq!(initial_window(536), 5_360);
        assert_eq!(initial_window(9000), 18_000);
    }
}
