//! Acknowledgment processing and loss recovery.
//!
//! Per ACK: validate (RFC 9293 + RFC 5961 §5), absorb SACK blocks (D-SACK
//! per RFC 2883 is detected and *never* treated as loss), apply the
//! cumulative ACK, take an RTT sample (TSecr or Karn), update the send
//! window, run loss detection (RACK with SACK, RFC 6582 NewReno without),
//! then let congestion control react: PRR during a reduction, slow start /
//! congestion avoidance otherwise.

use super::{seq_ge, seq_gt, seq_le, seq_lt, Deadline, Tcb, TLP_MIN_PTO_MS, TLP_WC_DELACK_MS};
use crate::congestion::CaState;
use crate::error::TcpError;
use crate::rtx_queue::seg_flags;
use crate::state::State;
use crate::wire::{flags, Segment};

impl<const BUF: usize> Tcb<BUF> {
    /// RFC 9293 §3.10.7.4 step 5 hardened by RFC 5961 §5.2: SEG.ACK is
    /// acceptable within `[SND.UNA − MAX.SND.WND, SND.NXT]`. Outside it (an
    /// ACK of unsent data, or so old that a blind injector needs only some
    /// stale sequence number) the whole segment is dropped after a
    /// rate-limited ACK, so callers check this before the segment may touch
    /// any state (TS.Recent, the ECN echo, the keepalive clock, …).
    pub(super) fn ack_acceptable(&self, ack: u32) -> bool {
        let max_wnd = self.max_snd_wnd.max(u32::from(self.local_mss));
        !seq_gt(ack, self.snd_nxt) && !seq_lt(ack, self.snd_una.wrapping_sub(max_wnd))
    }

    /// Process the ACK field of a segment that passed [`Self::ack_acceptable`].
    pub(super) fn process_ack(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        let ack = seg.ack;
        // Any acceptable ACK is proof of life (RFC 9293 §3.8.3 R2).
        self.rtx_count = 0;
        if seq_lt(ack, self.snd_una) {
            return Ok(()); // old ACK: ignore the field
        }

        let prior_una = self.snd_una;
        // FlightSize before this ACK. A reduction this ACK starts (loss or
        // ECE) is sized from it, because PRR counts this ACK's delivered
        // bytes too: RecoverFS must include them (RFC 6937 §3) or
        // prr_delivered / RecoverFS overshoots and PRR releases a burst.
        let prior_flight = self.snd_nxt.wrapping_sub(self.data_una());
        let now = self.now_ms;
        let mss = self.mss_payload();
        let tsecr_ms = match (self.ts_enabled, seg.options.ts) {
            (true, Some((_, e))) if e != 0 => Some(self.tsecr_to_ms(e)),
            _ => None,
        };
        let mut delivered: u32 = 0;
        self.rack.on_ack_start();

        // ---- SACK / D-SACK (RFC 2018, RFC 2883) ------------------------
        let mut dsack: Option<(u32, u32)> = None;
        let mut sack_present = false;
        if self.sack_enabled {
            let blocks = seg.options.sack.as_slice();
            if let Some(&(l0, r0)) = blocks.first() {
                sack_present = true;
                let is_dsack = seq_le(r0, ack)
                    || blocks
                        .get(1)
                        .is_some_and(|&(l1, r1)| seq_le(l1, l0) && seq_le(r0, r1));
                if is_dsack {
                    dsack = Some((l0, r0));
                    self.stats.dsacks_received = self.stats.dsacks_received.saturating_add(1);
                    self.rack.on_dsack(self.snd_una, self.snd_nxt);
                    if self.cc.on_dsack(l0, r0, mss) {
                        // Spurious episode: restore the window (done) and drop
                        // loss marks that were never acted on.
                        self.rtx.unmark_lost();
                        self.rack.on_recovery_exit();
                    }
                }
                let rack = &mut self.rack;
                let rtx = &mut self.rtx;
                for &(l, r) in blocks.iter().skip(usize::from(is_dsack)) {
                    // An ACK for out-of-order data echoes the TSval of the
                    // last in-order segment (RFC 7323 §4.3), never that of
                    // the segment it SACKs, so TSecr cannot disambiguate a
                    // SACKed retransmission; RACK falls back to min_rtt.
                    let n = rtx.sack(l, r, |s| rack.on_delivered(s, now, None));
                    delivered = delivered.saturating_add(n);
                }
            }
        }

        // ---- Cumulative ACK --------------------------------------------
        let acked = ack.wrapping_sub(prior_una);
        if acked > 0 {
            let syn_acked = self.syn_outstanding();
            let fin_acked =
                self.fin_sent && seq_le(prior_una, self.fin_seq) && seq_gt(ack, self.fin_seq);
            let sacked_before = self.rtx.sacked_bytes();
            let mut karn_ts: Option<u64> = None;
            {
                let rack = &mut self.rack;
                self.rtx.ack_to(ack, |s, newly| {
                    if newly {
                        rack.on_delivered(s, now, tsecr_ms);
                        if !s.has(seg_flags::EVER_RETRANS) {
                            karn_ts = Some(karn_ts.map_or(s.xmit_ts, |k| k.max(s.xmit_ts)));
                        }
                    }
                });
            }
            let sacked_removed = sacked_before.saturating_sub(self.rtx.sacked_bytes());
            // Without SACK, bytes beyond the first segment were already
            // credited by the duplicate ACKs that preceded this one.
            let reno_eaten = acked.saturating_sub(mss).min(self.reno_sacked);
            self.reno_sacked -= reno_eaten;
            delivered = delivered
                .saturating_add(
                    acked
                        .saturating_sub(sacked_removed)
                        .saturating_sub(reno_eaten),
                )
                .saturating_sub(u32::from(syn_acked));
            let data_acked = acked
                .saturating_sub(u32::from(fin_acked))
                .saturating_sub(u32::from(syn_acked));
            self.send_ring.consume(data_acked as usize);
            self.snd_una = ack;
            self.syn_unacked = false;
            self.dup_acks = 0;
            // RTT: RFC 7323 RTTM when timestamps are on, else Karn.
            let sample = match tsecr_ms {
                Some(t) => Some((now as u32).wrapping_sub(t)),
                None => karn_ts.and_then(|x| u32::try_from(now.saturating_sub(x)).ok()),
            };
            if let Some(r) = sample {
                if r < 60_000 {
                    self.update_rtt(r);
                }
            }
            self.note_progress(data_acked.saturating_add(u32::from(fin_acked)));
        }

        // ---- Send window (RFC 9293 §3.10.7.4, hardened) -----------------
        let wnd_before = self.snd_wnd;
        self.update_send_window(seg, prior_una);

        // ---- ECN-Echo (RFC 3168 §6.1.2): reduce once per window, never
        // retransmit — nothing was lost.
        if self.ecn_enabled
            && seg.has(flags::ECE)
            && self.cc.state() == CaState::Open
            && self.snd_una != self.snd_nxt
        {
            self.cc.enter_cwr(prior_flight, self.snd_nxt, mss);
            self.send_cwr_pending = true;
        }

        // ---- Loss detection --------------------------------------------
        // RACK whenever SACK is negotiated. Duplicate ACKs that carry no SACK
        // blocks at all (non-SACK peer, or blocks stripped by a middlebox)
        // fall back to RFC 6675 DupThresh / RFC 6582 NewReno.
        let mut newly_lost = self.sack_enabled && self.rack_detect();
        if !sack_present {
            let (lost, dup) = self.newreno_detect(seg, acked, wnd_before);
            newly_lost |= lost;
            if dup && !self.sack_enabled {
                let outstanding = self.snd_nxt.wrapping_sub(self.data_una());
                if self.reno_sacked.saturating_add(mss) <= outstanding {
                    self.reno_sacked += mss;
                    delivered = delivered.saturating_add(mss);
                }
            }
        }
        let outstanding = self.snd_nxt.wrapping_sub(self.data_una());
        self.reno_sacked = self.reno_sacked.min(outstanding);
        if self.rtx.lost_bytes() > 0 && !self.cc.in_loss_recovery() {
            self.enter_fast_recovery(prior_flight);
        }

        // ---- Tail loss probe outcome (RFC 8985 §7.4.2) -----------------
        self.tlp_on_ack(ack, dsack, sack_present, delivered);

        // ---- Congestion control ----------------------------------------
        if self.cc.maybe_exit(self.snd_una) {
            self.rack.on_recovery_exit();
        }
        let limited = self.take_cwnd_limited();
        if self.cc.in_reduction() {
            let pipe = self.pipe();
            self.cc
                .prr_update(delivered, pipe, mss, acked > 0 && !newly_lost);
        } else {
            self.cc.on_ack(delivered, mss, limited);
        }

        // ---- Timers (RFC 6298 §5.2/5.3) ---------------------------------
        if self.snd_una == self.snd_nxt {
            self.rto_deadline = Deadline::OFF;
            self.tlp_deadline = Deadline::OFF;
            self.rack_deadline = Deadline::OFF;
        } else if acked > 0 {
            self.arm_rto();
        }
        self.maybe_arm_tlp();

        // ---- Our FIN acknowledged --------------------------------------
        if self.fin_sent && self.snd_una == self.snd_nxt {
            match self.state {
                State::FinWait1 => {
                    self.state = State::FinWait2;
                    self.user_timeout_deadline = Deadline::OFF;
                    if self.fin_wait2_timeout_ms != 0 {
                        self.fin_wait2_deadline = Deadline::at(
                            self.now_ms
                                .saturating_add(u64::from(self.fin_wait2_timeout_ms)),
                        );
                    }
                }
                State::Closing => {
                    self.enter_time_wait();
                    self.state = State::TimeWait;
                }
                State::LastAck => self.close_clean(),
                _ => {}
            }
        }
        Ok(())
    }

    /// Window update. RFC 9293's SND.WL1/WL2 test keeps reordered stale
    /// ACKs from regressing the window, with two hardenings:
    /// an ACK that advances `SND.UNA` may always update the window (as
    /// Linux), and the WL1 candidate is clamped to `RCV.NXT` so a single
    /// forged in-window segment with a "future" sequence number cannot
    /// freeze the window against all of the peer's genuine ACKs.
    fn update_send_window(&mut self, seg: &Segment<'_>, prior_una: u32) {
        let seq = if seq_gt(seg.seq, self.rcv_nxt) {
            self.rcv_nxt
        } else {
            seg.seq
        };
        let fresh = seq_gt(seg.ack, prior_una)
            || seq_lt(self.snd_wl1, seq)
            || (self.snd_wl1 == seq && seq_le(self.snd_wl2, seg.ack));
        if !fresh {
            return;
        }
        let wnd = self.scale_peer_window(seg.window);
        self.snd_wnd = wnd;
        self.snd_wl1 = seq;
        self.snd_wl2 = seg.ack;
        self.max_snd_wnd = self.max_snd_wnd.max(wnd);
    }

    /// Re-arm the USER TIMEOUT only on meaningful progress: at least one
    /// full segment acknowledged since the last re-arm (or all work done).
    fn note_progress(&mut self, acked: u32) {
        self.persist_backoff_ms = 0;
        if self.user_timeout_ms == 0 {
            return;
        }
        if !self.has_send_work() {
            self.user_timeout_deadline = Deadline::OFF;
            self.ut_progress = 0;
            return;
        }
        self.ut_progress = self.ut_progress.saturating_add(acked);
        if self.ut_progress >= self.mss_payload() || !self.user_timeout_deadline.is_armed() {
            self.ut_progress = 0;
            self.user_timeout_deadline =
                Deadline::at(self.now_ms.saturating_add(u64::from(self.user_timeout_ms)));
        }
    }

    /// RACK loss detection (RFC 8985 §6.2 step 5); arms the reorder timer.
    pub(super) fn rack_detect(&mut self) -> bool {
        let mss = self.mss_payload();
        let reo = self.rack.reo_wnd(
            self.srtt_ms,
            self.cc.in_loss_recovery(),
            self.rtx.sacked_bytes(),
            mss,
        );
        let (marked, timeout) =
            crate::rack::detect_loss(&self.rack, &mut self.rtx, self.now_ms, reo);
        self.rack_deadline = match timeout {
            Some(t) => Deadline::at(self.now_ms.saturating_add(t)),
            None => Deadline::OFF,
        };
        marked
    }

    /// RFC 6582 NewReno / RFC 6675 DupThresh loss marking for ACKs without
    /// SACK information. Returns `(newly_lost, was_duplicate_ack)`.
    fn newreno_detect(&mut self, seg: &Segment<'_>, acked: u32, wnd_before: u32) -> (bool, bool) {
        if acked == 0 {
            let dup = seg.payload.is_empty()
                && !seg.has(flags::FIN)
                && self.snd_una != self.snd_nxt
                && self.snd_wnd == wnd_before;
            if dup {
                self.dup_acks = self.dup_acks.saturating_add(1);
                if self.dup_acks == 3 && !self.cc.in_loss_recovery() {
                    self.rtx.mark_lost(0);
                    return (true, true);
                }
            }
            return (false, dup);
        }
        // Partial ACK during NewReno recovery: the next segment is lost too.
        if !self.sack_enabled
            && self.cc.state() == CaState::Recovery
            && seq_lt(self.snd_una, self.cc.recovery_point())
        {
            self.rtx.mark_lost(0);
            return (true, false);
        }
        (false, false)
    }

    /// Start fast recovery. `flight` is the FlightSize the reduction is
    /// based on (RecoverFS): before the triggering ACK, if there is one.
    pub(super) fn enter_fast_recovery(&mut self, flight: u32) {
        let mss = self.mss_payload();
        if self.cc.state() == CaState::Cwr {
            self.cc.cwr_to_recovery();
        } else {
            self.cc
                .enter_recovery(flight, self.snd_una, self.snd_nxt, mss);
        }
        self.stats.fast_recoveries = self.stats.fast_recoveries.saturating_add(1);
        self.tlp_end_seq = None;
        self.tlp_deadline = Deadline::OFF;
    }

    /// Whether the sender used its window this round (gates cwnd growth),
    /// then roll the round over once it has been acknowledged.
    fn take_cwnd_limited(&mut self) -> bool {
        let in_ss = self.cc.cwnd < self.cc.ssthresh;
        let limited =
            self.cwnd_limited || (in_ss && self.pipe_hiwat.saturating_mul(2) > self.cc.cwnd);
        if seq_ge(self.snd_una, self.cwnd_limited_seq) {
            self.cwnd_limited = false;
            self.pipe_hiwat = self.pipe();
            self.cwnd_limited_seq = self.snd_nxt;
        }
        limited
    }

    /// RFC 8985 §7.4.2 `TLP_process_ack`.
    fn tlp_on_ack(&mut self, ack: u32, dsack: Option<(u32, u32)>, sack: bool, delivered: u32) {
        let Some(end) = self.tlp_end_seq else {
            return;
        };
        if !seq_ge(ack, end) {
            return;
        }
        if !self.tlp_is_retrans {
            self.tlp_end_seq = None;
            return;
        }
        if dsack.is_some_and(|(_, r)| r == end) {
            self.tlp_end_seq = None; // the probe was unnecessary
            return;
        }
        if seq_gt(ack, end) || (!sack && delivered == 0) {
            // The probe repaired a lost tail: one congestion response.
            self.tlp_end_seq = None;
            if self.cc.state() == CaState::Open {
                let mss = self.mss_payload();
                let w = self.cc.cwnd;
                self.cc.ssthresh = (w / 2).max(mss.saturating_mul(2));
                self.cc.cwnd = self.cc.ssthresh;
            }
        }
    }

    /// Arm the tail loss probe (RFC 8985 §7.2) when data is outstanding, the
    /// connection is not recovering, and the PTO would fire before the RTO.
    pub(super) fn maybe_arm_tlp(&mut self) {
        let eligible = self.sack_enabled
            && self.cc.state() == CaState::Open
            && self.tlp_end_seq.is_none()
            && self.snd_una != self.snd_nxt
            && matches!(
                self.state,
                State::Established
                    | State::CloseWait
                    | State::FinWait1
                    | State::Closing
                    | State::LastAck
            );
        if !eligible {
            self.tlp_deadline = Deadline::OFF;
            return;
        }
        let srtt = if self.rtt_first_sample {
            u64::from(self.srtt_ms)
        } else {
            500
        };
        let mut pto = srtt.saturating_mul(2);
        if self.rtx.len() == 1 {
            pto = pto.saturating_add(TLP_WC_DELACK_MS);
        }
        // RFC 8985 §7.2: never later than the RTO — the first timeout event
        // of a tail loss is a probe, not a window-collapsing RTO.
        let mut at = self.now_ms.saturating_add(pto.max(TLP_MIN_PTO_MS));
        if let Some(rto) = self.rto_deadline.get() {
            at = at.min(rto);
        }
        self.tlp_deadline = Deadline::at(at);
    }
}
