//! Acknowledgment processing and loss recovery.
//!
//! Per ACK: validate (RFC 9293 + RFC 5961 §5), absorb SACK blocks (D-SACK
//! per RFC 2883 is detected, validated, and *never* treated as loss), apply
//! the cumulative ACK, take an RTT sample (our send times; TSecr only when
//! retransmitted data is acknowledged), undo a loss episode the D-SACKs or
//! the timestamp echo show was spurious, update the send window, run loss
//! detection (RACK with SACK, RFC 6582 NewReno without), then let
//! congestion control react: PRR during a reduction, slow start /
//! congestion avoidance otherwise.

use super::{seq_ge, seq_gt, seq_le, seq_lt, Deadline, Tcb, TLP_MIN_PTO_MS, TLP_WC_DELACK_MS};
use crate::congestion::{CaState, UndoSeed};
use crate::error::TcpError;
use crate::rtx_queue::seg_flags;
use crate::state::State;
use crate::wire::{flags, Segment};

impl<const BUF: usize> Tcb<BUF> {
    /// RFC 9293 §3.10.7.4 step 5 hardened by RFC 5961 §5.2: SEG.ACK is
    /// acceptable within `[SND.UNA − MAX.SND.WND, SND.NXT]`, and, as in
    /// Linux, never below the sequence space acknowledged so far: an ACK of
    /// bytes we never sent is bogus, so on a connection that has sent
    /// little a blind injector must guess SND.UNA almost exactly. Outside
    /// it (an ACK of unsent data, or so old that a blind injector needs
    /// only some stale sequence number) the whole segment is dropped after
    /// a rate-limited ACK, so callers check this before the segment may
    /// touch any state (TS.Recent, the ECN echo, the keepalive clock, …).
    pub(super) fn ack_acceptable(&self, ack: u32) -> bool {
        let max_wnd = self.max_snd_wnd.max(u32::from(self.local_mss));
        let back = u32::try_from(self.snd_acked).map_or(max_wnd, |a| a.min(max_wnd));
        !seq_gt(ack, self.snd_nxt) && !seq_lt(ack, self.snd_una.wrapping_sub(back))
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
        // FlightSize before this ACK: an ECN-Echo starts a reduction only if
        // data was outstanding (as Linux, even when this ACK drained it).
        let prior_flight = self.snd_nxt.wrapping_sub(self.data_una());
        let now = self.now_ms;
        let mss = self.mss_payload();
        let tsecr_ms = match (self.ts_enabled, seg.options.ts) {
            (true, Some((_, e))) if e != 0 => Some(self.tsecr_to_ms(e)),
            _ => None,
        };
        let mut delivered: u32 = 0;
        self.rack.on_ack_start();
        self.rack.tlp_probe_end = self.tlp_end_seq.filter(|_| self.tlp_is_retrans);
        // ECN-Echo during a loss episode: the reduction stands, whatever
        // undo may follow (Linux `tcp_fastretrans_alert`).
        let ece = self.ecn_enabled && seg.has(flags::ECE);
        if ece && self.cc.in_loss_recovery() {
            self.cc.keep_reduction();
        }

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
                if is_dsack && self.dsack_valid(l0, r0, mss) {
                    dsack = Some((l0, r0));
                    self.stats.dsacks_received = self.stats.dsacks_received.saturating_add(1);
                    // A duplicate tail loss probe says nothing about
                    // reordering: the timer, not RACK, sent it (Linux
                    // `FLAG_DSACK_TLP`).
                    let tlp_dsack = self.tlp_end_seq == Some(r0) && r0.wrapping_sub(l0) <= mss;
                    if !tlp_dsack {
                        self.rack.on_dsack(self.snd_una, self.snd_nxt);
                    }
                    if self.cc.on_dsack(l0, r0, mss) {
                        // Spurious episode: restore the window (done) and drop
                        // loss marks that were never acted on.
                        self.rtx.unmark_lost();
                        self.rack.on_dsack_undo();
                    }
                }
                let (una, nxt) = (self.snd_una, self.snd_nxt);
                let rack = &mut self.rack;
                let rtx = &mut self.rtx;
                for &(l, r) in blocks.iter().skip(usize::from(is_dsack)) {
                    // Linux `tcp_is_sackblock_valid`: a block reaching past
                    // SND.NXT, or starting at or below SND.UNA, is ignored
                    // whole — clipped, it would report delivery of data the
                    // receiver never claimed.
                    if !seq_lt(l, r) || seq_gt(r, nxt) || !seq_gt(l, una) {
                        continue;
                    }
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
        let mut hold_detection = false;
        if acked > 0 {
            let syn_acked = self.syn_outstanding();
            let fin_acked =
                self.fin_sent && seq_le(prior_una, self.fin_seq) && seq_gt(ack, self.fin_seq);
            let sacked_before = self.rtx.sacked_bytes();
            // Send times of the newly acknowledged segments, for the RTT.
            let mut oldest_ts: Option<u64> = None;
            let mut newest_ts = 0u64;
            let mut retrans_acked = false;
            {
                let rack = &mut self.rack;
                self.rtx.ack_to(ack, |s, newly| {
                    if newly {
                        rack.on_delivered(s, now, tsecr_ms);
                        newest_ts = newest_ts.max(s.xmit_ts);
                        if s.has(seg_flags::EVER_RETRANS) {
                            retrans_acked = true;
                        } else {
                            oldest_ts = Some(oldest_ts.map_or(s.xmit_ts, |k| k.min(s.xmit_ts)));
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
            self.snd_acked = self.snd_acked.saturating_add(u64::from(acked));
            self.syn_unacked = false;
            self.dup_acks = 0;
            // RTT, preferring our own send times as Linux does: the peer and
            // middleboxes control TSecr. Without retransmissions, time the
            // oldest newly ACKed segment (what an RFC 7323 echo reports).
            // Otherwise Karn's rule rules out send times and TSecr (RTTM)
            // names the transmission that arrived; it is believed only if
            // not later than the newest transmission this ACK covers.
            let sample = if retrans_acked {
                tsecr_ms
                    .filter(|&t| !seq_gt(t, newest_ts as u32))
                    .map(|t| (now as u32).wrapping_sub(t))
            } else {
                oldest_ts.and_then(|x| u32::try_from(now.saturating_sub(x)).ok())
            };
            if let Some(r) = sample {
                if r < 60_000 {
                    self.update_rtt(r);
                }
            }
            self.note_progress(data_acked.saturating_add(u32::from(fin_acked)));
            hold_detection = self.try_undo_delayed(tsecr_ms);
        }
        self.pmtu_probe_on_ack();

        // ---- Send window (RFC 9293 §3.10.7.4, hardened) -----------------
        let wnd_before = self.snd_wnd;
        self.update_send_window(seg, prior_una);

        // ---- ECN-Echo (RFC 3168 §6.1.2): reduce once per window, never
        // retransmit — nothing was lost. As in Linux, also when this ACK
        // drained the flight: the mark was still for data we sent.
        if ece && self.cc.state() == CaState::Open && prior_flight > 0 {
            self.cc.enter_cwr(self.snd_nxt, mss, self.snd_wnd);
            self.send_cwr_pending = true;
        }

        // ---- Loss detection --------------------------------------------
        // RACK whenever SACK is negotiated. Duplicate ACKs that carry no SACK
        // blocks at all (non-SACK peer, or blocks stripped by a middlebox)
        // fall back to RFC 6675 DupThresh / RFC 6582 NewReno. Not when this
        // ACK showed a hole filled by a delayed original while
        // retransmissions are still out (Linux `tcp_try_undo_partial`):
        // reordering is deeper than assumed, so nothing more is marked lost.
        let mut newly_lost = self.sack_enabled && !hold_detection && self.rack_detect();
        if !sack_present && !hold_detection {
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
            self.enter_fast_recovery();
        }

        // ---- Tail loss probe outcome (RFC 8985 §7.4.2) -----------------
        // Linux's "pure dupack": nothing acknowledged or newly SACKed, no
        // data, no FIN, no window change.
        let pure_dupack = acked == 0
            && delivered == 0
            && seg.payload.is_empty()
            && !seg.has(flags::FIN)
            && self.snd_wnd == wnd_before;
        self.tlp_on_ack(ack, dsack, pure_dupack);

        // ---- Congestion control ----------------------------------------
        if self.cc.maybe_exit(self.snd_una) {
            self.rack.on_recovery_exit();
        }
        if !self.retx_outstanding() {
            self.cc.on_retransmissions_settled();
        }
        let limited = self.cwnd_is_limited();
        if self.cc.in_reduction() {
            let pipe = self.pipe();
            self.cc
                .prr_update(delivered, pipe, mss, acked > 0 && !newly_lost);
        } else {
            self.cc.on_ack(delivered, mss, limited);
        }

        // ---- Timers (RFC 6298 §5.2/5.3) ---------------------------------
        // Linux `tcp_check_sack_reneging`: the cumulative ACK stopped at a
        // segment the receiver had SACKed, so it dropped out-of-order data
        // it reported. Give it max(SRTT/2, 10 ms) to fill the hole before
        // the timeout forgets the SACK state and resends (not a whole RTO).
        let reneged = acked > 0 && self.rtx.get(0).is_some_and(|s| s.has(seg_flags::SACKED));
        if self.snd_una == self.snd_nxt {
            self.rto_deadline = Deadline::OFF;
            self.tlp_deadline = Deadline::OFF;
            self.rack_deadline = Deadline::OFF;
        } else if reneged {
            let grace = u64::from(self.srtt_ms / 2).max(10);
            self.rto_deadline = Deadline::at(self.now_ms.saturating_add(grace));
        } else if acked > 0 {
            self.arm_rto();
        }
        // Only an ACK of new data restarts the probe timer (Linux
        // `FLAG_SET_XMIT_TIMER`): duplicate ACKs, window updates and the
        // peer's data must not keep pushing a pending probe back to the RTO.
        let prior_tlp = self.tlp_deadline;
        self.maybe_arm_tlp();
        if acked == 0 {
            if let (Some(p), Some(n)) = (prior_tlp.get(), self.tlp_deadline.get()) {
                self.tlp_deadline = Deadline::at(p.min(n));
            }
        }

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

    /// A path-MTU probe that arrived (cumulatively ACKed, or SACKed, without
    /// ever being retransmitted) proves the larger size: raise the cap one
    /// step, and keep probing until the pre-clamp size is restored.
    fn pmtu_probe_on_ack(&mut self) {
        if !self.pmtu_probe_inflight {
            return;
        }
        let delivered = seq_ge(self.snd_una, self.pmtu_probe_end)
            || self
                .rtx
                .find(self.pmtu_probe_start)
                .and_then(|i| self.rtx.get(i))
                .is_some_and(|s| s.has(seg_flags::SACKED));
        if !delivered {
            return;
        }
        self.pmtu_probe_inflight = false;
        self.pmtu_mss = self.pmtu_mss.max(self.pmtu_probe_mss);
        if self.pmtu_mss >= self.pmtu_restore_mss {
            self.pmtu_restore_mss = 0;
        } else {
            self.pmtu_probe_at = self.now_ms;
        }
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

    /// Linux `tcp_dsack_seen`: believe a D-SACK only if it is non-empty,
    /// within what we sent, at most MAX.SND.WND long, and (cumulatively)
    /// reports no more duplicate segments than we retransmitted. A forged
    /// or network-duplicated D-SACK then cannot widen RACK's reordering
    /// window or undo a congestion response.
    fn dsack_valid(&mut self, l: u32, r: u32, mss: u32) -> bool {
        let max_wnd = self.max_snd_wnd.max(u32::from(self.local_mss));
        let len = r.wrapping_sub(l);
        if !seq_lt(l, r) || seq_gt(r, self.snd_nxt) || len > max_wnd {
            return false;
        }
        let segs = u64::from(len.div_ceil(mss.max(1)));
        let total = self.dsack_segs.saturating_add(segs);
        if total > self.stats.segs_retrans {
            return false;
        }
        self.dsack_segs = total;
        true
    }

    /// Undo a loss episode an ACK that advanced `SND.UNA` shows was
    /// spurious: Linux `tcp_packet_delayed` (see
    /// [`crate::congestion::Reno::packet_delayed`]) with Linux's response
    /// (`tcp_try_undo_partial`, `tcp_try_undo_recovery`,
    /// `tcp_try_undo_loss`). An original transmission filled the hole: it
    /// was delayed, not lost. From receivers that send no D-SACK (smoltcp,
    /// for one) this is the only evidence of a spurious episode. In fast
    /// recovery it proves reordering (RACK then allows its reordering
    /// window, which, as in Linux, only D-SACKs widen), and the reduction
    /// is undone once no retransmission is left in flight (any may still be
    /// repairing a real loss) or the episode ends with this ACK; until then
    /// returns `true`: mark nothing more lost on this ACK. A spurious
    /// timeout is undone at once.
    fn try_undo_delayed(&mut self, tsecr_ms: Option<u32>) -> bool {
        if !self
            .cc
            .packet_delayed(tsecr_ms, self.snd_una, self.sack_enabled)
        {
            return false;
        }
        if self.cc.state() == CaState::Recovery {
            self.rack.reordering_seen = true;
            if self.rtx.retrans_bytes() > 0 && seq_lt(self.snd_una, self.cc.recovery_point()) {
                return true;
            }
        }
        self.cc.undo();
        self.rtx.unmark_lost();
        false
    }

    /// Linux `tcp_any_retrans_done`: a retransmission is in flight, or the
    /// segment at `SND.UNA` was retransmitted, so an earlier retransmission
    /// may still fill a hole in a loss episode starting now.
    pub(super) fn retx_outstanding(&self) -> bool {
        self.rtx.retrans_bytes() > 0
            || self
                .rtx
                .get(0)
                .is_some_and(|s| s.has(seg_flags::EVER_RETRANS))
    }

    /// What a loss episode starting now inherits (Linux `tcp_init_undo`):
    /// `retrans_in_flight` retransmissions still in flight plus an
    /// unresolved tail-loss-probe retransmission.
    pub(super) fn undo_seed(&self, retrans_in_flight: u32) -> UndoSeed {
        let probe = self.tlp_end_seq.is_some() && self.tlp_is_retrans;
        UndoSeed {
            retx_outstanding: self.retx_outstanding(),
            retrans_in_flight: retrans_in_flight.saturating_add(u32::from(probe)),
        }
    }

    /// RFC 8985 §7.2 / Linux `tcp_schedule_loss_probe`: probes run while
    /// Open or reducing for ECN (CWR), never in loss recovery.
    pub(super) fn tlp_state_ok(&self) -> bool {
        matches!(self.cc.state(), CaState::Open | CaState::Cwr)
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

    /// Start fast recovery.
    pub(super) fn enter_fast_recovery(&mut self) {
        let mss = self.mss_payload();
        if self.cc.state() == CaState::Cwr {
            self.cc.cwr_to_recovery();
        } else {
            let seed = self.undo_seed(self.rtx.retrans_segs());
            self.cc
                .enter_recovery(self.snd_una, self.snd_nxt, mss, seed, self.snd_wnd);
        }
        self.stats.fast_recoveries = self.stats.fast_recoveries.saturating_add(1);
        self.tlp_end_seq = None;
        self.tlp_deadline = Deadline::OFF;
    }

    /// RFC 8985 §7.4.2 `TLP_process_ack` (Linux `tcp_process_tlp_ack`).
    fn tlp_on_ack(&mut self, ack: u32, dsack: Option<(u32, u32)>, pure_dupack: bool) {
        let Some(end) = self.tlp_end_seq else {
            return;
        };
        if !seq_ge(ack, end) {
            return;
        }
        if !self.tlp_is_retrans {
            self.tlp_end_seq = None; // a probe of new data was delivered
        } else if dsack.is_some_and(|(_, r)| r == end) {
            self.tlp_end_seq = None; // original and probe both arrived
        } else if seq_gt(ack, end) {
            // The probe repaired a lost tail: one congestion response.
            self.tlp_end_seq = None;
            if self.cc.state() == CaState::Open {
                let mss = self.mss_payload();
                let w = self.cc.cwnd.min(self.snd_wnd);
                self.cc.ssthresh = (w / 2).max(mss.saturating_mul(2));
                self.cc.cwnd = self.cc.ssthresh;
            }
        } else if pure_dupack {
            // A plain duplicate ACK at the probe's end: a receiver without
            // D-SACK saw both copies, so nothing was lost (case 2).
            self.tlp_end_seq = None;
        }
    }

    /// Arm the tail loss probe (RFC 8985 §7.2) when data is outstanding, the
    /// connection is not recovering, and the PTO would fire before the RTO.
    pub(super) fn maybe_arm_tlp(&mut self) {
        let eligible = self.sack_enabled
            && self.tlp_state_ok()
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
