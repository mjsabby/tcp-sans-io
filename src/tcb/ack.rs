//! Acknowledgment processing and loss recovery.
//!
//! Per ACK: validate (RFC 9293 + RFC 5961 §5), absorb SACK blocks (D-SACK
//! per RFC 2883 is detected, validated, and *never* treated as loss), apply
//! the cumulative ACK, take an RTT sample (our send times; TSecr only when
//! retransmitted data is acknowledged), undo a loss episode the D-SACKs,
//! the timestamp echo or F-RTO show was spurious, update the send window,
//! run loss detection (RACK with SACK, RFC 6582 NewReno without), then let
//! congestion control react: PRR during a reduction, slow start /
//! congestion avoidance otherwise.

use super::{
    seq_ge, seq_gt, seq_le, seq_lt, Deadline, Tcb, PMTU_PROBE_MAX_MS, TLP_MIN_PTO_MS,
    TLP_WC_DELACK_MS,
};
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
        // Closed in SYN-RECEIVED, our SYN unacknowledged: as in SYN-RECEIVED
        // itself (Linux `tcp_check_req`), an ACK must cover the SYN; one
        // at ISS acknowledges nothing the peer can have seen.
        if self.syn_unacked {
            return seq_gt(ack, self.iss) && !seq_gt(ack, self.snd_nxt);
        }
        let max_wnd = self.max_snd_wnd.max(u32::from(self.local_mss));
        let back = u32::try_from(self.snd_acked).map_or(max_wnd, |a| a.min(max_wnd));
        !seq_gt(ack, self.snd_nxt) && !seq_lt(ack, self.snd_una.wrapping_sub(back))
    }

    /// Process the ACK field of a segment that passed [`Self::ack_acceptable`].
    pub(super) fn process_ack(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        let ack = seg.ack;
        self.frto_new = false;
        self.frto_hold = false;
        // An ACK older than SND.UNA (reordered behind a newer one) is news
        // only for its SACK and D-SACK blocks (Linux `tcp_ack` old_ack).
        let old_ack = seq_lt(ack, self.snd_una);
        if old_ack && (!self.sack_enabled || seg.options.sack.is_empty()) {
            return Ok(());
        }
        // The peer answers, so persist probes start over (Linux
        // `icsk_probes_out`). The retransmission count, which black-hole
        // detection also reads, restarts only on an ACK of new data: reverse
        // traffic proves the path in one direction only.
        if !old_ack {
            self.probes_out = 0;
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
        // F-RTO's test (Linux `FLAG_ORIG_SACK_ACKED`): data sent before the
        // timeout and never retransmitted is (S)ACKed by this ACK.
        let frto_hi = self
            .cc
            .frto_undo_possible()
            .then(|| self.cc.recovery_point());
        let frto_orig = |s: &crate::rtx_queue::Seg| {
            frto_hi.is_some_and(|hi| !s.has(seg_flags::EVER_RETRANS) && seq_le(s.end, hi))
        };
        let mut orig_acked = false;
        // ECN-Echo during a loss episode: the reduction stands, whatever
        // undo may follow (Linux `tcp_fastretrans_alert`).
        let ece = !old_ack && self.ecn_enabled && seg.has(flags::ECE);
        if ece && self.cc.in_loss_recovery() {
            self.cc.keep_reduction();
        }

        // ---- SACK / D-SACK (RFC 2018, RFC 2883) ------------------------
        let mut dsack: Option<(u32, u32)> = None;
        let mut sack_present = false;
        // Send times (oldest, newest) of newly SACKed segments never resent:
        // RTT samples (Linux `tcp_sacktag_one` `first_sackt`/`last_sackt`).
        let mut sack_ts: Option<(u64, u64)> = None;
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
                    // `FLAG_DSACK_TLP`). Nor does a duplicate of what the
                    // retransmission timer resent: a spurious timeout shows
                    // a delay, and must not leave RACK waiting out a
                    // reordering window for every later loss (Linux, which
                    // learns reordering from SACKs alone, never lets such a
                    // D-SACK widen it before reordering is seen).
                    let tlp_dsack = self.tlp_end_seq == Some(r0) && r0.wrapping_sub(l0) <= mss;
                    let rto_dsack = self
                        .rto_span
                        .is_some_and(|(lo, hi)| seq_ge(l0, lo) && seq_le(r0, hi));
                    if !tlp_dsack && !rto_dsack {
                        self.rack.on_dsack(self.snd_una, self.snd_nxt);
                    }
                    let before = self.cc.ssthresh;
                    let resent = self.dsack_resent_segs(l0, r0, ack, mss);
                    if self.cc.on_dsack_segs(l0, r0, resent) {
                        // Spurious episode: restore the window (done) and drop
                        // loss marks that were never acted on.
                        self.withdraw_cwr(before);
                        self.unmark_lost();
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
                    let n = rtx.sack(l, r, mss, |s| {
                        rack.on_delivered(s, now, None, true);
                        orig_acked |= frto_orig(s);
                        if !s.has(seg_flags::EVER_RETRANS) {
                            let (o, n) = sack_ts.unwrap_or((s.xmit_ts, s.xmit_ts));
                            sack_ts = Some((o.min(s.xmit_ts), n.max(s.xmit_ts)));
                        }
                    });
                    delivered = delivered.saturating_add(n);
                }
            }
        }
        // Linux `FLAG_DATA_SACKED`: this ACK SACKed data not SACKed before.
        let newly_sacked = delivered > 0;
        if old_ack {
            // Linux `tcp_fastretrans_alert` for an old ACK: loss detection
            // and recovery on what it SACKed; nothing else in it is current.
            if self.cc.frto_undo_possible() {
                self.frto_on_ack(orig_acked, newly_sacked, false, false);
            }
            if core::mem::take(&mut self.rack.advanced) {
                self.rack_detect();
            }
            if self.rtx.unresent_lost_bytes() > 0 && !self.cc.in_loss_recovery() {
                self.enter_fast_recovery();
            }
            if self.cc.in_reduction() {
                let pipe = self.pipe();
                self.cc.prr_update(delivered, pipe, mss, false);
            }
            return Ok(());
        }

        // ---- Cumulative ACK --------------------------------------------
        let acked = ack.wrapping_sub(prior_una);
        let mut hold_detection = false;
        // Linux `FLAG_DATA_ACKED`: this ACK acknowledged data (not just our
        // SYN).
        let mut data_acked_any = false;
        let sack_rtt = sack_ts.and_then(|(o, n)| {
            let oldest = u32::try_from(now.saturating_sub(o)).ok()?;
            let newest = u32::try_from(now.saturating_sub(n)).ok()?;
            Some((oldest, newest))
        });
        if acked > 0 {
            self.rtx_count = 0;
            let syn_acked = self.syn_outstanding();
            data_acked_any = acked > u32::from(syn_acked);
            if syn_acked {
                self.complete_closed_handshake(seg);
            }
            let fin_acked =
                self.fin_sent && seq_le(prior_una, self.fin_seq) && seq_gt(ack, self.fin_seq);
            let sacked_before = self.rtx.sacked_bytes();
            // Send times of the newly acknowledged segments, for the RTT.
            let mut oldest_ts: Option<u64> = None;
            let mut newest_ts = 0u64;
            let mut retrans_acked = false;
            let mut segs_acked = 0u32;
            {
                let rack = &mut self.rack;
                self.rtx.ack_to(ack, |s, newly| {
                    if newly {
                        rack.on_delivered(s, now, tsecr_ms, false);
                        newest_ts = newest_ts.max(s.xmit_ts);
                        segs_acked += 1;
                        orig_acked |= frto_orig(s);
                        if s.has(seg_flags::EVER_RETRANS) {
                            retrans_acked = true;
                        } else {
                            oldest_ts = Some(oldest_ts.map_or(s.xmit_ts, |k| k.min(s.xmit_ts)));
                        }
                    }
                });
            }
            // Without SACK, an ACK that also covers a resend cannot show an
            // original got through before the timeout: the receiver may have
            // held it out of order (Linux `tcp_clean_rtx_queue`).
            if retrans_acked && !self.sack_enabled {
                orig_acked = false;
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
            // middleboxes control TSecr. Without retransmissions SRTT times
            // the oldest newly ACKed segment (what an RFC 7323 echo
            // reports) and `min_rtt` the newest (Linux `ca_rtt_us`), which
            // the receiver did not hold back waiting for more. A SACK of
            // data never resent times them too: SRTT when the cumulative
            // ACK cannot, `min_rtt` always (Linux `tcp_clean_rtx_queue`,
            // `tcp_ack_update_rtt`). Otherwise Karn's rule rules out send
            // times and TSecr (RTTM) names the transmission that arrived;
            // it is believed only if neither later than the newest
            // transmission this ACK covers nor earlier than the
            // connection's first segment (as the handshake checks): the
            // peer controls TSecr.
            let ack_rtt = oldest_ts.filter(|_| !retrans_acked).and_then(|x| {
                let oldest = u32::try_from(now.saturating_sub(x)).ok()?;
                let newest = u32::try_from(now.saturating_sub(newest_ts)).ok()?;
                Some((oldest, newest))
            });
            let sample = match (ack_rtt, sack_rtt) {
                (Some((r, _)), Some((_, ca))) => Some((r, ca)),
                (Some(s), None) | (None, Some(s)) => Some(s),
                (None, None) if retrans_acked => tsecr_ms
                    .filter(|&t| !seq_gt(t, newest_ts as u32))
                    .map(|t| (now as u32).wrapping_sub(t))
                    // Echoed no earlier than our first segment, in host
                    // time: a 32-bit comparison fails after 2^31 ms.
                    .filter(|&r| {
                        now.checked_sub(u64::from(r))
                            .is_some_and(|sent| sent >= self.syn_xmit_ms)
                    })
                    .map(|r| (r, r)),
                (None, None) => None,
            };
            if let Some((r, ca)) = sample {
                if r < 60_000 {
                    // A lone runt and nothing else to report was probably
                    // ACKed late (Linux `FLAG_ACK_MAYBE_DELAYED`): it may
                    // lower `min_rtt`, not raise it.
                    let maybe_delayed = segs_acked == 1
                        && data_acked < mss
                        && sacked_before == 0
                        && !sack_present
                        && !ece
                        && !syn_acked;
                    let ca = Some(ca).filter(|&c| {
                        !maybe_delayed || self.rack.min_rtt.get().is_none_or(|m| c <= m)
                    });
                    self.update_rtt(r, ca);
                }
            }
            self.note_progress(data_acked.saturating_add(u32::from(fin_acked)));
            hold_detection = self.try_undo_delayed(tsecr_ms);
        } else if let Some((r, ca)) = sack_rtt.filter(|&(r, _)| r < 60_000) {
            self.update_rtt(r, Some(ca));
        }
        self.pmtu_probe_on_ack();

        // ---- Send window (RFC 9293 §3.10.7.4, hardened) -----------------
        let wnd_before = self.snd_wnd;
        self.update_send_window(seg, prior_una);

        // ---- F-RTO, with the window this ACK opened (Linux
        // `tcp_process_loss` runs after `tcp_ack_update_window`).
        if self.cc.frto_undo_possible() {
            let dupack = acked == 0
                && seg.payload.is_empty()
                && !seg.has(flags::FIN)
                && self.snd_wnd == wnd_before
                && dsack.is_none();
            self.frto_on_ack(orig_acked, newly_sacked, dupack, acked > 0);
        }

        // ---- Tail loss probe outcome (RFC 8985 §7.4.2), before this ACK's
        // loss detection (Linux `tcp_process_tlp_ack` precedes
        // `tcp_fastretrans_alert`): a probe it shows delivered must not
        // count among the retransmissions a recovery it starts waits on to
        // be undone. Linux's "pure dupack": nothing acknowledged or newly
        // SACKed, no data, no FIN, no window change.
        let pure_dupack = acked == 0
            && delivered == 0
            && seg.payload.is_empty()
            && !seg.has(flags::FIN)
            && self.snd_wnd == wnd_before;
        self.tlp_on_ack(ack, dsack, pure_dupack);

        // ---- End of a reduction episode, before this ACK's loss detection
        // (Linux `tcp_fastretrans_alert` checks exit before it processes
        // the state): a loss it finds beyond the recovery point, or an
        // ECN-Echo, starts a new episode with its own reduction. Only a
        // loss episode wears down a widened reordering window.
        let loss_episode = self.cc.in_loss_recovery();
        if self.cc.maybe_exit(self.snd_una) && loss_episode {
            self.rack.on_recovery_exit();
        }
        // Linux `tcp_reset_reno_sack`: without SACK, duplicate ACKs counted
        // outside fast recovery are spent once SND.UNA moves, and all of
        // them when recovery ends (in recovery, each segment a partial ACK
        // covers beyond the first eats one, above).
        if acked > 0 && self.cc.state() != CaState::Recovery {
            self.reno_sacked = 0;
        }

        // ---- ECN-Echo (RFC 3168 §6.1.2): reduce once per window, never
        // retransmit — nothing was lost. As in Linux, also when this ACK
        // drained the flight: the mark was still for data we sent.
        if ece && self.cc.state() == CaState::Open && prior_flight > 0 {
            self.cc.enter_cwr(self.snd_nxt, mss, self.max_snd_wnd);
            self.queue_cwr();
        }

        // ---- Loss detection --------------------------------------------
        // RACK whenever SACK is negotiated, if this ACK delivered something
        // (Linux `tcp_rack_mark_lost`: otherwise nothing new can be lost
        // before the reordering timer, which stays armed); RFC 6675
        // DupThresh / RFC 6582 NewReno otherwise (Linux `tcp_is_reno`). A
        // duplicate ACK without SACK blocks on a SACK connection counts for
        // nothing: it would override RACK's reordering window. Not when
        // this ACK showed a hole filled by a delayed original while
        // retransmissions are still out (Linux `tcp_try_undo_partial`):
        // reordering is deeper than assumed, so nothing more is marked lost.
        let mut newly_lost = self.sack_enabled
            && !hold_detection
            && core::mem::take(&mut self.rack.advanced)
            && self.rack_detect();
        let mut dup = false;
        if !self.sack_enabled && !hold_detection {
            let (lost, is_dup) = self.newreno_detect(seg, acked, wnd_before);
            newly_lost |= lost;
            dup = is_dup;
        }
        // Linux `tcp_add_reno_sack` / `tcp_limit_reno_sacked`: a duplicate
        // ACK vouches for one more segment received, but never for the
        // holes (at least one segment) still outstanding.
        let outstanding = self.snd_nxt.wrapping_sub(self.data_una());
        let reno_limit = outstanding.saturating_sub(self.rtx.lost_bytes().max(mss));
        if dup && self.reno_sacked.saturating_add(mss) <= reno_limit {
            self.reno_sacked += mss;
            delivered = delivered.saturating_add(mss);
        }
        self.reno_sacked = self.reno_sacked.min(reno_limit);
        // Only a segment still awaiting its resend starts recovery: after an
        // undo, resends in flight keep their loss marks here (Linux clears
        // them, `tcp_undo_cwnd_reduction`), and must not restart it.
        if self.rtx.unresent_lost_bytes() > 0 && !self.cc.in_loss_recovery() {
            self.enter_fast_recovery();
        }

        // ---- Congestion control ----------------------------------------
        if !self.retx_outstanding() {
            self.cc.on_retransmissions_settled();
        }
        let limited = self.cwnd_is_limited();
        if self.cc.in_reduction() {
            let pipe = self.pipe();
            self.cc
                .prr_update(delivered, pipe, mss, acked > 0 && !newly_lost);
        } else if data_acked_any || (self.rack.reordering_seen && newly_sacked) {
            // RFC 5681 §3.1 / Linux `tcp_may_raise_cwnd`: only an ACK of
            // new data raises cwnd; SACKs (and duplicate ACKs) alone, only
            // once reordering has been seen (`FLAG_FORWARD_PROGRESS`). A
            // window that is overflowing a queue does not keep growing
            // while RACK waits out its reordering window.
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
            // The grace is the RTO's; no probe may take its place (Linux
            // clears `FLAG_SET_XMIT_TIMER`).
            self.tlp_deadline = Deadline::OFF;
        } else if acked > 0 {
            self.arm_rto();
        }
        // Only an ACK of new data restarts the probe timer (Linux
        // `FLAG_SET_XMIT_TIMER`): duplicate ACKs, window updates and the
        // peer's data must not keep pushing a pending probe back to the RTO.
        if !reneged {
            let prior_tlp = self.tlp_deadline;
            self.maybe_arm_tlp();
            if acked == 0 {
                if let (Some(p), Some(n)) = (prior_tlp.get(), self.tlp_deadline.get()) {
                    self.tlp_deadline = Deadline::at(p.min(n));
                }
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
        // A SACK proves the larger size only if it covers the whole probe:
        // a block for part of it means the probe did not arrive as sent.
        let delivered = seq_ge(self.snd_una, self.pmtu_probe_end)
            || self
                .rtx
                .find(self.pmtu_probe_start)
                .and_then(|i| self.rtx.get(i))
                .is_some_and(|s| s.has(seg_flags::SACKED) && seq_ge(s.end, self.pmtu_probe_end));
        if !delivered {
            return;
        }
        self.pmtu_probe_inflight = false;
        self.pmtu_mss = self.pmtu_mss.max(self.pmtu_probe_mss);
        if self.pmtu_mss < self.pmtu_restore_mss {
            self.pmtu_probe_at = self.now_ms;
        } else if self.pmtu_mss < self.local_mss {
            // Restored only to a size a later report capped the search at
            // (reports can arrive out of order, or be forged): try the full
            // size again in 10 minutes, as Linux re-probes
            // (`tcp_mtu_check_reprobe`) and a learned route MTU expires.
            self.pmtu_restore_mss = self.local_mss;
            self.pmtu_probe_backoff_ms = PMTU_PROBE_MAX_MS;
            self.pmtu_probe_at = self.now_ms.saturating_add(u64::from(PMTU_PROBE_MAX_MS));
        } else {
            self.pmtu_restore_mss = 0;
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
        let wnd = self.scale_peer_window(seg.window);
        // Linux `tcp_may_update_window`: an ACK that advances SND.UNA, a
        // newer segment, or, at the same sequence number, a wider or a zero
        // window. An older ACK reordered within one timestamp tick (PAWS
        // cannot tell) may not shrink the window.
        let fresh = seq_gt(seg.ack, prior_una)
            || seq_lt(self.snd_wl1, seq)
            || (self.snd_wl1 == seq && (wnd > self.snd_wnd || wnd == 0));
        if !fresh {
            return;
        }
        self.snd_wnd = wnd;
        self.snd_wl1 = seq;
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
        // Nor below what was sent and acknowledged (the bound an ACK has,
        // see `ack_acceptable`): data never sent cannot arrive twice.
        let back =
            u32::try_from(self.snd_acked.saturating_sub(1)).map_or(max_wnd, |a| a.min(max_wnd));
        if seq_lt(l, self.snd_una.wrapping_sub(back)) {
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

    /// The needless retransmissions a valid D-SACK `[l, r)` shows, for the
    /// undo count. Of data still queued, only segments we resent count
    /// (Linux `tcp_sacktag_one`): a duplicate of one sent once (the network
    /// copied it, or the peer forged the block) says nothing of our
    /// retransmissions. Of data acknowledged before this ACK, each MSS
    /// counts (Linux `tcp_check_dsack`), as nothing records what was resent
    /// there. A block straddling the cumulative ACK counts for nothing
    /// (`tcp_is_sackblock_valid`).
    fn dsack_resent_segs(&self, l: u32, r: u32, ack: u32, mss: u32) -> u32 {
        if seq_le(r, self.snd_una) {
            return r.wrapping_sub(l).div_ceil(mss.max(1)).max(1);
        }
        if seq_lt(l, ack) && seq_gt(r, ack) {
            return 0;
        }
        let from = if seq_lt(l, self.snd_una) {
            self.snd_una
        } else {
            l
        };
        let mut n = 0u32;
        let mut i = self.rtx.find(from);
        while let Some(s) = i.and_then(|i| self.rtx.get(i)) {
            if !seq_lt(s.start, r) {
                break;
            }
            if s.has(seg_flags::EVER_RETRANS) {
                n = n.saturating_add(1);
            }
            i = i.map(|i| i + 1);
        }
        n
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
        let before = self.cc.ssthresh;
        self.cc.undo();
        self.withdraw_cwr(before);
        self.unmark_lost();
        false
    }

    /// A window reduction began: tell an ECN peer, so it stops echoing the
    /// marks this reduction answers (Linux `tcp_ecn_queue_cwr`, on every
    /// reduction). Otherwise a stale ECN-Echo arriving once the episode
    /// ended would reduce again.
    pub(super) fn queue_cwr(&mut self) {
        if self.ecn_enabled {
            self.send_cwr_pending = true;
        }
    }

    /// An undo drops the loss marks: RACK judges what is still outstanding
    /// afresh on the next ACK, whether or not it delivers anything (Linux
    /// `tcp_undo_cwnd_reduction`: "Force RACK to re-exam losses").
    fn unmark_lost(&mut self) {
        self.rtx.unmark_lost();
        self.rack.advanced = true;
    }

    /// An undo restored `ssthresh` from `before`: withdraw a CWR not yet
    /// sent for the reduction it reverted (Linux `tcp_ecn_withdraw_cwr`),
    /// so marks it did not answer are still echoed.
    fn withdraw_cwr(&mut self, before: u32) {
        if self.cc.ssthresh > before {
            self.send_cwr_pending = false;
        }
    }

    /// F-RTO (RFC 5682 §3.1, the SACK-enhanced algorithm, which Linux
    /// `tcp_process_loss` runs for every connection) on an ACK in a
    /// timeout's Loss state. `orig_acked`: data sent before the timeout and
    /// never resent was (S)ACKed (Linux `FLAG_ORIG_SACK_ACKED`);
    /// `newly_sacked`, `dupack`, `una_advanced`: Linux `FLAG_DATA_SACKED`,
    /// `num_dupack`, `FLAG_SND_UNA_ADVANCED`. Only after a timeout, so out
    /// of the per-ACK path.
    #[cold]
    fn frto_on_ack(
        &mut self,
        orig_acked: bool,
        newly_sacked: bool,
        dupack: bool,
        una_advanced: bool,
    ) {
        if !self.cc.frto_undo_possible() {
            return;
        }
        // Step 3.b: not everything was lost, so the timeout was spurious
        // (`tcp_try_undo_loss(sk, true)`: no D-SACK or timestamp needed).
        // Timestamps catch most spurious timeouts, but not an ACK outage:
        // the D-SACKs for the resends were lost with the ACKs, and the
        // first ACK through echoes a resend.
        if orig_acked {
            let before = self.cc.ssthresh;
            self.cc.undo();
            self.withdraw_cwr(before);
            self.unmark_lost();
            self.rtx_count = 0;
            return;
        }
        let hi = self.cc.recovery_point();
        if seq_gt(self.snd_nxt, hi) {
            // Step 3.a: the receiver reported the new data step 2.b sent
            // out of order, or a duplicate ACK came: the loss was real.
            if newly_sacked || dupack {
                self.cc.frto_off();
            }
        } else if una_advanced && seq_lt(self.snd_una, hi) {
            // Step 2.b: the resend got through, not everything after it.
            // Send new data instead of the next presumed-lost segment, so
            // the next ACK tells: an original (S)ACKed means spurious, the
            // new data reported out of order means real. Nothing new to
            // send: conventional recovery.
            if (self.unsent_bytes() > 0 || self.fin_owed()) && self.usable_window() > 0 {
                self.frto_new = true;
            } else {
                self.cc.frto_off();
            }
        }
    }

    /// Linux `tcp_any_retrans_done`: a retransmission is in flight, or the
    /// segment at `SND.UNA` was retransmitted, so an earlier retransmission
    /// may still fill a hole in a loss episode starting now. An unresolved
    /// tail loss probe counts too: it re-sent the tail, not the head, and
    /// an ACK echoing it must not pass for an original's.
    pub(super) fn retx_outstanding(&self) -> bool {
        self.rtx.retrans_bytes() > 0
            || (self.tlp_end_seq.is_some() && self.tlp_is_retrans)
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
    /// Open or reducing for ECN (CWR), never in loss recovery, nor before
    /// the handshake completes (a FIN sent from SYN-RECEIVED: the SYN-ACK's
    /// timer owns it, as Linux skips probes on a Fast Open socket then).
    pub(super) fn tlp_state_ok(&self) -> bool {
        matches!(self.cc.state(), CaState::Open | CaState::Cwr) && !self.syn_unacked
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
            Some(t) => {
                // RFC 8985 §8: the reordering timer replaces a pending
                // probe (Linux arms both on one timer), which would resend
                // the tail while RACK waits out the hole the SACKs show.
                self.tlp_deadline = Deadline::OFF;
                Deadline::at(self.now_ms.saturating_add(t))
            }
            None => Deadline::OFF,
        };
        marked
    }

    /// RFC 6582 NewReno / RFC 6675 DupThresh loss marking when SACK was not
    /// negotiated. Returns `(newly_lost, was_duplicate_ack)`.
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
        if self.cc.state() == CaState::Recovery && seq_lt(self.snd_una, self.cc.recovery_point()) {
            self.rtx.mark_lost(0);
            return (true, false);
        }
        (false, false)
    }

    /// Start fast recovery — unless the loss is a path-MTU probe that did
    /// not get through (Linux `tcp_fastretrans_alert`: "MTU probe failure:
    /// don't reduce cwnd"): its size, not congestion, lost it.
    pub(super) fn enter_fast_recovery(&mut self) {
        if self.pmtu_probe_inflight
            && self.cc.state() == CaState::Open
            && self.snd_una == self.pmtu_probe_start
        {
            self.pmtu_probe_failed();
            self.simple_retransmit();
            return;
        }
        let mss = self.mss_payload();
        if self.cc.state() == CaState::Cwr {
            self.cc.cwr_to_recovery(self.snd_nxt);
        } else {
            let seed = self.undo_seed(self.rtx.retrans_segs());
            self.cc
                .enter_recovery(self.snd_una, self.snd_nxt, mss, seed, self.max_snd_wnd);
            self.queue_cwr();
        }
        self.stats.fast_recoveries = self.stats.fast_recoveries.saturating_add(1);
        self.tlp_end_seq = None;
        self.tlp_deadline = Deadline::OFF;
    }

    /// Linux `tcp_simple_retransmit`: segments larger than the path now
    /// carries were dropped for their size. Mark them lost and let them go
    /// out again, split to fit, in a Loss episode that keeps the window
    /// (see [`crate::congestion::Reno::enter_simple_loss`]).
    pub(super) fn simple_retransmit(&mut self) {
        let limit = self.mss_payload();
        for i in 0..self.rtx.len() {
            if self.rtx.get(i).is_some_and(|s| s.payload_len() > limit) {
                self.rtx.mark_lost(i);
            }
        }
        if self.rtx.lost_bytes() == 0 {
            return;
        }
        self.cc.enter_simple_loss(self.snd_nxt);
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
                self.cc.on_tlp_repair(self.mss_payload(), self.max_snd_wnd);
                self.queue_cwr();
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
            && !self.rack_deadline.is_armed()
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
