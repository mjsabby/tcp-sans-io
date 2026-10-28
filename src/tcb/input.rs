//! Inbound segment processing (RFC 9293 §3.10.7), per state.
//!
//! Synchronized states follow the RFC's check order: sequence
//! acceptability (+ PAWS), RST (RFC 5961 §3), SYN (RFC 5961 §4), the ACK
//! bit (segments without ACK are dropped), ACK acceptability (RFC 5961 §5 —
//! checked before the segment may update any state), ACK processing (see
//! [`super::ack`]), segment text, FIN. As in Linux, a segment with none of
//! ACK, SYN and RST is dropped before all of that. Responses to
//! unacceptable or suspicious segments are rate limited per connection,
//! except an immediate ACK to data or a FIN that could be the peer's own
//! retransmission (see `may_answer_at_once`).

use super::{
    seq_ge, seq_gt, seq_in_range, seq_le, seq_lt, Deadline, Endpoint, HeldFin, Tcb, DELAYED_ACK_MS,
    MIN_PEER_MSS, PAWS_IDLE_MS, TIME_WAIT_MAX_MS, TIME_WAIT_MS,
};
use crate::congestion::{self, Reno};
use crate::error::TcpError;
use crate::ooo::Insert;
use crate::state::State;
use crate::wire::{ecn, flags, Segment};

impl<const BUF: usize> Tcb<BUF> {
    pub(super) fn inject_segment(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if seg.dst_ip != self.local.ip || seg.dst_port != self.local.port {
            return Err(TcpError::NotForUs);
        }
        let from_remote = seg.src_ip == self.remote.ip && seg.src_port == self.remote.port;
        if self.state != State::Listen && !from_remote {
            if self.may_replace_half_open(seg) {
                self.reset_to_listen_or_closed();
            } else {
                return self.on_busy_listener(seg);
            }
        }
        self.stats.segs_in = self.stats.segs_in.saturating_add(1);
        match self.state {
            State::Closed => Err(TcpError::InvalidState),
            State::Listen => self.on_listen(seg),
            State::SynSent => self.on_syn_sent(seg),
            State::SynRcvd => self.on_syn_rcvd(seg),
            State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing
            | State::LastAck
            | State::TimeWait => self.on_synchronized(seg),
        }
    }

    /// A stateful listener holds one half-open at a time. A half-open whose
    /// SYN-ACK already needed a retransmission (its peer did not answer
    /// within an RTO — typically a spoofed source) yields to a SYN from a
    /// new peer, so one spoofed SYN cannot lock the listener for the whole
    /// SYN-ACK retransmit budget.
    fn may_replace_half_open(&self, seg: &Segment<'_>) -> bool {
        self.state == State::SynRcvd
            && self.is_listener
            && seg.has(flags::SYN)
            && !seg.has(flags::ACK)
            && !seg.has(flags::RST)
            && !seg.has(flags::FIN)
            && self.syn_rcvd_retries >= 1
    }

    /// Segment from a peer other than the half-open's, while a listener's
    /// only slot is busy (hybrid SYN cookies). SYNs are answered with a
    /// cookie SYN-ACK, holding no state; a valid cookie ACK proves the peer
    /// receives our packets — which a pending half-open has not yet shown —
    /// so it takes over the slot. Spoofed SYNs therefore cannot lock a
    /// listener out, however fast they arrive.
    fn on_busy_listener(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if self.state != State::SynRcvd || !self.is_listener || !self.cookie_secret_set {
            return Err(TcpError::NotForUs);
        }
        let ctl = seg.has(flags::RST) || seg.has(flags::FIN);
        if seg.has(flags::SYN) && !seg.has(flags::ACK) && !ctl {
            return self.emit_cookie_synack(seg);
        }
        if seg.has(flags::ACK) && !seg.has(flags::SYN) && !seg.has(flags::RST) {
            if let Some(opts) = self.validate_cookie(seg) {
                self.reset_to_listen_or_closed();
                return self.promote_via_cookie(seg, opts);
            }
        }
        Err(TcpError::NotForUs)
    }

    // ---------------------------------------------------------------------
    // LISTEN
    // ---------------------------------------------------------------------

    fn on_listen(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if seg.has(flags::RST) {
            return Ok(());
        }
        if seg.has(flags::ACK) {
            if !seg.has(flags::SYN) {
                // Possibly the third leg of a cookie handshake; otherwise a
                // stray ACK is dropped silently (no reflection target).
                if self.cookie_secret_set {
                    let _ = self.try_promote_via_cookie(seg)?;
                }
                return Ok(());
            }
            // RFC 9293 §3.10.7.2: an ACK in LISTEN draws <SEQ=SEG.ACK><RST>.
            if self.oow_allowed() {
                self.emit_rst_to(seg, seg.ack, 0, flags::RST)?;
            }
            return Ok(());
        }
        if !seg.has(flags::SYN) || seg.has(flags::FIN) {
            return Ok(());
        }
        // The half-open slot is free: hold this handshake statefully, which
        // keeps every option the client offers (cookies cannot carry window
        // scaling or SACK without timestamps).
        self.accept_syn_stateful(seg)
    }

    fn accept_syn_stateful(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        self.reset_connection_state();
        self.remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        self.iss = self.passive_iss(self.remote, seg.seq);
        self.snd_una = self.iss;
        self.snd_acked = 0;
        self.snd_nxt = self.iss;
        self.ts_offset = self.ts_offset_for(self.remote);
        self.absorb_syn_options(seg);
        self.ecn_enabled = seg.has(flags::ECE) && seg.has(flags::CWR);
        self.state = State::SynRcvd;
        self.syn_rcvd_retries = 0;
        self.syn_xmit_ms = self.now_ms;
        let _ = self.emit_synack()?;
        self.snd_nxt = self.iss.wrapping_add(1);
        self.syn_unacked = true;
        self.arm_rto();
        Ok(())
    }

    /// Record the peer's SYN: sequence numbers, window and options.
    fn absorb_syn_options(&mut self, seg: &Segment<'_>) {
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.rcv_adv_edge = self.rcv_nxt;
        self.last_ack_sent = self.rcv_nxt;
        // RFC 7323 §2.3: the window in a SYN is never scaled.
        self.snd_wnd = u32::from(seg.window);
        self.max_snd_wnd = self.snd_wnd;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        if let Some(mss) = seg.options.mss {
            self.peer_mss = mss.max(MIN_PEER_MSS);
        }
        if let Some(ws) = seg.options.wscale {
            self.ws_ok = true;
            self.snd_wscale = ws.min(14);
            self.rcv_wscale = Self::WS;
        } else {
            self.ws_ok = false;
            self.snd_wscale = 0;
            self.rcv_wscale = 0;
        }
        if let Some((tsval, _)) = seg.options.ts {
            self.ts_enabled = true;
            self.ts_recent = tsval;
            self.ts_recent_stamp = self.now_ms;
        }
        self.sack_enabled = seg.options.sack_permitted;
    }

    // ---------------------------------------------------------------------
    // SYN-SENT (RFC 9293 §3.10.7.3)
    // ---------------------------------------------------------------------

    fn on_syn_sent(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        // SND.UNA (= ISS) < SEG.ACK <= SND.NXT
        let ack_ok =
            seg.has(flags::ACK) && seq_gt(seg.ack, self.iss) && seq_le(seg.ack, self.snd_nxt);
        if seg.has(flags::ACK) && !ack_ok {
            // An ACK for something we never sent — typically a stale peer
            // socket on a reused 4-tuple. The RST clears it so our SYN
            // retransmission can succeed.
            if !seg.has(flags::RST) && self.oow_allowed() {
                self.emit_rst_to(seg, seg.ack, 0, flags::RST)?;
            }
            return Ok(());
        }
        if seg.has(flags::RST) {
            if ack_ok {
                self.abort_local(); // connection refused
            }
            return Ok(());
        }
        if !seg.has(flags::SYN) {
            return Ok(());
        }
        if ack_ok {
            self.complete_active_open(seg)
        } else {
            self.simultaneous_open(seg)
        }
    }

    fn complete_active_open(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        self.absorb_syn_options(seg);
        // RFC 3168 §6.1.1: ECN is on iff the SYN-ACK has ECE without CWR.
        self.ecn_enabled = seg.has(flags::ECE) && !seg.has(flags::CWR);
        self.snd_una = seg.ack;
        self.snd_acked = u64::from(seg.ack.wrapping_sub(self.iss));
        self.syn_unacked = false;
        self.rtx_count = 0;
        self.handshake_rtt_sample(seg);
        self.rto_deadline = Deadline::OFF;
        self.state = State::Established;
        self.on_established();
        // Data carried on a SYN-ACK (rare) is not accepted; our ACK of
        // `irs + 1` makes the peer retransmit it.
        self.send_pure_ack()
    }

    /// RFC 9293 §3.10.7.3: a SYN without ACK in SYN-SENT is a simultaneous
    /// open — enter SYN-RECEIVED and answer with a SYN-ACK.
    fn simultaneous_open(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        self.absorb_syn_options(seg);
        self.ecn_enabled = false;
        self.state = State::SynRcvd;
        self.syn_rcvd_retries = 0;
        self.syn_retransmitted = true; // no unambiguous handshake RTT sample
        let _ = self.emit_synack()?;
        self.arm_rto();
        Ok(())
    }

    /// Handshake RTT sample from the SYN's (or SYN-ACK's) own send time.
    /// Only after a retransmission does TSecr decide which one arrived, and
    /// only if it echoes a time between our first SYN and now (Linux checks
    /// the same in SYN-SENT): the peer controls TSecr.
    fn handshake_rtt_sample(&mut self, seg: &Segment<'_>) {
        let sample = if !self.syn_retransmitted {
            u32::try_from(self.now_ms.saturating_sub(self.syn_xmit_ms)).ok()
        } else {
            match (self.ts_enabled, seg.options.ts) {
                (true, Some((_, tsecr))) if tsecr != 0 => {
                    let t = self.tsecr_to_ms(tsecr);
                    let now = self.now_ms as u32;
                    (seq_ge(t, self.syn_xmit_ms as u32) && seq_le(t, now))
                        .then_some(now.wrapping_sub(t))
                }
                _ => None,
            }
        };
        if let Some(r) = sample {
            if r < 60_000 {
                self.update_rtt(r);
            }
        }
    }

    // ---------------------------------------------------------------------
    // SYN-RECEIVED
    // ---------------------------------------------------------------------

    fn on_syn_rcvd(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if seg.has(flags::RST) {
            // RFC 9293 §3.10.7.4 applies RFC 5961 §3.2 here too: a RST
            // outside the window is dropped, only one exactly at RCV.NXT
            // resets, and any other in-window RST draws a (rate-limited)
            // challenge ACK, so a guessed in-window sequence cannot abort
            // the handshake.
            if !self.acceptable(seg.seq, 0) {
                return Ok(()); // blind RST outside the window
            }
            // RFC 5961 §3.2 applies here too: only an exact match resets;
            // any other in-window RST draws a (rate-limited) challenge ACK.
            if seg.seq != self.rcv_nxt {
                return self.send_oow_ack();
            }
            if self.is_listener {
                self.reset_to_listen_or_closed();
            } else {
                self.abort_local(); // active (simultaneous) open refused
            }
            return Ok(());
        }
        if seg.has(flags::SYN) {
            if seg.has(flags::ACK) {
                // Simultaneous open: the peer's SYN-ACK acknowledges our SYN.
                if !self.is_listener && seg.seq == self.irs && seg.ack == self.iss.wrapping_add(1) {
                    return self.complete_passive_open(seg);
                }
                if self.oow_allowed() {
                    self.emit_rst_to(seg, seg.ack, 0, flags::RST)?;
                }
                return Ok(());
            }
            // Retransmitted SYN: our SYN-ACK was lost.
            if seg.seq == self.irs && self.oow_allowed() {
                let _ = self.emit_synack()?;
            }
            return Ok(());
        }
        if !seg.has(flags::ACK) {
            return Ok(());
        }
        if seg.ack != self.iss.wrapping_add(1) {
            if self.oow_allowed() {
                self.emit_rst_to(seg, seg.ack, 0, flags::RST)?;
            }
            return Ok(());
        }
        let seg_len = seg.payload.len() as u32 + u32::from(seg.has(flags::FIN));
        if !self.acceptable(seg.seq, seg_len) {
            return self.send_oow_ack();
        }
        self.complete_passive_open(seg)
    }

    fn complete_passive_open(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        let is_syn = seg.has(flags::SYN);
        self.snd_una = seg.ack;
        self.snd_acked = u64::from(seg.ack.wrapping_sub(self.iss));
        self.syn_unacked = false;
        self.snd_wnd = if is_syn {
            u32::from(seg.window)
        } else {
            self.scale_peer_window(seg.window)
        };
        self.max_snd_wnd = self.max_snd_wnd.max(self.snd_wnd);
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        if self.syn_rcvd_retries > 0 {
            self.syn_retransmitted = true;
        }
        self.handshake_rtt_sample(seg);
        self.rto_deadline = Deadline::OFF;
        self.rtx_count = 0;
        self.syn_rcvd_retries = 0;
        self.state = State::Established;
        self.on_established();
        if is_syn {
            return self.send_pure_ack();
        }
        // The third ACK may carry data or a FIN.
        self.on_synchronized(seg)
    }

    /// Common setup on entering ESTABLISHED.
    pub(super) fn on_established(&mut self) {
        self.cc = Reno::new(congestion::initial_window(self.mss_payload()));
        self.cwnd_limited = false;
        self.cwnd_limited_seq = self.snd_nxt;
        self.pipe_hiwat = 0;
        self.last_data_send_ms = self.now_ms;
        if !seq_gt(self.rcv_adv_edge, self.rcv_nxt) {
            self.rcv_adv_edge = self.rcv_nxt;
        }
        self.on_peer_alive();
    }

    /// An acceptable segment arrived: the peer is alive.
    fn on_peer_alive(&mut self) {
        self.keepalive_probes = 0;
        if self.keepalive_idle_ms != 0 {
            self.keepalive_deadline = Deadline::at(
                self.now_ms
                    .saturating_add(u64::from(self.keepalive_idle_ms)),
            );
        }
    }

    // ---------------------------------------------------------------------
    // Synchronized states
    // ---------------------------------------------------------------------

    /// RFC 9293 §3.10.7.4 segment acceptability (step 1), against the free
    /// space of the receive ring (the advertised window). A zero-length
    /// segment exactly at the right edge is accepted, as Linux and BSD do.
    pub(super) fn acceptable(&self, seq: u32, seg_len: u32) -> bool {
        let wnd = self.recv_ring.free() as u32;
        let nxt = self.rcv_nxt;
        if seg_len == 0 {
            return seq_in_range(seq, nxt, nxt.wrapping_add(wnd).wrapping_add(1));
        }
        if wnd == 0 {
            return false;
        }
        let end = nxt.wrapping_add(wnd);
        seq_in_range(seq, nxt, end) || seq_in_range(seq.wrapping_add(seg_len - 1), nxt, end)
    }

    pub(super) fn on_synchronized(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        // A segment with none of ACK, SYN and RST can change nothing here
        // (step 5 drops it); Linux and BSD discard it before step 1, so it
        // cannot draw a reply either.
        if !seg.has(flags::ACK) && !seg.has(flags::SYN) && !seg.has(flags::RST) {
            return Ok(());
        }
        let payload_len = seg.payload.len() as u32;
        let fin = seg.has(flags::FIN);
        let seg_len = payload_len + u32::from(fin) + u32::from(seg.has(flags::SYN));
        // A bare FIN at RCV.NXT needs no buffer space: accept it even into a
        // zero window (Linux does the same).
        let bare_fin = fin && payload_len == 0 && seg.seq == self.rcv_nxt;
        let acceptable = self.acceptable(seg.seq, seg_len) || bare_fin;
        // RFC 9293 §3.10.7.4: a zero window accepts no text, but "special
        // allowance should be made to accept valid ACKs ... and RSTs". A
        // segment at RCV.NXT (a window probe) has its control fields
        // processed and only its text dropped, as Linux does.
        let zero_window_probe =
            !acceptable && seg.seq == self.rcv_nxt && self.recv_ring.free() == 0;
        if !acceptable && !zero_window_probe {
            return self.on_unacceptable(seg, payload_len, fin);
        }
        if self.paws_reject(seg) {
            // RFC 7323 §5.3 R1: ACK and drop (paws_reject implies data or
            // a FIN; the ACK is immediate only if `may_answer_at_once`).
            return if self.may_answer_at_once(seg) {
                self.send_pure_ack()
            } else {
                self.send_oow_ack()
            };
        }
        // RFC 5961 §3.2: only an exact-match RST resets; any other
        // in-window RST draws a (rate-limited) challenge ACK.
        if seg.has(flags::RST) {
            if seg.seq == self.rcv_nxt {
                self.on_reset_received();
                return Ok(());
            }
            return self.send_oow_ack();
        }
        // RFC 5961 §4: a SYN on a synchronized connection is challenged.
        if seg.has(flags::SYN) {
            return self.send_oow_ack();
        }
        // RFC 9293 §3.10.7.4 step 5: "if the ACK bit is off, drop".
        if !seg.has(flags::ACK) {
            return Ok(());
        }
        // An unacceptable ACK drops the whole segment, so it is checked
        // before anything in the segment may update TS.Recent, the ECN echo
        // state or the keepalive clock: a forged far-future TSval riding on
        // a rejected ACK would otherwise make PAWS discard the peer's data.
        if !self.ack_acceptable(seg.ack) {
            return self.send_oow_ack();
        }
        self.update_ts_recent(seg);
        if self.ecn_enabled {
            // RFC 3168 §6.1.3: CWR ends the echo of earlier CE marks, but a
            // CE mark on the CWR-carrying packet itself must still be echoed.
            if seg.has(flags::CWR) {
                self.ce_observed = false;
            }
            if seg.ecn == ecn::CE {
                self.ce_observed = true;
            }
        }
        self.on_peer_alive();

        self.process_ack(seg)?;
        if self.state == State::Closed {
            return Ok(()); // our FIN was ACKed in LAST-ACK
        }
        if zero_window_probe {
            self.send_pure_ack()?;
            return self.maybe_send_data();
        }

        let prev_rcv_nxt = self.rcv_nxt;
        let mut ack_now = false;
        // Text and FIN are taken only until the peer's FIN (RFC 9293
        // §3.10.7.4 steps 7-8); after it they can only be bogus, and a second
        // FIN must not advance RCV.NXT.
        if self.state.can_recv() {
            // Out-of-order data already parked at this FIN's sequence number,
            // in a block that starts no later than this segment, comes first
            // in SEG.SEQ order: the FIN is not the end of the stream.
            let seg_fin = fin
                .then(|| seg.seq.wrapping_add(payload_len))
                .filter(|&f| !self.parked_ahead_of(seg.seq, f));
            if payload_len > 0 {
                ack_now |= self.receive_payload(seg, seg_fin);
            }
            if let Some(f) = seg_fin {
                ack_now |= self.receive_fin(seg.seq, f);
            } else if fin {
                ack_now = true; // an overridden FIN is a duplicate: ACK at once
            }
            ack_now |= self.maybe_consume_ooo_fin();
        }
        let advanced = self.rcv_nxt != prev_rcv_nxt;

        if ack_now {
            self.send_pure_ack()?;
        } else if advanced {
            self.schedule_delayed_ack(payload_len);
        } else if payload_len > 0 || fin {
            // Text or a FIN after the peer's FIN: nothing was taken.
            self.send_oow_ack()?;
        }
        self.maybe_send_data()
    }

    /// Step 1 failed. RFC 9293 answers with an ACK; RFC 5961 §5.2's ACK
    /// window decides how. A segment whose ACK field is acceptable (which an
    /// off-path sender would have to guess) may be the peer's: as in Linux
    /// and BSD, its ACK field is still processed if the segment ends at or
    /// after `Last.ACK.sent` (e.g. a retransmitted FIN that also acknowledges
    /// ours), and if it could be the peer's own retransmission
    /// ([`Self::may_answer_at_once`]) it is answered at once: duplicate data
    /// with a D-SACK (RFC 2883) so the sender learns its retransmission was
    /// spurious, a zero-window probe with our window. Every other reply comes
    /// out of the rate-limited budget.
    fn on_unacceptable(
        &mut self,
        seg: &Segment<'_>,
        payload_len: u32,
        fin: bool,
    ) -> Result<(), TcpError> {
        if seg.has(flags::RST) {
            return Ok(());
        }
        if seg.has(flags::SYN) || !seg.has(flags::ACK) || !self.ack_acceptable(seg.ack) {
            return self.send_oow_ack();
        }
        let end = seg.seq.wrapping_add(payload_len);
        let right_edge = self.rcv_nxt.wrapping_add(self.recv_ring.free() as u32);
        let ack_live = seq_ge(end.wrapping_add(u32::from(fin)), self.last_ack_sent)
            && seq_le(seg.seq, right_edge)
            && !self.paws_reject(seg);
        if ack_live {
            self.update_ts_recent(seg);
            self.on_peer_alive();
            self.process_ack(seg)?;
            if self.state == State::Closed {
                return Ok(()); // our FIN was ACKed in LAST-ACK
            }
        }
        let at_once = self.may_answer_at_once(seg);
        if at_once && self.state == State::TimeWait && fin && end.wrapping_add(1) == self.rcv_nxt {
            // RFC 9293 §3.10.7.4: a retransmitted FIN means our last ACK was
            // lost; re-ACK it and restart 2·MSL — but never beyond
            // TIME_WAIT_MAX_MS after entry, so FINs cannot pin the TCB.
            let restart = self.now_ms.saturating_add(TIME_WAIT_MS);
            let cap = self.time_wait_since_ms.saturating_add(TIME_WAIT_MAX_MS);
            self.time_wait_deadline = Deadline::at(restart.min(cap));
            return self.send_pure_ack();
        }
        if at_once && payload_len > 0 && seq_le(end, self.rcv_nxt) {
            // Duplicate data: answer at once, with a D-SACK (RFC 2883) so the
            // sender learns the retransmission was spurious.
            self.stats.dup_bytes_received = self
                .stats
                .dup_bytes_received
                .saturating_add(u64::from(payload_len));
            self.note_dsack(seg.seq, end);
            self.send_pure_ack()?;
        } else if at_once && seq_ge(seg.seq, self.rcv_nxt) && self.recv_ring.free() == 0 {
            // Beyond the window: the peer probing our zero window.
            self.send_pure_ack()?;
        } else {
            self.send_oow_ack()?;
        }
        if ack_live {
            self.maybe_send_data()?;
        }
        Ok(())
    }

    /// Whether an unacceptable data or FIN segment could be the peer's own
    /// (re)transmission — bytes we already hold, a zero-window probe, a FIN
    /// whose ACK was lost — rather than blind injection: ACK bit set with an
    /// acceptable SEG.ACK (RFC 5961 §5.2) and, once negotiated, a timestamp
    /// (RFC 7323 §3.2 puts one on every segment). The peer's loss recovery
    /// needs these answered at once (D-SACK undo counts every spurious
    /// retransmission), so only they bypass the out-of-window rate limiter;
    /// anything else could be a reflection attempt. PAWS freshness is not
    /// required: a late original legitimately carries an older TSval than
    /// its retransmission, and its D-SACK is what reveals the spurious one.
    fn may_answer_at_once(&self, seg: &Segment<'_>) -> bool {
        (!seg.payload.is_empty() || seg.has(flags::FIN))
            && seg.has(flags::ACK)
            && !seg.has(flags::SYN)
            && !seg.has(flags::RST)
            && self.ack_acceptable(seg.ack)
            && (!self.ts_enabled || seg.options.ts.is_some())
    }

    /// RFC 7323 §5 PAWS: drop a data-bearing segment whose timestamp is
    /// older than `TS.Recent` (a wrapped-sequence duplicate). Pure ACKs are
    /// exempt so reordered ACKs are never discarded.
    fn paws_reject(&self, seg: &Segment<'_>) -> bool {
        if !self.ts_enabled
            || seg.has(flags::RST)
            || (seg.payload.is_empty() && !seg.has(flags::FIN))
        {
            return false;
        }
        let Some((tsval, _)) = seg.options.ts else {
            return false;
        };
        if self.now_ms.saturating_sub(self.ts_recent_stamp) > PAWS_IDLE_MS {
            return false;
        }
        seq_lt(tsval, self.ts_recent)
    }

    /// RFC 7323 §4.3: TS.Recent follows only segments that cover the left
    /// window edge we last acknowledged (`Last.ACK.sent`), so an
    /// out-of-order or forged segment cannot push it forward.
    fn update_ts_recent(&mut self, seg: &Segment<'_>) {
        if !self.ts_enabled {
            return;
        }
        if let Some((tsval, _)) = seg.options.ts {
            if seq_le(seg.seq, self.last_ack_sent) && seq_ge(tsval, self.ts_recent) {
                self.ts_recent = tsval;
                self.ts_recent_stamp = self.now_ms;
            }
        }
    }

    fn on_reset_received(&mut self) {
        let report = matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2 | State::CloseWait
        );
        if report {
            self.abort_local();
        } else {
            self.close_clean();
        }
    }

    /// Accept payload into the receive ring. In-order bytes are appended;
    /// out-of-order bytes are parked at their final offset in the ring's
    /// free space (the whole receive window can be held across a hole).
    /// `seg_fin` is this segment's FIN, if it is to be processed: parked
    /// bytes absorbed after in-order ones stop there.
    /// Returns `true` when an immediate ACK is due (out-of-order arrival,
    /// a filled hole, or duplicate data).
    fn receive_payload(&mut self, seg: &Segment<'_>, seg_fin: Option<u32>) -> bool {
        let mut seq = seg.seq;
        let mut data = seg.payload;
        let mut ack_now = false;
        if seq_lt(seq, self.rcv_nxt) {
            let lead = self.rcv_nxt.wrapping_sub(seq) as usize;
            let Some(rest) = data.get(lead..).filter(|r| !r.is_empty()) else {
                return true;
            };
            self.stats.dup_bytes_received =
                self.stats.dup_bytes_received.saturating_add(lead as u64);
            self.note_dsack(seq, self.rcv_nxt);
            data = rest;
            seq = self.rcv_nxt;
            ack_now = true;
        }
        let free = self.recv_ring.free();
        let off = seq.wrapping_sub(self.rcv_nxt) as usize;
        if off >= free {
            return true;
        }
        let take = data.len().min(free - off);
        let Some(data) = data.get(..take) else {
            return true;
        };
        if off == 0 {
            let n = self.recv_ring.write(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
            self.stats.bytes_received = self.stats.bytes_received.saturating_add(n as u64);
            // In-order text is processed ahead of a FIN held out of order; if
            // it covers the FIN's sequence number, that FIN was not the end
            // of the stream (Linux drops such a FIN as fully covered).
            if self.ooo_fin.is_some_and(|h| seq_gt(self.rcv_nxt, h.seq)) {
                self.ooo_fin = None;
            }
            return self.absorb_ooo(seg_fin) || ack_now;
        }
        let end = seq.wrapping_add(take as u32);
        match self.ooo.insert(seq, end, self.rcv_nxt) {
            Insert::Stored { dup } => {
                let _ = self.recv_ring.write_at(off, data);
                if dup {
                    self.stats.dup_bytes_received =
                        self.stats.dup_bytes_received.saturating_add(take as u64);
                    self.note_dsack(seq, end);
                }
                // So does parked text from a segment that starts no later
                // than the held FIN's: it comes first in SEG.SEQ order.
                if self
                    .ooo_fin
                    .is_some_and(|h| seq_le(seq, h.start) && seq_gt(end, h.seq))
                {
                    self.ooo_fin = None;
                }
            }
            Insert::Full => {
                self.stats.ooo_drops = self.stats.ooo_drops.saturating_add(1);
            }
        }
        true
    }

    /// Queue a D-SACK (RFC 2883) for duplicate bytes `[l, r)`, trimmed to
    /// sequence space this connection can have received: nothing before the
    /// peer's first byte, nor more than `BUF` below `RCV.NXT` (a conforming
    /// sender never has more than our window unacknowledged, so it cannot
    /// legitimately repeat anything older).
    fn note_dsack(&mut self, l: u32, r: u32) {
        if !self.sack_enabled {
            return;
        }
        let span = if self.stats.bytes_received >= BUF as u64 {
            BUF as u32
        } else {
            self.rcv_nxt.wrapping_sub(self.irs.wrapping_add(1))
        };
        let floor = self.rcv_nxt.wrapping_sub(span);
        let l = if seq_lt(l, floor) { floor } else { l };
        if seq_lt(l, r) {
            self.dsack = Some((l, r));
        }
    }

    /// Make parked out-of-order bytes that now abut `RCV.NXT` readable, but
    /// never past a FIN that is processed before them (`seg_fin`, or one
    /// held out of order and not overridden): nothing after it belongs to
    /// the stream, and consuming the FIN purges the rest.
    fn absorb_ooo(&mut self, seg_fin: Option<u32>) -> bool {
        let mut new = self.ooo.advance(self.rcv_nxt);
        for f in [seg_fin, self.ooo_fin.map(|h| h.seq)].into_iter().flatten() {
            if seq_ge(f, self.rcv_nxt) && seq_gt(new, f) {
                new = f;
            }
        }
        let n = new.wrapping_sub(self.rcv_nxt);
        if n == 0 {
            return false;
        }
        let c = self.recv_ring.commit(n as usize);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(c as u32);
        self.stats.bytes_received = self.stats.bytes_received.saturating_add(c as u64);
        true
    }

    /// Handle the FIN at sequence number `fin` of a segment starting at
    /// `start`. At `RCV.NXT` it is consumed now; beyond it, it is held until
    /// `RCV.NXT` gets there (the lowest wins, as it is reached first; a
    /// repeat keeps the earliest start). A FIN is always ACKed at once.
    fn receive_fin(&mut self, start: u32, fin: u32) -> bool {
        if fin == self.rcv_nxt {
            self.consume_fin();
        } else if seq_gt(fin, self.rcv_nxt)
            && (fin.wrapping_sub(self.rcv_nxt) as usize) <= self.recv_ring.free()
        {
            match self.ooo_fin {
                Some(h) if seq_lt(h.seq, fin) => {}
                Some(h) if h.seq == fin && seq_le(h.start, start) => {}
                _ => self.ooo_fin = Some(HeldFin { start, seq: fin }),
            }
        }
        true
    }

    /// Whether out-of-order data parked at `fin` comes before a FIN segment
    /// starting at `start` in SEG.SEQ order: its block starts no later.
    /// (Adjacent parked data forms one block, as Linux coalesces it.)
    fn parked_ahead_of(&self, start: u32, fin: u32) -> bool {
        self.ooo
            .containing(fin)
            .is_some_and(|(block, _)| seq_le(block, start))
    }

    /// Consume a FIN held out of order once `RCV.NXT` reaches it. Returns
    /// whether it did: the caller then sends the one ACK the FIN is owed
    /// (an extra immediate or delayed ACK would be redundant).
    fn maybe_consume_ooo_fin(&mut self) -> bool {
        if self.ooo_fin.is_some_and(|h| h.seq == self.rcv_nxt) && self.state.can_recv() {
            self.consume_fin();
            return true;
        }
        false
    }

    /// The peer's FIN sits at `RCV.NXT`: consume it. Nothing follows a FIN,
    /// so out-of-order data parked beyond it is forgotten (never delivered,
    /// no longer SACKed), as Linux `tcp_fin` purges its out-of-order queue.
    fn consume_fin(&mut self) {
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.ooo.clear();
        self.ooo_fin = None;
        self.advance_state_on_remote_fin();
    }

    fn advance_state_on_remote_fin(&mut self) {
        self.state = match self.state {
            State::Established => State::CloseWait,
            State::FinWait1 => {
                if self.fin_sent && self.snd_una == self.snd_nxt {
                    self.enter_time_wait();
                    State::TimeWait
                } else {
                    State::Closing
                }
            }
            State::FinWait2 => {
                self.enter_time_wait();
                State::TimeWait
            }
            other => other,
        };
    }

    pub(super) fn enter_time_wait(&mut self) {
        self.time_wait_deadline = Deadline::at(self.now_ms.saturating_add(TIME_WAIT_MS));
        self.time_wait_since_ms = self.now_ms;
        self.fin_wait2_deadline = Deadline::OFF;
        self.keepalive_deadline = Deadline::OFF;
        self.user_timeout_deadline = Deadline::OFF;
    }

    /// RFC 5681 §4.2 / RFC 9293 §3.8.6.3: ACK at least every second
    /// full-sized segment, otherwise within `DELAYED_ACK_MS`. A coalesced
    /// segment counts as the number of MSS-sized segments it spans.
    fn schedule_delayed_ack(&mut self, payload_len: u32) {
        let full = payload_len / u32::from(self.local_mss.max(1));
        let units = full.clamp(1, u32::from(u8::MAX)) as u8;
        self.delayed_ack_count = self.delayed_ack_count.saturating_add(units);
        self.pending_ack = true;
        if self.delayed_ack_count >= 2 {
            let _ = self.send_pure_ack();
        } else if !self.ack_deadline.is_armed() {
            self.ack_deadline = Deadline::at(self.now_ms.saturating_add(DELAYED_ACK_MS));
        }
    }
}
