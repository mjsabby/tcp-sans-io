//! Inbound segment processing (RFC 9293 §3.10.7), per state.
//!
//! Synchronized states follow the RFC's check order: sequence
//! acceptability (+ PAWS), RST (RFC 5961 §3), SYN (RFC 5961 §4), the ACK
//! bit (segments without ACK are dropped), ACK acceptability (RFC 5961 §5 —
//! checked before the segment may update any state), ACK processing (see
//! [`super::ack`]), segment text, FIN. Responses to unacceptable or
//! suspicious segments are rate limited per connection, except an immediate
//! ACK to data or a FIN that could be the peer's own retransmission (see
//! `may_answer_at_once`).

use super::{
    seq_ge, seq_gt, seq_in_range, seq_le, seq_lt, Deadline, Endpoint, Tcb, DELAYED_ACK_MS,
    MIN_PEER_MSS, PAWS_IDLE_MS, TIME_WAIT_MS,
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
                return Err(TcpError::NotForUs);
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
        if self.cookie_secret_set {
            self.emit_cookie_synack(seg)
        } else {
            self.accept_syn_stateful(seg)
        }
    }

    fn accept_syn_stateful(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        self.reset_connection_state();
        self.remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        self.iss = self.passive_iss(self.remote, seg.seq);
        self.snd_una = self.iss;
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

    fn handshake_rtt_sample(&mut self, seg: &Segment<'_>) {
        let sample = match (self.ts_enabled, seg.options.ts) {
            (true, Some((_, tsecr))) if tsecr != 0 => {
                Some((self.now_ms as u32).wrapping_sub(self.tsecr_to_ms(tsecr)))
            }
            _ if !self.syn_retransmitted => {
                u32::try_from(self.now_ms.saturating_sub(self.syn_xmit_ms)).ok()
            }
            _ => None,
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
        let payload_len = seg.payload.len() as u32;
        let fin = seg.has(flags::FIN);
        let seg_len = payload_len + u32::from(fin) + u32::from(seg.has(flags::SYN));
        // A bare FIN at RCV.NXT needs no buffer space: accept it even into a
        // zero window (Linux does the same).
        let bare_fin = fin && payload_len == 0 && seg.seq == self.rcv_nxt;
        if !(self.acceptable(seg.seq, seg_len) || bare_fin) {
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
            if seg.ecn == ecn::CE {
                self.ce_observed = true;
            }
            if seg.has(flags::CWR) {
                self.ce_observed = false;
            }
        }
        self.on_peer_alive();

        self.process_ack(seg)?;
        if self.state == State::Closed {
            return Ok(()); // our FIN was ACKed in LAST-ACK
        }

        let prev_rcv_nxt = self.rcv_nxt;
        let mut ack_now = false;
        if payload_len > 0 && self.state.can_recv() {
            ack_now |= self.receive_payload(seg);
        }
        if fin {
            ack_now |= self.receive_fin(seg.seq.wrapping_add(payload_len));
        }
        self.maybe_consume_ooo_fin();
        let advanced = self.rcv_nxt != prev_rcv_nxt;
        if advanced && self.state == State::FinWait2 && self.fin_wait2_timeout_ms != 0 {
            // The peer is still sending on its half: keep waiting for its FIN.
            self.fin_wait2_deadline = Deadline::at(
                self.now_ms
                    .saturating_add(u64::from(self.fin_wait2_timeout_ms)),
            );
        }

        if ack_now || (fin && advanced) {
            self.send_pure_ack()?;
        } else if advanced {
            self.schedule_delayed_ack(payload_len);
        } else if payload_len > 0 || fin {
            // Consumed sequence space but nothing was accepted.
            self.send_pure_ack()?;
        }
        self.maybe_send_data()
    }

    /// Step 1 failed: reply per RFC 9293 (ACK) unless it is a RST. Only a
    /// segment that [`Self::may_answer_at_once`] gets an immediate reply;
    /// every other reply comes out of the rate-limited budget.
    fn on_unacceptable(
        &mut self,
        seg: &Segment<'_>,
        payload_len: u32,
        fin: bool,
    ) -> Result<(), TcpError> {
        if seg.has(flags::RST) {
            return Ok(());
        }
        if !self.may_answer_at_once(seg) {
            return self.send_oow_ack();
        }
        let end = seg.seq.wrapping_add(payload_len);
        if self.state == State::TimeWait && fin && end.wrapping_add(1) == self.rcv_nxt {
            // RFC 9293 §3.10.7.4: a retransmitted FIN means our last ACK was
            // lost; re-ACK it and restart 2·MSL.
            self.time_wait_deadline = Deadline::at(self.now_ms.saturating_add(TIME_WAIT_MS));
            return self.send_pure_ack();
        }
        // Duplicate data: answer at once, with a D-SACK (RFC 2883) so the
        // sender learns the retransmission was spurious.
        if payload_len > 0 && seq_le(end, self.rcv_nxt) {
            self.stats.dup_bytes_received = self
                .stats
                .dup_bytes_received
                .saturating_add(u64::from(payload_len));
            if self.sack_enabled {
                self.dsack = Some((seg.seq, end));
            }
            return self.send_pure_ack();
        }
        // Beyond the window: the peer probing our zero window.
        if seq_ge(seg.seq, self.rcv_nxt) && self.recv_ring.free() == 0 {
            return self.send_pure_ack();
        }
        self.send_oow_ack()
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
    /// Returns `true` when an immediate ACK is due (out-of-order arrival,
    /// a filled hole, or duplicate data).
    fn receive_payload(&mut self, seg: &Segment<'_>) -> bool {
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
            if self.sack_enabled {
                self.dsack = Some((seq, self.rcv_nxt));
            }
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
            return self.absorb_ooo() || ack_now;
        }
        let end = seq.wrapping_add(take as u32);
        match self.ooo.insert(seq, end, self.rcv_nxt) {
            Insert::Stored { dup } => {
                let _ = self.recv_ring.write_at(off, data);
                if dup {
                    self.stats.dup_bytes_received =
                        self.stats.dup_bytes_received.saturating_add(take as u64);
                    if self.sack_enabled {
                        self.dsack = Some((seq, end));
                    }
                }
            }
            Insert::Full => {
                self.stats.ooo_drops = self.stats.ooo_drops.saturating_add(1);
            }
        }
        true
    }

    /// Make parked out-of-order bytes that now abut `RCV.NXT` readable.
    fn absorb_ooo(&mut self) -> bool {
        let new = self.ooo.advance(self.rcv_nxt);
        let n = new.wrapping_sub(self.rcv_nxt);
        if n == 0 {
            return false;
        }
        let c = self.recv_ring.commit(n as usize);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(c as u32);
        self.stats.bytes_received = self.stats.bytes_received.saturating_add(c as u64);
        true
    }

    /// Handle a FIN occupying sequence number `fin_seq`.
    fn receive_fin(&mut self, fin_seq: u32) -> bool {
        if fin_seq == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.advance_state_on_remote_fin();
        } else if seq_gt(fin_seq, self.rcv_nxt)
            && (fin_seq.wrapping_sub(self.rcv_nxt) as usize) <= self.recv_ring.free()
        {
            // Out of order: remember it until the gap closes.
            self.ooo_fin = Some(fin_seq);
        }
        true
    }

    fn maybe_consume_ooo_fin(&mut self) {
        if self.ooo_fin == Some(self.rcv_nxt) && self.state.can_recv() {
            self.ooo_fin = None;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.advance_state_on_remote_fin();
            let _ = self.send_pure_ack();
        }
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
