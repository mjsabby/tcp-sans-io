//! Transmission: retransmissions, new data, FIN, probes and control segments.
//!
//! Sending is window-driven: a segment may go out while `pipe < cwnd`
//! (RFC 6675 / PRR set `cwnd`), lost segments first, then new data subject
//! to the peer's window and sender-side silly-window avoidance
//! (RFC 9293 §3.8.6.2.1). Sequence numbers are never rewound; a
//! retransmission re-sends a queued segment in place.

use super::{
    seq_ge, seq_gt, seq_lt, Deadline, Tcb, BLACKHOLE_MSS1, DELAYED_ACK_MS, PMTU_PROBE_MAX_MS,
    PMTU_PROBE_MIN_MS,
};
use crate::congestion;
use crate::error::TcpError;
use crate::rtx_queue::{seg_flags, Seg};
use crate::state::State;
use crate::tx_ring::TX_RING_CAP;
use crate::wire::{self, flags, SackBlocks, Segment, TcpOptions};
use crate::MSS;

/// A segment's payload: `len` bytes at `off` past the start of the send ring.
#[derive(Clone, Copy)]
struct RingSlice {
    off: usize,
    len: usize,
}

const NO_PAYLOAD: RingSlice = RingSlice { off: 0, len: 0 };

impl<const BUF: usize> Tcb<BUF> {
    /// States that (re)transmit data: established, or our FIN not yet
    /// acknowledged.
    #[inline]
    fn transmits_data(&self) -> bool {
        matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::Closing
                | State::LastAck
        )
    }

    /// Emit as many segments as the congestion window, the peer's window
    /// and the egress ring allow; then (re)arm the persist timer if data is
    /// stuck with nothing in flight.
    #[inline]
    pub(super) fn maybe_send_data(&mut self) -> Result<(), TcpError> {
        self.send_data(false)
    }

    /// What loss recovery sends on an ACK before the segment's text is
    /// taken (Linux `tcp_xmit_recovery`, at the end of `tcp_ack`): F-RTO's
    /// new data, else presumed-lost segments. They carry the ACK as it
    /// stood; the one the text earns follows on new data or a pure ACK,
    /// which the peer cannot discard as old. On a spurious resend the peer
    /// discards, it would have been lost.
    #[inline]
    pub(super) fn send_recovery(&mut self) -> Result<(), TcpError> {
        if self.frto_new || self.rtx.lost_bytes() > 0 {
            self.send_data(true)?;
        }
        Ok(())
    }

    /// The send loop of [`Self::maybe_send_data`], presumed-lost segments
    /// first, then new data; with `recovery_only`, that of
    /// [`Self::send_recovery`], which stops short of new data.
    fn send_data(&mut self, recovery_only: bool) -> Result<(), TcpError> {
        if !self.transmits_data() {
            return Ok(());
        }
        // Nothing queued, lost or owed (Linux runs `tcp_write_xmit` only with
        // data queued): no send loop and no window validation, which follows
        // sends; and no persist timer, which needs queued data.
        if self.unsent_bytes() == 0 && self.rtx.lost_bytes() == 0 && !self.fin_owed() {
            self.persist_deadline = Deadline::OFF;
            return Ok(());
        }
        let mut guard = 0u32;
        let mut sent = false;
        let mut stalled;
        loop {
            stalled = true;
            while !self.egress_full() {
                if crate::loop_budget_exhausted(
                    &mut guard,
                    TX_RING_CAP as u32 + 2,
                    "maybe_send_data",
                ) {
                    break;
                }
                if recovery_only && !self.frto_new && self.rtx.next_lost().is_none() {
                    stalled = false;
                    break;
                }
                if !self.send_one()? {
                    stalled = false;
                    break;
                }
                sent = true;
            }
            // F-RTO step 2.b (Linux `tcp_xmit_recovery`, `REXMIT_NEW`): new
            // data only, Nagle aside (see `send_one`, `send_new`), and if
            // any went out, nothing resent until the next ACK; if none
            // could go, F-RTO is over: resend as usual.
            if core::mem::take(&mut self.frto_new) {
                if sent {
                    self.frto_hold = true;
                } else {
                    self.cc.frto_off();
                    continue;
                }
            }
            break;
        }
        if recovery_only {
            // A full cwnd is found again by the send that follows.
            self.cwnd_hit = false;
            return Ok(());
        }
        let is_limited = core::mem::take(&mut self.cwnd_hit) || self.pipe() >= self.cc.cwnd;
        // Stopped by a full egress ring with data still queued, not by the
        // windows: the burst goes on once the host drains the ring, so
        // whether cwnd went unused is judged then (Linux sends a whole
        // window in one `tcp_write_xmit`). Judged now, a sender idle for an
        // RTO before writing a full window would decay cwnd as application
        // limited. The round's use of cwnd is recorded all the same, so a
        // sender the host's egress holds back is not cwnd-limited and its
        // window does not grow without bound (Linux `tcp_write_xmit` after
        // `tcp_small_queue_check`).
        let mid_burst = stalled && !is_limited && self.unsent_bytes() > 0;
        if sent || is_limited {
            self.cwnd_validate(is_limited, mid_burst);
        }
        self.update_persist();
        Ok(())
    }

    /// Linux `tcp_cwnd_validate` after a send attempt: per round of data
    /// (until `SND.UNA` passes what was outstanding), remember whether the
    /// sender filled cwnd and the most it had in flight — cwnd may only
    /// grow while it is being used (RFC 7661 in spirit). A sender that has
    /// used less than its window for an RTO decays it (Linux
    /// `tcp_cwnd_application_limited`), so a stale window is not burst out
    /// later; not `mid_burst` (see [`Self::send_data`]).
    #[inline]
    fn cwnd_validate(&mut self, is_limited: bool, mid_burst: bool) {
        let pipe = self.pipe();
        if seq_ge(self.snd_una, self.cwnd_limited_seq)
            || is_limited
            || (!self.cwnd_limited && pipe > self.pipe_hiwat)
        {
            self.cwnd_limited = is_limited;
            self.pipe_hiwat = pipe;
            self.cwnd_limited_seq = self.snd_nxt;
        }
        if self.cwnd_is_limited() {
            self.cwnd_used = 0;
            self.cwnd_stamp_ms = self.now_ms;
            return;
        }
        let outstanding = self.snd_nxt.wrapping_sub(self.snd_una);
        self.cwnd_used = self.cwnd_used.max(outstanding);
        if !mid_burst && self.now_ms.saturating_sub(self.cwnd_stamp_ms) >= u64::from(self.rto_ms) {
            // Not if the application is blocked on a full send buffer.
            if self.cc.state() == congestion::CaState::Open && self.send_ring.free() > 0 {
                let iw = congestion::initial_window(self.mss_payload());
                self.cc.on_application_limited(iw, self.cwnd_used);
                self.cwnd_used = 0;
            }
            self.cwnd_stamp_ms = self.now_ms;
        }
    }

    /// Linux `tcp_is_cwnd_limited`: cwnd was full this round — or, in slow
    /// start, at least half used, so it grows to twice what was sent.
    #[inline]
    pub(super) fn cwnd_is_limited(&self) -> bool {
        self.cwnd_limited
            || (self.cc.cwnd < self.cc.ssthresh && self.pipe_hiwat.saturating_mul(2) > self.cc.cwnd)
    }

    fn send_one(&mut self) -> Result<bool, TcpError> {
        // F-RTO step 2.b puts out new data in place of resends, and none
        // follow on the same ACK (see `send_data`).
        if !self.frto_new && !self.frto_hold {
            if let Some(i) = self.rtx.next_lost() {
                if self.pipe() >= self.cc.cwnd {
                    self.cwnd_hit = true;
                    return Ok(false);
                }
                return self.retransmit(i, false);
            }
        }
        self.send_new()
    }

    /// A FIN is owed once the application closed and it has not been sent.
    #[inline]
    pub(super) fn fin_owed(&self) -> bool {
        matches!(
            self.state,
            State::FinWait1 | State::Closing | State::LastAck
        ) && !self.fin_sent
    }

    /// The owed FIN rides on a segment of `len` new bytes if that segment
    /// ends the queued data and the peer's window admits the FIN's sequence
    /// number too (Linux `tcp_snd_wnd_test` counts it in `end_seq`);
    /// otherwise the data goes alone and the FIN waits for the window.
    #[inline]
    pub(super) fn fin_rides(&self, len: u32) -> bool {
        self.fin_owed() && len == self.unsent_bytes() && self.usable_window() > len
    }

    /// Bytes the peer's window still admits beyond `SND.NXT`.
    #[inline]
    pub(super) fn usable_window(&self) -> u32 {
        let edge = self.snd_una.wrapping_add(self.snd_wnd);
        if seq_gt(edge, self.snd_nxt) {
            edge.wrapping_sub(self.snd_nxt)
        } else {
            0
        }
    }

    fn send_new(&mut self) -> Result<bool, TcpError> {
        let unsent = self.unsent_bytes();
        if unsent == 0 {
            // A bare FIN owes no congestion credit, but it occupies a
            // sequence number the peer's window must admit (Linux
            // `tcp_snd_wnd_test`); the persist timer probes until it does.
            if self.fin_owed() && self.rtx.has_room_for_new() && self.usable_window() >= 1 {
                return self.emit_new(0, true);
            }
            return Ok(false);
        }
        if !self.rtx.has_room_for_new() {
            return Ok(false);
        }
        if self.pipe() >= self.cc.cwnd {
            self.cwnd_hit = true;
            return Ok(false);
        }
        let mss = self.data_mss();
        let avail = self.usable_window().min(unsent);
        let probe = self.pmtu_probe_len().filter(|&(len, _)| avail >= len);
        // Sender SWS avoidance: a full segment, everything that is queued,
        // or at least half the largest window the peer ever offered.
        let len = if let Some((plen, _)) = probe {
            plen
        } else if avail >= mss {
            mss
        } else if avail > 0 && (avail == unsent || avail >= self.max_snd_wnd / 2) {
            avail
        } else {
            return Ok(false);
        };
        let fin = self.fin_rides(len);
        // Nagle (RFC 9293 §3.7.4) in Minshall's variant, as Linux
        // `tcp_nagle_check`: a short segment waits while an earlier short
        // one is unacknowledged, unless it carries the FIN, or is F-RTO's
        // probe of new data (Linux `tcp_xmit_recovery`: `TCP_NAGLE_OFF`).
        if len < mss
            && !fin
            && !self.nodelay
            && !self.frto_new
            && seq_gt(self.snd_sml, self.snd_una)
            && !seq_gt(self.snd_sml, self.snd_nxt)
        {
            return Ok(false);
        }
        // Restart after idle (Linux `tcp_cwnd_restart`).
        let idle_ms = self.now_ms.saturating_sub(self.last_data_send_ms);
        if self.snd_una == self.snd_nxt && idle_ms > u64::from(self.rto_ms) {
            let iw = congestion::initial_window(self.mss_payload());
            self.cc.on_idle_restart(iw, idle_ms, self.rto_ms);
            self.cwnd_used = 0;
            self.cwnd_stamp_ms = self.now_ms;
        }
        let seq = self.snd_nxt;
        let sent = self.emit_new(len, fin)?;
        if let (true, Some((plen, cap))) = (sent, probe) {
            self.pmtu_probe_inflight = true;
            self.pmtu_probe_mss = cap;
            self.pmtu_probe_start = seq;
            self.pmtu_probe_end = seq.wrapping_add(plen);
        }
        Ok(sent)
    }

    /// After a black-hole clamp, the next new segment may be a path-MTU
    /// probe: `(payload, MSS cap)` one size step up, sent only from a calm
    /// state (no recovery, no unanswered timeout). Normal segments stay at
    /// the clamped size until a probe gets through.
    fn pmtu_probe_len(&self) -> Option<(u32, u16)> {
        if self.pmtu_restore_mss == 0
            || self.pmtu_probe_inflight
            || self.now_ms < self.pmtu_probe_at
            || self.rtx_count != 0
            || self.cc.state() != congestion::CaState::Open
        {
            return None;
        }
        let next = if self.pmtu_mss < BLACKHOLE_MSS1 && self.pmtu_restore_mss > BLACKHOLE_MSS1 {
            BLACKHOLE_MSS1
        } else {
            self.pmtu_restore_mss
        };
        let cap = self.local_mss.min(self.peer_mss).min(next);
        let ts = if self.ts_enabled { 12 } else { 0 };
        let len = u32::from(cap).saturating_sub(ts);
        (len > self.mss_payload()).then_some((len, next))
    }

    /// The probe was lost or had to be retransmitted: the larger size is
    /// (still) not getting through, or the path was lossy. Back off and
    /// retry later.
    pub(super) fn pmtu_probe_failed(&mut self) {
        self.pmtu_probe_inflight = false;
        self.pmtu_probe_backoff_ms = self
            .pmtu_probe_backoff_ms
            .saturating_mul(2)
            .clamp(PMTU_PROBE_MIN_MS, PMTU_PROBE_MAX_MS);
        self.pmtu_probe_at = self
            .now_ms
            .saturating_add(u64::from(self.pmtu_probe_backoff_ms));
    }

    /// Transmit `len` new bytes at `SND.NXT` (plus a FIN if `fin`). PSH
    /// marks the end of the queued data — the tail of what the application
    /// wrote — and, as Linux `forced_push`, at least every half of the
    /// peer's largest window; not every segment, so a GRO receiver can
    /// coalesce the run between.
    pub(super) fn emit_new(&mut self, len: u32, fin: bool) -> Result<bool, TcpError> {
        let seq = self.snd_nxt;
        let payload = RingSlice {
            off: seq.wrapping_sub(self.data_una()) as usize,
            len: len as usize,
        };
        if len > u32::from(MSS) {
            return Err(TcpError::Overflow);
        }
        let end = seq.wrapping_add(len);
        // Full-sized as sent: the D-SACK this segment carries is spent below.
        let full = self.data_mss();
        let push = len > 0
            && (len >= self.unsent_bytes()
                || end.wrapping_sub(self.pushed_seq) > self.max_snd_wnd / 2);
        let fl = flags::ACK | if push { flags::PSH } else { 0 } | if fin { flags::FIN } else { 0 };
        if !self.emit_data_segment(fl, seq, payload, len > 0)? {
            return Ok(false);
        }
        if push {
            self.pushed_seq = end;
        }
        if len > 0 && len < full {
            self.snd_sml = end; // Linux `tcp_minshall_update`
        }
        let seq_len = len + u32::from(fin);
        let pushed = self.rtx.push(Seg {
            start: seq,
            end: seq.wrapping_add(seq_len),
            xmit_ts: self.now_ms,
            xmit_seq: 0,
            flags: if fin { seg_flags::FIN } else { 0 } | if push { seg_flags::PSH } else { 0 },
        });
        if !pushed {
            return Err(TcpError::Overflow);
        }
        if fin {
            self.fin_sent = true;
            self.fin_seq = seq.wrapping_add(len);
        }
        self.snd_nxt = seq.wrapping_add(seq_len);
        self.cc.on_send(seq_len);
        if len > 0 {
            self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(u64::from(len));
            self.on_data_sent();
        }
        if !self.rto_deadline.is_armed() {
            self.arm_rto();
        }
        self.maybe_arm_tlp();
        Ok(true)
    }

    /// Data, new or retransmitted, went out (Linux `tcp_event_data_sent`):
    /// the idle clock restarts, and a reply within a delayed-ACK interval
    /// of the peer's data makes the connection interactive.
    fn on_data_sent(&mut self) {
        self.last_data_send_ms = self.now_ms;
        if self
            .last_data_recv_ms
            .is_some_and(|t| self.now_ms.saturating_sub(t) < DELAYED_ACK_MS)
        {
            self.pingpong = true;
        }
    }

    /// Retransmit queued segment `i` (splitting it first if the path MSS
    /// shrank below its size, or the peer's window ends inside it).
    /// `probe`: a tail loss probe re-sending a segment not deemed lost (see
    /// [`crate::rtx_queue::RtxQueue::on_probe`]).
    pub(super) fn retransmit(&mut self, i: usize, probe: bool) -> Result<bool, TcpError> {
        let mut mss = self.mss_payload();
        let Some(mut s) = self.rtx.get(i).copied() else {
            return Ok(false);
        };
        // The peer's window bounds retransmissions too (Linux
        // `__tcp_retransmit_skb`): after it shrinks, what lies beyond its
        // edge waits, and a segment that straddles it is split, so the ACK
        // of the part inside clocks out the next. Into a zero window the
        // head still goes, as the window probe.
        let edge = self.snd_una.wrapping_add(self.snd_wnd);
        if seq_lt(s.start, edge) {
            mss = mss.min(edge.wrapping_sub(s.start));
        } else if s.start != self.snd_una {
            return Ok(false);
        }
        if self.pmtu_probe_inflight
            && seq_lt(s.start, self.pmtu_probe_end)
            && seq_gt(s.end, self.pmtu_probe_start)
        {
            self.pmtu_probe_failed();
        }
        if s.payload_len() > mss {
            let at = s.start.wrapping_add(mss);
            // With no record for the split, merge two newer ones to make
            // one; failing that, wait for an ACK to free one: sending the
            // first MSS while marking the whole segment retransmitted would
            // strand the rest until the RTO.
            if !self.rtx.split(i, at) && !(self.rtx.coalesce_after(i) && self.rtx.split(i, at)) {
                return Ok(false);
            }
            if let Some(n) = self.rtx.get(i).copied() {
                s = n;
            }
        }
        let plen = s.payload_len().min(mss);
        let payload = RingSlice {
            off: s.start.wrapping_sub(self.data_una()) as usize,
            len: plen as usize,
        };
        if plen > u32::from(MSS) {
            return Err(TcpError::Overflow);
        }
        let fin = s.has(seg_flags::FIN) && plen == s.payload_len();
        let push = plen > 0 && s.has(seg_flags::PSH) && plen == s.payload_len();
        let fl = flags::ACK | if push { flags::PSH } else { 0 } | if fin { flags::FIN } else { 0 };
        // An owed ACK goes on its own first (Linux lets the resend carry
        // it): a peer that already holds the resent data may drop it as
        // older than its last ACK (Linux `tcp_sequence`) without reading
        // its ACK field, and the peer's own data would then wait for its
        // tail loss probe.
        if self.pending_ack {
            self.send_pure_ack()?;
        }
        if !self.emit_data_segment(fl, s.start, payload, false)? {
            return Ok(false);
        }
        if plen > 0 {
            self.on_data_sent();
        }
        if probe {
            self.rtx.on_probe(i, self.now_ms);
        } else {
            self.rtx.on_retransmit(i, self.now_ms);
        }
        self.cc.on_send(s.seq_len());
        self.cc.on_retransmit(self.now_ms);
        self.stats.segs_retrans = self.stats.segs_retrans.saturating_add(1);
        self.stats.bytes_retrans = self.stats.bytes_retrans.saturating_add(u64::from(plen));
        self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(u64::from(plen));
        // Re-sending the head restarts the RTO (Linux
        // `tcp_xmit_retransmit_queue`): its retransmission needs a round
        // trip, which a timer armed for the original may not leave.
        if i == 0 || !self.rto_deadline.is_armed() {
            self.arm_rto();
        }
        Ok(true)
    }

    /// Arm the persist timer when queued data or an owed FIN cannot be sent
    /// (zero or silly-small window) and nothing in flight will clock it out.
    fn update_persist(&mut self) {
        let stuck = (self.unsent_bytes() > 0 || self.fin_owed())
            && self.snd_una == self.snd_nxt
            && matches!(
                self.state,
                State::Established
                    | State::CloseWait
                    | State::FinWait1
                    | State::Closing
                    | State::LastAck
            );
        if !stuck {
            self.persist_deadline = Deadline::OFF;
            return;
        }
        if !self.persist_deadline.is_armed() {
            if self.persist_backoff_ms == 0 {
                self.persist_backoff_ms = self.rto_ms;
            }
            self.persist_deadline = Deadline::at(
                self.now_ms
                    .saturating_add(u64::from(self.persist_backoff_ms)),
            );
        }
    }

    // ---------------------------------------------------------------------
    // Segment construction
    // ---------------------------------------------------------------------

    /// Options for a segment carrying `payload_len` bytes: timestamps, plus
    /// as many SACK blocks (D-SACK first) as fit without pushing the segment
    /// past the MSS. New data segments are sized to leave room for them
    /// ([`Self::data_mss`]); a retransmission keeps its size and carries
    /// what fits. Pure ACKs carry up to 3 (with timestamps) or 4.
    fn segment_options(&mut self, payload_len: u32) -> TcpOptions {
        let mut opts = TcpOptions::NONE;
        let ts_len = if self.ts_enabled {
            opts.ts = Some((self.ts_val(), self.ts_recent));
            12
        } else {
            0
        };
        // A FIN held out of order is SACKed with the data (Linux reports
        // its sequence number as part of the segment's `end_seq`).
        let fin = self.ooo_fin.map(|h| (h.seq, h.tag));
        if self.sack_enabled && (self.dsack.is_some() || !self.ooo.is_empty() || fin.is_some()) {
            let cap = u32::from(self.local_mss.min(self.peer_mss).min(self.pmtu_mss));
            let budget = cap.saturating_sub(payload_len).min(40);
            // Encoded sizes: TS + n blocks = 12 + 8n; n blocks alone = 4 + 8n.
            let fixed = if ts_len > 0 { 12 } else { 4 };
            let n = (budget.saturating_sub(fixed) / 8).min(4) as usize;
            if n > 0 {
                let mut sb = SackBlocks::EMPTY;
                if let Some((l, r)) = self.dsack.take() {
                    sb.push(l, r);
                }
                let more = n.saturating_sub(sb.len());
                self.ooo.fill_sack_blocks(&mut sb, more, fin);
                opts.sack = sb;
            }
        }
        opts
    }

    /// Emit a data-bearing (or FIN) segment. `ect` marks a first
    /// transmission of data, the only segments that may be ECT (RFC 3168).
    fn emit_data_segment(
        &mut self,
        fl: u8,
        seq: u32,
        payload: RingSlice,
        ect: bool,
    ) -> Result<bool, TcpError> {
        let opts = self.segment_options(payload.len as u32);
        let queued = self.emit_segment(fl, seq, self.rcv_nxt, &opts, payload, ect)?;
        // The ACK rides on this segment, unless a D-SACK owed did not fit
        // (a retransmission keeps its size): then the ACK carrying it is
        // still owed.
        if queued && self.dsack.is_none() {
            self.on_ack_sent();
        }
        Ok(queued)
    }

    /// An ACK of everything received went out (Linux `tcp_event_ack_sent`):
    /// nothing is owed any more, and an owed one spends a quick ACK
    /// (`tcp_dec_quickack_mode`).
    fn on_ack_sent(&mut self) {
        if self.pending_ack {
            self.quick_acks = self.quick_acks.saturating_sub(1);
        }
        self.pending_ack = false;
        self.delayed_ack_count = 0;
        self.ack_pushed = 0;
        self.ack_deadline = Deadline::OFF;
    }

    pub(super) fn send_pure_ack(&mut self) -> Result<(), TcpError> {
        if self.egress_full() {
            // Owed now, not at a later delayed-ACK deadline: the first tick
            // after the host drains or resumes egress sends it.
            self.pending_ack = true;
            self.ack_deadline = Deadline::at(self.now_ms);
            return Ok(());
        }
        let opts = self.segment_options(0);
        if self.emit_segment(
            flags::ACK,
            self.snd_nxt,
            self.rcv_nxt,
            &opts,
            NO_PAYLOAD,
            false,
        )? {
            self.on_ack_sent();
        }
        Ok(())
    }

    /// Zero-window / keepalive probe: an ACK carrying an already
    /// acknowledged sequence number (RFC 9293 §3.8.4 / Linux), which the
    /// peer must answer with its current ACK and window. It consumes no
    /// sequence space, so it never inflates the peer's receive queue.
    pub(super) fn emit_probe(&mut self, seq: u32) -> Result<bool, TcpError> {
        let mut opts = TcpOptions::NONE;
        if self.ts_enabled {
            opts.ts = Some((self.ts_val(), self.ts_recent));
        }
        self.emit_segment(flags::ACK, seq, self.rcv_nxt, &opts, NO_PAYLOAD, false)
    }

    pub(super) fn emit_syn(&mut self) -> Result<bool, TcpError> {
        let opts = TcpOptions {
            mss: Some(self.local_mss),
            wscale: Some(Self::WS),
            ts: Some((self.ts_val(), 0)),
            sack_permitted: true,
            sack: SackBlocks::EMPTY,
        };
        // RFC 3168 §6.1.1 ECN-setup SYN. A retransmission goes without, in
        // case the path drops ECN-setup SYNs (§6.1.1.1, Linux
        // `tcp_ecn_clear_syn`).
        let ecn = if self.syn_retransmitted {
            0
        } else {
            flags::ECE | flags::CWR
        };
        self.emit_segment(flags::SYN | ecn, self.iss, 0, &opts, NO_PAYLOAD, false)
    }

    pub(super) fn emit_synack(&mut self) -> Result<bool, TcpError> {
        let opts = TcpOptions {
            mss: Some(self.local_mss),
            wscale: if self.ws_ok {
                Some(self.rcv_wscale)
            } else {
                None
            },
            ts: if self.ts_enabled {
                Some((self.ts_val(), self.ts_recent))
            } else {
                None
            },
            sack_permitted: self.sack_enabled,
            sack: SackBlocks::EMPTY,
        };
        let fl = flags::SYN | flags::ACK | if self.ecn_enabled { flags::ECE } else { 0 };
        self.emit_segment(fl, self.iss, self.rcv_nxt, &opts, NO_PAYLOAD, false)
    }

    /// Option-less control segment to the connected peer (RST / RST+ACK).
    pub(super) fn emit_ctl(&mut self, fl: u8, seq: u32, ack: u32) -> Result<bool, TcpError> {
        self.emit_segment(fl, seq, ack, &TcpOptions::NONE, NO_PAYLOAD, false)
    }

    /// RST addressed to the *sender* of `seg` (used where the TCB has no or
    /// a different pinned peer, e.g. LISTEN, SYN-SENT and CLOSED). IP ID 0,
    /// as Linux's control-socket RSTs: a counter bumped by packets to anyone
    /// would let a prober count them (an idle scan).
    pub(super) fn emit_rst_to(
        &mut self,
        seg: &Segment<'_>,
        seq: u32,
        ack: u32,
        fl: u8,
    ) -> Result<(), TcpError> {
        let (lip, lport) = (self.local.ip, self.local.port);
        let (rip, rport) = (seg.src_ip, seg.src_port);
        let full_csum = !self.tx_csum_offload;
        let queued = self.tx_ring.push_with(|buf| {
            wire::emit_with(
                buf,
                lip,
                rip,
                lport,
                rport,
                seq,
                ack,
                fl,
                0,
                &TcpOptions::NONE,
                0,
                |_| true,
                0,
                wire::ecn::NOT_ECT,
                full_csum,
            )
        })?;
        if queued {
            self.stats.segs_out = self.stats.segs_out.saturating_add(1);
        }
        Ok(())
    }

    fn emit_segment(
        &mut self,
        flag_bits: u8,
        seq: u32,
        ack: u32,
        options: &TcpOptions,
        payload: RingSlice,
        ect: bool,
    ) -> Result<bool, TcpError> {
        // Handshake and reset segments are exempt from host back-pressure:
        // deferring them would cost a handshake RTO or lose the reset.
        if self.tx_ring.is_full()
            || (self.egress_paused && flag_bits & (flags::SYN | flags::RST) == 0)
        {
            return Ok(false);
        }
        let is_syn = flag_bits & flags::SYN != 0;
        let (window, wnd_bytes) = self.outbound_window(is_syn);
        let mut fl = flag_bits;
        if self.ecn_enabled && !is_syn && flag_bits & flags::ACK != 0 {
            if self.ce_observed {
                fl |= flags::ECE;
            }
            if self.send_cwr_pending && ect {
                fl |= flags::CWR;
                self.send_cwr_pending = false;
            }
        }
        let ecn_cp = if self.ecn_enabled && !is_syn && ect {
            wire::ecn::ECT_0
        } else {
            wire::ecn::NOT_ECT
        };
        let (src_ip, dst_ip) = (self.local.ip, self.remote.ip);
        let (src_port, dst_port) = (self.local.port, self.remote.port);
        // A SYN-ACK carries IP ID 0, as Linux's (its listener numbers no
        // packet it sends to a would-be peer); the connection's own
        // segments, from the SYN on, count from its ISS-seeded counter.
        let syn_ack = flag_bits & (flags::SYN | flags::ACK) == flags::SYN | flags::ACK;
        let ip_id = if syn_ack { 0 } else { self.ip_id };
        let full_csum = !self.tx_csum_offload;
        // The payload goes straight from the send ring into the slot.
        let ring = &self.send_ring;
        let queued = self.tx_ring.push_with(|buf| {
            wire::emit_with(
                buf,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq,
                ack,
                fl,
                window,
                options,
                payload.len,
                |dst| ring.peek_at(payload.off, dst) == dst.len(),
                ip_id,
                ecn_cp,
                full_csum,
            )
        })?;
        if queued {
            if !syn_ack {
                self.ip_id = self.ip_id.wrapping_add(1);
            }
            self.stats.segs_out = self.stats.segs_out.saturating_add(1);
            if flag_bits & flags::ACK != 0 && flag_bits & flags::RST == 0 {
                self.last_ack_sent = ack;
                let edge = ack.wrapping_add(wnd_bytes);
                if seq_gt(edge, self.rcv_adv_edge) {
                    self.rcv_adv_edge = edge;
                }
                self.rcv_wnd = wnd_bytes;
            }
        }
        Ok(queued)
    }

    /// Receive window to advertise, in bytes (before scaling). Receiver SWS
    /// avoidance (RFC 9293 §3.8.6.2.2): the right edge only moves when at
    /// least `min(BUF/2, MSS)` more space opened, and it never moves left.
    fn advertised_window(&self) -> u32 {
        let free = self.recv_ring.free() as u32;
        let cur = if seq_gt(self.rcv_adv_edge, self.rcv_nxt) {
            self.rcv_adv_edge.wrapping_sub(self.rcv_nxt)
        } else {
            0
        };
        let thresh = (BUF as u32 / 2).min(u32::from(self.local_mss));
        if free >= cur.saturating_add(thresh) {
            free
        } else {
            cur
        }
    }

    /// Wire window field and the byte window it represents. SYN windows are
    /// unscaled (RFC 7323 §2.3). The window never offers more than the free
    /// space of the receive ring: bytes past it are trimmed on arrival, so a
    /// peer filling such a window loses its tail and must repair the hole
    /// with SACK recovery and a retransmission. Rounding to the scale
    /// granularity therefore rounds up to keep the previously advertised
    /// right edge only as far as that space allows, and otherwise down — a
    /// sub-unit retraction that window scaling makes unavoidable (RFC 7323
    /// §2.4). It loses nothing: segment acceptance is checked against the
    /// free space, which never moves left, not against the last window. The
    /// cap also lets a full buffer advertise a zero window.
    fn outbound_window(&self, is_syn: bool) -> (u16, u32) {
        let adv = self.advertised_window();
        if is_syn {
            let w = adv.min(u32::from(u16::MAX));
            return (w as u16, w);
        }
        let shift = u32::from(self.rcv_wscale);
        let cur = if seq_gt(self.rcv_adv_edge, self.rcv_nxt) {
            self.rcv_adv_edge.wrapping_sub(self.rcv_nxt)
        } else {
            0
        };
        let fits = (self.recv_ring.free() as u32) >> shift;
        let mut units = (adv >> shift).min(fits);
        if (units << shift) < cur {
            units = cur.div_ceil(1u32 << shift).min(fits);
        }
        let units = units.min(u32::from(u16::MAX));
        (units as u16, units << shift)
    }

    /// After the application drained the receive ring: announce a window
    /// that grew enough to matter, so a sender throttled by our window does
    /// not idle until the delayed ACK or its next probe.
    pub(super) fn maybe_send_window_update(&mut self) -> Result<(), TcpError> {
        if !matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            return Ok(());
        }
        let cur = if seq_gt(self.rcv_adv_edge, self.rcv_nxt) {
            self.rcv_adv_edge.wrapping_sub(self.rcv_nxt)
        } else {
            0
        };
        let (_, new) = self.outbound_window(false);
        // Linux `__tcp_cleanup_rbuf`: a window that at least doubled, or
        // reopened from zero (receiver SWS avoidance has already held it
        // shut until a useful amount is free), so a sender stalled on our
        // window does not wait for its next zero-window probe.
        if new > cur && new >= 2 * cur {
            self.send_pure_ack()?;
        }
        Ok(())
    }
}
