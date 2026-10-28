//! `tick()`: every timer-driven action.

use super::{
    Deadline, Tcb, BLACKHOLE_MSS1, BLACKHOLE_MSS2, BLACKHOLE_RTO_STEP1, BLACKHOLE_RTO_STEP2,
    MAX_RETRANSMITS, MAX_SYN_RCVD_RETRIES, MAX_SYN_RETRIES, RTO_MAX_MS,
};
use crate::error::TcpError;
use crate::rtx_queue::seg_flags;
use crate::state::State;
use crate::wire::flags;

impl<const BUF: usize> Tcb<BUF> {
    pub(super) fn run_timers(&mut self) -> Result<(), TcpError> {
        let now = self.now_ms;
        if self.time_wait_deadline.due(now) {
            // 2·MSL over. Unread received data stays readable; every timer
            // is disarmed so an event-driven host is not woken again.
            self.state = State::Closed;
            self.disarm_timers();
            return Ok(());
        }
        if self.state == State::FinWait2 && self.fin_wait2_deadline.due(now) {
            // The peer ACKed our FIN but never sent its own: reset it so it
            // cannot pin this TCB (Linux tcp_fin_timeout behaviour).
            let _ = self.emit_ctl(flags::RST | flags::ACK, self.snd_nxt, self.rcv_nxt)?;
            self.abort_local();
            return Ok(());
        }
        match self.state {
            State::SynSent => self.syn_sent_timer()?,
            State::SynRcvd => self.syn_rcvd_timer()?,
            _ => {}
        }
        // A due tail-loss probe goes first: it re-arms the RTO (RFC 8985 §7.3).
        if self.tlp_deadline.due(now) {
            self.fire_tlp()?;
        }
        if self.state.is_synchronized() && self.rto_deadline.due(now) {
            self.on_rto()?;
            if self.state == State::Closed {
                return Ok(());
            }
        }
        if self.rack_deadline.due(now) {
            self.rack_deadline = Deadline::OFF;
            if self.rack_detect() {
                if !self.cc.in_loss_recovery() {
                    let flight = self.snd_nxt.wrapping_sub(self.data_una());
                    self.enter_fast_recovery(flight);
                }
                // No ACK clocked this: credit one segment so PRR may send.
                let (pipe, mss) = (self.pipe(), self.mss_payload());
                self.cc.prr_update(mss, pipe, mss, false);
            }
        }
        if self.persist_deadline.due(now) {
            self.on_persist_timer()?;
            if self.state == State::Closed {
                return Ok(());
            }
        }
        self.check_keepalive()?;
        self.check_user_timeout();
        if self.state == State::Closed {
            return Ok(());
        }
        self.maybe_send_data()?;
        if self.pending_ack && self.ack_deadline.due(now) {
            self.send_pure_ack()?;
        }
        Ok(())
    }

    fn backoff_rto(&mut self) {
        self.rto_ms = self.rto_ms.saturating_mul(2).min(RTO_MAX_MS);
    }

    fn syn_sent_timer(&mut self) -> Result<(), TcpError> {
        if !self.rto_deadline.due(self.now_ms) {
            return Ok(());
        }
        self.rtx_count = self.rtx_count.saturating_add(1);
        if self.rtx_count > MAX_SYN_RETRIES {
            self.abort_local();
            return Ok(());
        }
        self.syn_retransmitted = true;
        self.backoff_rto();
        let _ = self.emit_syn()?;
        self.arm_rto();
        Ok(())
    }

    fn syn_rcvd_timer(&mut self) -> Result<(), TcpError> {
        if !self.rto_deadline.due(self.now_ms) {
            return Ok(());
        }
        self.syn_rcvd_retries = self.syn_rcvd_retries.saturating_add(1);
        if self.syn_rcvd_retries > MAX_SYN_RCVD_RETRIES {
            if self.is_listener {
                self.reset_to_listen_or_closed();
            } else {
                self.abort_local();
            }
            return Ok(());
        }
        self.syn_retransmitted = true;
        self.backoff_rto();
        let _ = self.emit_synack()?;
        self.arm_rto();
        Ok(())
    }

    /// RFC 6298 §5.4–5.7 / RFC 5681 §3.1: back off, collapse to the loss
    /// window and retransmit everything not SACKed, lowest first.
    fn on_rto(&mut self) -> Result<(), TcpError> {
        self.rto_deadline = Deadline::OFF;
        if self.snd_una == self.snd_nxt {
            return Ok(());
        }
        self.rtx_count = self.rtx_count.saturating_add(1);
        if self.rtx_count > MAX_RETRANSMITS {
            self.abort_local();
            return Ok(());
        }
        self.stats.rto_count = self.stats.rto_count.saturating_add(1);
        self.blackhole_check();
        // A SACKed head that was never cumulatively ACKed means the receiver
        // reneged: forget all SACK state (RFC 2018 §8).
        if self.rtx.get(0).is_some_and(|s| s.has(seg_flags::SACKED)) {
            self.rtx.clear_sacked();
        }
        let flight = self.snd_nxt.wrapping_sub(self.data_una());
        self.cc
            .on_rto(flight, self.snd_una, self.snd_nxt, self.mss_payload());
        self.rtx.mark_all_lost();
        self.reno_sacked = 0;
        self.tlp_end_seq = None;
        self.tlp_deadline = Deadline::OFF;
        self.rack_deadline = Deadline::OFF;
        self.dup_acks = 0;
        self.backoff_rto();
        self.arm_rto();
        Ok(())
    }

    /// Path-MTU black-hole fallback: repeated timeouts of a segment larger
    /// than a conservative size clamp the MSS (1024, then 536).
    fn blackhole_check(&mut self) {
        let target = if self.rtx_count >= BLACKHOLE_RTO_STEP2 {
            BLACKHOLE_MSS2
        } else if self.rtx_count >= BLACKHOLE_RTO_STEP1 {
            BLACKHOLE_MSS1
        } else {
            return;
        };
        let head = self.rtx.get(0).map_or(0, |s| s.payload_len());
        if self.pmtu_mss > target && head > u32::from(target).saturating_sub(12) {
            self.pmtu_mss = target;
        }
    }

    /// RFC 8985 §7.3: probe with new data if possible, else re-send the
    /// highest segment, to elicit an ACK that RACK can act on before RTO.
    fn fire_tlp(&mut self) -> Result<(), TcpError> {
        self.tlp_deadline = Deadline::OFF;
        let eligible = self.sack_enabled
            && self.cc.state() == crate::congestion::CaState::Open
            && self.tlp_end_seq.is_none()
            && self.snd_una != self.snd_nxt
            && !self.tx_ring.is_full();
        if !eligible {
            return Ok(());
        }
        let unsent = self.unsent_bytes();
        let mss = self.mss_payload();
        let usable = self.usable_window();
        let (sent, is_retrans) = if unsent > 0 && usable >= unsent.min(mss) && !self.rtx.is_full() {
            let len = unsent.min(mss);
            let fin = self.fin_owed() && len == unsent;
            (self.emit_new(len, fin)?, false)
        } else {
            match self.rtx.len().checked_sub(1) {
                Some(i) if self.rtx.get(i).is_some_and(|s| !s.has(seg_flags::SACKED)) => {
                    (self.retransmit(i)?, true)
                }
                _ => (false, false),
            }
        };
        if sent {
            self.stats.tlp_count = self.stats.tlp_count.saturating_add(1);
            self.tlp_end_seq = Some(self.snd_nxt);
            self.tlp_is_retrans = is_retrans;
            self.tlp_deadline = Deadline::OFF;
            self.arm_rto();
        }
        Ok(())
    }

    /// Persist timer. With a non-zero but silly-small window the RFC 9293
    /// §3.8.6.2.1 override sends what fits; with a zero window a probe
    /// carrying an old sequence number elicits the peer's current window.
    /// Unanswered probes count toward the R2 abort.
    fn on_persist_timer(&mut self) -> Result<(), TcpError> {
        self.persist_deadline = Deadline::OFF;
        let unsent = self.unsent_bytes();
        if unsent == 0 || self.snd_una != self.snd_nxt {
            return Ok(());
        }
        if self.tx_ring.is_full() {
            self.persist_deadline =
                Deadline::at(self.now_ms.saturating_add(u64::from(self.rto_ms)));
            return Ok(());
        }
        let usable = self.usable_window();
        if usable > 0 && !self.rtx.is_full() {
            let len = usable.min(unsent).min(self.mss_payload());
            let fin = self.fin_owed() && len == unsent;
            let _ = self.emit_new(len, fin)?;
        } else {
            let _ = self.emit_probe(self.snd_una.wrapping_sub(1))?;
            self.rtx_count = self.rtx_count.saturating_add(1);
            if self.rtx_count > MAX_RETRANSMITS {
                self.abort_local();
                return Ok(());
            }
        }
        let base = self.persist_backoff_ms.max(self.rto_ms);
        self.persist_backoff_ms = base.saturating_mul(2).min(RTO_MAX_MS);
        if self.unsent_bytes() > 0 && self.snd_una == self.snd_nxt {
            self.persist_deadline = Deadline::at(
                self.now_ms
                    .saturating_add(u64::from(self.persist_backoff_ms)),
            );
        }
        Ok(())
    }

    /// RFC 9293 §3.8.4 keepalive for fully idle ESTABLISHED connections.
    fn check_keepalive(&mut self) -> Result<(), TcpError> {
        if self.keepalive_idle_ms == 0 || !self.keepalive_deadline.due(self.now_ms) {
            return Ok(());
        }
        if self.state != State::Established {
            // Keepalive only guards fully idle ESTABLISHED connections; the
            // other states have their own bound (R2, FIN_WAIT_2, 2·MSL, or
            // the host's `close`), so drop the timer rather than re-arm it.
            self.keepalive_probes = 0;
            self.keepalive_deadline = Deadline::OFF;
            return Ok(());
        }
        if self.has_send_work() {
            // Not idle (retransmission / persist timers own liveness):
            // restart the idle clock instead of leaving a past deadline
            // armed, which would spin an event-driven host.
            self.keepalive_probes = 0;
            self.keepalive_deadline = Deadline::at(
                self.now_ms
                    .saturating_add(u64::from(self.keepalive_idle_ms)),
            );
            return Ok(());
        }
        if self.keepalive_probes >= self.keepalive_count {
            self.abort_local(); // peer vanished
            return Ok(());
        }
        if self.emit_probe(self.snd_nxt.wrapping_sub(1))? {
            self.keepalive_probes = self.keepalive_probes.saturating_add(1);
            self.keepalive_deadline = Deadline::at(
                self.now_ms
                    .saturating_add(u64::from(self.keepalive_intvl_ms)),
            );
        }
        Ok(())
    }

    /// RFC 9293 §3.8.3 USER TIMEOUT (armed lazily when send work appears;
    /// re-armed only by meaningful progress, see `note_progress`).
    fn check_user_timeout(&mut self) {
        if self.user_timeout_ms == 0
            || !self.has_send_work()
            || !matches!(
                self.state,
                State::Established
                    | State::CloseWait
                    | State::FinWait1
                    | State::Closing
                    | State::LastAck
            )
        {
            self.user_timeout_deadline = Deadline::OFF;
            self.ut_progress = 0;
            return;
        }
        if !self.user_timeout_deadline.is_armed() {
            self.user_timeout_deadline =
                Deadline::at(self.now_ms.saturating_add(u64::from(self.user_timeout_ms)));
        } else if self.user_timeout_deadline.due(self.now_ms) {
            self.abort_local();
        }
    }
}
