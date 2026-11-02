//! `tick()`: every timer-driven action.

use super::{
    seq_ge, seq_gt, Deadline, Tcb, BLACKHOLE_MSS1, BLACKHOLE_MSS2, BLACKHOLE_RTO_STEP1,
    BLACKHOLE_RTO_STEP2, MAX_RETRANSMITS, MAX_SYN_RCVD_RETRIES, MAX_SYN_RETRIES, PMTU_PROBE_MIN_MS,
    RTO_MAX_MS,
};
use crate::congestion::CaState;
use crate::error::TcpError;
use crate::rtx_queue::seg_flags;
use crate::state::State;
use crate::wire::flags;

impl<const BUF: usize> Tcb<BUF> {
    pub(super) fn run_timers(&mut self) -> Result<(), TcpError> {
        let now = self.now_ms;
        if self.time_wait_deadline.due(now) {
            // 2·MSL over. Unread received data stays readable. Segments the
            // peer sent during TIME_WAIT may have re-armed keepalive, so
            // disarm every timer, not just this one.
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
            // Closed in SYN-RECEIVED (RFC 9293 §3.10.4): the FIN waits
            // behind a SYN-ACK the peer may never have received, so keep
            // repeating that (Linux does the same for a Fast Open socket).
            State::FinWait1 if self.syn_unacked => self.syn_rcvd_timer()?,
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
                let recovering = self.cc.state() == CaState::Recovery;
                if !self.cc.in_loss_recovery() {
                    // Linux `tcp_rack_reo_timeout`.
                    self.enter_fast_recovery();
                }
                // No ACK clocked this: one segment of credit, as Linux gives
                // the timer when it enters recovery. Already recovering, a
                // PRR step too (Linux: none): what the timer marked just left
                // pipe, and cwnd, set by the last ACK, would send it all at
                // once. With a millisecond clock the reordering window is at
                // least 2 ms, so the timer, not ACKs, may mark most of a
                // window (Linux, timing in µs, marks it on ACKs, each a PRR
                // step); resent at once into a shallow queue, the resends
                // were lost and only a tail loss probe or the RTO repaired
                // them. At least one goes now to restart the ACK clock.
                let (pipe, mss) = (self.pipe(), self.mss_payload());
                self.cc.prr_update(mss, pipe, mss, false);
                if recovering {
                    self.cc.cwnd = self.cc.cwnd.max(pipe.saturating_add(mss));
                }
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
        // An ACK owed now goes alone, ahead of data, as on receipt: a
        // delayed ACK whose time has come (Linux's timer would have sent it
        // already) or an immediate one a full or paused egress held back,
        // which a peer counting duplicate ACKs must see data-less.
        if self.pending_ack && self.ack_deadline.due(now) {
            // The reply did not come in time to carry it: not interactive
            // after all (Linux `tcp_delack_timer_handler`).
            self.pingpong = false;
            self.send_pure_ack()?;
        }
        self.maybe_send_data()
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
        // Into a zero window the retransmissions are window probes the peer
        // answers: they count toward R2 only while unanswered (Linux
        // `tcp_retransmit_timer` gives up only on a silent peer), so a
        // reader that keeps its window shut is not aborted.
        let repeat = self.rtx_count != 0;
        if self.snd_wnd != 0 {
            self.rtx_count = self.rtx_count.saturating_add(1);
        } else {
            self.probes_out = self.probes_out.saturating_add(1);
        }
        if self.rtx_count > MAX_RETRANSMITS || self.probes_out > MAX_RETRANSMITS {
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
        // Linux `tcp_enter_loss` marks everything lost before seeding the
        // undo state, so of earlier retransmissions only a tail loss probe
        // still needs a D-SACK.
        let seed = self.undo_seed(0);
        // What the timer is about to resend: a D-SACK for it later shows a
        // delayed ACK path, not reordering (see `process_ack`).
        self.rto_span = Some(match self.rto_span {
            Some((lo, hi)) if seq_ge(hi, self.snd_una) => (
                lo,
                if seq_gt(self.snd_nxt, hi) {
                    self.snd_nxt
                } else {
                    hi
                },
            ),
            _ => (self.snd_una, self.snd_nxt),
        });
        self.cc.on_rto(
            self.snd_una,
            self.snd_nxt,
            self.mss_payload(),
            seed,
            self.max_snd_wnd,
            repeat,
        );
        // Linux `tcp_enter_loss`: no F-RTO while a path-MTU probe is out —
        // its loss is the size's, and later data getting through says
        // nothing about it.
        if self.pmtu_probe_inflight {
            self.cc.frto_off();
        }
        self.frto_new = false;
        self.frto_hold = false;
        self.queue_cwr();
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
    /// than a conservative size clamp the MSS (1024, then 536). A plain
    /// outage looks the same, so the clamp is provisional: probe segments at
    /// the next larger size later restore it if the path carries them.
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
            if self.pmtu_restore_mss == 0 {
                self.pmtu_restore_mss = self.pmtu_mss;
                self.pmtu_probe_backoff_ms = PMTU_PROBE_MIN_MS;
            }
            self.pmtu_mss = target;
            self.pmtu_probe_inflight = false;
            self.pmtu_probe_at = self
                .now_ms
                .saturating_add(u64::from(self.pmtu_probe_backoff_ms));
        }
    }

    /// RFC 8985 §7.3: probe with new data if possible, else re-send the
    /// highest segment, to elicit an ACK that RACK can act on before RTO.
    /// As in Linux `tcp_schedule_loss_probe`, a probe may also go out
    /// during an ECN window reduction (CWR), just not in loss recovery.
    fn fire_tlp(&mut self) -> Result<(), TcpError> {
        self.tlp_deadline = Deadline::OFF;
        let eligible = self.sack_enabled
            && self.tlp_state_ok()
            && self.tlp_end_seq.is_none()
            && self.snd_una != self.snd_nxt
            && !self.rack_deadline.is_armed();
        if !eligible {
            return Ok(());
        }
        if self.egress_full() {
            // Silence while egress is held is local queueing, not loss:
            // re-arm rather than probe into the host's queue.
            self.maybe_arm_tlp();
            return Ok(());
        }
        let unsent = self.unsent_bytes();
        let mss = self.data_mss();
        let usable = self.usable_window();
        let (sent, is_retrans) =
            if unsent > 0 && usable >= unsent.min(mss) && self.rtx.has_room_for_new() {
                let len = unsent.min(mss);
                let fin = self.fin_rides(len);
                (self.emit_new(len, fin)?, false)
            } else if self.pmtu_probe_inflight
                && self.snd_una == self.pmtu_probe_start
                && self.rtx.len() == 1
            {
                // A path-MTU probe alone in flight drew nothing back: too
                // big, most likely. Resend its data at the size in use
                // without a congestion response, as Linux does once ACKs
                // show a probe lost ("MTU probe failure: don't reduce
                // cwnd"); a probe of its first MSS (Linux: an inconclusive
                // MTU probe) would leave the rest for RACK to find lost and
                // halve the window over it. The tick sends it; the RTO
                // restarts, as for any probe.
                self.pmtu_probe_failed();
                self.simple_retransmit();
                self.arm_rto();
                return Ok(());
            } else {
                match self.rtx.len().checked_sub(1) {
                    Some(i) if self.rtx.get(i).is_some_and(|s| !s.has(seg_flags::SACKED)) => {
                        (self.retransmit(i, true)?, true)
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
        let stuck = |t: &Self| (t.unsent_bytes() > 0 || t.fin_owed()) && t.snd_una == t.snd_nxt;
        if !stuck(self) {
            return Ok(());
        }
        if self.egress_full() {
            self.persist_deadline =
                Deadline::at(self.now_ms.saturating_add(u64::from(self.rto_ms)));
            return Ok(());
        }
        let usable = self.usable_window();
        if usable > 0 && self.rtx.has_room_for_new() {
            let len = usable.min(unsent).min(self.data_mss());
            let fin = self.fin_rides(len);
            let _ = self.emit_new(len, fin)?;
        } else {
            let _ = self.emit_probe(self.snd_una.wrapping_sub(1))?;
            self.probes_out = self.probes_out.saturating_add(1);
            if self.probes_out > MAX_RETRANSMITS {
                self.abort_local();
                return Ok(());
            }
        }
        let base = self.persist_backoff_ms.max(self.rto_ms);
        self.persist_backoff_ms = base.saturating_mul(2).min(RTO_MAX_MS);
        if stuck(self) {
            self.persist_deadline = Deadline::at(
                self.now_ms
                    .saturating_add(u64::from(self.persist_backoff_ms)),
            );
        }
        Ok(())
    }

    /// RFC 9293 §3.8.4 keepalive for fully idle connections, in the states
    /// it runs in (see `keepalive_applies`).
    fn check_keepalive(&mut self) -> Result<(), TcpError> {
        if self.keepalive_idle_ms == 0 || !self.keepalive_deadline.due(self.now_ms) {
            return Ok(());
        }
        if !self.keepalive_applies() {
            // A handshake, LISTEN or TIME_WAIT: their own timers bound them,
            // so drop the timer rather than wake the host for nothing.
            self.keepalive_probes = 0;
            self.keepalive_deadline = Deadline::OFF;
            return Ok(());
        }
        if self.has_send_work() {
            // Not idle: the retransmission and persist timers own liveness.
            // Restart the idle clock instead of leaving a past deadline
            // armed, which would spin an event-driven host.
            self.keepalive_probes = 0;
            self.keepalive_deadline = Deadline::at(
                self.now_ms
                    .saturating_add(u64::from(self.keepalive_idle_ms)),
            );
            return Ok(());
        }
        if self.keepalive_probes >= self.keepalive_count {
            // The peer vanished. In CLOSE_WAIT its stream is complete and
            // nothing of ours is in flight (we only probe when idle), so
            // nothing was lost: close, keeping unread bytes readable before
            // EOF, as Linux delivers them. Anywhere else, abort.
            if self.state == State::CloseWait {
                self.close_clean();
            } else {
                self.abort_local();
            }
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
