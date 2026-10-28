//! RACK-TLP time-based loss detection (RFC 8985).
//!
//! RACK declares a segment lost once a segment *sent after it* has been
//! delivered and more than `RACK.rtt + reo_wnd` has elapsed since the lost
//! candidate was (re)transmitted. This module holds the RACK state machine
//! (steps 2–4 of RFC 8985 §6.2) and the loss scan (step 5) over the
//! per-segment retransmission queue.
//!
//! Two properties matter most for robustness:
//!
//! * **Retransmission ambiguity filter** (§6.2 step 2): a delivered segment
//!   that was retransmitted only advances RACK if the ACK provably refers to
//!   the latest transmission (TSecr) and the implied RTT is not below
//!   `min_rtt`. Without it, an ACK for an *original* transmission is credited
//!   to a just-sent retransmission, RACK concludes the RTT is ~0 and declares
//!   the whole window lost.
//! * **Transmit-time ordering**: candidates are judged by their *latest*
//!   transmit time, which the retransmission queue updates in place.

use crate::rtx_queue::{seg_flags, RtxQueue, Seg};

/// Window over which `min_rtt` is tracked (Linux uses 5 minutes).
pub const MIN_RTT_WINDOW_MS: u64 = 300_000;
/// RFC 8985 DupThresh used for the "enough SACKed" reordering heuristic.
const DUP_THRESH: u32 = 3;

#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
#[inline]
fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// RFC 8985 `RACK_sent_after`, ordering by [`Seg::xmit_seq`] rather than
/// by timestamp. The host clock is millisecond-granular, so timestamps tie
/// often, and the RFC's sequence tie-break would rank higher-sequence new
/// data sent just *before* a retransmission as sent after it (falsely
/// marking the retransmission lost once that data is SACKed). Halves of a
/// split segment share one transmission and tie-break by sequence.
#[inline]
pub fn sent_after(x1: u32, seq1: u32, x2: u32, seq2: u32) -> bool {
    let d = x1.wrapping_sub(x2) as i32;
    d > 0 || (d == 0 && seq_gt(seq1, seq2))
}

/// Windowed running minimum (Kathleen Nichols' three-sample algorithm, as in
/// Linux `lib/minmax.c`). All-zero is "no sample".
#[derive(Copy, Clone, Debug, Default)]
pub struct WinMin {
    t: [u64; 3],
    v: [u32; 3],
    valid: bool,
}

impl WinMin {
    pub const fn new() -> Self {
        Self {
            t: [0; 3],
            v: [0; 3],
            valid: false,
        }
    }

    pub fn get(&self) -> Option<u32> {
        if self.valid {
            Some(self.v[0])
        } else {
            None
        }
    }

    fn reset(&mut self, t: u64, v: u32) {
        self.t = [t; 3];
        self.v = [v; 3];
        self.valid = true;
    }

    pub fn update(&mut self, win: u64, t: u64, v: u32) {
        if !self.valid || v <= self.v[0] || t.saturating_sub(self.t[2]) > win {
            self.reset(t, v);
            return;
        }
        if v <= self.v[1] {
            self.t[1] = t;
            self.v[1] = v;
            self.t[2] = t;
            self.v[2] = v;
        } else if v <= self.v[2] {
            self.t[2] = t;
            self.v[2] = v;
        }
        let dt = t.saturating_sub(self.t[0]);
        if dt > win {
            self.t = [self.t[1], self.t[2], t];
            self.v = [self.v[1], self.v[2], v];
            if t.saturating_sub(self.t[0]) > win {
                self.t = [self.t[1], self.t[2], t];
                self.v = [self.v[1], self.v[2], v];
            }
        } else if self.t[1] == self.t[0] && dt > win / 4 {
            self.t[1] = t;
            self.v[1] = v;
            self.t[2] = t;
            self.v[2] = v;
        } else if self.t[2] == self.t[1] && dt > win / 2 {
            self.t[2] = t;
            self.v[2] = v;
        }
    }
}

/// RACK state (RFC 8985 §6.1). All-zero is the valid initial state.
#[derive(Copy, Clone, Debug, Default)]
pub struct Rack {
    /// A delivered segment has been recorded (`RACK.segment` exists).
    pub valid: bool,
    /// Transmission order (`RACK.xmit_ts`) of the most recently sent
    /// delivered segment.
    pub xmit_seq: u32,
    /// `RACK.end_seq` of that segment.
    pub end_seq: u32,
    /// `RACK.rtt`: RTT of the most recent valid delivery (ms).
    pub rtt: u32,
    /// Windowed minimum RTT (ms).
    pub min_rtt: WinMin,
    /// Highest delivered end sequence (`RACK.fack`).
    fack: u32,
    fack_valid: bool,
    /// `fack` as it stood before the ACK being processed: reordering is
    /// judged against it, so a cumulative ACK and SACK blocks arriving
    /// together are not mistaken for each other's reordering.
    prior_fack: u32,
    prior_fack_valid: bool,
    /// Reordering has been observed on this connection.
    pub reordering_seen: bool,
    /// `RACK.reo_wnd_mult` minus one (so all-zero means a multiplier of 1).
    reo_wnd_extra: u32,
    reo_wnd_persist: u32,
    dsack_round_active: bool,
    dsack_round: u32,
}

impl Rack {
    pub const fn new() -> Self {
        Self {
            valid: false,
            xmit_seq: 0,
            end_seq: 0,
            rtt: 0,
            min_rtt: WinMin::new(),
            fack: 0,
            fack_valid: false,
            prior_fack: 0,
            prior_fack_valid: false,
            reordering_seen: false,
            reo_wnd_extra: 0,
            reo_wnd_persist: 0,
            dsack_round_active: false,
            dsack_round: 0,
        }
    }

    /// Feed a valid (Karn / TSecr-checked) RTT sample into `min_rtt`.
    pub fn sample_rtt(&mut self, now: u64, rtt: u32) {
        self.min_rtt.update(MIN_RTT_WINDOW_MS, now, rtt);
    }

    /// Call once per ACK, before its [`Self::on_delivered`] calls.
    pub fn on_ack_start(&mut self) {
        self.prior_fack = self.fack;
        self.prior_fack_valid = self.fack_valid;
    }

    /// Steps 2 and 3 for one newly delivered (cumulatively ACKed or SACKed)
    /// segment. `tsecr_ms` is the ACK's TSecr mapped back onto the host
    /// clock (TSecr − TS offset), if timestamps are in use.
    pub fn on_delivered(&mut self, seg: &Seg, now: u64, tsecr_ms: Option<u32>) {
        // Step 3: reordering — a never-retransmitted segment delivered below
        // the highest sequence delivered by *earlier* ACKs arrived out of
        // order (Linux compares with `prior_fack` likewise).
        if self.prior_fack_valid
            && !seg.has(seg_flags::EVER_RETRANS)
            && seq_gt(self.prior_fack, seg.end)
        {
            self.reordering_seen = true;
        }
        if !self.fack_valid || seq_gt(seg.end, self.fack) {
            self.fack = seg.end;
            self.fack_valid = true;
        }
        // Step 2: retransmission ambiguity filter.
        let rtt = u32::try_from(now.saturating_sub(seg.xmit_ts)).unwrap_or(u32::MAX);
        if seg.has(seg_flags::EVER_RETRANS) {
            if let Some(t) = tsecr_ms {
                if (t.wrapping_sub(seg.xmit_ts as u32) as i32) < 0 {
                    return; // the ACK echoes an earlier transmission
                }
            }
            if let Some(m) = self.min_rtt.get() {
                if rtt < m {
                    return; // implausibly fast: acks the original
                }
            }
        }
        self.rtt = rtt;
        if !self.valid || sent_after(seg.xmit_seq, seg.end, self.xmit_seq, self.end_seq) {
            self.valid = true;
            self.xmit_seq = seg.xmit_seq;
            self.end_seq = seg.end;
        }
    }

    /// Step 4 bookkeeping when an ACK carried a D-SACK: grow the reordering
    /// window once per round trip that observes D-SACKs.
    pub fn on_dsack(&mut self, snd_una: u32, snd_nxt: u32) {
        if self.dsack_round_active && seq_ge(snd_una, self.dsack_round) {
            self.dsack_round_active = false;
        }
        if !self.dsack_round_active {
            self.dsack_round_active = true;
            self.dsack_round = snd_nxt;
            self.reo_wnd_extra = self.reo_wnd_extra.saturating_add(1).min(15);
            self.reo_wnd_persist = 16;
        }
        // A D-SACK proves a spurious retransmission (reordering or delay).
        self.reordering_seen = true;
    }

    /// Called when fast or RTO recovery ends.
    pub fn on_recovery_exit(&mut self) {
        self.reo_wnd_persist = self.reo_wnd_persist.saturating_sub(1);
        if self.reo_wnd_persist == 0 {
            self.reo_wnd_extra = 0;
        }
    }

    /// Step 4: the reordering window in ms.
    pub fn reo_wnd(&self, srtt: u32, in_recovery: bool, sacked_bytes: u32, mss: u32) -> u32 {
        if !self.reordering_seen && (in_recovery || sacked_bytes >= DUP_THRESH.saturating_mul(mss))
        {
            return 0;
        }
        let base = self.min_rtt.get().unwrap_or(srtt) / 4;
        base.saturating_mul(self.reo_wnd_extra + 1).min(srtt.max(1))
    }
}

/// Step 5: mark lost every unacknowledged segment sent before `RACK.segment`
/// whose deadline (`xmit_ts + RACK.rtt + reo_wnd`) has passed. Returns
/// whether anything was newly marked and, if some candidates are still
/// inside the reordering window, the delay (ms) after which to re-run.
pub fn detect_loss(rack: &Rack, q: &mut RtxQueue, now: u64, reo_wnd: u32) -> (bool, Option<u64>) {
    if !rack.valid {
        return (false, None);
    }
    let mut timeout = 0u64;
    let mut marked = false;
    let thresh = u64::from(rack.rtt).saturating_add(u64::from(reo_wnd));
    for i in 0..q.len() {
        let Some(s) = q.get(i).copied() else { break };
        if s.has(seg_flags::SACKED) || (s.has(seg_flags::LOST) && !s.has(seg_flags::RETRANS)) {
            continue;
        }
        if !sent_after(rack.xmit_seq, rack.end_seq, s.xmit_seq, s.end) {
            // Sent at/after RACK.segment. Never-retransmitted segments are
            // sent in sequence order, so every later one was sent later too.
            if !s.has(seg_flags::EVER_RETRANS) {
                break;
            }
            continue;
        }
        let deadline = s.xmit_ts.saturating_add(thresh);
        if now >= deadline {
            q.mark_lost(i);
            marked = true;
        } else {
            timeout = timeout.max(deadline - now);
        }
    }
    (marked, if timeout > 0 { Some(timeout) } else { None })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::rtx_queue::seg_flags::*;

    fn queue(ts: &[u64]) -> RtxQueue {
        let mut q = RtxQueue::new();
        for (k, t) in ts.iter().enumerate() {
            let k = k as u32;
            q.push(Seg {
                start: 1000 + k * 100,
                end: 1100 + k * 100,
                xmit_ts: *t,
                xmit_seq: 0,
                flags: 0,
            });
        }
        q
    }

    #[test]
    fn later_delivery_marks_earlier_segment_lost_after_reo_window() {
        let mut q = queue(&[100, 100, 101, 101]);
        let mut r = Rack::new();
        // Segment 3 (sent t=101) is SACKed at t=120: RTT 19.
        let s3 = *q.get(3).unwrap();
        q.sack(s3.start, s3.end, |_| ());
        r.on_delivered(&s3, 120, None);
        assert_eq!(r.rtt, 19);
        // Not in recovery, 1 segment SACKed: reo_wnd = srtt/4 without a min_rtt sample.
        let reo = r.reo_wnd(20, false, 100, 100);
        assert_eq!(reo, 5);
        let (m, t) = detect_loss(&r, &mut q, 120, reo);
        assert!(!m, "inside the reordering window");
        assert!(t.is_some());
        let (m, _) = detect_loss(&r, &mut q, 130, reo);
        assert!(m);
        assert_eq!(q.lost_bytes(), 300);
    }

    #[test]
    fn ack_of_original_does_not_credit_fresh_retransmission() {
        let mut q = queue(&[100, 100]);
        let mut r = Rack::new();
        r.sample_rtt(150, 50);
        q.mark_lost(0);
        q.on_retransmit(0, 200); // retransmitted at t=200
        let seg0 = *q.get(0).unwrap();
        // ACK arrives at t=201 echoing the original transmission (t=100).
        r.on_delivered(&seg0, 201, Some(100));
        assert!(!r.valid, "ambiguous retransmission must not advance RACK");
        // Without timestamps the min_rtt check rejects the 1 ms "RTT".
        r.on_delivered(&seg0, 201, None);
        assert!(!r.valid);
        // A genuine ACK of the retransmission (RTT 60 >= min_rtt) is accepted.
        r.on_delivered(&seg0, 260, Some(200));
        assert!(r.valid);
        assert_eq!(r.rtt, 60);
    }

    #[test]
    fn cumulative_ack_and_sack_in_one_ack_are_not_reordering() {
        // A delayed ACK covers in-order segments 0-1 and SACKs segment 3
        // (segment 2 lost). Whatever order the ACK's parts are processed in,
        // nothing arrived out of order.
        let mut q = queue(&[100, 100, 100, 100]);
        let mut r = Rack::new();
        r.on_ack_start();
        let s3 = *q.get(3).unwrap();
        q.sack(s3.start, s3.end, |s| r.on_delivered(s, 120, None));
        q.ack_to(1200, |s, newly| {
            if newly {
                r.on_delivered(s, 120, None);
            }
        });
        assert!(!r.reordering_seen);
        // A later ACK delivering segment 2 (never retransmitted) below the
        // previously delivered segment 3 *is* reordering.
        r.on_ack_start();
        q.ack_to(1400, |s, newly| {
            if newly {
                r.on_delivered(s, 125, None);
            }
        });
        assert!(r.reordering_seen);
    }

    #[test]
    fn retransmission_after_new_data_in_the_same_millisecond_is_not_lost() {
        // Segments 0..2 at t=100; segment 0 is lost. At t=150 new data
        // (segment 3) goes out first, then segment 0's retransmission, both
        // stamped 150 ms. Segment 3's SACK must not condemn the
        // retransmission: it was sent *before* it.
        let mut q = queue(&[100, 100, 100]);
        q.push(Seg {
            start: 1300,
            end: 1400,
            xmit_ts: 150,
            xmit_seq: 0,
            flags: 0,
        });
        q.mark_lost(0);
        q.on_retransmit(0, 150);
        let mut r = Rack::new();
        for i in [1, 2, 3] {
            let s = *q.get(i).unwrap();
            q.sack(s.start, s.end, |_| ());
            r.on_delivered(&s, 200, None);
        }
        let (m, _) = detect_loss(&r, &mut q, 200, 0);
        assert!(!m, "retransmission falsely marked lost");
        assert!(q.get(0).unwrap().has(RETRANS));
        // However long we wait, only the delivery of something sent after
        // the retransmission (or the RTO) may condemn it.
        let (m, _) = detect_loss(&r, &mut q, 260, 0);
        assert!(!m);
    }

    #[test]
    fn retransmitted_segment_is_judged_by_its_new_transmit_time() {
        let mut q = queue(&[100, 100, 100]);
        let mut r = Rack::new();
        q.mark_lost(0);
        q.on_retransmit(0, 150);
        // Segment 2 (sent t=100) delivered: segment 0's retransmission was
        // sent *after* it, so it is not a loss candidate.
        let s2 = *q.get(2).unwrap();
        q.sack(s2.start, s2.end, |_| ());
        r.on_delivered(&s2, 160, None);
        let (m, _) = detect_loss(&r, &mut q, 10_000, 0);
        assert!(m);
        assert!(
            q.get(0).unwrap().has(RETRANS),
            "retransmission still in flight"
        );
        assert!(q.get(1).unwrap().has(LOST));
    }

    #[test]
    fn dsack_grows_reordering_window() {
        let mut r = Rack::new();
        r.sample_rtt(0, 40);
        assert_eq!(r.reo_wnd(100, false, 0, 1000), 10);
        r.on_dsack(0, 5000);
        assert_eq!(
            r.reo_wnd(100, true, 0, 1000),
            20,
            "x2 and still applies in recovery"
        );
        r.on_dsack(1000, 6000); // same round: no further growth
        assert_eq!(r.reo_wnd(100, true, 0, 1000), 20);
    }

    #[test]
    fn winmin_expires_old_minimum() {
        let mut m = WinMin::default();
        m.update(100, 0, 10);
        m.update(100, 50, 30);
        assert_eq!(m.get(), Some(10));
        m.update(100, 220, 40);
        assert!(
            m.get().unwrap() > 10,
            "minimum older than the window expires"
        );
    }
}
