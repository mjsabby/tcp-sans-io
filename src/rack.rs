//! RACK-TLP (RFC 8985): time-based loss detection + Tail Loss Probe.
//!
//! Replaces (or complements) the dup-ACK / RTO pair as the primary loss
//! detector for SACK-enabled flows. RACK declares a segment lost when:
//!
//! 1. **Time elapsed**: more than `reo_wnd + rtt` has passed since the
//!    segment was sent, AND
//! 2. **Later delivery**: a strictly-later segment has been ACKed or
//!    SACKed (so the segment can't just be in flight ahead of us).
//!
//! The reordering window `reo_wnd` is `srtt/4` by default. Future work:
//! grow it on DSACK feedback (RFC 8985 §6.2 adaptive logic), shrink it
//! when no reordering is observed.
//!
//! TLP (Tail Loss Probe, §7): when there's un-ACKed data and no ACK
//! movement, schedule a probe at `PTO = max(2*SRTT, 10ms)`, well before
//! RTO. The probe is a retransmit of the last un-SACKed in-flight
//! segment; the resulting SACK/ACK lets RACK detect the loss
//! ~10x faster than waiting for RTO.

use crate::send_queue::{SendQueue, SendEntry};

/// RACK's recovery state — the "most recently delivered segment"
/// markers from RFC 8985 §6.1.
///
/// On every newly-delivered byte range, we update these to reflect the
/// send-time + end-seq + RTT of the segment that delivered it. Other
/// in-flight segments are then judged "lost" if their send-time is
/// strictly older and enough wall-clock has passed.
#[derive(Copy, Clone, Debug)]
pub struct Rack {
    /// Send timestamp (ms) of the segment last delivered.
    /// `0` means "no delivery yet" — RACK is not yet primed.
    pub xmit_ts_ms: u64,
    /// `end_seq` of the segment last delivered.
    pub end_seq: u32,
    /// RTT sample (ms) for that delivery: `now - xmit_ts_ms`.
    pub rtt_ms: u32,
    /// Reordering window (ms). Initial: max(`srtt/4`, 1ms). RFC 8985 §6.2
    /// permits adaptive growth; we keep it fixed in MVP.
    pub reo_wnd_ms: u32,
}

impl Rack {
    pub const fn new() -> Self {
        Self {
            xmit_ts_ms: 0,
            end_seq: 0,
            rtt_ms: 0,
            reo_wnd_ms: 0,
        }
    }

    /// Reset on RTO (RFC 8985 §5: RACK state is invalidated on RTO
    /// because the loss may have been due to severe network change).
    pub fn reset(&mut self) {
        self.xmit_ts_ms = 0;
        self.end_seq = 0;
        self.rtt_ms = 0;
        // Keep reo_wnd_ms — it's an estimate of path reordering, not
        // a per-event signal.
    }

    /// True iff RACK has at least one delivery sample and can make
    /// meaningful loss-detection decisions.
    #[inline]
    pub fn is_primed(&self) -> bool {
        self.xmit_ts_ms > 0
    }

    /// Update RACK on a fresh delivery — a single segment, identified
    /// by its original send time + end-seq, was newly ACKed/SACKed.
    /// `now_ms` lets us derive the latest RTT sample.
    ///
    /// Skip stale updates: a SACK retransmission may carry a send-ts
    /// older than what we've already recorded.
    pub fn update_on_delivery(&mut self, send_ts_ms: u64, end_seq: u32, now_ms: u64) {
        // RFC 8985 §6.1: update only if this delivery is "newer" than
        // the recorded marker. "Newer" means later send-ts, or equal
        // send-ts + later end-seq.
        let is_newer = send_ts_ms > self.xmit_ts_ms
            || (send_ts_ms == self.xmit_ts_ms && seq_gt(end_seq, self.end_seq));
        if !is_newer {
            return;
        }
        self.xmit_ts_ms = send_ts_ms;
        self.end_seq = end_seq;
        // RTT sample. Clamp to 1ms to avoid degenerate zero-RTT cases
        // on loopback / same-host scenarios.
        let rtt = now_ms.saturating_sub(send_ts_ms);
        self.rtt_ms = if rtt > u32::MAX as u64 {
            u32::MAX
        } else if rtt < 1 {
            1
        } else {
            rtt as u32
        };
    }

    /// Set reordering window from current SRTT estimate. Caller invokes
    /// this whenever SRTT is updated. Initial: `srtt/4`, clamped to
    /// `[1, srtt]`. Future work: DSACK-driven growth.
    pub fn set_reo_wnd_from_srtt(&mut self, srtt_ms: u32) {
        let r = (srtt_ms / 4).max(1);
        self.reo_wnd_ms = r;
    }

    /// Decide whether a send_queue entry has crossed RACK's
    /// "definitely-lost" threshold based on (a) being strictly earlier
    /// than the most-recently delivered segment, and (b) wall-clock
    /// elapsed since it was sent.
    ///
    /// Returns:
    /// * `Ordering::Lost(ms_remaining=0)` — declare lost now.
    /// * `Ordering::Reorder(ms_remaining)` — eligible but not yet old
    ///   enough; the caller should arm a reordering timer for `ms_remaining`.
    /// * `Ordering::NotEligible` — entry is later than (or equal to) the
    ///   most-recently delivered segment, so it could be in flight ahead.
    pub fn classify(&self, entry: &SendEntry, now_ms: u64) -> Ordering {
        if !self.is_primed() {
            return Ordering::NotEligible;
        }
        // Strictly-earlier predicate (RFC 8985 §6.1).
        let earlier = entry.send_ts_ms < self.xmit_ts_ms
            || (entry.send_ts_ms == self.xmit_ts_ms
                && seq_le(entry.seq_end, self.end_seq));
        if !earlier {
            return Ordering::NotEligible;
        }
        let elapsed = now_ms.saturating_sub(entry.send_ts_ms);
        let threshold = (self.rtt_ms as u64).saturating_add(self.reo_wnd_ms as u64);
        if elapsed >= threshold {
            Ordering::Lost
        } else {
            let remaining = threshold - elapsed;
            Ordering::Reorder(remaining)
        }
    }
}

impl Default for Rack {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of classifying a single send_queue entry against RACK state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ordering {
    Lost,
    /// `ms_remaining` until the entry crosses the threshold; arm timer.
    Reorder(u64),
    NotEligible,
}

/// Scan all entries in `queue`, returning (1) a list of newly-lost
/// `(seq_start, seq_end)` ranges and (2) the earliest reordering
/// deadline (absolute `now_ms + remaining`) for entries that are
/// eligible-but-not-yet-old-enough. The caller uses (2) to arm the
/// `rack_deadline` timer.
///
/// Returns at most 16 lost ranges per scan; callers should drain the
/// returned set into a persistent retransmit queue and re-scan on the
/// next ACK / timer expiry to pick up the rest if there are more.
pub fn detect_lost(
    rack: &Rack,
    queue: &SendQueue,
    now_ms: u64,
) -> ScanResult {
    let mut lost = LostRanges::new();
    let mut next_deadline: Option<u64> = None;
    for entry in queue.iter() {
        match rack.classify(entry, now_ms) {
            Ordering::Lost => {
                lost.push(entry.seq_start, entry.seq_end);
            }
            Ordering::Reorder(remaining) => {
                let deadline = now_ms.saturating_add(remaining);
                next_deadline = Some(match next_deadline {
                    Some(prev) => prev.min(deadline),
                    None => deadline,
                });
            }
            Ordering::NotEligible => {}
        }
    }
    ScanResult { lost, next_deadline }
}

pub struct ScanResult {
    pub lost: LostRanges,
    /// `Some(absolute_ms)` if any entry is eligible but not yet old
    /// enough — caller should arm a timer for this deadline.
    pub next_deadline: Option<u64>,
}

/// Bounded list of newly-lost ranges from a RACK scan. Cap at 16 — if
/// a single scan finds more, the rest will be discovered on the next
/// scan (timer or ACK driven).
pub struct LostRanges {
    data: [(u32, u32); 16],
    len: usize,
}

impl LostRanges {
    pub const fn new() -> Self {
        Self {
            data: [(0, 0); 16],
            len: 0,
        }
    }
    fn push(&mut self, left: u32, right: u32) {
        if self.len < self.data.len() {
            if let Some(slot) = self.data.get_mut(self.len) {
                *slot = (left, right);
                self.len += 1;
            }
        }
    }
    pub fn as_slice(&self) -> &[(u32, u32)] {
        self.data.get(..self.len).unwrap_or(&[])
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for LostRanges {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send_queue::SendQueue;

    #[test]
    fn unprimed_rack_never_marks_lost() {
        let rack = Rack::new();
        let mut q = SendQueue::new();
        q.push_entry(SendEntry { seq_start: 0, seq_end: 1000, send_ts_ms: 100, is_retx: false });
        let r = detect_lost(&rack, &q, 1_000_000);
        assert!(r.lost.is_empty());
        assert_eq!(r.next_deadline, None);
    }

    #[test]
    fn detect_lost_basic() {
        let mut rack = Rack::new();
        rack.set_reo_wnd_from_srtt(40); // reo_wnd = 10
        // Simulate: seg @ ts=100 ends at 1000, seg @ ts=200 ends at 2000.
        // Update RACK with the later delivery.
        rack.update_on_delivery(200, 2000, 250);
        // Now classify the seg @ ts=100, end=1000 at now=400.
        // earlier? yes (100 < 200). elapsed = 400-100 = 300 ≥ rtt(50)+reo_wnd(10) = 60. → Lost.
        let mut q = SendQueue::new();
        q.push_entry(SendEntry { seq_start: 0, seq_end: 1000, send_ts_ms: 100, is_retx: false });
        let r = detect_lost(&rack, &q, 400);
        assert_eq!(r.lost.as_slice(), &[(0, 1000)]);
    }

    #[test]
    fn detect_reorder_deadline() {
        let mut rack = Rack::new();
        rack.set_reo_wnd_from_srtt(40); // reo_wnd = 10
        rack.update_on_delivery(200, 2000, 250);
        // rtt = 50, reo_wnd = 10, threshold = 60.
        // entry @ ts=180, now = 210. elapsed = 30. remaining = 30.
        let mut q = SendQueue::new();
        q.push_entry(SendEntry { seq_start: 0, seq_end: 1000, send_ts_ms: 180, is_retx: false });
        let r = detect_lost(&rack, &q, 210);
        assert!(r.lost.is_empty());
        assert_eq!(r.next_deadline, Some(210 + 30));
    }

    #[test]
    fn not_eligible_when_later_than_delivered() {
        let mut rack = Rack::new();
        rack.set_reo_wnd_from_srtt(40);
        rack.update_on_delivery(200, 2000, 250);
        // Entry @ ts=300 (strictly later than RACK.xmit_ts=200).
        let mut q = SendQueue::new();
        q.push_entry(SendEntry { seq_start: 2000, seq_end: 3000, send_ts_ms: 300, is_retx: false });
        let r = detect_lost(&rack, &q, 10_000);
        assert!(r.lost.is_empty());
        assert_eq!(r.next_deadline, None);
    }

    #[test]
    fn stale_update_ignored() {
        let mut rack = Rack::new();
        rack.update_on_delivery(200, 2000, 250);
        let before = rack;
        // Try to update with an older send-ts.
        rack.update_on_delivery(150, 1500, 200);
        assert_eq!(rack.xmit_ts_ms, before.xmit_ts_ms);
        assert_eq!(rack.end_seq, before.end_seq);
        assert_eq!(rack.rtt_ms, before.rtt_ms);
    }
}
