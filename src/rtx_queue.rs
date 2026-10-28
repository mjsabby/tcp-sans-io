//! Per-segment retransmission queue (the RFC 6675 / RFC 8985 scoreboard).
//!
//! One entry per transmitted segment, ordered by sequence number and
//! contiguous, covering exactly `[SND.UNA, SND.NXT)` (a FIN occupies the last
//! sequence number of its entry). A retransmission updates its entry *in
//! place* (new transmit time, `RETRANS` flag) instead of recording a second,
//! overlapping copy, so every question loss recovery asks — "is this byte
//! SACKed / lost / in flight, and when was it last sent?" — has exactly one
//! answer.
//!
//! In-flight accounting follows RFC 6675 `pipe` (and Linux):
//! `pipe = outstanding - sacked - lost + retrans`, where `lost` counts
//! segments marked lost and `retrans` those whose retransmission is still
//! believed to be in flight. Counters are maintained incrementally and are
//! checked against a full recount by [`RtxQueue::debug_valid`].
//!
//! Capacity is bounded by [`RTX_QUEUE_CAP`]; the sender never transmits new
//! data while the queue is full, so the bound is a cap on segments in flight
//! (≈1.4 MiB at a 1448-byte MSS — above the default 1 MiB window).

/// Maximum number of segments in flight.
pub const RTX_QUEUE_CAP: usize = 1024;

/// Per-segment state bits.
pub mod seg_flags {
    /// Selectively acknowledged by the peer.
    pub const SACKED: u8 = 1 << 0;
    /// Deemed lost; needs (another) retransmission.
    pub const LOST: u8 = 1 << 1;
    /// A retransmission of this segment is currently in flight.
    pub const RETRANS: u8 = 1 << 2;
    /// Retransmitted at least once (Karn's algorithm, RACK ambiguity filter).
    pub const EVER_RETRANS: u8 = 1 << 3;
    /// The segment's last sequence number is a FIN.
    pub const FIN: u8 = 1 << 4;
}
use seg_flags::*;

/// One transmitted segment.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Seg {
    pub start: u32,
    /// Exclusive end in sequence space (includes the FIN, if any).
    pub end: u32,
    /// Time (ms) of the most recent (re)transmission.
    pub xmit_ts: u64,
    /// Transmission order of the most recent (re)transmission, assigned by
    /// [`RtxQueue`]. The host clock is millisecond-granular, so `xmit_ts`
    /// ties are common; RACK orders transmissions by this instead.
    pub xmit_seq: u32,
    pub flags: u8,
}

impl Seg {
    #[inline]
    pub fn seq_len(&self) -> u32 {
        self.end.wrapping_sub(self.start)
    }
    #[inline]
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
    /// Payload bytes (sequence length minus the FIN, if any).
    #[inline]
    pub fn payload_len(&self) -> u32 {
        self.seq_len().saturating_sub(u32::from(self.has(FIN)))
    }
}

#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// Bounded FIFO of [`Seg`]s.
pub struct RtxQueue {
    segs: [Seg; RTX_QUEUE_CAP],
    head: usize,
    len: usize,
    sacked: u32,
    lost: u32,
    retrans: u32,
    /// Logical index below which no segment is `LOST && !RETRANS`.
    lost_hint: usize,
    /// Next [`Seg::xmit_seq`] to hand out.
    next_xmit: u32,
}

impl Default for RtxQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RtxQueue {
    pub const fn new() -> Self {
        Self {
            segs: [Seg {
                start: 0,
                end: 0,
                xmit_ts: 0,
                xmit_seq: 0,
                flags: 0,
            }; RTX_QUEUE_CAP],
            head: 0,
            len: 0,
            sacked: 0,
            lost: 0,
            retrans: 0,
            lost_hint: 0,
            next_xmit: 0,
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.sacked = 0;
        self.lost = 0;
        self.retrans = 0;
        self.lost_hint = 0;
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == RTX_QUEUE_CAP
    }
    #[inline]
    pub fn sacked_bytes(&self) -> u32 {
        self.sacked
    }
    #[inline]
    pub fn lost_bytes(&self) -> u32 {
        self.lost
    }
    #[inline]
    pub fn retrans_bytes(&self) -> u32 {
        self.retrans
    }

    /// RFC 6675 `pipe` given the total outstanding sequence span.
    #[inline]
    pub fn pipe(&self, outstanding: u32) -> u32 {
        outstanding
            .saturating_sub(self.sacked)
            .saturating_sub(self.lost)
            .saturating_add(self.retrans)
    }

    #[inline]
    fn phys(&self, i: usize) -> usize {
        (self.head + i) % RTX_QUEUE_CAP
    }

    #[inline]
    pub fn get(&self, i: usize) -> Option<&Seg> {
        if i >= self.len {
            return None;
        }
        self.segs.get(self.phys(i))
    }

    #[inline]
    fn get_mut(&mut self, i: usize) -> Option<&mut Seg> {
        if i >= self.len {
            return None;
        }
        let p = self.phys(i);
        self.segs.get_mut(p)
    }

    pub fn last(&self) -> Option<&Seg> {
        self.len.checked_sub(1).and_then(|i| self.get(i))
    }

    /// Append a newly transmitted segment. Returns `false` when full.
    /// Append a freshly transmitted segment (its `xmit_seq` is assigned).
    pub fn push(&mut self, seg: Seg) -> bool {
        if self.is_full() {
            return false;
        }
        let p = self.phys(self.len);
        let xmit_seq = self.next_xmit;
        if let Some(slot) = self.segs.get_mut(p) {
            *slot = Seg { xmit_seq, ..seg };
            self.next_xmit = xmit_seq.wrapping_add(1);
            self.len += 1;
            true
        } else {
            false
        }
    }

    fn add_counts(&mut self, s: &Seg, sign: bool) {
        let n = s.seq_len();
        let apply = |c: &mut u32| {
            *c = if sign {
                c.saturating_add(n)
            } else {
                c.saturating_sub(n)
            }
        };
        if s.has(SACKED) {
            apply(&mut self.sacked);
        }
        if s.has(LOST) {
            apply(&mut self.lost);
        }
        if s.has(RETRANS) {
            apply(&mut self.retrans);
        }
    }

    /// Replace segment `i`'s flags, keeping the counters consistent.
    fn set_flags(&mut self, i: usize, flags: u8) {
        let Some(old) = self.get(i).copied() else {
            return;
        };
        self.add_counts(&old, false);
        let new = Seg { flags, ..old };
        self.add_counts(&new, true);
        if let Some(s) = self.get_mut(i) {
            s.flags = flags;
        }
        if flags & LOST != 0 && flags & RETRANS == 0 && i < self.lost_hint {
            self.lost_hint = i;
        }
    }

    /// Logical index of the segment containing `seq`.
    pub fn find(&self, seq: u32) -> Option<usize> {
        let first = self.get(0)?.start;
        let rel = seq.wrapping_sub(first);
        let (mut lo, mut hi) = (0usize, self.len);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let s = self.get(mid)?;
            if s.end.wrapping_sub(first) <= rel {
                lo = mid + 1;
            } else if s.start.wrapping_sub(first) > rel {
                hi = mid;
            } else {
                return Some(mid);
            }
        }
        None
    }

    /// Split segment `i` at `at` (strictly inside it). The FIN, if any, stays
    /// with the upper half. Returns `false` if there is no room.
    pub fn split(&mut self, i: usize, at: u32) -> bool {
        let Some(s) = self.get(i).copied() else {
            return false;
        };
        if !(seq_lt(s.start, at) && seq_lt(at, s.end)) || self.is_full() {
            return false;
        }
        // Shift entries i+1.. up by one.
        let mut j = self.len;
        while j > i + 1 {
            let src = self.segs.get(self.phys(j - 1)).copied();
            let dst = self.phys(j);
            if let (Some(v), Some(d)) = (src, self.segs.get_mut(dst)) {
                *d = v;
            }
            j -= 1;
        }
        self.len += 1;
        let lower = Seg {
            end: at,
            flags: s.flags & !FIN,
            ..s
        };
        let upper = Seg { start: at, ..s };
        if let Some(d) = self.get_mut(i) {
            *d = lower;
        }
        if let Some(d) = self.get_mut(i + 1) {
            *d = upper;
        }
        if i + 1 < self.lost_hint {
            self.lost_hint += 1;
        }
        true
    }

    /// Cumulative ACK up to `una`: remove (or trim) covered segments,
    /// calling `f` with each segment's pre-removal state (`newly_acked` =
    /// whether it had not been SACKed). Returns the sequence bytes removed.
    pub fn ack_to<F: FnMut(&Seg, bool)>(&mut self, una: u32, mut f: F) -> u32 {
        let mut removed = 0u32;
        while let Some(s) = self.get(0).copied() {
            if seq_le(s.end, una) {
                f(&s, !s.has(SACKED));
                self.add_counts(&s, false);
                removed = removed.saturating_add(s.seq_len());
                self.head = (self.head + 1) % RTX_QUEUE_CAP;
                self.len -= 1;
                self.lost_hint = self.lost_hint.saturating_sub(1);
            } else if seq_lt(s.start, una) {
                // Partially acknowledged: trim the head.
                f(&s, !s.has(SACKED));
                self.add_counts(&s, false);
                let trimmed = Seg { start: una, ..s };
                self.add_counts(&trimmed, true);
                removed = removed.saturating_add(una.wrapping_sub(s.start));
                if let Some(d) = self.get_mut(0) {
                    *d = trimmed;
                }
                break;
            } else {
                break;
            }
        }
        if self.len == 0 {
            self.head = 0;
            self.lost_hint = 0;
        }
        removed
    }

    /// Mark every segment fully inside `[left, right)` as SACKed, splitting
    /// segments the block only partially covers (when there is room).
    /// Calls `f` for each newly SACKed segment; returns newly SACKed bytes.
    pub fn sack<F: FnMut(&Seg)>(&mut self, left: u32, right: u32, mut f: F) -> u32 {
        if !seq_lt(left, right) || self.is_empty() {
            return 0;
        }
        let Some(first) = self.get(0).map(|s| s.start) else {
            return 0;
        };
        let Some(last) = self.last().map(|s| s.end) else {
            return 0;
        };
        // Clip to the queue's span.
        let l = if seq_lt(left, first) { first } else { left };
        let r = if seq_lt(last, right) { last } else { right };
        if !seq_lt(l, r) {
            return 0;
        }
        let Some(mut i) = self.find(l) else {
            return 0;
        };
        // Partial coverage at the left edge: split so a segment starts at l.
        if let Some(s) = self.get(i).copied() {
            if seq_lt(s.start, l) && !s.has(SACKED) && self.split(i, l) {
                i += 1;
            }
        }
        let mut newly = 0u32;
        while let Some(s) = self.get(i).copied() {
            if !seq_lt(s.start, r) {
                break;
            }
            if seq_lt(r, s.end) {
                // Block ends inside this segment: split, then SACK the lower part.
                if s.has(SACKED) || !self.split(i, r) {
                    break;
                }
                continue;
            }
            if !s.has(SACKED) && seq_le(l, s.start) {
                let nf = (s.flags | SACKED) & !(LOST | RETRANS);
                self.set_flags(i, nf);
                newly = newly.saturating_add(s.seq_len());
                f(&s);
            }
            i += 1;
        }
        newly
    }

    /// Mark segment `i` lost (its retransmission, if any, is lost too).
    pub fn mark_lost(&mut self, i: usize) {
        if let Some(s) = self.get(i).copied() {
            if !s.has(SACKED) && !(s.has(LOST) && !s.has(RETRANS)) {
                self.set_flags(i, (s.flags | LOST) & !RETRANS);
            }
        }
    }

    /// RTO: everything not SACKed is lost and will be retransmitted.
    pub fn mark_all_lost(&mut self) {
        for i in 0..self.len {
            self.mark_lost(i);
        }
        self.lost_hint = 0;
    }

    /// Clear `LOST` from segments not yet retransmitted (a loss episode was
    /// shown to be spurious); RACK or the RTO re-detects any real loss.
    pub fn unmark_lost(&mut self) {
        for i in 0..self.len {
            if let Some(s) = self.get(i).copied() {
                if s.has(LOST) && !s.has(RETRANS) {
                    self.set_flags(i, s.flags & !LOST);
                }
            }
        }
        self.lost_hint = 0;
    }

    /// Forget all SACK state (the receiver reneged).
    pub fn clear_sacked(&mut self) {
        for i in 0..self.len {
            if let Some(s) = self.get(i).copied() {
                if s.has(SACKED) {
                    self.set_flags(i, s.flags & !SACKED);
                }
            }
        }
    }

    /// Lowest segment that is `LOST` and not yet retransmitted.
    pub fn next_lost(&mut self) -> Option<usize> {
        let mut i = self.lost_hint;
        while let Some(s) = self.get(i) {
            if s.has(LOST) && !s.has(RETRANS) {
                self.lost_hint = i;
                return Some(i);
            }
            i += 1;
        }
        self.lost_hint = self.len;
        None
    }

    /// Record a retransmission of segment `i` at `now`.
    pub fn on_retransmit(&mut self, i: usize, now: u64) {
        if let Some(s) = self.get(i).copied() {
            self.set_flags(i, s.flags | RETRANS | EVER_RETRANS);
            let xmit_seq = self.next_xmit;
            if let Some(d) = self.get_mut(i) {
                d.xmit_ts = now;
                d.xmit_seq = xmit_seq;
                self.next_xmit = xmit_seq.wrapping_add(1);
            }
        }
    }

    /// Recount everything and check structural invariants.
    pub fn debug_valid(&self, snd_una: u32, snd_nxt: u32) -> Result<(), &'static str> {
        let (mut sacked, mut lost, mut retrans) = (0u32, 0u32, 0u32);
        let mut expect = None;
        for i in 0..self.len {
            let Some(s) = self.get(i) else {
                return Err("rtx: missing entry");
            };
            if !seq_lt(s.start, s.end) {
                return Err("rtx: empty segment");
            }
            if let Some(e) = expect {
                if s.start != e {
                    return Err("rtx: segments not contiguous");
                }
            }
            if s.has(SACKED) && s.has(LOST | RETRANS) {
                return Err("rtx: SACKED segment also LOST/RETRANS");
            }
            if s.has(RETRANS) && !s.has(EVER_RETRANS) {
                return Err("rtx: RETRANS without EVER_RETRANS");
            }
            if s.has(FIN) && i + 1 != self.len {
                return Err("rtx: FIN is not the last segment");
            }
            expect = Some(s.end);
            if s.has(SACKED) {
                sacked += s.seq_len();
            }
            if s.has(LOST) {
                lost += s.seq_len();
            }
            if s.has(RETRANS) {
                retrans += s.seq_len();
            }
        }
        if (sacked, lost, retrans) != (self.sacked, self.lost, self.retrans) {
            return Err("rtx: counters out of sync");
        }
        if let (Some(first), Some(last)) = (self.get(0), self.last()) {
            if seq_lt(first.start, snd_una) || last.end != snd_nxt {
                return Err("rtx: queue does not end at SND.NXT / starts below SND.UNA");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn q_with(n: u32, mss: u32) -> RtxQueue {
        let mut q = RtxQueue::new();
        for k in 0..n {
            assert!(q.push(Seg {
                start: 1000 + k * mss,
                end: 1000 + (k + 1) * mss,
                xmit_ts: u64::from(k),
                xmit_seq: 0,
                flags: 0,
            }));
        }
        q
    }

    #[test]
    fn sack_marks_and_pipe_accounts() {
        let mut q = q_with(10, 100);
        let out = 1000;
        assert_eq!(q.pipe(out), 1000);
        let mut seen = 0;
        assert_eq!(q.sack(1200, 1500, |_| seen += 1), 300);
        assert_eq!(seen, 3);
        assert_eq!(q.pipe(out), 700);
        // Repeated SACK reports nothing new.
        assert_eq!(q.sack(1200, 1500, |_| ()), 0);
        q.mark_lost(0);
        q.mark_lost(1);
        assert_eq!(q.pipe(out), 500);
        assert_eq!(q.next_lost(), Some(0));
        q.on_retransmit(0, 50);
        assert_eq!(q.pipe(out), 600, "retransmission is back in flight");
        assert_eq!(q.next_lost(), Some(1));
        q.debug_valid(1000, 2000).unwrap();
    }

    #[test]
    fn partial_sack_splits_segments() {
        let mut q = q_with(3, 100);
        assert_eq!(q.sack(1050, 1250, |_| ()), 200);
        // [1000,1050) [1050,1100)S [1100,1200)S [1200,1250)S [1250,1300)
        assert_eq!(q.len(), 5);
        assert_eq!(q.sacked_bytes(), 200);
        q.debug_valid(1000, 1300).unwrap();
    }

    #[test]
    fn cumulative_ack_removes_and_trims() {
        let mut q = q_with(4, 100);
        q.sack(1200, 1300, |_| ());
        let mut newly = 0;
        assert_eq!(
            q.ack_to(1250, |s, n| {
                if n {
                    newly += s.seq_len();
                }
            }),
            250
        );
        assert_eq!(newly, 200, "SACKed segment was not newly delivered");
        assert_eq!(q.get(0).unwrap().start, 1250);
        assert_eq!(q.sacked_bytes(), 50, "the trimmed head keeps its SACK mark");
        q.debug_valid(1250, 1400).unwrap();
    }

    #[test]
    fn rto_marks_everything_not_sacked_lost() {
        let mut q = q_with(5, 100);
        q.sack(1100, 1200, |_| ());
        q.on_retransmit(0, 9);
        q.mark_all_lost();
        assert_eq!(q.lost_bytes(), 400);
        assert_eq!(q.retrans_bytes(), 0);
        assert_eq!(q.pipe(500), 0);
        assert_eq!(q.next_lost(), Some(0));
        q.debug_valid(1000, 1500).unwrap();
    }

    #[test]
    fn find_and_wraparound() {
        let mut q = RtxQueue::new();
        let base = u32::MAX - 150;
        for k in 0..4u32 {
            q.push(Seg {
                start: base.wrapping_add(k * 100),
                end: base.wrapping_add((k + 1) * 100),
                ..Seg::default()
            });
        }
        assert_eq!(q.find(base.wrapping_add(250)), Some(2));
        assert_eq!(q.find(base.wrapping_add(400)), None);
        assert_eq!(
            q.sack(base.wrapping_add(100), base.wrapping_add(300), |_| ()),
            200
        );
        q.debug_valid(base, base.wrapping_add(400)).unwrap();
    }
}
