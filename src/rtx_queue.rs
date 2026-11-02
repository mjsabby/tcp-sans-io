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
//! An entry the path MSS has shrunk below is split before it is resent. When
//! the queue is full there is no record to split it into, so only its first
//! MSS goes out and the entry is flagged [`seg_flags::PARTIAL`] with the
//! length of that prefix, which alone counts as in flight. Once the whole
//! prefix is acknowledged, the rest is lost again and resent at once rather
//! than at the next RTO.
//!
//! In-flight accounting follows RFC 6675 `pipe` (and Linux):
//! `pipe = outstanding - sacked - lost + retrans`, where `lost` counts
//! segments marked lost and `retrans` those whose retransmission is still
//! believed to be in flight. Counters are maintained incrementally and are
//! checked against a full recount by [`RtxQueue::debug_valid`].
//!
//! Capacity is the const parameter `CAP` (default [`RTX_QUEUE_CAP`]); the
//! sender never transmits new data while the queue is full, so the bound is
//! a cap on segments in flight (≈1.4 MiB at a 1448-byte MSS by default —
//! above the default 1 MiB window; [`rtx_cap_for`] keeps that ratio for
//! smaller rings).
//!
//! A per-slot bitmap mirrors the `SACKED` flag so SACK processing and the
//! RACK scan step over SACKed runs a 64-slot word at a time: an ACK whose
//! blocks span an already SACKed queue (every duplicate ACK of a recovery
//! episode — or a hostile peer repeating one) costs a binary search and at
//! most 16 bitmap words per block, not a walk over every segment.

/// Default, and largest, number of segments in flight.
pub const RTX_QUEUE_CAP: usize = 1024;

/// Words in the per-slot SACKed bitmap, sized for the largest capacity (a
/// `[u64; CAP / 64]` would need `generic_const_exprs`): a queue uses the
/// first `CAP / 64`. `CAP` is a multiple of 64, so a word never spans the
/// ring's wrap point.
const SACK_WORDS: usize = RTX_QUEUE_CAP / 64;

/// Retransmission-queue capacity for a `buf`-byte send ring: one record per
/// KiB (as the default 1024 for 1 MiB: ≈1.4 per 1448-byte segment the ring
/// holds), rounded up to a multiple of 64 and clamped to
/// `64..=`[`RTX_QUEUE_CAP`]. For [`crate::Tcb`]'s `RTX` parameter.
pub const fn rtx_cap_for(buf: usize) -> usize {
    let cap = (buf / 1024).div_ceil(64) * 64;
    if cap < 64 {
        64
    } else if cap > RTX_QUEUE_CAP {
        RTX_QUEUE_CAP
    } else {
        cap
    }
}

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
    /// Only a prefix of the segment, [`super::Seg::sent`] bytes, went out in
    /// its last retransmission (no record to split it at the path MSS). Set
    /// with `RETRANS`; once that whole prefix is acknowledged the rest is
    /// marked `LOST`.
    pub const PARTIAL: u8 = 1 << 5;
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
    /// With [`PARTIAL`]: how many bytes from `start` the last retransmission
    /// sent that are not yet acknowledged; 0 otherwise.
    pub sent: u16,
}

// Records stay 24 bytes: `sent` lives in what was padding.
const _: () = assert!(core::mem::size_of::<Seg>() == 24);

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

/// Bytes of a `RETRANS` segment its retransmission put back in flight: just
/// the prefix of a partial one.
#[inline]
fn retrans_len(s: &Seg) -> u32 {
    if s.has(PARTIAL) {
        u32::from(s.sent)
    } else {
        s.seq_len()
    }
}

/// Bounded FIFO of [`Seg`]s, `CAP` of them at most.
pub struct RtxQueue<const CAP: usize = RTX_QUEUE_CAP> {
    segs: [Seg; CAP],
    /// Bit `p` is set iff the segment in physical slot `p` is SACKed.
    sacked_map: [u64; SACK_WORDS],
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

impl<const CAP: usize> Default for RtxQueue<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> RtxQueue<CAP> {
    /// Bitmap words in use.
    const WORDS: usize = CAP / 64;

    /// Compile-time check that the bitmap covers `CAP` (evaluated wherever
    /// a queue of this capacity is built).
    pub(crate) const VALID: () = assert!(
        CAP > 0 && CAP.is_multiple_of(64) && CAP <= RTX_QUEUE_CAP,
        "RtxQueue capacity must be a multiple of 64 in 64..=1024"
    );

    pub const fn new() -> Self {
        let () = Self::VALID;
        Self {
            segs: [Seg {
                start: 0,
                end: 0,
                xmit_ts: 0,
                xmit_seq: 0,
                flags: 0,
                sent: 0,
            }; CAP],
            sacked_map: [0; SACK_WORDS],
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
        self.sacked_map = [0; SACK_WORDS];
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
        self.len == CAP
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
        (self.head + i) % CAP
    }

    #[inline]
    fn sacked_bit(&self, p: usize) -> bool {
        self.sacked_map
            .get(p / 64)
            .is_some_and(|w| w & (1u64 << (p % 64)) != 0)
    }

    #[inline]
    fn set_sacked_bit(&mut self, p: usize, on: bool) {
        if let Some(w) = self.sacked_map.get_mut(p / 64) {
            let m = 1u64 << (p % 64);
            if on {
                *w |= m;
            } else {
                *w &= !m;
            }
        }
    }

    /// Move the SACKed bits of the `count` slots from physical slot `from`
    /// (circularly) up one slot, as `split` moves the entries: word at a
    /// time, highest bits first, so no source bit is overwritten unread.
    fn shift_sacked_bits_up(&mut self, from: usize, count: usize) {
        let low_mask = |n: usize| if n >= 64 { !0u64 } else { (1u64 << n) - 1 };
        let mut left = count;
        while left > 0 {
            // The highest remaining source bit and the run below it in its word.
            let hi = (from + left - 1) % CAP;
            let (w, top) = (hi / 64, hi % 64);
            let n = left.min(top + 1);
            let lo = top + 1 - n;
            let src = (self.sacked_map.get(w).copied().unwrap_or(0) >> lo) & low_mask(n);
            // Bit 63 carries into bit 0 of the next word (wrapping the ring).
            let stay = if top == 63 {
                if let Some(next) = self.sacked_map.get_mut((w + 1) % Self::WORDS) {
                    *next = (*next & !1) | (src >> (n - 1));
                }
                n - 1
            } else {
                n
            };
            if let Some(word) = self.sacked_map.get_mut(w).filter(|_| stay > 0) {
                let mask = low_mask(stay) << (lo + 1);
                *word = (*word & !mask) | ((src & low_mask(stay)) << (lo + 1) & mask);
            }
            left -= n;
        }
    }

    /// Logical index of the first segment at or after `from` that is not
    /// SACKed. Visits at most one bitmap word per 64 slots.
    pub fn next_unsacked(&self, from: usize) -> Option<usize> {
        let mut i = from;
        while i < self.len {
            let p = self.phys(i);
            let bit = p % 64;
            let word = self.sacked_map.get(p / 64).copied().unwrap_or(0);
            // Bit k of `clear` set ⇔ slot p + k is not SACKed.
            let clear = !word >> bit;
            let span = (64 - bit).min(self.len - i);
            let k = clear.trailing_zeros() as usize;
            if k < span {
                return Some(i + k);
            }
            i += span;
        }
        None
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
            self.set_sacked_bit(p, seg.has(SACKED));
            true
        } else {
            false
        }
    }

    fn add_counts(&mut self, s: &Seg, sign: bool) {
        let apply = |c: &mut u32, n: u32| {
            *c = if sign {
                c.saturating_add(n)
            } else {
                c.saturating_sub(n)
            }
        };
        let n = s.seq_len();
        if s.has(SACKED) {
            apply(&mut self.sacked, n);
        }
        if s.has(LOST) {
            apply(&mut self.lost, n);
        }
        if s.has(RETRANS) {
            apply(&mut self.retrans, retrans_len(s));
        }
    }

    /// Replace segment `i`'s flags, keeping the counters consistent.
    fn set_flags(&mut self, i: usize, flags: u8) {
        let sent = self.get(i).map_or(0, |s| s.sent);
        self.set_state(i, flags, sent);
    }

    /// Replace segment `i`'s flags and [`Seg::sent`] (dropped without
    /// `PARTIAL`), keeping the counters consistent.
    fn set_state(&mut self, i: usize, flags: u8, sent: u16) {
        let Some(old) = self.get(i).copied() else {
            return;
        };
        let sent = if flags & PARTIAL != 0 { sent } else { 0 };
        let new = Seg { flags, sent, ..old };
        self.add_counts(&old, false);
        self.add_counts(&new, true);
        if let Some(s) = self.get_mut(i) {
            *s = new;
        }
        let p = self.phys(i);
        self.set_sacked_bit(p, flags & SACKED != 0);
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
        // Shift entries i+1.. up by one (and their SACKed bits with them).
        let mut j = self.len;
        while j > i + 1 {
            let src = self.segs.get(self.phys(j - 1)).copied();
            let dst = self.phys(j);
            if let (Some(v), Some(d)) = (src, self.segs.get_mut(dst)) {
                *d = v;
            }
            j -= 1;
        }
        self.shift_sacked_bits_up(self.phys(i + 1), self.len - (i + 1));
        self.len += 1;
        let mut lower = Seg {
            end: at,
            flags: s.flags & !FIN,
            ..s
        };
        let mut upper = Seg { start: at, ..s };
        if s.has(PARTIAL) {
            // Each half keeps the part of the resent prefix it holds; a half
            // the prefix does not reach is lost.
            let (below, sent) = (at.wrapping_sub(s.start), u32::from(s.sent));
            if below <= sent {
                lower.flags &= !PARTIAL;
                lower.sent = 0;
            }
            if below < sent {
                upper.sent = (sent - below) as u16;
            } else {
                upper.flags = (s.flags | LOST) & !(RETRANS | PARTIAL);
                upper.sent = 0;
            }
            self.add_counts(&s, false);
            self.add_counts(&lower, true);
            self.add_counts(&upper, true);
        }
        if let Some(d) = self.get_mut(i) {
            *d = lower;
        }
        if let Some(d) = self.get_mut(i + 1) {
            *d = upper;
        }
        let p = self.phys(i + 1);
        self.set_sacked_bit(p, s.has(SACKED));
        if i + 1 < self.lost_hint {
            self.lost_hint += 1;
        }
        if s.has(PARTIAL) && upper.has(LOST) && !upper.has(RETRANS) {
            self.lost_hint = self.lost_hint.min(i + 1);
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
                self.head = (self.head + 1) % CAP;
                self.len -= 1;
                self.lost_hint = self.lost_hint.saturating_sub(1);
            } else if seq_lt(s.start, una) {
                // Partially acknowledged: trim the head.
                f(&s, !s.has(SACKED));
                self.add_counts(&s, false);
                let acked = una.wrapping_sub(s.start);
                let mut trimmed = Seg { start: una, ..s };
                if s.has(PARTIAL) {
                    if acked < u32::from(s.sent) {
                        // Part of the resent prefix is still in flight.
                        trimmed.sent = (u32::from(s.sent) - acked) as u16;
                    } else {
                        // All of it arrived; the rest was not resent.
                        trimmed.flags = (s.flags | LOST) & !(RETRANS | PARTIAL);
                        trimmed.sent = 0;
                        self.lost_hint = 0;
                    }
                }
                self.add_counts(&trimmed, true);
                removed = removed.saturating_add(acked);
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
            if s.has(SACKED) {
                // Step over the whole SACKed run at once.
                match self.next_unsacked(i + 1) {
                    Some(j) => {
                        i = j;
                        continue;
                    }
                    None => break,
                }
            }
            if seq_lt(r, s.end) {
                // Block ends inside this segment: split, then SACK the lower part.
                if !self.split(i, r) {
                    break;
                }
                continue;
            }
            if seq_le(l, s.start) {
                let nf = (s.flags | SACKED) & !(LOST | RETRANS | PARTIAL);
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
                self.set_flags(i, (s.flags | LOST) & !(RETRANS | PARTIAL));
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
        self.retransmitted(i, now, 0);
    }

    /// Record a retransmission at `now` of only the first `sent` (> 0) bytes
    /// of segment `i` (see [`seg_flags::PARTIAL`]).
    pub fn on_partial_retransmit(&mut self, i: usize, now: u64, sent: u16) {
        self.retransmitted(i, now, sent);
    }

    /// `sent` > 0: only that prefix was resent.
    fn retransmitted(&mut self, i: usize, now: u64, sent: u16) {
        if let Some(s) = self.get(i).copied() {
            let partial = if sent > 0 { PARTIAL } else { 0 };
            let flags = ((s.flags | RETRANS | EVER_RETRANS) & !PARTIAL) | partial;
            self.set_state(i, flags, sent);
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
            if self.sacked_bit(self.phys(i)) != s.has(SACKED) {
                return Err("rtx: SACKed bitmap out of sync");
            }
            if s.has(RETRANS) && !s.has(EVER_RETRANS) {
                return Err("rtx: RETRANS without EVER_RETRANS");
            }
            if s.has(PARTIAL) {
                if !s.has(RETRANS) {
                    return Err("rtx: PARTIAL without RETRANS");
                }
                if s.sent == 0 || u32::from(s.sent) >= s.payload_len() {
                    return Err("rtx: PARTIAL prefix not inside the segment");
                }
            } else if s.sent != 0 {
                return Err("rtx: resent prefix without PARTIAL");
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
                retrans += retrans_len(s);
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
                sent: 0,
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

    /// A partial retransmission puts only its prefix back in flight. An ACK
    /// inside the prefix just shortens it; once all of it is acknowledged,
    /// by a cumulative ACK or a SACK block that splits it off, the rest of
    /// the segment, never resent, is lost.
    #[test]
    fn partial_retransmission_leaves_the_rest_lost() {
        let mut q = q_with(3, 1000);
        q.on_partial_retransmit(0, 9, 500); // a tail-loss probe: not marked lost
        assert_eq!(q.next_lost(), None);
        q.ack_to(1001, |_, _| ());
        assert_eq!(q.next_lost(), None, "the rest of the prefix is in flight");
        assert_eq!((q.lost_bytes(), q.retrans_bytes()), (0, 499));
        q.debug_valid(1001, 4000).unwrap();
        q.ack_to(1500, |_, _| ());
        assert_eq!(q.next_lost(), Some(0));
        assert_eq!((q.lost_bytes(), q.retrans_bytes()), (500, 0));
        q.debug_valid(1500, 4000).unwrap();

        let mut q = q_with(3, 1000);
        q.mark_lost(1);
        q.on_partial_retransmit(1, 9, 500);
        assert_eq!(q.pipe(3000), 2500, "only the prefix is in flight");
        assert_eq!(q.sack(2000, 2200, |_| ()), 200);
        assert_eq!(q.next_lost(), None, "the rest of the prefix is in flight");
        assert_eq!(q.retrans_bytes(), 300);
        assert_eq!(q.sack(2200, 2500, |_| ()), 300);
        assert_eq!(q.next_lost(), Some(3));
        assert_eq!(q.get(3).map(|s| (s.start, s.end)), Some((2500, 3000)));
        assert_eq!((q.lost_bytes(), q.retrans_bytes()), (500, 0));
        q.debug_valid(1000, 4000).unwrap();
    }

    #[test]
    fn find_and_wraparound() {
        let mut q: RtxQueue = RtxQueue::new();
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

    /// Also at capacities below the bitmap's: their last word wraps to word 0.
    #[test]
    fn sacked_bitmap_shift_matches_a_bit_by_bit_move() {
        shift_matches_a_bit_by_bit_move::<RTX_QUEUE_CAP>();
        shift_matches_a_bit_by_bit_move::<256>();
        shift_matches_a_bit_by_bit_move::<64>();
    }

    fn shift_matches_a_bit_by_bit_move<const CAP: usize>() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..2_000 {
            let mut q = RtxQueue::<CAP>::new();
            for w in q.sacked_map.iter_mut() {
                *w = rnd();
            }
            let from = (rnd() % CAP as u64) as usize;
            let count = (rnd() % CAP as u64) as usize;
            let mut want = q.sacked_map;
            let bit = |m: &[u64; SACK_WORDS], p: usize| m[p / 64] >> (p % 64) & 1;
            for k in (0..count).rev() {
                let (s, d) = ((from + k) % CAP, (from + k + 1) % CAP);
                let b = bit(&want, s);
                want[d / 64] = (want[d / 64] & !(1 << (d % 64))) | (b << (d % 64));
            }
            q.shift_sacked_bits_up(from, count);
            assert_eq!(q.sacked_map, want, "cap {CAP} from {from} count {count}");
        }
    }

    #[test]
    fn next_unsacked_skips_runs_across_words_and_the_ring_wrap() {
        let mut q = q_with(1000, 10);
        // Move the head so the live range wraps the ring's end.
        q.ack_to(1000 + 900 * 10, |_, _| ());
        for k in 1000..1900u32 {
            assert!(q.push(Seg {
                start: 1000 + k * 10,
                end: 1000 + (k + 1) * 10,
                ..Seg::default()
            }));
        }
        let first = q.get(0).unwrap().start;
        assert_eq!(q.len(), 1000);
        // SACK everything except logical 0, 130 and 999.
        q.sack(first + 10, first + 1300, |_| ());
        q.sack(first + 1310, first + 9990, |_| ());
        q.debug_valid(first, first + 10_000).unwrap();
        assert_eq!(q.next_unsacked(0), Some(0));
        assert_eq!(q.next_unsacked(1), Some(130));
        assert_eq!(q.next_unsacked(131), Some(999));
        assert_eq!(q.next_unsacked(1000), None);
        // A repeated block over the SACKed runs only adds the hole at 130.
        assert_eq!(q.sack(first + 10, first + 9990, |_| ()), 10);
        assert_eq!(q.sack(first + 10, first + 9990, |_| ()), 0);
        // Splitting keeps the bitmap aligned with the shifted entries.
        assert!(q.split(0, first + 5));
        q.debug_valid(first, first + 10_000).unwrap();
        assert_eq!(q.next_unsacked(2), Some(999 + 1));
        // Cumulative ACK past the run; reused (formerly SACKed) slots start
        // un-SACKed.
        q.ack_to(first + 9990, |_, _| ());
        assert!(q.push(Seg {
            start: first + 10_000,
            end: first + 10_010,
            ..Seg::default()
        }));
        assert_eq!(q.next_unsacked(0), Some(0));
        assert_eq!(q.next_unsacked(1), Some(1));
        q.debug_valid(first + 9990, first + 10_010).unwrap();
    }
}
