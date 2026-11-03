//! Out-of-order receive tracking.
//!
//! Out-of-order payload is parked directly in the receive ring's free space
//! at its final position (see [`crate::ring::Ring::write_at`]), so the whole
//! advertised window can be held while a hole is repaired. This module only
//! tracks *which* sequence ranges beyond `RCV.NXT` are present.
//!
//! Ranges are kept sorted, disjoint and non-adjacent. The list is bounded by
//! [`OOO_MAX_RANGES`], sized so the default 1 MiB window can be held even
//! when every other segment is lost (the hole pattern a slow-start overshoot
//! leaves at a tail-drop bottleneck). A segment that would need a new range
//! when the list is full is rejected (not stored, not SACKed) and the sender
//! retransmits it. Nothing that has been SACKed is ever discarded (no
//! reneging). Lookups are binary searches; per-segment cost stays O(log n)
//! for the common append and O(n) word moves only when a hole closes.

use crate::wire::SackBlocks;

/// Maximum number of disjoint out-of-order ranges (holes + 1) tracked:
/// one per two full segments of receive buffer, at least 32, at most 512.
pub const OOO_MAX_RANGES: usize = {
    let n = crate::BUF_CAP / 2048;
    if n < 32 {
        32
    } else if n > 512 {
        512
    } else {
        n
    }
};

#[derive(Copy, Clone, Debug, Default)]
struct Range {
    start: u32,
    end: u32,
    /// Recency stamp: SACK blocks are reported most-recent first (RFC 2018 §4).
    tag: u32,
}

/// Outcome of [`OooList::insert`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Insert {
    /// The range was recorded (possibly merged). `dup`: the lowest run of
    /// it that was already held, which a D-SACK reports (Linux
    /// `tcp_data_queue_ofo` sets one for a partial overlap too);
    /// `dup_bytes`: how many of its bytes were already held in all.
    Stored {
        dup: Option<(u32, u32)>,
        dup_bytes: u32,
    },
    /// No room for another disjoint range; the segment must be dropped.
    Full,
}

impl Insert {
    /// Recorded, and nothing of it was held before.
    pub const NEW: Self = Self::Stored {
        dup: None,
        dup_bytes: 0,
    };
}

/// Sorted set of out-of-order sequence ranges above `RCV.NXT`.
pub struct OooList {
    ranges: [Range; OOO_MAX_RANGES],
    len: usize,
    next_tag: u32,
}

impl Default for OooList {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn off(seq: u32, base: u32) -> u32 {
    seq.wrapping_sub(base)
}

impl OooList {
    pub const fn new() -> Self {
        Self {
            ranges: [Range {
                start: 0,
                end: 0,
                tag: 0,
            }; OOO_MAX_RANGES],
            len: 0,
            next_tag: 1,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.next_tag = 1;
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn slice(&self) -> &[Range] {
        self.ranges.get(..self.len).unwrap_or(&[])
    }

    /// Lowest held sequence number, if any.
    pub fn first_start(&self) -> Option<u32> {
        self.slice().first().map(|r| r.start)
    }

    /// End of the highest held range, if any.
    pub fn last_end(&self) -> Option<u32> {
        self.slice().last().map(|r| r.end)
    }

    /// Total sequence bytes held.
    pub fn held_bytes(&self) -> u32 {
        self.slice()
            .iter()
            .fold(0u32, |a, r| a.saturating_add(r.end.wrapping_sub(r.start)))
    }

    /// Record `[start, end)` (all strictly above `rcv_nxt`) as held.
    pub fn insert(&mut self, start: u32, end: u32, rcv_nxt: u32) -> Insert {
        self.insert_with(start, end, rcv_nxt, |_, _| {})
    }

    /// [`Self::insert`], calling `new(l, r)` for each run of `[start, end)`
    /// that was not held before (none if the list is full), so only those
    /// bytes are stored: a byte already held keeps its first copy (RFC 9293
    /// §3.10.7.4 keeps just the new data; Linux `tcp_data_queue_ofo` drops
    /// a wholly duplicate segment).
    pub fn insert_with(
        &mut self,
        start: u32,
        end: u32,
        rcv_nxt: u32,
        mut new: impl FnMut(u32, u32),
    ) -> Insert {
        let (s, e) = (off(start, rcv_nxt), off(end, rcv_nxt));
        if s == 0 || e <= s {
            return Insert::NEW;
        }
        // Offsets from RCV.NXT are monotonic across the sorted list.
        // `lo`: first range ending at/after `s` (could merge or follow);
        // `hi`: one past the last range starting at/before `e`.
        let lo = self.slice().partition_point(|r| off(r.end, rcv_nxt) < s);
        let hi = lo
            + self
                .slice()
                .get(lo..)
                .map_or(0, |t| t.partition_point(|r| off(r.start, rcv_nxt) <= e));
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        if hi == lo {
            // Disjoint from everything: insert a new range at `lo`.
            if self.len == OOO_MAX_RANGES {
                return Insert::Full;
            }
            new(start, end);
            // Shift `lo..len` up one slot (the spare slot at `len` rotates
            // to `lo` and is overwritten).
            if let Some(t) = self.ranges.get_mut(lo..=self.len) {
                t.rotate_right(1);
                if let Some(slot) = t.first_mut() {
                    *slot = Range { start, end, tag };
                }
            }
            self.len += 1;
            return Insert::NEW;
        }
        // Merge ranges lo..hi with the new one.
        let (first, last) = match (
            self.ranges.get(lo).copied(),
            self.ranges.get(hi - 1).copied(),
        ) {
            (Some(f), Some(l)) => (f, l),
            _ => return Insert::Full,
        };
        let mut dup = None;
        let mut dup_bytes = 0u32;
        // `cur`: how far `[s, e)` is accounted for, held or reported new.
        let mut cur = s;
        for r in self.slice().get(lo..hi).unwrap_or(&[]) {
            let (rs, re) = (off(r.start, rcv_nxt), off(r.end, rcv_nxt));
            let is = rs.max(s);
            let ie = re.min(e);
            if is < ie {
                dup.get_or_insert((rcv_nxt.wrapping_add(is), rcv_nxt.wrapping_add(ie)));
                dup_bytes += ie - is;
            }
            if rs > cur {
                new(rcv_nxt.wrapping_add(cur), rcv_nxt.wrapping_add(rs.min(e)));
            }
            cur = cur.max(re);
        }
        if cur < e {
            new(rcv_nxt.wrapping_add(cur), end);
        }
        let m_start = if off(first.start, rcv_nxt) < s {
            first.start
        } else {
            start
        };
        let m_end = if off(last.end, rcv_nxt) > e {
            last.end
        } else {
            end
        };
        if let Some(slot) = self.ranges.get_mut(lo) {
            *slot = Range {
                start: m_start,
                end: m_end,
                tag,
            };
        }
        let removed = hi - lo - 1;
        if removed > 0 {
            if let Some(t) = self.ranges.get_mut(lo + 1..self.len) {
                t.rotate_left(removed);
            }
            self.len -= removed;
        }
        Insert::Stored { dup, dup_bytes }
    }

    /// Forget everything held at or beyond `limit` (> `rcv_nxt`), trimming a
    /// range that straddles it. Used once the peer's FIN position is known.
    pub fn truncate_from(&mut self, limit: u32, rcv_nxt: u32) {
        let lim = off(limit, rcv_nxt);
        // Ranges before `k` end at or below the limit and are kept whole.
        let k = self.slice().partition_point(|r| off(r.end, rcv_nxt) <= lim);
        let mut keep = k;
        if k < self.len {
            if let Some(r) = self.ranges.get_mut(k) {
                if off(r.start, rcv_nxt) < lim {
                    r.end = limit;
                    keep = k + 1;
                }
            }
        }
        self.len = self.len.min(keep);
    }

    /// `RCV.NXT` has advanced to `rcv_nxt`. Drop ranges now at or below it
    /// and, if a held range starts at or before `rcv_nxt`, consume it.
    /// Returns the new `RCV.NXT` (the end of the consumed contiguous run).
    pub fn advance(&mut self, rcv_nxt: u32) -> u32 {
        let mut nxt = rcv_nxt;
        let mut drop = 0;
        for r in self.slice() {
            // Wrap-aware: is r.start at or before nxt?
            if (r.start.wrapping_sub(nxt) as i32) <= 0 {
                if (r.end.wrapping_sub(nxt) as i32) > 0 {
                    nxt = r.end;
                }
                drop += 1;
            } else {
                break;
            }
        }
        if drop > 0 {
            if let Some(t) = self.ranges.get_mut(..self.len) {
                t.rotate_left(drop);
            }
            self.len -= drop;
        }
        nxt
    }

    /// A fresh recency stamp, for an out-of-order FIN reported alongside
    /// the ranges (see [`Self::fill_sack_blocks`]).
    pub fn take_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        tag
    }

    /// Whether a held range ends exactly at `seq`.
    pub fn ends_at(&self, seq: u32) -> bool {
        self.slice().iter().any(|r| r.end == seq)
    }

    /// Append up to `max` (≤ 4) SACK blocks, most recently changed first.
    /// `fin`: an out-of-order FIN `(seq, tag)` held beyond `RCV.NXT`. Its
    /// sequence number is SACKed too, as Linux reports a FIN segment's
    /// `end_seq`: it extends the block of the data that ends at it, or is
    /// a block of its own (a bare FIN).
    pub fn fill_sack_blocks(&self, sack: &mut SackBlocks, max: usize, fin: Option<(u32, u32)>) {
        // Single pass keeping the `k` youngest ranges. Ages are measured
        // back from `next_tag`, so tag wrap-around is harmless.
        let k = max.min(4);
        let age = |tag: u32| self.next_tag.wrapping_sub(tag);
        let keep = |top: &mut [Option<Range>; 4], mut cand: Range| {
            for slot in top.iter_mut().take(k) {
                match slot {
                    None => {
                        *slot = Some(cand);
                        break;
                    }
                    Some(held) if age(cand.tag) < age(held.tag) => core::mem::swap(held, &mut cand),
                    Some(_) => {}
                }
            }
        };
        let mut top: [Option<Range>; 4] = [None; 4];
        let mut fin_merged = false;
        for &r in self.slice() {
            let mut r = r;
            if let Some((f, tag)) = fin.filter(|&(f, _)| f == r.end) {
                r.end = f.wrapping_add(1);
                if age(tag) < age(r.tag) {
                    r.tag = tag;
                }
                fin_merged = true;
            }
            keep(&mut top, r);
        }
        if let Some((f, tag)) = fin.filter(|_| !fin_merged) {
            let end = f.wrapping_add(1);
            keep(&mut top, Range { start: f, end, tag });
        }
        for r in top.iter().take(k).flatten() {
            sack.push(r.start, r.end);
        }
    }

    /// Range containing `seq`, if any.
    pub fn containing(&self, seq: u32) -> Option<(u32, u32)> {
        self.slice()
            .iter()
            .find(|r| {
                (seq.wrapping_sub(r.start) as i32) >= 0 && (r.end.wrapping_sub(seq) as i32) > 0
            })
            .map(|r| (r.start, r.end))
    }

    /// Held bytes below `end` (in-order data from `rcv_nxt` up to `end`
    /// arrived, so they were received twice): the lowest such run and the
    /// total.
    pub fn overlap_below(&self, end: u32, rcv_nxt: u32) -> (Option<(u32, u32)>, u32) {
        let lim = off(end, rcv_nxt);
        let mut first = None;
        let mut total = 0u32;
        for r in self.slice() {
            if off(r.start, rcv_nxt) >= lim {
                break;
            }
            let stop = if off(r.end, rcv_nxt) < lim {
                r.end
            } else {
                end
            };
            first.get_or_insert((r.start, stop));
            total = total.saturating_add(stop.wrapping_sub(r.start));
        }
        (first, total)
    }

    /// Debug invariant: sorted, disjoint, non-adjacent, all above `rcv_nxt`.
    pub fn debug_valid(&self, rcv_nxt: u32) -> bool {
        let mut prev_end: Option<u32> = None;
        for r in self.slice() {
            let (s, e) = (off(r.start, rcv_nxt), off(r.end, rcv_nxt));
            if s == 0 || e <= s || e > i32::MAX as u32 {
                return false;
            }
            if let Some(p) = prev_end {
                if s <= p {
                    return false;
                }
            }
            prev_end = Some(e);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn blocks(l: &OooList, max: usize) -> std::vec::Vec<(u32, u32)> {
        let mut s = SackBlocks::EMPTY;
        l.fill_sack_blocks(&mut s, max, None);
        s.as_slice().to_vec()
    }

    #[test]
    fn merges_overlapping_and_adjacent_ranges() {
        let mut l = OooList::new();
        assert_eq!(l.insert(200, 300, 100), Insert::NEW);
        assert_eq!(l.insert(400, 500, 100), Insert::NEW);
        assert_eq!(l.insert(300, 400, 100), Insert::NEW); // bridges both
        assert_eq!(l.len(), 1);
        assert_eq!(l.held_bytes(), 300);
        assert_eq!(
            l.insert(250, 450, 100),
            Insert::Stored {
                dup: Some((250, 450)),
                dup_bytes: 200
            }
        );
        assert!(l.debug_valid(100));
    }

    #[test]
    fn advance_consumes_contiguous_prefix() {
        let mut l = OooList::new();
        l.insert(200, 300, 100);
        l.insert(400, 500, 100);
        assert_eq!(l.advance(150), 150, "hole at 150..200 still open");
        assert_eq!(l.advance(200), 300, "range starting at rcv_nxt is consumed");
        assert_eq!(l.len(), 1);
        assert_eq!(l.advance(450), 500, "range straddling rcv_nxt is consumed");
        assert!(l.is_empty());
    }

    #[test]
    fn sack_blocks_are_most_recent_first() {
        let mut l = OooList::new();
        l.insert(200, 300, 100);
        l.insert(600, 700, 100);
        l.insert(400, 500, 100);
        assert_eq!(blocks(&l, 3), [(400, 500), (600, 700), (200, 300)]);
        assert_eq!(blocks(&l, 1), [(400, 500)]);
    }

    #[test]
    fn full_list_rejects_new_disjoint_range_but_merges_adjacent() {
        let mut l = OooList::new();
        for i in 0..OOO_MAX_RANGES as u32 {
            let s = 1000 + i * 100;
            assert_eq!(l.insert(s, s + 10, 0), Insert::NEW);
        }
        let beyond = 1000 + OOO_MAX_RANGES as u32 * 100 + 1000;
        assert_eq!(l.insert(beyond, beyond + 10, 0), Insert::Full);
        assert_eq!(l.insert(1010, 1020, 0), Insert::NEW);
        assert_eq!(l.len(), OOO_MAX_RANGES);
        assert!(l.debug_valid(0));
    }

    #[test]
    fn alternating_holes_across_a_full_window_are_all_held() {
        // A slow-start overshoot at a tail-drop queue loses every other
        // segment: the whole default window must still be held and SACKed.
        let mut l = OooList::new();
        let mss = 1448u32;
        let window = crate::BUF_CAP as u32;
        let mut k = 1;
        while (2 * k + 1) * mss <= window && (k as usize) <= OOO_MAX_RANGES {
            let s = 2 * k * mss;
            assert_eq!(l.insert(s, s + mss, 0), Insert::NEW, "range {k}");
            k += 1;
        }
        assert!(
            crate::BUF_CAP < 256 * 1024 || l.len() >= 360,
            "held {}",
            l.len()
        );
        assert!(l.debug_valid(0));
        assert_eq!(blocks(&l, 3)[0].0, 2 * (k - 1) * mss, "newest first");
    }

    #[test]
    fn sack_block_order_survives_tag_wraparound() {
        let mut l = OooList::new();
        l.next_tag = u32::MAX - 1;
        l.insert(200, 300, 100);
        l.insert(600, 700, 100); // tag wraps here
        l.insert(400, 500, 100);
        assert_eq!(blocks(&l, 3), [(400, 500), (600, 700), (200, 300)]);
    }

    #[test]
    fn merge_spanning_many_ranges_and_out_of_order_inserts() {
        let mut l = OooList::new();
        for s in [900u32, 500, 700, 300] {
            l.insert(s, s + 50, 100);
        }
        assert_eq!(l.len(), 4);
        // Partly held: the lowest held run is the D-SACK, all of it duplicates.
        assert_eq!(
            l.insert(320, 920, 100),
            Insert::Stored {
                dup: Some((320, 350)),
                dup_bytes: 30 + 50 + 50 + 20
            }
        );
        assert_eq!(l.len(), 1);
        assert_eq!(l.containing(600), Some((300, 950)));
        assert!(l.debug_valid(100));
    }

    #[test]
    fn truncate_from_trims_straddling_range_and_drops_later_ones() {
        let mut l = OooList::new();
        l.insert(200, 300, 100);
        l.insert(400, 500, 100);
        l.insert(600, 700, 100);
        l.truncate_from(450, 100);
        assert_eq!(l.len(), 2);
        assert_eq!(l.last_end(), Some(450));
        assert!(l.debug_valid(100));
        l.truncate_from(400, 100);
        assert_eq!(
            (l.len(), l.last_end()),
            (1, Some(300)),
            "range ending at the limit kept"
        );
        l.truncate_from(150, 100);
        assert!(l.is_empty());
    }

    #[test]
    fn wraps_around_sequence_space() {
        let mut l = OooList::new();
        let base = u32::MAX - 50;
        l.insert(base.wrapping_add(100), base.wrapping_add(200), base);
        l.insert(base.wrapping_add(10), base.wrapping_add(20), base);
        assert!(l.debug_valid(base));
        assert_eq!(l.first_start(), Some(base.wrapping_add(10)));
        assert_eq!(l.advance(base.wrapping_add(10)), base.wrapping_add(20));
    }
    /// Only the runs not held before are reported new, across several
    /// held ranges, and none when the list is full.
    #[test]
    fn insert_with_reports_only_new_runs() {
        let mut l = OooList::new();
        l.insert(110, 120, 100);
        l.insert(130, 140, 100);
        let mut new = std::vec::Vec::new();
        let r = l.insert_with(105, 145, 100, |a, b| new.push((a, b)));
        assert_eq!(new, [(105, 110), (120, 130), (140, 145)]);
        assert_eq!(
            r,
            Insert::Stored {
                dup: Some((110, 120)),
                dup_bytes: 20
            }
        );
        new.clear();
        l.insert_with(112, 118, 100, |a, b| new.push((a, b)));
        assert!(new.is_empty(), "a wholly held run reported new: {new:?}");
    }
}
