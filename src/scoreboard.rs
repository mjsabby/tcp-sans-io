//! Sender-side SACK scoreboard for RFC 6675 selective retransmit.
//!
//! Tracks contiguous SACKed ranges above `snd_una`. Bounded capacity;
//! overflow evicts the **highest** ranges (preserves the lowest, which
//! are most relevant to advancing snd_una). Wrap-aware via the same
//! serial-number arithmetic used elsewhere in the stack.
//!
//! The scoreboard's operations are all O(N) in `SCOREBOARD_CAP` (fixed
//! at 16) — negligible on the hot path.
//!
//! Used by `Tcb::process_ack` to absorb incoming SACK blocks and by
//! `Tcb::maybe_send_data` to drive the NextSeg() retransmit algorithm.

/// Maximum number of disjoint SACKed ranges we track. RFC 6675 doesn't
/// specify; 16 comfortably absorbs the merged result of several
/// 4-block SACK options arriving across an RTT.
pub const SCOREBOARD_CAP: usize = 16;

/// One contiguous SACKed range, expressed as `[left, right)` (half-open).
/// `right - left` is the byte count, modulo wrap-around (we assume the
/// total window is < 2^31 bytes, which the stack already asserts).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Range {
    pub left: u32,
    pub right: u32,
}

impl Range {
    #[inline]
    pub fn len(&self) -> u32 {
        self.right.wrapping_sub(self.left)
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.left == self.right
    }
    #[inline]
    pub fn contains(&self, seq: u32) -> bool {
        // seq ∈ [left, right) in wrap-aware sense.
        let offset = seq.wrapping_sub(self.left);
        offset < self.len()
    }
}

/// Sender-side scoreboard. Ranges are kept sorted by `(left - snd_una)`
/// modulo 2^32 — the actual ordering for "above snd_una".
pub struct SackScoreboard {
    ranges: [Range; SCOREBOARD_CAP],
    len: usize,
    /// `snd_una` value at the time of the last prune; cached so callers
    /// can pass it around without storing it themselves.
    una: u32,
}

impl SackScoreboard {
    pub const fn new() -> Self {
        Self {
            ranges: [Range { left: 0, right: 0 }; SCOREBOARD_CAP],
            len: 0,
            una: 0,
        }
    }
}

impl Default for SackScoreboard {
    fn default() -> Self {
        Self::new()
    }
}

impl SackScoreboard {

    pub fn clear(&mut self) {
        self.len = 0;
        for r in self.ranges.iter_mut() {
            r.left = 0;
            r.right = 0;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn ranges(&self) -> &[Range] {
        self.ranges.get(..self.len).unwrap_or(&[])
    }

    /// Drop any range fully at or below `snd_una`, clip any range that
    /// straddles `snd_una` to start at `snd_una`. Must be called on every
    /// cumulative-ACK advance.
    pub fn prune_below(&mut self, snd_una: u32) {
        self.una = snd_una;
        let mut write = 0usize;
        for read in 0..self.len {
            let r = match self.ranges.get(read) {
                Some(r) => *r,
                None => continue,
            };
            // Fully below snd_una?
            if seq_le(r.right, snd_una) {
                continue; // drop
            }
            // Straddles? Clip left edge.
            let mut clipped = r;
            if seq_lt(r.left, snd_una) {
                clipped.left = snd_una;
            }
            if clipped.is_empty() {
                continue;
            }
            if let Some(slot) = self.ranges.get_mut(write) {
                *slot = clipped;
                write += 1;
            }
        }
        // Zero out trailing slots so the scoreboard's debug dump is clean.
        for k in write..self.len {
            if let Some(slot) = self.ranges.get_mut(k) {
                slot.left = 0;
                slot.right = 0;
            }
        }
        self.len = write;
    }

    /// Absorb a new SACK block, with overlap / adjacency merging. Drops
    /// invalid blocks (`left >= right`, or fully above `snd_max`).
    /// If the scoreboard overflows after adding+merging, evict the
    /// HIGHEST range (the lowest are more important for snd_una progress).
    pub fn add_range(&mut self, mut left: u32, mut right: u32, snd_una: u32, snd_max: u32) {
        // Drop ill-formed.
        if seq_le(right, left) {
            return;
        }
        // Clip to the valid window [snd_una, snd_max].
        if seq_le(left, snd_una) {
            left = snd_una;
        }
        if seq_lt(snd_max, right) {
            right = snd_max;
        }
        if seq_le(right, left) {
            return;
        }
        let new = Range { left, right };

        // Try to merge with any existing overlapping/adjacent range.
        // We do this in a loop because merging may chain: a new range
        // can connect two previously-separate ranges into one.
        let mut merged_into: Option<usize> = None;
        for i in 0..self.len {
            let existing = match self.ranges.get(i) {
                Some(r) => *r,
                None => continue,
            };
            if overlap_or_adjacent(existing, new) {
                let union = union_of(existing, new);
                if let Some(slot) = self.ranges.get_mut(i) {
                    *slot = union;
                }
                merged_into = Some(i);
                break;
            }
        }
        if let Some(i) = merged_into {
            // Cascade-merge: if the now-extended range absorbs other
            // ranges that became adjacent.
            self.cascade_merge_from(i);
            self.normalize();
            return;
        }

        // No merge target — append if there's room, else evict highest.
        if self.len < SCOREBOARD_CAP {
            if let Some(slot) = self.ranges.get_mut(self.len) {
                *slot = new;
                self.len += 1;
            }
        } else {
            // Find the range with the highest start (in wrap-aware sense
            // above una) and replace it if the new range is lower; otherwise
            // drop the new range. This biases retention toward lower seqs
            // (closer to snd_una, hence more important).
            let mut highest = 0usize;
            for i in 1..self.len {
                let cur = match self.ranges.get(i) {
                    Some(r) => *r,
                    None => continue,
                };
                let cur_off = cur.left.wrapping_sub(self.una);
                let hi = match self.ranges.get(highest) {
                    Some(r) => *r,
                    None => continue,
                };
                let hi_off = hi.left.wrapping_sub(self.una);
                if cur_off > hi_off {
                    highest = i;
                }
            }
            let hi = match self.ranges.get(highest) {
                Some(r) => *r,
                None => return,
            };
            let new_off = new.left.wrapping_sub(self.una);
            let hi_off = hi.left.wrapping_sub(self.una);
            if new_off < hi_off {
                if let Some(slot) = self.ranges.get_mut(highest) {
                    *slot = new;
                }
            }
            // else: silently drop — new range is even higher than what
            // we'd evict, no improvement.
        }
        self.normalize();
    }

    /// Bytes SACKed strictly above `seq` (used by IsLost and pipe calcs).
    pub fn sacked_above(&self, seq: u32) -> u32 {
        let mut total: u32 = 0;
        for r in self.ranges() {
            if seq_le(r.right, seq) {
                continue;
            }
            // Clip the range to start at max(seq, r.left).
            let left = if seq_lt(r.left, seq) { seq } else { r.left };
            if seq_le(r.right, left) {
                continue;
            }
            total = total.saturating_add(r.right.wrapping_sub(left));
        }
        total
    }

    /// Compute how many bytes in `[left, right)` are NOT yet covered by
    /// the scoreboard, after clipping to `[snd_una, snd_max]`. Used by
    /// RACK + PRR to derive newly-delivered evidence from incoming SACK
    /// blocks BEFORE the scoreboard absorbs them. Repeated SACKs report
    /// 0 newly-covered, so RACK markers don't get spuriously bumped.
    pub fn bytes_newly_covered(
        &self,
        mut left: u32,
        mut right: u32,
        snd_una: u32,
        snd_max: u32,
    ) -> u32 {
        // Clip to window.
        if seq_le(right, left) {
            return 0;
        }
        if seq_le(left, snd_una) {
            left = snd_una;
        }
        if seq_lt(snd_max, right) {
            right = snd_max;
        }
        if seq_le(right, left) {
            return 0;
        }
        // Subtract existing scoreboard overlap from [left, right).
        // Approach: walk SCOREBOARD_CAP ranges, accumulate the bytes
        // they cover within [left, right), and return remainder.
        let total = right.wrapping_sub(left);
        let mut covered: u32 = 0;
        for r in self.ranges() {
            // Intersection with [left, right).
            let il = if seq_lt(r.left, left) { left } else { r.left };
            let ir = if seq_lt(r.right, right) { r.right } else { right };
            if seq_lt(il, ir) {
                covered = covered.saturating_add(ir.wrapping_sub(il));
            }
        }
        total.saturating_sub(covered)
    }

    /// First unsacked sub-range within `[left, right)`. Returns `None` if
    /// the whole input range is covered (or invalid). Used by the RACK
    /// retransmit path to avoid resending bytes the peer already SACKed.
    pub fn first_unsacked_subrange(&self, left: u32, right: u32) -> Option<(u32, u32)> {
        if seq_le(right, left) {
            return None;
        }
        let mut cursor = left;
        while seq_lt(cursor, right) {
            // If cursor is inside any SACK range, jump to its right edge.
            let mut advanced = false;
            for r in self.ranges() {
                if r.contains(cursor) {
                    cursor = r.right;
                    advanced = true;
                    break;
                }
            }
            if advanced {
                continue;
            }
            // cursor is in a gap. Find the next SACK left-edge above it
            // (if any) and return [cursor, min(next_left, right)).
            let mut gap_end = right;
            for r in self.ranges() {
                if seq_gt(r.left, cursor) && seq_lt(r.left, gap_end) {
                    gap_end = r.left;
                }
            }
            return Some((cursor, gap_end));
        }
        None
    }

    /// Total bytes currently SACKed across all ranges.
    pub fn sacked_bytes(&self) -> u32 {
        self.sacked_above(self.una)
    }

    /// RFC 6675 §4 `IsLost(seq)`: returns true iff at least
    /// `DupThresh * MSS` bytes of SACKed data lie strictly above `seq`.
    /// `DupThresh` is fixed at 3 per RFC 5681.
    pub fn is_lost(&self, seq: u32, mss: u32) -> bool {
        const DUP_THRESH: u32 = 3;
        let threshold = mss.saturating_mul(DUP_THRESH);
        self.sacked_above(seq) >= threshold
    }

    /// `NextSeg(start)`: the lowest sequence ≥ max(start, snd_una) that:
    ///   * lies below snd_max,
    ///   * isn't already covered by a SACK range,
    ///   * satisfies IsLost (sufficient SACKed data above it).
    ///
    /// Returns `(seq, length)` of the contiguous unSACKed run to
    /// retransmit, capped at `mss` bytes.
    ///
    /// If no IsLost-qualifying gap exists, returns `None`. Callers fall
    /// back to either rescue-retransmit (the seq just below the
    /// highest SACK) or sending new data per the slow-start formula.
    pub fn next_seg(&self, start: u32, snd_max: u32, mss: u32) -> Option<(u32, u32)> {
        if seq_le(snd_max, start) {
            return None;
        }
        // Scan upward from `start`, skipping over SACK ranges. The result
        // is the first gap-start in [start, snd_max) that IsLost holds for.
        let mut cursor = start;
        while seq_lt(cursor, snd_max) {
            // If cursor is inside a SACK range, jump to its right edge.
            let mut advanced = false;
            for r in self.ranges() {
                if r.contains(cursor) {
                    cursor = r.right;
                    advanced = true;
                    break;
                }
            }
            if advanced {
                continue;
            }
            // cursor is in a gap. Determine the gap's right edge: the
            // smallest SACK left-edge above cursor, or snd_max.
            let mut gap_end = snd_max;
            for r in self.ranges() {
                if seq_gt(r.left, cursor) && seq_lt(r.left, gap_end) {
                    gap_end = r.left;
                }
            }
            let gap_len = gap_end.wrapping_sub(cursor);
            // IsLost check: enough SACKed data above cursor?
            if self.is_lost(cursor, mss) {
                let take = core::cmp::min(gap_len, mss);
                return Some((cursor, take));
            }
            cursor = gap_end;
        }
        None
    }

    // ---- helpers ----

    /// After a merge into slot `i`, look for more overlaps that might
    /// have become adjacent. Repeat until none.
    fn cascade_merge_from(&mut self, mut i: usize) {
        loop {
            let base = match self.ranges.get(i) {
                Some(r) => *r,
                None => return,
            };
            let mut found: Option<usize> = None;
            for j in 0..self.len {
                if j == i {
                    continue;
                }
                let other = match self.ranges.get(j) {
                    Some(r) => *r,
                    None => continue,
                };
                if overlap_or_adjacent(base, other) {
                    found = Some(j);
                    break;
                }
            }
            let Some(j) = found else { return };
            let other = match self.ranges.get(j) {
                Some(r) => *r,
                None => return,
            };
            let union = union_of(base, other);
            if let Some(slot) = self.ranges.get_mut(i) {
                *slot = union;
            }
            // Remove slot j by swapping with last; len--.
            self.len -= 1;
            if j < self.len {
                let last = match self.ranges.get(self.len) {
                    Some(r) => *r,
                    None => return,
                };
                if let Some(slot) = self.ranges.get_mut(j) {
                    *slot = last;
                }
                // After swap, the slot we cared about may have moved.
                if i == self.len {
                    i = j;
                }
            }
            if let Some(slot) = self.ranges.get_mut(self.len) {
                slot.left = 0;
                slot.right = 0;
            }
        }
    }

    /// Sort ranges by `(left - una)` ascending so the lowest-seq ones come
    /// first. Insertion sort: tiny N, runtime irrelevant.
    fn normalize(&mut self) {
        let una = self.una;
        for i in 1..self.len {
            let mut j = i;
            while j > 0 {
                let prev_off = match self.ranges.get(j - 1) {
                    Some(r) => r.left.wrapping_sub(una),
                    None => break,
                };
                let cur_off = match self.ranges.get(j) {
                    Some(r) => r.left.wrapping_sub(una),
                    None => break,
                };
                if cur_off < prev_off {
                    self.ranges.swap(j - 1, j);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
    }
}

#[inline]
fn overlap_or_adjacent(a: Range, b: Range) -> bool {
    // Two half-open ranges [a.l, a.r) and [b.l, b.r) are mergeable iff
    // a.l <= b.r AND b.l <= a.r (with wrap awareness).
    seq_le(a.left, b.right) && seq_le(b.left, a.right)
}

#[inline]
fn union_of(a: Range, b: Range) -> Range {
    Range {
        left: if seq_lt(a.left, b.left) { a.left } else { b.left },
        right: if seq_gt(a.right, b.right) { a.right } else { b.right },
    }
}

// ---- Wrap-aware comparisons (same semantics as tcb.rs's helpers) ----

#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn empty_scoreboard_returns_none() {
        let sb = SackScoreboard::new();
        assert!(sb.is_empty());
        assert_eq!(sb.sacked_above(100), 0);
        assert!(!sb.is_lost(100, 1460));
        assert_eq!(sb.next_seg(0, 0, 1460), None);
    }

    #[test]
    fn add_range_basic() {
        let mut sb = SackScoreboard::new();
        sb.add_range(100, 200, 0, 10_000);
        assert_eq!(sb.ranges().len(), 1);
        assert_eq!(sb.ranges()[0], Range { left: 100, right: 200 });
        assert_eq!(sb.sacked_above(0), 100);
        assert_eq!(sb.sacked_above(150), 50);
        assert_eq!(sb.sacked_above(200), 0);
    }

    #[test]
    fn add_range_merges_adjacent() {
        let mut sb = SackScoreboard::new();
        sb.add_range(100, 200, 0, 10_000);
        sb.add_range(200, 300, 0, 10_000);
        assert_eq!(sb.ranges().len(), 1);
        assert_eq!(sb.ranges()[0], Range { left: 100, right: 300 });
    }

    #[test]
    fn add_range_merges_overlapping() {
        let mut sb = SackScoreboard::new();
        sb.add_range(100, 200, 0, 10_000);
        sb.add_range(150, 250, 0, 10_000);
        assert_eq!(sb.ranges().len(), 1);
        assert_eq!(sb.ranges()[0], Range { left: 100, right: 250 });
    }

    #[test]
    fn add_range_drops_invalid() {
        let mut sb = SackScoreboard::new();
        sb.add_range(200, 100, 0, 10_000); // left > right
        sb.add_range(100, 100, 0, 10_000); // empty
        sb.add_range(50, 80, 100, 10_000); // fully below snd_una
        sb.add_range(11_000, 12_000, 0, 10_000); // fully above snd_max
        assert!(sb.is_empty());
    }

    #[test]
    fn prune_below_clips_straddler() {
        let mut sb = SackScoreboard::new();
        sb.add_range(100, 300, 0, 10_000);
        sb.add_range(500, 600, 0, 10_000);
        sb.prune_below(200);
        assert_eq!(sb.ranges().len(), 2);
        assert_eq!(sb.ranges()[0], Range { left: 200, right: 300 });
        assert_eq!(sb.ranges()[1], Range { left: 500, right: 600 });
    }

    #[test]
    fn next_seg_returns_first_lost_gap() {
        let mut sb = SackScoreboard::new();
        // Holes: [0, 1000), gap, [1000, 2000) SACKed, gap, [4000, 5000) SACKed
        // snd_max = 7000, mss = 1000.
        // sacked above 0 = 2000 → ≥ 3*MSS? No (3000). NOT lost.
        sb.add_range(1000, 2000, 0, 7000);
        sb.add_range(4000, 5000, 0, 7000);
        assert_eq!(sb.next_seg(0, 7000, 1000), None);
        // Add one more 1000-byte SACK → 3000 sacked above seq=0 → IS lost.
        sb.add_range(6000, 7000, 0, 7000);
        let seg = sb.next_seg(0, 7000, 1000).expect("should find a lost gap");
        assert_eq!(seg, (0, 1000));
    }

    #[test]
    fn next_seg_skips_sacked_ranges() {
        let mut sb = SackScoreboard::new();
        // SACK ranges: [1000, 2000), [3000, 4000), [5000, 6000), [7000, 8000)
        // Total sacked above 0 = 4000 → IsLost(0) true.
        sb.add_range(1000, 2000, 0, 10_000);
        sb.add_range(3000, 4000, 0, 10_000);
        sb.add_range(5000, 6000, 0, 10_000);
        sb.add_range(7000, 8000, 0, 10_000);
        // Start at 0: cursor=0 (gap). IsLost(0)? 4000 bytes sacked above
        // → true. Gap [0, 1000) returned.
        let seg = sb.next_seg(0, 10_000, 1000).expect("lost gap @0");
        assert_eq!(seg, (0, 1000));
        // Start at 1000 (already SACKed): skip to gap [2000, 3000).
        // IsLost(2000)? sacked_above(2000) = 3000 ≥ 3000 → true.
        let seg = sb.next_seg(1000, 10_000, 1000).expect("lost gap @2000");
        assert_eq!(seg, (2000, 1000));
        // Start at 4000: gap [4000, 5000). IsLost(4000)?
        // sacked_above(4000) = 2000 < 3000 → false. Skip ahead.
        // Gap [6000, 7000): IsLost(6000) = 1000 → false.
        // Gap [8000, 10_000): IsLost(8000) = 0 → false.
        // Result: None.
        assert_eq!(sb.next_seg(4000, 10_000, 1000), None);
    }
}
