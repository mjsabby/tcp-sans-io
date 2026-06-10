//! Multi-hole TCP receive reassembly buffer.
//!
//! Replaces the original single-hole `oo_buf` + `(oo_start, oo_len)` with a
//! bounded-capacity structure that can hold up to `MAX_HOLES` disjoint
//! contiguous runs of out-of-order data. This is what lets the receiver
//! report multi-block SACK to the sender (RFC 2018 §3), which in turn
//! lets an RFC 6675 sender selectively retransmit only the actual gaps.
//!
//! Storage layout: a single fixed-size byte arena divided into `MAX_HOLES`
//! equal slots. Each slot holds one contiguous run of bytes plus its
//! starting sequence number. Slots are allocated greedily on insert and
//! freed on drain; ranges that don't fit (too many simultaneous holes, or
//! a single run larger than `SLOT_CAP`) are dropped — the sender will
//! retransmit them via the RTO safety net.
//!
//! Operations are bounded-time in `MAX_HOLES` (small, fixed at 4), not
//! in the held byte count. Adjacent ranges are merged on insert, so the
//! data structure always represents the minimum set of disjoint runs.

use crate::REASM_CAP;

/// Maximum number of disjoint holes the reassembler will track. Linux
/// uses ~16 in practice; 4 is enough for the per-RTT loss-pattern
/// diversity in our target use cases (WireGuard tunnels with light to
/// moderate loss). Capped tightly to keep the per-connection footprint
/// honest.
pub const MAX_HOLES: usize = 4;

/// Per-slot capacity in bytes (equal partition of `REASM_CAP`).
pub const SLOT_CAP: usize = REASM_CAP / MAX_HOLES;

/// One stored out-of-order range. `len == 0` means the slot is unused.
#[derive(Copy, Clone, Debug)]
struct Slot {
    /// Starting sequence number of the held data.
    start: u32,
    /// Number of valid bytes in `data[..len]`.
    len: usize,
    /// Backing storage. Fixed-size for zero-allocation discipline.
    data: [u8; SLOT_CAP],
    /// Order of insertion (monotonic counter). Lets the SACK emitter
    /// surface the most-recently-changed range first per RFC 2018 §4.
    inserted_at: u32,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            start: 0,
            len: 0,
            data: [0u8; SLOT_CAP],
            inserted_at: 0,
        }
    }

    #[inline]
    fn is_used(&self) -> bool {
        self.len > 0
    }

    #[inline]
    fn end(&self) -> u32 {
        self.start.wrapping_add(self.len as u32)
    }
}

/// Multi-hole reassembly buffer.
pub struct Reassembly {
    slots: [Slot; MAX_HOLES],
    /// Monotonic counter for `Slot::inserted_at`; wraps harmlessly.
    next_tag: u32,
}

impl Reassembly {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::empty(); MAX_HOLES],
            next_tag: 1,
        }
    }
}

impl Default for Reassembly {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembly {
    /// Clear all held data. Used on connection teardown / RESET / listener
    /// recycle.
    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.start = 0;
            slot.len = 0;
            slot.inserted_at = 0;
        }
        self.next_tag = 1;
    }

    /// Total bytes currently held across all slots. Subtracted from the
    /// receive ring's free space to compute the advertised window.
    pub fn held_bytes(&self) -> usize {
        let mut n = 0;
        for slot in &self.slots {
            n += slot.len;
        }
        n
    }

    pub fn is_empty(&self) -> bool {
        self.held_bytes() == 0
    }

    /// Debug invariant: no two held runs overlap. The whole structure relies
    /// on this — overlapping slots double-count [`Self::held_bytes`] (shrinking
    /// the advertised window) and can strand a run below `rcv_nxt` where it can
    /// never drain (a receive-side wedge). `O(MAX_HOLES²)` (≤ 16 comparisons),
    /// invoked only by test / fuzz oracles, never on the hot path.
    pub fn debug_overlap_free(&self) -> bool {
        for i in 0..MAX_HOLES {
            let a = match self.slots.get(i) {
                Some(s) if s.is_used() => s,
                _ => continue,
            };
            for j in (i + 1)..MAX_HOLES {
                let b = match self.slots.get(j) {
                    Some(s) if s.is_used() => s,
                    _ => continue,
                };
                // Half-open [start, end) ranges overlap iff each starts before
                // the other ends (wrap-aware; held runs always lie within the
                // receive window, so the < 2^31 span assumption holds).
                if seq_lt(a.start, b.end()) && seq_lt(b.start, a.end()) {
                    return false;
                }
            }
        }
        true
    }

    /// Insert an out-of-order payload at `seq`. Bytes that overlap with
    /// already-held data are silently discarded (idempotent on retransmit).
    /// If the new bytes abut an existing slot they extend it (and may
    /// trigger merges with the neighbouring slot on the other side).
    /// If no slot is available and the new range doesn't abut anything,
    /// the segment is dropped — the sender will retransmit per RTO.
    ///
    /// `rcv_nxt` is the receiver's next-expected sequence; any payload
    /// bytes at or below `rcv_nxt` are dropped before insertion.
    ///
    /// Returns the number of bytes actually stored (or 0 if dropped).
    pub fn insert(&mut self, mut seq: u32, mut payload: &[u8], rcv_nxt: u32) -> usize {
        if payload.is_empty() {
            return 0;
        }
        // Trim leading bytes that lie at or below rcv_nxt — those belong
        // to the in-order path and the caller should have already
        // absorbed them.
        let lead = rcv_nxt.wrapping_sub(seq) as i32;
        if lead > 0 {
            let lead = lead as usize;
            if lead >= payload.len() {
                return 0;
            }
            if let Some(p) = payload.get(lead..) {
                payload = p;
                seq = seq.wrapping_add(lead as u32);
            } else {
                return 0;
            }
        }
        if payload.is_empty() {
            return 0;
        }

        // Reduce the incoming range to the largest gap that (a) starts at or
        // after `seq` and (b) overlaps nothing already held, so the structural
        // invariant "slots never overlap" is preserved. Without this, a segment
        // that starts *inside* an existing slot (a right / middle overlap, the
        // mirror image of the left overlap below) gets stored as a second,
        // overlapping slot. That is remotely triggerable and harmful twice over:
        // `held_bytes()` then double-counts the overlap — under-reporting the
        // advertised receive window for the life of the connection — and once
        // the lower slot drains, the higher slot is stranded with
        // `start < rcv_nxt` and can never be drained, wedging `rcv_nxt` even
        // though the peer already saw those bytes ACK/SACKed. Trailing bytes
        // past the first gap are dropped; the sender's RTO retransmits them,
        // exactly as for any other range that doesn't fit.
        //
        // (a) Skip a leading prefix already covered by a slot. Re-scan after
        //     each advance because the new `seq` may land inside another slot.
        //     Bounded: at most `MAX_HOLES` disjoint slots can cover the prefix.
        for _ in 0..=MAX_HOLES {
            let mut advanced = false;
            for i in 0..MAX_HOLES {
                let Some(slot) = self.slots.get(i) else {
                    continue;
                };
                if !slot.is_used() {
                    continue;
                }
                if seq_le(slot.start, seq) && seq_lt(seq, slot.end()) {
                    let skip = slot.end().wrapping_sub(seq) as usize;
                    if skip >= payload.len() {
                        return 0; // fully covered by this slot
                    }
                    match payload.get(skip..) {
                        Some(p) => {
                            payload = p;
                            seq = seq.wrapping_add(skip as u32);
                            advanced = true;
                        }
                        None => return 0,
                    }
                    break;
                }
            }
            if !advanced {
                break;
            }
        }
        if payload.is_empty() {
            return 0;
        }
        // (b) Clip the trailing edge so the kept range stops before the next
        //     slot, leaving a range disjoint from everything already held.
        let mut new_end = seq.wrapping_add(payload.len() as u32);
        for i in 0..MAX_HOLES {
            let Some(slot) = self.slots.get(i) else {
                continue;
            };
            if !slot.is_used() {
                continue;
            }
            if seq_lt(seq, slot.start) && seq_lt(slot.start, new_end) {
                new_end = slot.start;
            }
        }
        let keep = new_end.wrapping_sub(seq) as usize;
        if keep == 0 {
            return 0;
        }
        if keep < payload.len() {
            match payload.get(..keep) {
                Some(p) => payload = p,
                None => return 0,
            }
        }

        let new_end = seq.wrapping_add(payload.len() as u32);

        // First, try to extend an existing slot.
        for i in 0..MAX_HOLES {
            let used;
            let s_start;
            let s_end;
            let s_len;
            if let Some(slot) = self.slots.get(i) {
                used = slot.is_used();
                s_start = slot.start;
                s_end = slot.end();
                s_len = slot.len;
            } else {
                continue;
            }
            if !used {
                continue;
            }
            if seq == s_end {
                // Append. Bounded by SLOT_CAP.
                let space = SLOT_CAP - s_len;
                let n = core::cmp::min(payload.len(), space);
                if n == 0 {
                    return 0;
                }
                let tag = self.bump_tag();
                if let Some(slot) = self.slots.get_mut(i) {
                    let dst_off = slot.len;
                    if let (Some(dst), Some(src)) =
                        (slot.data.get_mut(dst_off..dst_off + n), payload.get(..n))
                    {
                        dst.copy_from_slice(src);
                    }
                    slot.len += n;
                    slot.inserted_at = tag;
                }
                self.maybe_merge(i);
                return n;
            }
            if new_end == s_start {
                // Prepend. Bounded by SLOT_CAP.
                let space = SLOT_CAP - s_len;
                let n = core::cmp::min(payload.len(), space);
                if n == 0 {
                    return 0;
                }
                let tag = self.bump_tag();
                if let Some(slot) = self.slots.get_mut(i) {
                    // Shift existing bytes right by `n`.
                    let kept = core::cmp::min(slot.len, SLOT_CAP - n);
                    slot.data.copy_within(0..kept, n);
                    if let (Some(dst), Some(src)) =
                        (slot.data.get_mut(..n), payload.get(payload.len() - n..))
                    {
                        dst.copy_from_slice(src);
                    }
                    slot.start = seq.wrapping_add((payload.len() - n) as u32);
                    slot.len = kept + n;
                    slot.inserted_at = tag;
                }
                self.maybe_merge(i);
                return n;
            }
        }

        // Couldn't extend anything; try to allocate a fresh slot.
        for i in 0..MAX_HOLES {
            let is_free = match self.slots.get(i) {
                Some(s) => !s.is_used(),
                None => continue,
            };
            if !is_free {
                continue;
            }
            let n = core::cmp::min(payload.len(), SLOT_CAP);
            if n == 0 {
                return 0;
            }
            let tag = self.bump_tag();
            if let Some(slot) = self.slots.get_mut(i) {
                if let (Some(dst), Some(src)) = (slot.data.get_mut(..n), payload.get(..n)) {
                    dst.copy_from_slice(src);
                }
                slot.start = seq;
                slot.len = n;
                slot.inserted_at = tag;
            }
            self.maybe_merge(i);
            return n;
        }

        // Out of slots and no abutment — drop. Sender's RTO will recover.
        0
    }

    /// Drain any prefix of contiguous data starting at exactly `rcv_nxt`.
    /// Returns a slice of bytes the caller should write into the receive
    /// ring; the caller passes back how many it actually consumed via
    /// `commit_drain`. If the ring fills mid-drain, the rest stays held.
    ///
    /// This API shape (lend bytes, then commit) avoids requiring an
    /// owning Vec inside the no_std arena.
    pub fn ready_slot(&self, rcv_nxt: u32) -> Option<(usize, u32, usize)> {
        for i in 0..MAX_HOLES {
            let slot = self.slots.get(i)?;
            if !slot.is_used() {
                continue;
            }
            if slot.start == rcv_nxt {
                return Some((i, slot.start, slot.len));
            }
        }
        None
    }

    /// Get an immutable view of slot `i`'s held bytes.
    pub fn slot_bytes(&self, i: usize) -> &[u8] {
        let slot = match self.slots.get(i) {
            Some(s) => s,
            None => return &[],
        };
        slot.data.get(..slot.len).unwrap_or(&[])
    }

    /// Consume the first `n` bytes of slot `i` (the caller successfully
    /// wrote them into the receive ring). `n == slot.len` frees the slot.
    pub fn commit_drain(&mut self, i: usize, n: usize) {
        let Some(slot) = self.slots.get_mut(i) else {
            return;
        };
        if !slot.is_used() {
            return;
        }
        let n = core::cmp::min(n, slot.len);
        if n == slot.len {
            slot.start = 0;
            slot.len = 0;
            slot.inserted_at = 0;
        } else if n > 0 {
            slot.data.copy_within(n..slot.len, 0);
            slot.start = slot.start.wrapping_add(n as u32);
            slot.len -= n;
        }
    }

    /// Populate `sack` with the held ranges' `(left, right)` edges, in
    /// most-recent-first order per RFC 2018 §4. Caps at `max_blocks`
    /// (caller computes the budget based on what other options fit).
    pub fn fill_sack_blocks(&self, sack: &mut crate::wire::SackBlocks, max_blocks: usize) {
        // Collect (tag, start, end) for active slots, sort by tag DESC.
        let mut entries: [(u32, u32, u32); MAX_HOLES] = [(0, 0, 0); MAX_HOLES];
        let mut n = 0;
        for slot in &self.slots {
            if slot.is_used() {
                if let Some(e) = entries.get_mut(n) {
                    *e = (slot.inserted_at, slot.start, slot.end());
                    n += 1;
                }
            }
        }
        // Insertion sort by tag DESC (n ≤ MAX_HOLES = 4; trivial cost).
        for i in 1..n {
            let mut j = i;
            while j > 0 {
                let prev = match entries.get(j - 1) {
                    Some(e) => *e,
                    None => break,
                };
                let cur = match entries.get(j) {
                    Some(e) => *e,
                    None => break,
                };
                if prev.0 < cur.0 {
                    entries.swap(j - 1, j);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
        let take = core::cmp::min(n, max_blocks);
        for k in 0..take {
            if let Some(e) = entries.get(k) {
                sack.push(e.1, e.2);
            }
        }
    }

    /// After modifying slot `i`, attempt to merge it with any other slot
    /// whose range now abuts (left or right). Idempotent — merges
    /// repeatedly until no more abutments remain.
    fn maybe_merge(&mut self, i: usize) {
        loop {
            let (start_i, end_i, len_i) = {
                let Some(s) = self.slots.get(i) else { return };
                if !s.is_used() {
                    return;
                }
                (s.start, s.end(), s.len)
            };
            let mut merged = false;
            for j in 0..MAX_HOLES {
                if j == i {
                    continue;
                }
                let (start_j, end_j, len_j) = {
                    let Some(s) = self.slots.get(j) else { continue };
                    if !s.is_used() {
                        continue;
                    }
                    (s.start, s.end(), s.len)
                };
                // Right abutment: slot j sits immediately after slot i.
                if end_i == start_j {
                    let space = SLOT_CAP - len_i;
                    if space == 0 {
                        continue;
                    }
                    let copy = core::cmp::min(len_j, space);
                    // Copy bytes from j into i's tail.
                    let src_bytes = {
                        let s = match self.slots.get(j) {
                            Some(s) => s,
                            None => continue,
                        };
                        let mut buf = [0u8; SLOT_CAP];
                        if let (Some(dst), Some(src)) = (buf.get_mut(..copy), s.data.get(..copy)) {
                            dst.copy_from_slice(src);
                        }
                        buf
                    };
                    if let Some(slot_i) = self.slots.get_mut(i) {
                        if let (Some(dst), Some(src)) = (
                            slot_i.data.get_mut(len_i..len_i + copy),
                            src_bytes.get(..copy),
                        ) {
                            dst.copy_from_slice(src);
                        }
                        slot_i.len += copy;
                    }
                    // Free or shrink j.
                    if let Some(slot_j) = self.slots.get_mut(j) {
                        if copy == len_j {
                            slot_j.start = 0;
                            slot_j.len = 0;
                            slot_j.inserted_at = 0;
                        } else {
                            slot_j.data.copy_within(copy..len_j, 0);
                            slot_j.start = slot_j.start.wrapping_add(copy as u32);
                            slot_j.len -= copy;
                        }
                    }
                    merged = true;
                    break;
                }
                // Left abutment: slot j sits immediately before slot i.
                if end_j == start_i {
                    // Symmetric: copy j into the front of i (shift i's
                    // existing bytes right). Bounded by SLOT_CAP space.
                    let space = SLOT_CAP - len_i;
                    if space == 0 {
                        continue;
                    }
                    let copy = core::cmp::min(len_j, space);
                    let src_bytes = {
                        let s = match self.slots.get(j) {
                            Some(s) => s,
                            None => continue,
                        };
                        let mut buf = [0u8; SLOT_CAP];
                        if let (Some(dst), Some(src)) =
                            (buf.get_mut(..copy), s.data.get(len_j - copy..len_j))
                        {
                            dst.copy_from_slice(src);
                        }
                        buf
                    };
                    if let Some(slot_i) = self.slots.get_mut(i) {
                        let kept = core::cmp::min(slot_i.len, SLOT_CAP - copy);
                        slot_i.data.copy_within(0..kept, copy);
                        if let (Some(dst), Some(src)) =
                            (slot_i.data.get_mut(..copy), src_bytes.get(..copy))
                        {
                            dst.copy_from_slice(src);
                        }
                        slot_i.start = end_j.wrapping_sub(copy as u32);
                        slot_i.len = kept + copy;
                    }
                    if let Some(slot_j) = self.slots.get_mut(j) {
                        if copy == len_j {
                            slot_j.start = 0;
                            slot_j.len = 0;
                            slot_j.inserted_at = 0;
                        } else {
                            slot_j.len -= copy;
                        }
                    }
                    merged = true;
                    break;
                }
            }
            if !merged {
                return;
            }
        }
    }

    #[inline]
    fn bump_tag(&mut self) -> u32 {
        let t = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        if self.next_tag == 0 {
            self.next_tag = 1; // never 0 (which means "free")
        }
        t
    }
}

// ---- Wrap-aware comparisons (same semantics as tcb.rs's helpers) ----

#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Drain every contiguous run starting at `*rcv_nxt`, advancing it. This
    /// mirrors `Tcb::drain_reassembly` but without a receive ring, so the test
    /// can observe exactly which bytes the reassembler can hand off in order.
    fn drain_contig(r: &mut Reassembly, rcv_nxt: &mut u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut guard = 0;
        while let Some((idx, start, len)) = r.ready_slot(*rcv_nxt) {
            assert_eq!(start, *rcv_nxt, "ready_slot must match rcv_nxt exactly");
            out.extend_from_slice(&r.slot_bytes(idx)[..len]);
            *rcv_nxt = rcv_nxt.wrapping_add(len as u32);
            r.commit_drain(idx, len);
            guard += 1;
            assert!(guard <= MAX_HOLES + 2, "drain made no progress");
        }
        out
    }

    /// A non-overlapping pair of out-of-order runs must be held verbatim and
    /// then drained in order once the gap is closed.
    #[test]
    fn disjoint_runs_reassemble_in_order() {
        let mut r = Reassembly::new();
        let a = [0xAA; 100];
        let b = [0xBB; 100];
        assert_eq!(r.insert(110, &a, 100), 100); // [110, 210)
        assert_eq!(r.insert(210, &b, 100), 100); // [210, 310) — abuts, merges
        assert_eq!(r.held_bytes(), 200);
        let filler = [0xCC; 10];
        // Simulate the gap [100,110) being delivered in order, then drain.
        let mut rcv = 110u32;
        let _ = filler;
        let drained = drain_contig(&mut r, &mut rcv);
        assert_eq!(drained.len(), 200);
        assert_eq!(rcv, 310);
        assert!(r.is_empty());
    }

    /// Regression: a run that *starts inside* an already-held run (a right /
    /// middle overlap) must not be stored as a second, overlapping slot.
    ///
    /// Overlapping slots are a remotely-triggerable defect:
    ///   * `held_bytes()` double-counts the overlap, so the advertised receive
    ///     window is under-reported for the life of the connection (a bounded
    ///     but permanent shrink), and
    ///   * once the lower slot drains, the higher slot is stranded with
    ///     `start < rcv_nxt` and can never be drained — the receiver can never
    ///     hand those bytes to the application even though it ACK/SACKed them,
    ///     wedging `rcv_nxt` (a receive-side stall no timer recovers).
    #[test]
    fn right_overlap_is_merged_not_duplicated() {
        let mut r = Reassembly::new();
        let a = [0xAA; 100]; // [100, 200)
        let b = [0xBB; 150]; // [150, 300) — starts inside `a`, extends past it
        assert_eq!(r.insert(100, &a, 0), 100);
        r.insert(150, &b, 0);

        // The distinct held span is [100, 300) = 200 bytes. A double-counting
        // overlap would report 250.
        assert_eq!(
            r.held_bytes(),
            200,
            "overlapping slots double-count held_bytes (window-shrink DoS)"
        );

        // Everything drains contiguously from 100 with nothing stranded.
        let mut rcv = 100u32;
        let drained = drain_contig(&mut r, &mut rcv);
        assert_eq!(drained.len(), 200, "stranded receive data (rcv_nxt wedge)");
        assert_eq!(rcv, 300);
        assert!(r.is_empty(), "no slot left stranded below rcv_nxt");
        // The non-overlapping regions keep their original bytes.
        assert_eq!(&drained[..50], &[0xAA; 50]); // [100,150) — only in `a`
        assert_eq!(&drained[150..], &[0xBB; 50]); // [250,300) — only in `b`
    }

    /// A run that fully spans an existing slot (overlap on both sides) must
    /// also avoid creating overlaps; the surplus is dropped (RTO-recoverable),
    /// never stored as an overlapping slot.
    #[test]
    fn spanning_overlap_keeps_disjoint_invariant() {
        let mut r = Reassembly::new();
        let mid = [0x11; 50]; // [200, 250)
        let span = [0x22; 300]; // [100, 400) — engulfs [200,250)
        assert_eq!(r.insert(200, &mid, 0), 50);
        r.insert(100, &span, 0);
        // No overlap may exist: the held total can never exceed the true span
        // [100,400) = 300 bytes.
        assert!(
            r.held_bytes() <= 300,
            "spanning insert created an overlapping slot: held={}",
            r.held_bytes()
        );
        // Whatever is held must drain in one contiguous, strictly-advancing
        // sequence from 100 (no slot stranded below rcv_nxt).
        let mut rcv = 100u32;
        let drained = drain_contig(&mut r, &mut rcv);
        assert_eq!(drained.len() as u32, rcv.wrapping_sub(100));
        assert!(r.is_empty(), "no stranded slot after spanning overlap");
    }

    /// A fully-duplicate run (already entirely covered) is dropped.
    #[test]
    fn fully_covered_run_is_dropped() {
        let mut r = Reassembly::new();
        let a = [0xAA; 200];
        assert_eq!(r.insert(100, &a, 0), 200);
        // [120,180) ⊂ [100,300): nothing new.
        let inner = [0xBB; 60];
        assert_eq!(r.insert(120, &inner, 0), 0);
        assert_eq!(r.held_bytes(), 200);
    }
}
