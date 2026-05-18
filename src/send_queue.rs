//! Send queue: per-transmission metadata used by RACK and TLP.
//!
//! Records every outbound payload-carrying segment (new data, selective
//! retransmit, TLP probe) along with its send timestamp. Pruned by
//! cumulative ACK (drops entries fully covered) and SACK (drops entries
//! fully covered by SACK ranges).
//!
//! Capacity is bounded at [`SEND_QUEUE_CAP`] (1024 entries × 24 B = 24 KiB
//! per connection). Sized to comfortably cover `BUF_CAP / MSS` so RACK
//! can detect loss of any segment currently in flight. Overflow evicts
//! the OLDEST entry, which is the only safe choice — the oldest entry
//! is either already past RACK's reo_wnd (and would be marked lost on
//! the next scan anyway) or has been outstanding so long that RTO would
//! fire before RACK could rescue it.

use crate::scoreboard::SackScoreboard;

/// Bound on the number of in-flight segments RACK can track. Sized for
/// `BUF_CAP=1 MiB` at MSS=1448 ≈ 720 segments, with margin.
pub const SEND_QUEUE_CAP: usize = 1024;

/// One transmission record. Layout chosen to keep it compact (24 B).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SendEntry {
    /// First sequence number carried by the segment.
    pub seq_start: u32,
    /// One past the last sequence number (half-open).
    pub seq_end: u32,
    /// `now_ms` at the moment of transmission.
    pub send_ts_ms: u64,
    /// True if this transmission was a retransmit (selective retransmit
    /// or TLP probe); false for new data. Not used directly by RACK but
    /// useful for diagnostics.
    pub is_retx: bool,
}

/// Append-only ring of send entries with FIFO eviction.
pub struct SendQueue {
    /// Circular buffer.
    entries: [SendEntry; SEND_QUEUE_CAP],
    /// Index of the oldest valid entry.
    head: usize,
    /// Number of valid entries (head..head+len, wrapping at SEND_QUEUE_CAP).
    len: usize,
}

impl SendQueue {
    pub const fn new() -> Self {
        const EMPTY: SendEntry = SendEntry {
            seq_start: 0,
            seq_end: 0,
            send_ts_ms: 0,
            is_retx: false,
        };
        Self {
            entries: [EMPTY; SEND_QUEUE_CAP],
            head: 0,
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Append an entry. On overflow, evict the oldest.
    pub fn push_entry(&mut self, entry: SendEntry) {
        if self.len == SEND_QUEUE_CAP {
            // Overflow: drop oldest, advance head.
            self.head = (self.head + 1) % SEND_QUEUE_CAP;
            self.len -= 1;
        }
        let idx = (self.head + self.len) % SEND_QUEUE_CAP;
        if let Some(slot) = self.entries.get_mut(idx) {
            *slot = entry;
            self.len += 1;
        }
    }

    /// Record a new transmission: `[seq, seq+len)` at `send_ts_ms`.
    pub fn push(&mut self, seq: u32, len: u32, send_ts_ms: u64, is_retx: bool) {
        if len == 0 {
            return;
        }
        self.push_entry(SendEntry {
            seq_start: seq,
            seq_end: seq.wrapping_add(len),
            send_ts_ms,
            is_retx,
        });
    }

    /// Iterate entries in insertion order (oldest first). Convenient for
    /// RACK scans.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            queue: self,
            index: 0,
        }
    }

    /// Remove all entries fully covered by `snd_una` (cumulative ACK
    /// progress) OR by any SACK range in `scoreboard`. Partially
    /// covered entries are kept whole; RACK still wants the original
    /// send-ts for the unsacked portion.
    pub fn prune(&mut self, snd_una: u32, scoreboard: &SackScoreboard) {
        // Compact in place: walk all entries, keep those still needed.
        let mut write = 0usize;
        for read in 0..self.len {
            let idx = (self.head + read) % SEND_QUEUE_CAP;
            let entry = match self.entries.get(idx) {
                Some(e) => *e,
                None => continue,
            };
            if seq_le(entry.seq_end, snd_una) {
                continue; // fully ACKed
            }
            if scoreboard_covers(scoreboard, entry.seq_start, entry.seq_end) {
                continue; // fully SACKed
            }
            let write_idx = (self.head + write) % SEND_QUEUE_CAP;
            if let Some(slot) = self.entries.get_mut(write_idx) {
                *slot = entry;
                write += 1;
            }
        }
        self.len = write;
    }

    /// Find the most recent send entry whose seq range covers `seq`.
    /// Used by `process_ack` to pull the send-ts of the segment that
    /// delivered a newly-SACKed byte. "Most recent" because retransmits
    /// create overlapping entries — the latest one is the one whose
    /// delivery this ACK most likely reflects.
    pub fn find_latest_covering(&self, seq: u32) -> Option<SendEntry> {
        let mut best: Option<SendEntry> = None;
        for entry in self.iter() {
            let covers = seq_le(entry.seq_start, seq) && seq_gt(entry.seq_end, seq);
            if covers {
                match best {
                    Some(b) if b.send_ts_ms >= entry.send_ts_ms => {}
                    _ => best = Some(*entry),
                }
            }
        }
        best
    }

    /// Find the highest-seq entry that hasn't been fully SACKed — used
    /// by TLP to pick the probe target.
    pub fn highest_unsacked(&self, scoreboard: &SackScoreboard) -> Option<SendEntry> {
        let mut best: Option<SendEntry> = None;
        for entry in self.iter() {
            if scoreboard_covers(scoreboard, entry.seq_start, entry.seq_end) {
                continue;
            }
            match best {
                Some(b) if seq_gt(b.seq_end, entry.seq_end) => {}
                _ => best = Some(*entry),
            }
        }
        best
    }
}

impl Default for SendQueue {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Iter<'a> {
    queue: &'a SendQueue,
    index: usize,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a SendEntry;
    fn next(&mut self) -> Option<&'a SendEntry> {
        if self.index >= self.queue.len {
            return None;
        }
        let idx = (self.queue.head + self.index) % SEND_QUEUE_CAP;
        self.index += 1;
        self.queue.entries.get(idx)
    }
}

/// Does the scoreboard fully cover `[seq_start, seq_end)`?
fn scoreboard_covers(scoreboard: &SackScoreboard, seq_start: u32, seq_end: u32) -> bool {
    for r in scoreboard.ranges() {
        if seq_le(r.left, seq_start) && seq_le(seq_end, r.right) {
            return true;
        }
    }
    false
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    extern crate std;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn push_pop_basic() {
        let mut q = SendQueue::new();
        assert!(q.is_empty());
        q.push(100, 100, 1, false);
        q.push(200, 100, 2, false);
        assert_eq!(q.len(), 2);
        let entries: Vec<SendEntry> = q.iter().copied().collect();
        assert_eq!(entries[0].seq_start, 100);
        assert_eq!(entries[1].seq_start, 200);
    }

    #[test]
    fn overflow_evicts_oldest() {
        let mut q = SendQueue::new();
        for i in 0..(SEND_QUEUE_CAP + 5) {
            q.push(i as u32 * 100, 100, i as u64, false);
        }
        assert_eq!(q.len(), SEND_QUEUE_CAP);
        // Oldest 5 entries should have been evicted; first remaining is i=5.
        let first = q.iter().next().unwrap();
        assert_eq!(first.send_ts_ms, 5);
    }

    #[test]
    fn prune_drops_acked_entries() {
        let mut q = SendQueue::new();
        let sb = SackScoreboard::new();
        q.push(100, 100, 1, false);
        q.push(200, 100, 2, false);
        q.push(300, 100, 3, false);
        // snd_una advances past first two entries.
        q.prune(300, &sb);
        assert_eq!(q.len(), 1);
        assert_eq!(q.iter().next().unwrap().seq_start, 300);
    }

    #[test]
    fn prune_drops_sacked_entries() {
        let mut q = SendQueue::new();
        let mut sb = SackScoreboard::new();
        q.push(100, 100, 1, false);
        q.push(200, 100, 2, false);
        q.push(300, 100, 3, false);
        sb.add_range(200, 300, 100, 10_000);
        q.prune(100, &sb);
        assert_eq!(q.len(), 2); // 100 stays, 200 dropped, 300 stays
        let entries: Vec<SendEntry> = q.iter().copied().collect();
        assert_eq!(entries[0].seq_start, 100);
        assert_eq!(entries[1].seq_start, 300);
    }

    #[test]
    fn find_latest_covering_picks_newest() {
        let mut q = SendQueue::new();
        q.push(100, 100, 1, false); // original
        q.push(100, 100, 5, true);  // retransmit
        let e = q.find_latest_covering(150).unwrap();
        assert_eq!(e.send_ts_ms, 5);
        assert!(e.is_retx);
    }

    #[test]
    fn highest_unsacked() {
        let mut q = SendQueue::new();
        let mut sb = SackScoreboard::new();
        q.push(100, 100, 1, false);
        q.push(200, 100, 2, false);
        q.push(300, 100, 3, false);
        sb.add_range(300, 400, 0, 10_000);
        let e = q.highest_unsacked(&sb).unwrap();
        assert_eq!(e.seq_start, 200);
    }
}
