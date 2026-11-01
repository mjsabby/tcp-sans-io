//! A seeded discrete-event link and a stack-independent wire observer.
//!
//! The link models what `bindings/netem/bench.sh` builds with namespaces:
//! one-way delay, a rate-limited bottleneck with a tail-drop queue, random
//! loss, reordering, duplication and corruption. The observer counts, from
//! the bytes on the wire alone, what each stack retransmitted and how much
//! of that the receiver already had — the same yardstick for both stacks.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};

use crate::pkt;
use crate::stacks::{Pkt, Time};

/// xorshift64* — deterministic and dependency-free.
#[derive(Clone)]
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(crate::stacks::splitmix(seed) | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    pub fn ppm(&mut self, ppm: u32) -> bool {
        ppm > 0 && self.next() % 1_000_000 < u64::from(ppm)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LinkCfg {
    pub delay_us: u64,
    /// Bottleneck rate in bit/s (0 = unlimited).
    pub rate_bps: u64,
    /// Bottleneck queue in packets (tail drop).
    pub queue: usize,
    pub loss_ppm: u32,
    pub reorder_ppm: u32,
    pub reorder_us: u64,
    pub dup_ppm: u32,
    pub corrupt_ppm: u32,
    /// Drop data-carrying packets whose link-entry index is in `[lo, hi)`.
    pub drop_data: (u64, u64),
    /// Drop the first `n` SYN-carrying packets.
    pub drop_syns: u32,
}

impl LinkCfg {
    pub const fn new(delay_ms: u64, rate_mbit: u64, queue: usize) -> Self {
        Self {
            delay_us: delay_ms * 1000,
            rate_bps: rate_mbit * 1_000_000,
            queue,
            loss_ppm: 0,
            reorder_ppm: 0,
            reorder_us: 0,
            dup_ppm: 0,
            corrupt_ppm: 0,
            drop_data: (0, 0),
            drop_syns: 0,
        }
    }
    pub const fn delay_us(mut self, us: u64) -> Self {
        self.delay_us = us;
        self
    }
    pub const fn loss(mut self, ppm: u32) -> Self {
        self.loss_ppm = ppm;
        self
    }
    pub const fn reorder(mut self, ppm: u32, extra_ms: u64) -> Self {
        self.reorder_ppm = ppm;
        self.reorder_us = extra_ms * 1000;
        self
    }
    pub const fn dup(mut self, ppm: u32) -> Self {
        self.dup_ppm = ppm;
        self
    }
    pub const fn corrupt(mut self, ppm: u32) -> Self {
        self.corrupt_ppm = ppm;
        self
    }
    pub const fn drop_data(mut self, lo: u64, hi: u64) -> Self {
        self.drop_data = (lo, hi);
        self
    }
    pub const fn drop_syns(mut self, n: u32) -> Self {
        self.drop_syns = n;
        self
    }
}

/// Sorted, disjoint `[lo, hi)` ranges.
#[derive(Default, Clone, Debug)]
pub struct RangeSet(Vec<(u64, u64)>);

impl RangeSet {
    pub fn overlap(&self, lo: u64, hi: u64) -> u64 {
        let i = self.0.partition_point(|&(_, e)| e <= lo);
        self.0[i..]
            .iter()
            .take_while(|&&(s, _)| s < hi)
            .map(|&(s, e)| e.min(hi) - s.max(lo))
            .sum()
    }
    pub fn insert(&mut self, lo: u64, hi: u64) {
        if lo >= hi {
            return;
        }
        let i = self.0.partition_point(|&(_, e)| e < lo);
        let mut j = i;
        let (mut nl, mut nh) = (lo, hi);
        while j < self.0.len() && self.0[j].0 <= hi {
            nl = nl.min(self.0[j].0);
            nh = nh.max(self.0[j].1);
            j += 1;
        }
        self.0.splice(i..j, [(nl, nh)]);
    }
    /// The range holding `x`.
    pub fn range_of(&self, x: u64) -> Option<(u64, u64)> {
        let i = self.0.partition_point(|&(_, e)| e <= x);
        self.0.get(i).copied().filter(|&(s, _)| s <= x)
    }
}

/// Map a 32-bit sequence offset onto 64 bits, nearest to `reference`.
fn unwrap(rel: u32, reference: u64) -> u64 {
    let v = (reference & !0xFFFF_FFFF) | u64::from(rel);
    if v > reference + (1 << 31) && v >= 1 << 32 {
        v - (1 << 32)
    } else if v + (1 << 31) < reference {
        v + (1 << 32)
    } else {
        v
    }
}

/// One direction of traffic, seen on the wire.
#[derive(Clone, Debug, Default)]
pub struct WireStats {
    pub pkts: u64,
    pub data_pkts: u64,
    pub payload: u64,
    /// Data segments (and their bytes) that resent sequence space.
    pub retx_pkts: u64,
    pub retx_bytes: u64,
    /// Payload bytes delivered that the receiver had already been given:
    /// retransmissions that were not needed.
    pub dup_delivered: u64,
    pub drops: u64,
    pub data_drops: u64,
    pub corrupted: u64,
    pub duplicated: u64,
    pub rst: u64,
    pub syn: u64,
    pub fin: u64,
    isn: Option<u32>,
    hi: u64,
    delivered: RangeSet,
}

impl WireStats {
    fn on_send(&mut self, s: &pkt::Seg) {
        self.pkts += 1;
        if s.has(pkt::RST) {
            self.rst += 1;
        }
        if s.has(pkt::SYN) {
            self.syn += 1;
            if self.isn.is_none() {
                self.isn = Some(s.seq);
                self.hi = 1;
            }
        }
        if s.has(pkt::FIN) {
            self.fin += 1;
        }
        if s.payload_len == 0 {
            return;
        }
        self.data_pkts += 1;
        self.payload += s.payload_len as u64;
        if let Some(isn) = self.isn {
            let lo = unwrap(s.seq.wrapping_sub(isn), self.hi);
            let hi = lo + s.payload_len as u64;
            if lo < self.hi {
                self.retx_pkts += 1;
                self.retx_bytes += hi.min(self.hi) - lo;
            }
            self.hi = self.hi.max(hi);
        }
    }

    fn on_deliver(&mut self, s: &pkt::Seg) {
        if s.payload_len == 0 {
            return;
        }
        if let Some(isn) = self.isn {
            let lo = unwrap(s.seq.wrapping_sub(isn), self.hi);
            let hi = lo + s.payload_len as u64;
            self.dup_delivered += self.delivered.overlap(lo, hi);
            self.delivered.insert(lo, hi);
        }
    }

    pub fn isn(&self) -> Option<u32> {
        self.isn
    }
}

struct InFlight {
    at: Time,
    order: u64,
    pkt: Pkt,
    /// A copy the link made, or a corrupted packet: not the sender's doing.
    synthetic: bool,
}

impl PartialEq for InFlight {
    fn eq(&self, o: &Self) -> bool {
        (self.at, self.order) == (o.at, o.order)
    }
}
impl Eq for InFlight {}
impl PartialOrd for InFlight {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for InFlight {
    // Reversed: BinaryHeap is a max-heap and we want the earliest first.
    fn cmp(&self, o: &Self) -> Ordering {
        (o.at, o.order).cmp(&(self.at, self.order))
    }
}

pub struct Link {
    pub cfg: LinkCfg,
    rng: Rng,
    busy_until: Time,
    departures: VecDeque<Time>,
    flight: BinaryHeap<InFlight>,
    order: u64,
    data_in: u64,
    syns_dropped: u32,
    pub stats: WireStats,
    /// Keep parsing segments for the statistics (off for CPU benchmarks).
    pub observe: bool,
    /// Print every packet (`--trace`), labelled with this direction.
    pub trace: Option<&'static str>,
}

fn trace_line(dir: &str, now: Time, what: &str, p: &[u8]) {
    let s = match pkt::parse(p) {
        Some(s) => s,
        None => {
            println!(
                "{:>10.3} {dir} {what} <unparsable {} B>",
                now as f64 / 1e3,
                p.len()
            );
            return;
        }
    };
    let mut o = String::new();
    if let Some(m) = s.mss {
        o += &format!(" mss={m}");
    }
    if let Some(w) = s.ws {
        o += &format!(" ws={w}");
    }
    if s.sack_ok {
        o += " sackOK";
    }
    for (l, r) in s.sack_blocks() {
        o += &format!(" sack={l}-{r}");
    }
    if let Some((v, e)) = s.ts {
        o += &format!(" ts={v}/{e}");
    }
    println!(
        "{:>10.3} {dir} {what:<7} {:<3} seq={} ack={} win={} len={}{o}",
        now as f64 / 1e3,
        pkt::flags_str(s.flags),
        s.seq,
        s.ack,
        s.win,
        s.payload_len
    );
}

impl Link {
    pub fn new(cfg: LinkCfg, seed: u64) -> Self {
        Self {
            cfg,
            rng: Rng::new(seed),
            busy_until: 0,
            departures: VecDeque::new(),
            flight: BinaryHeap::new(),
            order: 0,
            data_in: 0,
            syns_dropped: 0,
            stats: WireStats::default(),
            observe: true,
            trace: None,
        }
    }

    fn note(&self, now: Time, what: &str, p: &[u8]) {
        if let Some(dir) = self.trace {
            trace_line(dir, now, what, p);
        }
    }

    pub fn send(&mut self, now: Time, mut p: Pkt) {
        let seg = if self.observe { pkt::parse(&p) } else { None };
        let (data, syn) = match &seg {
            Some(s) => {
                self.stats.on_send(s);
                (s.payload_len > 0, s.has(pkt::SYN))
            }
            None => (false, false),
        };
        let drop = |l: &mut Link, why: &str| {
            l.note(now, why, &p);
            l.stats.drops += 1;
            l.stats.data_drops += u64::from(data);
        };
        if data {
            let i = self.data_in;
            self.data_in += 1;
            if (self.cfg.drop_data.0..self.cfg.drop_data.1).contains(&i) {
                return drop(self, "DROP");
            }
        }
        if syn && self.syns_dropped < self.cfg.drop_syns {
            self.syns_dropped += 1;
            return drop(self, "DROP");
        }
        if self.rng.ppm(self.cfg.loss_ppm) {
            return drop(self, "DROP");
        }
        let mut depart = now;
        if self.cfg.rate_bps > 0 {
            while self.departures.front().is_some_and(|&d| d <= now) {
                self.departures.pop_front();
            }
            if self.departures.len() >= self.cfg.queue {
                return drop(self, "QDROP");
            }
            let tx_us = (p.len() as u64 * 8 * 1_000_000).div_ceil(self.cfg.rate_bps);
            self.busy_until = self.busy_until.max(now) + tx_us;
            self.departures.push_back(self.busy_until);
            depart = self.busy_until;
        }
        let mut at = depart + self.cfg.delay_us;
        let mut what = "send";
        if self.rng.ppm(self.cfg.reorder_ppm) {
            at += self.cfg.reorder_us;
            what = "LATE";
        }
        let mut synthetic = false;
        self.note(now, what, &p);
        if self.rng.ppm(self.cfg.corrupt_ppm) && !p.is_empty() {
            let i = self.rng.below(p.len() as u64) as usize;
            let x = 1 + self.rng.below(255) as u8;
            p.bytes_mut()[i] ^= x;
            self.stats.corrupted += 1;
            synthetic = true;
        }
        if self.rng.ppm(self.cfg.dup_ppm) {
            self.stats.duplicated += 1;
            self.order += 1;
            self.flight.push(InFlight {
                at: at + 1 + self.rng.below(1000),
                order: self.order,
                pkt: p.clone(),
                synthetic: true,
            });
        }
        self.order += 1;
        self.flight.push(InFlight {
            at,
            order: self.order,
            pkt: p,
            synthetic,
        });
    }

    pub fn next_delivery(&self) -> Option<Time> {
        self.flight.peek().map(|f| f.at)
    }

    pub fn pop_due(&mut self, now: Time) -> Option<Pkt> {
        if self.next_delivery()? > now {
            return None;
        }
        let f = self.flight.pop()?;
        if self.observe && !f.synthetic {
            if let Some(s) = pkt::parse(&f.pkt) {
                self.stats.on_deliver(&s);
            }
        }
        Some(f.pkt)
    }

    pub fn idle(&self) -> bool {
        self.flight.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rangeset_merges_and_overlaps() {
        let mut r = RangeSet::default();
        r.insert(10, 20);
        r.insert(30, 40);
        assert_eq!(r.overlap(0, 100), 20);
        assert_eq!(r.overlap(15, 35), 10);
        r.insert(20, 30);
        assert_eq!(r.0, vec![(10, 40)]);
        r.insert(5, 12);
        assert_eq!(r.0, vec![(5, 40)]);
    }

    #[test]
    fn unwrap_crosses_the_wrap() {
        assert_eq!(unwrap(5, (1 << 32) - 10), (1 << 32) + 5);
        assert_eq!(unwrap(u32::MAX - 4, (1 << 32) + 5), (1 << 32) - 5);
        assert_eq!(unwrap(100, 50), 100);
    }
}
