//! Deterministic discrete-event simulation: two real [`Tcb`]s talking over a
//! seeded, rate-limited, delayed, lossy and reordering link.
//!
//! Unlike the scripted-peer tests, these measure *efficiency*, guarding the
//! loss-recovery machinery against regressions that still "complete":
//! retransmissions must track real drops (no spurious storms), goodput must
//! stay near the Reno/Mathis bound, and RTO must remain a last resort. Run
//! with `--nocapture` to see each scenario's summary line.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

extern crate std;

use core::cmp::Reverse;
use core::mem::MaybeUninit;
use std::boxed::Box;
use std::collections::{BinaryHeap, VecDeque};
use std::println;
use std::vec::Vec;

use crate::tcb::{events, Endpoint, Tcb, TcbConfig, TcbStats};
use crate::State;
use crate::MAX_PACKET;

const A_IP: [u8; 4] = [10, 0, 0, 2];
const B_IP: [u8; 4] = [10, 0, 0, 1];
const SMSS: f64 = 1448.0;

/// xorshift64* — deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn chance_ppm(&mut self, ppm: u32) -> bool {
        ppm > 0 && self.next() % 1_000_000 < u64::from(ppm)
    }
}

#[derive(Clone, Copy)]
struct LinkCfg {
    delay_us: u64,
    /// Bottleneck rate in bit/s (0 = unlimited).
    rate_bps: u64,
    /// Bottleneck queue in packets (tail drop).
    queue_pkts: usize,
    loss_ppm: u32,
    reorder_ppm: u32,
    reorder_extra_us: u64,
    /// Drop payload-carrying packets whose link-entry index is in `[lo, hi)`.
    drop_data: (u64, u64),
    /// Also drop the payload-carrying packets with these indices.
    drop_idx: &'static [u64],
    /// Drop every packet entering the link in `[lo, hi)` µs (an outage).
    blackout: (u64, u64),
    /// Remove D-SACK blocks, as from a receiver that never sends them.
    strip_dsack: bool,
    /// How the sending host feeds the bottleneck queue.
    host: Host,
}

/// How a host hands its TCB's packets to the bottleneck queue (a device
/// queue such as a TUN queue or virtio ring, when the host can see it).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Host {
    /// Every packet at once; the queue tail-drops what does not fit, like a
    /// router's.
    Push,
    /// A packet only while the queue has room: the rest waits in the TCB's
    /// egress ring, which stops the TCB when it fills.
    Ring,
    /// As `Ring`, and the TCB's egress is paused (`set_egress_paused`) once
    /// the queue is half full and resumed below a quarter, so segments are
    /// built when they can leave (Linux TCP Small Queues in spirit).
    Pause,
}

impl LinkCfg {
    const fn new(delay_ms: u64, rate_mbit: u64, queue_pkts: usize) -> Self {
        Self {
            delay_us: delay_ms * 1000,
            rate_bps: rate_mbit * 1_000_000,
            queue_pkts,
            loss_ppm: 0,
            reorder_ppm: 0,
            reorder_extra_us: 0,
            drop_data: (0, 0),
            drop_idx: &[],
            blackout: (0, 0),
            strip_dsack: false,
            host: Host::Push,
        }
    }
    const fn loss(mut self, ppm: u32) -> Self {
        self.loss_ppm = ppm;
        self
    }
    const fn reorder(mut self, ppm: u32, extra_ms: u64) -> Self {
        self.reorder_ppm = ppm;
        self.reorder_extra_us = extra_ms * 1000;
        self
    }
    const fn delay_us(mut self, us: u64) -> Self {
        self.delay_us = us;
        self
    }
    const fn reorder_us(mut self, ppm: u32, extra_us: u64) -> Self {
        self.reorder_ppm = ppm;
        self.reorder_extra_us = extra_us;
        self
    }
    const fn drop_data(mut self, lo: u64, hi: u64) -> Self {
        self.drop_data = (lo, hi);
        self
    }
    const fn drop_idx(mut self, idx: &'static [u64]) -> Self {
        self.drop_idx = idx;
        self
    }
    const fn strip_dsack(mut self) -> Self {
        self.strip_dsack = true;
        self
    }
    const fn host(mut self, host: Host) -> Self {
        self.host = host;
        self
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct LinkStats {
    data_in: u64,
    data_dropped: u64,
    queue_drops: u64,
    random_drops: u64,
    delivered: u64,
}

struct Link {
    cfg: LinkCfg,
    rng: Rng,
    /// When the bottleneck finishes sending what it holds, in ns: a
    /// 1500-byte packet takes 1.2 µs at 10 Gbit/s, so whole microseconds
    /// per packet would cap the link at 6 Gbit/s.
    busy_until_ns: u64,
    departures: VecDeque<u64>,
    flight: BinaryHeap<Reverse<(u64, u64, Vec<u8>)>>,
    order: u64,
    stats: LinkStats,
    /// `Host::Pause`: the sending TCB's egress is paused.
    paused: bool,
}

fn payload_len(pkt: &[u8]) -> usize {
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let doff = usize::from(pkt[ihl + 12] >> 4) * 4;
    total - ihl - doff
}

fn be32(p: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]])
}

/// Rewrite a leading D-SACK block (RFC 2883) out of the SACK option,
/// replacing the freed bytes with NOPs, and fix the TCP checksum.
fn strip_dsack(pkt: &mut [u8]) {
    let le = |a: u32, b: u32| (a.wrapping_sub(b) as i32) <= 0;
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let ack = be32(pkt, ihl + 8);
    let opts_end = ihl + usize::from(pkt[ihl + 12] >> 4) * 4;
    let mut i = ihl + 20;
    while i < opts_end && pkt[i] != 0 {
        if pkt[i] == 1 {
            i += 1;
            continue;
        }
        let len = usize::from(pkt[i + 1]);
        if pkt[i] == 5 && len >= 10 {
            let (l0, r0) = (be32(pkt, i + 2), be32(pkt, i + 6));
            let dsack = le(r0, ack)
                || (len >= 18 && le(be32(pkt, i + 10), l0) && le(r0, be32(pkt, i + 14)));
            if !dsack {
                return;
            }
            if len == 10 {
                pkt[i..i + len].fill(1);
            } else {
                pkt.copy_within(i + 10..i + len, i + 2);
                pkt[i + 1] = (len - 8) as u8;
                pkt[i + len - 8..i + len].fill(1);
            }
            let seg = ihl..total;
            pkt[ihl + 16..ihl + 18].fill(0);
            let mut sum = 6 + (total - ihl) as u64;
            for c in pkt[12..20].chunks(2).chain(pkt[seg].chunks(2)) {
                sum += u64::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)]));
            }
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            pkt[ihl + 16..ihl + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            return;
        }
        i += len.max(2);
    }
}

impl Link {
    fn new(cfg: LinkCfg, seed: u64) -> Self {
        Self {
            cfg,
            rng: Rng(seed | 1),
            busy_until_ns: 0,
            departures: VecDeque::new(),
            flight: BinaryHeap::new(),
            order: 0,
            stats: LinkStats::default(),
            paused: false,
        }
    }

    /// Packets in the bottleneck queue (or on the wire leaving it) at `now`.
    fn backlog(&mut self, now: u64) -> usize {
        while self.departures.front().is_some_and(|&d| d <= now) {
            self.departures.pop_front();
        }
        self.departures.len()
    }

    /// Whether the host hands the queue another packet now.
    fn admits(&mut self, now: u64) -> bool {
        self.cfg.host == Host::Push
            || self.cfg.rate_bps == 0
            || self.backlog(now) < self.cfg.queue_pkts
    }

    /// When the queue next frees a slot, if the host is holding packets back.
    fn next_room(&mut self, now: u64, held: bool) -> Option<u64> {
        if self.cfg.host == Host::Push || !(held || self.paused) {
            return None;
        }
        self.backlog(now);
        self.departures.front().copied()
    }

    fn send(&mut self, now: u64, mut pkt: Vec<u8>) {
        if self.cfg.strip_dsack {
            strip_dsack(&mut pkt);
        }
        let data = payload_len(&pkt) > 0;
        if data {
            let idx = self.stats.data_in;
            self.stats.data_in += 1;
            if (self.cfg.drop_data.0..self.cfg.drop_data.1).contains(&idx)
                || self.cfg.drop_idx.contains(&idx)
            {
                self.stats.data_dropped += 1;
                return;
            }
        }
        if (self.cfg.blackout.0..self.cfg.blackout.1).contains(&now) {
            self.stats.random_drops += 1;
            self.stats.data_dropped += u64::from(data);
            return;
        }
        if self.rng.chance_ppm(self.cfg.loss_ppm) {
            self.stats.random_drops += 1;
            self.stats.data_dropped += u64::from(data);
            return;
        }
        let mut depart = now;
        if self.cfg.rate_bps > 0 {
            while self.departures.front().is_some_and(|&d| d <= now) {
                self.departures.pop_front();
            }
            if self.departures.len() >= self.cfg.queue_pkts {
                self.stats.queue_drops += 1;
                self.stats.data_dropped += u64::from(data);
                return;
            }
            let bits = pkt.len() as u64 * 8;
            let tx_ns = (bits * 1_000_000_000).div_ceil(self.cfg.rate_bps);
            self.busy_until_ns = self.busy_until_ns.max(now * 1000) + tx_ns;
            depart = self.busy_until_ns.div_ceil(1000);
            self.departures.push_back(depart);
        }
        let mut at = depart + self.cfg.delay_us;
        if self.rng.chance_ppm(self.cfg.reorder_ppm) {
            at += self.cfg.reorder_extra_us;
        }
        self.order += 1;
        self.flight.push(Reverse((at, self.order, pkt)));
    }

    fn next_delivery(&self) -> Option<u64> {
        self.flight.peek().map(|Reverse((t, _, _))| *t)
    }

    fn pop_due(&mut self, now: u64) -> Option<Vec<u8>> {
        if self.next_delivery()? > now {
            return None;
        }
        self.stats.delivered += 1;
        self.flight.pop().map(|Reverse((_, _, p))| p)
    }
}

fn pattern(stream: u8, i: usize) -> u8 {
    ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8 ^ stream
}

struct Flow {
    stream: u8,
    total: usize,
    sent: usize,
    recvd: usize,
    /// Reader drains at most this many bytes per ms (None = immediately).
    read_rate: Option<usize>,
    read_budget: usize,
    last_read_ms: u64,
    done_us: Option<u64>,
}

impl Flow {
    fn new(stream: u8, total: usize) -> Self {
        Self {
            stream,
            total,
            sent: 0,
            recvd: 0,
            read_rate: None,
            read_budget: 0,
            last_read_ms: 0,
            done_us: None,
        }
    }

    fn pump_send(&mut self, t: &mut Tcb) {
        let mut chunk = [0u8; 16 * 1024];
        while self.sent < self.total {
            let n = chunk.len().min(self.total - self.sent);
            for (k, b) in chunk[..n].iter_mut().enumerate() {
                *b = pattern(self.stream, self.sent + k);
            }
            match t.send(&chunk[..n]) {
                Ok(w) if w > 0 => self.sent += w,
                _ => break,
            }
        }
    }

    fn pump_recv(&mut self, t: &mut Tcb, now_us: u64) {
        let now_ms = now_us / 1000;
        if let Some(rate) = self.read_rate {
            let dt = usize::try_from(now_ms - self.last_read_ms).unwrap();
            self.read_budget = (self.read_budget + dt * rate).min(64 * 1024);
            self.last_read_ms = now_ms;
        }
        let mut buf = [0u8; 16 * 1024];
        loop {
            let cap = match self.read_rate {
                Some(_) => buf.len().min(self.read_budget),
                None => buf.len(),
            };
            if cap == 0 {
                break;
            }
            match t.recv(&mut buf[..cap]) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    for (k, &b) in buf[..n].iter().enumerate() {
                        assert_eq!(b, pattern(self.stream, self.recvd + k), "corrupt stream");
                    }
                    self.recvd += n;
                    if self.read_rate.is_some() {
                        self.read_budget -= n;
                    }
                }
            }
        }
        assert!(self.recvd <= self.total, "received more than was sent");
        if self.recvd == self.total && self.done_us.is_none() {
            self.done_us = Some(now_us);
        }
    }
}

fn boxed_tcb(cfg: TcbConfig) -> Box<Tcb> {
    let mut slot: Box<MaybeUninit<Tcb>> = Box::new_uninit();
    // SAFETY: `init_in_place` fully initialises the storage on success.
    unsafe {
        Tcb::init_in_place(slot.as_mut_ptr(), cfg).unwrap();
        slot.assume_init()
    }
}

struct Sim {
    now_us: u64,
    a: Box<Tcb>,
    b: Box<Tcb>,
    ab: Link,
    ba: Link,
    f_ab: Flow,
    f_ba: Flow,
    start_us: u64,
}

fn drain_into(t: &mut Tcb, link: &mut Link, now_us: u64) -> usize {
    let mut buf = [0u8; MAX_PACKET];
    let mut packets = 0;
    while link.admits(now_us) {
        let Ok(n) = t.extract_packet(&mut buf) else {
            break;
        };
        if n == 0 {
            break;
        }
        link.send(now_us, buf[..n].to_vec());
        packets += 1;
    }
    if link.cfg.host == Host::Pause
        && !link.paused
        && link.backlog(now_us) >= link.cfg.queue_pkts / 2
    {
        t.set_egress_paused(true);
        link.paused = true;
    }
    packets
}

impl Sim {
    fn new(fwd: LinkCfg, rev: LinkCfg, seed: u64, ab_bytes: usize, ba_bytes: usize) -> Self {
        Self::with_iss(
            fwd,
            rev,
            seed,
            ab_bytes,
            ba_bytes,
            (0x1234_5678, 0x8765_4321),
        )
    }

    fn with_iss(
        fwd: LinkCfg,
        rev: LinkCfg,
        seed: u64,
        ab_bytes: usize,
        ba_bytes: usize,
        iss: (u32, u32),
    ) -> Self {
        let a = boxed_tcb(TcbConfig {
            local: Endpoint {
                ip: A_IP,
                port: 40_000,
            },
            remote: Endpoint { ip: B_IP, port: 80 },
            iss: iss.0,
            initial_rto_ms: 1000,
        });
        let mut b = boxed_tcb(TcbConfig {
            local: Endpoint { ip: B_IP, port: 80 },
            remote: Endpoint {
                ip: [0; 4],
                port: 0,
            },
            iss: iss.1,
            initial_rto_ms: 1000,
        });
        b.set_now(0);
        b.set_secret(&[0x42; 16]);
        b.listen().unwrap();
        let mut s = Self {
            now_us: 0,
            a,
            b,
            ab: Link::new(fwd, seed),
            ba: Link::new(rev, seed.rotate_left(17) ^ 0xA5A5),
            f_ab: Flow::new(0x00, ab_bytes),
            f_ba: Flow::new(0x5A, ba_bytes),
            start_us: 0,
        };
        s.a.set_now(0);
        s.a.connect().unwrap();
        drain_into(&mut s.a, &mut s.ab, 0);
        s
    }

    fn tick_all(&mut self) {
        let ms = self.now_us / 1000;
        let now_us = self.now_us;
        for (t, link) in [(&mut self.a, &mut self.ab), (&mut self.b, &mut self.ba)] {
            t.set_now(ms);
            if link.paused && link.backlog(now_us) <= link.cfg.queue_pkts / 4 {
                t.set_egress_paused(false);
                link.paused = false;
            }
            // The host contract: tick again after draining a full egress
            // ring, which stopped the stack mid-window.
            for _ in 0..64 {
                t.tick().unwrap();
                let full = t.debug_egress_full();
                if drain_into(t, link, now_us) == 0 || !full {
                    break;
                }
            }
            t.debug_validate_invariants().unwrap();
            // Output a full or paused egress holds back (an owed ACK) waits
            // for the host to drain or resume it, not for a deadline.
            let next = if t.debug_egress_full() {
                t.next_deadline()
            } else {
                t.debug_next_deadline()
            };
            if let Some(d) = next {
                assert!(
                    d > ms,
                    "armed deadline {d} not in the future after tick at {ms}"
                );
            }
        }
    }

    fn deliver_due(&mut self) -> bool {
        let ms = self.now_us / 1000;
        let mut any = false;
        while let Some(p) = self.ab.pop_due(self.now_us) {
            self.b.set_now(ms);
            self.b.inject_packet(&p).unwrap();
            drain_into(&mut self.b, &mut self.ba, self.now_us);
            any = true;
        }
        while let Some(p) = self.ba.pop_due(self.now_us) {
            self.a.set_now(ms);
            self.a.inject_packet(&p).unwrap();
            drain_into(&mut self.a, &mut self.ab, self.now_us);
            any = true;
        }
        any
    }

    fn app(&mut self) {
        if self.a.state() == State::Established && self.start_us == 0 {
            self.start_us = self.now_us;
        }
        self.f_ab.pump_send(&mut self.a);
        self.f_ba.pump_send(&mut self.b);
        self.f_ab.pump_recv(&mut self.b, self.now_us);
        self.f_ba.pump_recv(&mut self.a, self.now_us);
    }

    /// Advance until `done` holds; false on deadlock or `limit_us`.
    fn run(&mut self, limit_us: u64, done: impl Fn(&Self) -> bool) -> bool {
        for _ in 0..20_000_000u64 {
            self.app();
            self.tick_all();
            if done(self) {
                return true;
            }
            if self.deliver_due() {
                continue;
            }
            let tcb = [self.a.next_deadline(), self.b.next_deadline()]
                .into_iter()
                .flatten()
                .min()
                .map(|d| d * 1000);
            let reader = [&self.f_ab, &self.f_ba]
                .iter()
                .any(|f| f.read_rate.is_some() && f.recvd < f.total)
                .then_some(self.now_us + 1000);
            let now = self.now_us;
            let held_a = self.a.debug_snapshot().tx_len > 0;
            let held_b = self.b.debug_snapshot().tx_len > 0;
            let Some(next) = [
                tcb,
                self.ab.next_delivery(),
                self.ba.next_delivery(),
                reader,
                self.ab.next_room(now, held_a),
                self.ba.next_room(now, held_b),
            ]
            .into_iter()
            .flatten()
            .min() else {
                return false;
            };
            if next > limit_us {
                return false;
            }
            self.now_us = next.max(self.now_us);
        }
        panic!("simulation did not converge");
    }

    fn run_transfer(&mut self, limit_us: u64) -> Outcome {
        let ok = self.run(limit_us, |s| {
            s.f_ab.done_us.is_some() && s.f_ba.done_us.is_some()
        });
        assert!(
            ok,
            "transfer stalled at {} ms: a {:?} {}/{} b {:?} {}/{}\nA {:?}\nB {:?}",
            self.now_us / 1000,
            self.a.state(),
            self.f_ab.recvd,
            self.f_ab.total,
            self.b.state(),
            self.f_ba.recvd,
            self.f_ba.total,
            self.a.stats(),
            self.b.stats()
        );
        let end = self.f_ab.done_us.unwrap().max(self.f_ba.done_us.unwrap());
        // Let in-flight segments land so late spurious retransmissions are
        // counted by the receiver.
        let quiet = |t: &Tcb| {
            let d = t.debug_snapshot();
            d.snd_una == d.snd_nxt && d.tx_len == 0
        };
        let limit = self.now_us + 60_000_000;
        assert!(self.run(limit, |s| {
            quiet(&s.a) && quiet(&s.b) && s.ab.flight.is_empty() && s.ba.flight.is_empty()
        }));
        Outcome {
            secs: (end - self.start_us) as f64 / 1e6,
            a: self.a.stats(),
            b: self.b.stats(),
            fwd: self.ab.stats,
            rev: self.ba.stats,
        }
    }

    /// Both sides close; the four-way handshake must finish under the same
    /// impairments.
    fn close_both(&mut self) {
        self.a.close().unwrap();
        self.b.close().unwrap();
        let closed = |t: &Tcb| matches!(t.state(), State::TimeWait | State::Closed);
        let limit = self.now_us + 120_000_000;
        assert!(
            self.run(limit, |s| closed(&s.a) && closed(&s.b)),
            "close stalled: a {:?} b {:?}",
            self.a.state(),
            self.b.state()
        );
        assert_eq!(self.a.poll() & events::ERROR, 0);
        assert_eq!(self.b.poll() & events::ERROR, 0);
    }
}

struct Outcome {
    secs: f64,
    a: TcbStats,
    b: TcbStats,
    fwd: LinkStats,
    rev: LinkStats,
}

impl Outcome {
    fn goodput(&self, bytes: usize) -> f64 {
        bytes as f64 / self.secs
    }
    fn report(&self, name: &str, bytes: usize) {
        println!(
            "{name}: {:.2} MB/s in {:.3}s | A retx {} rto {} tlp {} fr {} dsack {} | \
             B dup {} B | fwd data {} drop {} (q {} rnd {}) | rev drop {}",
            self.goodput(bytes) / 1e6,
            self.secs,
            self.a.segs_retrans,
            self.a.rto_count,
            self.a.tlp_count,
            self.a.fast_recoveries,
            self.a.dsacks_received,
            self.b.dup_bytes_received,
            self.fwd.data_in,
            self.fwd.data_dropped,
            self.fwd.queue_drops,
            self.fwd.random_drops,
            self.rev.queue_drops + self.rev.random_drops,
        );
    }
    /// Every retransmission (either direction) repaired a real drop or was a
    /// tail-loss probe, and receivers saw no more duplicates than probes.
    fn assert_no_spurious_storm(&self, slack: u64) {
        for (name, tx, rx, link) in [
            ("A", &self.a, &self.b, &self.fwd),
            ("B", &self.b, &self.a, &self.rev),
        ] {
            let probes = u64::from(tx.tlp_count);
            assert!(
                tx.segs_retrans <= link.data_dropped + probes + slack,
                "{name}: spurious retransmissions: {} retransmitted for {} drops (+{probes} TLP)",
                tx.segs_retrans,
                link.data_dropped,
            );
            let dup_segs = rx.dup_bytes_received as f64 / SMSS;
            assert!(
                dup_segs <= (probes + slack) as f64,
                "{name}: receiver saw {dup_segs:.0} duplicate segments"
            );
        }
    }
}

/// Reno steady-state bound: MSS/RTT · sqrt(3/2) / sqrt(p).
fn mathis(rtt_s: f64, p: f64) -> f64 {
    SMSS / rtt_s * (1.5f64 / p).sqrt()
}

const MIB: usize = 1024 * 1024;

#[test]
fn clean_bottleneck_is_filled_without_spurious_retransmits() {
    let fwd = LinkCfg::new(10, 50, 64);
    let rev = LinkCfg::new(10, 50, 64);
    let bytes = 8 * MIB;
    let mut s = Sim::new(fwd, rev, 1, bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report("clean 50Mbit/20ms q64", bytes);
    let line = 50e6 / 8.0 * SMSS / 1500.0;
    assert!(o.goodput(bytes) >= 0.85 * line, "underfilled link");
    assert_eq!(
        o.a.rto_count, 0,
        "slow-start overshoot must be repaired without RTO"
    );
    o.assert_no_spurious_storm(0);
    s.close_both();
}

#[test]
fn random_loss_goodput_tracks_mathis() {
    for (seed, ppm, rtt_ms) in [(7u64, 10_000u32, 20u64), (8, 10_000, 50), (9, 1_000, 20)] {
        let fwd = LinkCfg::new(rtt_ms / 2, 100, 1000).loss(ppm);
        let rev = LinkCfg::new(rtt_ms / 2, 100, 1000);
        let bytes = 4 * MIB;
        let mut s = Sim::new(fwd, rev, seed, bytes, 0);
        let o = s.run_transfer(600_000_000);
        o.report(
            &std::format!("loss {}% rtt {rtt_ms}ms", f64::from(ppm) / 1e4),
            bytes,
        );
        let p = f64::from(ppm) / 1e6;
        let bound = mathis(rtt_ms as f64 / 1e3, p);
        assert!(
            o.goodput(bytes) >= 0.7 * bound,
            "goodput {:.0} B/s below 0.7x Mathis {:.0} B/s",
            o.goodput(bytes),
            bound
        );
        assert!(
            u64::from(o.a.rto_count) * 10 <= o.fwd.data_dropped.max(10),
            "RTO is not a last resort: {} RTOs for {} drops",
            o.a.rto_count,
            o.fwd.data_dropped
        );
        o.assert_no_spurious_storm(0);
        s.close_both();
    }
}

#[test]
fn burst_loss_in_one_window_is_repaired_in_a_round_trip() {
    let fwd = LinkCfg::new(10, 100, 1000).drop_data(300, 340);
    let rev = LinkCfg::new(10, 100, 1000);
    let bytes = 4 * MIB;
    let mut s = Sim::new(fwd, rev, 3, bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report("burst 40 pkts", bytes);
    assert_eq!(o.a.rto_count, 0, "a SACKed burst must not need RTO");
    assert_eq!(o.a.fast_recoveries, 1);
    o.assert_no_spurious_storm(0);
}

#[test]
fn tail_loss_is_repaired_by_tlp_not_rto() {
    // Ten segments (the initial window); the last three vanish.
    let fwd = LinkCfg::new(10, 100, 1000).drop_data(7, 10);
    let rev = LinkCfg::new(10, 100, 1000);
    let bytes = 10 * 1448;
    let mut s = Sim::new(fwd, rev, 4, bytes, 0);
    let o = s.run_transfer(10_000_000);
    o.report("tail loss", bytes);
    assert_eq!(o.a.rto_count, 0);
    assert!(o.a.tlp_count >= 1);
    // Handshake RTT 20 ms: PTO ≈ 2·SRTT after the last ACK, then one round
    // trip for the probe's SACK and one for the RACK repair. An RTO-based
    // repair would need at least the 200 ms floor on top.
    assert!(o.secs < 0.200, "tail repaired in {:.3}s", o.secs);
    o.assert_no_spurious_storm(0);
}

#[test]
fn reordering_is_learned_and_tolerated() {
    let fwd = LinkCfg::new(10, 50, 1000).reorder(20_000, 4);
    let rev = LinkCfg::new(10, 50, 1000);
    let bytes = 8 * MIB;
    let mut s = Sim::new(fwd, rev, 5, bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report("reorder 2% +4ms", bytes);
    let line = 50e6 / 8.0 * SMSS / 1500.0;
    assert!(o.goodput(bytes) >= 0.6 * line);
    // Early reordering may cost a few spurious retransmits before D-SACK
    // teaches RACK to widen its window; it must not persist.
    let spurious = o.b.dup_bytes_received as f64 / SMSS;
    assert!(spurious <= 5.0, "{spurious:.0} spurious retransmissions");
    assert!(o.a.dsacks_received > 0 || spurious == 0.0);
    assert_eq!(o.a.rto_count, 0);
}

/// The same reordering against a receiver that never sends D-SACKs
/// (smoltcp, for one): the timestamp echo alone must show that each "lost"
/// segment was only delayed and undo the reduction; otherwise every
/// reordering event cuts the window for good (1.6 MB/s here).
#[test]
fn reordering_is_tolerated_without_dsack() {
    let fwd = LinkCfg::new(10, 50, 1000).reorder(20_000, 4);
    let rev = LinkCfg::new(10, 50, 1000).strip_dsack();
    let bytes = 8 * MIB;
    let mut s = Sim::new(fwd, rev, 5, bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report("reorder 2% +4ms, no D-SACK", bytes);
    assert_eq!(o.a.dsacks_received, 0, "a D-SACK got through");
    let line = 50e6 / 8.0 * SMSS / 1500.0;
    assert!(o.goodput(bytes) >= 0.8 * line, "underfilled link");
    // Only D-SACKs widen RACK's reordering window (as in Linux), so some
    // reordering still costs a retransmission, but never the window.
    assert!(
        o.a.segs_retrans * 100 <= o.fwd.data_in,
        "retransmission storm"
    );
    assert_eq!(o.a.rto_count, 0);
}

/// A virtual link (200 µs RTT) whose ring overflows at the end of a burst:
/// the probe's SACK must let RACK mark the rest of the tail lost. With a
/// millisecond clock the probe's RTT reads 0 against a 1 ms `min_rtt`, and
/// the ambiguity filter used to leave the tail to a 200 ms RTO; and the
/// receiver must ACK the partial fill of the hole at once, not 40 ms later.
#[test]
fn sub_millisecond_tail_loss_is_repaired_without_rto() {
    let link = LinkCfg::new(0, 10_000, 1024).delay_us(100);
    let bytes = 10 * 1448;
    let mut s = Sim::new(link.drop_data(7, 10), link, 4, bytes, 0);
    let o = s.run_transfer(10_000_000);
    o.report("virtual link 200us, last 3 of 10 lost", bytes);
    assert_eq!(o.a.rto_count, 0, "tail left to the RTO");
    assert_eq!((o.a.tlp_count, o.a.segs_retrans), (1, 3));
    assert!(o.secs < 0.02, "repaired in {:.3} s", o.secs);
}

/// A virtual link (200 µs RTT) that loses three segments mid-burst, then
/// the first of their retransmissions. The later retransmissions are SACKed
/// within the millisecond they left, so their RTT reads 0 against a 1 ms
/// `min_rtt`; RACK's retransmission ambiguity filter used to discard them,
/// and nothing could find the lost retransmission before the RTO.
#[test]
fn sub_millisecond_lost_retransmission_is_repaired_without_rto() {
    for (name, drops) in [
        ("3 of 30 lost", &[15u64, 16, 17][..]),
        (
            "3 of 30 lost, then the first retransmission",
            &[15, 16, 17, 30][..],
        ),
    ] {
        let rev = LinkCfg::new(0, 10_000, 1024).delay_us(100);
        let bytes = 30 * 1448;
        let mut s = Sim::new(rev.drop_idx(drops), rev, 4, bytes, 0);
        let o = s.run_transfer(10_000_000);
        o.report(&std::format!("virtual link 200us, {name}"), bytes);
        assert_eq!(o.a.rto_count, 0, "{name}: left to the RTO");
        assert!(o.secs < 0.02, "{name}: repaired in {:.3} s", o.secs);
    }
}

/// A virtual link (200 µs RTT) loses the last data segment before a bare
/// FIN. The receiver SACKs the FIN it holds out of order, so RACK finds
/// the loss within milliseconds instead of leaving it to the RTO.
#[test]
fn sub_millisecond_loss_before_a_bare_fin_is_repaired_without_rto() {
    let link = LinkCfg::new(0, 10_000, 1024).delay_us(100);
    let mut s = Sim::new(link.drop_data(0, 1), link, 4, 0, 0);
    assert!(s.run(1_000_000, |s| {
        s.a.state() == State::Established && s.b.state() == State::Established
    }));
    s.f_ab.total = 1448;
    s.f_ab.done_us = None;
    assert!(s.run(1_000_000, |s| {
        s.f_ab.sent == 1448 && s.a.debug_snapshot().snd_nxt != s.a.debug_snapshot().snd_una
    }));
    s.a.close().unwrap();
    let o = s.run_transfer(1_000_000);
    o.report("virtual link 200us, data lost before a bare FIN", 1448);
    assert_eq!(o.a.rto_count, 0, "left to the RTO");
    assert!(o.secs < 0.02, "repaired in {:.3} s", o.secs);
}

/// A spurious timeout on a virtual link (a 300 ms ACK outage: the data
/// got through, the ACKs did not) earns D-SACKs for what the timer
/// resent. They show a delay, not reordering, so RACK still declares the
/// next losses as without the outage: three segments lost mid-burst, then
/// the first retransmission, are repaired as fast either way, not after a
/// widened reordering window or the RTO. (The lost retransmission waits
/// out the 2 ms floor: only SACKs within the tick its successors left show
/// it, which a late original's could equally explain.)
#[test]
fn spurious_timeout_does_not_teach_rack_reordering() {
    let mut took_without = 0;
    for outage in [false, true] {
        let v = LinkCfg::new(0, 10_000, 1024).delay_us(100);
        let mut rev = v;
        if outage {
            rev.blackout = (50_000, 350_000);
        }
        let mut s = Sim::new(v, rev, 4, 0, 0);
        assert!(s.run(1_000_000, |s| s.a.state() == State::Established));
        // A trickle of data across the outage.
        let mut t = s.now_us;
        while t < 1_200_000 {
            s.f_ab.total += 4 * 1448;
            assert!(s.run(t + 2_000_000, |s| s.f_ab.recvd == s.f_ab.total));
            t = s.now_us.max(t + 20_000);
            let quiet = t;
            let _ = s.run(quiet, |s| s.now_us >= quiet);
            s.now_us = s.now_us.max(quiet);
        }
        let p1 = s.a.stats();
        assert_eq!(p1.rto_count > 0, outage, "the outage caused the timeout");
        let n = s.ab.stats.data_in;
        let drops = std::vec![n + 15, n + 16, n + 17, n + 30].into_boxed_slice();
        s.ab.cfg.drop_idx = Box::leak(drops);
        let start = s.now_us;
        s.f_ab.total += 30 * 1448;
        assert!(s.run(start + 5_000_000, |s| s.f_ab.recvd == s.f_ab.total));
        let took = s.now_us - start;
        assert_eq!(s.a.stats().rto_count, p1.rto_count, "outage={outage}: RTO");
        assert!(took < 2_500, "outage={outage}: repaired in {took} us");
        if outage {
            assert!(
                took <= took_without,
                "repaired in {took} us after the outage, {took_without} us without"
            );
        } else {
            took_without = took;
        }
    }
}

/// Mild reordering on a virtual link (100 µs RTT, 1 % of packets 100 µs
/// late) is absorbed by RACK's reordering window. In whole milliseconds
/// `min_rtt / 4` is 0 below a 4 ms RTT, and every reordered packet used to
/// be retransmitted (hundreds per 32 MiB) with D-SACKs unable to widen 0.
#[test]
fn sub_millisecond_reordering_is_tolerated() {
    let fwd = LinkCfg::new(0, 10_000, 1024)
        .delay_us(50)
        .reorder_us(10_000, 100);
    let rev = LinkCfg::new(0, 10_000, 1024).delay_us(50);
    let bytes = 32 * MIB;
    let mut s = Sim::new(fwd, rev, 7, bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report("virtual link 100us, 1% +100us reorder", bytes);
    let spurious = o.b.dup_bytes_received as f64 / SMSS;
    assert!(spurious <= 10.0, "{spurious:.0} spurious retransmissions");
    assert_eq!(o.a.rto_count, 0);
}

/// The same reordering, where a reordered original's fast retransmission
/// leaves late in one millisecond and the original's cumulative ACK comes
/// back early in the next. RACK times the retransmission at 1 ms, which its
/// ambiguity filter cannot tell from the 1 ms minimum RTT, so the
/// retransmission became RACK's newest delivery, and with no reordering
/// window yet everything outstanding sent before it, a whole window of data
/// still in flight, was marked lost at once (105 segments for seed 1).
/// Linux, timing in microseconds, sees a retransmission ACKed faster than
/// the minimum RTT and ignores it (`tcp_rack_advance`).
#[test]
fn late_original_acked_across_a_millisecond_does_not_condemn_the_window() {
    let link = LinkCfg::new(0, 10_000, 1024)
        .delay_us(50)
        .reorder_us(10_000, 100);
    let rev = LinkCfg::new(0, 10_000, 1024).delay_us(50);
    let bytes = 8 * MIB;
    let mut s = Sim::new(link, rev, 1, bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report("virtual link 100us, 1% +100us reorder, seed 1", bytes);
    let spurious = o.b.dup_bytes_received as f64 / SMSS;
    assert!(spurious <= 10.0, "{spurious:.0} spurious retransmissions");
    assert_eq!(o.a.rto_count, 0);
    // The worst of 24 seeds: 262 spurious retransmissions over 16 MiB.
    let mut s = Sim::new(link, rev, 18, 2 * bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report("virtual link 100us, 1% +100us reorder, seed 18", 2 * bytes);
    let spurious = o.b.dup_bytes_received as f64 / SMSS;
    assert!(spurious <= 10.0, "{spurious:.0} spurious retransmissions");
    assert_eq!(o.a.rto_count, 0);
    // Both directions at once.
    let mut s = Sim::new(link, link, 1, 4 * MIB, 4 * MIB);
    let o = s.run_transfer(60_000_000);
    o.report("virtual link 100us, 1% +100us reorder, both ways", 4 * MIB);
    let spurious = (o.a.dup_bytes_received + o.b.dup_bytes_received) as f64 / SMSS;
    assert!(spurious <= 20.0, "{spurious:.0} spurious retransmissions");
    assert_eq!((o.a.rto_count, o.b.rto_count), (0, 0));
}

/// The same reordering through a shallow queue (256 packets): once
/// reordering is seen, RACK waits out its window (at least 2 ms with a
/// millisecond clock) before declaring a queue drop lost, while the sender
/// keeps filling the peer's window past the hole. Halving FlightSize, which
/// counts that SACKed data, then left cwnd where it was, and every round
/// overflowed the queue again; halving cwnd, as Linux does, settles.
#[test]
fn sub_millisecond_reordering_through_a_shallow_queue_halves_the_window() {
    let fwd = LinkCfg::new(0, 10_000, 256)
        .delay_us(50)
        .reorder_us(10_000, 100);
    let rev = LinkCfg::new(0, 10_000, 256).delay_us(50);
    let bytes = 32 * MIB;
    let mut s = Sim::new(fwd, rev, 7, bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report(
        "virtual link 100us, 1% +100us reorder, 256-pkt queue",
        bytes,
    );
    assert!(
        o.a.fast_recoveries <= 6,
        "{} recoveries",
        o.a.fast_recoveries
    );
    assert!(
        o.fwd.data_dropped * 100 <= o.fwd.data_in * 3,
        "{} of {} segments dropped",
        o.fwd.data_dropped,
        o.fwd.data_in
    );
    assert_eq!(o.a.rto_count, 0);
}

/// Both ways through a 64-packet queue with 1% of packets 0.1 ms late:
/// once reordering is seen, RACK's 2 ms reordering window (the millisecond
/// clock's floor) lets ACKs mark a slow-start overshoot lost only in part,
/// and the reordering timer marks the rest — hundreds of segments at once.
/// Resending them all at once (cwnd still read pipe + its last PRR step)
/// overflowed the queue again, and with nothing sent after the lost
/// resends, only a tail loss probe (one segment out: 200 ms) or the RTO
/// repaired them (0.22 s and 0.27 s, against 0.03 s and 0.07 s).
#[test]
fn two_way_shallow_queue_reordering_recovers_without_a_timeout() {
    for (rate, seed) in [(10_000, 6u64), (2_500, 9)] {
        let link = LinkCfg::new(0, rate, 64)
            .delay_us(50)
            .reorder_us(10_000, 100);
        let bytes = 16 * MIB;
        let mut s = Sim::new(link, link, seed, bytes, bytes);
        let o = s.run_transfer(600_000_000);
        o.report(
            &std::format!(
                "virtual link 100us, {rate} Mbit/s, 1% +100us reorder, 64-pkt queue, both ways, seed {seed}"
            ),
            bytes,
        );
        let timeouts = (o.a.rto_count, o.b.rto_count, o.a.tlp_count, o.b.tlp_count);
        assert_eq!(timeouts, (0, 0, 0, 0), "seed {seed}: RTOs, TLPs");
        assert!(o.secs < 0.1, "seed {seed}: {:.3} s", o.secs);
        for (name, tx, link) in [("A", &o.a, &o.fwd), ("B", &o.b, &o.rev)] {
            assert!(
                u64::from(tx.segs_retrans) <= link.data_dropped + 8,
                "seed {seed} {name}: {} retransmissions for {} drops",
                tx.segs_retrans,
                link.data_dropped
            );
        }
    }
}

/// Both ways at 1 Gbit/s through a 64-packet queue, 1% of packets 0.1 ms
/// late: SACKs queue behind the peer's data, and one for a resend's late
/// original arrived within the tick the resend left. Credited to the
/// resend, it condemned the resends sent just before it in that tick at
/// once (42 spurious retransmissions in this run).
#[test]
fn late_original_does_not_condemn_resends_of_the_same_tick() {
    let link = LinkCfg::new(0, 1_000, 64)
        .delay_us(50)
        .reorder_us(10_000, 100);
    let mut s = Sim::new(link, link, 4, 8 * MIB, 8 * MIB);
    let o = s.run_transfer(60_000_000);
    o.report(
        "virtual link 100us, 1 Gbit/s, 1% +100us reorder, 64-pkt queue, both ways",
        8 * MIB,
    );
    for (name, rx) in [("A", &o.b), ("B", &o.a)] {
        let spurious = rx.dup_bytes_received as f64 / SMSS;
        assert!(
            spurious <= 10.0,
            "{name}: {spurious:.0} spurious retransmissions"
        );
    }
}

/// What a two-way transfer over a virtual link needs to finish without a
/// single retransmission or probe: a host that hands packets to the device
/// queue only while it has room, leaving the rest in the TCB's egress ring
/// (`Host::Ring`), or that pauses the TCB's egress as the queue fills
/// (`Host::Pause`). The queue then never overflows, as a router's does on
/// every slow-start overshoot and Reno sawtooth (hundreds of segments per
/// run at 64–256 packets, as in the tests above). With 1% of packets
/// 0.1 ms late, only the first reordering is taken for a loss (one
/// recovery, at most four segments resent over seeds 1–8), before any has
/// been seen (as Linux: `tcp_rack_reo_wnd`).
#[test]
fn two_way_virtual_link_with_host_backpressure_retransmits_nothing() {
    for host in [Host::Ring, Host::Pause] {
        for (rate, queue) in [(10_000, 64), (10_000, 256), (1_000, 64)] {
            for late in [false, true] {
                let mut link = LinkCfg::new(0, rate, queue).delay_us(50).host(host);
                if late {
                    link = link.reorder_us(10_000, 100);
                }
                let bytes = 4 * MIB;
                let mut s = Sim::new(link, link, 1, bytes, bytes);
                let o = s.run_transfer(60_000_000);
                let name = std::format!(
                    "virtual link 100us, {} Mbit/s, {queue}-pkt queue, host {}, both ways{}",
                    rate,
                    if host == Host::Ring { "ring" } else { "pause" },
                    if late { ", 1% +100us reorder" } else { "" }
                );
                o.report(&name, bytes);
                for (st, l) in [(&o.a, &o.fwd), (&o.b, &o.rev)] {
                    assert_eq!(l.data_dropped, 0, "{name}");
                    assert_eq!((st.rto_count, st.tlp_count), (0, 0), "{name}");
                    let (recoveries, resends) = if late { (1, 4) } else { (0, 0) };
                    assert!(
                        st.fast_recoveries <= recoveries && st.segs_retrans <= resends,
                        "{name}: {} recoveries, {} retransmissions",
                        st.fast_recoveries,
                        st.segs_retrans
                    );
                }
                s.close_both();
            }
        }
    }
}

/// Request/response over a clean virtual link (200 µs RTT, 10 Gbit/s), from
/// 1 B to 1 MiB, odd segment counts included: no retransmission, probe or
/// timeout on either side, and no exchange waits on a delayed ACK.
#[test]
fn virtual_link_request_response_is_clean() {
    let link = LinkCfg::new(0, 10_000, 1024).delay_us(100);
    let quiet = |s: &Sim| {
        [&s.a, &s.b].iter().all(|t| {
            let d = t.debug_snapshot();
            d.snd_una == d.snd_nxt && d.tx_len == 0
        }) && s.ab.flight.is_empty()
            && s.ba.flight.is_empty()
    };
    for (req, resp) in [
        (1, 1),
        (100, 100),
        (1449, 1),
        (4344, 64),
        (64, 4345),
        (MIB, 64),
        (64, MIB),
    ] {
        let mut s = Sim::new(link, link, 5, 0, 0);
        assert!(s.run(1_000_000, |s| {
            s.a.state() == State::Established && s.b.state() == State::Established
        }));
        let mut worst = 0;
        for _ in 0..16 {
            let start = s.now_us;
            s.f_ab.total += req;
            s.f_ab.done_us = None;
            assert!(s.run(start + 5_000_000, |s| s.f_ab.recvd == s.f_ab.total));
            s.f_ba.total += resp;
            s.f_ba.done_us = None;
            assert!(s.run(start + 5_000_000, |s| s.f_ba.recvd == s.f_ba.total));
            worst = worst.max(s.now_us - start);
        }
        let limit = s.now_us + 2_000_000;
        assert!(s.run(limit, quiet), "{req}/{resp}: did not settle");
        for t in [s.a.stats(), s.b.stats()] {
            assert_eq!(
                (t.segs_retrans, t.tlp_count, t.rto_count),
                (0, 0, 0),
                "{req}/{resp}: {t:?}"
            );
        }
        // A delayed ACK holding up an exchange costs 40 ms.
        assert!(worst < 20_000, "{req}/{resp}: worst exchange {worst} µs");
    }
}

#[test]
fn ack_loss_does_not_trigger_retransmission() {
    let fwd = LinkCfg::new(10, 50, 1000);
    let rev = LinkCfg::new(10, 50, 1000).loss(200_000);
    let bytes = 4 * MIB;
    let mut s = Sim::new(fwd, rev, 6, bytes, 0);
    let o = s.run_transfer(60_000_000);
    o.report("20% ACK loss", bytes);
    let line = 50e6 / 8.0 * SMSS / 1500.0;
    assert!(o.goodput(bytes) >= 0.7 * line);
    o.assert_no_spurious_storm(0);
    s.close_both();
}

#[test]
fn bidirectional_lossy_transfer_and_close() {
    let fwd = LinkCfg::new(15, 20, 200).loss(10_000);
    let rev = LinkCfg::new(15, 20, 200).loss(10_000);
    let mut s = Sim::new(fwd, rev, 10, 2 * MIB, 2 * MIB);
    let o = s.run_transfer(600_000_000);
    o.report("bidir 1% both ways", 4 * MIB);
    for st in [o.a, o.b] {
        assert!(u64::from(st.rto_count) * 10 <= st.segs_retrans.max(10));
    }
    o.assert_no_spurious_storm(0);
    s.close_both();
}

#[test]
fn slow_reader_flow_controls_without_retransmission() {
    let fwd = LinkCfg::new(10, 100, 1000);
    let rev = LinkCfg::new(10, 100, 1000);
    let bytes = 2 * MIB;
    let mut s = Sim::new(fwd, rev, 11, bytes, 0);
    s.f_ab.read_rate = Some(500); // 500 KB/s
    let o = s.run_transfer(60_000_000);
    o.report("slow reader 500KB/s", bytes);
    assert_eq!(o.a.segs_retrans, 0, "flow control must not look like loss");
    assert!(o.goodput(bytes) >= 0.9 * 500_000.0);
    s.close_both();
}

#[test]
fn chaos_seeds_complete_with_integrity() {
    // Loss, reordering and ACK loss in both directions, sequence numbers
    // wrapping mid-transfer, small queue. Every seed must complete, deliver
    // intact data and close cleanly.
    for seed in 100..106u64 {
        let link = LinkCfg::new(8, 30, 40).loss(20_000).reorder(30_000, 3);
        let iss = (u32::MAX - 300_000, u32::MAX - 200_000);
        let mut s = Sim::with_iss(link, link, seed, 768 * 1024, 512 * 1024, iss);
        let o = s.run_transfer(900_000_000);
        o.report(&std::format!("chaos seed {seed}"), 1280 * 1024);
        assert!(o.a.rto_count + o.b.rto_count <= 6, "RTO-driven recovery");
        s.close_both();
    }
}
