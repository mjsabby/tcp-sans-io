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
    const fn drop_data(mut self, lo: u64, hi: u64) -> Self {
        self.drop_data = (lo, hi);
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
    busy_until: u64,
    departures: VecDeque<u64>,
    flight: BinaryHeap<Reverse<(u64, u64, Vec<u8>)>>,
    order: u64,
    stats: LinkStats,
}

fn payload_len(pkt: &[u8]) -> usize {
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let doff = usize::from(pkt[ihl + 12] >> 4) * 4;
    total - ihl - doff
}

impl Link {
    fn new(cfg: LinkCfg, seed: u64) -> Self {
        Self {
            cfg,
            rng: Rng(seed | 1),
            busy_until: 0,
            departures: VecDeque::new(),
            flight: BinaryHeap::new(),
            order: 0,
            stats: LinkStats::default(),
        }
    }

    fn send(&mut self, now: u64, pkt: Vec<u8>) {
        let data = payload_len(&pkt) > 0;
        if data {
            let idx = self.stats.data_in;
            self.stats.data_in += 1;
            if (self.cfg.drop_data.0..self.cfg.drop_data.1).contains(&idx) {
                self.stats.data_dropped += 1;
                return;
            }
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
            let tx_us = (bits * 1_000_000).div_ceil(self.cfg.rate_bps);
            self.busy_until = self.busy_until.max(now) + tx_us;
            self.departures.push_back(self.busy_until);
            depart = self.busy_until;
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
    /// Overwrite each TCB's reclaimable storage at every step.
    poison: bool,
    /// Change buffer limits at random moments.
    limit_chaos: Option<Rng>,
    /// Largest (send, receive) capacity each TCB reached.
    peak: [(usize, usize); 2],
}

/// Buffer limits `(snd_min, snd_max, rcv_min, rcv_max)`.
type Limits = (usize, usize, usize, usize);

/// Overwrite (the front of) every span the TCB will not read before writing
/// it again; the byte-exact flows catch any span that was still live.
fn poison(t: &mut Tcb) {
    for s in t.reclaimable() {
        let n = s.len().min(256 * 1024);
        s[..n].fill(0xA5);
    }
}

fn drain_into(t: &mut Tcb, link: &mut Link, now_us: u64) {
    let mut buf = [0u8; MAX_PACKET];
    while let Ok(n) = t.extract_packet(&mut buf) {
        if n == 0 {
            break;
        }
        link.send(now_us, buf[..n].to_vec());
    }
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
        Self::build(fwd, rev, seed, (ab_bytes, ba_bytes), iss, None)
    }

    /// `new`, with buffer limits set on both TCBs before they open.
    fn tuned(fwd: LinkCfg, rev: LinkCfg, seed: u64, bytes: (usize, usize), l: Limits) -> Self {
        Self::build(fwd, rev, seed, bytes, (0x1234_5678, 0x8765_4321), Some(l))
    }

    fn build(
        fwd: LinkCfg,
        rev: LinkCfg,
        seed: u64,
        (ab_bytes, ba_bytes): (usize, usize),
        iss: (u32, u32),
        limits: Option<Limits>,
    ) -> Self {
        let mut a = boxed_tcb(TcbConfig {
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
        if let Some((s0, s1, r0, r1)) = limits {
            a.set_buffer_limits(s0, s1, r0, r1).unwrap();
            b.set_buffer_limits(s0, s1, r0, r1).unwrap();
        }
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
            poison: false,
            limit_chaos: None,
            peak: [(0, 0); 2],
        };
        s.a.set_now(0);
        s.a.connect().unwrap();
        drain_into(&mut s.a, &mut s.ab, 0);
        s
    }

    fn tick_all(&mut self) {
        let ms = self.now_us / 1000;
        for (i, (t, link)) in [(&mut self.a, &mut self.ab), (&mut self.b, &mut self.ba)]
            .into_iter()
            .enumerate()
        {
            t.set_now(ms);
            t.tick().unwrap();
            drain_into(t, link, self.now_us);
            t.debug_validate_invariants().unwrap();
            if let Some(d) = t.debug_next_deadline() {
                assert!(
                    d > ms,
                    "armed deadline {d} not in the future after tick at {ms}"
                );
            }
            let (snd, rcv) = t.buffer_capacity();
            self.peak[i] = (self.peak[i].0.max(snd), self.peak[i].1.max(rcv));
            if self.poison {
                poison(t);
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
        if let Some(rng) = self.limit_chaos.as_mut() {
            if rng.chance_ppm(2000) {
                const BUF: usize = crate::BUF_CAP;
                const CHOICES: [Limits; 6] = [
                    (4096, 4096, 4096, 4096),
                    (4096, BUF, 4096, BUF),
                    (8192, 65536, 8192, 65536),
                    (BUF, BUF, BUF, BUF),
                    (65536, 262_144, 4096, 16384),
                    (4096, 16384, 65536, 262_144),
                ];
                let (s0, s1, r0, r1) = CHOICES[(rng.next() % 6) as usize];
                let t = if rng.next() & 1 == 0 {
                    &mut self.a
                } else {
                    &mut self.b
                };
                t.set_buffer_limits(s0, s1, r0, r1).unwrap();
            }
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
            let Some(next) = [
                tcb,
                self.ab.next_delivery(),
                self.ba.next_delivery(),
                reader,
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

    /// Stay idle for `ms`, then trade one small message each way.
    fn ping_after(&mut self, ms: u64) {
        self.now_us += ms * 1000;
        self.f_ab = Flow::new(0x61, 1000);
        self.f_ba = Flow::new(0x62, 1000);
        let limit = self.now_us + 10_000_000;
        assert!(self.run(limit, |s| {
            s.f_ab.done_us.is_some() && s.f_ba.done_us.is_some()
        }));
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

// ---------------------------------------------------------------------------
// Autotuned buffers (`set_buffer_limits`)
// ---------------------------------------------------------------------------

const TUNED: Limits = (4096, crate::BUF_CAP, 4096, crate::BUF_CAP);

/// From 64 KiB rings, autotuning fills the bottleneck as well as fixed
/// megabyte rings do, and in steady state the rings stay near what the path
/// holds (BDP 125 KB plus a 96 KB queue) — slow start may briefly overshoot.
#[test]
#[cfg(not(feature = "small-buffers"))] // sized for megabyte rings
fn autotuned_rings_fill_the_bottleneck_near_the_bdp() {
    let fwd = LinkCfg::new(10, 50, 64);
    let rev = LinkCfg::new(10, 50, 64);
    let bytes = 16 * MIB;
    let mut s = Sim::tuned(fwd, rev, 1, (bytes, 0), TUNED);
    let o = s.run_transfer(60_000_000);
    o.report("autotuned clean 50Mbit/20ms q64", bytes);
    let end = (s.a.buffer_capacity(), s.b.buffer_capacity());
    println!(
        "peak capacities: A {:?} B {:?}; at the end A {:?} B {:?}",
        s.peak[0], s.peak[1], end.0, end.1
    );
    let line = 50e6 / 8.0 * SMSS / 1500.0;
    assert!(o.goodput(bytes) >= 0.85 * line, "underfilled link");
    assert_eq!(o.a.rto_count, 0);
    o.assert_no_spurious_storm(2);
    assert!(end.0 .0 <= 512 * 1024, "sender ring {:?}", end.0);
    assert!(end.1 .1 <= 512 * 1024, "receiver ring {:?}", end.1);
    assert_eq!(s.peak[1].0, crate::INITIAL_RING_CAP, "B never sends");
    s.close_both();
}

/// On a long fat pipe the rings grow to the full window, and goodput stays
/// that of fixed megabyte rings.
#[test]
#[cfg(not(feature = "small-buffers"))] // sized for megabyte rings
fn autotuned_rings_grow_to_a_long_fat_pipe() {
    let link = LinkCfg::new(40, 100, 1000);
    let bytes = 32 * MIB;
    let fixed = Sim::new(link, link, 7, bytes, 0).run_transfer(120_000_000);
    fixed.report("fixed 100Mbit/80ms", bytes);
    let mut s = Sim::tuned(link, link, 7, (bytes, 0), TUNED);
    let tuned = s.run_transfer(120_000_000);
    tuned.report("autotuned 100Mbit/80ms", bytes);
    println!("peak capacities: A {:?} B {:?}", s.peak[0], s.peak[1]);
    assert!(tuned.goodput(bytes) >= 0.9 * fixed.goodput(bytes));
    assert_eq!(s.peak[0].0, crate::BUF_CAP, "sender grew to the window");
    assert_eq!(s.peak[1].1, crate::BUF_CAP, "receiver grew to the window");
}

/// After a bulk phase, a slow reader shrinks both ends' rings back down: the
/// sender's as its usable window collapses, the receiver's once the peer has
/// used up the window it had been promised.
#[test]
#[cfg(not(feature = "small-buffers"))] // sized for megabyte rings
fn autotuned_rings_shrink_when_the_reader_slows_down() {
    let link = LinkCfg::new(10, 50, 64);
    let mut s = Sim::tuned(link, link, 2, (4 * MIB, 0), TUNED);
    s.run_transfer(60_000_000);
    let grown = (s.a.buffer_capacity().0, s.b.buffer_capacity().1);
    assert!(grown.0 >= 256 * 1024 && grown.1 >= 256 * 1024, "{grown:?}");
    // More than the receiver's outstanding promise, read at 100 KB/s.
    s.f_ab = Flow::new(0x33, 1536 * 1024);
    s.f_ab.read_rate = Some(100);
    s.f_ab.last_read_ms = s.now_us / 1000;
    let limit = s.now_us + 60_000_000;
    assert!(
        s.run(limit, |s| s.f_ab.done_us.is_some()),
        "slow phase stalled"
    );
    // Shrinks are decided once per epoch: let one pass, then talk again.
    s.ping_after(2000);
    let small = (s.a.buffer_capacity().0, s.b.buffer_capacity().1);
    println!("grown {grown:?} -> slow reader {small:?}");
    assert!(small.0 <= 16 * 1024, "sender ring {small:?}");
    assert!(small.1 <= 16 * 1024, "receiver ring {small:?}");
    s.close_both();
}

/// Loss, reordering, random limit changes in both TCBs at any moment, and
/// every reclaimable byte overwritten at every step: the streams stay byte
/// exact (the flows check every byte) and the invariants hold.
#[test]
fn reclaimed_storage_and_limit_changes_never_corrupt_the_stream() {
    for seed in 0..6u64 {
        let link = LinkCfg::new(5, 20, 32).loss(10_000).reorder(20_000, 3);
        let mut s = Sim::tuned(link, link, 300 + seed, (MIB, 512 * 1024), TUNED);
        s.poison = true;
        s.limit_chaos = Some(Rng(seed + 1));
        let o = s.run_transfer(900_000_000);
        o.report(&std::format!("limit chaos seed {seed}"), 1536 * 1024);
        s.close_both();
    }
}
