//! Performance.
//!
//! 1. Goodput over the deterministic link simulation, on the path profiles
//!    `bindings/netem/bench.sh` uses (virtual time, so the numbers are exact
//!    and reproducible, and independent of the host's speed).
//! 2. CPU cost per byte and per request/response transaction, in wall-clock
//!    time, with both endpoints in one thread over a zero-delay in-memory
//!    wire. Only time spent inside each stack's calls is counted, per side.

use std::time::Instant as Clock;

use crate::net::LinkCfg;
use crate::report::{mbps, Table};
use crate::sim::{self, App, ClosePolicy, Goal, Scenario, MIB, MS, SEC};
use crate::stacks::{self, Opts, Pkt, Recv, Spec, St, Stack, Time};

// ---------------------------------------------------------------------------
// Link simulation.
// ---------------------------------------------------------------------------

pub struct Profile {
    pub name: &'static str,
    pub rtt_ms: u64,
    pub mbit: u64,
    pub loss_ppm: u32,
    pub queue: usize,
    pub reorder_ppm: u32,
    /// Data segments `[lo, hi)` (by link-entry index) are dropped.
    pub burst: (u64, u64),
    pub mib: u64,
}

const fn prof(
    name: &'static str,
    rtt_ms: u64,
    mbit: u64,
    loss_ppm: u32,
    queue: usize,
    mib: u64,
) -> Profile {
    Profile {
        name,
        rtt_ms,
        mbit,
        loss_ppm,
        queue,
        reorder_ppm: 0,
        burst: (0, 0),
        mib,
    }
}

pub const PROFILES: &[Profile] = &[
    prof("lan", 1, 1000, 0, 200, 64),
    prof("wan", 40, 100, 0, 160, 32),
    prof("wan-0.1", 40, 100, 1_000, 160, 16),
    prof("wan-1", 40, 100, 10_000, 160, 4),
    prof("metro-0.1", 10, 200, 1_000, 80, 32),
    prof("lossy-5", 20, 50, 50_000, 80, 2),
    prof("shallow", 20, 100, 0, 16, 32),
    Profile {
        reorder_ppm: 20_000,
        ..prof("reorder-2", 20, 50, 0, 1000, 8)
    },
    Profile {
        burst: (300, 340),
        ..prof("burst-40", 20, 100, 0, 1000, 4)
    },
];

impl Profile {
    fn links(&self) -> (LinkCfg, LinkCfg) {
        let half = self.rtt_ms * 1000 / 2;
        let fwd = LinkCfg::new(0, self.mbit, self.queue)
            .delay_us(half)
            .loss(self.loss_ppm)
            .reorder(self.reorder_ppm, 4)
            .drop_data(self.burst.0, self.burst.1);
        let rev = LinkCfg::new(0, 0, 1 << 20).delay_us(half);
        (fwd, rev)
    }
    pub fn describe(&self) -> String {
        let mut s = format!(
            "{} ms, {} Mbit/s, {}-pkt queue",
            self.rtt_ms, self.mbit, self.queue
        );
        if self.loss_ppm > 0 {
            s += &format!(", {}% loss", f64::from(self.loss_ppm) / 1e4);
        }
        if self.reorder_ppm > 0 {
            s += &format!(", {}% +4 ms reorder", f64::from(self.reorder_ppm) / 1e4);
        }
        if self.burst.1 > self.burst.0 {
            s += &format!(", {} consecutive drops", self.burst.1 - self.burst.0);
        }
        s + &format!("; {} MiB", self.mib)
    }
}
pub fn sim_pairs() -> Vec<(Spec, Spec)> {
    vec![
        (Spec::Ours, Spec::Ours),
        (Spec::SMOL, Spec::SMOL),
        (Spec::SMOL_RENO, Spec::SMOL_RENO),
        (Spec::SMOL, Spec::Ours),
        (Spec::Ours, Spec::SMOL),
    ]
}

#[derive(Clone, Debug, Default)]
pub struct SimCell {
    /// Goodput per seed (bytes/s); `None` = did not finish.
    pub goodput: Vec<Option<f64>>,
    pub retx: Vec<u64>,
    pub drops: Vec<u64>,
    pub needless: Vec<u64>,
}

fn median<T: Copy + PartialOrd>(v: &[T]) -> Option<T> {
    let mut v = v.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v.get(v.len() / 2).copied()
}

/// An upload over profile `p`. The sender keeps the connection open: a
/// FIN queued behind the data changes how smoltcp sends (it skips Nagle
/// in FIN-WAIT-1), which is not what a goodput figure should measure.
fn upload(p: &Profile, sender: Spec, receiver: Spec, seed: u64, bytes: u64) -> Scenario {
    let (fwd, rev) = p.links();
    let mut sc = Scenario::new(sender, receiver, fwd);
    sc.rev = rev;
    sc.seed = 100 + seed;
    sc.client_seed = 1000 + seed;
    sc.server_seed = 2000 + seed;
    sc.client_app = App::sender(bytes);
    sc.client_app.close = ClosePolicy::Never;
    sc.server_app = App::sender(0);
    sc.limit = 1800 * SEC;
    sc
}

pub fn sim_cell(p: &Profile, sender: Spec, receiver: Spec, seeds: u64, scale: u64) -> SimCell {
    let mut c = SimCell::default();
    for seed in 0..seeds {
        let sc = upload(p, sender, receiver, seed, p.mib * MIB / scale);
        let o = sim::run(&sc, Goal::Delivered);
        c.goodput.push(if o.ok() { o.goodput() } else { None });
        c.retx.push(o.fwd.retx_pkts);
        c.drops.push(o.fwd.data_drops);
        c.needless.push(o.fwd.dup_delivered.div_ceil(1448));
    }
    c
}

pub struct SimResults {
    pub cells: Vec<(&'static str, (Spec, Spec), SimCell)>,
}

/// One profile, one pairing, one seed, in detail.
pub fn diag(name: &str, sender: Spec, receiver: Spec, seed: u64, trace: bool) {
    let Some(p) = PROFILES.iter().find(|p| p.name == name) else {
        eprintln!("no such profile: {name}");
        return;
    };
    let mut sc = upload(p, sender, receiver, seed, p.mib * MIB);
    sc.trace = trace;
    let o = sim::run(&sc, Goal::Delivered);
    println!(
        "{} ({} → {}): {}",
        p.name,
        sender.label(),
        receiver.label(),
        p.describe()
    );
    if let Some(g) = o.goodput() {
        println!("  goodput {} Mbit/s", mbps(g));
    }
    crate::interop::print_outcome(&o);
}

pub fn run_sim(quick: bool) -> SimResults {
    let (seeds, scale) = if quick { (1, 4) } else { (5, 1) };
    let mut cells = Vec::new();
    for p in PROFILES {
        for pair in sim_pairs() {
            cells.push((p.name, pair, sim_cell(p, pair.0, pair.1, seeds, scale)));
        }
    }
    SimResults { cells }
}

fn goodput_cell(c: &SimCell) -> String {
    let done: Vec<f64> = c.goodput.iter().flatten().copied().collect();
    if done.len() < c.goodput.len() {
        return format!("DNF ({}/{} finished)", done.len(), c.goodput.len());
    }
    let (Some(m), Some(lo), Some(hi)) = (
        median(&done),
        done.iter().copied().reduce(f64::min),
        done.iter().copied().reduce(f64::max),
    ) else {
        return "–".into();
    };
    if done.len() == 1 || mbps(lo) == mbps(hi) {
        mbps(m)
    } else {
        format!("{} ({}–{})", mbps(m), mbps(lo), mbps(hi))
    }
}

pub fn print_sim(r: &SimResults) {
    let pairs = sim_pairs();
    let head = |first: &str| {
        let mut h = vec![first.to_string()];
        h.extend(
            pairs
                .iter()
                .map(|(s, d)| format!("{} → {}", s.label(), d.label())),
        );
        h
    };
    let mut t = Table::new(head("Profile (sender → receiver)"));
    let mut e = Table::new(head("Profile"));
    for p in PROFILES {
        let mut row = vec![format!("**{}**: {}", p.name, p.describe())];
        let mut erow = vec![p.name.to_string()];
        for pair in &pairs {
            let c = r
                .cells
                .iter()
                .find(|(n, pp, _)| *n == p.name && pp == pair)
                .map(|x| &x.2);
            row.push(c.map_or("–".into(), goodput_cell));
            erow.push(c.map_or("–".into(), |c| {
                format!(
                    "{} / {} / {}",
                    median(&c.retx).unwrap_or(0),
                    median(&c.drops).unwrap_or(0),
                    median(&c.needless).unwrap_or(0)
                )
            }));
        }
        t.row(row);
        e.row(erow);
    }
    println!("Goodput, Mbit/s: median (min–max) over seeds, from ESTABLISHED to the last byte delivered.\n");
    t.print();
    println!("Sender efficiency, medians: retransmitted segments / data segments dropped by the link / retransmissions of data the link had already delivered (a receiver may still have discarded it).\n");
    e.print();
}

// ---------------------------------------------------------------------------
// CPU.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct Cpu {
    /// Seconds spent inside the first / second endpoint's calls.
    pub a_secs: f64,
    pub b_secs: f64,
    pub bytes: u64,
    /// Data segments (bulk) or transactions (request/response).
    pub units: u64,
    /// Packets sent by the second endpoint (ACKs in a bulk transfer).
    pub b_pkts: u64,
    pub a_pkts: u64,
}

fn endpoints(a: Spec, b: Spec) -> (Box<dyn Stack>, Box<dyn Stack>) {
    let oa = Opts {
        local: (sim::CLIENT_IP, sim::CLIENT_PORT),
        remote: (sim::SERVER_IP, sim::SERVER_PORT),
        seed: 1,
        mtu: 1500,
    };
    let ob = Opts {
        local: (sim::SERVER_IP, sim::SERVER_PORT),
        remote: (sim::CLIENT_IP, sim::CLIENT_PORT),
        seed: 2,
        mtu: 1500,
    };
    (stacks::build(a, &oa), stacks::build(b, &ob))
}

/// Exchange packets (untimed) until both ends are ESTABLISHED.
fn establish(a: &mut dyn Stack, b: &mut dyn Stack, now: &mut Time) {
    let mut w = Vec::new();
    b.listen(*now);
    a.connect(*now);
    for _ in 0..1000 {
        a.poll(*now);
        a.drain(&mut w);
        for p in w.drain(..) {
            b.input(*now, p);
        }
        b.poll(*now);
        b.drain(&mut w);
        for p in w.drain(..) {
            a.input(*now, p);
        }
        if a.state() == St::Established && b.state() == St::Established {
            return;
        }
        *now += MS;
    }
    panic!("no handshake between {} and {}", a.name(), b.name());
}

fn next_time(now: Time, moved: bool, a: &mut dyn Stack, b: &mut dyn Stack) -> Time {
    if moved {
        return now + 10;
    }
    let w = [a.next_wake(now), b.next_wake(now)]
        .into_iter()
        .flatten()
        .min();
    w.unwrap_or(now + MS).max(now + 10)
}

/// `bytes` from `sender` to `receiver`, verified (outside the timing).
/// `per_packet`: every datagram is handed over and acted on before the
/// next (a host reading one packet per syscall); otherwise each side gets
/// the whole flight, then acts once. Each side ticks once per round, after
/// the application ran, as the tcp-sans-io host contract asks.
pub fn bulk(sender: Spec, receiver: Spec, bytes: u64, per_packet: bool) -> Cpu {
    let (mut a, mut b) = endpoints(sender, receiver);
    let mut now: Time = 0;
    establish(a.as_mut(), b.as_mut(), &mut now);
    let (mut ab, mut ba) = (
        Vec::<Pkt>::with_capacity(4096),
        Vec::<Pkt>::with_capacity(4096),
    );
    let mut out = Vec::<Pkt>::with_capacity(4096);
    let mut buf = vec![0u8; 64 * 1024];
    let (mut sent, mut recvd) = (0u64, 0u64);
    let (mut ta, mut tb) = (0f64, 0f64);
    let (mut data, mut acks) = (0u64, 0u64);
    let feed = |s: &mut dyn Stack, now: Time, inp: &mut Vec<Pkt>, out: &mut Vec<Pkt>| {
        if per_packet {
            for p in inp.drain(..) {
                s.input(now, p);
                s.process(now);
                s.drain(out);
            }
        } else {
            for p in inp.drain(..) {
                s.input(now, p);
            }
            s.process(now);
        }
    };
    while recvd < bytes {
        let t = Clock::now();
        feed(a.as_mut(), now, &mut ba, &mut ab);
        while sent < bytes {
            let n = ((bytes - sent) as usize).min(sim::PERIOD);
            let w = a.send(sim::pattern(1, sent, n));
            sent += w as u64;
            if w < n {
                break;
            }
        }
        a.poll(now);
        a.drain(&mut ab);
        ta += t.elapsed().as_secs_f64();
        let moved = !ab.is_empty();
        data += ab.len() as u64;

        let t = Clock::now();
        feed(b.as_mut(), now, &mut ab, &mut out);
        let mut spent = t.elapsed().as_secs_f64();
        loop {
            let t = Clock::now();
            let r = b.recv(&mut buf);
            spent += t.elapsed().as_secs_f64();
            match r {
                Recv::Data(n) => {
                    assert!(
                        sim::mismatch(1, recvd, &buf[..n]).is_none(),
                        "{} delivered corrupt data",
                        b.name()
                    );
                    recvd += n as u64;
                }
                _ => break,
            }
        }
        let t = Clock::now();
        b.poll(now);
        b.drain(&mut out);
        tb += spent + t.elapsed().as_secs_f64();
        acks += out.len() as u64;
        ba.append(&mut out);
        now = next_time(now, moved || !ba.is_empty(), a.as_mut(), b.as_mut());
    }
    Cpu {
        a_secs: ta,
        b_secs: tb,
        bytes,
        units: data,
        a_pkts: data,
        b_pkts: acks,
    }
}

/// `n` request/response transactions of `size` bytes each way.
pub fn rr(client: Spec, server: Spec, n: u64, size: usize) -> Cpu {
    let (mut a, mut b) = endpoints(client, server);
    let mut now: Time = 0;
    establish(a.as_mut(), b.as_mut(), &mut now);
    let msg = sim::pattern(3, 0, size);
    let mut buf = vec![0u8; 64 * 1024];
    let mut w = Vec::<Pkt>::with_capacity(64);
    let (mut ta, mut tb) = (0f64, 0f64);
    let (mut ap, mut bp) = (0u64, 0u64);
    // Hand `w` to `s` and let it act; then (optionally) the application
    // runs `app`, and `s` ticks to send what the application queued.
    fn turn(
        s: &mut dyn Stack,
        now: Time,
        w: &mut Vec<Pkt>,
        pkts: &mut u64,
        app: impl FnOnce(&mut dyn Stack),
    ) {
        for p in w.drain(..) {
            s.input(now, p);
        }
        s.process(now);
        app(s);
        s.poll(now);
        let k = w.len();
        s.drain(w);
        *pkts += (w.len() - k) as u64;
    }
    for _ in 0..n {
        let t = Clock::now();
        turn(a.as_mut(), now, &mut w, &mut ap, |s| {
            assert_eq!(s.send(msg), size, "{} would not take a request", s.name());
        });
        ta += t.elapsed().as_secs_f64();
        // Server: request in, response out (it may take a timer or two).
        let mut got = 0;
        for _ in 0..100 {
            let t = Clock::now();
            turn(b.as_mut(), now, &mut w, &mut bp, |s| {
                while let Recv::Data(k) = s.recv(&mut buf) {
                    got += k;
                }
                if got >= size {
                    s.send(msg);
                }
            });
            tb += t.elapsed().as_secs_f64();
            if got >= size {
                break;
            }
            let t = Clock::now();
            turn(a.as_mut(), now, &mut w, &mut ap, |_| {});
            ta += t.elapsed().as_secs_f64();
            now = next_time(now, false, a.as_mut(), b.as_mut());
        }
        // Client: response in.
        let mut got = 0;
        for _ in 0..100 {
            let t = Clock::now();
            turn(a.as_mut(), now, &mut w, &mut ap, |s| {
                while let Recv::Data(k) = s.recv(&mut buf) {
                    got += k;
                }
            });
            ta += t.elapsed().as_secs_f64();
            if got >= size {
                break;
            }
            let t = Clock::now();
            turn(b.as_mut(), now, &mut w, &mut bp, |_| {});
            tb += t.elapsed().as_secs_f64();
            now = next_time(now, false, a.as_mut(), b.as_mut());
        }
        assert!(got >= size, "transaction stalled");
        now += 10;
    }
    Cpu {
        a_secs: ta,
        b_secs: tb,
        bytes: n * size as u64 * 2,
        units: n,
        a_pkts: ap,
        b_pkts: bp,
    }
}

/// Median with the spread as ± half the min–max range, in percent.
fn spread(v: &[f64], decimals: usize) -> String {
    let m = median(v).unwrap_or(0.0);
    let lo = v.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = v.iter().copied().fold(0.0, f64::max);
    if v.len() < 2 || m <= 0.0 {
        return format!("{m:.decimals$}");
    }
    format!("{m:.decimals$} ±{:.0}%", (hi - lo) / 2.0 / m * 100.0)
}

pub fn run_cpu(quick: bool) {
    let (bytes, reps, txns) = if quick {
        (128 * MIB, 3, 50_000)
    } else {
        (1024 * MIB, 7, 200_000)
    };
    let pairs = [(Spec::Ours, Spec::Ours), (Spec::SMOL, Spec::SMOL)];
    let smol_nd = Spec::SMOL.with_nagle(false);
    let rr_pairs = [(Spec::Ours, Spec::Ours), (smol_nd, smol_nd)];
    // Interleave the configurations so drifting clocks, turbo and thermal
    // state affect them alike.
    let mut bulk_res = vec![[Vec::new(), Vec::new()]; pairs.len()];
    let mut rr_res = vec![Vec::new(); rr_pairs.len()];
    for _ in 0..reps {
        for (i, (s, d)) in pairs.iter().enumerate() {
            bulk_res[i][0].push(bulk(*s, *d, bytes, true));
            bulk_res[i][1].push(bulk(*s, *d, bytes, false));
        }
        for (i, (c, s)) in rr_pairs.iter().enumerate() {
            rr_res[i].push(rr(*c, *s, txns, 64));
        }
    }
    let gbps = |v: &[Cpu], side: fn(&Cpu) -> f64| {
        let xs: Vec<f64> = v
            .iter()
            .map(|c| c.bytes as f64 * 8.0 / side(c).max(1e-12) / 1e9)
            .collect();
        spread(&xs, 1)
    };
    let acks = |v: &[Cpu]| {
        let c = &v[0];
        format!("{:.0}", c.b_pkts as f64 * 100.0 / c.a_pkts.max(1) as f64)
    };
    let mut t = Table::new([
        "Bulk transfer (sender → receiver)",
        "Sender Gbit/s, per packet",
        "Receiver Gbit/s, per packet",
        "ACKs / 100 segments, per packet",
        "Sender Gbit/s, batched",
        "Receiver Gbit/s, batched",
        "ACKs / 100 segments, batched",
    ]);
    for ((s, d), [pp, ba]) in pairs.iter().zip(&bulk_res) {
        t.row([
            format!("{} → {}", s.label(), d.label()),
            gbps(pp, |c| c.a_secs),
            gbps(pp, |c| c.b_secs),
            acks(pp),
            gbps(ba, |c| c.a_secs),
            gbps(ba, |c| c.b_secs),
            acks(ba),
        ]);
    }
    println!(
        "{} MiB one way, median of {reps} interleaved runs (± half the range); Gbit/s of payload per \
         core-second spent in that endpoint. Per packet: each datagram is handed over and acted on \
         before the next (one read per packet, as from a TUN or WireGuard device). Batched: each side \
         gets the whole flight, then acts once. Only time inside each stack's calls counts (send/recv \
         copies, checksums, protocol work); the in-memory wire and the data verification are \
         excluded. Pin the process to one core for stable numbers.\n",
        bytes / MIB
    );
    t.print();

    let mut t = Table::new([
        "64 B request / 64 B response (client ⇄ server)",
        "Client µs / transaction",
        "Server µs / transaction",
        "Packets / transaction",
        "Transactions per core-second (both ends)",
    ]);
    for ((c, s), v) in rr_pairs.iter().zip(&rr_res) {
        let per = |side: fn(&Cpu) -> f64| {
            let xs: Vec<f64> = v.iter().map(|r| side(r) * 1e6 / r.units as f64).collect();
            spread(&xs, 2)
        };
        let tps: Vec<f64> = v
            .iter()
            .map(|r| r.units as f64 / (r.a_secs + r.b_secs))
            .collect();
        let r = &v[0];
        t.row([
            format!("{} ⇄ {}", c.label(), s.label()),
            per(|r| r.a_secs),
            per(|r| r.b_secs),
            format!("{:.2}", (r.a_pkts + r.b_pkts) as f64 / r.units as f64),
            format!("{:.0}", median(&tps).unwrap_or(0.0)),
        ]);
    }
    println!("{txns} transactions, median of {reps} interleaved runs.\n");
    t.print();
}
pub fn print_memory() {
    let mut t = Table::new(["Per-connection state", "Bytes", "Of which data buffers"]);
    for (what, total, bufs) in stacks::footprint() {
        t.row([what, total.to_string(), bufs]);
    }
    t.print();
}
