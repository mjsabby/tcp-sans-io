//! RFC conformance probes: a scripted raw peer drives each stack into a
//! state, sends one crafted segment and checks what comes back. Every probe
//! runs unchanged against both stacks.

use std::collections::VecDeque;

use crate::pkt::{self, Build, Seg, ACK, FIN, PSH, RST, SYN};
use crate::report::Table;
use crate::sim::{CLIENT_IP, CLIENT_PORT, MS, SEC, SERVER_IP, SERVER_PORT};
use crate::stacks::{self, Opts, Pkt, Recv, Spec, St, Stack, Time};

#[derive(Clone, Debug)]
pub enum Verdict {
    Pass(String),
    /// Survives, but short of the recommended behaviour.
    Warn(String),
    Fail(String),
    /// A measurement or an optional feature.
    Info(String),
}

impl Verdict {
    fn cell(&self) -> String {
        let (mark, s) = match self {
            Verdict::Pass(s) => ("✅", s),
            Verdict::Warn(s) => ("⚠️", s),
            Verdict::Fail(s) => ("❌", s),
            Verdict::Info(s) => ("ℹ️", s),
        };
        if s.is_empty() {
            mark.into()
        } else {
            format!("{mark} {s}")
        }
    }
}

fn pass(s: impl Into<String>) -> Verdict {
    Verdict::Pass(s.into())
}
fn fail(s: impl Into<String>) -> Verdict {
    Verdict::Fail(s.into())
}

// ---------------------------------------------------------------------------
// The lab: one stack under test and a scripted peer.
// ---------------------------------------------------------------------------

pub struct Got {
    pub at: Time,
    pub seg: Seg,
}

#[derive(Clone, Copy)]
pub struct SynOpts {
    pub mss: Option<u16>,
    pub ws: Option<u8>,
    pub sack: bool,
    pub ts: bool,
    /// Window field once synchronized (scaled by `ws`).
    pub win: u16,
}

impl Default for SynOpts {
    fn default() -> Self {
        Self {
            mss: Some(1460),
            ws: Some(7),
            sack: true,
            ts: true,
            win: 8192,
        }
    }
}

const PEER_ISN: u32 = 0x1000_0000;

fn trace_on() -> bool {
    std::env::var_os("PROBE_TRACE").is_some()
}

fn describe(s: &Seg) -> String {
    let mut o = format!(
        "{} {}:{}>{}:{} seq={} ack={} win={} len={}",
        pkt::flags_str(s.flags),
        s.src[3],
        s.sport,
        s.dst[3],
        s.dport,
        s.seq,
        s.ack,
        s.win,
        s.payload_len
    );
    for (a, b) in s.sack_blocks() {
        o += &format!(" sack={a}-{b}");
    }
    o
}

pub struct Lab {
    pub sut: Box<dyn Stack>,
    pub now: Time,
    pub got: VecDeque<Got>,
    pub peer: ([u8; 4], u16),
    pub me: ([u8; 4], u16),
    /// Peer's next sequence number (the stack's RCV.NXT once in sync).
    pub snd_nxt: u32,
    /// Next byte expected from the stack.
    pub rcv_nxt: u32,
    pub sut_iss: u32,
    pub ts_on: bool,
    pub ts_recent: u32,
    pub sack_on: bool,
    pub win: u16,
    ip_id: u16,
}

impl Lab {
    fn new(spec: Spec, server: bool) -> Lab {
        let (me, peer) = if server {
            ((SERVER_IP, SERVER_PORT), (CLIENT_IP, CLIENT_PORT))
        } else {
            ((CLIENT_IP, CLIENT_PORT), (SERVER_IP, SERVER_PORT))
        };
        let opts = Opts {
            local: me,
            remote: peer,
            seed: 7,
            mtu: 1500,
        };
        Lab {
            sut: stacks::build(spec, &opts),
            now: 0,
            got: VecDeque::new(),
            peer,
            me,
            snd_nxt: PEER_ISN,
            rcv_nxt: 0,
            sut_iss: 0,
            ts_on: false,
            ts_recent: 0,
            sack_on: false,
            win: 65535,
            ip_id: 1,
        }
    }

    pub fn server(spec: Spec) -> Lab {
        let mut l = Lab::new(spec, true);
        l.sut.listen(0);
        l.collect();
        l
    }

    pub fn client(spec: Spec) -> Lab {
        Lab::new(spec, false)
    }

    pub fn tsval(&self) -> u32 {
        7_000_000 + (self.now / MS) as u32
    }

    /// A segment from the peer with the current sequence state.
    pub fn seg(&mut self, flags: u8) -> Build {
        self.ip_id = self.ip_id.wrapping_add(1);
        Build {
            src: self.peer.0,
            dst: self.me.0,
            sport: self.peer.1,
            dport: self.me.1,
            seq: self.snd_nxt,
            ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            win: self.win,
            ts: self.ts_on.then(|| (self.tsval(), self.ts_recent)),
            ip_id: self.ip_id,
            ..Build::default()
        }
    }

    pub fn data(&mut self, len: usize) -> Build {
        let mut b = self.seg(ACK | PSH);
        b.payload = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
        b
    }

    fn collect(&mut self) {
        let mut out = Vec::new();
        self.sut.drain(&mut out);
        for p in out {
            if let Some(seg) = pkt::parse(&p) {
                if trace_on() {
                    println!("{:>10.3} sut> {}", self.now as f64 / 1e3, describe(&seg));
                }
                if (seg.dst, seg.dport) != self.peer {
                    continue;
                }
                if let Some((v, _)) = seg.ts {
                    self.ts_recent = v;
                }
                self.got.push_back(Got { at: self.now, seg });
            }
        }
    }

    pub fn send(&mut self, b: &Build) {
        self.send_raw(&b.emit());
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        if trace_on() {
            if let Some(s) = pkt::parse(bytes) {
                println!("{:>10.3} >sut {}", self.now as f64 / 1e3, describe(&s));
            }
        }
        self.sut.input(self.now, Pkt::from_slice(bytes));
        self.sut.poll(self.now);
        self.collect();
    }

    fn step(&mut self, deadline: Time) {
        let w = self.sut.next_wake(self.now).unwrap_or(Time::MAX);
        self.now = w.max(self.now + 1).min(deadline).max(self.now);
        self.sut.poll(self.now);
        self.collect();
    }

    /// Let `dt` of virtual time pass, servicing the stack's timers.
    pub fn advance(&mut self, dt: Time) {
        let end = self.now + dt;
        while self.now < end {
            self.step(end);
        }
    }

    /// The first segment matching `pred` within `within` (earlier
    /// non-matching ones are consumed).
    pub fn wait_for(&mut self, within: Time, pred: impl Fn(&Seg) -> bool) -> Option<Got> {
        let deadline = self.now + within;
        loop {
            while let Some(g) = self.got.pop_front() {
                if pred(&g.seg) {
                    return Some(g);
                }
            }
            if self.now >= deadline {
                return None;
            }
            self.step(deadline);
        }
    }

    pub fn take(&mut self) -> Vec<Got> {
        self.got.drain(..).collect()
    }

    /// Queue data on the stack and let it transmit.
    pub fn app_send(&mut self, n: usize) -> usize {
        let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let w = self.sut.send(&data);
        self.sut.poll(self.now);
        self.collect();
        w
    }

    /// Read everything the stack will give; (bytes, saw EOF).
    pub fn app_read(&mut self) -> (usize, bool) {
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        loop {
            match self.sut.recv(&mut buf) {
                Recv::Data(n) => total += n,
                Recv::Eof => {
                    self.sut.poll(self.now);
                    self.collect();
                    return (total, true);
                }
                _ => break,
            }
        }
        self.sut.poll(self.now);
        self.collect();
        (total, false)
    }

    pub fn alive(&self) -> bool {
        self.sut.state() == St::Established && !self.sut.was_reset()
    }

    /// Stack listens; the peer completes a handshake with `o`.
    pub fn handshake_server(&mut self, o: SynOpts) -> Result<Seg, String> {
        let mut syn = self.seg(SYN);
        syn.win = 65535;
        syn.mss = o.mss;
        syn.ws = o.ws;
        syn.sack_ok = o.sack;
        syn.ts = o.ts.then(|| (self.tsval(), 0));
        self.send(&syn);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        let sa = self
            .wait_for(3 * SEC, |s| s.has(SYN | ACK))
            .ok_or("no SYN-ACK")?
            .seg;
        self.sut_iss = sa.seq;
        self.rcv_nxt = sa.seq.wrapping_add(1);
        self.ts_on = o.ts && sa.ts.is_some();
        self.sack_on = o.sack && sa.sack_ok;
        self.win = o.win;
        let ack = self.seg(ACK);
        self.send(&ack);
        if self.sut.state() != St::Established {
            return Err(format!("not established: {:?}", self.sut.state()));
        }
        Ok(sa)
    }

    /// Stack connects; the peer answers the SYN with `o`.
    pub fn handshake_client(&mut self, o: SynOpts) -> Result<Seg, String> {
        self.sut.connect(self.now);
        self.collect();
        let syn = self.wait_for(SEC, |s| s.has(SYN)).ok_or("no SYN")?.seg;
        self.sut_iss = syn.seq;
        self.rcv_nxt = syn.seq.wrapping_add(1);
        self.ts_on = o.ts && syn.ts.is_some();
        self.sack_on = o.sack && syn.sack_ok;
        let mut sa = self.seg(SYN | ACK);
        sa.win = 65535;
        sa.mss = o.mss;
        sa.ws = if syn.ws.is_some() { o.ws } else { None };
        sa.sack_ok = self.sack_on;
        sa.ts = self
            .ts_on
            .then(|| (self.tsval(), syn.ts.map_or(0, |t| t.0)));
        self.send(&sa);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.win = o.win;
        self.advance(MS);
        if self.sut.state() != St::Established {
            return Err(format!("not established: {:?}", self.sut.state()));
        }
        self.take();
        Ok(syn)
    }

    /// An established connection (stack as server) with default options.
    pub fn established(spec: Spec) -> Result<Lab, String> {
        let mut l = Lab::server(spec);
        l.handshake_server(SynOpts::default())?;
        Ok(l)
    }

    /// Wait for a data segment from the stack.
    pub fn next_data(&mut self, within: Time) -> Option<Got> {
        self.wait_for(within, |s| s.payload_len > 0)
    }

    /// ACK everything received so far.
    pub fn ack_all(&mut self) {
        let b = self.seg(ACK);
        self.send(&b);
    }

    /// Collect the stack's data until `n` bytes arrived, ACKing each segment
    /// (or not); returns the segments.
    pub fn receive(&mut self, n: usize, ack: bool, within: Time) -> Vec<Got> {
        let mut v = Vec::new();
        let mut have = 0;
        while have < n {
            let Some(g) = self.next_data(within) else {
                break;
            };
            if g.seg.seq == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(g.seg.payload_len as u32);
                have += g.seg.payload_len;
            }
            if ack {
                self.ack_all();
            }
            v.push(g);
        }
        v
    }

    /// Move 64 KiB stack→peer over a 10 ms RTT, so the stack has an RTT
    /// estimate and a congestion window to work with (smoltcp starts at
    /// 2 KB).
    pub fn warm_up(&mut self) -> Result<(), String> {
        let mut rx = Receiver::new(self.rcv_nxt);
        if self.app_send(64 * 1024) < 64 * 1024 {
            return Err("send buffer too small".into());
        }
        transfer(self, &mut rx, 64 * 1024, &[], 10 * SEC)?;
        self.advance(50 * MS);
        self.take();
        Ok(())
    }

    /// Forget the peer side (keep the stack), to try another handshake.
    pub fn new_peer(&mut self, isn: u32) {
        self.snd_nxt = isn;
        self.ts_on = false;
        self.sack_on = false;
        self.win = 65535;
        self.got.clear();
    }
}

/// A receiver for the stack's data: tracks what arrived, ACKs every data
/// segment with the cumulative ACK and SACK blocks (most recent first), and
/// counts retransmissions of data it already had.
struct Receiver {
    base: u32,
    have: crate::net::RangeSet,
    recent: Vec<(u64, u64)>,
    needless: usize,
    retx: usize,
    top: u64,
}

impl Receiver {
    fn new(base: u32) -> Self {
        Self {
            base,
            have: Default::default(),
            recent: Vec::new(),
            needless: 0,
            retx: 0,
            top: 0,
        }
    }

    fn cum(&self) -> u64 {
        self.have.range_of(0).map_or(0, |r| r.1)
    }

    /// Account one data segment; `deliver` false simulates its loss.
    /// Returns the ACK a receiver would send (none for a lost segment).
    fn on_data(&mut self, l: &mut Lab, s: &Seg, deliver: bool) -> Option<Build> {
        let lo = u64::from(s.seq.wrapping_sub(self.base));
        let hi = lo + s.payload_len as u64;
        if lo < self.top {
            self.retx += 1;
            if self.have.overlap(lo, hi) == hi - lo {
                self.needless += 1;
            }
        }
        self.top = self.top.max(hi);
        if !deliver {
            return None;
        }
        self.have.insert(lo, hi);
        self.recent.retain(|&(a, b)| b < lo || a > hi);
        self.recent.insert(0, (lo, hi));
        let cum = self.cum();
        let mut blocks = Vec::new();
        for &(a, _) in &self.recent {
            // Report the whole contiguous range holding this segment.
            if let Some(r) = self.have.range_of(a).filter(|r| r.0 > cum) {
                if !blocks.contains(&r) {
                    blocks.push(r);
                }
            }
        }
        l.rcv_nxt = self.base.wrapping_add(cum as u32);
        let mut a = l.seg(ACK);
        if l.sack_on {
            a.sacks = blocks
                .iter()
                .take(3)
                .map(|&(x, y)| {
                    (
                        self.base.wrapping_add(x as u32),
                        self.base.wrapping_add(y as u32),
                    )
                })
                .collect();
        }
        Some(a)
    }
}

/// Round trip of the path the loss-recovery probes model.
const RTT: Time = 10 * MS;

/// Feed the stack's data segments to `rx`, whose ACKs reach the stack one
/// RTT later, until `total` bytes arrived in order. First transmissions
/// whose index is in `lost` are dropped. Returns the time taken.
fn transfer(
    l: &mut Lab,
    rx: &mut Receiver,
    total: u64,
    lost: &[usize],
    limit: Time,
) -> Result<Time, String> {
    let t0 = l.now;
    let mut acks: VecDeque<(Time, Build)> = VecDeque::new();
    let mut fresh = 0usize;
    loop {
        while acks.front().is_some_and(|(t, _)| *t <= l.now) {
            if let Some((_, b)) = acks.pop_front() {
                l.send(&b);
            }
        }
        while let Some(g) = l.got.pop_front() {
            if g.seg.payload_len == 0 {
                continue;
            }
            let lo = u64::from(g.seg.seq.wrapping_sub(rx.base));
            let deliver = if lo >= rx.top {
                fresh += 1;
                !lost.contains(&(fresh - 1))
            } else {
                true
            };
            if let Some(a) = rx.on_data(l, &g.seg, deliver) {
                acks.push_back((l.now + RTT, a));
            }
        }
        if rx.cum() >= total {
            return Ok(l.now - t0);
        }
        if l.now - t0 > limit {
            return Err(format!(
                "stalled: {} of {total} B after {} s",
                rx.cum(),
                (l.now - t0) / SEC
            ));
        }
        let wake = l.sut.next_wake(l.now).unwrap_or(Time::MAX);
        let next = acks
            .front()
            .map_or(Time::MAX, |a| a.0)
            .min(wake)
            .min(t0 + limit + 1);
        l.now = next.max(l.now + 1);
        l.sut.poll(l.now);
        l.collect();
    }
}

// ---------------------------------------------------------------------------
// Probes.
// ---------------------------------------------------------------------------

pub struct Probe {
    pub id: &'static str,
    pub rfc: &'static str,
    pub what: &'static str,
    pub run: fn(Spec) -> Verdict,
}

macro_rules! tri {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Verdict::Fail(format!("setup: {e}")),
        }
    };
}

fn opts_list(s: &Seg) -> String {
    let mut v = Vec::new();
    if let Some(m) = s.mss {
        v.push(format!("MSS {m}"));
    }
    if let Some(w) = s.ws {
        v.push(format!("WS {w}"));
    }
    if s.sack_ok {
        v.push("SACK".into());
    }
    if s.ts.is_some() {
        v.push("TS".into());
    }
    v.join(", ")
}

fn syn_options(spec: Spec) -> Verdict {
    let mut l = Lab::client(spec);
    l.sut.connect(0);
    l.collect();
    match l.wait_for(SEC, |s| s.has(SYN)) {
        Some(g) => {
            let s = g.seg;
            let all = s.mss.is_some() && s.ws.is_some() && s.sack_ok && s.ts.is_some();
            if all {
                pass(opts_list(&s))
            } else {
                Verdict::Info(opts_list(&s))
            }
        }
        None => fail("no SYN"),
    }
}

fn synack_only_offered(spec: Spec) -> Verdict {
    let mut l = Lab::server(spec);
    let o = SynOpts {
        ws: None,
        sack: false,
        ts: false,
        ..SynOpts::default()
    };
    let sa = tri!(l.handshake_server(o));
    if sa.ws.is_some() || sa.sack_ok || sa.ts.is_some() {
        fail(format!("SYN-ACK carries {}", opts_list(&sa)))
    } else {
        pass(opts_list(&sa))
    }
}

fn declined_options_unused(spec: Spec) -> Verdict {
    let mut l = Lab::client(spec);
    tri!(l.handshake_client(SynOpts {
        ws: None,
        sack: false,
        ts: false,
        ..SynOpts::default()
    }));
    // Out-of-order data from the peer would draw SACK blocks if SACK were
    // (wrongly) still in use.
    let mut d = l.data(100);
    d.seq = l.snd_nxt.wrapping_add(1000);
    l.send(&d);
    l.app_send(1000);
    l.advance(100 * MS);
    let segs = l.take();
    let bad: Vec<&str> = [
        segs.iter().any(|g| g.seg.ts.is_some()).then_some("TS"),
        segs.iter().any(|g| g.seg.nsacks > 0).then_some("SACK"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if segs.is_empty() {
        fail("sent nothing")
    } else if bad.is_empty() {
        pass("")
    } else {
        fail(format!("still sends {}", bad.join(", ")))
    }
}

fn mss_honoured(spec: Spec) -> Verdict {
    let mut l = Lab::server(spec);
    tri!(l.handshake_server(SynOpts {
        mss: Some(536),
        ..SynOpts::default()
    }));
    l.app_send(8000);
    let segs = l.receive(8000, true, 3 * SEC);
    let worst = segs
        .iter()
        .map(|g| g.seg.payload_len + g.seg.opt_len)
        .max()
        .unwrap_or(0);
    if segs.is_empty() {
        fail("no data")
    } else if worst > 536 {
        fail(format!("{worst} B of data+options > 536"))
    } else {
        pass(format!("≤ {worst} B"))
    }
}

fn wscale_honoured(spec: Spec) -> Verdict {
    let mut l = Lab::server(spec);
    // WS 7 with a window field of 4: 512 bytes.
    tri!(l.handshake_server(SynOpts {
        win: 4,
        ..SynOpts::default()
    }));
    let start = l.rcv_nxt;
    l.app_send(8000);
    l.advance(SEC);
    let top = l
        .take()
        .iter()
        .filter(|g| g.seg.payload_len > 0)
        .map(|g| g.seg.end().wrapping_sub(start))
        .max()
        .unwrap_or(0);
    if top > 512 {
        fail(format!("{top} B into a 512 B window"))
    } else if top == 0 {
        fail("sent nothing in 1 s")
    } else {
        pass(format!("{top} B"))
    }
}

fn simultaneous_open(spec: Spec) -> Verdict {
    let mut l = Lab::client(spec);
    l.sut.connect(0);
    l.collect();
    let Some(syn) = l.wait_for(SEC, |s| s.has(SYN)) else {
        return fail("no SYN");
    };
    l.rcv_nxt = syn.seg.seq.wrapping_add(1);
    l.ts_on = syn.seg.ts.is_some();
    // Our SYN crosses theirs.
    let mut s = l.seg(SYN);
    s.win = 65535;
    s.mss = Some(1460);
    s.ws = syn.seg.ws.map(|_| 7);
    s.sack_ok = syn.seg.sack_ok;
    s.ts = l.ts_on.then(|| (l.tsval(), 0));
    l.send(&s);
    l.snd_nxt = l.snd_nxt.wrapping_add(1);
    let Some(sa) = l.wait_for(3 * SEC, |s| s.has(SYN | ACK)) else {
        return fail(format!(
            "no SYN-ACK to a crossing SYN ({:?})",
            l.sut.state()
        ));
    };
    if sa.seg.ack != l.snd_nxt {
        return fail("SYN-ACK acks the wrong sequence");
    }
    let mut sa2 = l.seg(SYN | ACK);
    sa2.seq = PEER_ISN;
    sa2.win = 65535;
    sa2.mss = Some(1460);
    sa2.ws = s.ws;
    sa2.sack_ok = s.sack_ok;
    sa2.ts = s.ts;
    l.send(&sa2);
    l.win = 8192;
    let d = l.data(100);
    l.send(&d);
    l.snd_nxt = l.snd_nxt.wrapping_add(100);
    l.advance(50 * MS);
    let (n, _) = l.app_read();
    if l.sut.state() == St::Established && n == 100 {
        pass("")
    } else {
        fail(format!("{:?}, read {n} B", l.sut.state()))
    }
}

fn rst_in_window(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let mut r = l.seg(RST);
    r.seq = l.snd_nxt.wrapping_add(1000);
    l.send(&r);
    let challenge = l.wait_for(10 * MS, |s| s.has(ACK) && !s.has(RST)).is_some();
    l.advance(10 * MS);
    match (l.alive(), challenge) {
        (true, true) => pass("challenge ACK"),
        (true, false) => Verdict::Warn("ignored, no challenge ACK".into()),
        (false, _) => fail("connection reset by a blind in-window RST"),
    }
}

fn rst_exact(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let r = l.seg(RST);
    l.send(&r);
    l.advance(10 * MS);
    if l.sut.state() == St::Closed && l.sut.was_reset() {
        pass("")
    } else {
        fail(format!("still {:?}", l.sut.state()))
    }
}

fn rst_out_of_window(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let mut r = l.seg(RST);
    r.seq = l.snd_nxt.wrapping_add(1 << 30);
    l.send(&r);
    l.advance(10 * MS);
    let replies = l.take().len();
    match (l.alive(), replies) {
        (true, 0) => pass(""),
        (true, n) => Verdict::Warn(format!("{n} replies")),
        (false, _) => fail("reset"),
    }
}

fn syn_in_window(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let mut s = l.seg(SYN);
    s.seq = l.snd_nxt.wrapping_add(100);
    s.mss = Some(1460);
    l.send(&s);
    let challenge = l
        .wait_for(10 * MS, |s| s.has(ACK) && !s.has(RST) && !s.has(SYN))
        .is_some();
    l.advance(10 * MS);
    match (l.alive(), challenge) {
        (true, true) => pass("challenge ACK"),
        (true, false) => Verdict::Warn("dropped silently".into()),
        (false, _) => fail("connection reset by a SYN"),
    }
}

fn ack_beyond_snd_nxt(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let mut d = l.data(100);
    d.ack = l.rcv_nxt.wrapping_add(100_000);
    l.send(&d);
    l.advance(10 * MS);
    let acked = l.take().iter().any(|g| g.seg.has(ACK));
    let (n, _) = l.app_read();
    match (n, acked) {
        (0, true) => pass("dropped, ACK sent"),
        (0, false) => Verdict::Warn("dropped, no ACK".into()),
        _ => fail(format!("delivered {n} B acking unsent data")),
    }
}

fn old_ack_data_accepted(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    l.app_send(2896);
    let segs = l.receive(2896, false, SEC);
    if segs.is_empty() {
        return fail("setup: no data");
    }
    l.ack_all();
    // A data segment that was sent before that ACK and arrives after it
    // (reordering): its ACK field is below SND.UNA but within the window.
    let mut d = l.data(100);
    d.ack = l.rcv_nxt.wrapping_sub(1448);
    l.send(&d);
    l.advance(10 * MS);
    let (n, _) = l.app_read();
    if n == 100 {
        pass("")
    } else {
        fail("segment discarded because its ACK field was old")
    }
}

fn ack_too_old(spec: Spec) -> Verdict {
    let mut l = Lab::server(spec);
    // No window scaling and a 4 KiB window keep MAX.SND.WND small.
    tri!(l.handshake_server(SynOpts {
        ws: None,
        win: 4096,
        ..SynOpts::default()
    }));
    let mut d = l.data(100);
    d.ack = l.rcv_nxt.wrapping_sub(100_000);
    l.send(&d);
    l.advance(10 * MS);
    let (n, _) = l.app_read();
    if n == 0 {
        pass("")
    } else {
        fail(format!("delivered {n} B"))
    }
}

fn paws(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    if !l.ts_on {
        return Verdict::Info("n/a: no timestamps".into());
    }
    let mut d = l.data(100);
    d.ts = Some((1_000_000_000, l.ts_recent));
    l.send(&d);
    l.snd_nxt = l.snd_nxt.wrapping_add(100);
    let mut old = l.data(100);
    old.ts = Some((999_999_000, l.ts_recent));
    l.send(&old);
    l.advance(10 * MS);
    let (n, _) = l.app_read();
    if n == 100 {
        pass("old-timestamp segment dropped")
    } else {
        fail(format!(
            "accepted a segment with an old timestamp ({n} B read)"
        ))
    }
}

fn ooo_ranges(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    const N: u32 = 40;
    let base = l.snd_nxt;
    let seg = |l: &mut Lab, i: u32| {
        let mut d = l.data(1000);
        d.seq = base.wrapping_add(i * 1000);
        l.send(&d);
    };
    // Every other segment first: N separate out-of-order ranges.
    for i in 0..N {
        seg(&mut l, 2 * i + 1);
    }
    for i in 0..N {
        seg(&mut l, 2 * i);
    }
    l.advance(10 * MS);
    let (n, _) = l.app_read();
    let kept = (n / 1000).saturating_sub(1) / 2;
    if n == 2 * N as usize * 1000 {
        pass(format!("held all {N} ranges"))
    } else {
        Verdict::Warn(format!("held {kept} of {N} ranges"))
    }
}

fn sack_blocks(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    if !l.sack_on {
        return Verdict::Info("n/a: SACK not negotiated".into());
    }
    let base = l.snd_nxt;
    let mut s1 = l.data(1000);
    s1.seq = base.wrapping_add(1000);
    l.send(&s1);
    let Some(a1) = l.wait_for(50 * MS, |s| s.has(ACK)) else {
        return fail("no ACK for out-of-order data");
    };
    let mut s3 = l.data(1000);
    s3.seq = base.wrapping_add(3000);
    l.send(&s3);
    let Some(a2) = l.wait_for(50 * MS, |s| s.has(ACK)) else {
        return fail("no ACK for out-of-order data");
    };
    let r1 = (base.wrapping_add(1000), base.wrapping_add(2000));
    let r3 = (base.wrapping_add(3000), base.wrapping_add(4000));
    let b1 = a1.seg.sack_blocks();
    let b2 = a2.seg.sack_blocks();
    if b1.first() != Some(&r1) {
        return fail(format!("first ACK SACKs {b1:?}"));
    }
    if b2.first() != Some(&r3) {
        return fail(format!("most recent block not first: {b2:?}"));
    }
    if !b2.contains(&r1) {
        return Verdict::Warn("older block not repeated".into());
    }
    pass("")
}

fn dsack(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    if !l.sack_on {
        return Verdict::Info("n/a: SACK not negotiated".into());
    }
    let d = l.data(1000);
    l.send(&d);
    l.snd_nxt = l.snd_nxt.wrapping_add(1000);
    l.advance(100 * MS);
    l.take();
    l.send(&d);
    let r = (d.seq, d.seq.wrapping_add(1000));
    match l.wait_for(100 * MS, |s| s.has(ACK)) {
        Some(a) if a.seg.sack_blocks().first() == Some(&r) => pass("yes"),
        Some(_) => Verdict::Info("no".into()),
        None => Verdict::Info("no ACK".into()),
    }
}

fn fin_out_of_order(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let base = l.snd_nxt;
    let mut s2 = l.data(1000);
    s2.seq = base.wrapping_add(1000);
    s2.flags |= FIN;
    l.send(&s2);
    l.advance(10 * MS);
    let (n, eof) = l.app_read();
    if eof || n > 0 {
        return fail("EOF or data before the hole was filled");
    }
    let mut s1 = l.data(1000);
    s1.seq = base;
    l.send(&s1);
    l.advance(10 * MS);
    let (n, eof) = l.app_read();
    let fin_acked = l
        .take()
        .iter()
        .any(|g| g.seg.ack == base.wrapping_add(2001));
    match (n, eof, fin_acked) {
        (2000, true, true) => pass(""),
        (2000, true, false) => fail("FIN not acknowledged"),
        (2000, false, _) => Verdict::Warn("FIN discarded: the peer must resend it".into()),
        _ => fail(format!("read {n} B, eof {eof}")),
    }
}

fn ooo_immediate_ack(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let mut s = l.data(1000);
    s.seq = l.snd_nxt.wrapping_add(1000);
    let t0 = l.now;
    l.send(&s);
    match l.wait_for(SEC, |s| s.has(ACK)) {
        Some(g) if g.at == t0 => pass("immediate"),
        Some(g) => fail(format!("after {} ms", (g.at - t0) / MS)),
        None => fail("never"),
    }
}

fn ack_every_second(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let t0 = l.now;
    // Eight full segments, 120 µs apart (back to back at 100 Mbit/s).
    for _ in 0..8 {
        let d = l.data(1448);
        l.send(&d);
        l.snd_nxt = l.snd_nxt.wrapping_add(1448);
        l.advance(120);
    }
    let acks = l
        .take()
        .iter()
        .filter(|g| g.seg.has(ACK) && g.at < t0 + MS)
        .count();
    if acks >= 4 {
        pass(format!("{acks} ACKs / 8 segments"))
    } else {
        fail(format!("{acks} ACKs / 8 segments"))
    }
}

fn delayed_ack_bound(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let d = l.data(100);
    let t0 = l.now;
    l.send(&d);
    l.snd_nxt = l.snd_nxt.wrapping_add(100);
    let want = l.snd_nxt;
    match l.wait_for(2 * SEC, |s| s.has(ACK) && s.ack == want) {
        Some(g) if g.at - t0 < 500 * MS => pass(format!("{} ms", (g.at - t0) / MS)),
        Some(g) => fail(format!("{} ms", (g.at - t0) / MS)),
        None => fail("no ACK"),
    }
}

fn bad_checksum(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let d = l.data(100);
    let mut bytes = d.emit();
    let k = bytes.len() - 1;
    bytes[k] ^= 0x5a;
    l.send_raw(&bytes);
    l.advance(10 * MS);
    let (n, _) = l.app_read();
    if n != 0 {
        return fail("delivered corrupt data");
    }
    l.send(&d);
    l.advance(10 * MS);
    let (n, _) = l.app_read();
    if n == 100 {
        pass("")
    } else {
        fail("good copy not delivered")
    }
}

fn rto_backoff(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    l.app_send(100);
    let Some(first) = l.next_data(SEC) else {
        return fail("no data");
    };
    let seq = first.seg.seq;
    let mut times = vec![first.at];
    while times.len() < 6 {
        match l.wait_for(130 * SEC, |s| s.payload_len > 0 && s.seq == seq) {
            Some(g) => times.push(g.at),
            None => break,
        }
    }
    if times.len() < 4 {
        return fail(format!("{} retransmissions", times.len() - 1));
    }
    let mut gaps: Vec<Time> = times.windows(2).map(|w| w[1] - w[0]).collect();
    // A tail-loss probe (RFC 8985) is not an RTO: back-off starts after it.
    let tlp = l.sut.stats().is_some_and(|s| s.tlp_count > 0);
    let probe = tlp.then(|| gaps.remove(0));
    let doubling = gaps
        .windows(2)
        .all(|g| g[1] * 10 >= g[0] * 19 || g[1] >= 60 * SEC);
    let shown: Vec<String> = gaps
        .iter()
        .map(|g| format!("{:.1}", *g as f64 / 1e6))
        .collect();
    let mut s = format!("{} s", shown.join(", "));
    if let Some(p) = probe {
        s = format!("TLP {:.1} s, then {s}", p as f64 / 1e6);
    }
    if doubling {
        pass(s)
    } else {
        fail(format!("not doubling: {s}"))
    }
}

/// After a warm-up, the stack sends `n` full segments; the first
/// transmissions of the ones in `lost` vanish and a receiver ACKs and SACKs
/// everything else as it arrives. Returns (time to deliver it all,
/// retransmissions, retransmissions of data the receiver already had).
fn recovery(
    l: &mut Lab,
    n: usize,
    lost: &[usize],
    limit: Time,
) -> Result<(Time, usize, usize), String> {
    l.warm_up()?;
    let mut rx = Receiver::new(l.rcv_nxt);
    if l.app_send(n * 1448) < n * 1448 {
        return Err("send buffer too small".into());
    }
    let t = transfer(l, &mut rx, (n * 1448) as u64, lost, limit)?;
    Ok((t, rx.retx, rx.needless))
}

fn fast_retransmit(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    match recovery(&mut l, 10, &[0], 30 * SEC) {
        Ok((t, ..)) if t < 150 * MS => pass(format!("repaired in {} ms", t / MS)),
        Ok((t, ..)) => fail(format!("only by timeout, after {} ms", t / MS)),
        Err(e) => fail(e),
    }
}

fn sack_recovery(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    if !l.sack_on {
        return Verdict::Info("n/a: SACK not negotiated".into());
    }
    match recovery(&mut l, 20, &[2, 7, 12], 60 * SEC) {
        Ok((t, retx, needless)) => {
            let d = format!("{} ms, {retx} resent, {needless} needlessly", t / MS);
            if t < 150 * MS && needless == 0 {
                pass(d)
            } else {
                Verdict::Warn(d)
            }
        }
        Err(e) => fail(e),
    }
}

fn tail_loss(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    match recovery(&mut l, 10, &[7, 8, 9], 30 * SEC) {
        // Before even Linux's 200 ms minimum RTO: repaired by a probe.
        Ok((t, retx, _)) if t < 200 * MS => {
            pass(format!("repaired in {} ms, {retx} resent", t / MS))
        }
        Ok((t, retx, _)) => Verdict::Info(format!("repaired in {} ms, {retx} resent", t / MS)),
        Err(e) => fail(e),
    }
}

fn zero_window(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    tri!(l.warm_up());
    l.app_send(200_000);
    // Take everything in flight, then ACK it all with the window shut.
    l.advance(10 * MS);
    for g in l.take() {
        if g.seg.payload_len > 0 && g.seg.seq == l.rcv_nxt {
            l.rcv_nxt = g.seg.end();
        }
    }
    l.win = 0;
    l.ack_all();
    let t0 = l.now;
    let mut probes = vec![t0];
    while probes.len() < 5 {
        // Answer each probe with the window still shut.
        match l.wait_for(120 * SEC, |s| !s.has(RST)) {
            Some(g) => {
                probes.push(g.at);
                l.ack_all();
            }
            None => break,
        }
    }
    if probes.len() < 5 {
        return fail(format!("{} probes in 120 s", probes.len() - 1));
    }
    let gaps: Vec<String> = probes
        .windows(2)
        .map(|w| format!("{:.1}", (w[1] - w[0]) as f64 / 1e6))
        .collect();
    // The window opens, but the peer only says so in reply to a probe.
    l.win = 8192;
    if l.wait_for(120 * SEC, |s| !s.has(RST)).is_none() {
        return fail("probing stopped");
    }
    l.ack_all();
    let una = l.rcv_nxt;
    let resumed = l
        .wait_for(SEC, |s| s.payload_len > 0 && s.end().wrapping_sub(una) > 1)
        .is_some();
    if resumed {
        pass(format!("probes after {} s", gaps.join(", ")))
    } else {
        fail("did not resume after the window opened")
    }
}

fn give_up(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    l.app_send(1000);
    let t0 = l.now;
    // The peer vanishes.
    let limit = 30 * 60 * SEC;
    while l.now - t0 < limit && l.sut.state() == St::Established {
        l.advance(10 * SEC);
        l.take();
    }
    if l.sut.state() == St::Established {
        Verdict::Warn("still retransmitting after 30 min".into())
    } else {
        pass(format!("gave up after {} s", (l.now - t0) / SEC))
    }
}

fn time_wait_reack(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    l.sut.close(l.now);
    l.sut.poll(l.now);
    l.collect();
    let Some(fin) = l.wait_for(SEC, |s| s.has(FIN)) else {
        return fail("no FIN");
    };
    l.rcv_nxt = fin.seg.end();
    let f = l.seg(ACK | FIN);
    l.send(&f);
    l.snd_nxt = l.snd_nxt.wrapping_add(1);
    l.advance(10 * MS);
    if l.sut.state() != St::TimeWait {
        return fail(format!("{:?} instead of TIME_WAIT", l.sut.state()));
    }
    l.take();
    l.advance(SEC);
    l.send(&f);
    let want = l.snd_nxt;
    let reack = l
        .wait_for(10 * MS, |s| s.has(ACK) && s.ack == want)
        .is_some();
    let t = l.now;
    while l.sut.state() == St::TimeWait && l.now - t < 300 * SEC {
        l.advance(100 * MS);
    }
    let tw = format!("TIME_WAIT {:.0} s", (l.now - t) as f64 / 1e6);
    if reack {
        pass(tw)
    } else {
        fail(format!("retransmitted FIN not re-ACKed; {tw}"))
    }
}

fn fin_retransmit(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    l.sut.close(l.now);
    l.sut.poll(l.now);
    l.collect();
    let Some(fin) = l.wait_for(SEC, |s| s.has(FIN)) else {
        return fail("no FIN");
    };
    match l.wait_for(10 * SEC, |s| s.has(FIN) && s.seq == fin.seg.seq) {
        Some(g) => pass(format!("after {} ms", (g.at - fin.at) / MS)),
        None => fail("FIN not retransmitted"),
    }
}

fn close_wait_send(spec: Spec) -> Verdict {
    let mut l = tri!(Lab::established(spec));
    let f = l.seg(ACK | FIN);
    l.send(&f);
    l.snd_nxt = l.snd_nxt.wrapping_add(1);
    l.advance(10 * MS);
    let (_, eof) = l.app_read();
    if !eof || l.sut.state() != St::CloseWait {
        return fail(format!("{:?}, eof {eof}", l.sut.state()));
    }
    l.app_send(4000);
    let segs = l.receive(4000, true, SEC);
    let got: usize = segs.iter().map(|g| g.seg.payload_len).sum();
    l.sut.close(l.now);
    l.sut.poll(l.now);
    l.collect();
    let fin = l.wait_for(SEC, |s| s.has(FIN)).is_some();
    if got >= 4000 && fin {
        pass("")
    } else {
        fail(format!("sent {got} B after the peer's FIN, FIN {fin}"))
    }
}

fn spoofed_syn_lockout(spec: Spec) -> Verdict {
    let mut l = Lab::server(spec);
    // A SYN from an address that will never answer.
    let mut s = l.seg(SYN);
    s.src = [10, 66, 0, 1];
    s.sport = 1234;
    s.seq = 0xDEAD_0000;
    s.mss = Some(1460);
    l.send(&s);
    l.advance(50 * MS);
    l.take();
    // The real client, 50 ms later.
    match l.handshake_server(SynOpts::default()) {
        Ok(_) => pass("legitimate client served"),
        Err(e) => {
            // Is the listener still pinned two minutes later?
            l.advance(120 * SEC);
            l.new_peer(PEER_ISN + 7777);
            let later = l.handshake_server(SynOpts::default()).is_ok();
            fail(format!(
                "legitimate client refused ({e}); {}",
                if later {
                    "served 2 min later"
                } else {
                    "still refused 2 min later"
                }
            ))
        }
    }
}

fn listener_stray_ack(spec: Spec) -> Verdict {
    let mut l = Lab::server(spec);
    let mut a = l.seg(ACK);
    a.ack = 0x4242_4242;
    l.send(&a);
    l.advance(10 * MS);
    let rst = l.take().iter().any(|g| g.seg.has(RST));
    Verdict::Info(if rst { "RST" } else { "dropped silently" }.into())
}

pub fn probes() -> Vec<Probe> {
    vec![
        Probe {
            id: "SYN options",
            rfc: "9293, 7323, 2018",
            what: "options offered in our SYN",
            run: syn_options,
        },
        Probe {
            id: "SYN-ACK echoes only offered options",
            rfc: "7323 §2.2, 2018 §2",
            what: "peer offers MSS only",
            run: synack_only_offered,
        },
        Probe {
            id: "declined options unused",
            rfc: "7323 §3.2, 2018 §2",
            what: "SYN-ACK without TS/SACK: none sent later",
            run: declined_options_unused,
        },
        Probe {
            id: "peer MSS honoured",
            rfc: "9293 §3.7.1, 6691",
            what: "peer MSS 536: data + options ≤ 536",
            run: mss_honoured,
        },
        Probe {
            id: "window scale honoured",
            rfc: "7323 §2.3",
            what: "WS 7, window field 4 = 512 B",
            run: wscale_honoured,
        },
        Probe {
            id: "simultaneous open",
            rfc: "9293 §3.5 (MUST-10)",
            what: "SYNs cross",
            run: simultaneous_open,
        },
        Probe {
            id: "blind in-window RST",
            rfc: "5961 §3",
            what: "RST at RCV.NXT+1000",
            run: rst_in_window,
        },
        Probe {
            id: "RST at RCV.NXT",
            rfc: "9293 §3.10.7.4",
            what: "exact RST resets",
            run: rst_exact,
        },
        Probe {
            id: "out-of-window RST",
            rfc: "9293 §3.10.7.4",
            what: "ignored, no reply",
            run: rst_out_of_window,
        },
        Probe {
            id: "SYN in ESTABLISHED",
            rfc: "5961 §4",
            what: "challenge ACK, survive",
            run: syn_in_window,
        },
        Probe {
            id: "ACK of unsent data",
            rfc: "9293 §3.10.7.4",
            what: "data with SEG.ACK > SND.NXT dropped",
            run: ack_beyond_snd_nxt,
        },
        Probe {
            id: "old ACK, valid data",
            rfc: "9293 §3.10.7.4, 5961 §5.2",
            what: "SEG.ACK < SND.UNA in window: data kept",
            run: old_ack_data_accepted,
        },
        Probe {
            id: "ACK below SND.UNA−MAX.SND.WND",
            rfc: "5961 §5.2",
            what: "blind data injection dropped",
            run: ack_too_old,
        },
        Probe {
            id: "PAWS",
            rfc: "7323 §5.3",
            what: "old TSval segment dropped",
            run: paws,
        },
        Probe {
            id: "out-of-order holding",
            rfc: "9293 §3.10.7.4",
            what: "40 separate ranges, then the holes",
            run: ooo_ranges,
        },
        Probe {
            id: "SACK blocks",
            rfc: "2018 §4",
            what: "most recent block first",
            run: sack_blocks,
        },
        Probe {
            id: "D-SACK",
            rfc: "2883",
            what: "duplicate reported",
            run: dsack,
        },
        Probe {
            id: "out-of-order FIN",
            rfc: "9293 §3.10.7.4",
            what: "EOF only after the hole fills",
            run: fin_out_of_order,
        },
        Probe {
            id: "immediate ACK for out-of-order data",
            rfc: "5681 §4.2",
            what: "dup ACK not delayed",
            run: ooo_immediate_ack,
        },
        Probe {
            id: "ACK every 2nd full segment",
            rfc: "9293 §3.8.6.3, 5681 §4.2",
            what: "8 segments, 120 µs apart",
            run: ack_every_second,
        },
        Probe {
            id: "delayed ACK < 500 ms",
            rfc: "9293 §3.8.6.3 (MUST-40)",
            what: "one small segment",
            run: delayed_ack_bound,
        },
        Probe {
            id: "bad checksum dropped",
            rfc: "9293 §3.1",
            what: "flipped payload byte",
            run: bad_checksum,
        },
        Probe {
            id: "RTO backoff",
            rfc: "6298 §5.5",
            what: "intervals between retransmissions",
            run: rto_backoff,
        },
        Probe {
            id: "fast retransmit",
            rfc: "5681 §3.2",
            what: "3 dup ACKs: resend before RTO",
            run: fast_retransmit,
        },
        Probe {
            id: "SACK loss recovery",
            rfc: "6675, 8985",
            what: "3 holes in 20 segments",
            run: sack_recovery,
        },
        Probe {
            id: "zero-window probing",
            rfc: "9293 §3.8.6.1 (MUST-35/36)",
            what: "probe, back off, resume",
            run: zero_window,
        },
        Probe {
            id: "tail loss",
            rfc: "8985 §7",
            what: "last 3 of 10 lost",
            run: tail_loss,
        },
        Probe {
            id: "gives up on a dead peer",
            rfc: "9293 §3.8.3 (MUST-20)",
            what: "R2 / user timeout",
            run: give_up,
        },
        Probe {
            id: "TIME_WAIT re-ACKs FIN",
            rfc: "9293 §3.10.7.4",
            what: "retransmitted FIN",
            run: time_wait_reack,
        },
        Probe {
            id: "FIN retransmitted",
            rfc: "9293 §3.10.4",
            what: "unacknowledged FIN",
            run: fin_retransmit,
        },
        Probe {
            id: "send in CLOSE_WAIT",
            rfc: "9293 §3.10.4",
            what: "half-close: data after peer's FIN",
            run: close_wait_send,
        },
        Probe {
            id: "one spoofed SYN",
            rfc: "4987",
            what: "can a legitimate client still connect?",
            run: spoofed_syn_lockout,
        },
        Probe {
            id: "ACK to a listener",
            rfc: "9293 §3.10.7.2",
            what: "RST or silence",
            run: listener_stray_ack,
        },
    ]
}

pub struct ProbeResult {
    pub id: &'static str,
    pub spec: Spec,
    pub verdict: Verdict,
}

/// Probes that only describe behaviour (tcp-sans-io's silence towards an ACK
/// to a listener is a deliberate deviation). Every other probe must pass for
/// tcp-sans-io in `--check`.
const UNGATED: &[&str] = &["ACK to a listener"];

impl ProbeResult {
    /// For `--check`: a tcp-sans-io result that is not what it must be.
    pub fn regressed(&self) -> bool {
        self.spec.is_ours()
            && match &self.verdict {
                Verdict::Pass(_) => false,
                Verdict::Info(_) => !UNGATED.contains(&self.id),
                Verdict::Warn(_) | Verdict::Fail(_) => true,
            }
    }
}

/// One probe against one stack (set PROBE_TRACE=1 to see every segment).
pub fn run_one(id: &str, spec: Spec) {
    match probes().into_iter().find(|p| p.id == id) {
        Some(p) => println!("{} on {}: {:?}", p.id, spec.label(), (p.run)(spec)),
        None => eprintln!("no such probe: {id}"),
    }
}

pub fn run(specs: &[Spec]) -> Vec<ProbeResult> {
    let mut out = Vec::new();
    for p in probes() {
        for &spec in specs {
            let verdict = match std::panic::catch_unwind(|| (p.run)(spec)) {
                Ok(v) => v,
                Err(_) => fail("PANIC"),
            };
            out.push(ProbeResult {
                id: p.id,
                spec,
                verdict,
            });
        }
    }
    out
}

pub fn print(res: &[ProbeResult], specs: &[Spec]) {
    let mut head = vec!["Probe".to_string(), "RFC".to_string()];
    head.extend(specs.iter().map(|s| s.label()));
    let mut t = Table::new(head);
    for p in probes() {
        let mut row = vec![format!("**{}**: {}", p.id, p.what), p.rfc.to_string()];
        for s in specs {
            let v = res.iter().find(|r| r.id == p.id && r.spec == *s);
            row.push(v.map_or("–".into(), |r| r.verdict.cell()));
        }
        t.row(row);
    }
    t.print();
    for s in specs {
        let mine: Vec<_> = res.iter().filter(|r| r.spec == *s).collect();
        let count = |f: fn(&Verdict) -> bool| mine.iter().filter(|r| f(&r.verdict)).count();
        println!(
            "- {}: {} pass, {} warn, {} fail, {} info",
            s.label(),
            count(|v| matches!(v, Verdict::Pass(_))),
            count(|v| matches!(v, Verdict::Warn(_))),
            count(|v| matches!(v, Verdict::Fail(_))),
            count(|v| matches!(v, Verdict::Info(_))),
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(id: &'static str, spec: Spec, verdict: Verdict) -> ProbeResult {
        ProbeResult { id, spec, verdict }
    }

    #[test]
    fn check_gate_flags_any_non_pass_for_tcp_sans_io_only() {
        let warn = || Verdict::Warn("dropped silently".into());
        let na = || Verdict::Info("n/a: no timestamps".into());
        assert!(r("SYN in ESTABLISHED", Spec::Ours, warn()).regressed());
        assert!(r("PAWS", Spec::Ours, na()).regressed());
        assert!(r("PAWS", Spec::Ours, Verdict::Fail("x".into())).regressed());
        assert!(!r("PAWS", Spec::Ours, Verdict::Pass(String::new())).regressed());
        assert!(!r("ACK to a listener", Spec::Ours, Verdict::Info("RST".into())).regressed());
        assert!(!r("PAWS", Spec::SMOL, Verdict::Fail("x".into())).regressed());
    }
}
