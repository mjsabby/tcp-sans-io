//! Two stacks, a link each way, and an application on each side, run as a
//! deterministic discrete-event simulation in virtual time.

use std::sync::OnceLock;

use crate::net::{Link, LinkCfg, WireStats};
use crate::stacks::{self, Opts, Pkt, Recv, Spec, St, Stack, Time};
use tcp_sans_io::TcbStats;

pub const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
pub const SERVER_IP: [u8; 4] = [10, 0, 0, 1];
pub const CLIENT_PORT: u16 = 40_000;
pub const SERVER_PORT: u16 = 80;

pub const MS: Time = 1_000;
pub const SEC: Time = 1_000_000;
pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * 1024;

/// How long a `Goal::Delivered` run goes on after delivery for the wire to
/// settle (see [`run`]).
pub const SETTLE: Time = 10 * SEC;

// ---------------------------------------------------------------------------
// Stream contents: a random table with a prime period, so a byte delivered
// at the wrong offset (by a segment, window or ring size) never matches.
// ---------------------------------------------------------------------------

pub const PERIOD: usize = 65_521;

fn table() -> &'static [u8] {
    static T: OnceLock<Vec<u8>> = OnceLock::new();
    T.get_or_init(|| {
        let mut x = 0x1234_5678_9ABC_DEF0u64;
        let one: Vec<u8> = (0..PERIOD)
            .map(|_| {
                x = stacks::splitmix(x);
                x as u8
            })
            .collect();
        // Two periods back to back: any PERIOD-byte window is one slice.
        [one.as_slice(), one.as_slice()].concat()
    })
}

/// The `n <= PERIOD` stream bytes of `stream` starting at `off`.
pub fn pattern(stream: u64, off: u64, n: usize) -> &'static [u8] {
    let p = ((off + stream * 7919) % PERIOD as u64) as usize;
    &table()[p..p + n.min(PERIOD)]
}

/// Index of the first byte of `got` that is not stream `stream` at `off`.
pub fn mismatch(stream: u64, off: u64, got: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < got.len() {
        let n = (got.len() - i).min(PERIOD);
        let want = pattern(stream, off + i as u64, n);
        if want != &got[i..i + n] {
            let k = want.iter().zip(&got[i..i + n]).position(|(a, b)| a != b);
            return Some(i + k.unwrap_or(0));
        }
        i += n;
    }
    None
}

// ---------------------------------------------------------------------------
// Applications.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosePolicy {
    /// FIN as soon as everything is queued (a half-close).
    AfterSend,
    /// FIN once everything is queued *and* the peer's stream has arrived.
    AfterAll,
    /// FIN at this virtual time (once everything is queued).
    At(Time),
    Never,
}

#[derive(Clone, Copy, Debug)]
pub struct App {
    pub send: u64,
    pub close: ClosePolicy,
    /// Start sending only after reading the peer's stream to EOF.
    pub respond_after_eof: bool,
    /// Read at most this many bytes per ms (`None`: as fast as offered).
    pub read_rate: Option<u64>,
    /// Abort (RST) once this many bytes have been received.
    pub abort_after: Option<u64>,
}

impl App {
    pub const fn sender(bytes: u64) -> Self {
        Self {
            send: bytes,
            close: ClosePolicy::AfterAll,
            respond_after_eof: false,
            read_rate: None,
            abort_after: None,
        }
    }
}

struct Side {
    stack: Box<dyn Stack>,
    app: App,
    stream_out: u64,
    stream_in: u64,
    expect_in: u64,
    sent: u64,
    recvd: u64,
    eof: bool,
    reset_seen: bool,
    closed: bool,
    aborted_at: Option<Time>,
    done_at: Option<Time>,
    budget: u64,
    budget_ms: u64,
    corrupt: Option<u64>,
    out: Vec<Pkt>,
}

impl Side {
    fn app(&mut self, now: Time, scratch: &mut [u8]) {
        // Receive.
        if let Some(rate) = self.app.read_rate {
            let ms = now / MS;
            self.budget = (self.budget + (ms - self.budget_ms) * rate).min(256 * KIB);
            self.budget_ms = ms;
        }
        loop {
            let cap = match self.app.read_rate {
                Some(_) => (self.budget as usize).min(scratch.len()),
                None => scratch.len(),
            };
            if cap == 0 {
                break;
            }
            match self.stack.recv(&mut scratch[..cap]) {
                Recv::Data(n) => {
                    if self.corrupt.is_none() {
                        if let Some(k) = mismatch(self.stream_in, self.recvd, &scratch[..n]) {
                            self.corrupt = Some(self.recvd + k as u64);
                        }
                    }
                    self.recvd += n as u64;
                    if self.app.read_rate.is_some() {
                        self.budget -= n as u64;
                    }
                    if self.recvd >= self.expect_in && self.done_at.is_none() {
                        self.done_at = Some(now);
                    }
                }
                Recv::Eof => {
                    self.eof = true;
                    break;
                }
                Recv::Reset => {
                    self.reset_seen = true;
                    break;
                }
                Recv::Empty | Recv::Error => break,
            }
        }
        if self.expect_in == 0 && self.done_at.is_none() {
            self.done_at = Some(now);
        }
        if let Some(lim) = self.app.abort_after {
            if self.recvd >= lim && self.aborted_at.is_none() {
                self.aborted_at = Some(now);
                self.stack.abort(now);
                return;
            }
        }
        // Send.
        let st = self.stack.state();
        let may_send = matches!(st, St::Established | St::CloseWait)
            && (!self.app.respond_after_eof || self.eof)
            && !self.closed;
        while may_send && self.sent < self.app.send {
            let n = ((self.app.send - self.sent) as usize).min(16 * 1024);
            let w = self.stack.send(pattern(self.stream_out, self.sent, n));
            self.sent += w as u64;
            if w < n {
                break;
            }
        }
        // Close.
        let all_sent = self.sent >= self.app.send;
        let want_close = match self.app.close {
            ClosePolicy::AfterSend => all_sent,
            ClosePolicy::AfterAll => all_sent && self.recvd >= self.expect_in,
            ClosePolicy::At(t) => all_sent && now >= t,
            ClosePolicy::Never => false,
        };
        if want_close
            && !self.closed
            && self.aborted_at.is_none()
            && (!self.app.respond_after_eof || self.eof)
            && matches!(st, St::Established | St::CloseWait)
        {
            self.closed = true;
            self.stack.close(now);
        }
    }
}

// ---------------------------------------------------------------------------
// The simulation.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Scenario {
    pub client: Spec,
    pub server: Spec,
    pub fwd: LinkCfg,
    pub rev: LinkCfg,
    pub client_app: App,
    pub server_app: App,
    pub seed: u64,
    pub client_seed: u64,
    pub server_seed: u64,
    pub client_mtu: u16,
    pub server_mtu: u16,
    /// Virtual-time budget.
    pub limit: Time,
    /// Print every packet.
    pub trace: bool,
}

impl Scenario {
    pub fn new(client: Spec, server: Spec, link: LinkCfg) -> Self {
        Self {
            client,
            server,
            fwd: link,
            rev: link,
            client_app: App::sender(0),
            server_app: App::sender(0),
            seed: 1,
            client_seed: 11,
            server_seed: 22,
            client_mtu: 1500,
            server_mtu: 1500,
            limit: 600 * SEC,
            trace: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub error: Option<String>,
    pub established_at: Option<Time>,
    /// Client→server and server→client streams complete.
    pub fwd_done: Option<Time>,
    pub rev_done: Option<Time>,
    pub closed_at: Option<Time>,
    /// `Goal::Delivered`: when, after delivery, both links were idle and
    /// neither stack had anything unacknowledged.
    pub settled_at: Option<Time>,
    /// `Goal::Delivered`: the wire had not settled `SETTLE` after delivery,
    /// so the statistics stop there.
    pub unsettled: bool,
    pub fwd: WireStats,
    pub rev: WireStats,
    pub client_stats: Option<TcbStats>,
    pub server_stats: Option<TcbStats>,
    pub client_reset: bool,
    pub server_reset: bool,
    pub client_state: Option<St>,
    pub server_state: Option<St>,
    pub fwd_bytes: u64,
    pub rev_bytes: u64,
}

impl Outcome {
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }
    /// Seconds from connection establishment to the last byte delivered.
    pub fn transfer_secs(&self) -> Option<f64> {
        let start = self.established_at?;
        let end = match (self.fwd_done, self.rev_done) {
            (Some(a), Some(b)) => a.max(b),
            (Some(a), None) | (None, Some(a)) => a,
            _ => return None,
        };
        Some(end.saturating_sub(start) as f64 / 1e6)
    }
    pub fn goodput(&self) -> Option<f64> {
        let s = self.transfer_secs()?;
        Some((self.fwd_bytes + self.rev_bytes) as f64 / s.max(1e-9))
    }
}

pub struct Sim {
    pub now: Time,
    client: Side,
    server: Side,
    pub fwd: Link,
    pub rev: Link,
    established_at: Option<Time>,
    scratch: Vec<u8>,
    pub check_invariants: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Goal {
    /// Both streams delivered and both sides closed cleanly.
    CleanClose,
    /// Both streams delivered (connections left open).
    Delivered,
    /// One side aborted: the other must see the reset and both must be
    /// CLOSED within a second of the abort.
    Reset,
    /// Run until the server has sent a SYN-ACK (seed search).
    SynAck,
    /// Nothing left to happen: both links idle, and neither stack has data,
    /// a SYN or a FIN unacknowledged (so no retransmission can follow).
    Settled,
}

impl Sim {
    pub fn new(sc: &Scenario) -> Self {
        let copts = Opts {
            local: (CLIENT_IP, CLIENT_PORT),
            remote: (SERVER_IP, SERVER_PORT),
            seed: sc.client_seed,
            mtu: sc.client_mtu,
        };
        let sopts = Opts {
            local: (SERVER_IP, SERVER_PORT),
            remote: (CLIENT_IP, CLIENT_PORT),
            seed: sc.server_seed,
            mtu: sc.server_mtu,
        };
        let side = |spec, opts: &Opts, app: App, out_stream, in_stream, expect| Side {
            stack: stacks::build(spec, opts),
            app,
            stream_out: out_stream,
            stream_in: in_stream,
            expect_in: expect,
            sent: 0,
            recvd: 0,
            eof: false,
            reset_seen: false,
            closed: false,
            aborted_at: None,
            done_at: None,
            budget: 0,
            budget_ms: 0,
            corrupt: None,
            out: Vec::new(),
        };
        let mut s = Self {
            now: 0,
            client: side(sc.client, &copts, sc.client_app, 1, 2, sc.server_app.send),
            server: side(sc.server, &sopts, sc.server_app, 2, 1, sc.client_app.send),
            fwd: Link::new(sc.fwd, sc.seed),
            rev: Link::new(sc.rev, sc.seed.rotate_left(17) ^ 0xA5A5),
            established_at: None,
            scratch: vec![0u8; 64 * 1024],
            check_invariants: true,
        };
        if sc.trace {
            s.fwd.trace = Some("c>s");
            s.rev.trace = Some("s>c");
        }
        s.server.stack.listen(0);
        s.client.stack.connect(0);
        s.pump_out();
        s
    }

    fn pump_out(&mut self) {
        for (side, link) in [
            (&mut self.client, &mut self.fwd),
            (&mut self.server, &mut self.rev),
        ] {
            side.stack.drain(&mut side.out);
            for p in side.out.drain(..) {
                link.send(self.now, p);
            }
        }
    }

    fn poll_all(&mut self) -> Result<(), String> {
        for side in [&mut self.client, &mut self.server] {
            side.stack.poll(self.now);
            if self.check_invariants {
                side.stack
                    .invariants()
                    .map_err(|e| format!("{}: invariant: {e}", side.stack.name()))?;
            }
        }
        self.pump_out();
        Ok(())
    }

    /// Hand every due datagram over, and let each stack that got one act on
    /// it now, so both applications see the result at the same instant
    /// (tcp-sans-io acts inside `input`, smoltcp only when polled).
    fn deliver_due(&mut self) -> bool {
        let (mut to_server, mut to_client) = (false, false);
        while let Some(p) = self.fwd.pop_due(self.now) {
            self.server.stack.input(self.now, p);
            to_server = true;
        }
        while let Some(p) = self.rev.pop_due(self.now) {
            self.client.stack.input(self.now, p);
            to_client = true;
        }
        if to_server {
            self.server.stack.process(self.now);
        }
        if to_client {
            self.client.stack.process(self.now);
        }
        if to_server || to_client {
            self.pump_out();
        }
        to_server || to_client
    }

    fn reached(&self, goal: Goal) -> bool {
        let c = &self.client;
        let s = &self.server;
        match goal {
            Goal::Delivered => c.done_at.is_some() && s.done_at.is_some(),
            Goal::CleanClose => {
                c.done_at.is_some()
                    && s.done_at.is_some()
                    && c.eof
                    && s.eof
                    && c.stack.state().is_done()
                    && s.stack.state().is_done()
                    && self.fwd.idle()
                    && self.rev.idle()
            }
            Goal::Reset => {
                let saw = |x: &Side| x.reset_seen || x.stack.was_reset();
                let peer_saw = match (c.aborted_at, s.aborted_at) {
                    (Some(_), None) => saw(s),
                    (None, Some(_)) => saw(c),
                    _ => false,
                };
                peer_saw && c.stack.state() == St::Closed && s.stack.state() == St::Closed
            }
            Goal::SynAck => self.rev.stats.syn > 0,
            Goal::Settled => {
                self.fwd.idle() && self.rev.idle() && c.stack.settled() && s.stack.settled()
            }
        }
    }

    /// Advance until `goal` (Ok) or a failure (Err).
    pub fn run(&mut self, goal: Goal, limit: Time) -> Result<(), String> {
        if self.advance(goal, limit)? {
            Ok(())
        } else {
            Err(format!("not done by {:.1} s", limit as f64 / 1e6))
        }
    }

    /// Advance until `goal` (`Ok(true)`), until nothing is due by `limit`
    /// (`Ok(false)`), or a failure (`Err`).
    fn advance(&mut self, goal: Goal, limit: Time) -> Result<bool, String> {
        let mut stuck = 0u32;
        loop {
            for side in [&mut self.client, &mut self.server] {
                side.app(self.now, &mut self.scratch);
                if let Some(off) = side.corrupt {
                    return Err(format!(
                        "{} received a corrupt byte at offset {off}",
                        side.stack.name()
                    ));
                }
            }
            self.poll_all()?;
            if self.established_at.is_none() && self.client.stack.state().synchronized() {
                self.established_at = Some(self.now);
            }
            if self.reached(goal) {
                return Ok(true);
            }
            if goal == Goal::Reset {
                let aborted = self.client.aborted_at.or(self.server.aborted_at);
                if aborted.is_some_and(|t| self.now > t + SEC) {
                    return Err("the peer did not act on the RST within 1 s".into());
                }
            } else {
                for side in [&self.client, &self.server] {
                    if side.reset_seen || side.stack.was_reset() {
                        return Err(format!("{} saw the connection reset", side.stack.name()));
                    }
                }
            }
            if self.deliver_due() {
                continue;
            }
            let reader = [&self.client, &self.server]
                .iter()
                .any(|s| s.app.read_rate.is_some() && s.recvd < s.expect_in)
                .then_some(self.now + MS);
            let closer = [&self.client, &self.server]
                .iter()
                .filter_map(|s| match s.app.close {
                    ClosePolicy::At(t) if !s.closed && t > self.now => Some(t),
                    _ => None,
                })
                .min();
            let next = [
                self.client.stack.next_wake(self.now),
                self.server.stack.next_wake(self.now),
                self.fwd.next_delivery(),
                self.rev.next_delivery(),
                reader,
                closer,
            ]
            .into_iter()
            .flatten()
            .min();
            let Some(next) = next else {
                return Err("stalled: no timer armed and nothing in flight".into());
            };
            if next > limit {
                return Ok(false);
            }
            if next <= self.now {
                stuck += 1;
                if stuck > 10_000 {
                    return Err("busy loop: a stack keeps asking to be polled now".into());
                }
            } else {
                stuck = 0;
                self.now = next;
            }
        }
    }

    pub fn outcome(&self, error: Option<String>) -> Outcome {
        Outcome {
            error,
            established_at: self.established_at,
            fwd_done: self.server.done_at.filter(|_| self.client.app.send > 0),
            rev_done: self.client.done_at.filter(|_| self.server.app.send > 0),
            closed_at: None,
            settled_at: None,
            unsettled: false,
            fwd: self.fwd.stats.clone(),
            rev: self.rev.stats.clone(),
            client_stats: self.client.stack.stats(),
            server_stats: self.server.stack.stats(),
            client_reset: self.client.reset_seen || self.client.stack.was_reset(),
            server_reset: self.server.reset_seen || self.server.stack.was_reset(),
            client_state: Some(self.client.stack.state()),
            server_state: Some(self.server.stack.state()),
            fwd_bytes: self.server.recvd,
            rev_bytes: self.client.recvd,
        }
    }

    pub fn received(&self) -> (u64, u64) {
        (self.server.recvd, self.client.recvd)
    }

    pub fn states(&self) -> (St, St) {
        (self.client.stack.state(), self.server.stack.state())
    }

    /// Advance to `goal` within the scenario's budget and report; for
    /// `Goal::Delivered`, go on until the wire settles first (see [`run`]).
    pub fn conclude(&mut self, sc: &Scenario, goal: Goal) -> Outcome {
        let mut r = self.run(goal, sc.limit);
        let (mut settled_at, mut unsettled) = (None, false);
        if r.is_ok() && goal == Goal::Delivered {
            match self.advance(Goal::Settled, self.now + SETTLE) {
                Ok(true) => settled_at = Some(self.now),
                Ok(false) => unsettled = true,
                Err(e) => r = Err(format!("after delivery: {e}")),
            }
        }
        let mut o = self.outcome(r.err().map(|e| {
            let (f, b) = self.received();
            let (cs, ss) = self.states();
            format!(
                "{e} (t={:.3}s, delivered {f}/{} and {b}/{} B, states {cs:?}/{ss:?})",
                self.now as f64 / 1e6,
                sc.client_app.send,
                sc.server_app.send
            )
        }));
        o.settled_at = settled_at;
        o.unsettled = unsettled;
        if o.ok() && goal == Goal::CleanClose {
            o.closed_at = Some(self.now);
        }
        o
    }
}

/// Run a scenario to `goal`. A `Goal::Delivered` run then goes on until the
/// wire settles (both links idle, nothing unacknowledged; at most `SETTLE`
/// past delivery, flagged as `unsettled` if that runs out), so that late
/// retransmissions, tail-loss probes and timeouts are counted; transfer
/// times and goodput still end at delivery.
pub fn run(sc: &Scenario, goal: Goal) -> Outcome {
    Sim::new(sc).conclude(sc, goal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 64 bytes client → server over a 10 Gbit/s link with 100 µs each
    /// way; both sides keep the connection open.
    fn small_upload() -> Scenario {
        let link = LinkCfg::new(0, 10_000, 1024).delay_us(100);
        let mut sc = Scenario::new(Spec::Ours, Spec::Ours, link);
        sc.client_app = App::sender(64);
        sc.client_app.close = ClosePolicy::Never;
        sc.server_app.close = ClosePolicy::Never;
        sc
    }

    #[test]
    fn delivered_runs_on_until_the_wire_settles() {
        let o = run(&small_upload(), Goal::Delivered);
        assert!(o.ok(), "{:?}", o.error);
        assert!(!o.unsettled);
        assert!(o.settled_at > o.fwd_done && o.fwd_done.is_some());
    }

    #[test]
    fn retransmissions_after_delivery_are_counted() {
        let sc = small_upload();
        let mut s = Sim::new(&sc);
        s.run(Goal::SynAck, sc.limit).unwrap();
        // Every ACK from here on is lost: the data arrives, but its sender
        // goes on probing and retransmitting after delivery.
        s.rev.cfg.loss_ppm = 1_000_000;
        s.run(Goal::Delivered, sc.limit).unwrap();
        let delivered = s.now;
        assert_eq!(s.fwd.stats.retx_pkts, 0);
        let o = s.conclude(&sc, Goal::Delivered);
        assert!(o.ok(), "{:?}", o.error);
        assert_eq!(o.fwd_done, Some(delivered));
        assert!(o.unsettled && o.settled_at.is_none());
        let st = o.client_stats.expect("tcp-sans-io stats");
        assert!(
            o.fwd.retx_pkts >= 2 && st.tlp_count >= 1 && st.rto_count >= 1,
            "{:?} {st:?}",
            o.fwd
        );
    }
}
