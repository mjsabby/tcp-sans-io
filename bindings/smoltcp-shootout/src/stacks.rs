//! One sans-I/O interface over both stacks, so every scenario, probe and
//! benchmark drives tcp-sans-io and smoltcp through identical code.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::mem::MaybeUninit;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tcp_sans_io::tcb::events;
use tcp_sans_io::tx_ring::TX_RING_CAP;
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcbStats, TcpError};

/// Microseconds (virtual time in simulations).
pub type Time = u64;

// ---------------------------------------------------------------------------
// Packet buffers: recycled, so neither stack pays for the harness' mallocs.
// ---------------------------------------------------------------------------

pub const PKT_CAP: usize = 2048;

thread_local! {
    static POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    /// smoltcp's timestamp generator is a bare `fn() -> u32`, so the clock it
    /// reads lives here; set before every smoltcp poll.
    static SMOL_CLOCK_MS: Cell<u64> = const { Cell::new(0) };
}

/// One IPv4 datagram in a recycled fixed-size buffer.
pub struct Pkt {
    buf: Vec<u8>,
    len: usize,
}

impl Pkt {
    pub fn alloc() -> Pkt {
        let buf = POOL
            .try_with(|p| p.borrow_mut().pop())
            .ok()
            .flatten()
            .unwrap_or_else(|| vec![0u8; PKT_CAP]);
        Pkt { buf, len: 0 }
    }
    pub fn from_slice(b: &[u8]) -> Pkt {
        let mut p = Pkt::alloc();
        let n = b.len().min(PKT_CAP);
        p.buf[..n].copy_from_slice(&b[..n]);
        p.len = n;
        p
    }
    pub fn set_len(&mut self, n: usize) {
        self.len = n.min(PKT_CAP);
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

impl std::ops::Deref for Pkt {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Clone for Pkt {
    fn clone(&self) -> Pkt {
        Pkt::from_slice(self)
    }
}

impl Drop for Pkt {
    fn drop(&mut self) {
        let b = std::mem::take(&mut self.buf);
        if b.len() == PKT_CAP {
            let _ = POOL.try_with(|p| {
                let mut p = p.borrow_mut();
                if p.len() < 1 << 16 {
                    p.push(b);
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// The common interface.
// ---------------------------------------------------------------------------

/// RFC 9293 states, normalized across both stacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum St {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl St {
    pub fn is_done(self) -> bool {
        matches!(self, St::Closed | St::TimeWait)
    }
    pub fn synchronized(self) -> bool {
        !matches!(self, St::Closed | St::Listen | St::SynSent | St::SynRcvd)
    }
    /// Our SYN or FIN is sent (or owed) and not yet acknowledged.
    pub fn ctl_unacked(self) -> bool {
        matches!(
            self,
            St::SynSent | St::SynRcvd | St::FinWait1 | St::Closing | St::LastAck
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recv {
    Data(usize),
    /// Nothing to read right now.
    Empty,
    /// The peer's FIN: every byte it sent has been read.
    Eof,
    Reset,
    Error,
}

pub trait Stack {
    fn name(&self) -> String;
    fn connect(&mut self, now: Time);
    fn listen(&mut self, now: Time);
    /// Hand one inbound datagram to the stack.
    fn input(&mut self, now: Time, pkt: Pkt);
    /// Make the stack act on what `input` handed over, without running
    /// timers (tcp-sans-io acts inside `input`, which ticks only to refill
    /// an egress ring it has just drained full; smoltcp needs a poll).
    fn process(&mut self, now: Time) {
        self.poll(now);
    }
    /// Run timers and process everything handed over by `input`.
    fn poll(&mut self, now: Time);
    /// Move out every datagram the stack has emitted.
    fn drain(&mut self, out: &mut Vec<Pkt>);
    /// When `poll` next has timer work (`None`: only input can wake it).
    fn next_wake(&mut self, now: Time) -> Option<Time>;
    fn send(&mut self, data: &[u8]) -> usize;
    fn recv(&mut self, buf: &mut [u8]) -> Recv;
    /// Graceful close: FIN after the queued data.
    fn close(&mut self, now: Time);
    /// Abortive close: RST.
    fn abort(&mut self, now: Time);
    fn state(&self) -> St;
    /// Nothing left to (re)transmit: every byte, SYN and FIN sent has been
    /// acknowledged and no data is queued, so no retransmission can follow.
    fn settled(&self) -> bool;
    /// The connection ended abnormally (RST received, local abort, timeout).
    fn was_reset(&self) -> bool;
    /// Internal consistency, where the stack exposes a checker.
    fn invariants(&self) -> Result<(), String> {
        Ok(())
    }
    fn stats(&self) -> Option<TcbStats> {
        None
    }
}

// ---------------------------------------------------------------------------
// Construction.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cc {
    None,
    Reno,
    Cubic,
}

/// Which stack, and how it is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spec {
    /// tcp-sans-io with its default 1 MiB rings.
    Ours,
    /// tcp-sans-io with 64 KiB rings (`Tcb<65536>`).
    Ours64k,
    /// smoltcp with `buf`-byte socket buffers.
    Smol {
        cc: Cc,
        ts: bool,
        nagle: bool,
        buf: usize,
    },
}

pub const SMOL_BUF: usize = 1 << 20;

impl Spec {
    pub const SMOL: Spec = Spec::Smol {
        cc: Cc::Cubic,
        ts: true,
        nagle: true,
        buf: SMOL_BUF,
    };
    pub const SMOL_RENO: Spec = Spec::Smol {
        cc: Cc::Reno,
        ts: true,
        nagle: true,
        buf: SMOL_BUF,
    };

    pub fn is_ours(self) -> bool {
        matches!(self, Spec::Ours | Spec::Ours64k)
    }

    pub fn label(self) -> String {
        match self {
            Spec::Ours => "tcp-sans-io".into(),
            Spec::Ours64k => "tcp-sans-io/64K".into(),
            Spec::Smol { cc, ts, nagle, buf } => {
                let mut s = String::from("smoltcp");
                s += match cc {
                    Cc::Cubic => "",
                    Cc::Reno => "/reno",
                    Cc::None => "/no-cc",
                };
                if !ts {
                    s += "/no-ts";
                }
                if !nagle {
                    s += "/nodelay";
                }
                if buf != SMOL_BUF {
                    s += &format!("/{}K", buf >> 10);
                }
                s
            }
        }
    }

    pub fn with_buf(self, b: usize) -> Spec {
        match self {
            Spec::Smol { cc, ts, nagle, .. } => Spec::Smol {
                cc,
                ts,
                nagle,
                buf: b,
            },
            s => s,
        }
    }
    pub fn with_ts(self, on: bool) -> Spec {
        match self {
            Spec::Smol { cc, nagle, buf, .. } => Spec::Smol {
                cc,
                ts: on,
                nagle,
                buf,
            },
            s => s,
        }
    }
    pub fn with_nagle(self, on: bool) -> Spec {
        match self {
            Spec::Smol { cc, ts, buf, .. } => Spec::Smol {
                cc,
                ts,
                nagle: on,
                buf,
            },
            s => s,
        }
    }
}

/// Per-endpoint parameters common to both stacks.
#[derive(Clone, Copy, Debug)]
pub struct Opts {
    pub local: ([u8; 4], u16),
    pub remote: ([u8; 4], u16),
    /// Drives the ISS (active opens), the listener secret and smoltcp's RNG.
    pub seed: u64,
    pub mtu: u16,
}

pub fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub fn build(spec: Spec, o: &Opts) -> Box<dyn Stack> {
    match spec {
        Spec::Ours => Box::new(Ours::<{ tcp_sans_io::BUF_CAP }>::new(o)),
        Spec::Ours64k => Box::new(Ours::<65536>::new(o)),
        Spec::Smol { cc, ts, nagle, buf } => Box::new(Smol::new(o, cc, ts, nagle, buf)),
    }
}

// ---------------------------------------------------------------------------
// tcp-sans-io
// ---------------------------------------------------------------------------

/// Full egress rings drained in a row before `Ours::flush` gives up and
/// reports the stack as runaway: a 1 MiB send ring empties in ~23.
const FULL_RING_GUARD: usize = 1024;

pub struct Ours<const B: usize> {
    tcb: Box<Tcb<B>>,
    out: Vec<Pkt>,
    /// `flush` hit `FULL_RING_GUARD` (reported by `invariants`).
    runaway: bool,
}

impl<const B: usize> Ours<B> {
    pub fn new(o: &Opts) -> Self {
        let cfg = TcbConfig {
            local: Endpoint {
                ip: o.local.0,
                port: o.local.1,
            },
            remote: Endpoint {
                ip: o.remote.0,
                port: o.remote.1,
            },
            iss: splitmix(o.seed) as u32,
            initial_rto_ms: 1000,
        };
        let mut slot: Box<MaybeUninit<Tcb<B>>> = Box::new_uninit();
        // SAFETY: `init_in_place` fully initialises the slot when it succeeds.
        let mut tcb = unsafe {
            Tcb::<B>::init_in_place(slot.as_mut_ptr(), cfg).expect("tcb init");
            slot.assume_init()
        };
        let k = splitmix(o.seed ^ 0x005E_C2E7);
        let mut secret = [0u8; 16];
        secret[..8].copy_from_slice(&k.to_le_bytes());
        secret[8..].copy_from_slice(&splitmix(k).to_le_bytes());
        tcb.set_secret(&secret);
        if o.mtu != 1500 {
            tcb.set_mtu(o.mtu).expect("set_mtu");
        }
        Self {
            tcb,
            out: Vec::new(),
            runaway: false,
        }
    }

    fn at(&mut self, now: Time) {
        self.tcb.set_now(now / 1000);
    }

    /// Move out every staged datagram. The TCB stops staging when its
    /// egress ring (`TX_RING_CAP` datagrams) is full, and no timer resumes
    /// it, so whenever a drain finds the ring full, tick and drain again
    /// until one comes up short, as the host contract asks.
    fn flush(&mut self) {
        let mut full = 0;
        while self.drain_ring() >= TX_RING_CAP {
            full += 1;
            if full > FULL_RING_GUARD {
                self.runaway = true;
                return;
            }
            self.tcb.tick().expect("tick");
        }
    }

    fn drain_ring(&mut self) -> usize {
        let mut n = 0;
        while let Some(p) = self.tcb.extract_packet_with(Pkt::from_slice) {
            self.out.push(p);
            n += 1;
        }
        n
    }
}

impl<const B: usize> Stack for Ours<B> {
    fn name(&self) -> String {
        if B == tcp_sans_io::BUF_CAP {
            "tcp-sans-io".into()
        } else {
            format!("tcp-sans-io/{}K", B >> 10)
        }
    }
    fn connect(&mut self, now: Time) {
        self.at(now);
        self.tcb.connect().expect("connect");
        self.flush();
    }
    fn listen(&mut self, now: Time) {
        self.at(now);
        self.tcb.listen().expect("listen");
        self.flush();
    }
    fn input(&mut self, now: Time, pkt: Pkt) {
        self.at(now);
        let _ = self.tcb.inject_packet(&pkt);
        self.flush();
    }
    fn process(&mut self, _now: Time) {}
    fn poll(&mut self, now: Time) {
        self.at(now);
        self.tcb.tick().expect("tick");
        self.flush();
    }
    fn drain(&mut self, out: &mut Vec<Pkt>) {
        out.append(&mut self.out);
    }
    fn next_wake(&mut self, _now: Time) -> Option<Time> {
        self.tcb.next_deadline().map(|ms| ms.saturating_mul(1000))
    }
    fn send(&mut self, data: &[u8]) -> usize {
        self.tcb.send(data).unwrap_or(0)
    }
    fn recv(&mut self, buf: &mut [u8]) -> Recv {
        let r = match self.tcb.recv(buf) {
            Ok(0) => Recv::Empty,
            Ok(n) => Recv::Data(n),
            Err(TcpError::ConnectionClosed) => Recv::Eof,
            Err(TcpError::ConnectionReset) => Recv::Reset,
            Err(_) => Recv::Error,
        };
        self.flush();
        r
    }
    fn close(&mut self, now: Time) {
        self.at(now);
        let _ = self.tcb.close();
        self.flush();
    }
    fn abort(&mut self, now: Time) {
        self.at(now);
        let _ = self.tcb.abort();
        self.flush();
    }
    fn state(&self) -> St {
        match self.tcb.state() {
            State::Closed => St::Closed,
            State::Listen => St::Listen,
            State::SynSent => St::SynSent,
            State::SynRcvd => St::SynRcvd,
            State::Established => St::Established,
            State::FinWait1 => St::FinWait1,
            State::FinWait2 => St::FinWait2,
            State::CloseWait => St::CloseWait,
            State::Closing => St::Closing,
            State::LastAck => St::LastAck,
            State::TimeWait => St::TimeWait,
        }
    }
    fn settled(&self) -> bool {
        let s = self.tcb.debug_snapshot();
        !self.state().ctl_unacked() && s.snd_una == s.snd_nxt && s.send_ring_len == 0
    }
    fn was_reset(&self) -> bool {
        self.tcb.poll() & events::ERROR != 0
    }
    fn invariants(&self) -> Result<(), String> {
        if self.runaway {
            return Err(format!(
                "egress ring still full after {FULL_RING_GUARD} ticks in a row"
            ));
        }
        self.tcb.debug_validate_invariants().map_err(String::from)
    }
    fn stats(&self) -> Option<TcbStats> {
        Some(self.tcb.stats())
    }
}

// ---------------------------------------------------------------------------
// smoltcp: one Interface (IP medium) with one TCP socket per endpoint.
// ---------------------------------------------------------------------------

fn smol_tsval() -> u32 {
    SMOL_CLOCK_MS.with(|c| c.get() as u32)
}

pub struct Dev {
    rx: VecDeque<Pkt>,
    tx: Vec<Pkt>,
    mtu: usize,
}

pub struct RxTok(Pkt);
pub struct TxTok<'a>(&'a mut Vec<Pkt>);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut p = Pkt::alloc();
        p.set_len(len);
        let r = f(p.bytes_mut());
        self.0.push(p);
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _: Instant) -> Option<(RxTok, TxTok<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxTok(p), TxTok(&mut self.tx)))
    }
    fn transmit(&mut self, _: Instant) -> Option<TxTok<'_>> {
        Some(TxTok(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

pub struct Smol {
    iface: Interface,
    dev: Dev,
    sockets: SocketSet<'static>,
    h: SocketHandle,
    remote: IpEndpoint,
    local_port: u16,
    last: tcp::State,
    reset: bool,
    name: String,
}

fn smol_now(now: Time) -> Instant {
    Instant::from_micros(now as i64)
}

impl Smol {
    pub fn new(o: &Opts, cc: Cc, ts: bool, nagle: bool, buf: usize) -> Self {
        let mut dev = Dev {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu: usize::from(o.mtu),
        };
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = splitmix(o.seed ^ 0x5EED);
        let mut iface = Interface::new(cfg, &mut dev, Instant::ZERO);
        let [a, b, c, d] = o.local.0;
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(a, b, c, d), 8))
                .expect("addr");
        });
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; buf]),
            tcp::SocketBuffer::new(vec![0u8; buf]),
        );
        sock.set_congestion_control(match cc {
            Cc::None => tcp::CongestionControl::None,
            Cc::Reno => tcp::CongestionControl::Reno,
            Cc::Cubic => tcp::CongestionControl::Cubic,
        });
        if ts {
            sock.set_tsval_generator(Some(smol_tsval));
        }
        sock.set_nagle_enabled(nagle);
        let mut sockets = SocketSet::new(Vec::new());
        let h = sockets.add(sock);
        let [ra, rb, rc, rd] = o.remote.0;
        Self {
            iface,
            dev,
            sockets,
            h,
            remote: IpEndpoint::new(
                IpAddress::Ipv4(Ipv4Address::new(ra, rb, rc, rd)),
                o.remote.1,
            ),
            local_port: o.local.1,
            last: tcp::State::Closed,
            reset: false,
            name: Spec::Smol { cc, ts, nagle, buf }.label(),
        }
    }

    fn sock(&self) -> &tcp::Socket<'static> {
        self.sockets.get::<tcp::Socket>(self.h)
    }
    fn sock_mut(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.h)
    }

    /// A transition to CLOSED from anywhere but LAST-ACK / TIME-WAIT (or the
    /// handshake states, which smoltcp also leaves on an RST) is abnormal.
    fn track(&mut self) {
        let s = self.sock().state();
        if s == tcp::State::Closed
            && self.last != tcp::State::Closed
            && !matches!(self.last, tcp::State::LastAck | tcp::State::TimeWait)
        {
            self.reset = true;
        }
        self.last = s;
    }
}

impl Stack for Smol {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn connect(&mut self, now: Time) {
        let remote = self.remote;
        let port = self.local_port;
        let cx = self.iface.context();
        self.sockets
            .get_mut::<tcp::Socket>(self.h)
            .connect(cx, remote, port)
            .expect("smoltcp connect");
        self.poll(now);
    }
    fn listen(&mut self, now: Time) {
        let port = self.local_port;
        self.sock_mut().listen(port).expect("smoltcp listen");
        self.poll(now);
    }
    fn input(&mut self, _now: Time, pkt: Pkt) {
        self.dev.rx.push_back(pkt);
    }
    fn poll(&mut self, now: Time) {
        SMOL_CLOCK_MS.with(|c| c.set(now / 1000));
        self.iface
            .poll(smol_now(now), &mut self.dev, &mut self.sockets);
        self.track();
    }
    fn drain(&mut self, out: &mut Vec<Pkt>) {
        out.append(&mut self.dev.tx);
    }
    fn next_wake(&mut self, now: Time) -> Option<Time> {
        self.iface
            .poll_at(smol_now(now), &self.sockets)
            .map(|t| (t.total_micros().max(0) as u64).max(now))
    }
    fn send(&mut self, data: &[u8]) -> usize {
        self.sock_mut().send_slice(data).unwrap_or(0)
    }
    fn recv(&mut self, buf: &mut [u8]) -> Recv {
        match self.sock_mut().recv_slice(buf) {
            Ok(0) => Recv::Empty,
            Ok(n) => Recv::Data(n),
            Err(tcp::RecvError::Finished) => Recv::Eof,
            Err(_) if self.reset => Recv::Reset,
            Err(_) => Recv::Error,
        }
    }
    fn close(&mut self, _now: Time) {
        self.sock_mut().close();
    }
    fn abort(&mut self, now: Time) {
        self.sock_mut().abort();
        self.poll(now);
        self.reset = true;
    }
    fn state(&self) -> St {
        match self.sock().state() {
            tcp::State::Closed => St::Closed,
            tcp::State::Listen => St::Listen,
            tcp::State::SynSent => St::SynSent,
            tcp::State::SynReceived => St::SynRcvd,
            tcp::State::Established => St::Established,
            tcp::State::FinWait1 => St::FinWait1,
            tcp::State::FinWait2 => St::FinWait2,
            tcp::State::CloseWait => St::CloseWait,
            tcp::State::Closing => St::Closing,
            tcp::State::LastAck => St::LastAck,
            tcp::State::TimeWait => St::TimeWait,
        }
    }
    fn settled(&self) -> bool {
        // The send buffer holds everything not yet acknowledged.
        !self.state().ctl_unacked() && self.sock().send_queue() == 0
    }
    fn was_reset(&self) -> bool {
        self.reset
    }
}

/// Bytes of per-connection state, and what part of it is data buffers.
pub fn footprint() -> Vec<(String, usize, String)> {
    vec![
        (
            "tcp-sans-io (1 MiB rings)".into(),
            std::mem::size_of::<Tcb>(),
            (2 * tcp_sans_io::BUF_CAP).to_string(),
        ),
        (
            "tcp-sans-io (64 KiB rings, `Tcb<65536>`)".into(),
            std::mem::size_of::<Tcb<65536>>(),
            (2 * 65536).to_string(),
        ),
        (
            "smoltcp socket".into(),
            std::mem::size_of::<tcp::Socket<'static>>(),
            "caller-supplied".into(),
        ),
        (
            "smoltcp `Interface` (per interface)".into(),
            std::mem::size_of::<Interface>(),
            "—".into(),
        ),
    ]
}
