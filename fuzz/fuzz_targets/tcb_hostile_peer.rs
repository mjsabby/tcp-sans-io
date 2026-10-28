//! Structured hostile-peer fuzzer for both open modes. Every segment is
//! well-formed (valid checksums) with SEQ/ACK chosen relative to the TCB's
//! live state, from one of three peers, so the fuzzer reaches LISTEN /
//! SYN_RCVD, hybrid SYN cookies (a busy half-open slot answered with
//! cookies, cookie ACKs taking the slot over, key rotation), simultaneous
//! open and every closing state — instead of dying in the parser.
//!
//! Oracles: internal errors never escape; `debug_validate_invariants` and
//! `debug_check_liveness` hold; transitions are ones
//! `State::debug_transition_allowed` lists; `snd_una` / `rcv_nxt` only move
//! forward within a connection; `next_deadline()` lies in the future at
//! rest; at most one reply to any non-SYN segment in LISTEN and to any
//! segment from a peer other than the half-open's while in SYN_RCVD.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::wire::{self, flags, SackBlocks, TcpOptions};
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError, MAX_PACKET};

const LOCAL: ([u8; 4], u16) = ([10, 0, 0, 1], 8080);
const PEERS: [([u8; 4], u16); 3] = [
    ([10, 0, 0, 2], 5555),
    ([10, 0, 0, 3], 6666),
    ([10, 0, 0, 2], 5556),
];

struct R<'a> {
    d: &'a [u8],
    i: usize,
}

impl R<'_> {
    fn u8(&mut self) -> u8 {
        let v = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    fn done(&self) -> bool {
        self.i >= self.d.len()
    }
}

#[track_caller]
fn ni<T>(r: Result<T, TcpError>) -> Result<T, TcpError> {
    match r {
        Err(TcpError::Overflow) => panic!("internal Overflow escaped"),
        Err(TcpError::BufferTooSmall) => panic!("BufferTooSmall with MAX_PACKET buffers"),
        o => o,
    }
}

struct H {
    t: Box<Tcb>,
    prev: State,
    now: u64,
    last_synack: u32,
    last_tsval: u32,
    mono: Option<(u32, u32)>,
}

impl H {
    fn observe(&mut self) {
        let next = self.t.state();
        assert!(
            self.prev.debug_transition_allowed(next),
            "illegal transition {:?} -> {:?}",
            self.prev,
            next
        );
        if !next.is_synchronized() || !self.prev.is_synchronized() {
            self.mono = None;
        }
        self.prev = next;
        if let Err(e) = self.t.debug_validate_invariants() {
            panic!("invariant: {e}");
        }
        if next.is_synchronized() {
            let s = self.t.debug_snapshot();
            if let Some((u, r)) = self.mono {
                assert!((s.snd_una.wrapping_sub(u) as i32) >= 0, "snd_una regressed");
                assert!((s.rcv_nxt.wrapping_sub(r) as i32) >= 0, "rcv_nxt regressed");
            }
            self.mono = Some((s.snd_una, s.rcv_nxt));
        }
    }

    /// Drain; returns (packets emitted, packets addressed to `to`).
    fn drain(&mut self, to: Option<([u8; 4], u16)>) -> (usize, usize) {
        let mut out = [0u8; MAX_PACKET];
        let mut n_to = 0;
        for total in 0..40 {
            match ni(self.t.extract_packet(&mut out)) {
                Ok(0) | Err(_) => return (total, n_to),
                Ok(n) => {
                    let s = wire::parse(&out[..n]).expect("emitted packet must parse");
                    assert_eq!((s.src_ip, s.src_port), LOCAL, "wrong source");
                    if s.flags & (flags::SYN | flags::ACK) == (flags::SYN | flags::ACK) {
                        self.last_synack = s.seq;
                    }
                    if let Some((v, _)) = s.options.ts {
                        self.last_tsval = v;
                    }
                    if Some((s.dst_ip, s.dst_port)) == to {
                        n_to += 1;
                    }
                }
            }
        }
        panic!("more than 40 packets staged at once");
    }

    /// Tick and drain at a fixed clock until quiet (livelock oracle), then
    /// check liveness and that no reported deadline is already due.
    fn settle(&mut self) {
        for _ in 0..4096 {
            let _ = ni(self.t.tick());
            self.observe();
            if self.drain(None).0 == 0 {
                if let Err(e) = self.t.debug_check_liveness() {
                    panic!("{e}");
                }
                if let Some(d) = self.t.next_deadline() {
                    assert!(d > self.now, "next_deadline {d} <= now {} at rest", self.now);
                }
                return;
            }
        }
        panic!("livelock at fixed clock");
    }
}

fuzz_target!(|data: &[u8]| {
    let mut r = R { d: data, i: 0 };
    let mode = r.u8();
    let active = mode & 4 != 0;
    let remote = if active { PEERS[0] } else { ([0; 4], 0) };
    let mut b = Box::<Tcb>::new_uninit();
    // SAFETY: `b` is fresh, aligned storage for one Tcb; init_in_place
    // fully initialises it on success.
    let t = unsafe {
        Tcb::init_in_place(
            b.as_mut_ptr(),
            TcbConfig {
                local: Endpoint {
                    ip: LOCAL.0,
                    port: LOCAL.1,
                },
                remote: Endpoint {
                    ip: remote.0,
                    port: remote.1,
                },
                iss: 0x8000_0000 ^ u32::from(mode),
                initial_rto_ms: 1000,
            },
        )
        .unwrap();
        b.assume_init()
    };
    let mut h = H {
        t,
        prev: State::Closed,
        now: 1,
        last_synack: 0,
        last_tsval: 0,
        mono: None,
    };
    h.t.set_now(h.now);
    // Listeners need a secret: a host secret (deriving the cookie key), an
    // explicit cookie key, or both.
    if mode & 2 != 0 || mode & 1 == 0 {
        h.t.set_secret(&[0x11; 16]);
    }
    if mode & 1 != 0 {
        h.t.set_cookie_secret(&[0x22; 16]);
    }
    if mode & 8 != 0 {
        let _ = h.t.set_mtu(576 + u16::from(mode >> 4) * 50);
    }
    if mode & 0x40 != 0 {
        h.t.set_keepalive(0, 0, 0);
        h.t.set_user_timeout(0);
    }
    let opened = if active { h.t.connect() } else { h.t.listen() };
    assert!(opened.is_ok(), "open failed: {opened:?}");
    h.observe();
    h.drain(None);
    let mut tsv: u32 = 1000;
    let payload = [0x5au8; 1460];
    let mut rbuf = [0u8; 4096];
    let mut steps = 0;
    while !r.done() && steps < 200 {
        steps += 1;
        match r.u8() % 8 {
            0..=3 => {
                let src = PEERS[usize::from(r.u8() % 3)];
                let fl = r.u8();
                let snap = h.t.debug_snapshot();
                let plen = usize::from(r.u16() % 1461).min(if r.u8() & 1 == 0 { 64 } else { 1460 });
                let seq = match r.u8() % 4 {
                    0 => snap.rcv_nxt.wrapping_add(i32::from(r.u16() as i16) as u32),
                    1 => snap.rcv_nxt.wrapping_sub(1),
                    2 => r.u32(),
                    _ => snap.rcv_nxt.wrapping_sub((plen / 2) as u32),
                };
                let ack = match r.u8() % 5 {
                    0 => snap.snd_una.wrapping_add(i32::from(r.u16() as i16) as u32),
                    1 => snap.snd_nxt.wrapping_add(i32::from(r.u8() as i8) as u32),
                    2 => r.u32(),
                    3 => h.last_synack.wrapping_add(1),
                    _ => snap.snd_nxt,
                };
                let win = r.u16();
                let ob = r.u8();
                let mut o = TcpOptions::NONE;
                if ob & 1 != 0 {
                    o.mss = Some(r.u16());
                }
                if ob & 2 != 0 {
                    o.wscale = Some(r.u8() % 16);
                }
                if ob & 4 != 0 {
                    o.sack_permitted = true;
                }
                if ob & 8 != 0 {
                    tsv = tsv.wrapping_add(u32::from(r.u8()));
                    let v = if ob & 0x80 != 0 { r.u32() } else { tsv };
                    let e = if ob & 0x40 != 0 { r.u32() } else { h.last_tsval };
                    o.ts = Some((v, e));
                }
                if ob & 0x10 != 0 {
                    let mut sb = SackBlocks::EMPTY;
                    for _ in 0..(r.u8() % 4) {
                        let l = snap.snd_una.wrapping_add(u32::from(r.u16()));
                        sb.push(l, l.wrapping_add(u32::from(r.u16() % 4096)));
                    }
                    o.sack = sb;
                }
                let ecn = if ob & 0x20 != 0 { r.u8() & 3 } else { 0 };
                let p = payload.get(..plen).unwrap_or(&[]);
                let mut buf = vec![0u8; 20 + 60 + plen];
                let Ok(n) = wire::emit(
                    &mut buf, src.0, LOCAL.0, src.1, LOCAL.1, seq, ack, fl, win, &o, p, 1, ecn,
                ) else {
                    continue;
                };
                buf.truncate(n);
                let st_before = h.t.state();
                let _ = ni(h.t.inject_packet(&buf));
                h.observe();
                let (_, replies) = h.drain(Some(src));
                if st_before == State::Listen && fl & flags::SYN == 0 {
                    assert!(replies <= 1, "{replies} replies to a non-SYN segment in LISTEN");
                }
                if st_before == State::SynRcvd && h.t.state() == State::SynRcvd {
                    assert!(replies <= 1, "{replies} replies from a SYN_RCVD listener");
                }
            }
            4 => {
                let step = u64::from(r.u16());
                h.now += if step & 0x8000 != 0 {
                    (step & 0x7fff) * 100
                } else {
                    step
                };
                h.t.set_now(h.now);
                let _ = ni(h.t.tick());
                h.observe();
                h.drain(None);
            }
            5 => {
                let n = usize::from(r.u16());
                let _ = ni(h.t.send(&vec![0xa5u8; n]));
                h.observe();
            }
            6 => {
                let n = usize::from(r.u16()).min(rbuf.len());
                let _ = ni(h.t.recv(&mut rbuf[..n]));
                h.observe();
                h.drain(None);
            }
            _ => {
                match r.u8() % 7 {
                    0 => {
                        let _ = ni(h.t.close());
                    }
                    1 => {
                        let _ = ni(h.t.abort());
                    }
                    2 => {
                        let _ = ni(h.t.listen());
                    }
                    3 => h.t.update_pmtu(r.u16()),
                    4 => h.t.set_cookie_secret(&[r.u8(); 16]),
                    5 => h.t.set_secret(&[r.u8(); 16]),
                    _ => {
                        let _ = ni(h.t.connect());
                    }
                }
                h.observe();
                h.drain(None);
            }
        }
        h.settle();
    }
});
