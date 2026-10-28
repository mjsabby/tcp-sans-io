//! Fuzz `Tcb::inject_packet` with fuzzer-chosen TCP segments.
//!
//! The input is decoded into a sequence of segments, each wrapped in a
//! well-formed IPv4 datagram with **valid IP and TCP checksums** (random bytes
//! almost never pass the checksum gate, which left the original byte-chunking
//! harness stuck in the parser). SEQ/ACK are either raw 32-bit values or
//! rebased onto the live connection; TCP options are either raw bytes (the
//! option parser in context) or a structured set (MSS / WS / SACK-permitted /
//! timestamps / SACK blocks). The TCB starts in `LISTEN` (or `SYN_SENT`), and
//! the clock advances between segments so timer paths run too.
//!
//! Oracles:
//! * internal errors (`Overflow`, `BufferTooSmall` with harness-sized
//!   buffers) must never escape the API,
//! * the TCB's own debug invariants must hold after every operation,
//! * every emitted packet must parse and must come from the local endpoint,
//! * output per step is bounded (no ACK/output storm),
//! * state transitions must be ones `State::debug_transition_allowed` lists
//!   (the relation `docs/state-machine.dot` draws),
//! * `snd_una` / `rcv_nxt` only move forward while synchronized,
//! * at rest, a timer reported by `next_deadline` lies in the future.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::wire::{self, SackBlocks, TcpOptions};
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError, MAX_PACKET};

/// Panic iff a call surfaced an internal invariant code.
#[track_caller]
fn no_internal<T>(r: Result<T, TcpError>) -> Result<T, TcpError> {
    match r {
        Err(TcpError::Overflow) => {
            panic!("internal TcpError::Overflow escaped across the API boundary")
        }
        Err(TcpError::BufferTooSmall) => {
            panic!("internal TcpError::BufferTooSmall escaped with MAX_PACKET buffers")
        }
        other => other,
    }
}

#[track_caller]
fn check(tcb: &Tcb) {
    if let Err(e) = tcb.debug_validate_invariants() {
        panic!("TCB invariant failed: {e}");
    }
}

#[track_caller]
fn observe_state(prev: &mut State, tcb: &Tcb) {
    let next = tcb.state();
    if !prev.debug_transition_allowed(next) {
        panic!("illegal TCP state transition: {:?} -> {:?}", *prev, next);
    }
    *prev = next;
    check(tcb);
}

/// Livelock oracle: at a fixed clock with nothing injected, the stack must
/// stop emitting within a bounded number of tick+drain cycles. A spin here
/// would otherwise hang the process with no crash artifact.
fn settle(tcb: &mut Tcb, prev: &mut State, now: u64) {
    for _ in 0..4096 {
        let _ = no_internal(tcb.tick());
        observe_state(prev, tcb);
        let mut out = [0u8; MAX_PACKET];
        let mut emitted = false;
        for _ in 0..256 {
            match no_internal(tcb.extract_packet(&mut out)) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    emitted = true;
                    observe_state(prev, tcb);
                }
            }
        }
        if !emitted {
            if let Some(d) = tcb.next_deadline() {
                assert!(d > now, "next_deadline {d} <= now {now} at rest");
            }
            return;
        }
    }
    panic!("livelock: stack never quiesced at a fixed clock with no input");
}

/// Monotonic-progress oracle for the cumulative cursors (only meaningful
/// while the connection stays synchronized: a recycled listener restarts
/// its sequence space).
#[track_caller]
fn assert_monotonic(prev: &mut Option<(u32, u32)>, tcb: &Tcb) {
    if !tcb.state().is_synchronized() {
        *prev = None;
        return;
    }
    let s = tcb.debug_snapshot();
    if let Some((una, nxt)) = *prev {
        assert!(
            (s.snd_una.wrapping_sub(una) as i32) >= 0,
            "snd_una regressed: {una} -> {}",
            s.snd_una,
        );
        assert!(
            (s.rcv_nxt.wrapping_sub(nxt) as i32) >= 0,
            "rcv_nxt regressed: {nxt} -> {}",
            s.rcv_nxt,
        );
    }
    *prev = Some((s.snd_una, s.rcv_nxt));
}

const LOCAL_IP: [u8; 4] = [10, 0, 0, 1];
const LOCAL_PORT: u16 = 8080;
const PEERS: [([u8; 4], u16); 3] = [
    ([10, 0, 0, 2], 4000),
    ([10, 0, 0, 2], 4001),
    ([10, 0, 0, 9], 4000),
];

struct Input<'a> {
    d: &'a [u8],
    i: usize,
}

impl Input<'_> {
    fn done(&self) -> bool {
        self.i >= self.d.len()
    }
    fn u8(&mut self) -> u8 {
        let v = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    fn bytes(&mut self, n: usize) -> &[u8] {
        let start = self.i.min(self.d.len());
        let end = (start + n).min(self.d.len());
        self.i = start + n;
        &self.d[start..end]
    }
}

fn csum(data: &[u8], mut sum: u32) -> u16 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [b] = chunks.remainder() {
        sum += u32::from(*b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 + TCP datagram with raw option bytes and valid checksums.
#[allow(clippy::too_many_arguments)]
fn raw_segment(
    src: ([u8; 4], u16),
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let opt_len = options.len().min(40).div_ceil(4) * 4;
    let tcp_len = 20 + opt_len + payload.len();
    let total = 20 + tcp_len;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&src.0);
    p[16..20].copy_from_slice(&LOCAL_IP);
    let ip_sum = csum(&p[..20], 0);
    p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let t = &mut p[20..];
    t[0..2].copy_from_slice(&src.1.to_be_bytes());
    t[2..4].copy_from_slice(&LOCAL_PORT.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = (((20 + opt_len) / 4) as u8) << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&window.to_be_bytes());
    let n = options.len().min(40);
    t[20..20 + n].copy_from_slice(&options[..n]);
    t[20 + opt_len..].copy_from_slice(payload);
    let mut pseudo = 0u32;
    for w in [src.0, LOCAL_IP] {
        pseudo += u32::from(u16::from_be_bytes([w[0], w[1]]));
        pseudo += u32::from(u16::from_be_bytes([w[2], w[3]]));
    }
    pseudo += 6 + tcp_len as u32;
    let tcp_sum = csum(&p[20..], pseudo);
    p[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    p
}

fn make_tcb(mode: u8) -> Tcb {
    let active = mode & 0x10 != 0;
    let mut tcb = Tcb::new(TcbConfig {
        local: Endpoint {
            ip: LOCAL_IP,
            port: LOCAL_PORT,
        },
        remote: Endpoint {
            ip: PEERS[0].0,
            port: if active { PEERS[0].1 } else { 0 },
        },
        iss: 0xDEAD_BEEF,
        initial_rto_ms: 1000,
    })
    .unwrap();
    // The harness jumps the clock arbitrarily; disable the on-by-default
    // wall-clock aborts (USER TIMEOUT and keepalive) so neither can fire mid-
    // sequence on the compressed virtual clock (both are unit-tested separately).
    tcb.set_user_timeout(0);
    tcb.set_keepalive(0, 0, 0);
    // A listener needs a secret: a host secret (deriving the cookie key),
    // an explicit cookie secret, or both.
    if mode & 1 != 0 || mode & 2 == 0 {
        tcb.set_secret(&[0x11; 16]);
    }
    if mode & 2 != 0 {
        tcb.set_cookie_secret(&[0x22; 16]);
    }
    if mode & 4 != 0 {
        let _ = tcb.set_mtu(576 + u16::from(mode >> 5) * 128);
    }
    tcb
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input { d: data, i: 0 };
    let mode = inp.u8();
    let mut tcb = make_tcb(mode);
    let mut prev_state = State::Closed;
    let mut now_ms: u64 = 1;
    tcb.set_now(now_ms);
    let opened = if mode & 0x10 != 0 {
        tcb.connect()
    } else {
        tcb.listen()
    };
    if opened.is_err() {
        return;
    }
    observe_state(&mut prev_state, &tcb);
    let mut mono = None;
    let mut last_synack: u32 = 0;
    let mut last_tsval: u32 = 0;
    let mut tsv: u32 = 1000;
    let payload_src = [0x5au8; 1460];

    let mut steps = 0;
    while !inp.done() && steps < 256 {
        steps += 1;
        let sel = inp.u8();
        let src = PEERS[usize::from(sel % 3)];
        let snap = tcb.debug_snapshot();
        let seq = match (sel >> 2) & 3 {
            0 => inp.u32(),
            1 => snap.rcv_nxt.wrapping_add(i32::from(inp.u16() as i16) as u32),
            2 => snap.rcv_nxt,
            _ => snap.rcv_nxt.wrapping_sub(u32::from(inp.u8())),
        };
        let ack = match (sel >> 4) & 3 {
            0 => inp.u32(),
            1 => snap.snd_una.wrapping_add(i32::from(inp.u16() as i16) as u32),
            2 => snap.snd_nxt,
            _ => last_synack.wrapping_add(1),
        };
        let flags = inp.u8();
        let window = inp.u16();
        let plen = usize::from(inp.u16() % 1461);
        let payload = &payload_src[..plen];
        let packet = if sel & 0x40 != 0 {
            let olen = usize::from(inp.u8() % 41);
            let opts = inp.bytes(olen).to_vec();
            raw_segment(src, seq, ack, flags, window, &opts, payload)
        } else {
            let ob = inp.u8();
            let mut o = TcpOptions::NONE;
            if ob & 1 != 0 {
                o.mss = Some(inp.u16());
            }
            if ob & 2 != 0 {
                o.wscale = Some(inp.u8() % 16);
            }
            o.sack_permitted = ob & 4 != 0;
            if ob & 8 != 0 {
                tsv = tsv.wrapping_add(u32::from(inp.u8()));
                let v = if ob & 0x40 != 0 { inp.u32() } else { tsv };
                o.ts = Some((v, last_tsval));
            }
            if ob & 0x10 != 0 {
                let mut sb = SackBlocks::EMPTY;
                for _ in 0..(inp.u8() % 4) {
                    let l = snap.snd_una.wrapping_add(u32::from(inp.u16()));
                    sb.push(l, l.wrapping_add(u32::from(inp.u16() % 8192)));
                }
                o.sack = sb;
            }
            let ecn = if ob & 0x20 != 0 { inp.u8() & 3 } else { 0 };
            let mut b = vec![0u8; 20 + 60 + plen];
            match wire::emit(
                &mut b, src.0, LOCAL_IP, src.1, LOCAL_PORT, seq, ack, flags, window, &o,
                payload, 1, ecn,
            ) {
                Ok(n) => {
                    b.truncate(n);
                    b
                }
                Err(_) => continue,
            }
        };

        let _ = no_internal(tcb.inject_packet(&packet));
        observe_state(&mut prev_state, &tcb);
        // Drain any reply packets the stack staged.
        let mut out = [0u8; MAX_PACKET];
        let mut drained = 0u32;
        loop {
            match no_internal(tcb.extract_packet(&mut out)) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    drained += 1;
                    assert!(drained <= 40, "unbounded output in one step");
                    let s = wire::parse(&out[..n]).expect("self-emitted packet must parse");
                    assert_eq!(s.src_ip, LOCAL_IP, "emitted packet has wrong source IP");
                    assert_eq!(s.src_port, LOCAL_PORT, "emitted packet has wrong source port");
                    if s.has(wire::flags::SYN) && s.has(wire::flags::ACK) {
                        last_synack = s.seq;
                    }
                    if let Some((v, _)) = s.options.ts {
                        last_tsval = v;
                    }
                }
            }
            observe_state(&mut prev_state, &tcb);
        }
        assert_monotonic(&mut mono, &tcb);

        // Advance time: 0..=255 ms, or a long jump that fires backed-off
        // timers (cookie buckets, TIME_WAIT, FIN_WAIT_2, probes).
        let d = inp.u8();
        now_ms += if d & 0x80 != 0 {
            u64::from(d & 0x7f) * 1000
        } else {
            u64::from(d)
        };
        tcb.set_now(now_ms);
        check(&tcb);
        let _ = no_internal(tcb.tick());
        observe_state(&mut prev_state, &tcb);

        // Livelock + monotonic oracles at the (now fixed) clock.
        settle(&mut tcb, &mut prev_state, now_ms);
        assert_monotonic(&mut mono, &tcb);

        // Occasionally re-arm a closed listener, as a host recycling it would.
        if tcb.state() == State::Closed && sel & 0x80 != 0 {
            let _ = no_internal(tcb.listen());
            observe_state(&mut prev_state, &tcb);
        }
    }
});
