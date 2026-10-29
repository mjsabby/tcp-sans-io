//! Structured adversarial segments against an ESTABLISHED `Tcb`.
//!
//! `tcb_inject_sequence` and `tcb_hostile_peer` start from LISTEN or
//! SYN_SENT and spread their effort over handshakes, listeners and SYN
//! cookies; `tcb_client_session` scripts a mostly well-behaved peer. This
//! target concentrates on an established connection: every segment is built
//! with `wire::emit` (valid checksums) from fuzzer-chosen flags, sequence and
//! acknowledgment numbers (biased to the live window edges), window,
//! timestamp and SACK options, IPv4 ECN bits and payload, interleaved with
//! application `send` / `recv` / `close` / `abort`, PMTU updates and clock
//! jumps. It is the target that exercises the RFC 5961 / PAWS / ECN
//! acceptance paths with off-path-style input.
//!
//! Oracles:
//! * no panic (internal loop budgets panic in `std` builds),
//! * `debug_validate_invariants` after every call,
//! * every state change is one `State::debug_transition_allowed` lists,
//! * no internal error code (`Overflow` / `BufferTooSmall`) escapes,
//! * at most `TX_RING_CAP` packets per drain, every one parsable and
//!   addressed local → peer,
//! * `next_deadline()` is in the future after every `tick()`,
//! * `SND.UNA` / `RCV.NXT` never regress while the connection is open,
//! * the stack quiesces at a fixed clock and, if still open, has a timer
//!   covering its outstanding work (`debug_check_liveness`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::wire::{self, flags, SackBlocks, TcpOptions};
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError, MAX_PACKET};

const C_IP: [u8; 4] = [10, 0, 0, 1];
const S_IP: [u8; 4] = [10, 0, 0, 2];
const C_PORT: u16 = 40000;
const S_PORT: u16 = 443;
const C_ISS: u32 = 0x1234_5678;
const PEER_ISS: u32 = 0x7000_0000;
const MAX_STEPS: usize = 400;

/// Cursor over the fuzzer input; reads past the end yield zero.
struct In<'a> {
    d: &'a [u8],
    i: usize,
}

impl In<'_> {
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
fn no_internal<T>(r: Result<T, TcpError>) -> Result<T, TcpError> {
    match r {
        Err(TcpError::Overflow) => panic!("internal TcpError::Overflow escaped the API"),
        Err(TcpError::BufferTooSmall) => {
            panic!("internal TcpError::BufferTooSmall escaped with MAX_PACKET buffers")
        }
        other => other,
    }
}

#[track_caller]
fn check(t: &Tcb, prev: &mut State) {
    if let Err(e) = t.debug_validate_invariants() {
        panic!("TCB invariant failed: {e}");
    }
    let next = t.state();
    assert!(
        prev.debug_transition_allowed(next),
        "illegal TCP state transition: {prev:?} -> {next:?}"
    );
    *prev = next;
}

#[allow(clippy::too_many_arguments)]
fn peer_pkt(
    seq: u32,
    ack: u32,
    fl: u8,
    win: u16,
    opts: &TcpOptions,
    payload: &[u8],
    ecn: u8,
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 2048];
    let n = wire::emit(
        &mut buf, S_IP, C_IP, S_PORT, C_PORT, seq, ack, fl, win, opts, payload, 1, ecn,
    )
    .ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Drain egress, validating every packet. Returns the packet count and
/// folds the highest `seq + len` seen into `hi`.
fn drain(t: &mut Tcb, hi: &mut u32, prev: &mut State) -> usize {
    let mut out = [0u8; MAX_PACKET];
    let mut n_out = 0;
    for _ in 0..64 {
        match no_internal(t.extract_packet(&mut out)) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                n_out += 1;
                let seg = wire::parse(&out[..n]).expect("self-emitted packet must parse");
                assert_eq!(seg.src_ip, C_IP, "emitted packet has wrong source IP");
                assert_eq!(seg.dst_ip, S_IP, "emitted packet has wrong destination IP");
                let end = seg.seq.wrapping_add(seg.seq_len());
                if (end.wrapping_sub(*hi) as i32) > 0 {
                    *hi = end;
                }
            }
        }
        check(t, prev);
    }
    assert!(n_out <= 32, "more than TX_RING_CAP packets in one drain");
    n_out
}

/// Livelock oracle: at a fixed clock with no input the stack must go quiet.
fn settle(t: &mut Tcb, hi: &mut u32, prev: &mut State) {
    for _ in 0..2048 {
        let _ = no_internal(t.tick());
        check(t, prev);
        if drain(t, hi, prev) == 0 {
            return;
        }
    }
    panic!("livelock: stack never quiesced at a fixed clock with no input");
}

/// Active open against a scripted SYN-ACK whose options the fuzzer picks.
/// Returns `None` if the handshake did not complete (an invalid option mix).
fn handshake(
    inp: &mut In<'_>,
    t: &mut Tcb,
    now: &mut u64,
    hi: &mut u32,
    prev: &mut State,
) -> Option<HandshakeOpts> {
    let o = inp.u8();
    let use_ts = o & 1 != 0;
    let mss = match (o >> 4) & 3 {
        0 => 1460,
        1 => 536,
        2 => 64,
        _ => 9000,
    };
    t.set_now(*now);
    t.connect().ok()?;
    check(t, prev);
    let syn_tsval = {
        let mut out = [0u8; MAX_PACKET];
        let n = t.extract_packet(&mut out).ok()?;
        wire::parse(&out[..n]).ok()?.options.ts.map(|(v, _)| v)
    };
    let opts = TcpOptions {
        mss: Some(mss),
        wscale: (o & 2 != 0).then(|| inp.u8() & 15),
        ts: use_ts.then(|| (5, syn_tsval.unwrap_or(0))),
        sack_permitted: o & 4 != 0,
        sack: SackBlocks::EMPTY,
    };
    let fl = flags::SYN | flags::ACK | if o & 8 != 0 { flags::ECE } else { 0 };
    let synack = peer_pkt(PEER_ISS, C_ISS.wrapping_add(1), fl, 65535, &opts, &[], 0)?;
    *now += 20;
    t.set_now(*now);
    let _ = no_internal(t.inject_packet(&synack));
    check(t, prev);
    drain(t, hi, prev);
    (t.state() == State::Established).then_some(HandshakeOpts { use_ts })
}

struct HandshakeOpts {
    use_ts: bool,
}

fuzz_target!(|data: &[u8]| {
    let mut inp = In { d: data, i: 0 };
    let mut t = Tcb::new(TcbConfig {
        local: Endpoint {
            ip: C_IP,
            port: C_PORT,
        },
        remote: Endpoint {
            ip: S_IP,
            port: S_PORT,
        },
        iss: C_ISS,
        initial_rto_ms: 1000,
    })
    .unwrap();
    t.set_secret(&[9u8; 16]);
    let mut now: u64 = 1000;
    let mut hi = 0u32;
    let mut prev = t.state();
    let Some(hs) = handshake(&mut inp, &mut t, &mut now, &mut hi, &mut prev) else {
        return;
    };
    // What a well-behaved peer would send next, so some segments are
    // in order and the stream actually advances.
    let mut peer_seq = PEER_ISS.wrapping_add(1);
    let mut peer_ts: u32 = 6;
    let mut mono = {
        let s = t.debug_snapshot();
        (s.snd_una, s.rcv_nxt)
    };

    for _ in 0..MAX_STEPS {
        if inp.done() {
            break;
        }
        match inp.u8() % 8 {
            0..=3 => {
                let snap = t.debug_snapshot();
                let fl = inp.u8();
                let rel = u32::from(inp.u16());
                let seq = match inp.u8() % 6 {
                    0 => snap.rcv_nxt,
                    1 => snap.rcv_nxt.wrapping_add(rel),
                    2 => snap.rcv_nxt.wrapping_sub(rel),
                    3 => peer_seq,
                    4 => snap.rcv_nxt.wrapping_add(rel << 12),
                    _ => inp.u32(),
                };
                let arel = u32::from(inp.u16());
                let ack = match inp.u8() % 6 {
                    0 => snap.snd_nxt,
                    1 => snap.snd_una.wrapping_add(arel),
                    2 => snap.snd_una.wrapping_sub(arel),
                    3 => hi,
                    4 => snap.snd_nxt.wrapping_add(arel << 12),
                    _ => inp.u32(),
                };
                let win = inp.u16();
                let plen = match inp.u8() % 5 {
                    0 => 0,
                    1 => 1,
                    2 => 100,
                    3 => 1448,
                    _ => usize::from(inp.u16()) % 1460,
                };
                let payload = vec![inp.u8(); plen];
                let ts = (hs.use_ts && inp.u8() & 3 != 0).then(|| {
                    let tsval = match inp.u8() % 4 {
                        0 => peer_ts,
                        1 => peer_ts.wrapping_add(u32::from(inp.u8())),
                        2 => peer_ts.wrapping_sub(u32::from(inp.u8())),
                        _ => inp.u32(),
                    };
                    let tsecr = match inp.u8() % 3 {
                        0 => 0,
                        1 => (now as u32).wrapping_sub(u32::from(inp.u8())),
                        _ => inp.u32(),
                    };
                    (tsval, tsecr)
                });
                let mut sack = SackBlocks::EMPTY;
                for _ in 0..inp.u8() % 4 {
                    let base = match inp.u8() % 3 {
                        0 => snap.snd_una,
                        1 => hi,
                        _ => inp.u32(),
                    };
                    let l = base
                        .wrapping_add(u32::from(inp.u16()))
                        .wrapping_sub(u32::from(inp.u8()));
                    let r = l
                        .wrapping_add(u32::from(inp.u16()))
                        .wrapping_sub(u32::from(inp.u8()));
                    sack.push(l, r);
                }
                let opts = TcpOptions {
                    ts,
                    sack,
                    ..TcpOptions::NONE
                };
                let ecn = inp.u8() & 3;
                if let Some(p) = peer_pkt(seq, ack, fl, win, &opts, &payload, ecn) {
                    let _ = no_internal(t.inject_packet(&p));
                    check(&t, &mut prev);
                    drain(&mut t, &mut hi, &mut prev);
                    if seq == peer_seq
                        && fl & flags::ACK != 0
                        && fl & (flags::RST | flags::SYN) == 0
                    {
                        let after = t.debug_snapshot().rcv_nxt;
                        if (after.wrapping_sub(peer_seq) as i32) > 0 {
                            peer_seq = after;
                        }
                    }
                }
                peer_ts = peer_ts.wrapping_add(1);
            }
            4 => {
                let n = usize::from(inp.u16()) % 70_000;
                let _ = no_internal(t.send(&vec![0xA5u8; n]));
                check(&t, &mut prev);
            }
            5 => {
                let mut buf = vec![0u8; usize::from(inp.u16()) % 70_000 + 1];
                let _ = no_internal(t.recv(&mut buf));
                check(&t, &mut prev);
                drain(&mut t, &mut hi, &mut prev);
            }
            6 => {
                match inp.u8() % 8 {
                    0 => {
                        let _ = no_internal(t.close());
                    }
                    1 => {
                        let _ = no_internal(t.abort());
                    }
                    2 => t.update_pmtu(576 + inp.u16() % 1000),
                    3 => t.set_user_timeout(u32::from(inp.u16())),
                    4 => t.set_keepalive(u32::from(inp.u16()), u32::from(inp.u16()), inp.u8()),
                    _ => {}
                }
                check(&t, &mut prev);
                drain(&mut t, &mut hi, &mut prev);
            }
            _ => {
                let d = match inp.u8() % 4 {
                    0 => u64::from(inp.u8()),
                    1 => u64::from(inp.u16()),
                    2 => 1000 * u64::from(inp.u8()),
                    _ => 60_000 * (u64::from(inp.u8()) % 20),
                };
                now = now.saturating_add(d);
                t.set_now(now);
                let _ = no_internal(t.tick());
                check(&t, &mut prev);
                drain(&mut t, &mut hi, &mut prev);
                if let Some(dl) = t.next_deadline() {
                    assert!(
                        dl > now,
                        "next_deadline {dl} not after now {now} after tick"
                    );
                }
            }
        }
        let s = t.debug_snapshot();
        if t.state() == State::Closed {
            break;
        }
        assert!(
            (s.snd_una.wrapping_sub(mono.0) as i32) >= 0,
            "snd_una regressed"
        );
        assert!(
            (s.rcv_nxt.wrapping_sub(mono.1) as i32) >= 0,
            "rcv_nxt regressed"
        );
        mono = (s.snd_una, s.rcv_nxt);
    }
    settle(&mut t, &mut hi, &mut prev);
    if t.state() != State::Closed {
        if let Err(e) = t.debug_check_liveness() {
            panic!("liveness: {e}");
        }
    }
});
