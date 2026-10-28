//! Regression tests for the public-deployment hardening review.
//!
//! Each test reproduces a concrete attack or failure mode found in review
//! (blind injection, window freezing, ACK storms, resource pinning,
//! listener lockout, spurious retransmission, …) and asserts the fixed
//! behaviour. They drive only the public `Tcb` / `wire` API with scripted
//! peer packets, so they double as executable documentation of the threat
//! model.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::boxed::Box;
use std::vec;
use std::vec::Vec;

use crate::tcb::{Endpoint, Tcb, TcbConfig};
use crate::wire::{self, flags, SackBlocks, TcpOptions};
use crate::{State, TcpError, MAX_PACKET};

const CLI: ([u8; 4], u16) = ([10, 0, 0, 1], 40000);
const SRV: ([u8; 4], u16) = ([10, 0, 0, 2], 80);
const ATTACKER: ([u8; 4], u16) = ([6, 6, 6, 6], 1234);
const SRV_ISS: u32 = 50_000_000;

fn cfg(local: ([u8; 4], u16), remote: ([u8; 4], u16), iss: u32) -> TcbConfig {
    TcbConfig {
        local: Endpoint {
            ip: local.0,
            port: local.1,
        },
        remote: Endpoint {
            ip: remote.0,
            port: remote.1,
        },
        iss,
        initial_rto_ms: 1000,
    }
}

fn new_tcb(local: ([u8; 4], u16), remote: ([u8; 4], u16), iss: u32) -> Box<Tcb> {
    Box::new(Tcb::new(cfg(local, remote, iss)).unwrap())
}

#[allow(clippy::too_many_arguments)]
fn pkt(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack: u32,
    fl: u8,
    win: u16,
    opts: &TcpOptions,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = vec![0u8; 20 + 60 + payload.len()];
    let n = wire::emit(
        &mut b,
        src.0,
        dst.0,
        src.1,
        dst.1,
        seq,
        ack,
        fl,
        win,
        opts,
        payload,
        7,
        wire::ecn::NOT_ECT,
    )
    .unwrap();
    b.truncate(n);
    b
}

#[derive(Debug, Clone)]
struct Out {
    dst: ([u8; 4], u16),
    seq: u32,
    ack: u32,
    flags: u8,
    win: u16,
    len: usize,
    total_len: usize,
    opts: TcpOptions,
}

fn drain(t: &mut Tcb) -> Vec<Out> {
    let mut v = Vec::new();
    let mut buf = [0u8; MAX_PACKET];
    loop {
        let n = t.extract_packet(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        let s = wire::parse(&buf[..n]).expect("stack emitted an unparsable packet");
        v.push(Out {
            dst: (s.dst_ip, s.dst_port),
            seq: s.seq,
            ack: s.ack,
            flags: s.flags,
            win: s.window,
            len: s.payload.len(),
            total_len: n,
            opts: s.options,
        });
    }
    v
}

fn ts(v: u32, e: u32) -> TcpOptions {
    TcpOptions {
        ts: Some((v, e)),
        ..TcpOptions::NONE
    }
}

/// Client connected to a scripted server (MSS 1460, WS 7, TS, optional
/// SACK/ECN). Returns (tcb, server's next sequence number, client ISS).
fn established(now: u64, sack: bool, ecn: bool) -> (Box<Tcb>, u32, u32) {
    let iss = 1_000_000;
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(now);
    c.connect().unwrap();
    let syn = drain(&mut c);
    let fl = flags::SYN | flags::ACK | if ecn { flags::ECE } else { 0 };
    let o = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ts: Some((1, syn[0].opts.ts.unwrap().0)),
        sack_permitted: sack,
        sack: SackBlocks::EMPTY,
    };
    c.set_now(now + 10);
    c.inject_packet(&pkt(SRV, CLI, SRV_ISS, iss + 1, fl, 8192, &o, &[]))
        .unwrap();
    assert_eq!(c.state(), State::Established);
    drain(&mut c);
    (c, SRV_ISS + 1, iss)
}

/// Let `c` send `n` bytes; returns the data segments as (seq, end).
fn send_burst(c: &mut Tcb, now: u64, n: usize) -> Vec<(u32, u32)> {
    c.send(&vec![0x5a; n]).unwrap();
    c.set_now(now);
    c.tick().unwrap();
    drain(c)
        .iter()
        .filter(|o| o.len > 0)
        .map(|o| (o.seq, o.seq + o.len as u32))
        .collect()
}

// ---------------------------------------------------------------------------
// Blind injection (RFC 5961, RFC 9293 §3.10.7.4)
// ---------------------------------------------------------------------------

/// RFC 9293 step 5: a segment without the ACK bit is dropped. Before the
/// fix its payload reached the application, so a blind injector only had to
/// guess an in-window sequence number.
#[test]
fn data_without_ack_bit_is_not_delivered() {
    let (mut c, sseq, _) = established(1000, true, false);
    c.set_now(1020);
    let r = c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        0,
        flags::PSH,
        8192,
        &TcpOptions::NONE,
        b"INJECTED",
    ));
    assert!(r.is_ok());
    let mut buf = [0u8; 64];
    assert_eq!(
        c.recv(&mut buf).unwrap(),
        0,
        "payload of an ACK-less segment was delivered"
    );
}

/// A segment far outside the receive window must not have its ACK field
/// processed (it used to advance SND.UNA, discarding data the peer never
/// received).
#[test]
fn ack_on_out_of_window_segment_is_ignored() {
    let (mut c, sseq, iss) = established(1000, true, false);
    send_burst(&mut c, 1020, 8000);
    let before = c.debug_snapshot();
    let forged_seq = sseq.wrapping_sub(0x4000_0000);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        forged_seq,
        iss + 1 + 5000,
        flags::ACK,
        8192,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    let after = c.debug_snapshot();
    assert_eq!(
        after.snd_una, before.snd_una,
        "out-of-window ACK advanced SND.UNA"
    );
    assert_eq!(after.send_ring_len, before.send_ring_len);
}

/// RFC 5961 §5.2: an in-window segment whose ACK is older than
/// `SND.UNA - MAX.SND.WND` is dropped (with a challenge ACK), data and all.
#[test]
fn ack_far_below_snd_una_is_rejected_with_challenge() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1100);
    let bogus_ack = (iss + 1).wrapping_sub(50_000_000);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        bogus_ack,
        flags::ACK | flags::PSH,
        8192,
        &ts(5, 0),
        b"evil",
    ))
    .unwrap();
    let out = drain(&mut c);
    let mut buf = [0u8; 16];
    assert_eq!(
        c.recv(&mut buf).unwrap(),
        0,
        "data with an implausible ACK was accepted"
    );
    assert_eq!(out.len(), 1, "exactly one challenge ACK");
    assert_eq!(out[0].ack, sseq);
}

/// RFC 5961 §3: only an exact-match RST resets; in-window RSTs draw at most
/// one challenge ACK per rate-limit interval (no RST-driven ACK flood).
#[test]
fn challenge_acks_are_rate_limited() {
    let (mut c, sseq, _) = established(1000, true, false);
    let mut acks = 0;
    for k in 0..200u32 {
        c.set_now(2000 + u64::from(k)); // 200 RSTs within 200 ms
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq + 1 + k,
            0,
            flags::RST,
            0,
            &TcpOptions::NONE,
            &[],
        ))
        .unwrap();
        acks += drain(&mut c).len();
    }
    assert_eq!(c.state(), State::Established);
    assert!(acks <= 1, "challenge ACKs not rate limited: {acks}");
    assert!(c.stats().oow_suppressed >= 199);
}

/// A single forged in-window segment advertising a zero window with a
/// "future" sequence number used to win every later SND.WL1 comparison and
/// freeze the sender for good. The window must reopen on the peer's next
/// genuine ACK.
#[test]
fn forged_zero_window_cannot_freeze_the_sender() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let mut now = 1020u64;
    c.set_now(now);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        0xffff,
        &ts(3, 0),
        &[],
    ))
    .unwrap();
    // Attacker: in-window SEQ ahead of RCV.NXT, ACK = SND.UNA, WIN = 0.
    let una = c.debug_snapshot().snd_una;
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 1000,
        una,
        flags::ACK,
        0,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(c.debug_snapshot().snd_wnd, 0);
    c.send(&vec![1u8; 100_000]).unwrap();
    // Honest peer: answers every packet with its real (open) window.
    let mut peer_rcv = iss + 1;
    for _ in 0..2_000 {
        now += 10;
        c.set_now(now);
        c.tick().unwrap();
        let out = drain(&mut c);
        for o in &out {
            if o.len > 0 && o.seq == peer_rcv {
                peer_rcv += o.len as u32;
            }
        }
        if !out.is_empty() {
            c.inject_packet(&pkt(
                SRV,
                CLI,
                sseq,
                peer_rcv,
                flags::ACK,
                0xffff,
                &ts(4, 0),
                &[],
            ))
            .unwrap();
        }
        if peer_rcv == iss + 1 + 100_000 {
            break;
        }
    }
    assert_eq!(
        peer_rcv,
        iss + 1 + 100_000,
        "sender stayed frozen by a forged window"
    );
}

/// TS.Recent may only follow segments covering the left edge we last
/// ACKed (RFC 7323 §4.3); a forged out-of-order segment carrying a huge
/// TSval must not hijack our TSecr echo.
#[test]
fn forged_tsval_does_not_hijack_ts_recent() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1100);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 5000,
        iss + 1,
        flags::ACK,
        1000,
        &ts(0x7fff_0000, 0),
        b"x",
    ))
    .unwrap();
    drain(&mut c);
    c.send(b"hello").unwrap();
    c.tick().unwrap();
    let out = drain(&mut c);
    let echo = out.iter().find(|o| o.len > 0).unwrap().opts.ts.unwrap().1;
    assert_ne!(
        echo, 0x7fff_0000,
        "TSecr echoes a forged out-of-order TSval"
    );
}

/// RFC 7323 §5 PAWS: data whose timestamp is older than TS.Recent is a
/// wrapped duplicate and must be dropped.
#[test]
fn paws_drops_data_with_old_timestamp() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1100);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        1000,
        &ts(5_000, 0),
        b"new",
    ))
    .unwrap();
    drain(&mut c);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 3,
        iss + 1,
        flags::ACK,
        1000,
        &ts(4_000, 0),
        b"old",
    ))
    .unwrap();
    let mut buf = [0u8; 16];
    let n = c.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"new");
}

/// RFC 5961 §5.2 drops a segment with an unacceptable ACK whole. Its
/// timestamp used to be absorbed first, so one forged pure ACK of unsent
/// data (ACK = SND.NXT + 1) with a far-future TSval made PAWS discard all
/// of the peer's genuine data until the peer's clock caught up, and also
/// counted as proof of life for keepalive.
#[test]
fn rejected_ack_cannot_poison_ts_recent() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1100);
    let idle = c.next_deadline();
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 2,
        flags::ACK,
        8192,
        &ts(600_000, 0),
        &[],
    ))
    .unwrap();
    let out = drain(&mut c);
    assert_eq!(out.len(), 1, "challenge ACK");
    assert_eq!(
        out[0].opts.ts.unwrap().1,
        1,
        "TSecr must not echo the forgery"
    );
    assert_eq!(
        c.next_deadline(),
        idle,
        "a dropped segment is no proof of life"
    );
    c.set_now(1110);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK | flags::PSH,
        8192,
        &ts(2, 0),
        b"genuine",
    ))
    .unwrap();
    let mut buf = [0u8; 16];
    let n = c.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"genuine", "PAWS discarded the peer's data");
}

// ---------------------------------------------------------------------------
// ACK storms / reflection
// ---------------------------------------------------------------------------

/// One spoofed data segment desynchronizes two endpoints; each then answers
/// the other's ACKs as out-of-window. Without per-connection rate limiting
/// the exchange never stops (it was ~635k packets per virtual 5 s).
#[test]
fn injected_segment_cannot_start_an_ack_storm() {
    let mut a = new_tcb(CLI, SRV, 111);
    let mut b = new_tcb(SRV, CLI, 999);
    let mut now = 1u64;
    a.set_now(now);
    b.set_now(now);
    b.set_secret(&[3u8; 16]);
    b.listen().unwrap();
    a.connect().unwrap();
    let mut buf = [0u8; MAX_PACKET];
    let mut pump = |a: &mut Tcb, b: &mut Tcb, now: u64| -> usize {
        let mut moved = 0;
        a.set_now(now);
        b.set_now(now);
        a.tick().unwrap();
        b.tick().unwrap();
        for _ in 0..64 {
            let mut any = false;
            while let Ok(n) = a.extract_packet(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = b.inject_packet(&buf[..n]);
                moved += 1;
                any = true;
            }
            while let Ok(n) = b.extract_packet(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = a.inject_packet(&buf[..n]);
                moved += 1;
                any = true;
            }
            if !any {
                break;
            }
        }
        moved
    };
    for _ in 0..200 {
        now += 1;
        pump(&mut a, &mut b, now);
    }
    assert_eq!(a.state(), State::Established);
    let sb = b.debug_snapshot();
    let o = ts(now as u32, now as u32);
    b.inject_packet(&pkt(
        CLI,
        SRV,
        sb.rcv_nxt,
        sb.snd_una,
        flags::ACK | flags::PSH,
        0xffff,
        &o,
        &[0x41; 100],
    ))
    .unwrap();
    let mut storm = 0;
    for _ in 0..5_000 {
        now += 1;
        storm += pump(&mut a, &mut b, now);
    }
    // At most one rate-limited reply per side per 500 ms.
    assert!(
        storm <= 30,
        "{storm} packets in 5 s after one injected segment"
    );
}

/// Old data is answered at once (with a D-SACK) only if it could be the
/// peer's own retransmission: an acceptable ACK, plus a timestamp when
/// negotiated. Forged 1-byte old segments used to bypass the 500 ms budget,
/// drawing one 60-byte D-SACK ACK each (1.46x byte amplification) and
/// D-SACKs that could talk the peer out of a congestion response.
#[test]
fn forged_old_data_cannot_bypass_the_reply_rate_limit() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    let data = pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        0xffff,
        &ts(5, 0),
        &[1u8; 500],
    );
    c.inject_packet(&data).unwrap();
    drain(&mut c);
    let forged = pkt(
        SRV,
        CLI,
        sseq,
        iss + 1 + 65_536,
        flags::ACK,
        0xffff,
        &TcpOptions::NONE,
        b"X",
    );
    let mut replies = Vec::new();
    for _ in 0..100 {
        c.inject_packet(&forged).unwrap();
        replies.extend(drain(&mut c));
    }
    assert_eq!(replies.len(), 1, "forged old data shares the rate limit");
    assert!(replies[0].opts.sack.is_empty(), "no D-SACK for a forgery");
    assert_eq!(c.stats().dup_bytes_received, 0);
    // The peer's genuine retransmissions are still each D-SACKed at once.
    for _ in 0..2 {
        c.inject_packet(&data).unwrap();
        let out = drain(&mut c);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].opts.sack.as_slice(), &[(sseq, sseq + 500)]);
    }
}

/// A SYN-ACK arriving at a listener draws a RST addressed to its sender (it
/// used to go to 0.0.0.0:0), and replies are rate limited so a listener
/// cannot be used to reflect RSTs at line rate.
#[test]
fn listener_rst_goes_to_sender_and_is_rate_limited() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_secret(&[3u8; 16]);
    s.set_now(0);
    s.listen().unwrap();
    let mut rsts = Vec::new();
    for k in 0..50u32 {
        s.set_now(u64::from(k));
        s.inject_packet(&pkt(
            ATTACKER,
            SRV,
            1,
            99 + k,
            flags::SYN | flags::ACK,
            65535,
            &TcpOptions::NONE,
            &[],
        ))
        .unwrap();
        rsts.extend(drain(&mut s));
    }
    assert_eq!(rsts.len(), 1, "RST replies must be rate limited");
    assert_eq!(rsts[0].dst, ATTACKER);
    assert_eq!(rsts[0].flags, flags::RST);
    assert_eq!(rsts[0].seq, 99, "RST carries SEQ = SEG.ACK (RFC 9293)");
    assert_eq!(s.state(), State::Listen);
}

/// Unacceptable 1-byte segments used to draw an un-throttled ACK of up to
/// 76 bytes (TS + D-SACK + SACK) for half of all sequence numbers, ACK bit
/// or not, with a D-SACK for whatever range they named. Now a segment with
/// none of ACK/SYN/RST gets nothing, one whose ACK field is unacceptable
/// (RFC 5961 §5.2) goes through the rate limiter, and the immediate
/// duplicate-data ACK never reports sequence space never received.
#[test]
fn unacceptable_segments_need_an_acceptable_ack_for_an_immediate_reply() {
    fn flood(c: &mut Tcb, seq: u32, ack: u32, fl: u8, opts: &TcpOptions, n: u32) -> Vec<Out> {
        let mut replies = Vec::new();
        for k in 0..n {
            c.set_now(2000 + u64::from(k));
            let _ = c.inject_packet(&pkt(
                SRV,
                CLI,
                seq.wrapping_add(k),
                ack,
                fl,
                8192,
                opts,
                b"x",
            ));
            replies.extend(drain(c));
        }
        replies
    }
    let (mut c, sseq, iss) = established(1000, true, false);
    let old = sseq.wrapping_sub(1_000_000); // below the peer's ISN
    assert!(flood(&mut c, old, 0, 0, &TcpOptions::NONE, 200).is_empty());
    let blind = (iss + 1).wrapping_add(0x4000_0000);
    assert!(flood(&mut c, old, blind, flags::ACK, &TcpOptions::NONE, 200).len() <= 1);
    // The peer's own duplicates carry the timestamp RFC 7323 §3.2 requires
    // on every segment once negotiated.
    let genuine = flood(&mut c, old, iss + 1, flags::ACK, &ts(5, 0), 3);
    assert_eq!(
        genuine.len(),
        3,
        "the peer's duplicates are answered at once"
    );
    assert!(
        genuine.iter().all(|o| o.opts.sack.as_slice().is_empty()),
        "D-SACK for never-received data: {:?}",
        genuine[0].opts.sack
    );
}

// ---------------------------------------------------------------------------
// Handshake robustness
// ---------------------------------------------------------------------------

/// RFC 9293 §3.10.7.3: an ACK that does not acknowledge our SYN draws
/// `<SEQ=SEG.ACK><CTL=RST>`, which clears a stale peer connection on a
/// reused 4-tuple (it used to be ignored, stalling connect for minutes).
#[test]
fn syn_sent_resets_stale_peer_connection() {
    let mut c = new_tcb(CLI, SRV, 7_000);
    c.set_now(1);
    c.connect().unwrap();
    drain(&mut c);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        999_999,
        338_974_330,
        flags::ACK,
        569,
        &ts(5, 9),
        &[],
    ))
    .unwrap();
    let out = drain(&mut c);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].flags, flags::RST);
    assert_eq!(out[0].seq, 338_974_330);
    assert_eq!(c.state(), State::SynSent, "still connecting");
}

/// RFC 9293 simultaneous open: both ends send SYN, both answer SYN-ACK, both
/// reach ESTABLISHED and can exchange data.
#[test]
fn simultaneous_open_completes() {
    let mut a = new_tcb(CLI, SRV, 1_000);
    let mut b = new_tcb(SRV, CLI, 9_000);
    a.set_now(1);
    b.set_now(1);
    a.connect().unwrap();
    b.connect().unwrap();
    let mut buf = [0u8; MAX_PACKET];
    let mut q: Vec<(bool, Vec<u8>)> = Vec::new();
    for (to_b, t) in [(true, &mut *a), (false, &mut *b)] {
        while let Ok(n) = t.extract_packet(&mut buf) {
            if n == 0 {
                break;
            }
            q.push((to_b, buf[..n].to_vec()));
        }
    }
    for now in 2..50u64 {
        let batch = core::mem::take(&mut q);
        for (to_b, p) in batch {
            let (dst, src) = if to_b {
                (&mut *b, &mut *a)
            } else {
                (&mut *a, &mut *b)
            };
            let _ = src;
            dst.set_now(now);
            let _ = dst.inject_packet(&p);
        }
        for (to_b, t) in [(true, &mut *a), (false, &mut *b)] {
            t.set_now(now);
            t.tick().unwrap();
            while let Ok(n) = t.extract_packet(&mut buf) {
                if n == 0 {
                    break;
                }
                q.push((to_b, buf[..n].to_vec()));
            }
        }
        if a.state() == State::Established && b.state() == State::Established && q.is_empty() {
            break;
        }
    }
    assert_eq!(a.state(), State::Established);
    assert_eq!(b.state(), State::Established);
}

/// A listener holds one half-open. A spoofed SYN (whose source never
/// completes the handshake) used to lock it for ~63 s. While the slot is
/// busy, other peers' SYNs are answered with cookies (no state); once the
/// half-open has needed a SYN-ACK retransmission, a SYN from a new peer
/// takes over the slot statefully.
#[test]
fn spoofed_syn_cannot_lock_stateful_listener() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_secret(&[3u8; 16]);
    s.set_now(0);
    s.listen().unwrap();
    let syn = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(ATTACKER, SRV, 1, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    let held = drain(&mut s)[0].seq;
    // A fresh half-open keeps its slot; a concurrent SYN gets a cookie...
    s.set_now(100);
    s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    let out = drain(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].dst, out[0].flags), (CLI, flags::SYN | flags::ACK));
    assert_ne!(
        out[0].seq, held,
        "stateless cookie, not the half-open's ISS"
    );
    assert_eq!(s.state(), State::SynRcvd);
    // ...and after the first SYN-ACK retransmission (1 s RTO) it yields.
    let mut now = 100;
    while now < 1_200 {
        now += 100;
        s.set_now(now);
        s.tick().unwrap();
        drain(&mut s);
    }
    s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    let out = drain(&mut s);
    assert_eq!(s.state(), State::SynRcvd);
    assert!(out
        .iter()
        .any(|o| o.dst == CLI && o.flags == flags::SYN | flags::ACK));
    // The slot now belongs to CLI: its third ACK completes statefully.
    let isn = out[0].seq;
    s.inject_packet(&pkt(
        CLI,
        SRV,
        78,
        isn + 1,
        flags::ACK,
        65535,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(s.state(), State::Established);
}

/// SYN cookies used to drop window scaling and SACK (64 KiB window cap, no
/// selective recovery). They are now carried in the TSval low bits.
#[test]
fn cookie_connections_keep_window_scaling_and_sack() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_now(10_000);
    s.set_cookie_secret(&[7u8; 16]);
    s.listen().unwrap();
    // Occupy the half-open slot so the client is answered with a cookie.
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(ATTACKER, SRV, 9, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    drain(&mut s);
    let o = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ts: Some((100, 0)),
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &o, &[]))
        .unwrap();
    let sa = drain(&mut s);
    let synack = &sa[0];
    assert_eq!(synack.dst, CLI);
    assert_eq!(s.state(), State::SynRcvd, "the client holds no state yet");
    assert!(
        synack.opts.wscale.is_some(),
        "WS offered in the cookie SYN-ACK"
    );
    assert!(
        synack.opts.sack_permitted,
        "SACK offered in the cookie SYN-ACK"
    );
    let tsval = synack.opts.ts.unwrap().0;
    s.inject_packet(&pkt(
        CLI,
        SRV,
        501,
        synack.seq + 1,
        flags::ACK,
        65535,
        &ts(101, tsval),
        &[],
    ))
    .unwrap();
    assert_eq!(s.state(), State::Established);
    // Out-of-order data draws a SACK block, and our window is scaled.
    s.inject_packet(&pkt(
        CLI,
        SRV,
        501 + 1000,
        synack.seq + 1,
        flags::ACK,
        65535,
        &ts(102, tsval),
        b"x",
    ))
    .unwrap();
    let ack = drain(&mut s);
    assert!(
        !ack[0].opts.sack.is_empty(),
        "SACK active on a cookie connection"
    );
    let shift = synack.opts.wscale.unwrap();
    let adv = u32::from(ack[0].win) << shift;
    if crate::BUF_CAP > 65_535 {
        assert!(
            adv > 65_535,
            "advertised window is scaled beyond 64 KiB ({adv})"
        );
    }
}

/// Without a secret the timestamp offset is 0 (documented); with a host
/// secret TSval no longer reveals the host clock and differs per 4-tuple.
#[test]
fn host_secret_hides_clock_in_tsval() {
    let clock = 431_337_123u64;
    let mut a = new_tcb(CLI, SRV, 1);
    a.set_secret(&[9u8; 16]);
    a.set_now(clock);
    a.connect().unwrap();
    let t1 = drain(&mut a)[0].opts.ts.unwrap().0;
    let mut b = new_tcb((CLI.0, CLI.1 + 1), SRV, 1);
    b.set_secret(&[9u8; 16]);
    b.set_now(clock);
    b.connect().unwrap();
    let t2 = drain(&mut b)[0].opts.ts.unwrap().0;
    assert_ne!(u64::from(t1), clock & 0xffff_ffff);
    assert_ne!(t1, t2, "offset differs per connection");
}

// ---------------------------------------------------------------------------
// Resource pinning
// ---------------------------------------------------------------------------

/// A peer that ACKs our FIN but never sends its own used to pin the TCB in
/// FIN_WAIT_2 forever. It is now reset after the FIN_WAIT_2 timeout.
#[test]
fn fin_wait_2_is_bounded() {
    let (mut c, sseq, _) = established(1000, true, false);
    c.send(b"bye").unwrap();
    c.set_now(1020);
    c.close().unwrap();
    let out = drain(&mut c);
    let fin = out
        .iter()
        .find(|o| o.flags & flags::FIN != 0)
        .expect("FIN piggybacked");
    let end = fin.seq + fin.len as u32 + 1;
    c.set_now(1030);
    c.inject_packet(&pkt(SRV, CLI, sseq, end, flags::ACK, 8192, &ts(2, 0), &[]))
        .unwrap();
    assert_eq!(c.state(), State::FinWait2);
    let mut now = 1030u64;
    while now < 1030 + 61_000 {
        now += 1000;
        c.set_now(now);
        c.tick().unwrap();
        if c.state() == State::Closed {
            break;
        }
    }
    assert_eq!(c.state(), State::Closed);
    let rst = drain(&mut c);
    assert!(
        rst.iter().any(|o| o.flags & flags::RST != 0),
        "peer is told via RST"
    );
}

/// FIN_WAIT_2 is restarted while the application keeps reading the peer's
/// half (it still wants the data).
#[test]
fn fin_wait_2_survives_while_the_application_reads() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1010);
    c.close().unwrap();
    drain(&mut c);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 2,
        flags::ACK,
        8192,
        &ts(2, 0),
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::FinWait2);
    let mut seq = sseq;
    let mut buf = [0u8; 64];
    for k in 1..=5u64 {
        c.set_now(1010 + k * 50_000);
        c.tick().unwrap();
        c.inject_packet(&pkt(
            SRV,
            CLI,
            seq,
            iss + 2,
            flags::ACK | flags::PSH,
            8192,
            &ts(2 + k as u32, 0),
            b"more",
        ))
        .unwrap();
        seq += 4;
        drain(&mut c);
        assert_eq!(c.recv(&mut buf).unwrap(), 4);
        assert_eq!(
            c.state(),
            State::FinWait2,
            "half-closed peer still sending at +{k}x50s"
        );
    }
}

/// After the host closed, a peer trickling bytes nobody reads used to hold
/// FIN_WAIT_2 (and its ≈2 MiB TCB) indefinitely: each byte restarted the
/// timeout. Only the application reading restarts it now.
#[test]
fn fin_wait_2_trickle_cannot_pin_a_closed_connection() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    c.close().unwrap();
    drain(&mut c);
    c.set_now(1030);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 2,
        flags::ACK,
        8192,
        &ts(5, 0),
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::FinWait2);
    let mut now = 1030u64;
    for k in 0..100u32 {
        now += 10_000;
        c.set_now(now);
        c.tick().unwrap();
        if c.state() != State::FinWait2 {
            break;
        }
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq + k,
            iss + 2,
            flags::ACK,
            8192,
            &ts(10 + k, 0),
            b"x",
        ))
        .unwrap();
        drain(&mut c);
    }
    assert_eq!(c.state(), State::Closed, "trickle kept FIN_WAIT_2 alive");
    assert!(now <= 1030 + 70_000, "reset only after {} ms", now - 1030);
}

/// A "slow reader" that keeps the window tiny and acknowledges a few bytes
/// now and then (plus duplicate ACKs as proof of life) used to pin a TCB and
/// its 1 MiB send buffer indefinitely. Sub-MSS progress no longer re-arms
/// the USER TIMEOUT.
#[test]
fn slow_reader_is_aborted_by_user_timeout() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let mut now = 1020u64;
    c.set_now(now);
    c.send(&vec![0x99u8; 1 << 20]).unwrap();
    c.inject_packet(&pkt(SRV, CLI, sseq, iss + 1, flags::ACK, 1, &ts(3, 0), &[]))
        .unwrap(); // 1 << 7 = 128-byte window
    let mut peer_rcv = iss + 1;
    let mut last_ack = now;
    for step in 0..3600u64 {
        now += 1000;
        c.set_now(now);
        if c.state() != State::Established {
            break;
        }
        c.tick().unwrap();
        for o in drain(&mut c) {
            if o.len > 0 && o.seq == peer_rcv {
                peer_rcv += o.len as u32;
            }
        }
        if now - last_ack >= 290_000 {
            last_ack = now;
            let _ = c.inject_packet(&pkt(
                SRV,
                CLI,
                sseq,
                peer_rcv,
                flags::ACK,
                1,
                &ts(4, 0),
                &[],
            ));
        } else if step % 20 == 0 {
            let una = c.debug_snapshot().snd_una;
            let _ = c.inject_packet(&pkt(SRV, CLI, sseq, una, flags::ACK, 1, &ts(4, 0), &[]));
        }
        drain(&mut c);
    }
    assert_eq!(c.state(), State::Closed, "slow reader still pins the TCB");
    assert!(
        now - 1020 <= 700_000,
        "aborted only after {} s",
        (now - 1020) / 1000
    );
    let mut b = [0u8; 1];
    assert_eq!(c.recv(&mut b), Err(TcpError::ConnectionReset));
}

/// A peer that keeps answering zero-window probes but never opens its
/// window is aborted by the USER TIMEOUT.
#[test]
fn zero_window_stall_is_aborted_by_user_timeout() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let mut now = 1020u64;
    c.set_now(now);
    c.inject_packet(&pkt(SRV, CLI, sseq, iss + 1, flags::ACK, 0, &ts(3, 0), &[]))
        .unwrap();
    c.send(&vec![1u8; 10_000]).unwrap();
    let mut probes = 0;
    while now < 1020 + 400_000 && c.state() == State::Established {
        now += 500;
        c.set_now(now);
        c.tick().unwrap();
        for o in drain(&mut c) {
            assert_eq!(o.len, 0, "no data into a zero window");
            probes += 1;
            c.inject_packet(&pkt(SRV, CLI, sseq, iss + 1, flags::ACK, 0, &ts(4, 0), &[]))
                .unwrap();
        }
    }
    assert!(probes > 3, "zero-window probes were sent and answered");
    assert_eq!(c.state(), State::Closed);
    assert!(now <= 1020 + 310_000);
}

// ---------------------------------------------------------------------------
// Loss recovery correctness
// ---------------------------------------------------------------------------

/// Data the peer has SACKed must never be retransmitted, and an ECN echo
/// (no loss) must never cause a retransmission.
#[test]
fn sacked_data_is_never_retransmitted() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let mut now = 1020u64;
    c.set_now(now);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        0xffff,
        &ts(3, 0),
        &[],
    ))
    .unwrap();
    let segs = send_burst(&mut c, now, 10 * 1448);
    assert!(segs.len() >= 8);
    let mut sacked: Vec<(u32, u32)> = Vec::new();
    let mut retx = Vec::new();
    // Segment 0 is lost; each later arrival adds a SACK block.
    for k in 1..segs.len() {
        now += 1;
        c.set_now(now);
        sacked = vec![(segs[1].0, segs[k].1)];
        let o = TcpOptions {
            ts: Some((4, 0)),
            sack: SackBlocks::from_slice(&sacked),
            ..TcpOptions::NONE
        };
        c.inject_packet(&pkt(SRV, CLI, sseq, iss + 1, flags::ACK, 0xffff, &o, &[]))
            .unwrap();
        retx.extend(drain(&mut c).into_iter().filter(|o| o.len > 0));
    }
    // Run the timers for a while (including RTOs of the unacknowledged
    // retransmission): only the hole may ever be resent.
    for _ in 0..500 {
        now += 2;
        c.set_now(now);
        c.tick().unwrap();
        retx.extend(drain(&mut c).into_iter().filter(|o| o.len > 0));
    }
    let (sl, sr) = sacked[0];
    for r in &retx {
        let end = r.seq + r.len as u32;
        assert!(
            !(r.seq >= sl && end <= sr),
            "retransmitted SACKed data {:?}",
            (r.seq, end)
        );
        assert_eq!((r.seq, end), segs[0], "only the hole is ever retransmitted");
    }
    assert!(!retx.is_empty(), "the hole was retransmitted");
    assert_eq!(c.stats().segs_retrans as usize, retx.len());
}

#[test]
fn ecn_echo_reduces_window_without_retransmitting() {
    let (mut c, sseq, _) = established(1000, true, true);
    let sent = send_burst(&mut c, 1020, 10 * 1448);
    let highest = sent.last().unwrap().1;
    let cwnd_before = c.debug_snapshot().cwnd;
    c.set_now(1030);
    let o = ts(5, 0);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        sent[0].1,
        flags::ACK | flags::ECE,
        0xffff,
        &o,
        &[],
    ))
    .unwrap();
    let mut out = drain(&mut c);
    c.send(&vec![0u8; 2000]).unwrap();
    c.tick().unwrap();
    out.extend(drain(&mut c));
    assert!(
        out.iter().all(|p| p.len == 0 || p.seq >= highest),
        "ECE caused a retransmission"
    );
    assert_eq!(c.stats().segs_retrans, 0);
    assert!(c.debug_snapshot().ssthresh < cwnd_before, "window reduced");
    // RFC 3168 §6.1.2: the first new data segment afterwards carries CWR.
    let first_new = out.iter().find(|p| p.len > 0).expect("new data was sent");
    assert!(
        first_new.flags & flags::CWR != 0,
        "CWR on the first new segment"
    );
}

/// After an RTO the stack must keep using SND.NXT = the highest sequence
/// sent for pure ACKs and RSTs (it used to rewind SND.NXT, so its ACKs and
/// abort RST looked old/out-of-window to a peer that had the data).
#[test]
fn rto_does_not_rewind_sequence_numbers() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let segs = send_burst(&mut c, 1020, 8 * 1448);
    let snd_max = segs.last().unwrap().1;
    c.set_now(1020 + 5000);
    c.tick().unwrap(); // TLP
    c.set_now(1020 + 10_000);
    c.tick().unwrap(); // RTO
    drain(&mut c);
    assert!(c.stats().rto_count >= 1);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK | flags::PSH,
        0xffff,
        &ts(9, 0),
        b"x",
    ))
    .unwrap();
    let acks: Vec<u32> = drain(&mut c)
        .iter()
        .filter(|o| o.len == 0)
        .map(|o| o.seq)
        .collect();
    assert!(
        acks.iter().all(|&s| s == snd_max),
        "pure ACK seq {acks:?} != SND.MAX {snd_max}"
    );
    c.abort().unwrap();
    let rst = drain(&mut c);
    assert_eq!(
        rst[0].seq, snd_max,
        "abort RST must use the highest sequence sent"
    );
}

/// The receiver parks the whole window of out-of-order data across a single
/// hole (it used to keep only 16 KiB and force the sender to resend the rest).
#[test]
fn receiver_holds_full_window_across_a_hole() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    let seg = vec![0x66u8; 1448];
    let n_ooo = 600u32; // ~850 KiB after one lost segment
    for k in 1..=n_ooo {
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq + k * 1448,
            iss + 1,
            flags::ACK,
            0xffff,
            &ts(5, 0),
            &seg,
        ))
        .unwrap();
        drain(&mut c);
    }
    assert_eq!(c.debug_snapshot().oo_len, n_ooo * 1448);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        0xffff,
        &ts(6, 0),
        &seg,
    ))
    .unwrap();
    let ack = drain(&mut c);
    assert_eq!(
        ack[0].ack,
        sseq + (n_ooo + 1) * 1448,
        "everything delivered at once"
    );
    let mut buf = vec![0u8; 1 << 20];
    assert_eq!(c.recv(&mut buf).unwrap(), ((n_ooo + 1) * 1448) as usize);
}

/// Duplicate data draws an immediate ACK carrying a D-SACK block (RFC 2883),
/// which lets the sender detect its spurious retransmission.
#[test]
fn duplicate_data_is_reported_with_dsack() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    let p = pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        0xffff,
        &ts(5, 0),
        &[1u8; 500],
    );
    c.inject_packet(&p).unwrap();
    drain(&mut c);
    c.inject_packet(&p).unwrap();
    let out = drain(&mut c);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].opts.sack.as_slice()[0], (sseq, sseq + 500));
}

/// A D-SACK is believed only for data we retransmitted (Linux
/// `tcp_dsack_seen`): a forged or network-duplicated one used to widen
/// RACK's reordering window (slowing loss detection) on every ACK.
#[test]
fn dsack_is_believed_only_for_retransmitted_data() {
    fn ack_with_dsack(c: &mut Tcb, sseq: u32, now: u64, ack: u32, blk: (u32, u32)) {
        c.set_now(now);
        let o = TcpOptions {
            ts: Some((4, 0)),
            sack: SackBlocks::from_slice(&[blk]),
            ..TcpOptions::NONE
        };
        c.inject_packet(&pkt(SRV, CLI, sseq, ack, flags::ACK, 0xffff, &o, &[]))
            .unwrap();
        drain(c);
    }
    let (mut c, sseq, _) = established(1000, true, false);
    let segs = send_burst(&mut c, 1020, 2 * 1448);
    ack_with_dsack(&mut c, sseq, 1030, segs[0].1, segs[0]);
    assert_eq!(c.stats().dsacks_received, 0, "nothing was retransmitted");
    // Once the tail really is retransmitted (TLP / RTO), its D-SACK counts.
    let mut now = 1030;
    let mut retx = None;
    while retx.is_none() && now < 10_000 {
        now += 5;
        c.set_now(now);
        c.tick().unwrap();
        retx = drain(&mut c)
            .into_iter()
            .find(|o| o.len > 0)
            .map(|o| (o.seq, o.seq + o.len as u32));
    }
    ack_with_dsack(&mut c, sseq, now + 10, segs[1].1, retx.unwrap());
    assert_eq!(c.stats().dsacks_received, 1);
}

/// RTT comes from our own send times whenever the ACK covers no
/// retransmission: TSecr is the peer's to forge (or a middlebox's to
/// mangle). Echoing "now" used to force SRTT and min_rtt to 1 ms, and a
/// 59 s old echo pushed the RTO to 60 s. After a retransmission TSecr
/// decides, but not if it is later than any transmission it could echo.
#[test]
fn forged_tsecr_cannot_skew_rtt() {
    fn send_and_ack(c: &mut Tcb, sseq: u32, sent: u64, acked: u64, tsecr: u32) {
        c.set_now(sent);
        c.send(&[7u8; 1000]).unwrap();
        c.tick().unwrap();
        drain(c);
        c.set_now(acked);
        let nxt = c.debug_snapshot().snd_nxt;
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            nxt,
            flags::ACK,
            8192,
            &ts(9, tsecr),
            &[],
        ))
        .unwrap();
        drain(c);
    }
    let iss = 1_000_000;
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(1000);
    c.connect().unwrap();
    drain(&mut c);
    c.set_now(1010);
    let o = TcpOptions {
        mss: Some(1460),
        ts: Some((1, 1010)), // claims our SYN left just now
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    let synack = pkt(
        SRV,
        CLI,
        SRV_ISS,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &o,
        &[],
    );
    c.inject_packet(&synack).unwrap();
    drain(&mut c);
    assert_eq!(
        c.stats().srtt_ms,
        10,
        "handshake RTT from the SYN's send time"
    );

    let sseq = SRV_ISS + 1;
    send_and_ack(&mut c, sseq, 1100, 1180, 1180); // 80 ms; TSecr claims 0
    let s = c.stats();
    assert_eq!((s.min_rtt_ms, s.srtt_ms), (10, (7 * 10 + 80) / 8));
    send_and_ack(&mut c, sseq, 2000, 2050, 2050u32.wrapping_sub(59_000));
    assert!(c.stats().rto_ms < 1_000, "RTO {} ms", c.stats().rto_ms);

    c.set_now(3000);
    c.send(&[7u8; 1000]).unwrap();
    c.tick().unwrap();
    drain(&mut c);
    let mut now = 3000;
    while !drain(&mut c).iter().any(|o| o.len > 0) {
        assert!(now < 10_000, "no retransmission");
        now += 5;
        c.set_now(now);
        c.tick().unwrap();
    }
    let before = c.stats();
    c.set_now(now + 30);
    let nxt = c.debug_snapshot().snd_nxt;
    let o = ts(10, (now + 30) as u32);
    c.inject_packet(&pkt(SRV, CLI, sseq, nxt, flags::ACK, 8192, &o, &[]))
        .unwrap();
    let after = c.stats();
    assert_eq!(
        (after.srtt_ms, after.min_rtt_ms),
        (before.srtt_ms, before.min_rtt_ms),
        "a TSecr later than the retransmission was believed"
    );
}

// ---------------------------------------------------------------------------
// MTU
// ---------------------------------------------------------------------------

#[test]
fn set_mtu_limits_mss_and_datagram_size() {
    let mut c = new_tcb(CLI, SRV, 1);
    c.set_mtu(1420).unwrap();
    c.set_now(0);
    c.connect().unwrap();
    let syn = drain(&mut c);
    assert_eq!(syn[0].opts.mss, Some(1380));
    let o = TcpOptions {
        mss: Some(1460),
        ts: Some((1, 0)),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    c.inject_packet(&pkt(
        SRV,
        CLI,
        SRV_ISS,
        2,
        flags::SYN | flags::ACK,
        65535,
        &o,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    c.send(&vec![0u8; 100_000]).unwrap();
    c.tick().unwrap();
    let out = drain(&mut c);
    assert!(
        out.iter().all(|p| p.total_len <= 1420),
        "datagram exceeds the MTU"
    );
    assert!(out.iter().any(|p| p.total_len == 1420));
    assert_eq!(
        c.set_mtu(1500),
        Err(TcpError::InvalidState),
        "MTU fixed after the open"
    );
}

#[test]
fn reported_pmtu_resegments_in_flight_data() {
    let (mut c, _, _) = established(1000, true, false);
    let segs = send_burst(&mut c, 1020, 4 * 1448);
    assert!(segs.iter().all(|s| s.1 - s.0 == 1448));
    c.set_now(1030);
    c.update_pmtu(1280);
    let out = drain(&mut c);
    assert!(
        !out.is_empty(),
        "in-flight segments are resent at the new size"
    );
    assert!(out.iter().all(|p| p.total_len <= 1280));
    assert_eq!(out[0].seq, segs[0].0);
}

#[test]
fn repeated_timeouts_of_large_segments_clamp_the_mss() {
    let (mut c, _, _) = established(1000, true, false);
    send_burst(&mut c, 1020, 1448);
    let mut now = 1020u64;
    let mut sizes = Vec::new();
    for _ in 0..6 {
        now += 61_000;
        c.set_now(now);
        c.tick().unwrap();
        sizes.extend(drain(&mut c).iter().filter(|o| o.len > 0).map(|o| o.len));
    }
    assert!(
        sizes.iter().any(|&l| l <= 1024),
        "MSS never clamped: {sizes:?}"
    );
}

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------

/// `tcp_init` builds the ~2 MiB handle in place: it must work on a thread
/// whose whole stack is far smaller than the handle (it used to need a
/// 2.08 MiB stack frame and crashed on 1–2 MiB thread stacks).
#[test]
fn tcp_init_runs_on_a_small_thread_stack() {
    let r = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            use crate::ffi::*;
            let size = tcp_handle_size();
            let align = tcp_handle_align();
            let layout = std::alloc::Layout::from_size_align(size, align).unwrap();
            // SAFETY: test-only allocation of the documented size/alignment.
            let mem = unsafe { std::alloc::alloc(layout) } as *mut TcpStreamHandle;
            assert!(!mem.is_null());
            let ip = [10u8, 0, 0, 1];
            // SAFETY: `mem` is a fresh, aligned block of `size` bytes.
            let rc = unsafe { tcp_init(mem, ip.as_ptr(), 1, ip.as_ptr(), 2, 7, 1000) };
            assert_eq!(rc, 0);
            // SAFETY: live handle; NULL with zero length is permitted.
            unsafe {
                assert_eq!(tcp_connect(mem, 0), 0);
                assert_eq!(tcp_next_deadline(mem), 1000, "SYN retransmission timer");
                assert_eq!(tcp_next_deadline(core::ptr::null()), u64::MAX);
                let mut n = 99usize;
                assert_eq!(
                    tcp_send(mem, core::ptr::null(), 0, &mut n),
                    TcpError::InvalidState.as_code()
                );
                assert_eq!(
                    tcp_inject_packet(mem, core::ptr::null(), 0, 0),
                    TcpError::MalformedPacket.as_code()
                );
                assert_eq!(
                    tcp_extract_packet(mem, core::ptr::null_mut(), 0, &mut n),
                    TcpError::BufferTooSmall.as_code()
                );
                assert_eq!(
                    tcp_inject_packet(mem, core::ptr::null(), 5, 0),
                    TcpError::NullPointer.as_code()
                );
                assert_eq!(tcp_destroy(mem), 0);
                std::alloc::dealloc(mem as *mut u8, layout);
            }
        })
        .unwrap()
        .join();
    assert!(r.is_ok());
}

/// Misaligned storage is rejected instead of being written through.
#[test]
fn tcp_init_rejects_misaligned_storage() {
    use crate::ffi::*;
    let size = tcp_handle_size();
    let layout = std::alloc::Layout::from_size_align(size + 64, 64).unwrap();
    // SAFETY: test-only allocation.
    let base = unsafe { std::alloc::alloc(layout) };
    let ip = [10u8, 0, 0, 1];
    // SAFETY: deliberately misaligned pointer inside a valid block.
    let rc = unsafe {
        tcp_init(
            base.add(1) as *mut TcpStreamHandle,
            ip.as_ptr(),
            1,
            ip.as_ptr(),
            2,
            7,
            1000,
        )
    };
    assert_eq!(rc, TcpError::InvalidState.as_code());
    // SAFETY: matching dealloc.
    unsafe { std::alloc::dealloc(base, layout) };
}

// ---------------------------------------------------------------------------
// Second review: protocol and hardening findings
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn pkt_ecn(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack: u32,
    fl: u8,
    win: u16,
    opts: &TcpOptions,
    payload: &[u8],
    ecn: u8,
) -> Vec<u8> {
    let mut b = vec![0u8; 20 + 60 + payload.len()];
    let n = wire::emit(
        &mut b, src.0, dst.0, src.1, dst.1, seq, ack, fl, win, opts, payload, 7, ecn,
    )
    .unwrap();
    b.truncate(n);
    b
}

fn recv_all(c: &mut Tcb) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    while let Ok(n) = c.recv(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

/// A blind segment with a guessable in-window SEQ but a bogus ACK fails the
/// RFC 5961 §5 check — and must leave no trace. Its far-future TSval used
/// to be copied into TS.Recent first, after which PAWS discarded every
/// genuine data segment (the receive direction was dead for ~24 days).
#[test]
fn segment_failing_the_ack_check_cannot_poison_ts_recent() {
    for pure_ack in [false, true] {
        let (mut c, sseq, iss) = established(1000, true, false);
        c.set_now(1020);
        let poison = ts(0x7000_0000, 0);
        let bogus_ack = (iss + 1).wrapping_add(0x8000_0000);
        let forged = if pure_ack {
            pkt(SRV, CLI, sseq, bogus_ack, flags::ACK, 8192, &poison, &[])
        } else {
            pkt(
                SRV,
                CLI,
                sseq.wrapping_sub(1000),
                bogus_ack,
                flags::ACK,
                8192,
                &poison,
                &[0x41; 1400],
            )
        };
        c.inject_packet(&forged).unwrap();
        drain(&mut c);
        assert!(recv_all(&mut c).is_empty(), "forged data delivered");
        c.set_now(1040);
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            iss + 1,
            flags::ACK | flags::PSH,
            8192,
            &ts(50, 0),
            b"data",
        ))
        .unwrap();
        assert_eq!(
            recv_all(&mut c),
            b"data",
            "genuine data PAWS-rejected (pure ACK variant: {pure_ack})"
        );
        c.set_now(1100);
        c.tick().unwrap(); // delayed ACK
        let out = drain(&mut c);
        assert_eq!(
            out.last().unwrap().opts.ts.unwrap().1,
            50,
            "TSecr not poisoned"
        );
    }
}

/// RFC 3168 §6.1.3: CWR stops the echo of *earlier* CE marks, but a CE
/// mark on the CWR-carrying packet itself is new congestion and must be
/// echoed (it used to be cleared by the CWR in the same segment).
#[test]
fn ce_on_a_cwr_segment_is_echoed() {
    let (mut c, sseq, iss) = established(1000, true, true);
    c.set_now(1020);
    c.inject_packet(&pkt_ecn(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK | flags::PSH | flags::CWR,
        8192,
        &ts(5, 0),
        &[1u8; 100],
        wire::ecn::CE,
    ))
    .unwrap();
    c.set_now(1100);
    c.tick().unwrap();
    let out = drain(&mut c);
    let ack = out
        .iter()
        .rev()
        .find(|o| o.flags & flags::ACK != 0)
        .unwrap();
    assert_ne!(ack.flags & flags::ECE, 0, "CE signal lost");
    // A later CWR without CE does end the echo.
    c.inject_packet(&pkt_ecn(
        SRV,
        CLI,
        sseq + 100,
        iss + 1,
        flags::ACK | flags::PSH | flags::CWR,
        8192,
        &ts(6, 0),
        &[1u8; 100],
        wire::ecn::ECT_0,
    ))
    .unwrap();
    c.set_now(1200);
    c.tick().unwrap();
    let out = drain(&mut c);
    let ack = out
        .iter()
        .rev()
        .find(|o| o.flags & flags::ACK != 0)
        .unwrap();
    assert_eq!(ack.flags & flags::ECE, 0);
}

/// After the peer's FIN, nothing it sends can occupy sequence space: a
/// second FIN at RCV.NXT used to advance RCV.NXT, so we acknowledged a
/// sequence number the peer never sent.
#[test]
fn fin_after_the_peers_fin_does_not_advance_rcv_nxt() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK | flags::FIN,
        8192,
        &ts(5, 0),
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::CloseWait);
    drain(&mut c);
    // A bare FIN at RCV.NXT, then one carrying data.
    for (k, payload) in [&b""[..], b"late"].into_iter().enumerate() {
        c.set_now(1030 + k as u64);
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq + 1,
            iss + 1,
            flags::ACK | flags::FIN,
            8192,
            &ts(6 + k as u32, 0),
            payload,
        ))
        .unwrap();
        let out = drain(&mut c);
        assert!(out.iter().all(|o| o.ack == sseq + 1), "{out:?}");
        assert_eq!(c.debug_snapshot().rcv_nxt, sseq + 1);
        assert_eq!(c.state(), State::CloseWait);
        c.debug_validate_invariants().unwrap();
    }
}

/// RFC 9293 §3.10.7.4: with a zero receive window, valid ACKs must still be
/// accepted. The ACK carried by a peer's one-byte window probe at RCV.NXT
/// used to be ignored along with the probe's data.
#[test]
fn zero_window_probe_acknowledgment_is_processed() {
    let (mut c, sseq, iss) = established(1000, true, false);
    // Our window-scale shift: the smallest that fits the ring in 16 bits.
    let shift = (0..15).find(|&s| (crate::BUF_CAP >> s) <= 0xffff).unwrap();
    let chunk = [7u8; 1448];
    let (mut seq, mut t, mut tsv) = (sseq, 1020u64, 10u32);
    // The peer fills our receive buffer; the application never reads.
    loop {
        t += 1;
        tsv += 1;
        c.set_now(t);
        c.inject_packet(&pkt(
            SRV,
            CLI,
            seq,
            iss + 1,
            flags::ACK,
            65535,
            &ts(tsv, 0),
            &chunk,
        ))
        .unwrap();
        for o in drain(&mut c) {
            // Window scaling may round the advertised edge up by less than
            // one unit, never further: it used to creep ~16 bytes per ACK at
            // 1 MiB (shift 5), so a full buffer never advertised zero.
            let edge = o.ack + (u32::from(o.win) << shift);
            assert!(
                edge < sseq + crate::BUF_CAP as u32 + (1 << shift),
                "edge {edge} past the buffer"
            );
        }
        let after = c.debug_snapshot().rcv_nxt;
        if after == seq {
            break;
        }
        seq = after;
    }
    assert_eq!(c.debug_snapshot().recv_ring_len as usize, crate::BUF_CAP);
    c.send(&[1u8; 1000]).unwrap();
    c.tick().unwrap();
    let d = drain(&mut c);
    assert!(d.iter().any(|o| o.len == 1000 && o.win == 0));
    t += 5;
    tsv += 1;
    c.set_now(t);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        seq,
        iss + 1 + 1000,
        flags::ACK,
        65535,
        &ts(tsv, 0),
        b"p",
    ))
    .unwrap();
    let out = drain(&mut c);
    assert_eq!(
        c.debug_snapshot().snd_una,
        iss + 1 + 1000,
        "probe's ACK ignored"
    );
    assert_eq!(out.len(), 1, "the probe is answered");
    assert_eq!(
        (out[0].ack, out[0].win),
        (seq, 0),
        "probe data not accepted"
    );
}

/// Found by fuzzing: a FIN accepted at P while out-of-order data was parked
/// at P+1 left a range starting at RCV.NXT (breaking the stack's own
/// invariant), and the stack then SACKed data beyond the peer's FIN.
#[test]
fn fin_before_parked_out_of_order_data_purges_it() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 11,
        iss + 1,
        flags::ACK,
        8192,
        &ts(5, 0),
        &[1u8; 100],
    ))
    .unwrap();
    drain(&mut c);
    c.set_now(1021);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK | flags::FIN,
        8192,
        &ts(6, 0),
        &[2u8; 10],
    ))
    .unwrap();
    let out = drain(&mut c);
    c.debug_validate_invariants().unwrap();
    assert_eq!(c.state(), State::CloseWait);
    let last = out.last().unwrap();
    assert_eq!(last.ack, sseq + 11);
    assert!(last.opts.sack.is_empty(), "SACKed data beyond the FIN");
    assert_eq!(recv_all(&mut c), [2u8; 10]);
}

/// Out-of-order data beyond a FIN that is itself still out of order cannot
/// belong to the stream either: it is never stored, so filling the hole
/// delivers exactly the data before the FIN, then the FIN.
#[test]
fn data_beyond_an_out_of_order_fin_is_never_delivered() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    // FIN at sseq+20 (after 10 bytes at sseq+10), then junk beyond it:
    // one segment straddling the FIN (matching bytes before it), one past it.
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 10,
        iss + 1,
        flags::ACK | flags::FIN,
        8192,
        &ts(5, 0),
        &[2u8; 10],
    ))
    .unwrap();
    let mut straddle = vec![2u8; 2];
    straddle.extend_from_slice(&[9u8; 98]);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 18,
        iss + 1,
        flags::ACK,
        8192,
        &ts(5, 0),
        &straddle,
    ))
    .unwrap();
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 30,
        iss + 1,
        flags::ACK,
        8192,
        &ts(5, 0),
        &[9u8; 50],
    ))
    .unwrap();
    drain(&mut c);
    c.debug_validate_invariants().unwrap();
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        8192,
        &ts(6, 0),
        &[1u8; 10],
    ))
    .unwrap();
    let out = drain(&mut c);
    c.debug_validate_invariants().unwrap();
    assert_eq!(c.state(), State::CloseWait);
    assert_eq!(out.last().unwrap().ack, sseq + 21);
    let mut want = vec![1u8; 10];
    want.extend_from_slice(&[2u8; 10]);
    assert_eq!(recv_all(&mut c), want);
}

/// A peer re-sending its FIN every 59 s used to keep a TIME_WAIT TCB (and
/// its storage) alive indefinitely. Restarts are capped at 120 s after
/// entering TIME_WAIT.
#[test]
fn time_wait_cannot_be_pinned_by_fin_retransmissions() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    c.close().unwrap();
    drain(&mut c);
    c.set_now(1030);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 2,
        flags::ACK | flags::FIN,
        8192,
        &ts(5, 0),
        &[],
    ))
    .unwrap();
    drain(&mut c);
    assert_eq!(c.state(), State::TimeWait);
    let mut now = 1030u64;
    let mut reacks = 0;
    for k in 0..10u32 {
        now += 59_000;
        c.set_now(now);
        c.tick().unwrap();
        if c.state() != State::TimeWait {
            break;
        }
        let _ = c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            iss + 2,
            flags::ACK | flags::FIN,
            8192,
            &ts(6 + k, 0),
            &[],
        ));
        reacks += drain(&mut c).len();
    }
    assert_eq!(c.state(), State::Closed);
    assert!(reacks >= 1, "retransmitted FINs are still re-ACKed");
    assert!(now - 1030 <= 2 * 60_000 + 59_000, "held {} ms", now - 1030);
}

/// Without a secret, every connection a reused listener accepted got the
/// same ISN and a TSval equal to the host clock; `listen()` now requires a
/// secret, which keys both.
#[test]
fn listener_isns_and_timestamps_are_keyed() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 0xDEAD_BEEF);
    assert_eq!(s.listen(), Err(TcpError::InvalidState));
    s.set_secret(&[0x33; 16]);
    let o = TcpOptions {
        mss: Some(1460),
        ts: Some((1, 0)),
        ..TcpOptions::NONE
    };
    let mut isns = Vec::new();
    for (i, cli) in [([1, 1, 1, 1], 1111u16), ([2, 2, 2, 2], 2222u16)]
        .into_iter()
        .enumerate()
    {
        let now = 5_000_000 + i as u64 * 777;
        s.set_now(now);
        s.listen().unwrap();
        s.inject_packet(&pkt(cli, SRV, 42, 0, flags::SYN, 65535, &o, &[]))
            .unwrap();
        let sa = drain(&mut s).remove(0);
        assert_ne!(
            u64::from(sa.opts.ts.unwrap().0),
            now,
            "TSval is the host clock"
        );
        assert_ne!(sa.seq, 0xDEAD_BEEF);
        isns.push(sa.seq);
        s.abort().unwrap();
        drain(&mut s);
    }
    assert_ne!(isns[0], isns[1], "same ISN for two clients");
}

/// A client without timestamps (Windows' default) used to lose window
/// scaling and SACK on any cookie listener. The free half-open slot is now
/// used statefully, which keeps every option.
#[test]
fn idle_cookie_listener_keeps_ws_and_sack_without_timestamps() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 1);
    s.set_secret(&[1; 16]);
    s.set_cookie_secret(&[2; 16]);
    s.set_now(10_000);
    s.listen().unwrap();
    let o = TcpOptions {
        mss: Some(1460),
        wscale: Some(8),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(CLI, SRV, 5000, 0, flags::SYN, 65535, &o, &[]))
        .unwrap();
    let synack = drain(&mut s).remove(0);
    assert!(synack.opts.wscale.is_some() && synack.opts.sack_permitted);
    assert_eq!(s.state(), State::SynRcvd);
}

/// 200 spoofed SYNs per second used to lock a listener out: every time the
/// half-open became replaceable, the attacker's next SYN took it. A busy
/// listener now answers the legitimate client with a cookie, whose valid
/// ACK takes over the slot.
#[test]
fn spoofed_syn_flood_cannot_lock_out_a_listener() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 1);
    s.set_secret(&[3; 16]);
    s.set_now(0);
    s.listen().unwrap();
    let legit: ([u8; 4], u16) = ([192, 168, 1, 1], 5555);
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    let mut legit_synack = None;
    for t in 0..=3_000u64 {
        s.set_now(t);
        s.tick().unwrap();
        if t % 5 == 0 {
            let src = (
                [100, (t >> 16) as u8, (t >> 8) as u8, t as u8],
                1024 + t as u16,
            );
            let _ = s.inject_packet(&pkt(src, SRV, t as u32, 0, flags::SYN, 65535, &mss, &[]));
        }
        if t == 1003 {
            s.inject_packet(&pkt(legit, SRV, 777, 0, flags::SYN, 65535, &mss, &[]))
                .unwrap();
        }
        for o in drain(&mut s) {
            if o.dst == legit && o.flags == flags::SYN | flags::ACK {
                legit_synack = Some(o.seq);
            }
        }
        if t == 1050 {
            let isn = legit_synack.expect("the legitimate client was answered");
            s.inject_packet(&pkt(
                legit,
                SRV,
                778,
                isn + 1,
                flags::ACK,
                65535,
                &TcpOptions::NONE,
                b"hi",
            ))
            .unwrap();
            assert_eq!(s.state(), State::Established);
            break;
        }
    }
    assert_eq!(
        s.state(),
        State::Established,
        "legitimate client locked out"
    );
    assert_eq!(recv_all(&mut s), b"hi");
}

/// With only a cookie secret (no host secret) the cookie key also keys the
/// timestamp offset. A handshake validated with the pre-rotation key must
/// keep that offset, or our TSval would jump and the peer's PAWS would drop
/// our segments.
#[test]
fn cookie_promotion_after_rotation_keeps_the_timestamp_offset() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 1);
    s.set_cookie_secret(&[1; 16]);
    s.set_now(10_000);
    s.listen().unwrap();
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(ATTACKER, SRV, 9, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    drain(&mut s);
    let o = TcpOptions {
        mss: Some(1460),
        ts: Some((100, 0)),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &o, &[]))
        .unwrap();
    let synack = drain(&mut s).remove(0);
    let synack_tsval = synack.opts.ts.unwrap().0;
    s.set_cookie_secret(&[2; 16]);
    s.set_now(10_050);
    s.inject_packet(&pkt(
        CLI,
        SRV,
        501,
        synack.seq + 1,
        flags::ACK | flags::PSH,
        65535,
        &ts(101, synack_tsval),
        b"GET /",
    ))
    .unwrap();
    assert_eq!(
        s.state(),
        State::Established,
        "pre-rotation cookie accepted"
    );
    s.set_now(10_100);
    s.tick().unwrap(); // delayed ACK of the request
    let ack = drain(&mut s);
    let ack = ack.last().expect("data is acknowledged");
    let tsval = ack.opts.ts.unwrap().0;
    let advance = tsval.wrapping_sub(synack_tsval);
    assert!(
        advance <= 100 + 64,
        "TSval jumped by {advance} across promotion"
    );
}

/// The path-MTU black-hole fallback fires after any ~1.4 s outage (three
/// RTOs of a full-sized segment) and used to clamp the MSS for good. Probes
/// at the larger size now restore it once the path is back.
#[test]
fn short_outage_clamp_is_undone_by_probing() {
    let (mut c, sseq, iss) = established(1000, true, false);
    assert_eq!(c.stats().mss, 1448);
    c.send(&vec![0u8; 200_000]).unwrap();
    let mut now = 1020u64;
    while now < 1020 + 1_500 {
        now += 10;
        c.set_now(now);
        c.tick().unwrap();
        drain(&mut c); // path down: everything is lost
    }
    assert!(c.stats().mss < 1448, "outage triggered the clamp");
    let mut acked = iss + 1;
    let mut tsv = 50u32;
    for _ in 0..3_000 {
        now += 10;
        c.set_now(now);
        c.tick().unwrap();
        for o in drain(&mut c) {
            if o.len > 0 && o.seq == acked {
                acked += o.len as u32;
            }
        }
        tsv += 1;
        let _ = c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            acked,
            flags::ACK,
            65535,
            &ts(tsv, 0),
            &[],
        ));
        let _ = c.send(&vec![0u8; 65536]);
        if c.stats().mss == 1448 {
            break;
        }
    }
    assert_eq!(c.stats().mss, 1448, "MSS restored after the outage");
    assert!(
        now - 1020 <= 1_500 + 15_000,
        "restored only after {} ms",
        now - 1020
    );
}

/// On a real black hole (full-sized segments never arrive), the probe is
/// lost: the clamp stays and the probes back off.
#[test]
fn black_hole_clamp_survives_failed_probes() {
    let after = |a: u32, b: u32| (a.wrapping_sub(b) as i32) > 0;
    let (mut c, sseq, iss) = established(1000, true, false);
    c.send(&vec![0u8; 400_000]).unwrap();
    let mut now = 1020u64;
    let mut acked = iss + 1;
    let mut tsv = 50u32;
    let mut probes = 0;
    let mut clamped = false;
    // The receiver holds one SACK block above `acked` (one probe is missing
    // at a time) and, like any receiver, only ACKs what reaches it.
    let mut sacked: Option<(u32, u32)> = None;
    for _ in 0..12_000 {
        now += 10;
        c.set_now(now);
        c.tick().unwrap();
        let mut delivered = false;
        for o in drain(&mut c) {
            if o.len > 1012 {
                if clamped {
                    probes += 1;
                }
                continue; // the black hole eats every large segment
            }
            if o.len == 0 {
                continue;
            }
            delivered = true;
            let end = o.seq + o.len as u32;
            if !after(o.seq, acked) {
                if after(end, acked) {
                    acked = end;
                }
            } else {
                sacked = Some(match sacked {
                    Some((l, r)) if !after(o.seq, r) => (l, if after(end, r) { end } else { r }),
                    Some(b) => b,
                    None => (o.seq, end),
                });
            }
            if let Some((l, r)) = sacked {
                if !after(l, acked) {
                    if after(r, acked) {
                        acked = r;
                    }
                    sacked = None;
                }
            }
        }
        if delivered {
            tsv += 1;
            let mut opts = ts(tsv, 0);
            if let Some((l, r)) = sacked {
                opts.sack = SackBlocks::from_slice(&[(l, r)]);
            }
            let _ = c.inject_packet(&pkt(SRV, CLI, sseq, acked, flags::ACK, 65535, &opts, &[]));
        }
        clamped |= c.stats().mss < 1448;
        let _ = c.send(&vec![0u8; 65536]);
    }
    assert!(clamped, "the black hole was detected");
    assert!(c.stats().mss <= 1012, "clamp undone on a real black hole");
    assert!(probes >= 2, "probes were sent ({probes})");
    assert!(probes <= 4, "probes back off ({probes} in 2 min)");
    assert_eq!(c.state(), State::Established);
    assert!(
        after(acked, iss + 100_000),
        "data keeps flowing at the clamped size"
    );
}
