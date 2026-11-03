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

use crate::congestion::CaState;
use crate::tcb::{events, Endpoint, Tcb, TcbConfig};
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
    drain_with_ip_id(t).into_iter().map(|(o, _)| o).collect()
}

/// [`drain`], with each datagram's IP ID.
fn drain_with_ip_id(t: &mut Tcb) -> Vec<(Out, u16)> {
    let mut v = Vec::new();
    let mut buf = [0u8; MAX_PACKET];
    loop {
        let n = t.extract_packet(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        let s = wire::parse(&buf[..n]).expect("stack emitted an unparsable packet");
        let out = Out {
            dst: (s.dst_ip, s.dst_port),
            seq: s.seq,
            ack: s.ack,
            flags: s.flags,
            win: s.window,
            len: s.payload.len(),
            total_len: n,
            opts: s.options,
        };
        v.push((out, u16::from_be_bytes([buf[4], buf[5]])));
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
    established_rtt(now, 10, sack, ecn)
}

/// [`established`] with a handshake round trip of `rtt` ms.
fn established_rtt(now: u64, rtt: u64, sack: bool, ecn: bool) -> (Box<Tcb>, u32, u32) {
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
    c.set_now(now + rtt);
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

/// RFC 5961 §5.2 accepts an ACK down to `SND.UNA − MAX.SND.WND`. On a
/// connection that has sent less than that, the range reaches below its
/// ISS, so a blind injector could use any ACK within the peer's window. As
/// in Linux, an ACK of bytes we never sent is unacceptable: once data has
/// been acknowledged, a reordered segment ACKing part of it is accepted,
/// but never one ACKing bytes before our ISS.
#[test]
fn ack_of_bytes_never_sent_is_rejected() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1100);
    let inject = |c: &mut Tcb, seq: u32, ack: u32, tsval: u32, payload: &[u8]| {
        c.inject_packet(&pkt(
            SRV,
            CLI,
            seq,
            ack,
            flags::ACK,
            8192,
            &ts(tsval, 0),
            payload,
        ))
        .unwrap();
    };
    // Only our SYN has been acknowledged: SND.UNA = SND.NXT = iss + 1.
    for back in [2u32, 1_000] {
        inject(&mut c, sseq, (iss + 1).wrapping_sub(back), 5, b"evil");
        assert!(
            recv_all(&mut c).is_empty(),
            "ACK {back} below SND.UNA accepted"
        );
    }
    drain(&mut c);

    let sent = send_burst(&mut c, 1200, 3000);
    let end = sent.last().unwrap().1;
    inject(&mut c, sseq, end, 6, &[]);
    inject(&mut c, sseq, iss + 1 + 1000, 7, b"late");
    assert_eq!(recv_all(&mut c), b"late", "a reordered segment is fine");
    inject(&mut c, sseq + 4, iss.wrapping_sub(500), 8, b"evil");
    assert!(
        recv_all(&mut c).is_empty(),
        "ACK of bytes before our ISS accepted"
    );
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
    let third = pkt(
        CLI,
        SRV,
        501,
        synack.seq + 1,
        flags::ACK,
        65535,
        &ts(101, tsval),
        &[],
    );
    let mut s = hand_off(&mut s, &third, 10_000, |t| t.set_cookie_secret(&[7u8; 16]));
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

/// An ACK from the scripted server echoing `tsecr`, optionally with SACK
/// blocks (never a D-SACK); returns what `c` sent in response.
fn ts_ack(c: &mut Tcb, sseq: u32, now: u64, ack: u32, tsecr: u32, sack: &[(u32, u32)]) -> Vec<Out> {
    c.set_now(now);
    let o = TcpOptions {
        ts: Some((7, tsecr)),
        sack: SackBlocks::from_slice(sack),
        ..TcpOptions::NONE
    };
    c.inject_packet(&pkt(SRV, CLI, sseq, ack, flags::ACK, 0xffff, &o, &[]))
        .unwrap();
    drain(c)
}

/// Opens the scaled window, then sends `n` full segments at 1020 ms.
fn ts_burst(c: &mut Tcb, sseq: u32, iss: u32, n: usize) -> Vec<Out> {
    ts_ack(c, sseq, 1020, iss + 1, 1010, &[]);
    c.send(&vec![0x5a; n * 1448]).unwrap();
    c.tick().unwrap();
    let burst: Vec<Out> = drain(c).into_iter().filter(|o| o.len > 0).collect();
    assert_eq!(burst.len(), n);
    burst
}

fn tsval(o: &Out) -> u32 {
    o.opts.ts.unwrap().0
}

/// Eifel detection (RFC 3522) with Linux's response: in fast recovery, an
/// ACK filling the hole that echoes the original's TSval rather than the
/// retransmission's shows the segment was delayed, not lost. The reduction
/// is undone without any D-SACK (smoltcp never sends one); an echo of the
/// retransmission keeps it.
#[test]
fn timestamp_echo_undoes_only_a_spurious_fast_recovery() {
    for delayed in [true, false] {
        let (mut c, sseq, iss) = established(1000, true, false);
        let burst = ts_burst(&mut c, sseq, iss, 10);
        let end = |k: usize| burst[k].seq + burst[k].len as u32;
        let before = c.stats();
        // Segment 0 is held up; three later ones are SACKed (TS.Recent still
        // echoes the handshake), so RACK declares segment 0 lost.
        let mut retx = Vec::new();
        for k in 1..=3 {
            let out = ts_ack(&mut c, sseq, 1030, iss + 1, 1010, &[(burst[1].seq, end(k))]);
            retx.extend(out.into_iter().filter(|o| o.len > 0));
        }
        assert_eq!(retx.len(), 1, "one fast retransmission");
        assert_eq!(retx[0].seq, burst[0].seq);
        assert_eq!(c.stats().ca_state, CaState::Recovery as u8);
        assert!(tsval(&burst[0]) < tsval(&retx[0]));
        // The hole is filled by the original or by the retransmission.
        let echo = tsval(if delayed { &burst[0] } else { &retx[0] });
        ts_ack(&mut c, sseq, 1040, end(3), echo, &[]);
        let s = c.stats();
        assert_eq!(s.dsacks_received, 0);
        if delayed {
            assert_eq!(s.ca_state, CaState::Open as u8, "spurious recovery undone");
            assert_eq!(s.ssthresh, before.ssthresh);
            assert!(s.cwnd >= before.cwnd, "cwnd {} < {}", s.cwnd, before.cwnd);
        } else {
            assert_eq!(s.ca_state, CaState::Recovery as u8, "real loss: kept");
            assert!(s.ssthresh < before.ssthresh);
        }
    }
}

/// The same detection after a timeout (Linux `tcp_try_undo_loss`): an ACK
/// echoing the original transmission's TSval shows the RTO was spurious (a
/// delay spike, not loss), so the collapsed window is restored at once. The
/// ACK covers only the resent segment, so F-RTO has no original to judge
/// by: the echo alone decides.
#[test]
fn timestamp_echo_undoes_only_a_spurious_timeout() {
    for spurious in [true, false] {
        let (mut c, sseq, iss) = established(1000, false, false);
        let burst = ts_burst(&mut c, sseq, iss, 4);
        let before = c.stats();
        let mut now = 1020;
        let retx = loop {
            now += 5;
            assert!(now < 5000, "no retransmission timeout");
            c.set_now(now);
            c.tick().unwrap();
            if let Some(o) = drain(&mut c).into_iter().find(|o| o.len > 0) {
                break o;
            }
        };
        assert_eq!((c.stats().rto_count, retx.seq), (1, burst[0].seq));
        let echo = tsval(if spurious { &burst[0] } else { &retx });
        let head = burst[0].seq + burst[0].len as u32;
        ts_ack(&mut c, sseq, now + 10, head, echo, &[]);
        let s = c.stats();
        if spurious {
            assert_eq!(s.ca_state, CaState::Open as u8);
            assert_eq!(s.ssthresh, before.ssthresh);
            assert!(s.cwnd >= before.cwnd, "cwnd {} < {}", s.cwnd, before.cwnd);
        } else {
            assert!(s.ssthresh < before.ssthresh && s.cwnd < before.cwnd);
        }
    }
}

/// The first-retransmission time is forgotten once an episode's
/// retransmissions are all acknowledged, so a later tail loss probe and
/// timeout are judged against the probe's own send time. A stamp left over
/// from an earlier episode used to hide a spurious timeout and, 2^31 ms on,
/// to wrap and "undo" a genuine one.
#[test]
fn timestamp_undo_restarts_its_clock_after_each_episode() {
    for (gap, spurious) in [(1_000u64, true), (1u64 << 31, false)] {
        let (mut c, sseq, iss) = established(1000, true, false);
        // An earlier fast recovery that repaired a real loss.
        let burst = ts_burst(&mut c, sseq, iss, 10);
        let mut retx = Vec::new();
        for k in 1..=3 {
            let sack = [(burst[1].seq, burst[k].seq + burst[k].len as u32)];
            let out = ts_ack(&mut c, sseq, 1030, iss + 1, 1010, &sack);
            retx.extend(out.into_iter().filter(|o| o.len > 0));
        }
        let all = burst[9].seq + burst[9].len as u32;
        ts_ack(&mut c, sseq, 1040, all, tsval(&retx[0]), &[]);
        assert_eq!(c.stats().ca_state, CaState::Open as u8);
        // Much later, a tail that is never acknowledged: TLP, then RTO.
        let mut now = 1040 + gap;
        c.set_now(now);
        c.send(&vec![0x5a; 4 * 1448]).unwrap();
        c.tick().unwrap();
        let tail: Vec<Out> = drain(&mut c).into_iter().filter(|o| o.len > 0).collect();
        assert_eq!(tail.len(), 4);
        let before = c.stats();
        let rto_retx = loop {
            now += 5;
            assert!(now < 1040 + gap + 5000, "no retransmission timeout");
            c.set_now(now);
            c.tick().unwrap();
            let out = drain(&mut c);
            if c.stats().rto_count == 1 {
                break out.into_iter().find(|o| o.seq == tail[0].seq).unwrap();
            }
        };
        assert_eq!(c.stats().tlp_count, 1);
        // Only the resent head is ACKed: F-RTO has no original to judge by.
        let echo = tsval(if spurious { &tail[0] } else { &rto_retx });
        let head = tail[0].seq + tail[0].len as u32;
        ts_ack(&mut c, sseq, now + 10, head, echo, &[]);
        let s = c.stats();
        if spurious {
            assert_eq!(s.ca_state, CaState::Open as u8);
            assert_eq!(s.ssthresh, before.ssthresh, "spurious timeout kept");
        } else {
            assert!(s.ssthresh < before.ssthresh, "genuine timeout undone");
        }
    }
}

/// Tick `c` from `now` until its first retransmission timeout; returns the
/// resend of `head` and the time.
fn until_rto(c: &mut Tcb, mut now: u64, head: u32) -> (Out, u64) {
    loop {
        now += 1;
        assert!(now < 10_000, "no retransmission timeout");
        c.set_now(now);
        c.tick().unwrap();
        let out = drain(c);
        if c.stats().rto_count == 1 {
            let retx = out.into_iter().find(|o| o.len > 0 && o.seq == head);
            return (retx.expect("the timeout resent the head"), now);
        }
    }
}

/// F-RTO (RFC 5682 §3.1; Linux `tcp_process_loss` step 3.b): after a
/// timeout, a SACK of data sent before it and never resent shows that not
/// everything was lost, so the timeout was spurious — even though the ACK
/// echoes the resend and carries no D-SACK, as after an outage of the ACK
/// path took the D-SACKs with it. Without SACK, a cumulative ACK that also
/// covers the resend is no such evidence (see
/// `frto_without_sack_takes_no_ack_covering_the_resend_as_proof`).
#[test]
fn frto_undoes_a_timeout_once_never_resent_data_is_acknowledged() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let burst = ts_burst(&mut c, sseq, iss, 4);
    let end = |k: usize| burst[k].seq + burst[k].len as u32;
    let before = c.stats();
    let (retx, now) = until_rto(&mut c, 1020, burst[0].seq);
    let blocks = [(burst[1].seq, end(3))];
    ts_ack(&mut c, sseq, now + 1, end(0), tsval(&retx), &blocks);
    let s = c.stats();
    assert_eq!(s.dsacks_received, 0);
    assert_eq!(s.ca_state, CaState::Open as u8, "timeout kept");
    assert_eq!(s.ssthresh, before.ssthresh);
    assert!(s.cwnd >= before.cwnd, "cwnd {} < {}", s.cwnd, before.cwnd);
}

/// Without SACK, segments the receiver held out of order are ACKed together
/// with the resend that fills the hole in front of them, so such an ACK
/// cannot show the timeout was spurious (Linux `tcp_clean_rtx_queue` drops
/// `FLAG_ORIG_SACK_ACKED` when retransmitted data is ACKed). Here segments 0
/// and 2 were lost: undoing would also unmark segment 2 and leave it to a
/// second timeout.
#[test]
fn frto_without_sack_takes_no_ack_covering_the_resend_as_proof() {
    let (mut c, sseq, iss) = established(1000, false, false);
    let burst = ts_burst(&mut c, sseq, iss, 4);
    let end = |k: usize| burst[k].seq + burst[k].len as u32;
    let before = c.stats();
    // Segments 1 and 3 arrive: two duplicate ACKs, short of fast retransmit.
    ts_ack(&mut c, sseq, 1025, burst[0].seq, tsval(&burst[0]), &[]);
    ts_ack(&mut c, sseq, 1026, burst[0].seq, tsval(&burst[0]), &[]);
    let (retx, now) = until_rto(&mut c, 1026, burst[0].seq);
    let out = ts_ack(&mut c, sseq, now + 5, end(1), tsval(&retx), &[]);
    let s = c.stats();
    assert!(s.ssthresh < before.ssthresh, "real loss undone");
    assert_eq!(s.ca_state, CaState::Loss as u8);
    assert!(
        out.iter().any(|o| o.len > 0 && o.seq == burst[2].seq),
        "lost segment 2 not resent: {out:?}"
    );
}

/// F-RTO steps 2.b and 3 (Linux `tcp_process_loss`, `REXMIT_NEW`): the
/// first ACK after a timeout covers the resend alone, so new data goes out
/// instead of the next presumed-lost segment. If the next ACK reports that
/// data out of order, the loss was real: the lost segments are resent and
/// the timeout stands, even when a later ACK covers originals never resent.
/// If it acknowledges an original instead, the timeout was spurious.
#[test]
fn frto_probes_with_new_data_after_a_partial_ack() {
    for (sack, real) in [(false, true), (true, true), (false, false), (true, false)] {
        let (mut c, sseq, iss) = established(1000, sack, false);
        let burst = ts_burst(&mut c, sseq, iss, 10);
        let end = |k: usize| burst[k].seq + burst[k].len as u32;
        c.send(&vec![0x5b; 4 * 1448]).unwrap();
        c.tick().unwrap();
        assert!(
            drain(&mut c).iter().all(|o| o.len == 0),
            "cwnd was not full"
        );
        let before = c.stats();
        let (retx, now) = until_rto(&mut c, 1020, burst[0].seq);
        // With SACK a tail loss probe sent new data before the timeout.
        let rto_nxt = c.debug_snapshot().snd_nxt;
        let out = ts_ack(&mut c, sseq, now + 1, end(0), tsval(&retx), &[]);
        let new: Vec<&Out> = out.iter().filter(|o| o.len > 0).collect();
        let seqs: Vec<u32> = new.iter().map(|o| o.seq).collect();
        assert!(
            !new.is_empty() && new.iter().all(|o| o.seq.wrapping_sub(rto_nxt) < 1 << 30),
            "case {sack}/{real}: step 2.b sent {seqs:?}, not new data from {rto_nxt}"
        );
        let new_end = new.iter().map(|o| o.seq + o.len as u32).max().unwrap();
        if real {
            // Segment 1 was lost: the new data arrives above the hole.
            let blocks = [(rto_nxt, new_end)];
            let blocks: &[(u32, u32)] = if sack { &blocks } else { &[] };
            let out = ts_ack(&mut c, sseq, now + 2, end(0), tsval(&retx), blocks);
            assert!(
                out.iter().any(|o| o.len > 0 && o.seq == burst[1].seq),
                "case {sack}/{real}: lost segment not resent"
            );
            // Its resend fills the hole; segments 2..9 had arrived.
            ts_ack(&mut c, sseq, now + 3, new_end, tsval(&retx), &[]);
            let s = c.stats();
            assert!(
                s.ssthresh < before.ssthresh,
                "case {sack}/{real}: real timeout undone"
            );
        } else {
            // Segment 1 was only late: an ACK covers originals never resent.
            ts_ack(&mut c, sseq, now + 2, end(9), tsval(&retx), &[]);
            let s = c.stats();
            assert_eq!(s.ca_state, CaState::Open as u8, "case {sack}/{real}");
            assert_eq!(
                s.ssthresh, before.ssthresh,
                "case {sack}/{real}: spurious timeout kept"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tail loss probes, RACK, undo, ACK policy and cwnd validation
// ---------------------------------------------------------------------------

/// Tick `c` a millisecond at a time from `now` until it sends data.
fn first_data(c: &mut Tcb, mut now: u64, limit: u64) -> (Out, u64) {
    loop {
        now += 1;
        assert!(now < limit, "nothing sent before {limit} ms");
        c.set_now(now);
        c.tick().unwrap();
        if let Some(o) = drain(c).into_iter().find(|o| o.len > 0) {
            return (o, now);
        }
    }
}

/// RFC 8985 §7.4.2 case 2 / Linux `tcp_process_tlp_ack`: a receiver without
/// D-SACK answers a probe whose original had arrived with a plain duplicate
/// ACK. Nothing was lost; that used to halve cwnd and ssthresh.
#[test]
fn tlp_answered_by_a_plain_dup_ack_keeps_the_window() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let two = ts_burst(&mut c, sseq, iss, 2);
    let end = two[1].seq + two[1].len as u32;
    let before = c.stats();
    let (probe, now) = first_data(&mut c, 1020, 1500);
    assert_eq!((c.stats().tlp_count, probe.seq), (1, two[1].seq));
    ts_ack(&mut c, sseq, now + 5, end, tsval(&two[1]), &[]); // the originals'
    let mid = c.stats();
    ts_ack(&mut c, sseq, now + 6, end, tsval(&probe), &[]); // the probe's dup
    let s = c.stats();
    assert_eq!(s.ca_state, CaState::Open as u8);
    assert_eq!(
        s.ssthresh, before.ssthresh,
        "a probe of nothing lost cut ssthresh"
    );
    assert!(s.cwnd >= mid.cwnd);
}

/// A tail-loss-probe retransmission re-sends data not deemed lost: as in
/// Linux (not in `retrans_out`) it must not count twice in pipe.
#[test]
fn tail_loss_probe_does_not_inflate_pipe() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let two = ts_burst(&mut c, sseq, iss, 2);
    let (probe, _) = first_data(&mut c, 1020, 1500);
    assert_eq!(probe.seq, two[1].seq);
    assert_eq!(c.stats().pipe, 2 * 1448);
}

/// Only an ACK of new data restarts the probe timer (Linux
/// `FLAG_SET_XMIT_TIMER`): the peer's own data arriving every few
/// milliseconds used to push a pending probe out to the RTO.
#[test]
fn peer_data_does_not_postpone_the_tail_loss_probe() {
    let (mut c, mut sseq, iss) = established(1000, true, false);
    let tail = send_burst(&mut c, 1100, 3 * 1448);
    assert_eq!(tail.len(), 3);
    let mut now = 1100;
    let probe_at = loop {
        now += 5;
        assert!(now < 1400, "no retransmission");
        c.set_now(now);
        let data = pkt(
            SRV,
            CLI,
            sseq,
            iss + 1,
            flags::ACK | flags::PSH,
            8192,
            &ts(7, 0),
            &[0; 100],
        );
        c.inject_packet(&data).unwrap();
        sseq += 100;
        c.tick().unwrap();
        if drain(&mut c).iter().any(|o| o.len > 0) {
            break now;
        }
    };
    assert_eq!(c.stats().tlp_count, 1);
    assert!(
        probe_at <= 1125,
        "SRTT 10 ms, yet the probe left at {probe_at} ms"
    );
}

/// A tail loss probe guards the tail during an ECN reduction (CWR) too, as
/// Linux `tcp_schedule_loss_probe` allows; it used to wait for the RTO.
#[test]
fn tail_loss_probe_runs_during_cwr() {
    let (mut c, sseq, _) = established(1000, true, true);
    let a = send_burst(&mut c, 1100, 4 * 1448);
    c.set_now(1110);
    let ece = pkt(
        SRV,
        CLI,
        sseq,
        a[0].1,
        flags::ACK | flags::ECE,
        8192,
        &ts(7, 0),
        &[],
    );
    c.inject_packet(&ece).unwrap();
    drain(&mut c);
    assert_eq!(c.stats().ca_state, CaState::Cwr as u8);
    let (_, now) = first_data(&mut c, 1110, 2000);
    assert!(
        now <= 1150,
        "first retransmission {} ms after the ECE",
        now - 1110
    );
    assert_eq!(c.stats().tlp_count, 1);
}

/// RACK's reorder timer firing in fast recovery marks more segments lost;
/// they must go out (Linux `tcp_rack_reo_timeout` leaves cwnd alone and the
/// newly lost leave pipe). A PRR step without an ACK used to set
/// cwnd = pipe and send nothing until the RTO.
#[test]
fn reorder_timer_in_recovery_retransmits_what_it_marks() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 0, &[]); // open the scaled window
    let s0 = send_burst(&mut c, 1100, 1448);
    let s1 = send_burst(&mut c, 1124, 1448);
    let rest = send_burst(&mut c, 1125, 8 * 1448);
    assert_eq!((s0.len(), s1.len(), rest.len()), (1, 1, 8));
    // One later segment is SACKed: s0 is past RACK's deadline, s1 (sent
    // 21 ms ago, RACK RTT 20 ms + the reordering window) not yet.
    let out = ts_ack(&mut c, sseq, 1145, s0[0].0, 0, &[rest[0]]);
    assert!(out.iter().any(|o| o.len > 0 && o.seq == s0[0].0));
    assert_eq!(c.stats().ca_state, CaState::Recovery as u8);
    let mut now = 1145;
    let resent = loop {
        now += 1;
        assert!(now < 1200, "s1 left to the RTO");
        c.set_now(now);
        c.tick().unwrap();
        if drain(&mut c).iter().any(|o| o.len > 0 && o.seq == s1[0].0) {
            break now;
        }
    };
    assert!(resent <= 1150, "s1 resent at {resent} ms");
    assert_eq!(c.stats().rto_count, 0);
}

/// A tail loss probe that repaired a real loss counts against undoing the
/// recovery it led into (Linux `tcp_init_undo`): D-SACKs for the episode's
/// own retransmissions alone used to restore the window.
#[test]
fn dsack_undo_also_waits_for_the_tail_loss_probe() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b: Vec<(u32, u32)> = ts_burst(&mut c, sseq, iss, 10)
        .iter()
        .map(|o| (o.seq, o.seq + o.len as u32))
        .collect();
    // 0..=6 arrive; 7 and 8 are delayed; 9 is lost.
    ts_ack(&mut c, sseq, 1030, b[6].1, 0, &[]);
    let (probe, now) = first_data(&mut c, 1030, 1300);
    assert_eq!(probe.seq, b[9].0);
    // The probe arrives: 7 and 8 look lost and are retransmitted.
    ts_ack(&mut c, sseq, now + 10, b[6].1, 0, &[b[9]]);
    ts_ack(&mut c, sseq, now + 20, b[7].1, 0, &[b[9]]);
    ts_ack(&mut c, sseq, now + 30, b[9].1, 0, &[]);
    let reduced = c.stats();
    assert!(reduced.ssthresh < 1 << 30);
    // The delayed originals of 7 and 8 land: D-SACKs for both
    // retransmissions, none for the probe that repaired 9.
    ts_ack(&mut c, sseq, now + 40, b[9].1, 0, &[b[7]]);
    ts_ack(&mut c, sseq, now + 41, b[9].1, 0, &[b[8]]);
    assert_eq!(
        c.stats().ssthresh,
        reduced.ssthresh,
        "the probe repaired a real loss"
    );
}

/// ECN-Echo during a loss episode makes the reduction mandatory (Linux
/// `tcp_fastretrans_alert`: `if (ece_ack) tp->prior_ssthresh = 0`): an undo
/// may end the episode but not restore the window. A timestamp undo on the
/// ECE-bearing ACK used to restore it, and the ECE was then ignored.
#[test]
fn ecn_echo_keeps_a_loss_reduction_through_undo() {
    let (mut c, sseq, iss) = established(1000, true, true);
    let b = ts_burst(&mut c, sseq, iss, 10);
    let initial = c.stats();
    let sack = [(b[1].seq, b[3].seq + b[3].len as u32)];
    let out = ts_ack(&mut c, sseq, 1030, b[0].seq, tsval(&b[3]), &sack);
    assert!(out.iter().any(|o| o.len > 0 && o.seq == b[0].seq));
    // Everything acknowledged, echoing an original (a spurious episode by
    // timestamps), with ECE.
    c.set_now(1040);
    let all = b[9].seq + b[9].len as u32;
    let ece = pkt(
        SRV,
        CLI,
        sseq,
        all,
        flags::ACK | flags::ECE,
        0xffff,
        &ts(8, tsval(&b[9])),
        &[],
    );
    c.inject_packet(&ece).unwrap();
    drain(&mut c);
    assert!(
        c.stats().ssthresh < initial.ssthresh,
        "ECN-Echo's reduction was undone"
    );
}

/// Linux `tcp_packet_delayed` with nothing retransmitted yet: an ACK that
/// fills the hole while the fast retransmission is still held back (egress
/// paused) shows the "loss" was delay, so the reduction is undone.
#[test]
fn recovery_with_nothing_retransmitted_is_undone_by_the_filling_ack() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 10);
    let initial = c.stats();
    c.set_egress_paused(true);
    let sack = [(b[1].seq, b[3].seq + b[3].len as u32)];
    ts_ack(&mut c, sseq, 1030, b[0].seq, 0, &sack);
    let s = c.stats();
    assert_eq!((s.ca_state, s.segs_retrans), (CaState::Recovery as u8, 0));
    ts_ack(&mut c, sseq, 1031, b[3].seq + b[3].len as u32, 0, &[]);
    let s = c.stats();
    assert_eq!(s.ca_state, CaState::Open as u8);
    assert_eq!(s.ssthresh, initial.ssthresh, "spurious recovery kept");
}

/// Spend the quick ACKs (Linux quickack mode) a connection's first data
/// earns: one-byte segments from the server until one's ACK is held, then
/// let that delayed ACK go and read the bytes. Returns the server's next
/// sequence number and the time reached.
fn spend_quick_acks(c: &mut Tcb, mut seq: u32, ack: u32, mut now: u64) -> (u32, u64) {
    for _ in 0..64 {
        c.set_now(now);
        let one = pkt(SRV, CLI, seq, ack, flags::ACK, 0xffff, &ts(5, 0), &[0u8; 1]);
        c.inject_packet(&one).unwrap();
        seq += 1;
        if drain(c).is_empty() {
            break;
        }
        now += 1;
    }
    now += 50;
    c.set_now(now);
    c.tick().unwrap();
    assert!(!drain(c).is_empty(), "the held ACK goes with the timer");
    let mut buf = [0u8; 128];
    while c.recv(&mut buf).unwrap() > 0 {}
    drain(c);
    (seq, now)
}

/// Linux `__tcp_cleanup_rbuf`: a read that empties the receive queue sends
/// the ACK a short segment earned at once (a Nagle sender waits for it),
/// unless the connection is interactive and the reply will carry it.
#[test]
fn reading_a_short_segment_acks_at_once_unless_interactive() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let (mut seq, t0) = spend_quick_acks(&mut c, sseq, iss + 1, 1020);
    let mut buf = [0u8; 4096];
    let data = |seq: u32, tsv: u32, ack: u32| {
        pkt(
            SRV,
            CLI,
            seq,
            ack,
            flags::ACK | flags::PSH,
            0xffff,
            &ts(tsv, 1010),
            &[2u8; 100],
        )
    };
    c.set_now(t0 + 1);
    c.inject_packet(&data(seq, 7, iss + 1)).unwrap();
    seq += 100;
    assert!(
        drain(&mut c).is_empty(),
        "a lone short segment's ACK is held"
    );
    c.set_now(t0 + 2);
    assert_eq!(c.recv(&mut buf).unwrap(), 100);
    let out = drain(&mut c);
    assert_eq!(out.len(), 1, "the read that empties the queue sends it");
    assert_eq!(out[0].ack, seq);
    for round in 0..3u32 {
        // Within an RTO of the last data (an idle RTO earns quick ACKs).
        let now = t0 + 10 + u64::from(round) * 50;
        c.set_now(now);
        c.inject_packet(&data(seq, 8 + round, iss + 1 + 100 * round))
            .unwrap();
        seq += 100;
        assert!(drain(&mut c).is_empty());
        assert_eq!(c.recv(&mut buf).unwrap(), 100);
        let on_read = drain(&mut c);
        if round >= 1 {
            assert!(
                on_read.is_empty(),
                "round {round}: interactive, the reply carries it"
            );
        }
        c.send(&[3u8; 100]).unwrap();
        c.tick().unwrap();
        let reply = drain(&mut c);
        assert_eq!((reply.len(), reply[0].ack), (1, seq));
        c.set_now(now + 1);
        let ack = pkt(
            SRV,
            CLI,
            seq,
            iss + 1 + 100 * (round + 1),
            flags::ACK,
            0xffff,
            &ts(9 + round, 1010),
            &[],
        );
        c.inject_packet(&ack).unwrap();
        drain(&mut c);
    }
}

/// A client that sends its first request right after connecting is not yet
/// interactive (Linux counts a reply only once data has arrived), so the
/// response is ACKed at once (quickack) or when read; a server holding the
/// rest of its response for that ACK (Nagle) would otherwise wait 40 ms.
#[test]
fn first_request_after_connecting_is_not_interactive() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.send(&[1u8; 100]).unwrap();
    c.set_now(1011);
    c.tick().unwrap();
    assert_eq!(drain(&mut c).len(), 1);
    c.set_now(1020);
    let resp = pkt(
        SRV,
        CLI,
        sseq,
        iss + 101,
        flags::ACK | flags::PSH,
        0xffff,
        &ts(7, 1011),
        &[2u8; 100],
    );
    c.inject_packet(&resp).unwrap();
    let mut out = drain(&mut c);
    let mut buf = [0u8; 256];
    assert_eq!(c.recv(&mut buf).unwrap(), 100);
    out.extend(drain(&mut c));
    assert!(
        out.iter().any(|o| o.ack == sseq + 100),
        "the response's ACK waits for a timer"
    );
}

/// Linux `tcp_incr_quickack`: a new connection ACKs its first segments one
/// by one (up to 16, half the window in receive-MSS segments), so a sender
/// in slow start is not held to every other segment, nor to a 40 ms timer
/// for an odd one.
#[test]
fn new_connection_acks_its_first_segments_at_once() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let mut quick = 0;
    for i in 0..32u32 {
        c.set_now(1020 + u64::from(i));
        let one = pkt(
            SRV,
            CLI,
            sseq + i,
            iss + 1,
            flags::ACK,
            0xffff,
            &ts(5, 0),
            &[0u8; 1],
        );
        c.inject_packet(&one).unwrap();
        if drain(&mut c).is_empty() {
            break;
        }
        quick += 1;
    }
    assert_eq!(quick, 16);
}

/// Linux `tcp_event_data_recv`: data after more than an RTO without any is
/// a sender restarting from a small window; ACK it at once again.
#[test]
fn data_after_an_idle_rto_is_acked_at_once() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let (seq, t0) = spend_quick_acks(&mut c, sseq, iss + 1, 1020);
    c.set_now(t0 + 1000);
    let one = pkt(
        SRV,
        CLI,
        seq,
        iss + 1,
        flags::ACK,
        0xffff,
        &ts(6, 0),
        &[0u8; 1],
    );
    c.inject_packet(&one).unwrap();
    assert_eq!(drain(&mut c).len(), 1, "a restarting sender waits 40 ms");
}

/// Linux `__tcp_ecn_check_ce`: a CE mark the sender has yet to hear of is
/// echoed at once — its window may be too small to clock another ACK.
#[test]
fn ce_mark_is_echoed_at_once() {
    let (mut c, sseq, iss) = established(1000, true, true);
    let (seq, t0) = spend_quick_acks(&mut c, sseq, iss + 1, 1020);
    c.set_now(t0 + 1);
    let marked = pkt_ecn(
        SRV,
        CLI,
        seq,
        iss + 1,
        flags::ACK,
        0xffff,
        &ts(6, 0),
        &[0u8; 1],
        wire::ecn::CE,
    );
    c.inject_packet(&marked).unwrap();
    let out = drain(&mut c);
    assert_eq!(out.len(), 1, "the CE mark waits for the delayed ACK");
    assert_ne!(out[0].flags & flags::ECE, 0);
}

/// Linux `tcp_data_queue`: a retransmission of data we hold shows the
/// sender recovering; after its D-SACK, new data is ACKed at once too, even
/// on a connection that was interactive.
#[test]
fn duplicate_data_turns_quick_acks_back_on() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let (mut seq, t0) = spend_quick_acks(&mut c, sseq, iss + 1, 1020);
    let data = |seq: u32| {
        pkt(
            SRV,
            CLI,
            seq,
            iss + 1,
            flags::ACK | flags::PSH,
            0xffff,
            &ts(6, 0),
            &[2u8; 100],
        )
    };
    c.set_now(t0 + 1);
    c.inject_packet(&data(seq)).unwrap();
    seq += 100;
    c.send(&[3u8; 10]).unwrap();
    c.tick().unwrap();
    drain(&mut c); // the reply carries the ACK: interactive now
    c.set_now(t0 + 2);
    c.inject_packet(&data(seq - 100)).unwrap();
    assert_eq!(drain(&mut c).len(), 1, "the duplicate's D-SACK");
    c.set_now(t0 + 3);
    c.inject_packet(&data(seq)).unwrap();
    assert_eq!(drain(&mut c).len(), 1, "new data after it waits 40 ms");
}

/// RFC 5681 §4.2: a segment that fills part of a hole is ACKed at once (as
/// Linux while out-of-order data is queued); its ACK used to wait 40 ms,
/// stalling the sender's recovery.
#[test]
fn partial_hole_fill_is_acked_at_once() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let seg = |seq: u32, tsv: u32| {
        pkt(
            SRV,
            CLI,
            seq,
            iss + 1,
            flags::ACK,
            8192,
            &ts(tsv, 0),
            &[0x55; 1448],
        )
    };
    c.set_now(1020);
    c.inject_packet(&seg(sseq + 2 * 1448, 2)).unwrap();
    drain(&mut c);
    c.set_now(1021);
    c.inject_packet(&seg(sseq, 3)).unwrap();
    assert!(
        drain(&mut c).iter().any(|p| p.ack == sseq + 1448),
        "partial fill not ACKed at once"
    );
}

/// In-order data covering parked out-of-order bytes received them twice:
/// report them with a D-SACK (Linux `tcp_ofo_queue`), and ACK at once.
#[test]
fn in_order_data_over_parked_data_is_dsacked() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let seg = |seq: u32, len: usize, tsv: u32| {
        pkt(
            SRV,
            CLI,
            seq,
            iss + 1,
            flags::ACK,
            8192,
            &ts(tsv, 0),
            &vec![0x55; len],
        )
    };
    c.set_now(1020);
    c.inject_packet(&seg(sseq + 500, 500, 2)).unwrap();
    drain(&mut c);
    c.set_now(1021);
    c.inject_packet(&seg(sseq, 1000, 3)).unwrap();
    let out = drain(&mut c);
    let ack = out
        .iter()
        .find(|o| o.ack == sseq + 1000)
        .expect("hole filled: ACK at once");
    assert_eq!(
        ack.opts.sack.as_slice().first().copied(),
        Some((sseq + 500, sseq + 1000)),
        "no D-SACK for the parked copy"
    );
    assert_eq!(c.stats().dup_bytes_received, 500);
}

/// Linux `tcp_cwnd_validate`: a flight that fills cwnd keeps its round
/// cwnd-limited until all of it is acknowledged, so slow start doubles the
/// window. The round used to end at the flight's first ACK, stalling growth.
#[test]
fn a_flight_that_fills_cwnd_doubles_it_in_slow_start() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 10); // exactly the initial window
    let iw = c.stats().cwnd;
    assert_eq!(iw, 10 * 1448);
    ts_ack(
        &mut c,
        sseq,
        1030,
        b[3].seq + b[3].len as u32,
        tsval(&b[3]),
        &[],
    );
    ts_ack(
        &mut c,
        sseq,
        1031,
        b[9].seq + b[9].len as u32,
        tsval(&b[9]),
        &[],
    );
    assert_eq!(c.stats().cwnd, 2 * iw);
}

/// Linux `tcp_rtt_estimator` / `tcp_set_rto`: fixed-point SRTT follows a
/// small RTT rise (in integer ms it could not rise by less than 8 ms), and
/// RTO keeps a 200 ms margin over a steady long RTT (it fell to SRTT + 1).
#[test]
fn rtt_estimator_tracks_small_changes_and_keeps_the_rto_margin() {
    for (handshake, path) in [(1u64, 8u64), (300, 300)] {
        let (mut c, sseq, _) = established_rtt(1000, handshake, true, false);
        let mut now = 2000;
        for _ in 0..40 {
            let seg = send_burst(&mut c, now, 1448);
            now += path;
            ts_ack(&mut c, sseq, now, seg[0].1, 0, &[]);
            now += 100;
        }
        let s = c.stats();
        assert!(
            s.srtt_ms.abs_diff(path as u32) <= 1,
            "SRTT {} ms on a {path} ms path",
            s.srtt_ms
        );
        assert!(
            s.rto_ms >= s.srtt_ms + 200,
            "RTO {} ms over SRTT {} ms",
            s.rto_ms,
            s.srtt_ms
        );
    }
}

/// Retransmitting the head restarts the RTO (Linux
/// `tcp_xmit_retransmit_queue`): a fast retransmission just before the
/// original's deadline used to be followed by a spurious timeout.
#[test]
fn retransmitting_the_head_restarts_the_rto() {
    let (mut c, sseq, iss) = established(1000, false, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 0, &[]); // open the scaled window
    let segs = send_burst(&mut c, 1100, 4 * 1448);
    assert_eq!(segs.len(), 4);
    let at = 1100 + u64::from(c.stats().rto_ms) - 5;
    let mut out = Vec::new();
    for _ in 0..3 {
        out = ts_ack(&mut c, sseq, at, segs[0].0, 0, &[]);
    }
    assert!(
        out.iter().any(|o| o.len > 0 && o.seq == segs[0].0),
        "no fast retransmission"
    );
    for now in at + 1..at + 50 {
        c.set_now(now);
        c.tick().unwrap();
        drain(&mut c);
    }
    assert_eq!(
        c.stats().rto_count,
        0,
        "a timeout right after the retransmission"
    );
}

/// Nagle in Minshall's variant (Linux's default): a short segment waits
/// while an earlier short one is unacknowledged, and goes out with its ACK;
/// `set_nodelay(true)` sends it at once.
#[test]
fn nagle_holds_a_short_segment_behind_an_unacknowledged_one() {
    for nodelay in [false, true] {
        let (mut c, sseq, _) = established(1000, true, false);
        c.set_nodelay(nodelay);
        let first = send_burst(&mut c, 1020, 100);
        assert_eq!(first.len(), 1);
        let second = send_burst(&mut c, 1021, 100);
        assert_eq!(second.len(), usize::from(nodelay), "nodelay={nodelay}");
        if !nodelay {
            let out = ts_ack(&mut c, sseq, 1030, first[0].1, 0, &[]);
            assert!(
                out.iter().any(|o| o.len == 100 && o.seq == first[0].1),
                "the ACK did not release the held segment"
            );
        }
    }
}

/// PSH marks the end of what was queued (Linux marks the tail of a write),
/// not every segment, so a GRO receiver can coalesce the run before it.
#[test]
fn psh_marks_only_the_tail_of_queued_data() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 0, &[]); // open the scaled window
    c.send(&[0x5a; 4 * 1448 + 100]).unwrap();
    c.tick().unwrap();
    let pushed: Vec<bool> = drain(&mut c)
        .iter()
        .filter(|o| o.len > 0)
        .map(|o| o.flags & flags::PSH != 0)
        .collect();
    assert_eq!(pushed, [false, false, false, false, true]);
}

/// RFC 2018 §4 / Linux `tcp_current_mss`: while the peer's data is out of
/// order, our full-sized data segments carry the SACK blocks too (their
/// payload shrinks by 8 bytes a block), so a peer in a two-way transfer
/// learns of the hole from the ACKs riding on our data.
#[test]
fn data_segments_carry_sack_blocks_while_data_is_out_of_order() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 0, &[]); // open the scaled window
    c.set_now(1021);
    let past_hole = pkt(
        SRV,
        CLI,
        sseq + 100,
        iss + 1,
        flags::ACK,
        0xffff,
        &ts(7, 0),
        &[1u8; 100],
    );
    c.inject_packet(&past_hole).unwrap();
    drain(&mut c);
    c.send(&[0x5a; 3 * 1448]).unwrap();
    c.tick().unwrap();
    let data: Vec<Out> = drain(&mut c).into_iter().filter(|o| o.len > 0).collect();
    assert_eq!(data[0].len, 1448 - 8);
    for o in &data {
        assert_eq!(o.ack, sseq);
        assert_eq!(
            o.opts.sack.len(),
            1,
            "a {}-byte segment without the SACK block",
            o.len
        );
        assert!(o.total_len <= 1500);
    }
}

/// A third ACK with a "future" sequence number (inside the window, not at
/// RCV.NXT) must not become SND.WL1: the peer's genuine window updates at
/// RCV.NXT used to be ignored as older, freezing the window at its zero.
#[test]
fn third_ack_cannot_freeze_the_send_window() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_secret(&[3u8; 16]);
    s.set_now(0);
    s.listen().unwrap();
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    let isn = drain(&mut s)[0].seq;
    let none = TcpOptions::NONE;
    s.inject_packet(&pkt(
        CLI,
        SRV,
        78 + 50_000,
        isn + 1,
        flags::ACK,
        0,
        &none,
        &[],
    ))
    .unwrap();
    assert_eq!(s.state(), State::Established);
    s.inject_packet(&pkt(CLI, SRV, 78, isn + 1, flags::ACK, 65535, &none, &[]))
        .unwrap();
    assert_eq!(s.stats().snd_wnd, 65535, "window frozen by the forged WL1");
}

/// CLOSE in SYN-RECEIVED queues a FIN behind a SYN-ACK the peer may never
/// have received; the SYN-ACK must keep being retransmitted (Linux does for
/// a Fast Open socket in FIN-WAIT-1), not only the FIN.
#[test]
fn close_in_syn_received_keeps_retransmitting_the_syn_ack() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_secret(&[3u8; 16]);
    s.set_now(0);
    s.listen().unwrap();
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    drain(&mut s);
    assert_eq!(s.state(), State::SynRcvd);
    s.close().unwrap();
    let mut synacks = 0;
    for now in (100..5_000).step_by(100) {
        s.set_now(now);
        s.tick().unwrap();
        synacks += drain(&mut s)
            .iter()
            .filter(|o| o.flags & flags::SYN != 0)
            .count();
    }
    assert!(
        synacks >= 2,
        "{synacks} SYN-ACK retransmissions after close"
    );
}

/// A reset in CLOSING that discards data of ours must report it (Linux
/// `tcp_reset`), after the peer's completed stream is read; it used to close
/// as if everything had been delivered.
#[test]
fn reset_after_the_peers_fin_reports_our_lost_data() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    c.send(&vec![0x55; 100_000]).unwrap();
    c.close().unwrap();
    c.tick().unwrap();
    drain(&mut c);
    c.set_now(1030);
    let fin = flags::ACK | flags::FIN | flags::PSH;
    c.inject_packet(&pkt(SRV, CLI, sseq, iss + 1, fin, 8192, &ts(7, 0), b"bye"))
        .unwrap();
    drain(&mut c);
    assert_eq!(c.state(), State::Closing);
    c.set_now(1031);
    let rst = pkt(SRV, CLI, sseq + 4, 0, flags::RST, 0, &TcpOptions::NONE, &[]);
    c.inject_packet(&rst).unwrap();
    assert_eq!(c.state(), State::Closed);
    assert_ne!(c.poll() & events::ERROR, 0, "lost data closed as delivered");
    let mut buf = [0u8; 16];
    assert_eq!(c.recv(&mut buf).unwrap(), 3, "the peer's bytes come first");
    assert_eq!(c.recv(&mut buf), Err(TcpError::ConnectionReset));
}

/// PAWS applies to pure ACKs too (Linux exempts only a duplicate ACK that
/// cannot change the window): a reordered older ACK advertising a zero
/// window used to overwrite the newer, open one and stall the sender.
#[test]
fn reordered_old_zero_window_ack_is_dropped_by_paws() {
    let (mut c, sseq, iss) = established(1000, true, false);
    for (now, tsv, win) in [(1020, 106, 60_000), (1021, 103, 0)] {
        c.set_now(now);
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            iss + 1,
            flags::ACK,
            win,
            &ts(tsv, 0),
            &[],
        ))
        .unwrap();
        drain(&mut c);
    }
    c.send(b"hello").unwrap();
    c.tick().unwrap();
    let sent: usize = drain(&mut c).iter().map(|o| o.len).sum();
    assert_eq!(sent, 5, "the stale zero window was believed");
}

/// Linux `tcp_paws_check`: a TS.Recent of 0 (a SYN-ACK stamped 0) is no
/// reference, and an expired one is replaced by the next in-order TSval.
/// Data after a zero SYN timestamp used to be rejected when the peer's real
/// clock had its top bit set, and an expired reference never refreshed, so
/// replays were let in.
#[test]
fn paws_reference_is_replaced_when_zero_or_expired() {
    let iss = 1_000_000;
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(1000);
    c.connect().unwrap();
    let syn = drain(&mut c);
    let o = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ts: Some((0, syn[0].opts.ts.unwrap().0)),
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    c.set_now(1010);
    let synack = flags::SYN | flags::ACK;
    c.inject_packet(&pkt(SRV, CLI, SRV_ISS, iss + 1, synack, 8192, &o, &[]))
        .unwrap();
    drain(&mut c);
    let data = |seq: u32, tsv: u32, b: &[u8]| {
        pkt(
            SRV,
            CLI,
            seq,
            iss + 1,
            flags::ACK | flags::PSH,
            8192,
            &ts(tsv, 0),
            b,
        )
    };
    let mut buf = [0u8; 8];
    c.set_now(1020);
    c.inject_packet(&data(SRV_ISS + 1, 0x8000_0001, b"abc"))
        .unwrap();
    assert_eq!(c.recv(&mut buf).unwrap(), 3, "rejected against TS.Recent 0");

    let (mut c, sseq, _) = established(1000, true, false);
    let age = (1u64 << 31) + 1000; // the peer's clock looks "older" now
    let fresh = 1u32.wrapping_add(age as u32);
    c.set_now(1010 + age);
    c.inject_packet(&data(sseq, fresh, b"A")).unwrap();
    c.set_now(1011 + age);
    c.inject_packet(&data(sseq + 1, fresh.wrapping_sub(10), b"B"))
        .unwrap();
    assert_eq!(
        c.recv(&mut buf).unwrap(),
        1,
        "a replay passed a stale reference"
    );
}

/// Linux `tcp_is_sackblock_valid`: a SACK block reaching past SND.NXT is
/// ignored whole; it used to be clipped into a report that the outstanding
/// data had arrived.
#[test]
fn sack_block_past_snd_nxt_is_ignored() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 4);
    let nxt = b[3].seq + b[3].len as u32;
    ts_ack(&mut c, sseq, 1030, b[0].seq, 0, &[(b[1].seq, nxt + 1)]);
    assert_eq!(c.stats().pipe, 4 * 1448);
}

/// Linux `tcp_check_sack_reneging`: a cumulative ACK stopping at SACKed data
/// shows the receiver dropped what it SACKed. After a grace of
/// max(SRTT/2, 10 ms) the sender forgets the SACKs and resends — it used to
/// wait a whole RTO.
#[test]
fn sack_reneging_is_repaired_after_a_short_grace() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 3);
    let end = |i: usize| b[i].seq + b[i].len as u32;
    ts_ack(&mut c, sseq, 1028, b[0].seq, 0, &[(b[1].seq, end(2))]);
    ts_ack(&mut c, sseq, 1029, end(0), 0, &[]); // 1 and 2 reneged
    let (resent, now) = first_data(&mut c, 1029, 1300);
    assert_eq!(resent.seq, b[1].seq);
    assert!(now <= 1040, "reneging repaired at {now} ms");
}

/// With the egress ring full (not paused), an owed ACK waits for the host
/// to drain; `next_deadline` must not report it due, or an event-driven
/// host spins (after `tick` every deadline is in the future).
#[test]
fn full_egress_ring_does_not_report_an_owed_ack_due() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    let p = pkt(SRV, CLI, sseq, iss + 1, flags::ACK, 8192, &ts(7, 0), b"x");
    for _ in 0..=crate::tx_ring::TX_RING_CAP + 1 {
        c.inject_packet(&p).unwrap(); // duplicates: each answered at once
    }
    c.set_now(1021);
    c.tick().unwrap();
    assert!(c.next_deadline().is_none_or(|d| d > 1021));
    drain(&mut c);
    c.tick().unwrap();
    assert!(
        drain(&mut c).iter().any(|o| o.ack == sseq + 1),
        "the owed ACK is sent once the host drains"
    );
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

/// A reported path MTU holds for 10 minutes, as a route's learned PMTU
/// (Linux `ip_rt_mtu_expires`); then one segment probes the size before
/// it. It used to cap the segment size for the rest of the connection, so
/// a path that grew back, or a forged report, did so for good. A report
/// of the size in use (a probe that did not fit) holds it 10 more minutes.
#[test]
fn reported_pmtu_expires_after_ten_minutes() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 1000, &[]);
    // One write, ACKed: the largest payload it went out in.
    let write = |c: &mut Tcb, now: u64| {
        c.set_now(now);
        c.send(&vec![0x5a; 4 * 1448]).unwrap();
        c.tick().unwrap();
        let data: Vec<Out> = drain(c).into_iter().filter(|o| o.len > 0).collect();
        let end = data.iter().map(|o| o.seq + o.len as u32).max().unwrap();
        ts_ack(c, sseq, now + 1, end, now as u32, &[]);
        data.iter().map(|o| o.len).max().unwrap()
    };
    let reduced = 1020;
    c.update_pmtu(1280);
    let mut now = reduced;
    for _ in 0..9 {
        now += 60_000;
        assert_eq!(write(&mut c, now), 1228, "at {now} ms");
    }
    now = reduced + 600_000;
    assert_eq!(write(&mut c, now), 1448, "the old size probed after 10 min");
    now += 60_000;
    assert_eq!(write(&mut c, now), 1448, "and restored once it got through");
    // Reduced again; 10 minutes on, the probe does not fit and is reported.
    c.update_pmtu(1280);
    let reduced = now + 1;
    for _ in 0..9 {
        now += 60_000;
        assert_eq!(write(&mut c, now), 1228, "at {now} ms");
    }
    now = reduced + 600_000;
    c.set_now(now);
    c.send(&vec![0x5a; 1448]).unwrap();
    c.tick().unwrap();
    assert!(drain(&mut c).iter().any(|o| o.len == 1448), "probe sent");
    c.update_pmtu(1280);
    let (resend, t) = first_data(&mut c, now, now + 5_000);
    assert!(
        resend.len <= 1228,
        "the dropped probe resent at the size in use"
    );
    now = t;
    let nxt = c.debug_snapshot().snd_nxt;
    ts_ack(&mut c, sseq, now, nxt, now as u32, &[]);
    for _ in 0..9 {
        now += 60_000;
        assert_eq!(
            write(&mut c, now),
            1228,
            "held 10 more minutes: at {now} ms"
        );
    }
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

/// RFC 3168 §6.1.2: CE is a property of data segments; pure ACKs are sent
/// Not-ECT, so a CE mark on one is forged (or a middlebox artefact). It
/// used to set the echo state, so an in-window pure ACK with CE made every
/// following ACK of ours carry ECE and the peer halve its window; Linux
/// only looks at CE on the data it queues.
#[test]
fn ce_on_a_pure_ack_is_not_echoed() {
    let (mut c, sseq, iss) = established(1000, true, true);
    c.set_now(1020);
    c.inject_packet(&pkt_ecn(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        8192,
        &ts(5, 0),
        &[],
        wire::ecn::CE,
    ))
    .unwrap();
    drain(&mut c);
    for k in 0..2u32 {
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq + k * 100,
            iss + 1,
            flags::ACK | flags::PSH,
            8192,
            &ts(6 + k, 0),
            &[1u8; 100],
        ))
        .unwrap();
    }
    let out = drain(&mut c);
    assert!(!out.is_empty());
    assert!(
        out.iter().all(|o| o.flags & flags::ECE == 0),
        "CE on a pure ACK was echoed"
    );
    // CE on data is still echoed.
    c.inject_packet(&pkt_ecn(
        SRV,
        CLI,
        sseq + 200,
        iss + 1,
        flags::ACK | flags::PSH,
        8192,
        &ts(8, 0),
        &[1u8; 100],
        wire::ecn::CE,
    ))
    .unwrap();
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 300,
        iss + 1,
        flags::ACK | flags::PSH,
        8192,
        &ts(9, 0),
        &[1u8; 100],
    ))
    .unwrap();
    let out = drain(&mut c);
    assert!(
        out.iter().any(|o| o.flags & flags::ECE != 0),
        "CE on data must be echoed"
    );
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
            // The advertised edge never passes the buffer: it used to creep
            // ~16 bytes per ACK at 1 MiB (shift 5), so a full buffer never
            // advertised zero.
            let edge = o.ack + (u32::from(o.win) << shift);
            assert!(
                edge <= sseq + crate::BUF_CAP as u32,
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

/// Window scaling may retract the advertised edge by less than one unit
/// (RFC 7323 §2.4), but the edge must never pass the free space of the
/// receive ring. Rounding up to keep the previous edge used to offer up to
/// `2^shift - 1` bytes beyond it; a peer filling that window had those bytes
/// trimmed on arrival, and every such hole cost it a SACK recovery and a
/// retransmission (every few MiB of a guest upload through tinyvmm's NAT).
#[test]
fn peer_filling_every_advertised_window_loses_nothing() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let shift = (0..15).find(|&s| (crate::BUF_CAP >> s) <= 0xffff).unwrap();
    let chunk = [7u8; 1448];
    let mut buf = [0u8; 4096];
    let (mut seq, mut t, mut tsv) = (sseq, 1020u64, 10u32);
    let (mut edge, mut read) = (sseq, 0u32);
    // Every edge must lie within the ring: its capacity past what was read.
    let absorb = |out: Vec<Out>, edge: &mut u32, read: u32| {
        for o in out.iter().filter(|o| o.flags & flags::ACK != 0) {
            let e = o.ack + (u32::from(o.win) << shift);
            let limit = sseq + read + crate::BUF_CAP as u32;
            assert!(e <= limit, "edge {e} past the receive ring ({limit})");
            *edge = (*edge).max(e);
        }
    };
    // The application reads odd amounts while the peer keeps sending up to
    // the furthest edge ever advertised, so the edge lands on every
    // alignment relative to the scale unit.
    for round in 0..600u32 {
        let mut sent_any = false;
        while seq < edge || (round == 0 && !sent_any) {
            let len = if round == 0 && !sent_any {
                chunk.len()
            } else {
                ((edge - seq) as usize).min(chunk.len())
            };
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
                &chunk[..len],
            ))
            .unwrap();
            seq += len as u32;
            sent_any = true;
            assert_eq!(
                c.debug_snapshot().rcv_nxt,
                seq,
                "bytes sent inside the advertised window were dropped"
            );
            absorb(drain(&mut c), &mut edge, read);
        }
        if round > 0 {
            let want = 997 + (round as usize * 37) % 1500;
            read += c.recv(&mut buf[..want]).unwrap() as u32;
        }
        t += 50;
        c.set_now(t);
        c.tick().unwrap();
        absorb(drain(&mut c), &mut edge, read);
        c.debug_validate_invariants().unwrap();
    }
    // The window kept reopening as the application read.
    assert!(
        edge + 8192 >= sseq + read + crate::BUF_CAP as u32,
        "window stuck: edge {edge}, read {read}"
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

/// Out-of-order data from segments that start after a FIN's own segment is
/// processed after the FIN (RFC 9293 SEG.SEQ order), so it never extends
/// the stream: filling the hole delivers exactly the data before the FIN,
/// then the FIN, and the rest is purged.
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
/// ACK the host hands to a fresh listener (`ListenerBusy`): the spoofed
/// half-open in the slot is live, so it is not given up.
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
            let ack = pkt(
                legit,
                SRV,
                778,
                isn + 1,
                flags::ACK,
                65535,
                &TcpOptions::NONE,
                b"hi",
            );
            let mut conn = hand_off(&mut s, &ack, t, |c| c.set_secret(&[3; 16]));
            assert_eq!(
                conn.state(),
                State::Established,
                "legitimate client locked out"
            );
            assert_eq!(recv_all(&mut conn), b"hi");
            return;
        }
    }
    unreachable!("the flood ran past the legitimate client's ACK");
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
    let third = pkt(
        CLI,
        SRV,
        501,
        synack.seq + 1,
        flags::ACK | flags::PSH,
        65535,
        &ts(101, synack_tsval),
        b"GET /",
    );
    // A listener set up after the rotation gets the old key, then the new.
    let mut s = hand_off(&mut s, &third, 10_050, |t| {
        t.set_cookie_secret(&[1; 16]);
        t.set_cookie_secret(&[2; 16]);
    });
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
/// lost: the clamp stays, the probes back off, and no lost probe costs the
/// window (Linux `tcp_fastretrans_alert`: "MTU probe failure: don't reduce
/// cwnd").
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
    let mut recoveries_at_clamp = 0;
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
        if !clamped && c.stats().mss < 1448 {
            clamped = true;
            recoveries_at_clamp = c.stats().fast_recoveries;
        }
        let _ = c.send(&vec![0u8; 65536]);
    }
    assert!(clamped, "the black hole was detected");
    assert!(c.stats().mss <= 1012, "clamp undone on a real black hole");
    assert!(probes >= 2, "probes were sent ({probes})");
    assert!(probes <= 4, "probes back off ({probes} in 2 min)");
    assert_eq!(
        c.stats().fast_recoveries,
        recoveries_at_clamp,
        "a lost probe cost a fast recovery"
    );
    assert_eq!(c.state(), State::Established);
    assert!(
        after(acked, iss + 100_000),
        "data keeps flowing at the clamped size"
    );
}

// ---------------------------------------------------------------------------
// Window updates, recovery episodes, ECN, path MTU and closing
// ---------------------------------------------------------------------------

/// A reordered ACK repeating the newest SEQ and ACK must not shrink the
/// window: acknowledging nothing new, only a larger or a zero window
/// updates it (Linux `tcp_may_update_window`). Within one millisecond PAWS
/// cannot tell it is stale, and its tiny window stalled the sender.
#[test]
fn reordered_ack_with_a_smaller_window_does_not_shrink_it() {
    let (mut c, sseq, iss) = established_rtt(1000, 0, true, false);
    for win in [8192, 1] {
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            iss + 1,
            flags::ACK,
            win,
            &ts(7, 0),
            &[],
        ))
        .unwrap();
        drain(&mut c);
    }
    c.send(&[0x5a; 1448]).unwrap();
    c.tick().unwrap();
    let sent: usize = drain(&mut c).iter().map(|o| o.len).sum();
    assert_eq!(sent, 1448, "a stale window stalled the sender");
}

/// An ACK reordered behind a newer cumulative ACK still carries news in
/// its SACK blocks (Linux `tcp_ack` processes them on old ACKs): a D-SACK
/// there shows the retransmission needless and undoes the reduction.
#[test]
fn dsack_on_a_reordered_old_ack_undoes_a_spurious_recovery() {
    for old_ack in [false, true] {
        let (mut c, sseq, iss) = established(1000, true, false);
        let burst = ts_burst(&mut c, sseq, iss, 10);
        let end = |k: usize| burst[k].seq + burst[k].len as u32;
        let before = c.stats().cwnd;
        let mut retx = Vec::new();
        for k in 1..=3 {
            retx.extend(
                ts_ack(&mut c, sseq, 1030, iss + 1, 1010, &[(burst[1].seq, end(k))])
                    .into_iter()
                    .filter(|o| o.len > 0),
            );
        }
        assert_eq!(retx.len(), 1);
        ts_ack(&mut c, sseq, 1040, end(9), tsval(&retx[0]), &[]);
        assert!(c.stats().cwnd < before);
        let ack = if old_ack { end(3) } else { end(9) };
        ts_ack(
            &mut c,
            sseq,
            1041,
            ack,
            tsval(&retx[0]),
            &[(burst[0].seq, end(0))],
        );
        assert!(
            c.stats().cwnd >= before,
            "old_ack={old_ack}: the D-SACK did not undo the reduction"
        );
    }
}

/// Reverse traffic acknowledges nothing we sent, so it must not reset the
/// retransmission count black-hole detection reads (Linux resets
/// `icsk_retransmits` only when SND.UNA advances).
#[test]
fn reverse_data_does_not_hide_a_path_mtu_black_hole() {
    for reverse_data in [false, true] {
        let (mut c, sseq, iss) = established(1000, false, false);
        send_burst(&mut c, 1020, 1448);
        let mut smallest = usize::MAX;
        for i in 1..=80u32 {
            c.set_now(1020 + u64::from(i) * 100);
            if reverse_data {
                let p = pkt(
                    SRV,
                    CLI,
                    sseq + i - 1,
                    iss + 1,
                    flags::ACK | flags::PSH,
                    8192,
                    &ts(7 + i, 0),
                    b"x",
                );
                c.inject_packet(&p).unwrap();
                c.recv(&mut [0u8; 1]).unwrap();
            }
            c.tick().unwrap();
            for o in drain(&mut c).into_iter().filter(|o| o.len > 0) {
                smallest = smallest.min(o.len);
            }
        }
        assert!(
            smallest <= 1012,
            "reverse_data={reverse_data}: no fallback after repeated timeouts"
        );
    }
}

/// SACK splits leave the retransmission queue's reserved slot alone: after
/// a path-MTU drop the head needs it to split, or nothing could be resent
/// until an ACK freed one.
#[test]
fn partial_sacks_leave_the_split_reserve_to_retransmissions() {
    let iss = 1_000_000;
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(1000);
    c.connect().unwrap();
    let syn = drain(&mut c);
    let opts = TcpOptions {
        mss: Some(1036),
        wscale: Some(7),
        ts: Some((1, tsval(&syn[0]))),
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    c.set_now(1010);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        SRV_ISS,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &opts,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let sseq = SRV_ISS + 1;
    let mut now = 1020;
    ts_ack(&mut c, sseq, now, iss + 1, 0, &[]);
    while c.stats().cwnd < crate::BUF_CAP as u32 {
        assert!(now < 1050, "failed to grow the test flight");
        c.send(&vec![0x5a; c.stats().cwnd as usize]).unwrap();
        loop {
            c.tick().unwrap();
            if drain(&mut c).is_empty() {
                break;
            }
        }
        now += 1;
        let end = c.debug_snapshot().snd_nxt;
        ts_ack(&mut c, sseq, now, end, 0, &[]);
    }
    let start = c.debug_snapshot().snd_una;
    c.send(&vec![0x5a; 1023 * 1024]).unwrap();
    let mut flight = Vec::new();
    loop {
        c.tick().unwrap();
        let out = drain(&mut c);
        if out.is_empty() {
            break;
        }
        flight.extend(out.into_iter().filter(|o| o.len > 0));
    }
    assert_eq!(flight.len(), 1023);
    assert!(flight.iter().all(|o| o.len == 1024));
    let end = c.debug_snapshot().snd_nxt;
    ts_ack(
        &mut c,
        sseq,
        now + 1,
        start,
        0,
        &[(start + 1024, end - 512)],
    );
    c.update_pmtu(576);
    drain(&mut c);
    let mut retransmitted = 0;
    for _ in 0..4 {
        c.set_now(c.debug_snapshot().rto_deadline);
        c.tick().unwrap();
        retransmitted += drain(&mut c).iter().filter(|o| o.len > 0).count();
        c.debug_validate_invariants().unwrap();
    }
    assert!(retransmitted > 0, "a partial SACK took the last split slot");
}

/// CWR holds until something beyond its reduction point is acknowledged,
/// so our CWR flag has reached the peer: an ECN-Echo for the same marks
/// arriving before that does not reduce again (Linux
/// `tcp_fastretrans_alert`).
#[test]
fn ece_before_our_cwr_reached_the_peer_does_not_reduce_twice() {
    let (mut c, sseq, iss) = established(1000, true, true);
    let b = ts_burst(&mut c, sseq, iss, 10);
    let end = b[9].seq + b[9].len as u32;
    let ece = pkt(
        SRV,
        CLI,
        sseq,
        end,
        flags::ACK | flags::ECE,
        0xffff,
        &ts(8, 1020),
        &[],
    );
    c.set_now(1030);
    c.inject_packet(&ece).unwrap();
    drain(&mut c);
    let reduced = c.stats().ssthresh;
    // The first chance to send CWR; the same ECE again before it arrived.
    send_burst(&mut c, 1031, 5 * 1448);
    c.set_now(1032);
    c.inject_packet(&ece).unwrap();
    drain(&mut c);
    assert_eq!(c.stats().ssthresh, reduced, "one mark reduced twice");
}

/// Every reduction tells an ECN peer it happened (Linux
/// `tcp_ecn_queue_cwr`): the first new data after fast recovery begins
/// carries CWR, so marks the reduction answered stop being echoed.
#[test]
fn fast_recovery_sends_cwr_to_an_ecn_peer() {
    let (mut c, sseq, iss) = established(1000, true, true);
    let b = ts_burst(&mut c, sseq, iss, 10);
    let end = |i: usize| b[i].seq + b[i].len as u32;
    ts_ack(
        &mut c,
        sseq,
        1030,
        b[0].seq,
        tsval(&b[0]),
        &[(b[1].seq, end(8))],
    );
    assert_eq!(c.stats().ca_state, CaState::Recovery as u8);
    c.send(&vec![0x44; 4 * 1448]).unwrap();
    let out = ts_ack(
        &mut c,
        sseq,
        1032,
        b[0].seq,
        tsval(&b[0]),
        &[(b[1].seq, end(9))],
    );
    let new: Vec<&Out> = out
        .iter()
        .filter(|o| o.len > 0 && o.seq >= end(9))
        .collect();
    assert!(!new.is_empty(), "no new data sent");
    assert!(new[0].flags & flags::CWR != 0, "no CWR after the reduction");
}

/// A reduction halves the window in use, capped by the largest window the
/// peer has offered, not by the one it offers now: a reader briefly
/// behind must not deepen it.
#[test]
fn reduction_is_capped_by_the_largest_peer_window_not_the_current_one() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 10);
    let end = |i: usize| b[i].seq + b[i].len as u32;
    let cwnd = c.stats().cwnd;
    // b0 arrives, b1 is lost, and the reader is behind: 2 KiB of window.
    let o = TcpOptions {
        ts: Some((7, tsval(&b[0]))),
        sack: SackBlocks::from_slice(&[(b[2].seq, end(8))]),
        ..TcpOptions::NONE
    };
    c.set_now(1030);
    c.inject_packet(&pkt(SRV, CLI, sseq, end(0), flags::ACK, 16, &o, &[]))
        .unwrap();
    drain(&mut c);
    assert_eq!(c.stats().ca_state, CaState::Recovery as u8);
    assert_eq!(c.stats().ssthresh, cwnd / 2);
}

/// Retransmissions restart the idle clock too (Linux `tcp_event_data_sent`
/// runs for every data segment): a tail loss repaired by a probe is not
/// idleness, so the next request does not restart from a halved window.
#[test]
fn tail_loss_probe_repair_is_not_mistaken_for_idle() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1010, iss + 1, 1000, &[]);
    c.send(&vec![0x5a; 10 * 1448]).unwrap();
    c.set_now(1010);
    c.tick().unwrap();
    let burst: Vec<Out> = drain(&mut c).into_iter().filter(|o| o.len > 0).collect();
    assert_eq!(burst.len(), 10);
    let end = |k: usize| burst[k].seq + burst[k].len as u32;
    ts_ack(&mut c, sseq, 1020, end(8), 1010, &[]);
    let (probe, t_probe) = first_data(&mut c, 1021, 2000);
    assert_eq!(probe.seq, burst[9].seq, "the probe re-sent the tail");
    ts_ack(&mut c, sseq, t_probe + 10, end(9), t_probe as u32, &[]);
    // The next request, 40 ms after the probe: not idle for an RTO.
    c.send(&vec![0x5a; 10 * 1448]).unwrap();
    c.set_now(t_probe + 40);
    c.tick().unwrap();
    drain(&mut c);
    // The application-limited decay (RFC 2861, Linux
    // `tcp_cwnd_application_limited`) still applies; an idle restart
    // would have cut the window back to the initial one.
    assert!(c.stats().cwnd > 10 * 1448, "restarted as if idle");
}

/// A retransmitted SYN drops the ECN-setup flags (RFC 3168 §6.1.1.1,
/// Linux `tcp_ecn_clear_syn`), so a path that drops ECN SYNs still
/// connects.
#[test]
fn retransmitted_syn_falls_back_from_ecn() {
    let mut c = new_tcb(CLI, SRV, 1_000_000);
    c.set_now(1000);
    c.connect().unwrap();
    let syn = drain(&mut c);
    assert_eq!(
        syn[0].flags & (flags::ECE | flags::CWR),
        flags::ECE | flags::CWR
    );
    c.set_now(2000);
    c.tick().unwrap();
    let retx = drain(&mut c);
    assert!(retx.len() == 1 && retx[0].flags & flags::SYN != 0);
    assert_eq!(retx[0].flags & (flags::ECE | flags::CWR), 0);
}

/// A smaller path MTU is not congestion: what no longer fits is resent
/// without reducing the window (Linux `tcp_simple_retransmit`).
#[test]
fn path_mtu_drop_resends_without_reducing_the_window() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1010, iss + 1, 0, &[]);
    let segs = send_burst(&mut c, 1020, 8 * 1448);
    let before = c.stats();
    c.set_now(1022);
    c.update_pmtu(1280);
    assert!(drain(&mut c).iter().any(|o| o.len > 0), "nothing resent");
    ts_ack(&mut c, sseq, 1030, segs[0].1, 0, &[]);
    let s = c.stats();
    assert_eq!(s.fast_recoveries, 0, "taken for congestion");
    assert_eq!(s.ssthresh, before.ssthresh, "ssthresh reduced");
    assert!(s.cwnd >= before.cwnd, "cwnd reduced");
}

/// SACK reneging gives the receiver max(SRTT/2, 10 ms) before the timeout
/// resends; no loss probe may take that timer's place and push the repair
/// back a whole RTO (Linux `tcp_check_sack_reneging` clears
/// `FLAG_SET_XMIT_TIMER`).
#[test]
fn sack_reneging_grace_is_not_lost_to_a_probe() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 4);
    let end = |i: usize| b[i].seq + b[i].len as u32;
    ts_ack(&mut c, sseq, 1028, b[0].seq, 0, &[(b[1].seq, end(2))]);
    ts_ack(&mut c, sseq, 1029, end(0), 0, &[]); // 1 and 2 reneged
    let mut now = 1029;
    loop {
        now += 1;
        assert!(now <= 1040, "reneged data not resent within the grace");
        c.set_now(now);
        c.tick().unwrap();
        if drain(&mut c).iter().any(|o| o.len > 0 && o.seq == b[1].seq) {
            break;
        }
    }
}

/// CLOSE in SYN-RECEIVED (RFC 9293 §3.10.4) sends the FIN at once, but the
/// handshake is not over: a retransmitted SYN gets the SYN-ACK again, the
/// third ACK completes the setup (an RTT sample among it), and a handshake
/// that times out ends the connection the application closed rather than
/// reviving the listener.
#[test]
fn close_in_syn_received_still_completes_or_ends_the_handshake() {
    let opts = TcpOptions {
        mss: Some(1460),
        ts: Some((100, 0)),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    let closed_half_open = |now: u64| {
        let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
        s.set_secret(&[3u8; 16]);
        s.set_now(now);
        s.listen().unwrap();
        s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &opts, &[]))
            .unwrap();
        let synack = drain(&mut s).remove(0);
        s.close().unwrap();
        drain(&mut s);
        assert_eq!(s.state(), State::FinWait1);
        (s, synack)
    };
    let (mut s, synack) = closed_half_open(1000);
    s.set_now(1025);
    let third = pkt(
        CLI,
        SRV,
        78,
        synack.seq + 1,
        flags::ACK,
        65535,
        &ts(125, tsval(&synack)),
        &[],
    );
    s.inject_packet(&third).unwrap();
    drain(&mut s);
    assert_eq!(s.stats().srtt_ms, 25, "the handshake's RTT was not sampled");

    let (mut s, _) = closed_half_open(0);
    s.set_now(600);
    s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &opts, &[]))
        .unwrap();
    assert!(
        drain(&mut s).iter().any(|o| o.flags & flags::SYN != 0),
        "a retransmitted SYN got no SYN-ACK"
    );
    let mut now = 600;
    while s.state() != State::Closed {
        let prev = s.state();
        now += 61_000;
        assert!(now < 2_000_000, "the handshake never timed out");
        s.set_now(now);
        s.tick().unwrap();
        drain(&mut s);
        assert!(
            prev.debug_transition_allowed(s.state()),
            "{prev:?} -> {:?}",
            s.state()
        );
    }
}

/// An unresolved tail loss probe may still fill a hole: its send time stays
/// the timestamp-undo reference, so the probe's own ACK cannot pass for a
/// delayed original's and undo a real reduction.
#[test]
fn unresolved_probe_keeps_the_timestamp_undo_reference() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 3);
    let end = |i: usize| b[i].seq + b[i].len as u32;
    let (probe, t_tlp) = first_data(&mut c, 1020, 1500);
    assert_eq!((c.stats().tlp_count, probe.seq), (1, b[2].seq));
    ts_ack(&mut c, sseq, t_tlp + 5, end(0), tsval(&b[0]), &[]);
    c.send(&vec![0x33; 3 * 1448]).unwrap();
    let more = ts_ack(&mut c, sseq, t_tlp + 10, end(1), tsval(&b[1]), &[]);
    assert_eq!(more.len(), 3);
    let more_end = more[2].seq + more[2].len as u32;
    let retx = ts_ack(
        &mut c,
        sseq,
        t_tlp + 30,
        end(1),
        tsval(&b[1]),
        &[(more[0].seq, more_end)],
    );
    assert!(retx.iter().any(|o| o.len > 0 && o.seq == b[2].seq));
    assert_eq!(c.stats().ca_state, CaState::Recovery as u8);
    let reduced = c.stats().ssthresh;
    // The probe, not a delayed original, filled the hole.
    ts_ack(&mut c, sseq, t_tlp + 35, more_end, tsval(&probe), &[]);
    assert_eq!(c.stats().ssthresh, reduced, "a real loss was undone");
}

/// Once an episode has ended, only D-SACKs for its own retransmissions can
/// still undo it: one for a later probe says nothing about it.
#[test]
fn later_probe_dsack_does_not_undo_an_earlier_episode() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let initial = c.stats().ssthresh;
    let b = ts_burst(&mut c, sseq, iss, 10);
    let end = |i: usize| b[i].seq + b[i].len as u32;
    let out = ts_ack(
        &mut c,
        sseq,
        1030,
        b[0].seq,
        tsval(&b[0]),
        &[(b[1].seq, end(3))],
    );
    let retx0 = out.iter().find(|o| o.len > 0 && o.seq == b[0].seq).unwrap();
    let reduced = c.stats().ssthresh;
    assert!(reduced < initial);
    ts_ack(&mut c, sseq, 1050, end(9), tsval(retx0), &[]);
    assert_eq!(c.stats().ca_state, CaState::Open as u8);
    c.set_now(2000);
    c.send(&[0x77; 1448]).unwrap();
    c.tick().unwrap();
    let seg = drain(&mut c).into_iter().find(|o| o.len > 0).unwrap();
    let seg_end = seg.seq + seg.len as u32;
    let (probe, now) = first_data(&mut c, 2000, 2500);
    assert_eq!(probe.seq, seg.seq);
    let o = TcpOptions {
        ts: Some((50, tsval(&probe))),
        sack: SackBlocks::from_slice(&[(seg.seq, seg_end)]),
        ..TcpOptions::NONE
    };
    c.set_now(now + 5);
    c.inject_packet(&pkt(SRV, CLI, sseq, seg_end, flags::ACK, 0xffff, &o, &[]))
        .unwrap();
    drain(&mut c);
    assert_eq!(
        c.stats().ssthresh,
        reduced,
        "the earlier reduction was undone"
    );
}

/// A loss beyond the recovery point that the episode-ending ACK reveals
/// starts a new episode with its own reduction (Linux checks for the end
/// of an episode before it detects losses); it used to be repaired in the
/// Open state without one.
#[test]
fn loss_found_by_the_ack_ending_recovery_starts_a_new_episode() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 10);
    let end = |i: usize| b[i].seq + b[i].len as u32;
    let out = ts_ack(
        &mut c,
        sseq,
        1030,
        b[0].seq,
        tsval(&b[0]),
        &[(b[1].seq, end(8))],
    );
    let retx0 = out
        .iter()
        .find(|o| o.len > 0 && o.seq == b[0].seq)
        .unwrap()
        .clone();
    assert_eq!(c.stats().ca_state, CaState::Recovery as u8);
    c.send(&vec![0x44; 4 * 1448]).unwrap();
    let more: Vec<Out> = ts_ack(
        &mut c,
        sseq,
        1032,
        b[0].seq,
        tsval(&b[0]),
        &[(b[1].seq, end(9))],
    )
    .into_iter()
    .filter(|o| o.len > 0)
    .collect();
    assert_eq!(more.len(), 4);
    let episodes = c.stats().fast_recoveries;
    // The retransmission ends the episode; the first new segment is gone.
    let sack = [(more[1].seq, more[3].seq + more[3].len as u32)];
    ts_ack(&mut c, sseq, 1039, end(9), tsval(&retx0), &sack);
    assert_eq!(c.stats().ca_state, CaState::Recovery as u8);
    assert_eq!(c.stats().fast_recoveries, episodes + 1);
}

/// In TIME-WAIT, data retransmitted with the FIN is D-SACKed like any
/// duplicate, not just re-ACKed.
#[test]
fn time_wait_dsacks_data_retransmitted_with_the_fin() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    c.close().unwrap();
    drain(&mut c);
    c.set_now(1030);
    let data_fin = pkt(
        SRV,
        CLI,
        sseq,
        iss + 2,
        flags::ACK | flags::FIN | flags::PSH,
        8192,
        &ts(5, 0),
        &[0xab; 100],
    );
    c.inject_packet(&data_fin).unwrap();
    drain(&mut c);
    assert_eq!(c.state(), State::TimeWait);
    c.set_now(1050);
    c.inject_packet(&data_fin).unwrap();
    let out = drain(&mut c);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].opts.sack.as_slice(), &[(sseq, sseq + 100)]);
    assert_eq!(c.stats().dup_bytes_received, 100);
}

/// `min_rtt` times the newest segment an ACK covers (Linux `ca_rtt_us`):
/// the oldest one's time includes how long the application took to write
/// the next.
#[test]
fn min_rtt_times_the_newest_acknowledged_segment() {
    let (mut c, sseq, _) = established_rtt(1000, 20, true, false);
    assert_eq!(c.stats().min_rtt_ms, 20);
    let seg0 = send_burst(&mut c, 2000, 1448);
    let seg1 = send_burst(&mut c, 2015, 1448);
    assert_eq!((seg0.len(), seg1.len()), (1, 1));
    ts_ack(&mut c, sseq, 2016, seg1[0].1, 0, &[]);
    assert_eq!(c.stats().min_rtt_ms, 1);
}

/// A path-MTU probe counts as delivered only when all of it is: a SACK
/// block for part of it proves nothing about the larger size.
#[test]
fn partial_sack_of_a_path_mtu_probe_is_not_its_delivery() {
    let (mut c, sseq, iss) = established(1000, true, false);
    send_burst(&mut c, 1020, 1448);
    let mut now = 1020u64;
    for _ in 0..4 {
        now += 61_000;
        c.set_now(now);
        c.tick().unwrap();
        drain(&mut c);
    }
    assert_eq!(c.stats().mss, 1012, "the black hole was detected");
    now += 10;
    ts_ack(&mut c, sseq, now, iss + 1 + 1448, 0, &[]);
    now += 9_995;
    let pre = send_burst(&mut c, now, 1012);
    assert_eq!(pre[0].1 - pre[0].0, 1012);
    now += 10;
    c.set_now(now);
    c.send(&vec![0x55; 6000]).unwrap();
    c.tick().unwrap();
    let sent: Vec<Out> = drain(&mut c).into_iter().filter(|o| o.len > 0).collect();
    assert_eq!(sent[0].len, 1448, "a probe went out");
    let probe = sent[0].seq;
    ts_ack(&mut c, sseq, now + 5, pre[0].0, 0, &[(probe, probe + 500)]);
    assert_eq!(c.stats().mss, 1012, "raised on part of the probe");
}

/// A SYN-cookie handshake turns timestamps on only if our SYN-ACK carried
/// them (RFC 7323 §3.2): the cookie's MAC records whether it did, so a
/// TSopt on the third ACK, zero or not, cannot switch on timestamps or the
/// window scaling, SACK and ECN bits a TSecr would carry.
#[test]
fn cookie_handshake_ignores_timestamps_the_syn_ack_lacked() {
    for tsecr in [0, 0x3e] {
        let mut s = new_tcb(SRV, ([0; 4], 0), 1);
        s.set_secret(&[1; 16]);
        s.set_now(10_000);
        s.listen().unwrap();
        let no_ts = TcpOptions {
            mss: Some(1460),
            ..TcpOptions::NONE
        };
        s.inject_packet(&pkt(ATTACKER, SRV, 9, 0, flags::SYN, 65535, &no_ts, &[]))
            .unwrap();
        drain(&mut s);
        s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &no_ts, &[]))
            .unwrap();
        let synack = drain(&mut s).remove(0);
        assert!(synack.opts.ts.is_none());
        s.set_now(10_020);
        let ack = pkt(
            CLI,
            SRV,
            501,
            synack.seq + 1,
            flags::ACK | flags::PSH,
            65535,
            &ts(123, tsecr),
            b"hi",
        );
        let mut s = hand_off(&mut s, &ack, 10_020, |t| t.set_secret(&[1; 16]));
        assert_eq!(s.state(), State::Established, "tsecr {tsecr:#x}");
        drain(&mut s);
        let snap = s.debug_snapshot();
        assert_eq!(
            s.stats().mss,
            1460,
            "tsecr {tsecr:#x}: timestamps turned on"
        );
        assert_eq!(
            snap.snd_wnd, 65535,
            "tsecr {tsecr:#x}: window scaling turned on"
        );
    }
}

// ---------------------------------------------------------------------------
// Receive path, resets and retransmission-queue limits (audit iteration 3)
// ---------------------------------------------------------------------------

/// A FIN held out of order is SACKed with the data (Linux reports a
/// segment's `end_seq`, FIN included), so the sender's RACK can see what
/// is missing before it.
#[test]
fn out_of_order_fin_is_sacked() {
    for len in [0usize, 100] {
        let (mut c, seq, iss) = established_rtt(1000, 1, true, false);
        c.set_now(1002);
        let fin = pkt(
            SRV,
            CLI,
            seq + 1448,
            iss + 1,
            flags::ACK | flags::FIN,
            8192,
            &ts(2, 0),
            &vec![0x5a; len],
        );
        c.inject_packet(&fin).unwrap();
        let out = drain(&mut c);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ack, seq);
        assert_eq!(
            out[0].opts.sack.as_slice(),
            &[(seq + 1448, seq + 1449 + len as u32)],
            "{len} bytes + FIN"
        );
    }
}

/// Out-of-order data partly overlapping data already held gets a D-SACK
/// for the overlap, ahead of the block it joins (Linux
/// `tcp_data_queue_ofo`).
#[test]
fn partial_out_of_order_overlap_is_dsacked() {
    let (mut c, sseq, iss) = established_rtt(1000, 0, true, false);
    for (seq, len) in [(sseq + 500, 1000), (sseq + 1000, 1000)] {
        let p = pkt(
            SRV,
            CLI,
            seq,
            iss + 1,
            flags::ACK,
            8192,
            &ts(2, 1000),
            &vec![0x55; len],
        );
        c.inject_packet(&p).unwrap();
        let out = drain(&mut c);
        if seq == sseq + 1000 {
            assert_eq!(
                out[0].opts.sack.as_slice(),
                &[(sseq + 1000, sseq + 1500), (sseq + 500, sseq + 2000)]
            );
            assert_eq!(c.stats().dup_bytes_received, 500);
        }
    }
}

/// A peer's RST purges what we had to send, not what we received (Linux
/// `tcp_reset`): bytes that already arrived stay readable, with or without
/// the peer's FIN, and the reset is reported after the last of them.
#[test]
fn peer_reset_keeps_received_data_readable() {
    for fin in [false, true] {
        let (mut c, sseq, iss) = established(1000, true, false);
        let body = b"response already delivered to TCP";
        let fl = flags::ACK | flags::PSH | if fin { flags::FIN } else { 0 };
        c.set_now(1002);
        c.inject_packet(&pkt(SRV, CLI, sseq, iss + 1, fl, 8192, &ts(2, 0), body))
            .unwrap();
        drain(&mut c);
        let rst = sseq + body.len() as u32 + u32::from(fin);
        c.inject_packet(&pkt(
            SRV,
            CLI,
            rst,
            0,
            flags::RST,
            0,
            &TcpOptions::NONE,
            &[],
        ))
        .unwrap();
        assert_eq!(c.state(), State::Closed);
        let mut buf = [0u8; 64];
        assert_eq!(c.recv(&mut buf), Ok(body.len()), "fin={fin}");
        assert_eq!(&buf[..body.len()], body);
        assert_eq!(c.recv(&mut buf), Err(TcpError::ConnectionReset));
    }
}

/// RACK's tick of slack for a retransmission SACKed within the millisecond
/// it left holds after the path has shown reordering too: a lost
/// retransmission ahead of it is repaired by RACK, not the RTO, whichever
/// side of a millisecond boundary the ACK falls.
#[test]
fn sub_millisecond_lost_retransmission_after_reordering_is_repaired_by_rack() {
    for (reordered, ack_at) in [(false, 1013), (true, 1014), (true, 1013)] {
        let (mut c, sseq, iss) = established_rtt(1000, 0, true, false);
        ts_ack(&mut c, sseq, 1000, iss + 1, 1000, &[]);
        let warmup = send_burst(&mut c, 1000, 3 * 1448);
        if reordered {
            ts_ack(&mut c, sseq, 1000, iss + 1, 1000, &[warmup[1]]);
        }
        ts_ack(&mut c, sseq, 1000, warmup[2].1, 1000, &[]);
        let lost = send_burst(&mut c, 1010, 3 * 1448);
        let tail = send_burst(&mut c, 1013, 7 * 1448);
        assert_eq!((lost.len(), tail.len()), (3, 7));
        let sack = [(tail[0].0, tail[6].1)];
        let retx = ts_ack(&mut c, sseq, 1013, lost[0].0, 1000, &sack);
        assert_eq!(retx.iter().filter(|o| o.len > 0).count(), 3);
        // The first retransmission is lost again; the other two arrive.
        let sack = [(lost[1].0, tail[6].1)];
        let out = ts_ack(&mut c, sseq, ack_at, lost[0].0, 1000, &sack);
        let repair = match out.into_iter().find(|o| o.len > 0) {
            Some(o) => o,
            None => first_data(&mut c, ack_at, 2000).0,
        };
        assert_eq!(repair.seq, lost[0].0);
        assert_eq!(
            c.stats().rto_count,
            0,
            "reordered={reordered}, ACK at {ack_at}"
        );
    }
}

/// A path MTU that shrinks again before anything is acknowledged needs a
/// split for every retransmission. With the queue full and its spare
/// record spent, merging two newer records frees one, rather than leaving
/// the head unsendable at every timeout.
#[cfg(not(feature = "small-buffers"))]
#[test]
fn repeated_path_mtu_drops_with_a_full_queue_keep_retransmitting() {
    let iss = 1_000_000;
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(1000);
    c.connect().unwrap();
    let syn = drain(&mut c);
    let opts = TcpOptions {
        mss: Some(1036),
        wscale: Some(7),
        ts: Some((1, tsval(&syn[0]))),
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    c.set_now(1010);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        SRV_ISS,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &opts,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let sseq = SRV_ISS + 1;
    let mut now = 1020;
    ts_ack(&mut c, sseq, now, iss + 1, 0, &[]);
    while c.stats().cwnd < crate::BUF_CAP as u32 {
        assert!(now < 1050, "failed to grow the test flight");
        c.send(&vec![0x5a; c.stats().cwnd as usize]).unwrap();
        loop {
            c.tick().unwrap();
            if drain(&mut c).is_empty() {
                break;
            }
        }
        now += 1;
        let end = c.debug_snapshot().snd_nxt;
        ts_ack(&mut c, sseq, now, end, 0, &[]);
    }
    assert_eq!(c.send(&vec![0x5a; 1023 * 1024]), Ok(1023 * 1024));
    let mut flight = 0;
    loop {
        c.tick().unwrap();
        let out = drain(&mut c);
        if out.is_empty() {
            break;
        }
        flight += out.iter().filter(|o| o.len > 0).count();
    }
    assert_eq!(flight, 1023);
    c.update_pmtu(900);
    drain(&mut c);
    c.update_pmtu(576);
    let mut out = drain(&mut c);
    for _ in 0..3 {
        c.set_now(c.debug_snapshot().rto_deadline);
        c.tick().unwrap();
        out.extend(drain(&mut c));
        c.debug_validate_invariants().unwrap();
    }
    assert!(
        out.iter().any(|o| o.len > 0 && o.total_len <= 576),
        "nothing fit the path: {:?}",
        c.stats()
    );
}

/// A FIN whose ACK was lost is retransmitted with backoff; each copy is
/// answered at once in every state that has consumed it (Linux
/// `tcp_data_queue`), not only in TIME_WAIT, so it is not left to the
/// out-of-window limiter (one ACK per 500 ms) while the peer backs off.
#[test]
fn retransmitted_fin_is_acked_at_once_in_every_state_that_consumed_it() {
    for state in [State::CloseWait, State::LastAck, State::Closing] {
        let (mut c, sseq, iss) = established(1000, true, false);
        let fin = |c: &mut Tcb, now: u64, tsv: u32| {
            c.set_now(now);
            let p = pkt(
                SRV,
                CLI,
                sseq,
                iss + 1,
                flags::ACK | flags::FIN,
                8192,
                &ts(tsv, 0),
                &[],
            );
            c.inject_packet(&p).unwrap();
            drain(c)
        };
        if state == State::Closing {
            c.close().unwrap();
            drain(&mut c);
        }
        assert_eq!(fin(&mut c, 1100, 10).len(), 1);
        if state == State::LastAck {
            c.close().unwrap();
            drain(&mut c);
        }
        assert_eq!(c.state(), state);
        // Our ACKs are lost; the peer retransmits 200 ms, then 400 ms later.
        for (now, tsv) in [(1300, 11), (1700, 12)] {
            let out = fin(&mut c, now, tsv);
            assert_eq!(c.state(), state);
            assert_eq!(
                out.len(),
                1,
                "{state:?}: retransmitted FIN at {now} ms not ACKed"
            );
            assert_eq!(out[0].ack, sseq + 1);
        }
    }
}

/// Linux `tcp_reset_check`: after the peer's FIN, a RST carrying the FIN's
/// own sequence number (RCV.NXT − 1), as a stack that aborts right after
/// closing sends, resets in CLOSE_WAIT, LAST_ACK and CLOSING. It was
/// dropped as out of window, leaving the connection to the application's
/// close or to keepalive.
#[test]
fn reset_at_the_peer_fin_sequence_resets_after_its_fin() {
    for state in [State::CloseWait, State::LastAck, State::Closing] {
        let (mut c, sseq, iss) = established(1000, true, false);
        if state == State::Closing {
            c.close().unwrap();
        }
        c.set_now(1100);
        let fin = pkt(
            SRV,
            CLI,
            sseq,
            iss + 1,
            flags::ACK | flags::FIN,
            8192,
            &ts(10, 0),
            &[],
        );
        c.inject_packet(&fin).unwrap();
        if state == State::LastAck {
            c.close().unwrap();
        }
        assert_eq!(c.state(), state);
        drain(&mut c);
        let rst = |c: &mut Tcb, seq: u32| {
            let p = pkt(SRV, CLI, seq, 0, flags::RST, 0, &TcpOptions::NONE, &[]);
            c.inject_packet(&p).unwrap();
        };
        c.set_now(1105);
        rst(&mut c, sseq - 1);
        assert_eq!(
            c.state(),
            state,
            "a RST below the FIN's sequence number reset"
        );
        rst(&mut c, sseq);
        assert_eq!(c.state(), State::Closed, "{state:?}");
    }
}

/// RFC 5961 §3.2 as Linux extends it (`tcp_validate_incoming`): with
/// out-of-order data held, a RST at the right edge of the SACK blocks we
/// report resets too — the peer's SND.NXT when what preceded a hole was
/// lost — a held FIN included; elsewhere in the window it draws a
/// challenge ACK.
#[test]
fn reset_at_the_right_edge_of_our_sack_blocks_resets() {
    for fin in [false, true] {
        let (mut c, sseq, iss) = established(1000, true, false);
        c.set_now(1100);
        let fl = flags::ACK | if fin { flags::FIN } else { 0 };
        let ooo = pkt(
            SRV,
            CLI,
            sseq + 100,
            iss + 1,
            fl,
            8192,
            &ts(10, 0),
            &[7; 200],
        );
        c.inject_packet(&ooo).unwrap();
        let edge = sseq + 300 + u32::from(fin);
        let out = drain(&mut c);
        assert_eq!(
            out.last().unwrap().opts.sack.as_slice(),
            &[(sseq + 100, edge)]
        );
        let rst = |c: &mut Tcb, seq: u32| {
            let p = pkt(SRV, CLI, seq, 0, flags::RST, 0, &TcpOptions::NONE, &[]);
            c.inject_packet(&p).unwrap();
            drain(c)
        };
        c.set_now(1105);
        assert_eq!(rst(&mut c, edge - 1).len(), 1, "fin={fin}: challenge ACK");
        assert_eq!(c.state(), State::Established);
        rst(&mut c, edge);
        assert_eq!(c.state(), State::Closed, "fin={fin}");
    }
}

/// An ACK due now goes on its own, ahead of the data its segment releases;
/// Linux lets the data carry it (`tcp_data_snd_check` before
/// `tcp_ack_snd_check`). Only a data-less ACK counts as a duplicate (RFC
/// 5681 §2): a sender that recovers by duplicate ACKs alone (smoltcp
/// resets its count on any segment with data) saw them ride on our data and
/// stalled on its timeout in two-way lossy transfers (the shootout's
/// kitchen sink: 0.87 s → 1.89 s).
#[test]
fn an_ack_due_now_goes_alone_ahead_of_data() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 1010, &[]);
    c.send(&vec![0x5a; 40 * 1448]).unwrap();
    c.tick().unwrap();
    let burst: Vec<Out> = drain(&mut c).into_iter().filter(|o| o.len > 0).collect();
    assert_eq!(burst.len(), 10);
    c.set_now(1030);
    let acked = burst[1].seq + burst[1].len as u32;
    let o = ts(8, tsval(&burst[1]));
    let data = pkt(SRV, CLI, sseq, acked, flags::ACK, 0xffff, &o, &[7u8; 1448]);
    c.inject_packet(&data).unwrap();
    let out = drain(&mut c);
    let summary: Vec<(usize, u32)> = out.iter().map(|o| (o.len, o.ack)).collect();
    assert_eq!(summary.first(), Some(&(0, sseq + 1448)), "{summary:?}");
    assert!(out.iter().skip(1).any(|o| o.len > 0), "{summary:?}");
}

/// RACK's ambiguity filter (Linux `tcp_rack_advance`) on a millisecond
/// clock: a retransmission cumulatively ACKed within the millisecond it
/// left reads 0 ms against a `min_rtt` floored at 1. When it left in a
/// later millisecond than the original, an echo of its TSval proves it is
/// what arrived, so RACK advances and finds the tail lost behind it at
/// once, not at the RTO.
#[test]
fn sub_millisecond_cumulative_ack_of_a_retransmission_advances_rack() {
    let (mut c, sseq, iss) = established_rtt(1000, 0, true, false);
    let b = ts_burst(&mut c, sseq, iss, 10);
    let end = |i: usize| b[i].seq + b[i].len as u32;
    // Segments 0 and 9 are lost; 1..=8 are SACKed a millisecond later.
    let out = ts_ack(
        &mut c,
        sseq,
        1021,
        b[0].seq,
        tsval(&b[0]),
        &[(b[1].seq, end(8))],
    );
    let retx = out.iter().find(|o| o.len > 0 && o.seq == b[0].seq);
    let retx = retx.expect("segment 0 fast-retransmitted");
    let out = ts_ack(&mut c, sseq, 1021, end(8), tsval(retx), &[]);
    assert!(
        out.iter().any(|o| o.len > 0 && o.seq == b[9].seq),
        "the tail behind the retransmission was not found lost"
    );
    assert_eq!(c.stats().rto_count, 0);
}

/// Loss recovery's resends go out before the segment's text is taken
/// (Linux `tcp_xmit_recovery` at the end of `tcp_ack`), carrying the ACK
/// as it stood; the ACK the text earns follows on new data or a pure ACK.
/// A spurious resend the peer discards as old used to carry it away, and
/// the peer's data waited for its tail loss probe.
#[test]
fn recovery_resends_do_not_carry_away_the_ack_their_segment_earned() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let (seq, now) = spend_quick_acks(&mut c, sseq, iss + 1, 1020);
    let b = send_burst(&mut c, now + 10, 4 * 1448);
    // The peer's data arrives with SACKs that make segment 0 look lost.
    let o = TcpOptions {
        ts: Some((6, (now + 10) as u32)),
        sack: SackBlocks::from_slice(&[(b[1].0, b[3].1)]),
        ..TcpOptions::NONE
    };
    c.set_now(now + 20);
    let data = pkt(
        SRV,
        CLI,
        seq,
        b[0].0,
        flags::ACK | flags::PSH,
        0xffff,
        &o,
        &[0xab; 100],
    );
    c.inject_packet(&data).unwrap();
    let out = drain(&mut c);
    let resend = out.iter().find(|p| p.len > 0 && p.seq == b[0].0);
    assert_eq!(
        resend.map(|p| p.ack),
        Some(seq),
        "the resend carries the ACK as it stood"
    );
    // The resend was spurious: the peer had segment 0 and drops it.
    ts_ack(
        &mut c,
        seq + 100,
        now + 25,
        b[3].1,
        (now + 10) as u32,
        &[b[0]],
    );
    let mut acked = out.iter().any(|p| p.ack == seq + 100);
    for t in (now + 26)..=(now + 70) {
        c.set_now(t);
        c.tick().unwrap();
        acked |= drain(&mut c).iter().any(|p| p.ack == seq + 100);
    }
    assert!(acked, "the peer's 100 bytes were never acknowledged");
}

/// A burst stopped by a full egress ring, not by the windows, is not
/// application limited: after an RTO of light use, a write of a full
/// window used to decay cwnd (Linux `tcp_cwnd_application_limited`) on
/// its first ring-full of segments, before the host could drain the rest.
#[test]
fn a_full_egress_ring_mid_burst_is_not_application_limited() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let mut now = 1020u64;
    ts_ack(&mut c, sseq, now, iss + 1, 1000, &[]);
    for _ in 0..3 {
        let w = c.stats().cwnd as usize;
        c.send(&vec![0x5a; w]).unwrap();
        while !{
            c.tick().unwrap();
            drain(&mut c).is_empty()
        } {}
        now += 10;
        let nxt = c.debug_snapshot().snd_nxt;
        ts_ack(&mut c, sseq, now, nxt, (now - 10) as u32, &[]);
    }
    let cwnd = c.stats().cwnd;
    assert!(cwnd >= 64 * 1448, "cwnd {cwnd} fits the egress ring");
    let rto = u64::from(c.stats().rto_ms);
    now += rto / 2;
    let seg = send_burst(&mut c, now, 1448);
    now += 10;
    ts_ack(&mut c, sseq, now, seg[0].1, (now - 10) as u32, &[]);
    now += rto / 2 + 10;
    c.set_now(now);
    c.send(&vec![0x5a; cwnd as usize]).unwrap();
    let mut sent = 0usize;
    loop {
        c.tick().unwrap();
        let batch = drain(&mut c);
        if batch.is_empty() {
            break;
        }
        sent += batch.iter().map(|o| o.len).sum::<usize>();
    }
    assert_eq!(c.stats().cwnd, cwnd, "a ring-full mid-burst decayed cwnd");
    assert_eq!(sent as u32, cwnd);
}

/// Closed in SYN-RECEIVED (our FIN out, our SYN unacknowledged), an ACK
/// must still cover the SYN, as in SYN-RECEIVED itself (Linux
/// `tcp_check_req`): one at our ISS acknowledges nothing the peer could
/// have seen, and its text and FIN used to be taken.
#[test]
fn ack_of_nothing_after_close_in_syn_rcvd_is_rejected() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_secret(&[3u8; 16]);
    s.set_now(1000);
    s.listen().unwrap();
    let syn = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    let synack = drain(&mut s).remove(0);
    s.close().unwrap();
    drain(&mut s);
    assert_eq!(s.state(), State::FinWait1);
    let fl = flags::ACK | flags::FIN;
    let bogus = pkt(
        CLI,
        SRV,
        78,
        synack.seq,
        fl,
        65535,
        &TcpOptions::NONE,
        b"spoof",
    );
    s.inject_packet(&bogus).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(
        s.recv(&mut buf),
        Ok(0),
        "text taken before the SYN was acknowledged"
    );
    assert_eq!(s.state(), State::FinWait1);
    // The real third ACK still completes the handshake (and ACKs our FIN).
    let ack = pkt(
        CLI,
        SRV,
        78,
        synack.seq + 2,
        flags::ACK,
        65535,
        &TcpOptions::NONE,
        &[],
    );
    s.inject_packet(&ack).unwrap();
    assert_eq!(s.state(), State::FinWait2);
}

/// A SYN with a new ISN in SYN-RECEIVED, from the half-open's own peer
/// (it gave up and opened again from the same port), was ignored, leaving
/// the peer to wait out our SYN-ACK retries. Outside the window it now
/// draws a (rate-limited) ACK, as Linux `tcp_check_req` sends, which the
/// peer answers with a RST that frees the half-open; inside the window the
/// half-open returns to LISTEN (RFC 9293 §3.10.7.4).
#[test]
fn new_isn_syn_in_syn_rcvd_is_answered() {
    for (isn, in_window) in [(0x4000_0000u32, false), (5_000, true)] {
        let syn = TcpOptions {
            mss: Some(1460),
            ..TcpOptions::NONE
        };
        let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
        s.set_secret(&[3u8; 16]);
        s.set_now(2000);
        s.listen().unwrap();
        s.inject_packet(&pkt(CLI, SRV, 100, 0, flags::SYN, 65535, &syn, &[]))
            .unwrap();
        drain(&mut s);
        assert_eq!(s.state(), State::SynRcvd);
        s.set_now(2600);
        s.inject_packet(&pkt(CLI, SRV, isn, 0, flags::SYN, 65535, &syn, &[]))
            .unwrap();
        let out = drain(&mut s);
        if in_window {
            assert!(out.is_empty(), "{out:?}");
            assert_eq!(s.state(), State::Listen);
        } else {
            assert!(
                out.iter().any(|o| o.flags == flags::ACK && o.ack == 101),
                "new-ISN SYN not challenged: {out:?}"
            );
            assert_eq!(s.state(), State::SynRcvd);
        }
    }
}

/// An ACK that both shows a tail loss probe needless (its D-SACK) and
/// starts fast recovery: the probe is settled first, as Linux runs
/// `tcp_process_tlp_ack` before `tcp_fastretrans_alert`, so the recovery's
/// undo does not wait on a D-SACK for the probe that already came.
#[test]
fn a_probe_settled_by_the_ack_that_starts_recovery_does_not_block_its_undo() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let b = ts_burst(&mut c, sseq, iss, 2);
    let end = |v: &[Out], i: usize| v[i].seq + v[i].len as u32;
    let (probe, t) = first_data(&mut c, 1020, 1500);
    assert_eq!((c.stats().tlp_count, probe.seq), (1, b[1].seq));
    c.send(&vec![0x44; 4 * 1448]).unwrap();
    let m: Vec<Out> = ts_ack(&mut c, sseq, t + 5, end(&b, 1), tsval(&b[1]), &[])
        .into_iter()
        .filter(|o| o.len > 0)
        .collect();
    assert_eq!(m.len(), 4);
    let before = c.stats().ssthresh;
    let blocks = [(b[1].seq, end(&b, 1)), (m[1].seq, end(&m, 3))];
    let retx: Vec<Out> = ts_ack(&mut c, sseq, t + 15, end(&b, 1), tsval(&probe), &blocks)
        .into_iter()
        .filter(|o| o.len > 0)
        .collect();
    assert!(retx.iter().any(|o| o.seq == m[0].seq));
    assert_eq!(c.stats().ca_state, CaState::Recovery as u8);
    // Segment m[0] was only late: its resend is D-SACKed.
    let dsack = [(m[0].seq, end(&m, 0))];
    ts_ack(&mut c, sseq, t + 25, end(&m, 3), tsval(&retx[0]), &dsack);
    assert_eq!(c.stats().ssthresh, before, "spurious recovery kept");
}

/// Loss found during an ECN reduction while CWR is held exactly at its
/// recovery point: fast recovery covers what was sent up to the loss (RFC
/// 6675 `RecoveryPoint = HighData`). Keeping CWR's point, as Linux does,
/// ended recovery on the next duplicate ACK and reduced again for the same
/// loss.
#[test]
fn loss_during_an_ecn_reduction_reduces_once() {
    let (mut c, sseq, iss) = established(1000, true, true);
    let b = ts_burst(&mut c, sseq, iss, 10);
    let end = |v: &[Out], i: usize| v[i].seq + v[i].len as u32;
    let cwr_point = end(&b, 9);
    c.set_now(1030);
    let ece = pkt(
        SRV,
        CLI,
        sseq,
        end(&b, 5),
        flags::ACK | flags::ECE,
        0xffff,
        &ts(8, 1020),
        &[],
    );
    c.inject_packet(&ece).unwrap();
    drain(&mut c);
    assert_eq!(c.stats().ca_state, CaState::Cwr as u8);
    let ssthresh = c.stats().ssthresh;
    c.send(&vec![0x55; 6 * 1448]).unwrap();
    let m: Vec<Out> = ts_ack(&mut c, sseq, 1035, cwr_point, 1020, &[])
        .into_iter()
        .filter(|o| o.len > 0)
        .collect();
    assert!(m.len() >= 4);
    assert_eq!(c.stats().ca_state, CaState::Cwr as u8, "held at its point");
    for now in [1045, 1046] {
        ts_ack(
            &mut c,
            sseq,
            now,
            cwr_point,
            1035,
            &[(m[1].seq, end(&m, 3))],
        );
        let s = c.stats();
        assert_eq!(s.ca_state, CaState::Recovery as u8, "at {now}");
        assert_eq!((s.fast_recoveries, s.ssthresh), (1, ssthresh), "at {now}");
    }
}

/// TSecr times a retransmission only if it echoes a time since the
/// connection began, as the handshake requires: the peer controls it, and
/// an echo from before the connection pinned the RTO near its 60 s cap.
#[test]
fn timestamp_echo_before_the_connection_gives_no_rtt_sample() {
    let (mut c, sseq, _) = established(1000, true, false);
    let segs = send_burst(&mut c, 3000, 1448);
    let mut now = 3000u64;
    while !drain(&mut c).iter().any(|o| o.len > 0) {
        now += 5;
        c.set_now(now);
        c.tick().unwrap();
    }
    c.set_now(now + 30);
    let forged = (now as u32 + 30).wrapping_sub(59_000);
    let ack = pkt(
        SRV,
        CLI,
        sseq,
        segs[0].1,
        flags::ACK,
        8192,
        &ts(10, forged),
        &[],
    );
    c.inject_packet(&ack).unwrap();
    drain(&mut c);
    assert!(c.stats().rto_ms < 2_000, "RTO {} ms", c.stats().rto_ms);
}

/// A D-SACK can only name data that was sent: one below what has been
/// sent and acknowledged (here, below our ISS) is ignored, like an ACK of
/// it (see `ack_of_bytes_never_sent_is_rejected`).
#[test]
fn dsack_below_the_data_ever_sent_is_ignored() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let segs = send_burst(&mut c, 3000, 1448);
    let mut now = 3000u64;
    while !drain(&mut c).iter().any(|o| o.len > 0) {
        now += 5;
        c.set_now(now);
        c.tick().unwrap();
    }
    let never_sent = (iss.wrapping_sub(100_000), iss.wrapping_sub(99_000));
    ts_ack(&mut c, sseq, now + 40, segs[0].1, now as u32, &[never_sent]);
    assert_eq!(c.stats().dsacks_received, 0);
}

// ---------------------------------------------------------------------------
// F-RTO, RTT samples, timers, listeners and egress (audit iteration 4)
// ---------------------------------------------------------------------------

/// Tick until a tick sends nothing more.
fn send_until_quiet(c: &mut Tcb) {
    loop {
        c.tick().unwrap();
        if drain(c).is_empty() {
            return;
        }
    }
}

/// A spurious timeout on a connection without timestamps or SACK (as
/// Windows peers default to): a two-segment flight, the second short, with
/// one more byte queued behind it. Returns what the first ACK after the
/// timeout (covering the resend) sent, where new data starts, and ssthresh
/// before the timeout and after the next original's ACK.
fn frto_short_probe(nodelay: bool) -> (Vec<Out>, u32, u32, u32) {
    let (iss, sseq) = (1_000_000, SRV_ISS + 1);
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(1000);
    c.connect().unwrap();
    drain(&mut c);
    let opts = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ..TcpOptions::NONE
    };
    c.set_now(1010);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        SRV_ISS,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &opts,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    c.set_nodelay(nodelay);
    // A 2816-byte window: one full segment and a short one.
    c.set_now(1020);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        22,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let original = send_burst(&mut c, 1020, 22 * 128);
    assert_eq!(original.len(), 2);
    let new_start = original[1].1;
    c.send(&[0x6b]).unwrap();
    c.tick().unwrap();
    assert!(drain(&mut c).iter().all(|o| o.len == 0), "window not full");
    let before = c.stats().ssthresh;
    let (_, now) = until_rto(&mut c, 1020, original[0].0);
    let ack = |c: &mut Tcb, now: u64, a: u32| {
        c.set_now(now);
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            a,
            flags::ACK,
            65535,
            &TcpOptions::NONE,
            &[],
        ))
        .unwrap();
        drain(c)
    };
    let out = ack(&mut c, now + 1, original[0].1);
    ack(&mut c, now + 2, new_start);
    (out, new_start, before, c.stats().ssthresh)
}

/// F-RTO step 2.b (Linux `tcp_process_loss`, `tcp_xmit_recovery` with
/// `REXMIT_NEW`): the ACK that covers only the resend sends new data in
/// place of the next presumed-lost segment — even a runt Nagle would hold
/// back (Linux pushes it with `TCP_NAGLE_OFF`) — and nothing else, so the
/// next ACK can tell. Here it covers the second original, never resent:
/// the timeout is undone.
#[test]
fn frto_probes_with_new_data_alone_even_under_nagle() {
    for nodelay in [false, true] {
        let (out, new_start, before, after) = frto_short_probe(nodelay);
        let data: Vec<(u32, usize)> = out
            .iter()
            .filter(|o| o.len > 0)
            .map(|o| (o.seq, o.len))
            .collect();
        assert_eq!(data, [(new_start, 1)], "nodelay {nodelay}");
        assert_eq!(after, before, "nodelay {nodelay}: spurious timeout kept");
    }
}

/// The hold on resends lasts until the next ACK, not just the send of the
/// ACK that started it: ticks in between resend nothing either (Linux
/// resends from `tcp_xmit_recovery` and its timers, never from
/// `tcp_write_xmit`).
#[test]
fn frto_holds_resends_through_ticks_until_the_next_ack() {
    let iss = 1_000_000;
    let sseq = SRV_ISS + 1;
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(1000);
    c.connect().unwrap();
    drain(&mut c);
    let opts = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    c.set_now(1010);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        SRV_ISS,
        iss + 1,
        flags::SYN | flags::ACK,
        65535,
        &opts,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let burst = send_burst(&mut c, 1020, 3 * 1460);
    assert_eq!(burst.len(), 3);
    let new_start = burst[2].1;
    let (_, now) = until_rto(&mut c, 1020, burst[0].0);
    c.send(&[0x5b; 200]).unwrap();
    let ack = |c: &mut Tcb, now: u64, a: u32| {
        c.set_now(now);
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            a,
            flags::ACK,
            65535,
            &TcpOptions::NONE,
            &[],
        ))
        .unwrap();
        drain(c)
    };
    let mut sent: Vec<(u32, usize)> = ack(&mut c, now + 1, burst[0].1)
        .iter()
        .filter(|o| o.len > 0)
        .map(|o| (o.seq, o.len))
        .collect();
    for t in now + 2..=now + 3 {
        c.set_now(t);
        c.tick().unwrap();
        sent.extend(
            drain(&mut c)
                .iter()
                .filter(|o| o.len > 0)
                .map(|o| (o.seq, o.len)),
        );
    }
    assert_eq!(sent, [(new_start, 200)]);
    ack(&mut c, now + 4, burst[1].1);
    assert_eq!(
        c.stats().ca_state,
        CaState::Open as u8,
        "spurious timeout kept"
    );
}

/// F-RTO also runs for a timeout during an ECN reduction (Linux
/// `tcp_enter_loss`: any state below Recovery) and its undo needs no undo
/// state (`tcp_try_undo_loss(sk, true)`), but restores nothing a CWR left:
/// the ECN reduction stands.
#[test]
fn frto_after_a_timeout_in_cwr_keeps_the_ecn_reduction() {
    let (mut c, sseq, iss) = established(1000, true, true);
    let burst = ts_burst(&mut c, sseq, iss, 10);
    let end = |k: usize| burst[k].seq + burst[k].len as u32;
    c.set_now(1030);
    let ece = pkt(
        SRV,
        CLI,
        sseq,
        end(0),
        flags::ACK | flags::ECE,
        65535,
        &ts(7, tsval(&burst[0])),
        &[],
    );
    c.inject_packet(&ece).unwrap();
    drain(&mut c);
    assert_eq!(c.stats().ca_state, CaState::Cwr as u8);
    let reduced = c.stats().ssthresh;
    let (retx, now) = until_rto(&mut c, 1030, burst[1].seq);
    let resent = c.stats().segs_retrans;
    // Originals never resent are SACKed: the timeout was spurious.
    ts_ack(
        &mut c,
        sseq,
        now + 1,
        end(1),
        tsval(&retx),
        &[(burst[2].seq, end(9))],
    );
    let s = c.stats();
    assert_eq!(s.ca_state, CaState::Open as u8, "timeout kept");
    assert_eq!(s.ssthresh, reduced, "ECN reduction undone");
    assert_eq!(s.segs_retrans, resent, "originals resent");
}

/// An immediate ACK a paused egress held back goes out on its own once the
/// host resumes, not on the data queued meanwhile: a duplicate ACK must be
/// data-less for a peer that counts them (RFC 5681 §2; smoltcp).
#[test]
fn an_immediate_ack_held_by_paused_egress_goes_out_alone() {
    let (mut c, sseq, iss) = established(1000, false, false);
    c.set_egress_paused(true);
    c.send(&vec![0x5b; 1448]).unwrap();
    c.set_now(1020);
    let ooo = pkt(
        SRV,
        CLI,
        sseq + 1448,
        iss + 1,
        flags::ACK,
        65535,
        &ts(7, 1010),
        &vec![0x5a; 1448],
    );
    c.inject_packet(&ooo).unwrap();
    assert!(drain(&mut c).is_empty());
    c.set_egress_paused(false);
    c.tick().unwrap();
    let out = drain(&mut c);
    assert!(
        out.iter()
            .any(|o| o.len == 0 && o.ack == sseq && o.flags == flags::ACK),
        "{out:?}"
    );
    assert!(out.iter().any(|o| o.len == 1448), "{out:?}");
}

/// The peer's retransmitted FIN may also acknowledge our data and move our
/// window: in CLOSE-WAIT that must still clock out what is queued, or arm
/// the persist timer if the window closed (Linux `tcp_rcv_state_process`
/// sends after `tcp_ack` in every state that can).
#[test]
fn a_retransmitted_fin_that_acks_data_still_lets_queued_data_out() {
    for wnd in [0u16, 8192] {
        let (mut c, sseq, iss) = established(1000, true, false);
        c.set_now(1020);
        let fin = pkt(
            SRV,
            CLI,
            sseq,
            iss + 1,
            flags::ACK | flags::FIN,
            12,
            &ts(10, 1000),
            &[],
        );
        c.inject_packet(&fin).unwrap();
        drain(&mut c);
        assert_eq!(c.state(), State::CloseWait);
        c.send(&vec![0xaa; 2 * 1448]).unwrap();
        c.tick().unwrap();
        assert_eq!(drain(&mut c).iter().filter(|o| o.len > 0).count(), 1);
        c.set_now(1250);
        let again = pkt(
            SRV,
            CLI,
            sseq,
            iss + 1 + 1448,
            flags::ACK | flags::FIN,
            wnd,
            &ts(20, 1020),
            &[],
        );
        c.inject_packet(&again).unwrap();
        let out = drain(&mut c);
        assert_eq!(c.debug_check_liveness(), Ok(()), "window {wnd}");
        if wnd > 0 {
            assert!(
                out.iter().any(|o| o.len == 1448 && o.seq == iss + 1 + 1448),
                "{out:?}"
            );
        }
    }
}

/// A SACK of data never resent times the round trip too (Linux
/// `tcp_sacktag_one`, `tcp_ack_update_rtt`). Here it lowers `min_rtt` from
/// the handshake's 2 ms to the path's sub-millisecond floor of 1 ms, so
/// RACK takes the SACKed resends that follow as delivered and repairs a
/// lost one rather than leaving it to the RTO: once the reordering floor
/// has passed, as SACKs within the tick the resends left could equally be
/// for late originals.
#[test]
fn a_sack_of_data_never_resent_samples_the_rtt() {
    let (mut c, sseq, iss) = established_rtt(1000, 2, true, false);
    ts_ack(&mut c, sseq, 1002, iss + 1, 1000, &[]);
    assert_eq!(c.stats().min_rtt_ms, 2);
    let b = send_burst(&mut c, 1010, 10 * 1448);
    let resent = ts_ack(&mut c, sseq, 1010, b[0].0, 1010, &[(b[3].0, b[9].1)]);
    assert_eq!(resent.iter().filter(|o| o.len > 0).count(), 3);
    assert_eq!(c.stats().min_rtt_ms, 1);
    ts_ack(&mut c, sseq, 1010, b[0].0, 1010, &[(b[1].0, b[9].1)]);
    let (again, now) = first_data(&mut c, 1010, 1100);
    assert_eq!((again.seq, now), (b[0].0, 1012));
    assert_eq!(c.stats().rto_count, 0);
}

/// An ACK inside a segment trims it but delivers nothing whole, so it
/// gives no RTT sample (Linux `tcp_clean_rtx_queue` stops at it). A peer
/// ACKing a byte at a time would otherwise drive SRTT, and the RTO with
/// it, toward a minute.
#[test]
fn acks_inside_a_segment_give_no_rtt_sample() {
    let (mut c, sseq, _) = established_rtt(1000, 10, true, false);
    let segs = send_burst(&mut c, 1020, 1448);
    let (srtt, rto) = (c.stats().srtt_ms, c.stats().rto_ms);
    let mut now = 1020u64;
    for k in 1..=350u32 {
        now += 150;
        ts_ack(&mut c, sseq, now, segs[0].0 + k, 1020, &[]);
    }
    assert_eq!((c.stats().srtt_ms, c.stats().rto_ms), (srtt, rto));
}

/// A full retransmission queue whose segments were all resent once still
/// finds a record to split one when the path MTU drops again: segments
/// resent before can be merged as long as no resend is in flight.
/// Refusing them sent nothing at all, timeout after timeout, until R2.
#[cfg(not(feature = "small-buffers"))]
#[test]
fn a_path_mtu_drop_after_resends_still_finds_room_to_split() {
    let iss = 1_000_000;
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(1000);
    c.connect().unwrap();
    let syn = drain(&mut c);
    let opts = TcpOptions {
        mss: Some(1036),
        wscale: Some(7),
        ts: Some((1, tsval(&syn[0]))),
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    c.set_now(1010);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        SRV_ISS,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &opts,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let sseq = SRV_ISS + 1;
    let mut now = 1020;
    ts_ack(&mut c, sseq, now, iss + 1, 0, &[]);
    while c.stats().cwnd < crate::BUF_CAP as u32 {
        c.send(&vec![0x5a; c.stats().cwnd as usize]).unwrap();
        send_until_quiet(&mut c);
        now += 1;
        let end = c.debug_snapshot().snd_nxt;
        ts_ack(&mut c, sseq, now, end, 0, &[]);
    }
    assert_eq!(c.send(&vec![0x5a; 1023 * 1024]), Ok(1023 * 1024));
    send_until_quiet(&mut c);
    for mtu in [900, 700] {
        c.update_pmtu(mtu);
        send_until_quiet(&mut c);
    }
    c.update_pmtu(576);
    let mut out = drain(&mut c);
    for _ in 0..3 {
        c.set_now(c.debug_snapshot().rto_deadline);
        c.tick().unwrap();
        out.extend(drain(&mut c));
        c.debug_validate_invariants().unwrap();
    }
    assert!(
        out.iter().any(|o| o.len > 0 && o.total_len <= 576),
        "nothing sent: {:?}",
        c.stats()
    );
}

/// A path-MTU probe alone in flight that draws nothing back for a PTO most
/// likely did not fit: its data goes out again at the size in use, in
/// full, with no window reduction ("MTU probe failure: don't reduce cwnd",
/// as Linux treats a probe ACKs show lost) — not a tail loss probe of its
/// first part, which would leave the rest for RACK to find lost and halve
/// the window over.
#[test]
fn a_lone_pmtu_probe_with_no_answer_is_resent_without_a_reduction() {
    let (mut c, sseq, _) = established(1000, true, false);
    c.set_now(1020);
    c.update_pmtu(1064);
    let mut now = 1020 + 600_000;
    c.set_now(now);
    c.send(&vec![0x55; 1448]).unwrap();
    c.tick().unwrap();
    let probe = drain(&mut c).into_iter().find(|o| o.len > 0).unwrap();
    assert_eq!(probe.len, 1448);
    let before = c.stats();
    let resent = loop {
        now += 1;
        assert!(now < 1020 + 602_000, "nothing resent");
        c.set_now(now);
        c.tick().unwrap();
        let out: Vec<Out> = drain(&mut c).into_iter().filter(|o| o.len > 0).collect();
        if !out.is_empty() {
            break out;
        }
    };
    let parts: Vec<(u32, usize)> = resent.iter().map(|o| (o.seq, o.len)).collect();
    assert_eq!(parts, [(probe.seq, 1012), (probe.seq + 1012, 436)]);
    ts_ack(
        &mut c,
        sseq,
        now + 1,
        probe.seq + 1448,
        tsval(&resent[1]),
        &[],
    );
    let s = c.stats();
    assert_eq!((s.tlp_count, s.fast_recoveries, s.rto_count), (0, 0, 0));
    assert_eq!(s.ca_state, CaState::Open as u8);
    assert!(
        s.ssthresh >= before.ssthresh && s.cwnd >= before.cwnd,
        "{s:?}"
    );
}

/// A path-MTU probe sent when a reported MTU expires does not fit, and the
/// host reports the size in use again. Linux keeps the probe pending
/// (`tcp_v4_mtu_reduced` acts only on a report below the size in use), so
/// its loss is an "MTU probe failure: don't reduce cwnd"
/// (`tcp_fastretrans_alert`), not congestion.
#[test]
fn a_lost_probe_reported_at_the_size_in_use_is_no_congestion() {
    for icmp in [false, true] {
        let (mut c, sseq, iss) = established(1000, true, false);
        ts_ack(&mut c, sseq, 1020, iss + 1, 1000, &[]);
        c.update_pmtu(1280);
        let mut now = 1020u64 + 600_001;
        c.set_now(now);
        c.send(&vec![0x5a; 1448 + 6 * 1228]).unwrap();
        c.tick().unwrap();
        let data: Vec<Out> = drain(&mut c).into_iter().filter(|o| o.len > 0).collect();
        assert_eq!(data[0].len, 1448, "probe first");
        assert!(data.len() >= 4, "{} segments", data.len());
        if icmp {
            c.update_pmtu(1280);
        }
        let ssthresh = c.debug_snapshot().ssthresh;
        let probe_end = data[0].seq + 1448;
        // The receiver SACKs everything after the dropped probe.
        now += 1;
        for d in &data[1..] {
            let r = d.seq + d.len as u32;
            ts_ack(
                &mut c,
                sseq,
                now,
                data[0].seq,
                now as u32 - 1,
                &[(probe_end, r)],
            );
        }
        for _ in 0..5 {
            now += 1;
            c.set_now(now);
            c.tick().unwrap();
            drain(&mut c);
        }
        assert_eq!(c.stats().fast_recoveries, 0, "icmp {icmp}");
        assert_eq!(c.debug_snapshot().ssthresh, ssthresh, "icmp {icmp}");
    }
}

/// In SYN-RECEIVED a SYN-ACK that acknowledges our SYN but is not the
/// simultaneous open's is not reset: <SEQ=SEG.ACK> would land at RCV.NXT
/// of a peer that took our SYN-ACK. Outside the window it draws an ACK
/// (Linux `tcp_check_req`); inside, the half-open returns to LISTEN, as for
/// a SYN there (RFC 9293 §3.10.7.4).
#[test]
fn an_acceptable_syn_ack_in_syn_received_is_not_reset() {
    for (seq, in_window) in [(400u32, false), (5000, true)] {
        let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
        s.set_secret(&[3u8; 16]);
        s.set_now(1000);
        s.listen().unwrap();
        let syn_opts = TcpOptions {
            mss: Some(1460),
            ts: Some((10, 0)),
            sack_permitted: true,
            ..TcpOptions::NONE
        };
        s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &syn_opts, &[]))
            .unwrap();
        let synack = drain(&mut s).remove(0);
        s.set_now(1005);
        let odd = pkt(
            CLI,
            SRV,
            seq,
            synack.seq + 1,
            flags::SYN | flags::ACK,
            65535,
            &syn_opts,
            &[],
        );
        s.inject_packet(&odd).unwrap();
        let out = drain(&mut s);
        assert!(out.iter().all(|o| o.flags & flags::RST == 0), "{out:?}");
        if in_window {
            assert_eq!(s.state(), State::Listen);
        } else {
            assert!(out.iter().any(|o| o.flags == flags::ACK), "{out:?}");
            assert_eq!(s.state(), State::SynRcvd);
        }
    }
}

/// A connection a SYN cookie promoted sent nothing before the promotion,
/// so no TSecr from before it may time a resend: a forged echo up to a
/// minute old would pin the RTO near its 60 s cap.
#[test]
fn a_cookie_promoted_connection_takes_no_tsecr_from_before_it() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 1);
    s.set_secret(&[7u8; 16]);
    let now0 = 100_000u64;
    s.set_now(now0);
    s.listen().unwrap();
    let syn_opts = TcpOptions {
        mss: Some(1460),
        ts: Some((100, 0)),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    // A half-open holds the slot, so the next SYN gets a cookie.
    s.inject_packet(&pkt(ATTACKER, SRV, 9, 0, flags::SYN, 65535, &syn_opts, &[]))
        .unwrap();
    drain(&mut s);
    s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &syn_opts, &[]))
        .unwrap();
    let cookie_synack = drain(&mut s).remove(0);
    s.set_now(now0 + 10);
    let third = pkt(
        CLI,
        SRV,
        501,
        cookie_synack.seq + 1,
        flags::ACK,
        8192,
        &ts(110, tsval(&cookie_synack)),
        &[],
    );
    let mut s = hand_off(&mut s, &third, now0 + 10, |t| t.set_secret(&[7u8; 16]));
    drain(&mut s);
    assert_eq!(s.state(), State::Established);
    let segs = send_burst(&mut s, now0 + 20, 1448);
    let mut now = now0 + 20;
    let resend_tsval = loop {
        now += 10;
        s.set_now(now);
        s.tick().unwrap();
        if let Some(o) = drain(&mut s).into_iter().find(|o| o.len > 0) {
            break tsval(&o);
        }
    };
    s.set_now(now + 10);
    let forged = (resend_tsval + 10).wrapping_sub(59_000);
    s.inject_packet(&pkt(
        CLI,
        SRV,
        501,
        segs[0].1,
        flags::ACK,
        8192,
        &ts(200, forged),
        &[],
    ))
    .unwrap();
    drain(&mut s);
    assert!(s.stats().rto_ms < 5_000, "RTO {} ms", s.stats().rto_ms);
}

/// A burst that fills the egress ring before cwnd still counts toward the
/// round's use of cwnd (Linux `tcp_cwnd_validate` after any send): here a
/// peer window of 32 segments ends the burst on the ring's last slot, and
/// without that record slow start would not grow cwnd for it.
#[test]
fn a_burst_that_fills_the_egress_ring_still_counts_toward_slow_start() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let mut now = 1020u64;
    ts_ack(&mut c, sseq, now, iss + 1, 1000, &[]);
    for _ in 0..2 {
        let w = c.stats().cwnd as usize;
        c.send(&vec![0x5a; w]).unwrap();
        send_until_quiet(&mut c);
        now += 10;
        let nxt = c.debug_snapshot().snd_nxt;
        ts_ack(&mut c, sseq, now, nxt, (now - 10) as u32, &[]);
    }
    let cwnd = c.stats().cwnd;
    assert_eq!(cwnd, 40 * 1448);
    // A short write leaves the round application limited.
    let seg = send_burst(&mut c, now + 1, 1448);
    now += 5;
    ts_ack(&mut c, sseq, now, seg[0].1, (now - 4) as u32, &[]);
    // The peer's window: exactly 32 segments.
    now += 1;
    c.set_now(now);
    let una = c.debug_snapshot().snd_una;
    let tsopt = ts(now as u32, (now - 1) as u32);
    c.inject_packet(&pkt(SRV, CLI, sseq, una, flags::ACK, 0, &tsopt, &[]))
        .unwrap();
    c.inject_packet(&pkt(SRV, CLI, sseq, una, flags::ACK, 362, &tsopt, &[]))
        .unwrap();
    drain(&mut c);
    assert_eq!(c.stats().snd_wnd, 32 * 1448);
    c.send(&vec![0x5a; 64 * 1448]).unwrap();
    let mut sent = 0;
    loop {
        c.tick().unwrap();
        let batch = drain(&mut c);
        if batch.is_empty() {
            break;
        }
        sent += batch.iter().filter(|o| o.len > 0).count();
    }
    assert_eq!(sent, 32);
    now += 10;
    c.set_now(now);
    let nxt = c.debug_snapshot().snd_nxt;
    let all = pkt(
        SRV,
        CLI,
        sseq,
        nxt,
        flags::ACK,
        362,
        &ts(now as u32, (now - 10) as u32),
        &[],
    );
    c.inject_packet(&all).unwrap();
    drain(&mut c);
    assert!(
        c.stats().cwnd > cwnd,
        "cwnd {} did not grow",
        c.stats().cwnd
    );
}

/// RFC 8985 §8: the reordering timer and the probe timer exclude each
/// other (Linux runs both on one timer). A SACK showing a hole arms the
/// former in place of a pending probe, which would otherwise resend the
/// tail first while RACK waits out the hole.
#[test]
fn no_tail_loss_probe_while_the_reordering_timer_runs() {
    let (mut c, sseq, iss) = established_rtt(1000, 1, true, false);
    let w = send_burst(&mut c, 1005, 3 * 1448);
    ts_ack(&mut c, sseq, 1006, iss + 1, 1005, &[w[1]]);
    ts_ack(&mut c, sseq, 1006, w[2].1, 1005, &[]);
    let b = send_burst(&mut c, 1010, 3 * 1448);
    ts_ack(&mut c, sseq, 1019, b[0].0, 1010, &[b[1]]);
    let mut out = Vec::new();
    for t in [1020, 1021] {
        c.set_now(t);
        c.tick().unwrap();
        out.extend(drain(&mut c));
    }
    assert_eq!(c.stats().tlp_count, 0, "{out:?}");
    assert!(out.iter().any(|o| o.len > 0 && o.seq == b[0].0), "{out:?}");
}

/// An owed ACK goes out on its own ahead of a resend (Linux lets the resend
/// carry it): the peer drops a resend of data it holds as older than its
/// last ACK (Linux `tcp_sequence`) without reading the ACK field, and the
/// data that ACK covered would wait for the peer's tail loss probe — 200
/// ms with one segment in flight. Two live connections; RACK's timer
/// resends a segment that was only late.
#[test]
fn an_owed_ack_does_not_ride_only_on_a_resend() {
    fn raw_drain(t: &mut Tcb) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; MAX_PACKET];
        loop {
            let n = t.extract_packet(&mut buf).unwrap();
            if n == 0 {
                return out;
            }
            out.push(buf[..n].to_vec());
        }
    }
    let (mut c, sseq, iss) = established_rtt(1000, 0, true, false);
    let (seq, base) = spend_quick_acks(&mut c, sseq, iss + 1, 1020);
    let now = base + 10;
    // The peer, as a live connection in step with `c`.
    let mut s = new_tcb(SRV, CLI, seq - 1);
    s.set_now(now - 1);
    s.connect().unwrap();
    let syn = drain(&mut s);
    s.set_now(now);
    let opts = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ts: Some((now as u32, syn[0].opts.ts.unwrap().0)),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(
        CLI,
        SRV,
        iss,
        seq,
        flags::SYN | flags::ACK,
        8192,
        &opts,
        &[],
    ))
    .unwrap();
    drain(&mut s);
    assert_eq!(s.debug_snapshot().rcv_nxt, c.debug_snapshot().snd_nxt);
    assert_eq!(s.debug_snapshot().snd_nxt, c.debug_snapshot().rcv_nxt);
    c.set_now(now);
    c.send(&[0x5a; 2 * 1448]).unwrap();
    c.tick().unwrap();
    let original = raw_drain(&mut c);
    assert_eq!(original.len(), 2);
    // The second segment arrives first; the peer's SACK for it is lost.
    s.inject_packet(&original[1]).unwrap();
    drain(&mut s);
    // The peer sends 100 bytes: `c` owes it a delayed ACK.
    s.send(&[0x5b; 100]).unwrap();
    s.tick().unwrap();
    let reverse = raw_drain(&mut s);
    assert_eq!(reverse.len(), 1);
    c.inject_packet(&reverse[0]).unwrap();
    assert!(drain(&mut c).is_empty());
    // The first segment was only late; the cumulative ACK for it is lost.
    s.set_now(now + 1);
    s.inject_packet(&original[0]).unwrap();
    drain(&mut s);
    // RACK's timer resends it; the peer has it already.
    c.set_now(now + 2);
    c.tick().unwrap();
    s.set_now(now + 2);
    for p in raw_drain(&mut c) {
        s.inject_packet(&p).unwrap();
    }
    for t in now + 3..=now + 205 {
        for p in raw_drain(&mut s) {
            c.inject_packet(&p).unwrap();
        }
        c.set_now(t);
        s.set_now(t);
        c.tick().unwrap();
        for p in raw_drain(&mut c) {
            s.inject_packet(&p).unwrap();
        }
        s.tick().unwrap();
    }
    let st = s.stats();
    assert_eq!((st.tlp_count, st.segs_retrans), (0, 0), "{st:?}");
    assert_eq!(s.debug_snapshot().snd_una, s.debug_snapshot().snd_nxt);
}

/// A cookie SYN-ACK is delayed and the client's retransmitted SYN takes the
/// listener's timed-out slot statefully, with another ISN. The client took
/// the cookie: its ACK proves a connection this slot's SYN-ACK has not, and
/// a RST <SEQ=SEG.ACK> would reset it at its RCV.NXT. Linux finds the
/// cookie valid too (and, unable to hash a duplicate, drops it); here it
/// takes the slot.
#[test]
fn a_valid_cookie_ack_after_its_peer_retook_the_slot_promotes() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_secret(&[3u8; 16]);
    s.set_now(1000);
    s.listen().unwrap();
    let syn = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(ATTACKER, SRV, 1, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    drain(&mut s);
    s.set_now(1100);
    s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    let cookie = drain(&mut s)[0].seq;
    s.set_now(2000);
    s.tick().unwrap();
    drain(&mut s);
    s.set_now(2001);
    s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    let stateful = drain(&mut s)[0].seq;
    assert_ne!(cookie, stateful);
    let mut peer = new_tcb(CLI, SRV, 77);
    peer.set_now(1100);
    peer.connect().unwrap();
    drain(&mut peer);
    peer.set_now(2002);
    peer.inject_packet(&pkt(
        SRV,
        CLI,
        cookie,
        78,
        flags::SYN | flags::ACK,
        65535,
        &syn,
        &[],
    ))
    .unwrap();
    assert_eq!(peer.state(), State::Established);
    drain(&mut peer);
    s.set_now(2002);
    s.inject_packet(&pkt(
        CLI,
        SRV,
        78,
        cookie + 1,
        flags::ACK,
        65535,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    let out = drain(&mut s);
    for p in &out {
        peer.inject_packet(&pkt(SRV, CLI, p.seq, p.ack, p.flags, p.win, &p.opts, &[]))
            .unwrap();
    }
    assert_eq!(peer.state(), State::Established, "{out:?}");
    assert_eq!(s.state(), State::Established);
}

// ---------------------------------------------------------------------------
// Two-way virtual links (audit iteration 5)
// ---------------------------------------------------------------------------

/// With SACK negotiated, RACK alone declares losses (Linux `tcp_is_reno`
/// picks duplicate-ACK counting only for connections without SACK): three
/// duplicate ACKs that happen to carry no SACK blocks used to resend the
/// hole at once, overriding the reordering window RACK was waiting out
/// after reordering had been seen.
#[test]
fn sackless_duplicate_acks_do_not_override_rack_on_a_sack_connection() {
    let (mut c, sseq, iss) = established_rtt(1000, 0, true, false);
    ts_ack(&mut c, sseq, 1000, iss + 1, 1000, &[]);
    // Reordering seen: segment 1 is SACKed before segment 0 arrives.
    let w = send_burst(&mut c, 1000, 3 * 1448);
    ts_ack(&mut c, sseq, 1000, w[0].0, 1000, &[w[1]]);
    ts_ack(&mut c, sseq, 1000, w[2].1, 1000, &[]);
    let b = send_burst(&mut c, 1010, 4 * 1448);
    ts_ack(&mut c, sseq, 1010, b[0].0, 1010, &[(b[1].0, b[3].1)]);
    for _ in 0..3 {
        ts_ack(&mut c, sseq, 1010, b[0].0, 1010, &[]);
    }
    assert_eq!(c.stats().segs_retrans, 0);
    // The reordering window still ends it, if the hole stays.
    let (resend, _) = first_data(&mut c, 1010, 1100);
    assert_eq!(resend.seq, b[0].0);
}

/// Resends leave in one tick; a SACK of a later resend's late original,
/// within that tick, is credited to the resend (ambiguous at a 1 ms clock)
/// and used to condemn the resends sent just before it at once. They may
/// have been sent after that original: they wait out the reordering floor.
#[test]
fn resends_of_a_tick_survive_a_late_originals_sack_in_it() {
    let (mut c, sseq, iss) = established_rtt(1000, 0, true, false);
    ts_ack(&mut c, sseq, 1000, iss + 1, 1000, &[]);
    let segs = send_burst(&mut c, 1000, 10 * 1448);
    assert_eq!(segs.len(), 10);
    let retx1 = ts_ack(
        &mut c,
        sseq,
        1001,
        segs[0].0,
        1000,
        &[(segs[3].0, segs[7].1)],
    );
    assert_eq!(retx1.iter().filter(|o| o.len > 0).count(), 3);
    let retx2 = ts_ack(
        &mut c,
        sseq,
        1001,
        segs[0].0,
        1000,
        &[(segs[3].0, segs[7].1), (segs[9].0, segs[9].1)],
    );
    assert_eq!(retx2.iter().filter(|o| o.len > 0).count(), 1);
    assert_eq!(c.stats().segs_retrans, 4);
    let spurious = ts_ack(
        &mut c,
        sseq,
        1001,
        segs[0].0,
        1000,
        &[(segs[3].0, segs[9].1)],
    );
    assert_eq!(spurious.iter().filter(|o| o.len > 0).count(), 0);
    assert_eq!(c.stats().segs_retrans, 4);
}

// ---------------------------------------------------------------------------
// General sweep (audit iteration 6)
// ---------------------------------------------------------------------------

/// SACK blocks of a byte or two inside one segment split nothing (Linux
/// `tcp_match_skb_to_sack` never splits a single-segment skb): splitting
/// at every block edge let a peer fill the retransmission queue, after
/// which no new data could be sent, and each fragment would go out again
/// in a packet of its own.
#[test]
fn one_byte_sack_blocks_do_not_shatter_the_retransmission_queue() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let now = 1020u64;
    ts_ack(&mut c, sseq, now, iss + 1, 1000, &[]);
    let segs = send_burst(&mut c, now, 2 * 1448);
    assert_eq!(segs.len(), 2);
    for k in 0..511u32 {
        let l = segs[1].0 + 1 + 2 * k;
        ts_ack(&mut c, sseq, now, segs[0].0, now as u32, &[(l, l + 1)]);
    }
    c.send(&[0x5a; 1448]).unwrap();
    c.tick().unwrap();
    let out: Vec<Out> = drain(&mut c).into_iter().filter(|o| o.len > 0).collect();
    assert!(!out.is_empty(), "new data blocked by a shattered queue");
    c.debug_validate_invariants().unwrap();
}

/// A full queue of segments alternately SACKed and lost has no pair to
/// merge for the split a path-MTU drop needs at the head; the newest two
/// merge anyway (to be sent again), or nothing at all would go out until
/// R2 gave up.
#[test]
fn alternating_sacks_and_a_path_mtu_drop_leave_the_head_splittable() {
    let iss = 1_000_000;
    let mut c = new_tcb(CLI, SRV, iss);
    c.set_now(1000);
    c.connect().unwrap();
    let syn = drain(&mut c);
    let opts = TcpOptions {
        mss: Some(1036),
        wscale: Some(7),
        ts: Some((1, tsval(&syn[0]))),
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    c.set_now(1010);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        SRV_ISS,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &opts,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let sseq = SRV_ISS + 1;
    let mut now = 1020u64;
    ts_ack(&mut c, sseq, now, iss + 1, 0, &[]);
    while c.stats().cwnd < crate::BUF_CAP as u32 {
        c.send(&vec![0x5a; c.stats().cwnd as usize]).unwrap();
        send_until_quiet(&mut c);
        now += 1;
        let end = c.debug_snapshot().snd_nxt;
        ts_ack(&mut c, sseq, now, end, 0, &[]);
    }
    let start = c.debug_snapshot().snd_una;
    assert_eq!(c.send(&vec![0x5a; 1023 * 1024]), Ok(1023 * 1024));
    send_until_quiet(&mut c);
    for k in (1..1023u32).step_by(2) {
        let seg = start + k * 1024;
        ts_ack(&mut c, sseq, now, start, 0, &[(seg, seg + 1024)]);
    }
    c.update_pmtu(900);
    send_until_quiet(&mut c);
    ts_ack(&mut c, sseq, now, start, 0, &[(start + 848, start + 1024)]);
    c.update_pmtu(576);
    let mut out = drain(&mut c);
    for _ in 0..5 {
        let d = c.debug_snapshot().rto_deadline;
        if d == u64::MAX {
            break;
        }
        c.set_now(d);
        c.tick().unwrap();
        out.extend(drain(&mut c));
        c.debug_validate_invariants().unwrap();
    }
    assert!(
        out.iter().any(|o| o.len > 0 && o.total_len <= 576),
        "nothing small enough for the path went out"
    );
}

/// A path-MTU probe that drew nothing back is resent at the size in use
/// without a window reduction when it is the last segment in flight, not
/// only when it is the only one: a tail loss probe of its first MSS left
/// the rest stranded until the RTO.
#[test]
fn a_lost_path_mtu_probe_behind_another_segment_is_resent_whole() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 1000, &[]);
    c.set_now(1020);
    c.update_pmtu(1064);
    let mut now = 1020 + 599_999;
    let pre = send_burst(&mut c, now, 1012);
    assert_eq!(pre[0].1 - pre[0].0, 1012);
    now += 1;
    let probe = send_burst(&mut c, now, 1448);
    assert_eq!(
        probe[0].1 - probe[0].0,
        1448,
        "a path-MTU probe at the tail"
    );
    let before = c.stats();
    let mut resent = Vec::new();
    while resent.is_empty() {
        now += 1;
        assert!(now < 1020 + 600_100, "nothing was resent");
        c.set_now(now);
        c.tick().unwrap();
        resent = drain(&mut c)
            .into_iter()
            .filter(|o| o.len > 0)
            .collect::<Vec<_>>();
    }
    let end = resent.iter().map(|o| o.seq + o.len as u32).max().unwrap();
    now += 1;
    let echo = resent.last().unwrap().opts.ts.unwrap().0;
    ts_ack(&mut c, sseq, now, end, echo, &[]);
    resent.extend(drain(&mut c).into_iter().filter(|o| o.len > 0));
    let end = resent.iter().map(|o| o.seq + o.len as u32).max().unwrap();
    assert_eq!(end, probe[0].1, "the rest of the probe was stranded");
    let after = c.stats();
    assert_eq!(after.fast_recoveries, 0, "a lost probe reduced the window");
    assert!(after.ssthresh >= before.ssthresh && after.cwnd >= before.cwnd);
}

/// Without SACK, duplicate ACKs credit a segment each to the window's
/// accounting but raise cwnd no more than an ACK of new data would (Linux
/// `tcp_may_raise_cwnd`), are spent once SND.UNA moves outside recovery
/// (`tcp_reset_reno_sack`), and never vouch for the holes
/// (`tcp_limit_reno_sacked`).
#[test]
fn duplicate_acks_without_sack_neither_grow_nor_leak_the_window() {
    let (mut c, sseq, iss) = established(1000, false, false);
    let mut now = 1020u64;
    let ack = |c: &mut Tcb, now: u64, ack: u32| {
        c.set_now(now);
        let o = ts(now as u32, now as u32);
        c.inject_packet(&pkt(SRV, CLI, sseq, ack, flags::ACK, 8192, &o, &[]))
            .unwrap();
        drain(c)
    };
    ack(&mut c, now, iss + 1);
    let mss = c.stats().mss;
    let segs = send_burst(&mut c, now, 10 * mss as usize);
    let cwnd = c.stats().cwnd;
    now += 1;
    ack(&mut c, now, segs[0].0);
    ack(&mut c, now, segs[0].0);
    assert_eq!(c.stats().cwnd, cwnd, "duplicate ACKs grew cwnd");
    for &(_, end) in &segs {
        now += 1;
        c.send(&vec![0x5a; mss as usize]).unwrap();
        ack(&mut c, now, end);
    }
    let snap = c.debug_snapshot();
    assert_eq!(
        c.stats().pipe,
        snap.snd_nxt - snap.snd_una,
        "duplicate ACKs left pipe under-counted"
    );
}

/// SACKs alone do not raise cwnd until reordering has been seen (Linux
/// `tcp_may_raise_cwnd`: `FLAG_DATA_ACKED`): a slow start that overflowed
/// a queue does not keep doubling while RACK waits out its reordering
/// window. The ACK of new data that follows raises it.
#[test]
fn sacks_alone_do_not_grow_the_window_before_reordering_is_seen() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let now = 1020u64;
    ts_ack(&mut c, sseq, now, iss + 1, 1000, &[]);
    let n = c.stats().cwnd as usize;
    let segs = send_burst(&mut c, now, n);
    let cwnd = c.stats().cwnd;
    ts_ack(
        &mut c,
        sseq,
        now + 1,
        segs[0].0,
        1000,
        &[(segs[1].0, segs[1].1)],
    );
    assert_eq!(c.stats().fast_recoveries, 0);
    assert_eq!(c.stats().cwnd, cwnd, "a SACK alone grew cwnd");
    ts_ack(&mut c, sseq, now + 1, segs[2].0, 1000, &[]);
    assert!(
        c.stats().cwnd > cwnd,
        "an ACK of new data did not grow cwnd"
    );
}

/// Closed in SYN_RCVD, the FIN that followed a lost SYN-ACK reached a peer
/// still in SYN-SENT, which drops it: it follows the retransmitted SYN-ACK
/// (Linux's timeout marks it lost), rather than waiting for a timeout
/// after the handshake.
#[test]
fn a_fin_queued_in_syn_rcvd_follows_the_retransmitted_syn_ack() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 7);
    s.set_secret(&[1; 16]);
    s.set_now(1000);
    s.listen().unwrap();
    let syn = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    assert!(drain(&mut s).iter().any(|o| o.flags & flags::SYN != 0));
    s.close().unwrap();
    assert!(drain(&mut s).iter().any(|o| o.flags & flags::FIN != 0));
    let rto = s.next_deadline().unwrap();
    s.set_now(rto);
    s.tick().unwrap();
    let out = drain(&mut s);
    let synack = out.iter().position(|o| o.flags & flags::SYN != 0);
    let fin = out.iter().position(|o| o.flags & flags::FIN != 0);
    assert!(
        matches!((synack, fin), (Some(a), Some(b)) if a < b),
        "the FIN did not follow the SYN-ACK: {:?}",
        out.iter().map(|o| o.flags).collect::<Vec<_>>()
    );
}

/// A timestamp echo names the transmission an ACK covers, also once the
/// connection is older than 2^31 ms: it was compared, modulo 2^32, with
/// the time of our first segment, which looked like the future for half
/// of every 49.7 days, and the RTO stayed backed off.
#[test]
fn rtt_samples_from_timestamps_survive_the_32_bit_wrap() {
    let (mut c, sseq, iss) = established(1000, true, false);
    let wrapped = 1000u64 + (1u64 << 31) + 50_000;
    ts_ack(&mut c, sseq, wrapped, iss + 1, 1000, &[]);
    let segs = send_burst(&mut c, wrapped, 1448);
    let mut now = wrapped;
    let mut echo = 0;
    for _ in 0..3 {
        now = c.next_deadline().unwrap();
        c.set_now(now);
        c.tick().unwrap();
        if let Some(o) = drain(&mut c).into_iter().find(|o| o.len > 0) {
            echo = tsval(&o);
        }
    }
    assert!(c.stats().rto_ms >= 800);
    c.set_now(now + 10);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        segs[0].1,
        flags::ACK,
        8192,
        &ts(100, echo),
        &[],
    ))
    .unwrap();
    drain(&mut c);
    assert!(
        c.stats().rto_ms < 400,
        "the echo gave no RTT sample (RTO {} ms)",
        c.stats().rto_ms
    );
}

/// The FIN of an out-of-order segment whose text is dropped (no room for
/// another out-of-order range) is dropped with it, as Linux drops the
/// skb: SACKing the FIN alone claimed the end of a stream whose data was
/// missing.
#[test]
fn the_fin_of_a_dropped_out_of_order_segment_is_not_sacked() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 1000, &[]);
    for i in 0..crate::ooo::OOO_MAX_RANGES as u32 {
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq + 100 + i * 20,
            iss + 1,
            flags::ACK,
            8192,
            &ts(10 + i, 1000),
            &[0x41; 10],
        ))
        .unwrap();
        drain(&mut c);
    }
    assert_eq!(c.stats().ooo_drops, 0);
    let seq = sseq + 100 + (crate::ooo::OOO_MAX_RANGES as u32 + 5) * 20;
    let fin = seq + 10;
    c.inject_packet(&pkt(
        SRV,
        CLI,
        seq,
        iss + 1,
        flags::ACK | flags::FIN,
        8192,
        &ts(9999, 1000),
        &[0x42; 10],
    ))
    .unwrap();
    assert_eq!(c.stats().ooo_drops, 1);
    let sacked_fin = drain(&mut c)
        .iter()
        .flat_map(|a| a.opts.sack.as_slice().iter().copied())
        .any(|(_, r)| r == fin + 1);
    assert!(!sacked_fin, "the FIN of dropped text was SACKed");
}

/// A held out-of-order FIN sent again is reported in the ACK's first SACK
/// block (RFC 2018 §4; Linux `tcp_sack_new_ofo_skb` moves a duplicate's
/// block first too), not left out behind newer blocks.
#[test]
fn a_repeated_out_of_order_fin_is_sacked_first() {
    let (mut c, sseq, iss) = established(1000, true, false);
    ts_ack(&mut c, sseq, 1020, iss + 1, 1000, &[]);
    let fin_seq = sseq + 1000;
    let fin = |v| {
        pkt(
            SRV,
            CLI,
            fin_seq,
            iss + 1,
            flags::ACK | flags::FIN,
            8192,
            &ts(v, 1000),
            &[],
        )
    };
    c.inject_packet(&fin(10)).unwrap();
    drain(&mut c);
    for k in 0..3u32 {
        c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq + 100 + k * 200,
            iss + 1,
            flags::ACK,
            8192,
            &ts(11 + k, 1000),
            &[0x41; 10],
        ))
        .unwrap();
        drain(&mut c);
    }
    c.inject_packet(&fin(20)).unwrap();
    let acks = drain(&mut c);
    let first = acks
        .last()
        .and_then(|a| a.opts.sack.as_slice().first().copied());
    assert_eq!(first, Some((fin_seq, fin_seq + 1)), "{acks:?}");
}

/// A peer keepalive gives up on is reset, in case it comes back (Linux
/// `tcp_keepalive_timer`), from CLOSE_WAIT too.
#[test]
fn keepalive_resets_the_peer_it_gives_up_on() {
    for close_wait in [false, true] {
        let (mut c, sseq, iss) = established(1000, true, false);
        c.set_now(1020);
        if close_wait {
            c.inject_packet(&pkt(
                SRV,
                CLI,
                sseq,
                iss + 1,
                flags::ACK | flags::FIN,
                8192,
                &ts(3, 0),
                &[],
            ))
            .unwrap();
            drain(&mut c);
            assert_eq!(c.state(), State::CloseWait);
        }
        c.set_keepalive(10_000, 1_000, 3);
        let (mut now, mut rst) = (1020u64, false);
        while c.state() != State::Closed && now < 1020 + 600_000 {
            now = c.next_deadline().unwrap_or(now + 1000).max(now + 1);
            c.set_now(now);
            c.tick().unwrap();
            rst |= drain(&mut c).iter().any(|o| o.flags & flags::RST != 0);
        }
        assert_eq!(c.state(), State::Closed, "close_wait={close_wait}");
        assert!(rst, "close_wait={close_wait}: no RST");
    }
}

/// A segment for a connection that is gone draws a RST (RFC 9293
/// §3.10.7.1), as from Linux, which no longer has the socket: the peer
/// otherwise retransmitted into silence until its own timeout. Not a RST
/// or a SYN (which may be for a listener the host runs), and one per
/// rate-limit interval.
#[test]
fn a_closed_connection_answers_its_peer_with_a_reset() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_user_timeout(50);
    send_burst(&mut c, 1020, 100);
    c.set_now(1100);
    c.tick().unwrap();
    drain(&mut c);
    assert_eq!(c.state(), State::Closed, "USER TIMEOUT");
    let data = pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        8192,
        &ts(5, 0),
        b"late",
    );
    assert_eq!(c.inject_packet(&data), Err(TcpError::InvalidState));
    let rst = drain(&mut c);
    assert!(
        matches!(rst.as_slice(), [o] if o.flags == flags::RST && o.seq == iss + 1),
        "no RST <SEQ=SEG.ACK>"
    );
    let _ = c.inject_packet(&data);
    assert!(drain(&mut c).is_empty(), "not rate limited");
    c.set_now(2000);
    let no_ack = pkt(SRV, CLI, sseq, 0, flags::FIN, 8192, &TcpOptions::NONE, &[]);
    let _ = c.inject_packet(&no_ack);
    let rst = drain(&mut c);
    assert!(
        matches!(rst.as_slice(), [o] if o.flags == flags::RST | flags::ACK && o.ack == sseq + 1),
        "no RST <SEQ=0><ACK=SEG.SEQ+SEG.LEN>"
    );
    c.set_now(3000);
    for fl in [flags::SYN, flags::RST | flags::ACK] {
        let _ = c.inject_packet(&pkt(
            SRV,
            CLI,
            sseq,
            iss + 1,
            fl,
            8192,
            &TcpOptions::NONE,
            &[],
        ));
    }
    assert!(drain(&mut c).is_empty(), "a SYN or RST drew a RST");
}

/// PAWS gives up on TS.Recent after 2147 s idle (Linux `TCP_PAWS_WRAP`),
/// not 24 days: a peer whose clock ticks in microseconds (Linux
/// `tcp_usec_ts`) laps half the timestamp space that soon, and every
/// segment it sent after a longer idle was dropped as old.
#[test]
fn paws_relaxes_for_a_microsecond_peer_after_a_long_idle() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_keepalive(0, 0, 0);
    c.set_now(1020);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK | flags::PSH,
        8192,
        &ts(5_000_000, 0),
        b"a",
    ))
    .unwrap();
    drain(&mut c);
    let mut buf = [0u8; 16];
    assert_eq!(c.recv(&mut buf), Ok(1));
    let idle_s: u64 = 40 * 60;
    c.set_now(1020 + idle_s * 1000);
    let tsv = 5_000_000u32.wrapping_add((idle_s * 1_000_000) as u32);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 1,
        iss + 1,
        flags::ACK | flags::PSH,
        8192,
        &ts(tsv, 0),
        b"b",
    ))
    .unwrap();
    drain(&mut c);
    assert_eq!(c.recv(&mut buf), Ok(1), "dropped by PAWS after 40 min idle");
}

// ---------------------------------------------------------------------------
// Security review (public exposure)
// ---------------------------------------------------------------------------

/// A listener keyed like its siblings whose half-open slot is taken, so it
/// answers `from`'s SYN (with `opts`) at `now` with a cookie SYN-ACK.
fn cookie_listener(now: u64, from: ([u8; 4], u16), opts: &TcpOptions) -> (Box<Tcb>, Out) {
    let mut s = new_tcb(SRV, ([0; 4], 0), 1);
    s.set_secret(&[4; 16]);
    s.set_now(now);
    s.listen().unwrap();
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(ATTACKER, SRV, 9, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    drain(&mut s);
    s.inject_packet(&pkt(from, SRV, 500, 0, flags::SYN, 65535, opts, &[]))
        .unwrap();
    let synack = drain(&mut s).remove(0);
    (s, synack)
}

/// The handshake's third ACK, answering `synack`.
fn third_ack(from: ([u8; 4], u16), synack: &Out) -> Vec<u8> {
    let ack = synack.seq.wrapping_add(1);
    pkt(
        from,
        SRV,
        501,
        ack,
        flags::ACK,
        65535,
        &TcpOptions::NONE,
        &[],
    )
}

/// The host's side of `ListenerBusy`: `busy`, its slot held by a live
/// half-open, hands back another peer's cookie ACK at `now`, and a fresh
/// listener the host sets up like its others (`setup`: the secrets) takes
/// it and becomes that peer's connection.
fn hand_off(busy: &mut Tcb, ack: &[u8], now: u64, setup: impl FnOnce(&mut Tcb)) -> Box<Tcb> {
    busy.set_now(now);
    assert_eq!(busy.inject_packet(ack), Err(TcpError::ListenerBusy));
    let mut fresh = new_tcb(SRV, ([0; 4], 0), 1);
    fresh.set_now(now);
    setup(&mut fresh);
    fresh.listen().unwrap();
    fresh.inject_packet(ack).unwrap();
    fresh
}

/// A listener that completes a handshake becomes that connection, so the
/// host sets up the next listener; the cookies the first one sent while its
/// slot was busy must connect there. A per-listener window (Linux
/// `tcp_synq_no_recent_overflow`) refused them, as the next listener had
/// sent none: of two clients connecting within one RTT, the second was
/// reset. A cookie past its two buckets is still refused.
#[test]
fn the_next_listener_takes_the_cookie_acks_its_predecessor_drew() {
    const C2: ([u8; 4], u16) = ([10, 0, 0, 12], 50002);
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    let listener = |now: u64| {
        let mut s = new_tcb(SRV, ([0; 4], 0), 1);
        s.set_secret(&[4; 16]);
        s.set_now(now);
        s.listen().unwrap();
        s
    };
    let mut first = listener(10_000);
    first
        .inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    let synack = drain(&mut first).remove(0);
    first.set_now(10_001);
    first
        .inject_packet(&pkt(C2, SRV, 500, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    let cookie = drain(&mut first).remove(0);
    assert_eq!(cookie.dst, C2, "no cookie SYN-ACK");
    first.set_now(10_002);
    first.inject_packet(&third_ack(CLI, &synack)).unwrap();
    assert_eq!(first.state(), State::Established);

    let mut next = listener(10_002);
    next.set_now(10_003);
    next.inject_packet(&third_ack(C2, &cookie)).unwrap();
    assert_eq!(next.state(), State::Established, "cookie client reset");

    let mut late = listener(130_000);
    let _ = late.inject_packet(&third_ack(C2, &cookie));
    assert_eq!(late.state(), State::Listen, "took an expired cookie");
}

/// A blind forger needs one of the cookies the listener would take for its
/// ACK: those it could have sent the SYN, with any options, in the two live
/// buckets. Linux has 8 of 2^32 (2⁻²⁹ a guess); ours were 32 (2⁻²⁷): eight
/// MSS values, and the SYN's timestamps chose between two MACs. Now the MSS
/// index takes 2 bits and the bucket's parity a third, and timestamps are
/// no dimension at all: a cookie offered with them still connects without
/// them (a BSD peer drops options from its fourth SYN), as on Linux.
#[test]
fn a_syn_has_at_most_eight_valid_cookies() {
    let mut cookies = Vec::new();
    for now in [10_000, 70_000] {
        for mss in [536, 1000, 1300, 1380, 1440, 1452, 1460, 8960, 65495] {
            for offer_ts in [false, true] {
                let o = TcpOptions {
                    mss: Some(mss),
                    wscale: offer_ts.then_some(7),
                    ts: offer_ts.then_some((100, 0)),
                    sack_permitted: offer_ts,
                    ..TcpOptions::NONE
                };
                cookies.push(cookie_listener(now, CLI, &o).1.seq);
            }
        }
    }
    cookies.sort_unstable();
    cookies.dedup();
    assert!(
        cookies.len() <= 8,
        "{} valid cookies per SYN",
        cookies.len()
    );

    let o = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ts: Some((100, 0)),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    let (mut s, synack) = cookie_listener(70_000, CLI, &o);
    assert!(synack.opts.ts.is_some());
    let s = hand_off(&mut s, &third_ack(CLI, &synack), 70_020, |t| {
        t.set_secret(&[4; 16])
    });
    assert_eq!(s.state(), State::Established, "options lost on the ACK");
    assert_eq!(s.stats().mss, 1460, "timestamps on");
    assert_eq!(s.debug_snapshot().snd_wnd, 65535, "window scaling on");
}

/// What a listener sends would-be peers (SYN-ACKs, stateful, retransmitted
/// or cookie, and RSTs) carries IP ID 0, as Linux's: our datagrams are all
/// DF (RFC 6864 §4.1). One counter used to number every packet the TCB
/// sent anyone, so a prober reading it could count the listener's other
/// traffic (an idle scan). A connection numbers only its own segments, so
/// what the listener sent others before does not move them.
#[test]
fn listener_packets_carry_ip_id_zero_and_connections_count_their_own() {
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    let run = |strangers: bool| {
        let mut s = new_tcb(SRV, ([0; 4], 0), 0x1234_5678);
        s.set_secret(&[4; 16]);
        s.set_now(10_000);
        s.listen().unwrap();
        s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &mss, &[]))
            .unwrap();
        let mut sent = drain_with_ip_id(&mut s);
        if strangers {
            s.inject_packet(&pkt(ATTACKER, SRV, 9, 0, flags::SYN, 65535, &mss, &[]))
                .unwrap();
            let stray = pkt(
                ([7; 4], 7),
                SRV,
                1,
                2,
                flags::ACK,
                65535,
                &TcpOptions::NONE,
                &[],
            );
            let _ = s.inject_packet(&stray);
            sent.extend(drain_with_ip_id(&mut s));
        }
        s.set_now(11_100);
        s.tick().unwrap();
        sent.extend(drain_with_ip_id(&mut s));
        s.inject_packet(&third_ack(CLI, &sent[0].0)).unwrap();
        assert_eq!(s.state(), State::Established);
        s.send(b"hello").unwrap();
        s.tick().unwrap();
        (sent, drain_with_ip_id(&mut s))
    };
    let (quiet_sent, quiet_data) = run(false);
    let (sent, data) = run(true);
    let to_cli = sent.iter().filter(|(o, _)| o.dst == CLI).count();
    assert!(to_cli >= 2, "the SYN-ACK was not retransmitted");
    assert!(sent.iter().any(|(o, _)| o.dst == ATTACKER), "no cookie");
    assert!(
        sent.iter().any(|(o, _)| o.flags & flags::RST != 0),
        "no RST"
    );
    for (o, id) in quiet_sent.iter().chain(&sent) {
        assert_eq!(*id, 0, "flags {:#x} to {:?} numbered", o.flags, o.dst);
    }
    assert!(!data.is_empty());
    assert_eq!(
        data.first().map(|d| d.1),
        quiet_data.first().map(|d| d.1),
        "packets to others moved the connection's numbering"
    );
}

// ---------------------------------------------------------------------------
// Public exposure (audit iteration 7)
// ---------------------------------------------------------------------------

/// An abort with the egress ring full (the host holding back what the
/// device queue cannot take) lost its RST: `abort` succeeded, and draining
/// afterwards, as the C header says, found none. The RST is now owed and
/// staged as soon as the host takes a packet out, behind those staged
/// before it, so it reaches the peer at its RCV.NXT.
#[test]
fn an_abort_with_a_full_egress_ring_still_resets_the_peer() {
    let (mut c, sseq, iss) = established(100, true, false);
    c.send(&[0x42; 1448]).unwrap();
    c.set_now(111);
    c.tick().unwrap();
    for i in 0..31 {
        let held = pkt(
            SRV,
            CLI,
            sseq + 1 + 2 * i,
            iss + 1,
            flags::ACK,
            8192,
            &ts(10, 100),
            b"X",
        );
        c.inject_packet(&held).unwrap();
    }
    assert!(c.debug_egress_full(), "the egress ring is not full");
    let snd_nxt = iss + 1 + 1448;
    c.abort().unwrap();
    assert_eq!(c.state(), State::Closed);
    let out = drain(&mut c);
    let resets: Vec<&Out> = out.iter().filter(|o| o.flags & flags::RST != 0).collect();
    assert_eq!(resets.len(), 1, "{} packets, no RST", out.len());
    let last = out.last().unwrap();
    assert!(
        last.flags & flags::RST != 0 && last.seq == snd_nxt && last.ack == sseq,
        "the RST is not last at SND.NXT: {last:?}"
    );
}

/// An out-of-order segment repeating bytes already held used to overwrite
/// them: `GOOD`, then `EVIL` at the same sequence, delivered `EVIL`. Held
/// bytes keep their first copy (Linux `tcp_data_queue_ofo` drops a wholly
/// duplicate segment; RFC 9293 §3.10.7.4 keeps just the new data), and of
/// a partial overlap only the new bytes are stored.
#[test]
fn a_duplicate_out_of_order_segment_does_not_overwrite_held_bytes() {
    let (mut c, sseq, iss) = established(100, true, false);
    let seg = |c: &mut Tcb, at: u32, body: &[u8]| {
        c.inject_packet(&pkt(
            SRV,
            CLI,
            at,
            iss + 1,
            flags::ACK,
            8192,
            &ts(10, 100),
            body,
        ))
        .unwrap();
        drain(c)
    };
    seg(&mut c, sseq + 1, b"GOOD");
    let out = seg(&mut c, sseq + 1, b"EVIL");
    assert!(
        out.iter()
            .any(|o| o.opts.sack.as_slice().first() == Some(&(sseq + 1, sseq + 5))),
        "the duplicate is not D-SACKed"
    );
    seg(&mut c, sseq + 3, b"xxNEW");
    seg(&mut c, sseq, b"+");
    assert_eq!(recv_all(&mut c), b"+GOODNEW");
}

/// A SYN from a source no host sends from (zero network, multicast, the
/// limited broadcast, loopback to a non-loopback address) was answered with
/// a SYN-ACK, stateful or cookie, aimed at that group or broadcast address.
/// Linux drops these as martians before TCP (`ip_route_input_slow`).
#[test]
fn a_listener_ignores_segments_from_martian_sources() {
    for busy in [false, true] {
        for ip in [[0, 0, 0, 0], [224, 0, 0, 1], [255; 4], [127, 0, 0, 1]] {
            let mut s = new_tcb(SRV, ([0; 4], 0), 1);
            s.set_secret(&[7; 16]);
            s.set_now(1000);
            s.listen().unwrap();
            if busy {
                s.inject_packet(&pkt(
                    ATTACKER,
                    SRV,
                    9,
                    0,
                    flags::SYN,
                    65535,
                    &TcpOptions::NONE,
                    &[],
                ))
                .unwrap();
                drain(&mut s);
            }
            let syn = pkt(
                (ip, 1234),
                SRV,
                42,
                0,
                flags::SYN,
                65535,
                &TcpOptions::NONE,
                &[],
            );
            assert_eq!(s.inject_packet(&syn), Err(TcpError::MalformedPacket));
            let ack = pkt(
                (ip, 1234),
                SRV,
                42,
                7,
                flags::ACK,
                65535,
                &TcpOptions::NONE,
                &[],
            );
            let _ = s.inject_packet(&ack);
            let out = drain(&mut s);
            assert!(out.is_empty(), "busy {busy}: answered {ip:?}: {out:?}");
        }
    }
}

/// A host-secret rotation between a cookie SYN-ACK and its ACK: the derived
/// cookie key keeps the previous key valid, but the TSecr was checked
/// against the new secret's timestamp offset, so the connection came up
/// with timestamps, window scaling and SACK off while the client had them
/// on (and read our windows scaled). The cookie key that issued the SYN-ACK
/// now keys its offset.
#[test]
fn a_host_secret_rotation_keeps_a_cookie_handshakes_options() {
    let o = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ts: Some((100, 0)),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    let (mut s, synack) = cookie_listener(10_000, CLI, &o);
    let tsval = synack.opts.ts.expect("the SYN-ACK has timestamps").0;
    s.set_secret(&[5; 16]);
    let third = pkt(
        CLI,
        SRV,
        501,
        synack.seq + 1,
        flags::ACK | flags::PSH,
        65535,
        &ts(101, tsval),
        b"GET /",
    );
    // A listener set up after the rotation gets the old secret, then the new.
    let mut s = hand_off(&mut s, &third, 10_050, |t| {
        t.set_secret(&[4; 16]);
        t.set_secret(&[5; 16]);
    });
    assert_eq!(s.state(), State::Established);
    assert_eq!(s.stats().mss, 1448, "timestamps off");
    s.set_now(10_100);
    s.tick().unwrap();
    let ack = drain(&mut s).pop().expect("the request is acknowledged");
    let advance = ack.opts.ts.expect("no timestamps").0.wrapping_sub(tsval);
    assert!(advance <= 100 + 64, "TSval jumped by {advance}");
}

/// Each smaller path-MTU report resends whatever no longer fits, so forged
/// reports a byte apart cost about a flight each. Linux takes an ICMP only
/// if the sequence number it quotes is in flight (`tcp_v4_err`);
/// `update_pmtu_icmp` checks it too.
#[test]
fn a_path_mtu_report_must_quote_a_sequence_number_in_flight() {
    let (mut c, _, iss) = established(1000, true, false);
    let flight = send_burst(&mut c, 1010, 10 * 1448);
    let (una, nxt) = (iss + 1, flight.last().unwrap().1);
    for seq in [una.wrapping_sub(1), nxt + 1, una.wrapping_add(1 << 30)] {
        assert_eq!(c.update_pmtu_icmp(1400, seq), Err(TcpError::NotForUs));
    }
    assert!(drain(&mut c).is_empty(), "a forged report resent data");
    assert_eq!(c.stats().mss, 1448);
    c.update_pmtu_icmp(1400, una + 1448).unwrap();
    assert_eq!(c.stats().mss, 1400 - 40 - 12);
    assert!(drain(&mut c).iter().any(|o| o.len > 0), "nothing resent");
}

/// A report larger than the size in use lowered the size probing restores
/// for good: 576 and then 580 (reordered reports, or forged ones) left the
/// connection at 528-byte segments forever, where 576 alone expires in 10
/// minutes. Restoring a capped size now probes the full one again 10
/// minutes later, as Linux re-probes.
#[test]
fn a_larger_path_mtu_report_does_not_make_a_reduction_permanent() {
    let run = |reports: &[u16]| {
        let (mut c, sseq, iss) = established(1000, true, false);
        ts_ack(&mut c, sseq, 1020, iss + 1, 1000, &[]);
        for &mtu in reports {
            c.update_pmtu(mtu);
        }
        for minute in 1..=30 {
            let now = 1020 + minute * 60_000;
            send_burst(&mut c, now, 3 * 1448);
            let end = c.debug_snapshot().snd_nxt;
            ts_ack(&mut c, sseq, now + 1, end, now as u32, &[]);
        }
        c.stats().mss
    };
    assert_eq!(run(&[576]), 1448);
    assert_eq!(run(&[576, 580]), 1448, "the reduction became permanent");
}

/// Opens `c`'s connection after `retries` SYN timeouts; the SYN-ACK has
/// timestamps echoing the SYN sent at `echo` (an index into the SYNs), or
/// none. Returns the time it arrived.
fn open_after_syn_timeouts(c: &mut Tcb, retries: usize, echo: Option<usize>) -> u64 {
    c.set_now(1000);
    c.connect().unwrap();
    let mut tsvals = vec![drain(c)[0].opts.ts.unwrap().0];
    let mut now = 1000;
    for _ in 0..retries {
        now = c.next_deadline().unwrap();
        c.set_now(now);
        c.tick().unwrap();
        tsvals.push(drain(c)[0].opts.ts.unwrap().0);
    }
    now += 10;
    c.set_now(now);
    let o = TcpOptions {
        mss: Some(1460),
        ts: echo.map(|i| (7, tsvals[i])),
        ..TcpOptions::NONE
    };
    let synack = pkt(
        SRV,
        CLI,
        SRV_ISS,
        1_000_001,
        flags::SYN | flags::ACK,
        65535,
        &o,
        &[],
    );
    c.inject_packet(&synack).unwrap();
    drain(c);
    now
}

/// A handshake that gave no RTT sample (a SYN resent, no timestamps) left
/// the SYN timer's backoff as the first data RTO: 2 s after one timeout, a
/// minute after six. Linux falls back to 3 s (`tcp_init_metrics`, RFC 6298
/// §5.7).
#[test]
fn the_first_data_rto_after_an_unsampled_handshake_is_three_seconds() {
    for retries in [1, 6] {
        let mut c = new_tcb(CLI, SRV, 1_000_000);
        let now = open_after_syn_timeouts(&mut c, retries, None);
        c.send(b"first request").unwrap();
        c.tick().unwrap();
        drain(&mut c);
        assert_eq!(c.stats().rto_ms, 3000, "{retries} SYN timeouts");
        assert_eq!(
            c.next_deadline(),
            Some(now + 3000),
            "{retries} SYN timeouts"
        );
    }
}

/// More than one SYN timeout used to leave a ten-segment initial window.
/// Linux starts such a transfer from one segment (`tcp_init_transfer`),
/// unless the SYN-ACK's TSecr shows the first SYN arrived after all.
#[test]
fn repeated_syn_timeouts_start_the_transfer_from_one_segment() {
    for (retries, echo, want) in [
        (1, None, 10),
        (2, None, 1),
        (2, Some(2), 1),
        (2, Some(0), 10),
    ] {
        let mut c = new_tcb(CLI, SRV, 1_000_000);
        open_after_syn_timeouts(&mut c, retries, echo);
        c.send(&[0x5a; 14 * 1448]).unwrap();
        c.tick().unwrap();
        let sent = drain(&mut c).iter().filter(|o| o.len > 0).count();
        assert_eq!(sent, want, "{retries} timeouts, echo of SYN {echo:?}");
    }
}

/// `recv` takes no clock (the C API has no time argument), so a read on a
/// turn with no datagram restarted the FIN_WAIT_2 timeout from the last
/// turn's time: data read a second before the old deadline left a second.
/// The next `tick` now restarts it from its own time.
#[test]
fn a_read_restarts_fin_wait_2_from_the_time_of_its_turn() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1010);
    c.close().unwrap();
    drain(&mut c);
    c.set_now(1030);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 2,
        flags::ACK | flags::PSH,
        8192,
        &ts(2, 0),
        b"ab",
    ))
    .unwrap();
    c.tick().unwrap();
    drain(&mut c);
    assert_eq!(c.state(), State::FinWait2);
    assert_eq!(c.next_deadline(), Some(61_030));
    let mut byte = [0u8; 1];
    assert_eq!(c.recv(&mut byte), Ok(1));
    c.set_now(60_000);
    c.tick().unwrap();
    assert_eq!(c.next_deadline(), Some(120_000));
    c.set_now(61_030);
    c.tick().unwrap();
    assert_eq!(
        c.state(),
        State::FinWait2,
        "timed out a second after a read"
    );
}

/// An undo (F-RTO here) returns to Open while the head's retransmission is
/// still out, marked lost and retransmitted; `lost_bytes() > 0` then
/// re-entered fast recovery on the very ACK that undid the episode. Linux
/// clears every loss mark on undo (`tcp_undo_cwnd_reduction`), so only a
/// segment still awaiting its retransmission starts recovery.
#[test]
fn an_undo_does_not_reenter_recovery_for_a_resend_in_flight() {
    let (mut c, sseq, _) = established_rtt(1000, 10, true, false);
    let segs = send_burst(&mut c, 1020, 4 * 1448);
    let cwnd = c.stats().cwnd;
    let (_, now) = until_rto(&mut c, 1020, segs[0].0);
    assert_eq!(c.stats().ca_state, 2, "no timeout");
    ts_ack(
        &mut c,
        sseq,
        now + 1,
        segs[0].0,
        65535,
        &[(segs[1].0, segs[1].1)],
    );
    drain(&mut c);
    assert_eq!(c.stats().ca_state, 0, "recovery re-entered after the undo");
    assert_eq!(c.stats().fast_recoveries, 0);
    assert_eq!(c.stats().cwnd, cwnd);
}

/// The same after a close in SYN_RCVD whose SYN-ACK timed out: the FIN it
/// queued was marked lost and resent, and the third ACK entered fast
/// recovery with nothing left to resend.
#[test]
fn the_third_ack_after_a_syn_ack_timeout_and_a_close_starts_no_recovery() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 7);
    s.set_secret(&[1; 16]);
    s.set_now(1000);
    s.listen().unwrap();
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    let synack = drain(&mut s).remove(0);
    s.close().unwrap();
    drain(&mut s);
    let rto = s.next_deadline().unwrap();
    s.set_now(rto);
    s.tick().unwrap();
    drain(&mut s);
    s.set_now(rto + 10);
    s.inject_packet(&third_ack(CLI, &synack)).unwrap();
    drain(&mut s);
    assert_eq!(
        s.stats().fast_recoveries,
        0,
        "the third ACK started recovery"
    );
    assert_eq!(s.stats().ca_state, 0);
}

/// Each listener transition (a SYN taking the slot, an exact RST freeing
/// it, a cookie promotion) reset the per-TCB rate limit on replies to
/// stray segments, so cycling LISTEN ↔ SYN_RCVD with a known ISN drew a
/// RST per stray ACK at line rate instead of one per 500 ms. The limit now
/// spans connections, as Linux keeps it on the socket.
#[test]
fn listener_transitions_keep_the_reply_rate_limit() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 1);
    s.set_secret(&[4; 16]);
    s.set_now(10_000);
    s.listen().unwrap();
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    let mut rsts = 0;
    for k in 0..10u8 {
        let stray = pkt(
            ([192, 0, 2, k], 40_000),
            SRV,
            1,
            2,
            flags::ACK,
            65535,
            &TcpOptions::NONE,
            &[],
        );
        let _ = s.inject_packet(&stray);
        rsts += drain(&mut s)
            .iter()
            .filter(|o| o.flags & flags::RST != 0)
            .count();
        s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &mss, &[]))
            .unwrap();
        s.inject_packet(&pkt(
            CLI,
            SRV,
            501,
            0,
            flags::RST,
            0,
            &TcpOptions::NONE,
            &[],
        ))
        .unwrap();
        drain(&mut s);
    }
    assert_eq!(rsts, 1, "{rsts} RSTs to stray ACKs within one millisecond");
}

/// A listener transition cleared the egress ring, losing what was staged
/// for other peers: a cookie SYN-ACK queued behind the host's full device
/// queue vanished when the half-open's RST freed the slot.
#[test]
fn listener_transitions_keep_packets_staged_for_other_peers() {
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    let (mut s, _) = cookie_listener(10_000, CLI, &mss);
    let other = ([10, 0, 0, 99], 55_555);
    s.inject_packet(&pkt(other, SRV, 800, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    let rst = pkt(ATTACKER, SRV, 10, 0, flags::RST, 0, &TcpOptions::NONE, &[]);
    s.inject_packet(&rst).unwrap();
    assert_eq!(s.state(), State::Listen);
    assert!(
        drain(&mut s)
            .iter()
            .any(|o| o.dst == other && o.flags & flags::SYN != 0),
        "the cookie SYN-ACK staged for another peer was dropped"
    );
}

/// A D-SACK for a segment above SND.UNA that was never resent (the network
/// copied it, or the peer forged the block) counted toward the undo of a
/// real loss episode whenever any retransmission had happened. Linux counts
/// a D-SACK of queued data only for segments it resent (`tcp_sacktag_one`).
#[test]
fn a_dsack_for_data_never_resent_does_not_undo_a_real_loss() {
    let (mut c, sseq, _) = established_rtt(1000, 10, true, false);
    let segs = send_burst(&mut c, 1020, 5 * 1448);
    let resent = ts_ack(
        &mut c,
        sseq,
        1030,
        segs[0].0,
        1020,
        &[(segs[1].0, segs[3].1)],
    );
    assert_eq!(
        resent.first().map(|o| o.seq),
        Some(segs[0].0),
        "no fast retransmit"
    );
    let reduced = c.stats().ssthresh;
    ts_ack(
        &mut c,
        sseq,
        1045,
        segs[4].1,
        1030,
        &[(segs[4].0, segs[4].1)],
    );
    assert_eq!(
        c.stats().cwnd,
        reduced,
        "a duplicate of data sent once undid the loss"
    );
}

/// A tail loss probe the peer's shrunken window cut short recorded SND.NXT
/// as its end, so RACK did not recognise the SACK of the part sent as the
/// probe's and found nothing lost. It now records the end of what was sent.
#[test]
fn a_tail_loss_probe_cut_by_the_window_is_recognised_by_its_end() {
    let (mut c, sseq, iss) = established_rtt(1000, 10, true, false);
    let segs = send_burst(&mut c, 1020, 2 * 1448);
    c.set_now(1025);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 101,
        flags::ACK,
        15,
        &ts(7, 1020),
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let pto = c.next_deadline().unwrap();
    c.set_now(pto);
    c.tick().unwrap();
    let probe = drain(&mut c);
    assert_eq!(probe.len(), 1);
    assert_eq!((probe[0].seq, probe[0].len), (segs[1].0, 572));
    ts_ack(
        &mut c,
        sseq,
        pto + 2,
        iss + 101,
        1020,
        &[(segs[1].0, segs[1].0 + 572)],
    );
    assert_eq!(
        c.stats().fast_recoveries,
        1,
        "the probe's SACK found no loss"
    );
}

/// A pure ACK below RCV.NXT with a TSval older than TS.Recent drew a
/// (rate-limited) duplicate ACK; Linux drops it silently (`PAWS_OLD_ACK`).
/// The check meant to do so came after the window check, which such an ACK
/// never passes.
#[test]
fn an_old_pure_ack_failing_paws_is_dropped_silently() {
    let (mut c, sseq, iss) = established(1000, true, false);
    c.set_now(1020);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq,
        iss + 1,
        flags::ACK,
        8192,
        &ts(200, 1000),
        b"hello",
    ))
    .unwrap();
    drain(&mut c);
    c.set_now(1025);
    c.inject_packet(&pkt(
        SRV,
        CLI,
        sseq + 2,
        iss + 1,
        flags::ACK,
        8192,
        &ts(50, 1000),
        &[],
    ))
    .unwrap();
    assert!(
        drain(&mut c).is_empty(),
        "an old ACK failing PAWS was answered"
    );
}

/// An old SYN (a TSval below the one that opened the half-open) in
/// SYN_RCVD skipped PAWS: in the window it sent the half-open back to
/// LISTEN. Linux ACKs and drops it (`tcp_check_req`).
#[test]
fn an_old_syn_in_syn_rcvd_fails_paws() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 1);
    s.set_secret(&[4; 16]);
    s.set_now(10_000);
    s.listen().unwrap();
    let syn = |tsval| TcpOptions {
        mss: Some(1460),
        ts: Some((tsval, 0)),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &syn(1000), &[]))
        .unwrap();
    drain(&mut s);
    s.set_now(10_010);
    s.inject_packet(&pkt(CLI, SRV, 501, 0, flags::SYN, 65535, &syn(500), &[]))
        .unwrap();
    drain(&mut s);
    assert_eq!(s.state(), State::SynRcvd, "an old SYN reset the half-open");
}

/// A cookie ACK from another peer used to take a listener's slot from a
/// live half-open: its client's third ACK then reached the next listener
/// and was reset just after `connect()` succeeded, as happens when
/// connections arrive in bursts. A busy listener now hands such an ACK back
/// (`ListenerBusy`) for a fresh listener to take, so both connect, as with
/// Linux's independent request sockets. A half-open whose SYN-ACK went
/// unanswered for an RTO (a spoofed source, typically) still yields to it.
#[test]
fn a_cookie_ack_never_displaces_a_live_half_open() {
    let mss = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    let other = ([10, 0, 0, 7], 41_000);
    let mut s = new_tcb(SRV, ([0; 4], 0), 1);
    s.set_secret(&[4; 16]);
    s.set_now(10_000);
    s.listen().unwrap();
    s.inject_packet(&pkt(CLI, SRV, 500, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    let synack = drain(&mut s).remove(0);
    s.inject_packet(&pkt(other, SRV, 500, 0, flags::SYN, 65535, &mss, &[]))
        .unwrap();
    let cookie = drain(&mut s).remove(0);
    let fresh = hand_off(&mut s, &third_ack(other, &cookie), 10_010, |t| {
        t.set_secret(&[4; 16])
    });
    assert_eq!(fresh.state(), State::Established, "the cookie client");
    assert!(drain(&mut s).is_empty(), "answered the handed-back ACK");
    s.set_now(10_020);
    s.inject_packet(&third_ack(CLI, &synack)).unwrap();
    assert_eq!(s.state(), State::Established, "the half-open's client");

    // A half-open whose SYN-ACK needed a retransmission yields the slot.
    let (mut s, cookie) = cookie_listener(20_000, other, &mss);
    s.set_now(21_000);
    s.tick().unwrap();
    drain(&mut s);
    s.inject_packet(&third_ack(other, &cookie)).unwrap();
    assert_eq!(s.state(), State::Established, "a stale half-open held on");
}
