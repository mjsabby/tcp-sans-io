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

/// A SYN-ACK arriving at a listener draws a RST addressed to its sender (it
/// used to go to 0.0.0.0:0), and replies are rate limited so a listener
/// cannot be used to reflect RSTs at line rate.
#[test]
fn listener_rst_goes_to_sender_and_is_rate_limited() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
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

/// A non-cookie listener holds one half-open. A spoofed SYN (whose source
/// never completes the handshake) used to lock it for ~63 s; once the
/// half-open has needed a SYN-ACK retransmission, a SYN from a new peer
/// replaces it.
#[test]
fn spoofed_syn_cannot_lock_stateful_listener() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_now(0);
    s.listen().unwrap();
    let syn = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    s.inject_packet(&pkt(ATTACKER, SRV, 1, 0, flags::SYN, 65535, &syn, &[]))
        .unwrap();
    drain(&mut s);
    // A fresh half-open is protected: a concurrent SYN is turned away...
    s.set_now(100);
    assert_eq!(
        s.inject_packet(&pkt(CLI, SRV, 77, 0, flags::SYN, 65535, &syn, &[])),
        Err(TcpError::NotForUs)
    );
    // ...but after the first SYN-ACK retransmission (1 s RTO) it yields.
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
}

/// SYN cookies used to drop window scaling and SACK (64 KiB window cap, no
/// selective recovery). They are now carried in the TSval low bits.
#[test]
fn cookie_connections_keep_window_scaling_and_sack() {
    let mut s = new_tcb(SRV, ([0; 4], 0), 4242);
    s.set_now(10_000);
    s.listen().unwrap();
    s.set_cookie_secret(&[7u8; 16]);
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

/// FIN_WAIT_2 is refreshed while the peer keeps sending on its half.
#[test]
fn fin_wait_2_survives_while_peer_sends() {
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
        assert_eq!(
            c.state(),
            State::FinWait2,
            "half-closed peer still sending at +{k}x50s"
        );
    }
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
