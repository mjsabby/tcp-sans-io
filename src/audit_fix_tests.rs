//! Regression tests for the main-branch audit: each test pins one finding
//! (see the test's comment for what used to happen).

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
use crate::wire::{self, flags, TcpOptions};
use crate::{State, TcpError, MAX_PACKET};

type Ep = ([u8; 4], u16);
const SRV: Ep = ([10, 0, 0, 1], 80);
const A: Ep = ([10, 0, 0, 2], 40000);
const B: Ep = ([10, 0, 0, 3], 40001);
const X: Ep = ([198, 18, 0, 9], 5555);

fn ep(e: Ep) -> Endpoint {
    Endpoint { ip: e.0, port: e.1 }
}

#[allow(clippy::too_many_arguments)]
fn pkt(
    src: Ep,
    dst: Ep,
    seq: u32,
    ack: u32,
    fl: u8,
    win: u16,
    opts: &TcpOptions,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = vec![0u8; MAX_PACKET + payload.len()];
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
        9,
        wire::ecn::NOT_ECT,
    )
    .unwrap();
    b.truncate(n);
    b
}

#[derive(Debug, Clone)]
struct Out {
    dst: Ep,
    seq: u32,
    ack: u32,
    flags: u8,
    total_len: usize,
    ip_id: u16,
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
            total_len: n,
            ip_id: u16::from_be_bytes([buf[4], buf[5]]),
            opts: s.options,
        });
    }
    v
}

fn listener() -> Box<Tcb> {
    let mut t = Box::new(
        Tcb::new(TcbConfig {
            local: ep(SRV),
            remote: ep(([0; 4], 0)),
            iss: 77,
            initial_rto_ms: 1000,
        })
        .unwrap(),
    );
    t.set_secret(&[0x42; 16]);
    // No backlog beside the slot: these tests pin the cookie path, which
    // overlapping handshakes take once the backlog is full.
    t.set_listen_backlog(0);
    t.set_now(0);
    t.listen().unwrap();
    t
}

fn syn_opts(ts: Option<u32>, sack: bool, ws: Option<u8>) -> TcpOptions {
    TcpOptions {
        mss: Some(1460),
        wscale: ws,
        ts: ts.map(|v| (v, 0)),
        sack_permitted: sack,
        ..TcpOptions::NONE
    }
}

fn ts(v: u32, e: u32) -> TcpOptions {
    TcpOptions {
        ts: Some((v, e)),
        ..TcpOptions::NONE
    }
}

fn syn(src: Ep, seq: u32, o: &TcpOptions) -> Vec<u8> {
    pkt(src, SRV, seq, 0, flags::SYN, 65535, o, &[])
}

/// A half-open that loses the listener's only slot used to be lost: its
/// ISN was not a cookie, so its valid third ACK was dropped everywhere,
/// unanswered, and the client retransmitted until its own timeout. The
/// slot's SYN-ACK is now a cookie too.
#[test]
fn displaced_half_open_completes_by_cookie_with_its_options() {
    let mut s = listener();
    s.inject_packet(&syn(A, 100, &syn_opts(Some(500), true, Some(7))))
        .unwrap();
    let sa = drain(&mut s).remove(0);
    assert_eq!((sa.dst, sa.flags), (A, flags::SYN | flags::ACK));
    assert!(sa.opts.sack_permitted && sa.opts.wscale.is_some());
    assert_eq!(s.remote(), Some(ep(A)));

    // B is answered with a cookie and, completing first, takes the slot.
    s.set_now(5);
    s.inject_packet(&syn(B, 200, &syn_opts(Some(900), true, Some(7))))
        .unwrap();
    let sb = drain(&mut s).remove(0);
    assert_eq!(sb.dst, B);
    s.set_now(10);
    let b_ack = ts(901, sb.opts.ts.unwrap().0);
    s.inject_packet(&pkt(
        B,
        SRV,
        201,
        sb.seq + 1,
        flags::ACK,
        65535,
        &b_ack,
        &[],
    ))
    .unwrap();
    assert_eq!(s.state(), State::Established);
    assert_eq!(s.remote(), Some(ep(B)));

    // A's third ACK (with data) at the host's next listener.
    let a_ack = pkt(
        A,
        SRV,
        101,
        sa.seq + 1,
        flags::ACK | flags::PSH,
        65535,
        &ts(501, sa.opts.ts.unwrap().0),
        b"hello",
    );
    assert_eq!(s.inject_packet(&a_ack), Err(TcpError::NotForUs));
    let mut f = listener();
    f.set_now(20);
    f.inject_packet(&a_ack).unwrap();
    assert_eq!(f.state(), State::Established);
    assert_eq!(f.remote(), Some(ep(A)));
    let mut buf = [0u8; 16];
    assert_eq!(f.recv(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");
    // Window scaling (7) and timestamps came through the cookie.
    assert_eq!(f.stats().snd_wnd, 65535 << 7);
    let out = drain(&mut f);
    assert!(out.iter().all(|o| o.opts.ts.is_some()));
}

/// Without timestamps nothing can carry window scaling or SACK through a
/// cookie: such a half-open's ISN is marked, and once it lost the slot its
/// ACK draws a RST (it used to be dropped silently) rather than a
/// connection that disagrees with the client about its options.
#[test]
fn displaced_half_open_whose_options_no_cookie_carries_is_reset() {
    let mut s = listener();
    s.inject_packet(&syn(A, 100, &syn_opts(None, true, Some(7))))
        .unwrap();
    let sa = drain(&mut s).remove(0);
    // Its SYN-ACK goes unanswered for an RTO; a spoofed SYN takes the slot.
    s.set_now(1000);
    s.tick().unwrap();
    drain(&mut s);
    s.set_now(1001);
    s.inject_packet(&syn(X, 7, &syn_opts(None, false, None)))
        .unwrap();
    drain(&mut s);
    assert_eq!(s.remote(), Some(ep(X)));

    let a_ack = pkt(
        A,
        SRV,
        101,
        sa.seq + 1,
        flags::ACK,
        65535,
        &TcpOptions::NONE,
        &[],
    );
    s.inject_packet(&a_ack).unwrap();
    let out = drain(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].dst, out[0].flags, out[0].seq),
        (A, flags::RST, sa.seq + 1)
    );
    assert_eq!(out[0].ip_id, 0);
    assert_eq!(s.remote(), Some(ep(X)), "the slot is undisturbed");

    let mut f = listener();
    f.set_now(1002);
    f.inject_packet(&a_ack).unwrap();
    assert_eq!(f.state(), State::Listen);
    let out = drain(&mut f);
    assert_eq!((out.len(), out[0].flags), (1, flags::RST));
}

/// A client that offered nothing a cookie cannot carry completes after
/// losing the slot, timestamps or not.
#[test]
fn displaced_half_open_without_options_completes() {
    let mut s = listener();
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    let sa = drain(&mut s).remove(0);
    let mut f = listener();
    f.set_now(30);
    f.inject_packet(&pkt(
        A,
        SRV,
        101,
        sa.seq + 1,
        flags::ACK,
        4096,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(f.state(), State::Established);
    assert_eq!(f.stats().snd_wnd, 4096);
}

/// RFC 9293 §3.10.7.2: an ACK that is no cookie draws `<SEQ=SEG.ACK><RST>`
/// from a listener, idle or busy (it used to be dropped silently, leaving a
/// stranded peer to time out), at most one per rate-limit interval.
#[test]
fn stray_ack_to_a_listener_draws_one_rate_limited_rst() {
    let mut s = listener();
    let stray = pkt(
        X,
        SRV,
        5,
        0xdead_beef,
        flags::ACK,
        100,
        &TcpOptions::NONE,
        b"x",
    );
    s.inject_packet(&stray).unwrap();
    let out = drain(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].dst, out[0].flags, out[0].seq),
        (X, flags::RST, 0xdead_beef)
    );
    assert_eq!(out[0].ip_id, 0);
    s.set_now(100);
    s.inject_packet(&stray).unwrap();
    assert!(drain(&mut s).is_empty(), "rate limited");
    assert_eq!(s.state(), State::Listen);

    // Busy with A's half-open: the same answer, and the limit carries over.
    s.set_now(700);
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    drain(&mut s);
    s.inject_packet(&stray).unwrap();
    let out = drain(&mut s);
    assert_eq!((out.len(), out[0].flags, out[0].dst), (1, flags::RST, X));
    s.set_now(800);
    s.inject_packet(&stray).unwrap();
    assert!(drain(&mut s).is_empty());
    assert_eq!(s.remote(), Some(ep(A)));
}

/// The listener's packets to would-be peers carry IP ID 0: a counter
/// shared by all of them let a stranger count the packets sent to others.
#[test]
fn listener_packets_to_strangers_carry_ip_id_zero() {
    let mut s = listener();
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    let sa = drain(&mut s).remove(0);
    assert_eq!(sa.ip_id, 0);
    for k in 0..3u32 {
        s.inject_packet(&syn(X, 7 + k, &syn_opts(None, false, None)))
            .unwrap();
        // The half-open's SYN-ACK is repeated in between.
        s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
            .unwrap();
        s.set_now(u64::from(k + 1) * 600);
        for o in drain(&mut s) {
            assert_eq!(o.flags, flags::SYN | flags::ACK);
            assert_eq!(o.ip_id, 0, "to {:?}", o.dst);
        }
    }
}

/// Segments from sources no host sends from, or claiming this endpoint as
/// their source, are dropped: a listener used to aim up to six SYN-ACKs at
/// a multicast group or the broadcast address.
#[test]
fn martian_and_own_address_sources_are_dropped() {
    let mut s = listener();
    for src in [
        ([224, 0, 0, 5], 9),
        ([255, 255, 255, 255], 9),
        ([0, 1, 2, 3], 9),
        ([127, 0, 0, 1], 9),
        SRV,
    ] {
        let r = s.inject_packet(&syn(src, 1, &syn_opts(None, false, None)));
        assert_eq!(r, Err(TcpError::MalformedPacket), "{src:?}");
        assert_eq!(s.state(), State::Listen);
        assert!(drain(&mut s).is_empty());
    }
}

/// RFC 9293 §3.10.7.1: a closed TCB answers its former peer's segments with
/// a RST (rate limited) instead of leaving it to time out; never a SYN,
/// which may be meant for the host's listener.
#[test]
fn closed_tcb_resets_its_former_peer() {
    let mut s = listener();
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    let sa = drain(&mut s).remove(0);
    s.inject_packet(&pkt(
        A,
        SRV,
        101,
        sa.seq + 1,
        flags::ACK,
        4096,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(s.state(), State::Established);
    s.abort().unwrap();
    let out = drain(&mut s);
    assert_eq!((out.len(), out[0].flags), (1, flags::RST | flags::ACK));
    assert_eq!(s.state(), State::Closed);

    s.set_now(1000);
    let data = pkt(
        A,
        SRV,
        101,
        sa.seq + 1,
        flags::ACK,
        4096,
        &TcpOptions::NONE,
        b"late",
    );
    assert_eq!(s.inject_packet(&data), Err(TcpError::InvalidState));
    let out = drain(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].dst, out[0].flags, out[0].seq),
        (A, flags::RST, sa.seq + 1)
    );
    s.set_now(1100);
    assert_eq!(s.inject_packet(&data), Err(TcpError::InvalidState));
    assert!(drain(&mut s).is_empty(), "rate limited");
    s.set_now(2000);
    let _ = s.inject_packet(&syn(A, 900, &syn_opts(None, false, None)));
    assert!(
        drain(&mut s).is_empty(),
        "a SYN is left to the host's listener"
    );
}

/// `close()` in SYN_RCVD used to queue a FIN behind a SYN-ACK nothing
/// retransmitted any more: with the SYN-ACK lost, the TCB sent FINs for
/// 300 s. It now resets the half-open and closes.
#[test]
fn close_in_syn_rcvd_resets_the_half_open() {
    let mut s = listener();
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    let sa = drain(&mut s).remove(0);
    s.close().unwrap();
    assert_eq!(s.state(), State::Closed);
    let out = drain(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].dst, out[0].flags, out[0].seq, out[0].ack),
        (A, flags::RST | flags::ACK, sa.seq + 1, 101)
    );
    assert_eq!(s.next_deadline(), None);
    s.debug_validate_invariants().unwrap();
}

/// `abort()` with the egress ring full used to lose its RST. It is now owed
/// and staged as soon as the host extracts a packet.
#[test]
fn abort_with_a_full_egress_ring_still_sends_its_rst() {
    let mut s = listener();
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    drain(&mut s);
    // Cookie SYN-ACKs to others fill the ring (the host is not draining).
    for k in 0..200u32 {
        let src = ([198, 18, 1, (k % 250) as u8], 2000 + k as u16);
        s.inject_packet(&syn(src, k, &syn_opts(None, false, None)))
            .unwrap();
    }
    s.abort().unwrap();
    assert_eq!(s.state(), State::Closed);
    let out = drain(&mut s);
    let rsts: Vec<&Out> = out.iter().filter(|o| o.flags & flags::RST != 0).collect();
    assert_eq!(rsts.len(), 1, "of {} packets", out.len());
    assert_eq!(rsts[0].dst, A);
    assert_eq!(out.last().unwrap().flags & flags::RST, flags::RST);
}

fn client() -> (Box<Tcb>, u32) {
    let iss = 7_000_000;
    let mut c = Box::new(
        Tcb::new(TcbConfig {
            local: ep(A),
            remote: ep(SRV),
            iss,
            initial_rto_ms: 1000,
        })
        .unwrap(),
    );
    c.set_now(0);
    c.connect().unwrap();
    (c, iss)
}

/// A spoofed bare SYN during an active open (it needs the port, no sequence
/// number) moved the client to SYN_RCVD with a forged IRS; the server's
/// genuine SYN-ACK was then refused and the connect failed. The SYN-ACK
/// acknowledges our SYN, as SYN-SENT requires, so it is taken.
#[test]
fn spoofed_syn_does_not_derail_an_active_open() {
    let (mut c, iss) = client();
    drain(&mut c);
    c.set_now(3);
    c.inject_packet(&pkt(
        SRV,
        A,
        0x6666_0000,
        0,
        flags::SYN,
        100,
        &syn_opts(Some(1), false, None),
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::SynRcvd);
    drain(&mut c);
    c.set_now(10);
    c.inject_packet(&pkt(
        SRV,
        A,
        5000,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &syn_opts(None, false, None),
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::Established);
    let out = drain(&mut c);
    assert_eq!((out.len(), out[0].flags, out[0].ack), (1, flags::ACK, 5001));
    assert!(
        out[0].opts.ts.is_none(),
        "the forged SYN's options are gone"
    );
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 1,
        flags::ACK,
        8192,
        &TcpOptions::NONE,
        b"data",
    ))
    .unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(c.recv(&mut buf).unwrap(), 4);
    c.debug_validate_invariants().unwrap();
}

/// Client established with timestamps and SACK against a scripted server
/// whose next sequence number is 5001. Returns (tcb, client ISS).
fn established_ts() -> (Box<Tcb>, u32) {
    let (mut c, iss) = client();
    let s = drain(&mut c).remove(0);
    let o = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ts: Some((1, s.opts.ts.unwrap().0)),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    c.set_now(10);
    c.inject_packet(&pkt(
        SRV,
        A,
        5000,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &o,
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::Established);
    drain(&mut c);
    (c, iss)
}

/// A duplicate-data segment carrying an ACK older than SND.UNA (acceptable
/// within a whole window below it, so far easier to guess than a current
/// one) used to move TS.Recent: one forged segment with a far-future TSval
/// made PAWS drop everything the real peer sent afterwards.
#[test]
fn old_ack_cannot_move_ts_recent() {
    let (mut c, iss) = established_ts();
    c.send(&[7u8; 3000]).unwrap();
    c.set_now(20);
    c.tick().unwrap();
    drain(&mut c);
    c.set_now(30);
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 3001,
        flags::ACK,
        8192,
        &ts(2, 0),
        &[],
    ))
    .unwrap();
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 3001,
        flags::ACK,
        8192,
        &ts(3, 0),
        &[1u8; 100],
    ))
    .unwrap();
    drain(&mut c);
    let mut buf = [0u8; 256];
    assert_eq!(c.recv(&mut buf).unwrap(), 100);

    c.set_now(40);
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 1001,
        flags::ACK,
        8192,
        &ts(0x4000_0000, 0),
        &[1u8; 100],
    ))
    .unwrap();
    drain(&mut c);
    c.set_now(50);
    c.inject_packet(&pkt(
        SRV,
        A,
        5101,
        iss + 3001,
        flags::ACK,
        8192,
        &ts(4, 0),
        b"genuine",
    ))
    .unwrap();
    let n = c.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"genuine", "PAWS discarded the peer's data");
}

/// An ICMP "fragmentation needed" is believed only if it quotes a sequence
/// number in flight, and the reduction is not permanent: after 10 minutes a
/// segment probes the old size again (it used to hold for the connection's
/// life, with nothing for the host to check a forged report against).
#[test]
fn icmp_pmtu_report_is_checked_and_expires() {
    let (mut c, iss) = established_ts();
    c.send(&[7u8; 4 * 1448]).unwrap();
    c.set_now(20);
    c.tick().unwrap();
    let segs = drain(&mut c);
    assert!(segs.iter().all(|s| s.total_len == 1500));
    c.set_now(30);
    assert_eq!(
        c.update_pmtu_icmp(1280, iss.wrapping_add(50_000)),
        Err(TcpError::NotForUs)
    );
    assert_eq!(c.update_pmtu_icmp(1280, iss), Err(TcpError::NotForUs));
    assert!(drain(&mut c).is_empty());
    assert_eq!(c.stats().mss, 1448);

    assert_eq!(c.update_pmtu_icmp(1280, segs[1].seq), Ok(()));
    let out = drain(&mut c);
    assert!(!out.is_empty() && out.iter().all(|p| p.total_len <= 1280));
    assert_eq!(c.stats().mss, 1228);
    // Everything is acknowledged; the clamp holds for 10 minutes.
    let mut una = iss + 1 + 4 * 1448;
    c.set_now(40);
    c.inject_packet(&pkt(SRV, A, 5001, una, flags::ACK, 8192, &ts(2, 0), &[]))
        .unwrap();
    drain(&mut c);
    let mut now = 40u64;
    let mut tsv = 3;
    let round = |c: &mut Tcb, now: u64, una: &mut u32, tsv: &mut u32| -> usize {
        c.set_now(now);
        c.send(&[9u8; 6000]).unwrap();
        c.tick().unwrap();
        let out = drain(c);
        let biggest = out.iter().map(|p| p.total_len).max().unwrap_or(0);
        *una = una.wrapping_add(6000);
        c.set_now(now + 5);
        *tsv += 1;
        c.inject_packet(&pkt(
            SRV,
            A,
            5001,
            *una,
            flags::ACK,
            8192,
            &ts(*tsv, 0),
            &[],
        ))
        .unwrap();
        drain(c);
        biggest
    };
    now += 300_000;
    assert!(
        round(&mut c, now, &mut una, &mut tsv) <= 1280,
        "still clamped"
    );
    now += 300_100;
    assert_eq!(round(&mut c, now, &mut una, &mut tsv), 1500, "one probe");
    assert_eq!(round(&mut c, now + 100, &mut una, &mut tsv), 1500);
    assert_eq!(c.stats().mss, 1448, "restored once the probe arrived");
}

/// Any acceptable ACK used to restart the retransmission count, so a peer
/// that kept sending (its own data, keepalives) kept a path-MTU black hole
/// from ever being detected and the R2 abort from ever firing: the transfer
/// stalled until the USER TIMEOUT, or for good with that off. Only an ACK
/// of new data restarts it now.
#[test]
fn reverse_traffic_does_not_hide_a_black_hole_or_block_r2() {
    let (mut c, iss) = established_ts();
    c.set_user_timeout(0);
    c.send(&[7u8; 20_000]).unwrap();
    let (mut sseq, mut tsv) = (5001u32, 2u32);
    let mut clamped_at = None;
    let mut now = 20u64;
    while now < 900_000 && c.state() != State::Closed {
        c.set_now(now);
        c.tick().unwrap();
        drain(&mut c);
        if (now - 20) % 500 == 0 {
            // The peer's own data: acknowledges nothing of ours.
            tsv += 1;
            let _ = c.inject_packet(&pkt(
                SRV,
                A,
                sseq,
                iss + 1,
                flags::ACK,
                8192,
                &ts(tsv, 0),
                &[1u8; 10],
            ));
            sseq += 10;
            drain(&mut c);
            let mut buf = [0u8; 64];
            let _ = c.recv(&mut buf);
        }
        if clamped_at.is_none() && c.stats().mss < 1448 {
            clamped_at = Some(now);
        }
        now += 50;
    }
    assert!(
        clamped_at.is_some_and(|t| t < 30_000),
        "black-hole clamp after a few timeouts, got {clamped_at:?}"
    );
    assert_eq!(
        c.state(),
        State::Closed,
        "R2 gives up on unacknowledged data"
    );
    assert!(now < 600_000, "aborted at {now} ms");
}

/// The USER TIMEOUT used to count progress only in whole segments, so an
/// application trickling tiny records (always something in flight, under
/// one MSS acknowledged in 5 minutes) was aborted although every byte was
/// acknowledged promptly. Against an open window any acknowledgment counts.
#[test]
fn user_timeout_spares_a_healthy_trickle() {
    let (mut c, iss) = established_ts();
    let mut sent: Vec<(u64, u32)> = Vec::new();
    let (mut una, mut tsv) = (iss + 1, 2u32);
    let mut now = 20u64;
    while now < 400_000 {
        c.set_now(now);
        if (now - 20) % 250 == 0 {
            c.send(&[0x55]).unwrap();
        }
        c.tick().unwrap();
        for o in drain(&mut c) {
            if o.total_len > 52 {
                sent.push((now, o.seq.wrapping_add(o.total_len as u32 - 52)));
            }
        }
        // The peer acknowledges 300 ms after each segment left.
        let due = sent
            .iter()
            .filter(|&&(t, e)| t + 300 <= now && (e.wrapping_sub(una) as i32) > 0)
            .map(|&(_, e)| e)
            .last();
        if let Some(e) = due {
            una = e;
            tsv += 1;
            c.inject_packet(&pkt(SRV, A, 5001, una, flags::ACK, 8192, &ts(tsv, 0), &[]))
                .unwrap();
            drain(&mut c);
        }
        assert_eq!(c.state(), State::Established, "aborted at {now} ms");
        now += 50;
    }
    assert!(una.wrapping_sub(iss) > 1200, "the trickle was acknowledged");
}

/// The previous cookie key used to be kept only by a TCB that had itself
/// issued a cookie under it, so the host's next listener, given the old key
/// and then the new, forgot the old one and reset every client whose
/// handshake straddled the rotation.
#[test]
fn cookie_survives_a_rotation_at_the_next_listener() {
    let (k1, k2) = ([0x11u8; 16], [0x22u8; 16]);
    let mut s = listener();
    s.set_cookie_secret(&k1);
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    drain(&mut s);
    s.set_now(5);
    s.inject_packet(&syn(B, 200, &syn_opts(Some(900), true, Some(7))))
        .unwrap();
    let sb = drain(&mut s).remove(0);

    let mut f: Box<Tcb> = Box::new(
        Tcb::new(TcbConfig {
            local: ep(SRV),
            remote: ep(([0; 4], 0)),
            iss: 78,
            initial_rto_ms: 1000,
        })
        .unwrap(),
    );
    f.set_now(1000);
    f.set_secret(&[0x42; 16]);
    f.set_cookie_secret(&k1);
    f.set_cookie_secret(&k2);
    f.listen().unwrap();
    let ack = ts(901, sb.opts.ts.unwrap().0);
    f.inject_packet(&pkt(B, SRV, 201, sb.seq + 1, flags::ACK, 65535, &ack, &[]))
        .unwrap();
    assert_eq!(f.state(), State::Established);
    assert_eq!(f.remote(), Some(ep(B)));
}

/// `connect()` with the egress ring full used to stage no SYN and arm no
/// timer: SYN_SENT with nothing to wake it. The timer now sends the SYN.
#[test]
fn connect_with_a_full_egress_ring_still_sends_its_syn() {
    let mut s = listener();
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    drain(&mut s);
    for k in 0..200u32 {
        let src = ([198, 18, 2, (k % 250) as u8], 3000 + k as u16);
        s.inject_packet(&syn(src, k, &syn_opts(None, false, None)))
            .unwrap();
    }
    s.abort().unwrap();
    s.set_now(10);
    s.connect().unwrap();
    assert_eq!(s.state(), State::SynSent);
    let due = s.next_deadline().expect("a timer is armed");
    let out = drain(&mut s);
    assert!(out
        .iter()
        .all(|o| o.flags & flags::SYN == 0 || o.flags & flags::ACK != 0));
    s.set_now(due);
    s.tick().unwrap();
    let out = drain(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].dst, out[0].flags & (flags::SYN | flags::ACK)),
        (A, flags::SYN)
    );
    s.debug_validate_invariants().unwrap();
}

/// A TCB connected again without `reinit` used to repeat its configured
/// ISS on every connection (RFC 6528 asks for a fresh one). It now draws
/// one from the host secret, and refuses without a secret.
#[test]
fn reconnect_draws_a_fresh_iss_or_is_refused() {
    let (mut c, iss) = client();
    assert_eq!(drain(&mut c)[0].seq, iss);
    c.abort().unwrap();
    drain(&mut c);
    assert_eq!(c.connect(), Err(TcpError::InvalidState));
    assert_eq!(c.state(), State::Closed);
    assert!(drain(&mut c).is_empty());

    c.set_secret(&[9; 16]);
    let mut seen = vec![iss];
    for k in 1..4u64 {
        c.set_now(k * 7);
        c.connect().unwrap();
        let s = drain(&mut c);
        assert_eq!(s[0].flags & flags::SYN, flags::SYN);
        assert!(!seen.contains(&s[0].seq), "ISS {:#x} reused", s[0].seq);
        seen.push(s[0].seq);
        c.abort().unwrap();
        drain(&mut c);
    }
}

/// The other side of the rule: with a full segment or more waiting, a peer
/// that acknowledges a byte now and then is not making progress, whatever
/// window it advertises, and the USER TIMEOUT still reaps it.
#[test]
fn user_timeout_reaps_a_byte_at_a_time_acker_with_an_open_window() {
    let (mut c, iss) = established_ts();
    c.send(&[7u8; 20_000]).unwrap();
    let (mut una, mut tsv) = (iss + 1, 2u32);
    let mut now = 20u64;
    while now < 400_000 && c.state() != State::Closed {
        c.set_now(now);
        c.tick().unwrap();
        drain(&mut c);
        if (now - 20) % 60_000 == 0 {
            una += 1;
            tsv += 1;
            let _ = c.inject_packet(&pkt(SRV, A, 5001, una, flags::ACK, 8192, &ts(tsv, 0), &[]));
            drain(&mut c);
        }
        now += 50;
    }
    assert_eq!(c.state(), State::Closed);
    assert!((300_000..=301_000).contains(&now), "aborted at {now} ms");
}

/// The key setters take no clock, so the previous key's 128 s used to be
/// counted from a new listener's zero clock (or an idle one's stale clock)
/// and had expired before the first packet: a rotation reset the handshakes
/// in flight. Its lifetime now starts at the next clocked call.
#[test]
fn cookie_rotation_does_not_depend_on_the_clock_at_the_setter() {
    let (k1, k2) = ([0x11u8; 16], [0x22u8; 16]);
    let t0 = 10_000_000u64;
    let mut s = listener();
    s.set_cookie_secret(&k1);
    // An idle listener holding K1, last touched at time 0.
    let mut idle = listener();
    idle.set_cookie_secret(&k1);

    s.set_now(t0);
    s.inject_packet(&syn(A, 100, &syn_opts(None, false, None)))
        .unwrap();
    drain(&mut s);
    s.inject_packet(&syn(B, 200, &syn_opts(Some(900), true, Some(7))))
        .unwrap();
    let sb = drain(&mut s).remove(0);
    let ack = pkt(
        B,
        SRV,
        201,
        sb.seq + 1,
        flags::ACK,
        65535,
        &ts(901, sb.opts.ts.unwrap().0),
        &[],
    );

    // A new listener set up in the documented order, clock first seen at
    // `listen`.
    let mut f: Box<Tcb> = Box::new(
        Tcb::new(TcbConfig {
            local: ep(SRV),
            remote: ep(([0; 4], 0)),
            iss: 79,
            initial_rto_ms: 1000,
        })
        .unwrap(),
    );
    f.set_secret(&[0x42; 16]);
    f.set_cookie_secret(&k1);
    f.set_cookie_secret(&k2);
    f.set_now(t0 + 100);
    f.listen().unwrap();
    f.inject_packet(&ack).unwrap();
    assert_eq!(f.state(), State::Established, "new listener");

    // The idle one is rotated without a clock, then gets the packet.
    idle.set_cookie_secret(&k2);
    idle.set_now(t0 + 100);
    idle.inject_packet(&ack).unwrap();
    assert_eq!(idle.state(), State::Established, "idle listener");

    // The old key still lapses: 128 s after the rotation was first clocked.
    let mut late = listener();
    late.set_cookie_secret(&k1);
    late.set_cookie_secret(&k2);
    late.set_now(t0);
    late.tick().unwrap();
    late.set_now(t0 + 129_000);
    late.inject_packet(&ack).unwrap();
    assert_eq!(late.state(), State::Listen);
}

/// Bytes received and acknowledged, but not yet read, used to be discarded
/// when a RST (or a local timeout) followed in the same batch of packets.
/// They stay readable; the error follows the last of them, as on Linux.
#[test]
fn received_bytes_stay_readable_after_a_reset() {
    let (mut c, iss) = established_ts();
    c.set_now(30);
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 1,
        flags::ACK,
        8192,
        &ts(2, 0),
        b"last words",
    ))
    .unwrap();
    c.inject_packet(&pkt(
        SRV,
        A,
        5011,
        iss + 1,
        flags::RST,
        0,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::Closed);
    let mut buf = [0u8; 32];
    let n = c.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"last words");
    assert_eq!(c.recv(&mut buf), Err(TcpError::ConnectionReset));

    // The application's own abort discards what it has not read.
    let (mut c, iss) = established_ts();
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 1,
        flags::ACK,
        8192,
        &ts(2, 0),
        b"unread",
    ))
    .unwrap();
    c.abort().unwrap();
    assert_eq!(c.recv(&mut buf), Err(TcpError::ConnectionReset));
}

/// After a tail loss probe, the peer's own data carrying the same ACK used
/// to pass for "the probe repaired a loss" and halve the window, with
/// nothing lost: a tax on every two-way connection.
#[test]
fn peer_data_after_a_tail_loss_probe_is_not_a_loss() {
    let (mut c, iss) = established_ts();
    c.send(&[7u8; 3 * 1448]).unwrap();
    let mut now = 20u64;
    c.set_now(now);
    c.tick().unwrap();
    assert_eq!(drain(&mut c).len(), 3);
    while c.stats().tlp_count == 0 {
        now += 5;
        assert!(now < 2_000, "no tail loss probe");
        c.set_now(now);
        c.tick().unwrap();
        drain(&mut c);
    }
    // The (delayed) ACK of everything, then the peer's next data segment.
    let end = iss + 1 + 3 * 1448;
    c.set_now(now + 1);
    c.inject_packet(&pkt(SRV, A, 5001, end, flags::ACK, 8192, &ts(2, 0), &[]))
        .unwrap();
    let cwnd = c.stats().cwnd;
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        end,
        flags::ACK,
        8192,
        &ts(3, 0),
        &[1u8; 10],
    ))
    .unwrap();
    assert_eq!(c.stats().cwnd, cwnd, "no loss, no reduction");
    assert_eq!(c.stats().segs_retrans, 1, "just the probe");
}

/// `close()` was the only way to send a FIN, so a host that ended its
/// sending side and kept reading was reset when the peer stayed silent for
/// the 60 s FIN_WAIT_2 timeout. `shutdown_write()` half-closes without
/// that timer; `close()` then starts it.
#[test]
fn half_close_is_not_timed_until_the_host_closes() {
    let (mut c, iss) = established_ts();
    c.set_keepalive(0, 0, 0);
    c.set_now(20);
    c.shutdown_write().unwrap();
    let fin = drain(&mut c).remove(0);
    assert_eq!(fin.flags & flags::FIN, flags::FIN);
    c.set_now(30);
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 2,
        flags::ACK,
        8192,
        &ts(2, 0),
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::FinWait2);
    assert_eq!(c.next_deadline(), None, "nothing times the peer's half");
    c.set_now(200_000);
    c.tick().unwrap();
    assert_eq!(c.state(), State::FinWait2);
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 2,
        flags::ACK,
        8192,
        &ts(3, 0),
        b"late data",
    ))
    .unwrap();
    let mut buf = [0u8; 32];
    assert_eq!(c.recv(&mut buf).unwrap(), 9);
    c.set_now(200_100);
    c.tick().unwrap(); // the delayed ACK
    drain(&mut c);
    assert_eq!(c.next_deadline(), None);

    // Done reading: the usual FIN_WAIT_2 timeout applies from here.
    c.set_now(300_000);
    c.close().unwrap();
    assert_eq!(c.next_deadline(), Some(360_000));
    c.set_now(360_000);
    c.tick().unwrap();
    assert_eq!(c.state(), State::Closed);
    let out = drain(&mut c);
    assert_eq!(out.last().unwrap().flags & flags::RST, flags::RST);
}

/// A backlog nobody adds to (the tail of a closed connection) used to be
/// kept alive by a peer acknowledging a byte every few minutes, because
/// with less than a segment waiting any ACK counted as progress. That now
/// holds only while the application keeps writing.
#[test]
fn user_timeout_reaps_a_byte_at_a_time_acker_of_a_small_tail() {
    let (mut c, iss) = established_ts();
    c.send(&[7u8; 400]).unwrap();
    c.set_now(20);
    c.close().unwrap();
    let (mut una, mut tsv) = (iss + 1, 2u32);
    let mut acks = 0;
    let mut now = 20u64;
    while now < 2_000_000 && c.state() != State::Closed {
        c.set_now(now);
        c.tick().unwrap();
        drain(&mut c);
        if (now - 20) % 200_000 == 100_000 {
            una += 1;
            tsv += 1;
            acks += 1;
            let _ = c.inject_packet(&pkt(SRV, A, 5001, una, flags::ACK, 8192, &ts(tsv, 0), &[]));
            drain(&mut c);
        }
        now += 50;
    }
    assert!(acks >= 1, "the scripted ACKs fired");
    assert_eq!(c.state(), State::Closed);
    assert!(now <= 301_000, "aborted at {now} ms after {acks} ACKs");
}

/// A handshake that needed retransmissions and gave no RTT sample (no
/// timestamps) used to carry its backed-off timeout into the data phase:
/// 4 s after two lost SYNs, up to 60 s after more. It starts from the 3 s
/// fallback instead.
#[test]
fn handshake_backoff_does_not_carry_into_the_data_phase() {
    let (mut c, iss) = client();
    drain(&mut c);
    let mut now = 0u64;
    let mut syns = 0;
    while syns < 4 {
        now = c.next_deadline().unwrap();
        c.set_now(now);
        c.tick().unwrap();
        syns += drain(&mut c).len();
    }
    assert!(now >= 15_000, "four SYN retransmissions by {now} ms");
    c.set_now(now + 10);
    c.inject_packet(&pkt(
        SRV,
        A,
        5000,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &syn_opts(None, false, None),
        &[],
    ))
    .unwrap();
    assert_eq!(c.state(), State::Established);
    assert_eq!(c.stats().rto_ms, 3000);
}

/// Without timestamps an ACK of retransmitted data gives no RTT sample
/// (Karn), and the backed-off timeout used to stay: every later loss then
/// waited the doubled timeout, compounding to tens of seconds. An ACK of
/// new data now ends the backoff.
#[test]
fn ack_of_retransmitted_data_ends_the_rto_backoff() {
    let (mut c, iss) = client();
    drain(&mut c);
    c.set_now(10);
    c.inject_packet(&pkt(
        SRV,
        A,
        5000,
        iss + 1,
        flags::SYN | flags::ACK,
        8192,
        &syn_opts(None, false, None),
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let base = c.stats().rto_ms;
    assert!(base <= 400, "a 10 ms handshake sample: {base}");
    c.send(&[1u8; 1000]).unwrap();
    c.set_now(20);
    c.tick().unwrap();
    drain(&mut c);
    // Four timeouts go unanswered.
    let mut now = 20u64;
    while c.stats().rto_count < 4 {
        now = c.next_deadline().unwrap();
        c.set_now(now);
        c.tick().unwrap();
        drain(&mut c);
    }
    assert!(
        c.stats().rto_ms >= 8 * base,
        "backed off: {}",
        c.stats().rto_ms
    );
    // The retransmission is acknowledged: no sample, but the path works.
    c.set_now(now + 10);
    c.inject_packet(&pkt(
        SRV,
        A,
        5001,
        iss + 1001,
        flags::ACK,
        8192,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(c.stats().rto_ms, base);
}

#[path = "backlog_tests.rs"]
mod backlog;
