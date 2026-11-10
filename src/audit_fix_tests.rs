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
