//! Server-side (passive open) conformance + adversarial-input tests.
//!
//! Mirrors the structure of `conformance_tests.rs`: each test reads as a
//! short packetdrill-style script. Two scenario classes:
//!
//!   * **Spec-compliant flows** — drive a normal three-way handshake with
//!     a TCB in `LISTEN`, optionally with SYN cookies, and verify the
//!     emitted wire bytes plus state transitions.
//!   * **Adversarial inputs** — feed the LISTEN/SYN_RCVD TCB hostile
//!     traffic (bare ACKs, FINs, SYN+ACKs, off-path SYN floods with
//!     forged ACKs, bogus cookies, RSTs in arbitrary states, fragmented
//!     packets, malformed checksums via `wire::parse`'s acceptance set)
//!     and verify the TCB does not get promoted to ESTABLISHED nor wedge.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::vec;
use std::vec::Vec;

use crate::tcb::{events, Endpoint, Tcb, TcbConfig};
use crate::wire::{self, flags, SackBlocks, Segment, TcpOptions};
use crate::{State, MAX_PACKET};

// ---------------------------------------------------------------------------
// Test rig
// ---------------------------------------------------------------------------

const SERVER_IP: [u8; 4] = [10, 0, 0, 1];
const SERVER_PORT: u16 = 80;
const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
const CLIENT_PORT: u16 = 49152;
const ATTACKER_IP: [u8; 4] = [10, 0, 0, 99];
const ATTACKER_PORT: u16 = 31337;
const SERVER_ISS: u32 = 0x9000_0000;
const CLIENT_ISS: u32 = 0x1000_0000;
const PEER_WIN: u16 = 65_535;
const INIT_RTO_MS: u32 = 1000;
const HOST_SECRET: [u8; 16] = [0x5a; 16];

/// A listener (not yet listening) with a host secret installed, as
/// `listen()` requires. Its passive ISNs are keyed, so tests read the
/// server's ISS from the SYN-ACK.
fn make_listener() -> Tcb {
    // The remote in TcbConfig is wildcarded by `listen()` immediately, so
    // the value here doesn't matter — we pass real-looking values for
    // clarity in test output.
    let cfg = TcbConfig {
        local: Endpoint {
            ip: SERVER_IP,
            port: SERVER_PORT,
        },
        remote: Endpoint {
            ip: [0, 0, 0, 0],
            port: 0,
        },
        iss: SERVER_ISS,
        initial_rto_ms: INIT_RTO_MS,
    };
    let mut t = Tcb::new(cfg).expect("tcb");
    t.set_secret(&HOST_SECRET);
    t
}

#[allow(clippy::too_many_arguments)]
fn build_in_from(
    src_ip: [u8; 4],
    src_port: u16,
    flag_bits: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mss: Option<u16>,
    ts: Option<(u32, u32)>,
    sack_permitted: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; MAX_PACKET];
    let opts = TcpOptions {
        mss,
        ts,
        sack_permitted,
        ..TcpOptions::NONE
    };
    let n = wire::emit(
        &mut buf,
        src_ip,
        SERVER_IP,
        src_port,
        SERVER_PORT,
        seq,
        ack,
        flag_bits,
        win,
        &opts,
        payload,
        0,
        wire::ecn::NOT_ECT,
    )
    .expect("emit peer packet");
    buf.truncate(n);
    buf
}

fn build_in(
    flag_bits: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mss: Option<u16>,
    ts: Option<(u32, u32)>,
    sack_permitted: bool,
    payload: &[u8],
) -> Vec<u8> {
    build_in_from(
        CLIENT_IP,
        CLIENT_PORT,
        flag_bits,
        seq,
        ack,
        win,
        mss,
        ts,
        sack_permitted,
        payload,
    )
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ParsedOut {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    wscale: Option<u8>,
    ts: Option<(u32, u32)>,
    sack_permitted: bool,
    payload: Vec<u8>,
}

impl ParsedOut {
    fn from(s: &Segment<'_>) -> Self {
        Self {
            src_ip: s.src_ip,
            dst_ip: s.dst_ip,
            src_port: s.src_port,
            dst_port: s.dst_port,
            seq: s.seq,
            ack: s.ack,
            flags: s.flags,
            window: s.window,
            mss: s.options.mss,
            wscale: s.options.wscale,
            ts: s.options.ts,
            sack_permitted: s.options.sack_permitted,
            payload: s.payload.to_vec(),
        }
    }
}

fn pop(tcb: &mut Tcb) -> ParsedOut {
    let mut buf = [0u8; MAX_PACKET];
    let n = tcb.extract_packet(&mut buf).expect("extract");
    assert!(n > 0, "expected outbound packet");
    let seg = wire::parse(&buf[..n]).expect("parse own emit");
    ParsedOut::from(&seg)
}

fn try_pop(tcb: &mut Tcb) -> Option<ParsedOut> {
    let mut buf = [0u8; MAX_PACKET];
    let n = tcb.extract_packet(&mut buf).expect("extract");
    if n == 0 {
        return None;
    }
    let seg = wire::parse(&buf[..n]).expect("parse own emit");
    Some(ParsedOut::from(&seg))
}

// ---------------------------------------------------------------------------
// Spec-compliant flows — stateful (no cookies)
// ---------------------------------------------------------------------------

#[test]
fn passive_handshake_completes_and_emits_correct_synack() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");
    assert_eq!(s.state(), State::Listen);
    assert!(s.poll() & events::LISTENING != 0);

    // Client SYN.
    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        Some((42, 0)),
        true,
        &[],
    );
    s.set_now(1);
    s.inject_packet(&syn).expect("inject SYN");
    assert_eq!(s.state(), State::SynRcvd);
    assert!(s.poll() & events::HALF_OPEN != 0);

    // Server SYN-ACK.
    let synack = pop(&mut s);
    assert_eq!(synack.src_ip, SERVER_IP);
    assert_eq!(synack.dst_ip, CLIENT_IP);
    assert_eq!(synack.flags, flags::SYN | flags::ACK);
    assert_ne!(
        synack.seq, SERVER_ISS,
        "passive ISN is keyed by the host secret (RFC 6528), not the configured ISS"
    );
    assert_eq!(synack.ack, CLIENT_ISS.wrapping_add(1));
    assert_eq!(synack.mss, Some(1460), "SYN-ACK must offer MSS");
    let (_, tsecr) = synack.ts.expect("SYN-ACK must echo TS");
    assert_eq!(tsecr, 42, "SYN-ACK TSecr must echo client TSval");
    assert!(synack.sack_permitted, "negotiated SACK should be echoed");

    // Client final ACK.
    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(1),
        PEER_WIN,
        None,
        Some((43, 0)),
        false,
        &[],
    );
    s.set_now(2);
    s.inject_packet(&ack).expect("inject ACK");
    assert_eq!(s.state(), State::Established);
    assert!(s.poll() & events::ESTABLISHED != 0);
    // No spurious post-ESTABLISHED packet.
    assert!(try_pop(&mut s).is_none(), "no extra packet after handshake");
}

#[test]
fn passive_handshake_with_piggybacked_data_in_third_ack() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        Some((100, 0)),
        true,
        &[],
    );
    s.set_now(1);
    s.inject_packet(&syn).expect("inject SYN");
    let synack = pop(&mut s);

    let payload = b"GET / HTTP/1.0\r\n\r\n";
    let ack = build_in(
        flags::ACK | flags::PSH,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(1),
        PEER_WIN,
        None,
        Some((101, 0)),
        false,
        payload,
    );
    s.set_now(2);
    s.inject_packet(&ack).expect("inject piggybacked ACK");
    assert_eq!(s.state(), State::Established);

    // Recv ring should hold the request.
    let mut buf = [0u8; 1024];
    let n = s.recv(&mut buf).expect("recv");
    assert_eq!(&buf[..n], payload);
}

// ---------------------------------------------------------------------------
// SYN-ACK retransmits in SYN_RCVD
// ---------------------------------------------------------------------------

#[test]
fn syn_rcvd_retransmits_synack_on_rto_then_reverts_to_listen() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.set_now(0);
    s.inject_packet(&syn).expect("inject SYN");
    assert_eq!(s.state(), State::SynRcvd);
    let synack0 = pop(&mut s);

    // Drive RTOs without ever sending the third ACK. After enough
    // retransmits we should drop back to LISTEN, not stay wedged.
    let mut now = 0u64;
    let mut rto = INIT_RTO_MS as u64;
    let mut retries = 0;
    while s.state() == State::SynRcvd {
        now += rto + 1;
        s.set_now(now);
        s.tick().expect("tick");
        if let Some(p) = try_pop(&mut s) {
            assert_eq!(p.flags, flags::SYN | flags::ACK);
            assert_eq!(p.seq, synack0.seq);
            retries += 1;
        }
        rto = (rto * 2).min(60_000);
        assert!(retries < 20, "infinite retransmit loop");
    }
    assert_eq!(s.state(), State::Listen, "must revert to LISTEN");
    assert!(retries >= 1, "at least one retransmit before giving up");
    // After reverting to LISTEN, a fresh SYN must start a new handshake.
    let syn2 = build_in(
        flags::SYN,
        CLIENT_ISS.wrapping_add(0x1000),
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.set_now(now + 1);
    s.inject_packet(&syn2).expect("inject SYN after revert");
    assert_eq!(s.state(), State::SynRcvd);
}

#[test]
fn syn_retransmit_in_syn_rcvd_is_idempotent() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.set_now(0);
    s.inject_packet(&syn).expect("inject SYN");
    let synack0 = pop(&mut s);

    // Same SYN again — must re-emit SYN-ACK with same SEQ/ACK.
    s.set_now(1);
    s.inject_packet(&syn).expect("inject SYN retransmit");
    let synack1 = pop(&mut s);
    assert_eq!(synack0.seq, synack1.seq);
    assert_eq!(synack0.ack, synack1.ack);
    assert_eq!(synack0.flags, synack1.flags);
    assert_eq!(s.state(), State::SynRcvd);
}

// ---------------------------------------------------------------------------
// LISTEN-state adversarial defences
// ---------------------------------------------------------------------------

#[test]
fn listen_requires_a_secret() {
    let cfg = TcbConfig {
        local: Endpoint {
            ip: SERVER_IP,
            port: SERVER_PORT,
        },
        remote: Endpoint {
            ip: [0; 4],
            port: 0,
        },
        iss: SERVER_ISS,
        initial_rto_ms: INIT_RTO_MS,
    };
    let mut s: Tcb = Tcb::new(cfg).expect("tcb");
    assert_eq!(s.listen(), Err(crate::TcpError::InvalidState));
    assert_eq!(s.state(), State::Closed);
    s.set_cookie_secret(&[1; 16]);
    s.listen().expect("a cookie secret is enough");
    let mut t: Tcb = Tcb::new(cfg).expect("tcb");
    t.set_secret(&[2; 16]);
    t.listen().expect("a host secret is enough");
    t.reinit(cfg);
    assert_eq!(
        t.listen(),
        Err(crate::TcpError::InvalidState),
        "reinit clears the secrets"
    );
}

#[test]
fn listen_drops_stray_bare_ack_silently() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    // Forged third-ACK without a prior SYN (not a valid cookie). It must be
    // silently dropped — never promote to ESTABLISHED — and must *not*
    // reflect a RST (avoid amplification).
    let bogus = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        SERVER_ISS.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.inject_packet(&bogus).expect("inject bogus ACK");
    assert_eq!(s.state(), State::Listen, "must remain in LISTEN");
    assert!(
        try_pop(&mut s).is_none(),
        "must not respond — no reflection"
    );
}

#[test]
fn listen_drops_fin_silently() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let fin = build_in(flags::FIN, CLIENT_ISS, 0, PEER_WIN, None, None, false, &[]);
    s.inject_packet(&fin).expect("inject FIN");
    assert_eq!(s.state(), State::Listen);
    assert!(try_pop(&mut s).is_none());
}

#[test]
fn listen_drops_rst_silently() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let rst = build_in(flags::RST, 0, 0, PEER_WIN, None, None, false, &[]);
    // RST in LISTEN is silently absorbed (RFC 793 §3.4) — no error.
    s.inject_packet(&rst).expect("inject RST");
    assert_eq!(s.state(), State::Listen);
    assert!(try_pop(&mut s).is_none());
}

#[test]
fn listen_replies_rst_to_synack() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let bogus_synack = build_in(
        flags::SYN | flags::ACK,
        CLIENT_ISS,
        SERVER_ISS.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.inject_packet(&bogus_synack).expect("inject SYN-ACK");
    let rst = pop(&mut s);
    assert_eq!(rst.flags, flags::RST);
    assert_eq!(s.state(), State::Listen, "remain in LISTEN");
}

#[test]
fn listen_rejects_packet_with_wrong_local_ip() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    // Build a packet addressed to a different IP — should be rejected by
    // the local-side filter, not silently absorbed into the listener.
    let mut buf = vec![0u8; MAX_PACKET];
    let opts = TcpOptions::NONE;
    let n = wire::emit(
        &mut buf,
        CLIENT_IP,
        [10, 0, 0, 200], // wrong dst
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_ISS,
        0,
        flags::SYN,
        PEER_WIN,
        &opts,
        &[],
        0,
        wire::ecn::NOT_ECT,
    )
    .expect("emit");
    buf.truncate(n);
    let err = s.inject_packet(&buf).expect_err("must reject");
    assert!(matches!(err, crate::TcpError::NotForUs));
    assert_eq!(s.state(), State::Listen);
}

// ---------------------------------------------------------------------------
// SYN_RCVD-state adversarial defences (off-path, blind attacks)
// ---------------------------------------------------------------------------

#[test]
fn syn_rcvd_answers_other_peers_statelessly() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    // Legitimate handshake start.
    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let synack = pop(&mut s);
    assert_eq!(s.state(), State::SynRcvd);

    // Another peer's SYN while the slot is busy: answered with a cookie
    // SYN-ACK, holding no state; the half-open stays pinned to its peer.
    let attacker_syn = build_in_from(
        ATTACKER_IP,
        ATTACKER_PORT,
        flags::SYN,
        0xdead_beef,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&attacker_syn)
        .expect("busy listener answers");
    let cookie_synack = pop(&mut s);
    assert_eq!(cookie_synack.dst_ip, ATTACKER_IP);
    assert_eq!(cookie_synack.flags, flags::SYN | flags::ACK);
    assert_eq!(cookie_synack.ack, 0xdead_beef_u32.wrapping_add(1));
    assert_ne!(cookie_synack.seq, synack.seq);
    assert!(try_pop(&mut s).is_none());
    assert_eq!(s.state(), State::SynRcvd, "stay locked to original peer");

    // Other segments from a stranger are still not ours.
    let stray = build_in_from(
        ATTACKER_IP,
        ATTACKER_PORT,
        flags::ACK,
        0xdead_bef0,
        synack.seq.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    assert_eq!(
        s.inject_packet(&stray),
        Err(crate::TcpError::NotForUs),
        "an ACK that is not a valid cookie is not ours"
    );

    // The original handshake completes undisturbed.
    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.inject_packet(&ack).expect("third ACK");
    assert_eq!(s.state(), State::Established);
}

#[test]
fn syn_rcvd_blind_ack_with_wrong_ack_value_does_not_promote() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let synack = pop(&mut s);

    // Attacker (same 5-tuple — assume on-path discoverer of the SYN, but
    // can't read our SYN-ACK) tries to forge a third ACK. They guess the
    // ACK value wrong: anything other than ISS+1 → RST, no promotion.
    let bogus = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(0xdead),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.inject_packet(&bogus).expect("inject bogus ACK");
    let rst = pop(&mut s);
    assert_eq!(rst.flags, flags::RST, "must RST a wrong-ACK");
    assert_eq!(s.state(), State::SynRcvd, "must stay in SYN_RCVD");
}

#[test]
fn syn_rcvd_off_path_rst_with_wrong_seq_is_dropped() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let _ = pop(&mut s);
    assert_eq!(s.state(), State::SynRcvd);

    // Off-path RST with a SEQ outside our receive window. Must be ignored.
    // BUF_CAP is up to 1 MiB, so we offset well beyond that to ensure
    // the RST seq sits outside even a fully-open receive window.
    let rst = build_in(
        flags::RST,
        CLIENT_ISS.wrapping_add(0x0200_0000), // 32 MiB out — well outside any RFC-permitted window
        SERVER_ISS.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.inject_packet(&rst).expect("inject off-path RST");
    assert_eq!(s.state(), State::SynRcvd, "blind RST must be ignored");
}

#[test]
fn syn_rcvd_exact_rst_reverts_to_listen() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let _ = pop(&mut s);

    // Exact-match RST (SEQ = RCV.NXT) from the pinned peer — abort the
    // half-open, return to LISTEN.
    let rst = build_in(
        flags::RST,
        CLIENT_ISS.wrapping_add(1),
        0,
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.inject_packet(&rst).expect("inject RST");
    assert_eq!(s.state(), State::Listen, "listener recycles back to LISTEN");
}

/// RFC 9293 §3.10.7.4 applies RFC 5961 §3.2 to SYN-RECEIVED too: an
/// in-window RST that is not exactly at RCV.NXT draws a rate-limited
/// challenge ACK and leaves the half-open intact. It used to erase it, so
/// the genuine third ACK then landed on a bare LISTEN and was lost.
#[test]
fn syn_rcvd_non_exact_in_window_rst_is_challenged() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");
    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let synack = pop(&mut s);

    let rst = build_in(
        flags::RST,
        CLIENT_ISS.wrapping_add(2),
        0,
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.set_now(10);
    s.inject_packet(&rst).expect("inject RST");
    assert_eq!(s.state(), State::SynRcvd, "half-open must survive");
    let challenge = pop(&mut s);
    assert_eq!(challenge.flags, flags::ACK);
    assert_eq!(
        (challenge.seq, challenge.ack),
        (synack.seq.wrapping_add(1), CLIENT_ISS.wrapping_add(1)),
        "challenge ACK is <SEQ=SND.NXT><ACK=RCV.NXT>"
    );
    s.inject_packet(&rst).expect("inject RST again");
    assert!(try_pop(&mut s).is_none(), "challenge ACKs are rate limited");

    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.set_now(20);
    s.inject_packet(&ack).expect("inject final ACK");
    assert_eq!(s.state(), State::Established);
}

/// RFC 5961 §3.2 holds in SYN-RECEIVED too: an in-window RST that does not
/// exactly match RCV.NXT draws a challenge ACK instead of tearing the
/// half-open down (it used to accept any RST within the 1 MiB window).
#[test]
fn syn_rcvd_in_window_rst_must_match_exactly() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");
    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let synack = pop(&mut s);
    let mut challenges = 0;
    for k in 0..20u32 {
        s.set_now(u64::from(k));
        let rst = build_in(
            flags::RST,
            CLIENT_ISS.wrapping_add(2 + k * 4096),
            0,
            0,
            None,
            None,
            false,
            &[],
        );
        s.inject_packet(&rst).expect("inject RST");
        while let Some(p) = try_pop(&mut s) {
            assert_eq!(p.flags, flags::ACK, "challenge ACK");
            assert_eq!(p.ack, CLIENT_ISS.wrapping_add(1));
            assert_eq!(p.seq, synack.seq.wrapping_add(1));
            challenges += 1;
        }
        assert_eq!(s.state(), State::SynRcvd, "non-exact RST {k} accepted");
    }
    assert_eq!(challenges, 1, "challenge ACKs are rate limited");
}

// ---------------------------------------------------------------------------
// SYN-cookie (stateless) flows
// ---------------------------------------------------------------------------
//
// The listener's single half-open slot is used statefully; cookies answer
// SYNs only while it is busy. Each test first occupies the slot with a SYN
// from a peer that never completes (a spoofed source).

const COOKIE_SECRET: [u8; 16] = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
];

/// Fill the listener's half-open slot with a SYN that is never completed.
fn occupy_slot(s: &mut Tcb) {
    let syn = build_in_from(
        ATTACKER_IP,
        ATTACKER_PORT,
        flags::SYN,
        0x7777_0000,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("occupying SYN");
    let synack = pop(s);
    assert_eq!(synack.dst_ip, ATTACKER_IP);
    assert_eq!(s.state(), State::SynRcvd);
}

#[test]
fn cookie_handshake_round_trip() {
    let mut s = make_listener();
    s.set_cookie_secret(&COOKIE_SECRET);
    s.set_now(0);
    s.listen().expect("listen");
    occupy_slot(&mut s);

    // SYN from client.
    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        Some((100, 0)),
        true,
        &[],
    );
    s.set_now(1);
    s.inject_packet(&syn).expect("inject SYN");

    // Cookie SYN-ACK should appear; the half-open slot is untouched.
    let synack = pop(&mut s);
    assert_eq!(synack.flags, flags::SYN | flags::ACK);
    assert_eq!(synack.dst_ip, CLIENT_IP);
    assert_eq!(synack.ack, CLIENT_ISS.wrapping_add(1));
    let cookie = synack.seq;
    assert_eq!(s.state(), State::SynRcvd, "cookies hold no state");
    // SACK-permitted survives the stateless handshake: it is encoded in the
    // low bits of our TSval (the peer offered timestamps).
    assert!(
        synack.sack_permitted,
        "cookie SYN-ACK negotiates SACK via TS"
    );
    let (synack_tsval, _) = synack.ts.expect("TS echoed in the cookie SYN-ACK");

    // Client final ACK echoing cookie+1 and our TSval.
    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        cookie.wrapping_add(1),
        PEER_WIN,
        None,
        Some((101, synack_tsval)),
        false,
        &[],
    );
    s.set_now(2);
    s.inject_packet(&ack).expect("inject final ACK");
    assert_eq!(
        s.state(),
        State::Established,
        "cookie validates → ESTABLISHED"
    );
}

/// Security / DoS regression: a connection promoted to ESTABLISHED via the
/// stateless SYN-cookie path must end the promoting inject with keepalive
/// armed, so a peer that completes the cookie handshake and then vanishes is
/// still reaped by the (default-on) keepalive.
///
/// The cookie path is special: `try_promote_via_cookie` runs
/// `reset_connection_state` (which clears `keepalive_deadline`) *inside* the
/// third-ACK inject, so the proof-of-life re-arm must happen after segment
/// processing — otherwise this most-attacked, stateless path would be the one
/// place keepalive silently fails to arm and an abandoned connection pins its
/// buffers forever.
#[test]
fn cookie_promoted_idle_connection_is_reaped_by_default_keepalive() {
    let mut s = make_listener();
    s.set_cookie_secret(&COOKIE_SECRET);
    s.set_now(0);
    s.listen().expect("listen");
    occupy_slot(&mut s);

    // SYN → cookie SYN-ACK (holds no state for this peer).
    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        Some((100, 0)),
        true,
        &[],
    );
    s.set_now(1);
    s.inject_packet(&syn).expect("inject SYN");
    let synack = pop(&mut s);
    let cookie = synack.seq;

    // Third ACK validates the cookie → ESTABLISHED, all within this one inject
    // (the inject that also wipes per-connection state mid-promotion).
    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        cookie.wrapping_add(1),
        PEER_WIN,
        None,
        Some((101, 0)),
        false,
        &[],
    );
    s.set_now(2);
    s.inject_packet(&ack).expect("inject final ACK");
    assert_eq!(
        s.state(),
        State::Established,
        "cookie validates → ESTABLISHED"
    );

    // Peer now vanishes. Without arming-after-promotion the connection would
    // have no timer at all and sit in ESTABLISHED forever; with the fix the
    // default keepalive probes and then reaps it.
    let mut probes = 0u32;
    for _ in 0..32 {
        let dl = match s.debug_next_deadline() {
            Some(d) => d,
            None => break,
        };
        s.set_now(dl + 1);
        s.tick().expect("tick");
        while try_pop(&mut s).is_some() {
            probes += 1;
        }
        if s.state() == State::Closed {
            break;
        }
    }
    assert_eq!(
        s.state(),
        State::Closed,
        "vanished cookie-promoted peer must be reaped by default keepalive"
    );
    assert!(
        probes >= 1,
        "keepalive must have probed the cookie-promoted peer"
    );
}

#[test]
fn cookie_rejects_forged_third_ack() {
    let mut s = make_listener();
    s.set_cookie_secret(&COOKIE_SECRET);
    s.set_now(0);
    s.listen().expect("listen");

    // Attacker has never sent a SYN, just guesses a cookie value.
    let forged = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        0xdead_beef, // not a valid cookie
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.set_now(1);
    s.inject_packet(&forged).expect("inject forged ACK");
    assert_eq!(s.state(), State::Listen, "forged cookie must not promote");
    assert!(try_pop(&mut s).is_none(), "no reflection for failed cookie");

    // Nor can a forged cookie take over a busy slot.
    occupy_slot(&mut s);
    assert_eq!(s.inject_packet(&forged), Err(crate::TcpError::NotForUs));
    assert_eq!(s.state(), State::SynRcvd);
    assert!(try_pop(&mut s).is_none());
}

#[test]
fn cookie_handshake_survives_one_time_bucket_rollover() {
    let mut s = make_listener();
    s.set_cookie_secret(&COOKIE_SECRET);
    s.set_now(0);
    s.listen().expect("listen");
    occupy_slot(&mut s);

    // SYN at t = 0.
    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let synack = pop(&mut s);
    let cookie = synack.seq;

    // Third ACK arrives ~70 s later (past one bucket boundary, still
    // within the validator's two-bucket window).
    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        cookie.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.set_now(70_000);
    s.inject_packet(&ack).expect("inject delayed ACK");
    assert_eq!(s.state(), State::Established);
}

/// Issue a cookie SYN-ACK to the client from a busy listener, rotate the
/// cookie secret `rotations` times (each intermediate key issuing a cookie of
/// its own), then deliver the client's third ACK.
fn cookie_ack_after_rotations(rotations: u8) -> State {
    let mut s = make_listener();
    s.set_cookie_secret(&COOKIE_SECRET);
    s.set_now(0);
    s.listen().expect("listen");
    occupy_slot(&mut s);
    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let cookie = pop(&mut s).seq;
    for k in 0..rotations {
        s.set_cookie_secret(&[0xA0 | k; 16]);
        let other = build_in_from(
            [10, 0, 0, 50 + k],
            40_000,
            flags::SYN,
            0x2000_0000,
            0,
            PEER_WIN,
            Some(1460),
            None,
            false,
            &[],
        );
        s.inject_packet(&other).expect("another peer's SYN");
        assert_eq!(pop(&mut s).dst_ip, [10, 0, 0, 50 + k]);
    }
    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        cookie.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.set_now(1);
    let _ = s.inject_packet(&ack);
    s.state()
}

/// Rotating the cookie secret keeps the previous key for validation, so a
/// handshake in flight across a rotation still completes (it used to be
/// silently dropped, leaving the client to hang).
#[test]
fn cookie_survives_one_secret_rotation() {
    assert_eq!(cookie_ack_after_rotations(1), State::Established);
}

#[test]
fn cookie_rejected_after_two_secret_rotations() {
    assert_eq!(
        cookie_ack_after_rotations(2),
        State::SynRcvd,
        "only the previous key is kept"
    );
}

// ---------------------------------------------------------------------------
// SYN flood resistance (stateless)
// ---------------------------------------------------------------------------

#[test]
fn syn_flood_under_cookies_holds_one_half_open() {
    let mut s = make_listener();
    s.set_cookie_secret(&COOKIE_SECRET);
    s.set_now(0);
    s.listen().expect("listen");

    // Simulate a flood of 1000 SYNs from spoofed sources. The first takes
    // the half-open slot; every later one is answered with a cookie and
    // holds no state (the slot stays with the first source).
    let mut synacks = 0;
    for i in 0..1000u32 {
        let src_ip = [10, 0, 1, (i & 0xff) as u8];
        let src_port = 30000 + ((i >> 8) & 0xffff) as u16;
        let seq = 0x4000_0000u32.wrapping_add(i);
        let syn = build_in_from(
            src_ip,
            src_port,
            flags::SYN,
            seq,
            0,
            PEER_WIN,
            Some(1460),
            None,
            false,
            &[],
        );
        s.set_now(i as u64 / 4);
        s.inject_packet(&syn).expect("inject flood SYN");
        assert_eq!(s.state(), State::SynRcvd, "SYN-flood iter {i}");
        // Drain this iteration's SYN-ACK so the next inject can run (the
        // FFI contract requires a drained egress ring before inject).
        while let Some(p) = try_pop(&mut s) {
            assert_eq!(p.dst_ip, src_ip);
            assert_eq!(p.ack, seq.wrapping_add(1));
            synacks += 1;
        }
    }
    assert_eq!(synacks, 1000, "every SYN answered");
}

#[test]
fn half_open_lifetime_is_capped() {
    // The single-TCB design means at most one half-open at a time; an
    // off-path attacker who knows the 5-tuple can hold the slot for at most
    // MAX_SYN_RCVD_RETRIES retransmits before we revert.
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    assert_eq!(s.state(), State::SynRcvd);

    // Drain SYN-ACK then drive RTOs without ever responding. The slot
    // *must* eventually clear so a legitimate client can connect later.
    let _ = pop(&mut s);
    let mut now = 0u64;
    let mut rto = INIT_RTO_MS as u64;
    let mut steps = 0;
    while s.state() == State::SynRcvd {
        now += rto + 1;
        s.set_now(now);
        s.tick().expect("tick");
        let _ = try_pop(&mut s);
        rto = (rto * 2).min(60_000);
        steps += 1;
        assert!(steps < 20, "did not clear half-open after 20 RTO steps");
    }
    assert_eq!(s.state(), State::Listen);
}

// ---------------------------------------------------------------------------
// Listener lifecycle
// ---------------------------------------------------------------------------

#[test]
fn closed_to_listen_to_closed_is_clean() {
    let mut s = make_listener();
    s.listen().expect("listen");
    assert_eq!(s.state(), State::Listen);
    s.close().expect("close listener");
    assert_eq!(s.state(), State::Closed);
}
#[test]
fn listen_recycles_after_clean_close() {
    // Full handshake, peer FINs, we FIN, both sides clean — TCB returns
    // to a usable LISTEN if `is_listener` was set. (Right now only RTO
    // and RST drive the recycle path; this test ensures we don't *break*
    // that future behaviour by accidentally promoting `is_listener` to
    // a one-shot flag.)
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        None,
        false,
        &[],
    );
    s.inject_packet(&syn).expect("inject SYN");
    let synack = pop(&mut s);
    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    s.inject_packet(&ack).expect("inject final ACK");
    assert_eq!(s.state(), State::Established);
    // RST aborts cleanly back to LISTEN since `is_listener` was set.
    let rst = build_in(
        flags::RST,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(1),
        PEER_WIN,
        None,
        None,
        false,
        &[],
    );
    // The current implementation only recycles to LISTEN from SYN_RCVD;
    // from ESTABLISHED a RST currently goes to CLOSED. That's the
    // documented behaviour — pin it.
    s.inject_packet(&rst).expect("inject RST");
    assert_eq!(s.state(), State::Closed);
}

// ---------------------------------------------------------------------------
// RFC 7323 §2 — Window Scale option, passive-open side
// ---------------------------------------------------------------------------

/// Variant of `build_in` that includes a Window Scale option.
#[allow(clippy::too_many_arguments)]
fn build_in_ws(
    flag_bits: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mss: Option<u16>,
    wscale: Option<u8>,
    ts: Option<(u32, u32)>,
    sack_permitted: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; MAX_PACKET];
    let opts = TcpOptions {
        mss,
        wscale,
        ts,
        sack_permitted,
        sack: SackBlocks::EMPTY,
    };
    let n = wire::emit(
        &mut buf,
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        SERVER_PORT,
        seq,
        ack,
        flag_bits,
        win,
        &opts,
        payload,
        0,
        wire::ecn::NOT_ECT,
    )
    .expect("emit");
    buf.truncate(n);
    buf
}

/// Passive open with peer offering WS=8: our SYN-ACK MUST echo a WS
/// option. The post-handshake third ACK's window is then interpreted
/// scaled (window << 8).
///
/// Asserts SYN-ACK window saturates at `u16::MAX`, which holds only for
/// `BUF_CAP >= 65 KiB`; gated out of the `small-buffers` profile.
#[cfg(not(feature = "small-buffers"))]
#[test]
fn passive_handshake_negotiates_window_scale() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let peer_ws = 8u8;
    let third_ack_win = 1000u16;

    // Client SYN with WS=8.
    let syn = build_in_ws(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        Some(peer_ws),
        Some((42, 0)),
        true,
        &[],
    );
    s.set_now(1);
    s.inject_packet(&syn).expect("inject SYN");
    assert_eq!(s.state(), State::SynRcvd);

    // SYN-ACK must include WS option (echoing back is mandatory per
    // RFC 7323 §2.2 — without it, scaling is disabled both ways). The
    // exact shift is implementation-defined; we just assert it's present.
    let synack = pop(&mut s);
    assert_eq!(synack.flags, flags::SYN | flags::ACK);
    let our_ws = synack.wscale.expect("SYN-ACK must echo our local WS shift");
    assert!(our_ws >= 1, "shift ≥ 1 required to fit our BUF_CAP");
    // SYN-ACK window itself is NEVER scaled (RFC 7323 §2.3).
    assert_eq!(
        synack.window,
        u16::MAX,
        "SYN-ACK window field must be unscaled (raw saturated)",
    );

    // Client final ACK with window=1000 — post-handshake, so this gets
    // scaled by peer_ws=8. Effective peer window: 1000 << 8 = 256_000.
    let ack = build_in_ws(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(1),
        third_ack_win,
        None,
        None,
        Some((43, 0)),
        false,
        &[],
    );
    s.set_now(2);
    s.inject_packet(&ack).expect("inject ACK");
    assert_eq!(s.state(), State::Established);

    let snap = s.debug_snapshot();
    let expected = (third_ack_win as u32) << peer_ws;
    assert_eq!(
        snap.snd_wnd, expected,
        "third ACK window must apply WS shift: {} << {} = {}",
        third_ack_win, peer_ws, expected,
    );
}

/// Passive open with a peer that does NOT offer WS: we MUST omit WS in
/// our SYN-ACK and treat the peer's windows as raw 16-bit values.
#[test]
fn passive_handshake_without_ws_disables_scaling() {
    let mut s = make_listener();
    s.set_now(0);
    s.listen().expect("listen");

    let syn = build_in(
        flags::SYN,
        CLIENT_ISS,
        0,
        PEER_WIN,
        Some(1460),
        Some((42, 0)),
        true,
        &[],
    );
    s.set_now(1);
    s.inject_packet(&syn).expect("inject SYN");

    let synack = pop(&mut s);
    assert_eq!(
        synack.wscale, None,
        "SYN-ACK must omit WS when peer didn't offer it",
    );

    // Third ACK with window=1000 — interpreted RAW (no shift).
    let ack = build_in(
        flags::ACK,
        CLIENT_ISS.wrapping_add(1),
        synack.seq.wrapping_add(1),
        1000,
        None,
        Some((43, 0)),
        false,
        &[],
    );
    s.set_now(2);
    s.inject_packet(&ack).expect("inject ACK");
    let snap = s.debug_snapshot();
    assert_eq!(snap.snd_wnd, 1000, "no WS → window is raw");
}
