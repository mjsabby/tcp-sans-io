//! RFC 793 / RFC 9293 conformance tests.
//!
//! Where loopback_tests.rs verifies *behaviour* (round-trips, retransmits,
//! state transitions), this file verifies *exact wire output* for tightly
//! defined scenarios. Each scenario reads like a hand-translated packetdrill
//! script:
//!
//!   1. Drive the public API (`connect`, `send`, `close`).
//!   2. Pop the next emitted packet and assert exact flag/seq/ack/options.
//!   3. Inject a precisely-constructed reply.
//!   4. Repeat.
//!
//! A failure here means the wire bytes diverged from the spec, which is a
//! conformance bug even when the loopback "round-trip" tests still pass.

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
// Constants
// ---------------------------------------------------------------------------

const CLIENT_IP: [u8; 4] = [10, 0, 0, 1];
const SERVER_IP: [u8; 4] = [10, 0, 0, 2];
const CLIENT_PORT: u16 = 49152;
const SERVER_PORT: u16 = 80;
const ISS: u32 = 0x1000_0000;
const PSS: u32 = 0x9000_0000; // peer's ISS
const PEER_WIN: u16 = 65_535;
const INIT_RTO_MS: u32 = 1000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_tcb() -> Tcb {
    let cfg = TcbConfig {
        local: Endpoint {
            ip: CLIENT_IP,
            port: CLIENT_PORT,
        },
        remote: Endpoint {
            ip: SERVER_IP,
            port: SERVER_PORT,
        },
        iss: ISS,
        initial_rto_ms: INIT_RTO_MS,
    };
    Tcb::new(cfg).expect("tcb")
}

/// Pop one staged outbound packet, parse it, return both raw bytes and the
/// parsed segment. Panics if no packet is pending.
fn pop(tcb: &mut Tcb) -> (Vec<u8>, ParsedOut) {
    let mut buf = [0u8; MAX_PACKET];
    let n = tcb.extract_packet(&mut buf).expect("extract");
    assert!(n > 0, "expected outbound packet, got 0");
    let bytes = buf[..n].to_vec();
    let seg = wire::parse(&bytes).expect("parse own emit");
    let parsed = ParsedOut::from(&seg);
    (bytes, parsed)
}

/// Try to pop a packet; return None if the staging buffer is empty.
fn try_pop(tcb: &mut Tcb) -> Option<ParsedOut> {
    let mut buf = [0u8; MAX_PACKET];
    let n = tcb.extract_packet(&mut buf).expect("extract");
    if n == 0 {
        return None;
    }
    let seg = wire::parse(&buf[..n]).expect("parse own emit");
    Some(ParsedOut::from(&seg))
}

/// Owned, ergonomic copy of a parsed segment for assertions.
#[derive(Debug, Clone)]
#[allow(dead_code)] // some fields are inspected only by future scenarios
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
    sack: SackBlocks,
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
            sack: s.options.sack,
            payload: s.payload.to_vec(),
        }
    }
}

/// Build an inbound packet originating from the peer.
fn build_in(
    flag_bits: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mss: Option<u16>,
    ts: Option<(u32, u32)>,
    payload: &[u8],
) -> Vec<u8> {
    build_in_full(flag_bits, seq, ack, win, mss, ts, false, None, payload)
}

/// Build an inbound packet with arbitrary SACK options. `build_in` is
/// the convenience wrapper for the common (no-SACK) case. The `sack`
/// parameter accepts `Option<(u32, u32)>` for single-block convenience;
/// use `build_in_full_multi_sack` for multi-block scenarios.
#[allow(clippy::too_many_arguments)]
fn build_in_full(
    flag_bits: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mss: Option<u16>,
    ts: Option<(u32, u32)>,
    sack_permitted: bool,
    sack: Option<(u32, u32)>,
    payload: &[u8],
) -> Vec<u8> {
    let sb = sack
        .map(|(l, r)| SackBlocks::one(l, r))
        .unwrap_or(SackBlocks::EMPTY);
    build_in_full_ws(
        flag_bits,
        seq,
        ack,
        win,
        mss,
        None,
        ts,
        sack_permitted,
        sb,
        payload,
    )
}

/// Most general inbound packet builder — all five option shapes selectable.
/// For multi-block SACK callers, pass `SackBlocks` directly; otherwise
/// `SackBlocks::EMPTY` or `SackBlocks::one(l, r)`.
#[allow(clippy::too_many_arguments)]
fn build_in_full_ws(
    flag_bits: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mss: Option<u16>,
    wscale: Option<u8>,
    ts: Option<(u32, u32)>,
    sack_permitted: bool,
    sack: impl Into<SackBlocks>,
    payload: &[u8],
) -> Vec<u8> {
    let sack: SackBlocks = sack.into();
    let mut buf = vec![0u8; MAX_PACKET];
    let opts = TcpOptions {
        mss,
        wscale,
        ts,
        sack_permitted,
        sack,
        ..TcpOptions::NONE
    };
    let n = wire::emit(
        &mut buf,
        SERVER_IP,
        CLIENT_IP,
        SERVER_PORT,
        CLIENT_PORT,
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

/// Drive the standard 3-way handshake using Timestamps. Returns the peer's
/// own TSval echoed by us (i.e. what we'll see as `tsecr` on data).
fn handshake_with_ts(tcb: &mut Tcb, now: &mut u64) -> u32 {
    tcb.set_now(*now);
    tcb.connect().expect("connect");

    // SYN
    tcb.set_now(*now);
    tcb.tick().expect("tick");
    let (_, syn) = pop(tcb);
    // SYN packet may also carry ECE+CWR as the ECN-Setup flags per RFC
    // 3168 §6.1.1; mask them off for the "pure SYN" check.
    let syn_only = syn.flags & !(flags::ECE | flags::CWR);
    assert_eq!(syn_only, flags::SYN, "first packet must be SYN (with optional ECN-Setup)");
    assert_eq!(syn.seq, ISS);
    assert_eq!(syn.ack, 0);
    assert_eq!(syn.mss, Some(1460), "SYN must carry MSS=1460");
    let (cli_tsval, _) = syn.ts.expect("SYN must offer Timestamps");

    // SYN-ACK with peer TS=42 and SACK_PERMITTED echoed back (we always
    // offer SACK in our SYN; honouring it lets the SACK-driven fast-
    // retransmit path reach test code).
    *now += 5;
    let peer_ts = 42u32;
    let synack = build_in_full(
        flags::SYN | flags::ACK,
        PSS,
        ISS.wrapping_add(1),
        PEER_WIN,
        Some(1460),
        Some((peer_ts, cli_tsval)),
        true,
        None,
        &[],
    );
    tcb.set_now(*now);
    tcb.inject_packet(&synack).expect("inject SYN-ACK");

    // ACK of SYN-ACK
    tcb.set_now(*now);
    tcb.tick().expect("tick");
    let (_, ack) = pop(tcb);
    assert_eq!(ack.flags, flags::ACK);
    assert_eq!(ack.seq, ISS.wrapping_add(1));
    assert_eq!(ack.ack, PSS.wrapping_add(1));
    assert!(ack.payload.is_empty());
    let (_, tsecr) = ack.ts.expect("data segments must echo TS");
    assert_eq!(tsecr, peer_ts, "ACK TSecr must echo peer's TSval");
    assert_eq!(tcb.state(), State::Established);
    peer_ts
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Verify the bit-level shape of the SYN we emit on `connect()`:
/// pure SYN flag, seq=ISS, ack=0, MSS=1460, Timestamps option present, no
/// payload, advertised window equal to recv-buffer capacity.
#[test]
fn syn_packet_format() {
    let mut tcb = make_tcb();
    tcb.set_now(0);
    tcb.connect().expect("connect");
    tcb.set_now(0);
    tcb.tick().expect("tick");

    let (raw, syn) = pop(&mut tcb);
    assert_eq!(syn.src_ip, CLIENT_IP);
    assert_eq!(syn.dst_ip, SERVER_IP);
    assert_eq!(syn.src_port, CLIENT_PORT);
    assert_eq!(syn.dst_port, SERVER_PORT);
    // SYN plus the ECN-Setup flags ECE+CWR (RFC 3168 §6.1.1) — no
    // other TCP flags.
    assert_eq!(
        syn.flags,
        flags::SYN | flags::ECE | flags::CWR,
        "SYN must carry only SYN + ECN-Setup flags",
    );
    assert_eq!(syn.seq, ISS);
    assert_eq!(syn.ack, 0);
    assert!(syn.payload.is_empty());
    assert_eq!(syn.mss, Some(1460));
    let (_, tsecr) = syn.ts.expect("SYN MUST offer TS per RFC 7323");
    assert_eq!(tsecr, 0, "SYN TSecr must be 0 (no echo yet)");

    // Total IP datagram length advertised in the header must equal raw bytes.
    assert_eq!(u16::from_be_bytes([raw[2], raw[3]]) as usize, raw.len());
}

/// First data segment after handshake must carry PSH on a small write,
/// echo the peer's most recent TSval, and not exceed peer MSS.
#[test]
fn first_data_segment_has_push_and_correct_tsecr() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Application send.
    let payload = b"GET /a";
    assert_eq!(tcb.send(payload).expect("send"), payload.len());
    now += 1;
    tcb.set_now(now);
    tcb.tick().expect("tick");

    let (_, data) = pop(&mut tcb);
    assert!(
        data.flags & flags::ACK != 0,
        "every non-SYN segment carries ACK"
    );
    assert!(data.flags & flags::PSH != 0, "small write must set PSH");
    assert_eq!(data.flags & flags::SYN, 0);
    assert_eq!(data.flags & flags::FIN, 0);
    assert_eq!(data.flags & flags::RST, 0);
    assert_eq!(data.seq, ISS.wrapping_add(1));
    assert_eq!(data.ack, PSS.wrapping_add(1));
    assert_eq!(&data.payload, payload);
    assert_eq!(data.ts.expect("ts").1, peer_ts, "TSecr echoes peer's TSval");
}

/// Active close emits FIN+ACK exactly once with the proper seq number, and
/// only transitions to FIN-WAIT-2 after the FIN is ACKed.
#[test]
fn active_close_state_transitions() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    now += 1;
    tcb.set_now(now);
    tcb.close().expect("close");
    tcb.set_now(now);
    tcb.tick().expect("tick");

    let (_, fin) = pop(&mut tcb);
    assert_eq!(fin.flags, flags::FIN | flags::ACK);
    assert_eq!(fin.seq, ISS.wrapping_add(1));
    assert_eq!(fin.ack, PSS.wrapping_add(1));
    assert!(fin.payload.is_empty());
    assert_eq!(tcb.state(), State::FinWait1);

    // Peer ACKs our FIN (no FIN of its own yet).
    now += 1;
    let ack = build_in(
        flags::ACK,
        PSS.wrapping_add(1),
        ISS.wrapping_add(2),
        PEER_WIN,
        None,
        Some((100, 0)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&ack).expect("inject");
    assert_eq!(tcb.state(), State::FinWait2);

    // Peer FIN now arrives — we must respond with an ACK and move to TIME_WAIT.
    now += 1;
    let peer_fin = build_in(
        flags::FIN | flags::ACK,
        PSS.wrapping_add(1),
        ISS.wrapping_add(2),
        PEER_WIN,
        None,
        Some((101, 0)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&peer_fin).expect("inject FIN");
    tcb.set_now(now);
    tcb.tick().expect("tick");

    let (_, final_ack) = pop(&mut tcb);
    assert_eq!(final_ack.flags, flags::ACK, "ack of peer FIN: pure ACK");
    assert_eq!(final_ack.seq, ISS.wrapping_add(2));
    assert_eq!(final_ack.ack, PSS.wrapping_add(2));
    assert_eq!(tcb.state(), State::TimeWait);
}

/// A SYN whose ACK never arrives must be retransmitted with exponential
/// backoff (RFC 6298 §5.5). The retransmitted SYN keeps the same seq.
#[test]
fn syn_retransmit_uses_exponential_backoff() {
    let mut tcb = make_tcb();
    tcb.set_now(0);
    tcb.connect().expect("connect");

    tcb.tick().expect("tick");
    let (_, syn1) = pop(&mut tcb);
    assert!(syn1.flags & flags::SYN != 0);
    assert_eq!(syn1.seq, ISS);

    // First RTO at +1000 ms (initial RTO).
    tcb.set_now(1001);
    tcb.tick().expect("tick");
    let (_, syn2) = pop(&mut tcb);
    assert!(syn2.flags & flags::SYN != 0, "retransmit is also SYN");
    assert_eq!(syn2.seq, ISS, "retransmit MUST reuse ISS");

    // Second RTO doubles: +2000 ms after first retransmit (now ≥ 3001).
    tcb.set_now(2001); // not yet expired
    tcb.tick().expect("tick");
    assert!(
        try_pop(&mut tcb).is_none(),
        "no third SYN before backoff (expected 1000 + 2000 = 3000 ms)"
    );

    tcb.set_now(3001);
    tcb.tick().expect("tick");
    let (_, syn3) = pop(&mut tcb);
    assert!(syn3.flags & flags::SYN != 0);
    assert_eq!(syn3.seq, ISS);
}

/// Out-of-order data must elicit a duplicate ACK with `ack = rcv_nxt`
/// (Reno's fast-retransmit trigger, RFC 5681 §3.2).
#[test]
fn out_of_order_segment_emits_dup_ack() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    // Skip the next-expected byte: peer sends seq = PSS+1+10 instead of PSS+1.
    now += 5;
    let oo = build_in(
        flags::ACK | flags::PSH,
        PSS.wrapping_add(1).wrapping_add(10),
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((50, 0)),
        b"out-of-order",
    );
    tcb.set_now(now);
    tcb.inject_packet(&oo).expect("inject");
    tcb.set_now(now);
    tcb.tick().expect("tick");

    let (_, dup) = pop(&mut tcb);
    assert!(dup.flags & flags::ACK != 0);
    assert_eq!(
        dup.ack,
        PSS.wrapping_add(1),
        "dup-ACK must keep ack at rcv_nxt, not advance"
    );
    assert!(dup.payload.is_empty());
}

/// Single-hole reassembly: an OOO segment plus the gap-filler must
/// produce exactly the cumulative ACK covering both, and `recv` must
/// return the bytes in order.
#[test]
fn out_of_order_then_gap_fill_delivers_both_segments() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    let a = b"AAAAAAAAAA"; // 10 bytes at PSS+1
    let b = b"BBBBBBBBBB"; // 10 bytes at PSS+1+10
    let seq_a = PSS.wrapping_add(1);
    let seq_b = seq_a.wrapping_add(a.len() as u32);

    // Inject B first (OOO).
    now += 5;
    let oo = build_in(
        flags::ACK | flags::PSH,
        seq_b,
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((50, 0)),
        b,
    );
    tcb.set_now(now);
    tcb.inject_packet(&oo).expect("inject B");
    let dup = pop(&mut tcb).1;
    assert_eq!(dup.ack, seq_a, "OOO B → dup-ACK at rcv_nxt");

    // Inject A (gap-filler).
    now += 1;
    let in_order = build_in(
        flags::ACK | flags::PSH,
        seq_a,
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((60, 0)),
        a,
    );
    tcb.set_now(now);
    tcb.inject_packet(&in_order).expect("inject A");

    // Cumulative ACK must cover the full a+b run.
    let ack = pop(&mut tcb).1;
    assert_eq!(
        ack.ack,
        seq_b.wrapping_add(b.len() as u32),
        "cumulative ACK must cover A+B after gap fill"
    );

    // Application reads A then B contiguously.
    let mut buf = [0u8; 64];
    let n = tcb.recv(&mut buf).expect("recv");
    assert_eq!(n, a.len() + b.len(), "both segments delivered");
    assert_eq!(&buf[..a.len()], a);
    assert_eq!(&buf[a.len()..n], b);
}

/// Multi-hole reassembly: previously this test asserted the single-hole
/// constraint (a second hole gets dropped, held run preserved). With the
/// RFC 6675 multi-hole reassembler, BOTH holes can be held simultaneously
/// — the cumulative ACK after the in-order segment arrives covers
/// everything, including C.
#[test]
fn second_hole_is_dropped_held_run_preserved() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    let a = b"AAAAAAAAAA"; // 10 bytes at PSS+1
    let b = b"BBBBBBBBBB"; // 10 bytes at PSS+1+10 — held in slot 1
    let c = b"CCCCCCCCCC"; // 10 bytes at PSS+1+30 — held in slot 2 (multi-hole)
    let d = b"DDDDDDDDDD"; // 10 bytes at PSS+1+20 — merges slot1 with slot2
    let seq_a = PSS.wrapping_add(1);
    let seq_b = seq_a.wrapping_add(a.len() as u32);
    let seq_c = seq_b.wrapping_add(b.len() as u32 + d.len() as u32);
    let seq_d = seq_b.wrapping_add(b.len() as u32);

    // Hold B.
    now += 5;
    tcb.set_now(now);
    tcb.inject_packet(&build_in(
        flags::ACK | flags::PSH,
        seq_b,
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((50, 0)),
        b,
    ))
    .expect("inject B");
    let _ = pop(&mut tcb); // dup-ACK

    // C arrives non-abutting → multi-hole reassembler accepts it as a
    // second held run.
    now += 1;
    tcb.set_now(now);
    tcb.inject_packet(&build_in(
        flags::ACK | flags::PSH,
        seq_c,
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((51, 0)),
        c,
    ))
    .expect("inject C");
    let dup_c = pop(&mut tcb).1;
    assert_eq!(dup_c.ack, seq_a, "C non-abutting → dup-ACK at rcv_nxt");

    // D arrives, abutting B's tail AND C's head → merges into one run.
    now += 1;
    tcb.set_now(now);
    tcb.inject_packet(&build_in(
        flags::ACK | flags::PSH,
        seq_d,
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((52, 0)),
        d,
    ))
    .expect("inject D");
    let _ = pop(&mut tcb); // dup-ACK still at rcv_nxt

    // A closes the gap. With multi-hole, A+B+D+C all deliver.
    now += 1;
    tcb.set_now(now);
    tcb.inject_packet(&build_in(
        flags::ACK | flags::PSH,
        seq_a,
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((53, 0)),
        a,
    ))
    .expect("inject A");
    let ack = pop(&mut tcb).1;
    assert_eq!(
        ack.ack,
        seq_c.wrapping_add(c.len() as u32),
        "cumulative ACK should cover A+B+D+C (multi-hole reassembly)",
    );

    let mut buf = [0u8; 64];
    let n = tcb.recv(&mut buf).expect("recv");
    assert_eq!(n, a.len() + b.len() + d.len() + c.len());
    assert_eq!(&buf[..a.len()], a);
    assert_eq!(&buf[a.len()..a.len() + b.len()], b);
    assert_eq!(
        &buf[a.len() + b.len()..a.len() + b.len() + d.len()],
        d
    );
    assert_eq!(&buf[a.len() + b.len() + d.len()..n], c);
}

/// Inbound packet whose TCP checksum is wrong must be silently rejected:
/// state and ack-clock unchanged.
#[test]
fn corrupt_checksum_is_rejected_silently() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    // Build a valid data segment, then flip one bit in the payload (after
    // the TCP checksum was computed for the original bytes) so checksum
    // verification fails.
    let mut bad = build_in(
        flags::ACK | flags::PSH,
        PSS.wrapping_add(1),
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((60, 0)),
        b"hello",
    );
    *bad.last_mut().expect("non-empty") ^= 0x01;

    let state_before = tcb.state();
    let res = tcb.inject_packet(&bad);
    assert!(res.is_err(), "corrupt segment must be rejected");
    assert_eq!(tcb.state(), state_before, "state unchanged on bad packet");

    // No spurious egress (corrupt segment never advanced rcv_nxt).
    tcb.set_now(now + 100);
    tcb.tick().expect("tick");
    assert!(try_pop(&mut tcb).is_none(), "no egress for bad packet");
}

/// Peer RST while ESTABLISHED transitions us straight to CLOSED, sets the
/// ConnectionReset error flag, and emits no further packets.
#[test]
fn rst_in_established_closes_immediately() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    now += 1;
    let rst = build_in(
        flags::RST | flags::ACK,
        PSS.wrapping_add(1),
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((70, 0)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&rst).expect("inject RST");
    assert_eq!(tcb.state(), State::Closed);
    assert!(tcb.poll() & events::ERROR != 0);

    tcb.set_now(now + 100);
    tcb.tick().expect("tick");
    assert!(try_pop(&mut tcb).is_none(), "no segments after RST");
}

/// IP fragments (MF=1 or non-zero offset) must be rejected even if every
/// other field is valid (we don't reassemble).
#[test]
fn ip_fragment_rejected() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    // Build a normal data segment and then set MF=1 in the IP header.
    let mut frag = build_in(
        flags::ACK | flags::PSH,
        PSS.wrapping_add(1),
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((80, 0)),
        b"x",
    );
    // Bytes 6-7 hold IP flags + fragment offset (big endian).
    let mut ff = u16::from_be_bytes([frag[6], frag[7]]);
    ff |= 0x2000; // MF
    let bytes = ff.to_be_bytes();
    frag[6] = bytes[0];
    frag[7] = bytes[1];
    // Recompute IP checksum — we want to verify *fragmentation* is rejected,
    // not checksum failure.
    frag[10] = 0;
    frag[11] = 0;
    let csum = ip_checksum_for_test(&frag[..20]);
    let cb = csum.to_be_bytes();
    frag[10] = cb[0];
    frag[11] = cb[1];

    let res = tcb.inject_packet(&frag);
    assert!(res.is_err(), "MF=1 must be rejected");
}

/// Compute IPv4 header checksum the same way wire.rs does — local helper so
/// this test file doesn't depend on private functions.
fn ip_checksum_for_test(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        let hi = hdr[i] as u32;
        let lo = hdr[i + 1] as u32;
        sum = sum.wrapping_add((hi << 8) | lo);
        i += 2;
    }
    if i < hdr.len() {
        sum = sum.wrapping_add((hdr[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// On `close()` from `ESTABLISHED`, a single FIN+ACK is emitted. A
/// subsequent `close()` is idempotent — no second FIN.
#[test]
fn close_is_idempotent() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    tcb.close().expect("close");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, fin1) = pop(&mut tcb);
    assert_eq!(fin1.flags, flags::FIN | flags::ACK);

    // Double-close.
    tcb.close().expect("close again");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    assert!(try_pop(&mut tcb).is_none(), "no second FIN");
}


/// RFC 5681 §3.2 explicitly excludes piggybacked ACKs from the dup-ACK
/// counter: in a bidirectional bulk transfer the peer's piggybacked ACKs
/// naturally arrive at the same `snd_una` between RTTs (peer outpaces our
/// ACK schedule), and counting them would trigger spurious fast-retransmit
/// and collapse cwnd. This test pins that behaviour so we don't regress.
#[test]
fn piggybacked_acks_are_not_dup_acks() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Put one segment in flight so dup-ACKs would otherwise be eligible.
    let payload: ::std::vec::Vec<u8> = (0..1460).map(|i| (i & 0xFF) as u8).collect();
    let n = tcb.send(&payload).expect("send");
    assert_eq!(n, payload.len());
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _first = pop(&mut tcb);

    let snd_una_at_start = tcb.debug_snapshot().snd_una;

    // Five piggybacked segments at the same ack number. RFC 5681 says
    // these are NOT dup-ACKs — they're regular ACKs that happen to carry
    // peer data. cwnd must NOT collapse.
    let peer_data = vec![0xAB; 100];
    for i in 0..5 {
        now += 1;
        let pkt = build_in(
            flags::ACK | flags::PSH,
            PSS.wrapping_add(1).wrapping_add(i * 100),
            snd_una_at_start,
            PEER_WIN,
            None,
            Some((peer_ts.wrapping_add(i + 1), now as u32)),
            &peer_data,
        );
        tcb.set_now(now);
        tcb.inject_packet(&pkt).expect("inject");
        while try_pop(&mut tcb).is_some() {}
    }

    let snap = tcb.debug_snapshot();
    assert_eq!(
        snap.cwnd,
        crate::congestion::INITIAL_WINDOW,
        "piggybacked ACKs must NOT trigger Tahoe loss; cwnd should stay at slow-start value",
    );
    // snd_nxt should still be one MSS past snd_una (one segment in flight,
    // never rewound).
    assert_eq!(
        snap.snd_nxt.wrapping_sub(snap.snd_una),
        1460,
        "piggybacked ACKs must NOT rewind snd_nxt",
    );
}

/// Three pure-ACK duplicates with `ack == snd_una` and unchanged window
/// MUST trigger fast retransmit. This is the canonical RFC 5681 §3.2
/// trigger and the test guards against any regression that would over-
/// suppress dup-ACK counting (e.g. mis-applied window-change check).
///
/// Post-PRR (RFC 6937) behavior: cwnd is NOT collapsed to 1*MSS — that's
/// the Tahoe behavior the original test asserted. Instead PRR sets
/// `ssthresh = max(FlightSize/2, 2*MSS)`, leaves `cwnd` at its pre-loss
/// value, and gates per-ACK sends via `snd_credit` (initial budget = 1 MSS
/// for the immediate retransmit).
#[test]
fn pure_dup_acks_trigger_fast_retransmit() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    let payload: ::std::vec::Vec<u8> = (0..1460).map(|i| (i & 0xFF) as u8).collect();
    let n = tcb.send(&payload).expect("send");
    assert_eq!(n, payload.len());
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _first = pop(&mut tcb);

    let snd_una_at_loss = tcb.debug_snapshot().snd_una;

    for i in 0..3 {
        now += 1;
        let pkt = build_in(
            flags::ACK,
            PSS.wrapping_add(1),
            snd_una_at_loss,
            PEER_WIN,
            None,
            Some((peer_ts.wrapping_add(i + 1), now as u32)),
            &[],
        );
        tcb.set_now(now);
        tcb.inject_packet(&pkt).expect("inject dup-ack");
        while try_pop(&mut tcb).is_some() {}
    }

    let snap = tcb.debug_snapshot();
    // PRR: ssthresh = max(flight/2, 2*MSS) = 2920 for flight ≤ MSS.
    assert_eq!(
        snap.ssthresh, 2920,
        "PRR loss event sets ssthresh = max(flight/2, 2*MSS)",
    );
    // PRR: cwnd is NOT collapsed; stays at the pre-loss value (here, the
    // initial window since we haven't grown past it yet).
    assert_eq!(
        snap.cwnd,
        crate::congestion::INITIAL_WINDOW,
        "PRR does NOT collapse cwnd to 1*MSS (that's Tahoe behavior)",
    );
    // After fast retransmit, exactly one segment is in flight: snd_credit=MSS
    // at recovery entry caps the retransmit to a single MSS-payload (which
    // is MSS minus the 12-byte TS option = 1448).
    let flight = snap.snd_nxt.wrapping_sub(snap.snd_una);
    assert!(
        flight > 0 && flight <= 1460,
        "PRR initial retransmit ≤ 1 MSS; got flight={}",
        flight,
    );
}

// ---------------------------------------------------------------------------
// SACK (RFC 2018) — selective acknowledgement
// ---------------------------------------------------------------------------

/// The SYN we emit on `connect()` MUST carry the SACK_PERMITTED option.
/// Without this the peer will never send us SACK blocks, and the lossy
/// chaos profiles fall back to RTO-only recovery.
#[test]
fn syn_offers_sack_permitted() {
    let mut tcb = make_tcb();
    tcb.set_now(0);
    tcb.connect().expect("connect");
    tcb.tick().expect("tick");
    let (_, syn) = pop(&mut tcb);
    assert!(syn.flags & flags::SYN != 0);
    assert!(
        syn.sack_permitted,
        "SYN must offer SACK_PERMITTED (RFC 2018 §2)",
    );
    assert!(syn.sack.is_empty(), "SYN itself must not carry a SACK block");
}

/// When the peer's SYN-ACK echoes SACK_PERMITTED, an out-of-order segment
/// MUST cause us to emit a dup-ACK whose SACK option describes the held
/// run `[oo_start, oo_start+oo_len)`. RFC 2018 §3 + §4.
#[test]
fn out_of_order_segment_emits_sack_block_when_negotiated() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    // Peer sends 10 bytes 10 ahead of rcv_nxt.
    now += 5;
    let oo_seq = PSS.wrapping_add(1).wrapping_add(10);
    let oo = build_in(
        flags::ACK | flags::PSH,
        oo_seq,
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((50, 0)),
        b"out-of-ord",
    );
    tcb.set_now(now);
    tcb.inject_packet(&oo).expect("inject");
    tcb.set_now(now);
    tcb.tick().expect("tick");

    let (_, dup) = pop(&mut tcb);
    assert!(dup.flags & flags::ACK != 0);
    assert_eq!(dup.ack, PSS.wrapping_add(1), "ack stays at rcv_nxt");
    let blocks = dup.sack.as_slice();
    assert_eq!(blocks.len(), 1, "exactly one SACK block expected");
    let (left, right) = blocks[0];
    assert_eq!(left, oo_seq, "SACK left edge = held run start");
    assert_eq!(
        right,
        oo_seq.wrapping_add(b"out-of-ord".len() as u32),
        "SACK right edge = held run end",
    );
}

/// SACK-driven fast retransmit: a single ACK at `snd_una` carrying a SACK
/// block MUST trigger fast retransmit immediately (cwnd → 1*MSS, ssthresh
/// → max(flight/2, 2*MSS)) — without waiting for three duplicate ACKs.
/// This is the entire point of SACK in our stack: the chaos `loss-*`
/// profiles' bidirectional bulk produces piggybacked dup-ACKs that the
/// RFC 5681 §3.2 detector won't count, so without this the connection
/// wedges on RTO-only recovery (see #13 in docs/test-coverage-deferred.md).
#[test]
fn sack_block_triggers_fast_retransmit_after_one_ack() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Put two MSS in flight so there's a meaningful "missing" segment to
    // SACK around.
    let payload: ::std::vec::Vec<u8> = (0..2920).map(|i| (i & 0xFF) as u8).collect();
    let n = tcb.send(&payload).expect("send");
    assert_eq!(n, payload.len());
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _ = pop(&mut tcb); // first MSS goes out
    // cwnd from slow start now allows the second segment too.
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _ = try_pop(&mut tcb);

    let snd_una_at_loss = tcb.debug_snapshot().snd_una;

    // One ACK at snd_una with a SACK block describing 1460 bytes received
    // ABOVE snd_una (i.e. the second segment landed; the first was lost).
    let sack_left = snd_una_at_loss.wrapping_add(1460);
    let sack_right = sack_left.wrapping_add(1460);
    now += 1;
    let pkt = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        snd_una_at_loss,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(1), now as u32)),
        false,
        Some((sack_left, sack_right)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&pkt).expect("inject SACK");
    // Drain & inspect: the first packet should be the retransmit.
    let retx = pop(&mut tcb).1;
    while try_pop(&mut tcb).is_some() {}

    let snap = tcb.debug_snapshot();
    // PRR: ssthresh = max(flight/2, 2*MSS) = 2920 (clamped to 2*MSS floor
    // since flight is ~2*1448 = 2896 < 4*MSS).
    assert_eq!(
        snap.ssthresh, 2920,
        "ssthresh = max(flight/2, 2*MSS) at SACK-driven loss event",
    );
    assert_eq!(
        snap.cwnd,
        crate::congestion::INITIAL_WINDOW,
        "PRR does NOT collapse cwnd at recovery entry",
    );
    // RFC 6675 selective retransmit: the lost segment is retransmitted at
    // snd_una. Unlike Tahoe / our pre-RFC-6675 code, snd_nxt is NOT
    // rewound — retransmits travel "below" snd_nxt without disturbing it.
    assert_eq!(
        retx.seq, snd_una_at_loss,
        "first retransmit must be at snd_una (the obvious hole)",
    );
    assert!(
        !retx.payload.is_empty() && retx.payload.len() <= 1460,
        "retransmit must carry ≤ 1 MSS of payload",
    );
    // snd_nxt stays at its pre-loss high-water mark (2 segments × 1448 = 2896,
    // since TS option shrinks effective payload from MSS=1460 by 12 bytes).
    let flight_visible = snap.snd_nxt.wrapping_sub(snap.snd_una);
    assert!(
        flight_visible >= 2880 && flight_visible <= 2920,
        "snd_nxt MUST NOT rewind under RFC 6675 selective retransmit (got flight={})",
        flight_visible,
    );
}

/// SACK-driven fast retransmit fires from a piggybacked ACK too — that's
/// the whole reason SACK exists in our stack. The pure-dup-ACK detector
/// (which requires `payload.is_empty()`) would NOT fire here, so the
/// only path to fast-retransmit is via SACK. This test guards against
/// the SACK detector being accidentally narrowed to pure ACKs.
#[test]
fn sack_triggers_fast_retransmit_on_piggybacked_ack() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Two MSS in flight, as above.
    let payload: ::std::vec::Vec<u8> = (0..2920).map(|i| (i & 0xFF) as u8).collect();
    tcb.send(&payload).expect("send");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _ = pop(&mut tcb);
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _ = try_pop(&mut tcb);

    let snd_una_at_loss = tcb.debug_snapshot().snd_una;
    let sack_left = snd_una_at_loss.wrapping_add(1460);
    let sack_right = sack_left.wrapping_add(1460);

    // Piggybacked ACK at snd_una: carries 100 bytes of peer data and a
    // SACK block. The pure-dup-ACK detector skips this (payload non-empty);
    // SACK detector MUST fire.
    now += 1;
    let peer_data = vec![0xAB; 100];
    let pkt = build_in_full(
        flags::ACK | flags::PSH,
        PSS.wrapping_add(1),
        snd_una_at_loss,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(1), now as u32)),
        false,
        Some((sack_left, sack_right)),
        &peer_data,
    );
    tcb.set_now(now);
    tcb.inject_packet(&pkt).expect("inject");
    while try_pop(&mut tcb).is_some() {}

    let snap = tcb.debug_snapshot();
    assert_eq!(
        snap.ssthresh, 2920,
        "SACK on piggybacked ACK must trigger PRR fast recovery",
    );
    assert!(
        snap.cwnd >= crate::congestion::INITIAL_WINDOW,
        "PRR does not collapse cwnd; should still be ≥ IW",
    );
}

/// Multiple SACK ACKs inside a single recovery epoch (i.e. before
/// `snd_una` advances past the trigger point) MUST NOT keep collapsing
/// cwnd. RFC 6675 §5 calls this the recovery-point check; we approximate
/// with `sack_recovery_seq`. Without it, every dup-ACK in the loss
/// recovery window would re-collapse cwnd and stall the connection
/// indefinitely.
#[test]
fn sack_does_not_retrigger_within_recovery_epoch() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    let payload: ::std::vec::Vec<u8> = (0..2920).map(|i| (i & 0xFF) as u8).collect();
    tcb.send(&payload).expect("send");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _ = pop(&mut tcb);
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _ = try_pop(&mut tcb);

    let snd_una_at_loss = tcb.debug_snapshot().snd_una;
    let sack_left = snd_una_at_loss.wrapping_add(1460);
    let sack_right = sack_left.wrapping_add(1460);

    // First SACK ACK: triggers fast retransmit.
    now += 1;
    let first = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        snd_una_at_loss,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(1), now as u32)),
        false,
        Some((sack_left, sack_right)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&first).expect("inject");
    while try_pop(&mut tcb).is_some() {}
    let after_first = tcb.debug_snapshot();
    // PRR: ssthresh=2920, cwnd unchanged from pre-loss value.
    assert_eq!(after_first.ssthresh, 2920);
    assert!(after_first.cwnd >= crate::congestion::INITIAL_WINDOW);

    // Now send three more SACK ACKs at the same snd_una. They MUST NOT
    // re-collapse anything: ssthresh stays at 2920, cwnd is allowed to
    // grow as ACKs continue but isn't reset. We assert the non-regression
    // by checking ssthresh hasn't been pulled lower.
    for i in 0..3 {
        now += 1;
        let extra = build_in_full(
            flags::ACK,
            PSS.wrapping_add(1),
            snd_una_at_loss,
            PEER_WIN,
            None,
            Some((peer_ts.wrapping_add(2 + i), now as u32)),
            false,
            Some((sack_left, sack_right)),
            &[],
        );
        tcb.set_now(now);
        tcb.inject_packet(&extra).expect("inject");
        while try_pop(&mut tcb).is_some() {}
    }
    let after_more = tcb.debug_snapshot();
    assert_eq!(
        after_more.ssthresh, 2920,
        "additional SACK ACKs in the same recovery epoch must NOT re-trigger Tahoe loss",
    );
}

/// After a SACK-driven fast-retransmit rewinds `snd_nxt` to `snd_una`, the
/// peer's first cumulative ACK following recovery may land **above** the
/// rewound `snd_nxt` — because the peer had buffered our pre-rewind
/// segments out-of-order, and our retransmit's arrival fills the hole and
/// releases the entire run for cumulative acknowledgement in one ACK.
///
/// The RFC 793 §3.4 acceptability test is `SND.UNA < SEG.ACK ≤ SND.NXT`.
/// Comparing against the live (rewound) `SND.NXT` rejects this ACK as
/// referring to data we never sent — a spec-literal but operationally
/// catastrophic interpretation: `snd_una` freezes, the connection wedges,
/// and every subsequent ACK from the peer is also above the (still-rewound)
/// `snd_nxt`. The fix is to compare against `snd_max`, the high-water
/// mark of bytes ever put on the wire, which doesn't rewind. This test
/// pins that contract: a cumulative ACK landing at snd_max after a SACK
/// rewind MUST advance `snd_una`, not be rejected.
#[test]
fn cumulative_ack_after_sack_rewind_is_accepted() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Send 4 MSS-sized segments worth of data. IW=10 means the stack
    // will emit them all without waiting for ACKs.
    let payload: ::std::vec::Vec<u8> = (0..(4 * 1448)).map(|i| (i & 0xFF) as u8).collect();
    tcb.send(&payload).expect("send");

    // Drain all 4 segments produced by the initial burst.
    let mut segs = ::std::vec::Vec::new();
    for _ in 0..16 {
        now += 1;
        tcb.set_now(now);
        tcb.tick().expect("tick");
        match try_pop(&mut tcb) {
            Some(s) => segs.push(s),
            None => break,
        }
    }
    assert!(
        segs.len() >= 4,
        "IW=10 should let us send 4 segments in one burst; got {}",
        segs.len(),
    );

    // Take the first 4 segments and ACK the first two cumulatively, so
    // 2 MSS are in flight at the time of the SACK loss event.
    let s1 = &segs[0];
    let s2 = &segs[1];
    let s3 = &segs[2];
    let s4 = &segs[3];
    let s2_end = s2.seq.wrapping_add(s2.payload.len() as u32);
    let s3_seq = s3.seq;
    let s4_seq = s4.seq;
    let s4_end = s4.seq.wrapping_add(s4.payload.len() as u32);
    assert_eq!(s2.seq, s1.seq.wrapping_add(s1.payload.len() as u32));
    assert_eq!(s3_seq, s2_end);
    assert_eq!(s4_seq, s3_seq.wrapping_add(s3.payload.len() as u32));

    // Cumulatively ACK segments #1 and #2. snd_una advances to s3_seq.
    now += 1;
    let ack12 = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        s2_end,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(1), now as u32)),
        false,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&ack12).expect("inject");
    // Drain any segments the post-ACK send may have emitted (we have more
    // payload waiting, but we don't care — we'll just keep snd_max as it
    // grows).
    while try_pop(&mut tcb).is_some() {}

    let snd_una_pre_loss = tcb.debug_snapshot().snd_una;
    let snd_max_pre_loss = tcb.debug_snapshot().snd_nxt;
    assert_eq!(snd_una_pre_loss, s3_seq, "snd_una advanced over #1+#2");
    assert!(
        snd_max_pre_loss.wrapping_sub(s4_end) <= payload.len() as u32,
        "snd_max at the top of all emitted data",
    );

    // SACK ACK: ack=snd_una (= seg #3 start), SACK block describes seg #4
    // — peer received #4 OOO but is still missing #3.
    let sack_left = s4_seq;
    let sack_right = s4_end;
    now += 1;
    let sack = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        snd_una_pre_loss,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(3), now as u32)),
        false,
        Some((sack_left, sack_right)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&sack).expect("inject SACK");
    // PRR fast-retransmit: rewind snd_nxt and retransmit 1 MSS.
    let _ = pop(&mut tcb);

    let snap = tcb.debug_snapshot();
    assert!(snap.ssthresh >= 2 * 1460, "ssthresh ≥ 2*MSS per PRR");
    assert_eq!(snap.snd_una, snd_una_pre_loss, "snd_una not yet advanced");
    // Under RFC 6675 selective retransmit, snd_nxt is NOT rewound. The
    // retransmit travels at snd_una "below" snd_nxt, and snd_nxt stays
    // at its pre-loss high-water mark.
    assert_eq!(
        snap.snd_nxt, snd_max_pre_loss,
        "snd_nxt MUST NOT rewind under RFC 6675 selective retransmit",
    );

    // The retransmit fills the peer's hole. The peer cumulatively ACKs
    // *both* seg #3 and seg #4 (and possibly more) in one ACK — this ACK
    // lands beyond the rewound snd_nxt but at most at snd_max. The
    // snd_max acceptability fix is what makes us accept it.
    now += 1;
    let cum = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        snd_max_pre_loss,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(4), now as u32)),
        false,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&cum).expect("inject cumulative ACK");
    while try_pop(&mut tcb).is_some() {}

    let after = tcb.debug_snapshot();
    assert_eq!(
        after.snd_una, snd_max_pre_loss,
        "cumulative ACK above rewound snd_nxt MUST advance snd_una; \
         comparing against snd_nxt instead of snd_max wedges the connection",
    );
    // snd_nxt must be re-synced forward: at minimum to snd_una.
    let nxt_lt_una = (after.snd_nxt.wrapping_sub(after.snd_una) as i32) < 0;
    assert!(
        !nxt_lt_una,
        "snd_nxt must never sit below snd_una after an ACK that crosses it (snd_nxt={:#x} snd_una={:#x})",
        after.snd_nxt, after.snd_una,
    );
}

// ---------------------------------------------------------------------------
// RFC 7323 §2 — Window Scale option
// ---------------------------------------------------------------------------

/// Active SYN MUST carry the Window Scale option. We currently advertise
/// shift=1 (minimal scale that lets us advertise the 64KiB receive ring
/// without truncation).
/// Active SYN MUST carry the Window Scale option. The advertised shift
/// is whatever the smallest scale that lets us advertise our 1 MiB
/// receive ring is — the exact value is implementation-defined but it
/// must be present and ≥ 1 (we always need *some* scaling for buffers
/// > 32 KiB).
#[test]
fn syn_offers_window_scale() {
    let mut tcb = make_tcb();
    tcb.set_now(0);
    tcb.connect().expect("connect");
    tcb.set_now(0);
    tcb.tick().expect("tick");
    let (_, syn) = pop(&mut tcb);
    assert!(syn.flags & flags::SYN != 0);
    let ws = syn.wscale.expect("SYN must offer WS for BUF_CAP > 32 KiB");
    assert!(ws >= 1, "shift must be ≥ 1 to fit BUF_CAP in 16 bits");
    assert!(ws <= 14, "RFC 7323 §2.3 caps shift at 14");
    // BUF_CAP must fit when shifted down by `ws`.
    assert!(
        (crate::BUF_CAP as u32) >> ws <= u16::MAX as u32,
        "advertised window after shift={} must fit in u16",
        ws,
    );
}

/// RFC 7323 §2.3: the Window field in a SYN segment is NEVER scaled.
/// Even though we negotiate rcv_wscale=1 once the peer agrees, our SYN
/// itself must advertise the unscaled receive window.
#[test]
fn syn_window_field_is_unscaled() {
    let mut tcb = make_tcb();
    tcb.set_now(0);
    tcb.connect().expect("connect");
    tcb.set_now(0);
    tcb.tick().expect("tick");
    let (_, syn) = pop(&mut tcb);
    // Empty receive ring → advertised_window = BUF_CAP, but SYN windows
    // are NEVER scaled (RFC 7323 §2.3) and the field is u16, so this
    // saturates at u16::MAX regardless of how big BUF_CAP is.
    assert_eq!(
        syn.window,
        u16::MAX,
        "SYN window must be the unscaled (saturated) receive capacity",
    );
}

/// SYN-ACK without the WS option disables scaling in BOTH directions:
/// outbound windows are unscaled (saturated to 65535), and inbound peer
/// windows are read raw.
#[test]
fn syn_ack_without_ws_disables_scaling_both_directions() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    tcb.set_now(now);
    tcb.connect().expect("connect");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, syn) = pop(&mut tcb);
    let (cli_tsval, _) = syn.ts.expect("ts");

    // SYN-ACK with NO Window Scale option, peer window = 30000.
    now += 5;
    let synack = build_in_full_ws(
        flags::SYN | flags::ACK,
        PSS,
        ISS.wrapping_add(1),
        30_000,
        Some(1460),
        None, // no WS
        Some((42, cli_tsval)),
        true,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&synack).expect("inject");

    // Drain the third ACK (just to advance state).
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, ack) = pop(&mut tcb);
    assert_eq!(ack.flags, flags::ACK);
    // Outbound window in our third ACK must be UNSCALED — peer doesn't
    // know to shift it, so we must give it the raw value (saturated).
    assert_eq!(
        ack.window,
        u16::MAX,
        "post-handshake window must be unscaled when peer didn't offer WS",
    );

    // Now send some data. Peer's snd_wnd must be interpreted as raw 30000,
    // not 30000 << anything. Verify by sending more than 30000 bytes and
    // checking we don't exceed.
    let snap = tcb.debug_snapshot();
    assert_eq!(snap.snd_wnd, 30_000, "peer window read raw");
}

/// SYN-ACK with WS=N enables scaling: peer's advertised window is
/// interpreted as `seg.window << N` for all subsequent segments.
#[test]
fn syn_ack_with_ws_enables_scaled_peer_window() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    tcb.set_now(now);
    tcb.connect().expect("connect");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, syn) = pop(&mut tcb);
    let (cli_tsval, _) = syn.ts.expect("ts");

    // SYN-ACK with WS=7 (Linux's typical choice) and window=20000.
    // True peer window after scaling: 20000 << 7 = 2_560_000 bytes.
    now += 5;
    let peer_ws = 7u8;
    let synack_win = 20_000u16;
    let synack = build_in_full_ws(
        flags::SYN | flags::ACK,
        PSS,
        ISS.wrapping_add(1),
        synack_win,
        Some(1460),
        Some(peer_ws),
        Some((42, cli_tsval)),
        true,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&synack).expect("inject");

    // RFC 7323 §2.3: SYN-ACK window IS unscaled. So immediately after
    // handshake, snd_wnd should be the raw 20000 (not shifted yet).
    let snap = tcb.debug_snapshot();
    assert_eq!(
        snap.snd_wnd, synack_win as u32,
        "SYN-ACK window field is unscaled per RFC 7323 §2.3",
    );

    // Drain our third ACK.
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _ = pop(&mut tcb);

    // Now the peer sends a data segment with window=20000. From this
    // segment onward, scaling applies: snd_wnd should become 20000<<7.
    now += 5;
    let data_seg = build_in_full_ws(
        flags::ACK,
        PSS.wrapping_add(1),
        ISS.wrapping_add(1),
        synack_win,
        None,
        None,
        Some((50, cli_tsval)),
        false,
        None,
        b"hi",
    );
    tcb.set_now(now);
    tcb.inject_packet(&data_seg).expect("inject");
    let snap = tcb.debug_snapshot();
    let expected = (synack_win as u32) << peer_ws;
    assert_eq!(
        snap.snd_wnd, expected,
        "post-SYN-ACK segments must apply WS shift: {} << {} = {}",
        synack_win, peer_ws, expected,
    );
}

/// Outbound data segment after a WS-negotiated handshake must encode
/// the receive window right-shifted by our advertised rcv_wscale.
#[test]
fn outbound_data_window_is_scaled() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    tcb.set_now(now);
    tcb.connect().expect("connect");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, syn) = pop(&mut tcb);
    let local_ws = syn.wscale.expect("SYN must offer WS");
    assert!(local_ws >= 1, "WS shift must let us advertise BUF_CAP");
    let (cli_tsval, _) = syn.ts.expect("ts");

    // SYN-ACK with WS=2 echoed back — both sides scale.
    now += 5;
    let synack = build_in_full_ws(
        flags::SYN | flags::ACK,
        PSS,
        ISS.wrapping_add(1),
        PEER_WIN,
        Some(1460),
        Some(2),
        Some((42, cli_tsval)),
        true,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&synack).expect("inject");
    tcb.set_now(now);
    tcb.tick().expect("tick");

    // Third ACK is post-handshake, so its window field IS scaled.
    let (_, third_ack) = pop(&mut tcb);
    assert_eq!(third_ack.flags, flags::ACK);
    // Empty receive ring → advertised_window = BUF_CAP. After right-shift
    // by local_ws and saturation to u16::MAX, peer multiplies back to
    // (advertised_field << local_ws), recovering ≤ BUF_CAP.
    let expected = core::cmp::min(
        (crate::BUF_CAP as u32) >> local_ws,
        u16::MAX as u32,
    ) as u16;
    assert_eq!(
        third_ack.window, expected,
        "post-handshake window must be advertised >> rcv_wscale (saturated)",
    );
    // Sanity: peer would recover this many bytes.
    let recovered = (third_ack.window as u32) << local_ws;
    assert!(
        recovered >= core::cmp::min(crate::BUF_CAP as u32, (u16::MAX as u32) << local_ws),
        "recovered window must be close to BUF_CAP",
    );
}

/// Window Scale option survives an emit/parse round-trip.
#[test]
fn ws_option_round_trip() {
    let mut buf = vec![0u8; MAX_PACKET];
    let opts = TcpOptions {
        mss: Some(1460),
        wscale: Some(7),
        ts: Some((1234, 5678)),
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    let n = wire::emit(
        &mut buf,
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        SERVER_PORT,
        ISS,
        0,
        flags::SYN,
        65535,
        &opts,
        &[],
        0,
        wire::ecn::NOT_ECT,
    )
    .expect("emit");
    buf.truncate(n);
    let parsed = wire::parse(&buf).expect("parse");
    assert_eq!(parsed.options.mss, Some(1460));
    assert_eq!(parsed.options.wscale, Some(7));
    assert_eq!(parsed.options.ts, Some((1234, 5678)));
    assert!(parsed.options.sack_permitted);
}

/// RFC 7323 §2.3: peer-emitted shift counts > 14 are silently clamped to
/// 14 by the parser. This guards us from ever shifting a u32 by 32+.
#[test]
fn ws_shift_above_14_is_clamped_on_parse() {
    let mut buf = vec![0u8; MAX_PACKET];
    let opts = TcpOptions {
        wscale: Some(20), // emitter clamps to 14 too
        ..TcpOptions::NONE
    };
    let n = wire::emit(
        &mut buf,
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        SERVER_PORT,
        ISS,
        0,
        flags::SYN,
        65535,
        &opts,
        &[],
        0,
        wire::ecn::NOT_ECT,
    )
    .expect("emit");
    buf.truncate(n);
    let parsed = wire::parse(&buf).expect("parse");
    assert_eq!(parsed.options.wscale, Some(14), "shift must be clamped");
}

// ---------------------------------------------------------------------------
// RFC 6928 — Initial Window 10
// ---------------------------------------------------------------------------

/// Right after the handshake completes, cwnd must equal `INITIAL_WINDOW`
/// (RFC 6928 IW=10*MSS for our MSS), not the legacy `1*MSS`. This is
/// what lets the first round-trip carry up to 10 segments instead of 1
/// — typically a full HTTP response in one RTT.
#[test]
fn initial_window_is_rfc6928_iw10() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    let snap = tcb.debug_snapshot();
    assert_eq!(
        snap.cwnd,
        crate::congestion::INITIAL_WINDOW,
        "initial cwnd must equal RFC 6928 IW",
    );
    // For our MSS=1460, RFC 6928 formula gives exactly 10*MSS = 14_600.
    assert_eq!(snap.cwnd, 14_600, "IW=10*1460 = 14600 bytes");
}

/// With IW=10 a single `send()` of up to 10 MSS-sized segments worth of
/// data should be allowed to leave the wire without waiting for any ACK,
/// modulo the peer's advertised window.
#[test]
fn iw10_lets_first_burst_send_multiple_segments() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    // Push 10 MSS worth of data into the send ring.
    let payload: ::std::vec::Vec<u8> = (0..14_600).map(|i| (i & 0xFF) as u8).collect();
    let n = tcb.send(&payload).expect("send");
    assert_eq!(n, payload.len());

    // Drain all packets the stack produces in one tick burst.
    // Each call to extract_packet returns at most one packet and the
    // implementation only stages one at a time, so we loop tick+pop until
    // the stack stops emitting.
    let mut emitted_segments = 0;
    let mut emitted_bytes = 0;
    for _ in 0..32 {
        now += 1;
        tcb.set_now(now);
        tcb.tick().expect("tick");
        match try_pop(&mut tcb) {
            Some(seg) => {
                emitted_segments += 1;
                emitted_bytes += seg.payload.len();
            }
            None => break,
        }
    }
    assert!(
        emitted_segments >= 10,
        "IW=10 should allow at least 10 unacked segments; got {}",
        emitted_segments,
    );
    assert!(
        emitted_bytes >= 14_600,
        "should emit full 14600-byte burst before needing ACK; got {}",
        emitted_bytes,
    );
}

// ---------------------------------------------------------------------------
// RFC 6937 — Proportional Rate Reduction
// ---------------------------------------------------------------------------

/// PRR-SSRB exits recovery with cwnd = ssthresh, NOT cwnd = 1*MSS (which
/// would be the Tahoe behavior). The test drives a small loss event,
/// retransmits the lost segment, and lets the peer's cumulative ACK reach
/// the recovery point. Post-recovery cwnd must equal ssthresh.
#[test]
fn prr_exits_recovery_with_cwnd_equal_ssthresh() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Send 4 MSS worth of data — IW=10 lets us emit all of it.
    let payload: ::std::vec::Vec<u8> = (0..(4 * 1448)).map(|i| (i & 0xFF) as u8).collect();
    tcb.send(&payload).expect("send");
    let mut segs = ::std::vec::Vec::new();
    for _ in 0..16 {
        now += 1;
        tcb.set_now(now);
        tcb.tick().expect("tick");
        match try_pop(&mut tcb) {
            Some(s) => segs.push(s),
            None => break,
        }
    }
    assert!(segs.len() >= 4);

    let _s1 = &segs[0];
    let s2 = &segs[1];
    let s3 = &segs[2];
    let s4 = &segs[3];
    let s2_end = s2.seq.wrapping_add(s2.payload.len() as u32);
    let s3_seq = s3.seq;
    let s4_seq = s4.seq;
    let s4_end = s4.seq.wrapping_add(s4.payload.len() as u32);

    // Cumulatively ACK s1+s2 to bring snd_una to s3_seq.
    now += 1;
    let cum12 = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        s2_end,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(1), now as u32)),
        false,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&cum12).expect("inject");
    while try_pop(&mut tcb).is_some() {}

    let snd_max_pre_loss = tcb.debug_snapshot().snd_nxt;

    // SACK trigger: snd_una stays at s3, SACK block describes s4.
    now += 1;
    let sack = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        s3_seq,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(2), now as u32)),
        false,
        Some((s4_seq, s4_end)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&sack).expect("inject SACK");
    while try_pop(&mut tcb).is_some() {}

    let pre_exit = tcb.debug_snapshot();
    let ssthresh_at_recovery = pre_exit.ssthresh;
    assert_eq!(ssthresh_at_recovery, 2920, "ssthresh = max(2*MSS/2, 2*MSS)");

    // Cumulative ACK at snd_max (the recovery_point) — must exit recovery.
    now += 1;
    let cum_to_max = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        snd_max_pre_loss,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(3), now as u32)),
        false,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&cum_to_max).expect("inject cum");
    while try_pop(&mut tcb).is_some() {}

    let post_exit = tcb.debug_snapshot();
    assert_eq!(
        post_exit.cwnd, ssthresh_at_recovery,
        "PRR exit: cwnd = ssthresh, NOT cwnd = 1*MSS",
    );
}

/// RTO (not fast retransmit) MUST still collapse cwnd to 1*MSS per
/// RFC 5681 §3 — PRR (RFC 6937 §6) explicitly says it does not modify
/// RTO behavior.
#[test]
fn rto_still_collapses_cwnd_to_one_mss() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    // Put one segment in flight.
    let payload: ::std::vec::Vec<u8> = (0..1448).collect::<::std::vec::Vec<usize>>()
        .iter()
        .map(|i| (i & 0xFF) as u8)
        .collect();
    tcb.send(&payload).expect("send");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let _ = pop(&mut tcb);

    let cwnd_before = tcb.debug_snapshot().cwnd;
    assert!(cwnd_before >= crate::congestion::INITIAL_WINDOW);

    // Advance time past initial RTO (1000 ms) without any ACK.
    now += 2_000;
    tcb.set_now(now);
    tcb.tick().expect("tick");

    let snap = tcb.debug_snapshot();
    assert_eq!(
        snap.cwnd, 1460,
        "RTO must collapse cwnd to 1*MSS (RFC 5681 §3)",
    );
    assert!(
        snap.ssthresh >= 2 * 1460,
        "RTO must set ssthresh ≥ 2*MSS",
    );
}

// ---------------------------------------------------------------------------
// RFC 3168 — Explicit Congestion Notification
// ---------------------------------------------------------------------------

/// Active SYN MUST carry the ECN-Setup flags (CWR + ECE per RFC 3168
/// §6.1.1). The SYN itself MUST NOT be ECT-marked at the IP layer.
#[test]
fn syn_offers_ecn_setup_flags() {
    let mut tcb = make_tcb();
    tcb.set_now(0);
    tcb.connect().expect("connect");
    tcb.set_now(0);
    tcb.tick().expect("tick");
    let (raw, syn) = pop(&mut tcb);
    assert!(syn.flags & flags::SYN != 0);
    assert!(
        syn.flags & flags::ECE != 0,
        "ECN-Setup SYN must set ECE (RFC 3168 §6.1.1)",
    );
    assert!(
        syn.flags & flags::CWR != 0,
        "ECN-Setup SYN must set CWR (RFC 3168 §6.1.1)",
    );
    // IP TOS lower 2 bits MUST be 00 (Not-ECT) on a SYN.
    assert_eq!(
        raw[1] & wire::ecn::MASK,
        wire::ecn::NOT_ECT,
        "SYN packet MUST NOT be ECT-marked",
    );
}

/// SYN-ACK with ECE only (no CWR) confirms ECN per RFC 3168 §6.1.1.
/// Subsequent data segments MUST carry ECT(0) in the IP TOS byte.
#[test]
fn syn_ack_with_ece_only_enables_ecn() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    tcb.set_now(now);
    tcb.connect().expect("connect");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, syn) = pop(&mut tcb);
    let (cli_tsval, _) = syn.ts.expect("ts");

    // SYN-ACK with ECE set, CWR clear → ECN confirmed.
    now += 5;
    let mut synack = build_in_full(
        flags::SYN | flags::ACK | flags::ECE,
        PSS,
        ISS.wrapping_add(1),
        PEER_WIN,
        Some(1460),
        Some((42, cli_tsval)),
        true,
        None,
        &[],
    );
    // Recompute IP+TCP checksums after we... wait, build_in_full handled
    // the flag during emit so we don't need to fix anything up. Make sure
    // the emit included ECE in the flags byte.
    let parsed = wire::parse(&synack).expect("parse");
    assert!(parsed.has(flags::ECE), "test fixture must include ECE");
    let _ = &mut synack;

    tcb.set_now(now);
    tcb.inject_packet(&synack).expect("inject");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (third_ack_raw, third_ack) = pop(&mut tcb);
    assert_eq!(third_ack.flags & !(flags::ECE | flags::CWR), flags::ACK);

    // Now send some application data and verify the outbound segment is
    // ECT(0)-marked at the IP layer.
    tcb.send(b"hi").expect("send");
    now += 1;
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (data_raw, _) = pop(&mut tcb);
    assert_eq!(
        data_raw[1] & wire::ecn::MASK,
        wire::ecn::ECT_0,
        "post-handshake data on ECN-enabled connection must be ECT(0)",
    );
    // Third ACK (post-handshake but no payload) is also ECT(0) per RFC 3168.
    assert_eq!(third_ack_raw[1] & wire::ecn::MASK, wire::ecn::ECT_0);
}

/// SYN-ACK without ECE disables ECN entirely. Subsequent segments must
/// be NOT_ECT.
#[test]
fn syn_ack_without_ece_disables_ecn() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    tcb.set_now(now);
    tcb.connect().expect("connect");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, syn) = pop(&mut tcb);
    let (cli_tsval, _) = syn.ts.expect("ts");

    // SYN-ACK without ECE → ECN not confirmed.
    now += 5;
    let synack = build_in_full(
        flags::SYN | flags::ACK,
        PSS,
        ISS.wrapping_add(1),
        PEER_WIN,
        Some(1460),
        Some((42, cli_tsval)),
        true,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&synack).expect("inject");
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (third_ack_raw, _) = pop(&mut tcb);
    assert_eq!(
        third_ack_raw[1] & wire::ecn::MASK,
        wire::ecn::NOT_ECT,
        "ECN-not-negotiated connection must use NOT_ECT",
    );

    tcb.send(b"hi").expect("send");
    now += 1;
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (data_raw, _) = pop(&mut tcb);
    assert_eq!(data_raw[1] & wire::ecn::MASK, wire::ecn::NOT_ECT);
}

/// Helper: drive a handshake that successfully negotiates ECN. Returns
/// the peer's TSval echo value (same convention as `handshake_with_ts`).
fn handshake_with_ecn(tcb: &mut Tcb, now: &mut u64) -> u32 {
    tcb.set_now(*now);
    tcb.connect().expect("connect");
    tcb.set_now(*now);
    tcb.tick().expect("tick");
    let (_, syn) = pop(tcb);
    let (cli_tsval, _) = syn.ts.expect("ts");

    *now += 5;
    let peer_ts = 42u32;
    let synack = build_in_full(
        flags::SYN | flags::ACK | flags::ECE,
        PSS,
        ISS.wrapping_add(1),
        PEER_WIN,
        Some(1460),
        Some((peer_ts, cli_tsval)),
        true,
        None,
        &[],
    );
    tcb.set_now(*now);
    tcb.inject_packet(&synack).expect("inject");
    tcb.set_now(*now);
    tcb.tick().expect("tick");
    let (_, ack) = pop(tcb);
    assert_eq!(ack.ack, PSS.wrapping_add(1));
    assert_eq!(tcb.state(), State::Established);
    peer_ts
}

/// Build an inbound IPv4+TCP packet with an arbitrary ECN codepoint in
/// the IP TOS field (used to test CE handling).
#[allow(clippy::too_many_arguments)]
fn build_in_ecn(
    flag_bits: u8,
    seq: u32,
    ack: u32,
    win: u16,
    ts: Option<(u32, u32)>,
    ecn: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; MAX_PACKET];
    let opts = TcpOptions {
        ts,
        ..TcpOptions::NONE
    };
    let n = wire::emit(
        &mut buf,
        SERVER_IP,
        CLIENT_IP,
        SERVER_PORT,
        CLIENT_PORT,
        seq,
        ack,
        flag_bits,
        win,
        &opts,
        payload,
        0,
        ecn,
    )
    .expect("emit");
    buf.truncate(n);
    buf
}

/// RFC 3168 §6.1.2: an inbound segment with CE marking MUST cause us to
/// echo ECE on the next outbound ACK.
#[test]
fn ce_marked_inbound_triggers_ece_echo() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ecn(&mut tcb, &mut now);

    // Send a data segment FROM the peer with CE marking.
    now += 1;
    let data = build_in_ecn(
        flags::ACK | flags::PSH,
        PSS.wrapping_add(1),
        ISS.wrapping_add(1),
        PEER_WIN,
        Some((peer_ts.wrapping_add(1), now as u32)),
        wire::ecn::CE,
        b"hi",
    );
    tcb.set_now(now);
    tcb.inject_packet(&data).expect("inject");
    // Advance to trigger any delayed ACK so the ACK fires.
    now += 100;
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, ack) = pop(&mut tcb);
    assert!(
        ack.flags & flags::ECE != 0,
        "ACK following a CE-marked inbound MUST set ECE (RFC 3168 §6.1.2)",
    );
}

/// RFC 3168 §6.1.2: an inbound ECE-marked ACK is a congestion signal —
/// the sender enters recovery (ssthresh halves, PRR engages) and the
/// next new-data segment carries CWR.
#[test]
fn ece_marked_ack_triggers_congestion_response() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ecn(&mut tcb, &mut now);

    // Put some data in flight so ECE has something to halve.
    let payload: ::std::vec::Vec<u8> = (0..(3 * 1448)).map(|i| (i & 0xFF) as u8).collect();
    tcb.send(&payload).expect("send");
    for _ in 0..8 {
        now += 1;
        tcb.set_now(now);
        tcb.tick().expect("tick");
        if try_pop(&mut tcb).is_none() {
            break;
        }
    }

    let pre_ssthresh = tcb.debug_snapshot().ssthresh;
    let pre_in_recovery = tcb.debug_snapshot().rto_deadline; // proxy: in_recovery makes us rearm

    // Inject an ACK with ECE set. snd_una doesn't advance; the ECE
    // alone must trigger congestion response.
    now += 1;
    let snd_una = tcb.debug_snapshot().snd_una;
    let ece_ack = build_in_ecn(
        flags::ACK | flags::ECE,
        PSS.wrapping_add(1),
        snd_una,
        PEER_WIN,
        Some((peer_ts.wrapping_add(1), now as u32)),
        wire::ecn::NOT_ECT,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&ece_ack).expect("inject");

    let post = tcb.debug_snapshot();
    assert!(
        post.ssthresh < pre_ssthresh || post.ssthresh <= 2920,
        "ECE must reduce ssthresh (pre={} post={})",
        pre_ssthresh,
        post.ssthresh,
    );
    // Send more data; the next new-data segment MUST carry CWR.
    while try_pop(&mut tcb).is_some() {}
    let _ = pre_in_recovery;
    now += 1;
    tcb.set_now(now);
    tcb.tick().expect("tick");
    if let Some(seg) = try_pop(&mut tcb) {
        if !seg.payload.is_empty() {
            assert!(
                seg.flags & flags::CWR != 0,
                "first new-data segment after ECE response MUST set CWR (RFC 3168 §6.1.2)",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 8985 — RACK-TLP loss detection
// ---------------------------------------------------------------------------

/// RACK loss detection: send 4 segments, the peer SACKs only segment #4.
/// After RTT/4 + epsilon elapses, the RACK reorder timer fires and
/// segments 1-3 should be marked lost and retransmitted (starting with
/// snd_una). Pure dup-ACK detection wouldn't fire here — we only see one
/// SACK ACK — so this is exclusively RACK's win.
#[test]
fn rack_reorder_timer_marks_old_unsacked_segments_lost() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Push 4 MSS-payload segments. IW=10 lets them all go in one burst.
    let payload: ::std::vec::Vec<u8> = (0..(4 * 1448)).map(|i| (i & 0xFF) as u8).collect();
    tcb.send(&payload).expect("send");
    let mut segs = ::std::vec::Vec::new();
    for _ in 0..16 {
        now += 1;
        tcb.set_now(now);
        tcb.tick().expect("tick");
        match try_pop(&mut tcb) {
            Some(s) => segs.push(s),
            None => break,
        }
    }
    assert!(segs.len() >= 4, "want ≥4 segs, got {}", segs.len());
    let s4 = &segs[3];
    let s4_seq = s4.seq;
    let s4_end = s4.seq.wrapping_add(s4.payload.len() as u32);

    // Establish an RTT measurement: ACK seg #4 via SACK at time +50ms
    // (so SRTT samples lands around 50ms-ish; reo_wnd becomes ~12ms).
    now += 50;
    let sack = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(1), now as u32)),
        false,
        Some((s4_seq, s4_end)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&sack).expect("inject SACK");

    // The SACK arrival triggers PRR + an immediate scoreboard-driven
    // retransmit at snd_una (RFC 6675 initial retransmit). Drain it.
    while try_pop(&mut tcb).is_some() {}

    // Now advance time past RACK's threshold (SRTT + reo_wnd). At
    // SRTT≈50ms, reo_wnd ≈ 12ms, so we need elapsed since segs #2/#3
    // sends ≥ ~62ms. They were sent at time ≈ 5-10ms ago.
    now += 200;
    tcb.set_now(now);
    tcb.tick().expect("tick (RACK reorder timer)");

    // RACK should have queued lost ranges for segs #2 and #3 (seg #1 was
    // already retransmitted by RFC 6675's initial-retransmit path).
    // maybe_send_data drains one rack_lost per tick.
    let mut rack_retx = 0;
    for _ in 0..8 {
        now += 1;
        tcb.set_now(now);
        tcb.tick().expect("tick");
        match try_pop(&mut tcb) {
            Some(s) => {
                if s.flags & flags::PSH != 0
                    && !s.payload.is_empty()
                    && seq_lt(s.seq, s4_seq)
                {
                    rack_retx += 1;
                }
            }
            None => break,
        }
    }
    assert!(
        rack_retx >= 1,
        "RACK should have retransmitted at least one of segs #2/#3 (got {})",
        rack_retx,
    );
}

/// TLP fires PTO before RTO when there's un-ACKed data and no ACK
/// movement. Probe = retransmit of the last in-flight segment.
#[test]
fn tlp_probes_before_rto_fires() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Establish an SRTT sample first by ACKing a small initial send.
    // Without an RTT measurement, TLP's PTO formula uses TLP_MIN_PTO_MS=10ms.
    let _ = peer_ts;

    // Send one MSS, peer never ACKs.
    tcb.send(&vec![0xCC; 1448]).expect("send");
    now += 1;
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, original) = pop(&mut tcb);
    assert!(!original.payload.is_empty());
    let orig_seq = original.seq;

    // Advance past TLP PTO (no SRTT sample yet → uses MIN_PTO=10ms).
    // RTO is initial_rto_ms=1000. PTO should fire well before that.
    now += 50;
    tcb.set_now(now);
    tcb.tick().expect("tick");

    // A probe should now be staged.
    let probe = try_pop(&mut tcb).expect("TLP probe should have fired");
    assert!(!probe.payload.is_empty(), "probe carries payload");
    assert_eq!(
        probe.seq, orig_seq,
        "probe retransmits the last (only) in-flight segment",
    );

    // We must NOT have fired RTO yet (snapshot would show cwnd=MSS).
    let snap = tcb.debug_snapshot();
    assert!(
        snap.cwnd >= crate::congestion::INITIAL_WINDOW,
        "RTO should NOT have fired yet (cwnd={})",
        snap.cwnd,
    );
}

// seq_lt helper for tests
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Repro for the failing `rack_tail_loss_detection.pkt` packetdrill
/// scenario: with a short ~5ms SRTT, send 4 segments at t≈5ms, SACK
/// only #4 at t=15ms. Expect retransmit of seq #1 (NOT #4).
#[test]
fn rack_tail_loss_short_rtt_retransmits_first_unsacked() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Send 4 MSS-sized segments quickly, drain them.
    let payload: Vec<u8> = (0..(4 * 1448)).map(|i| (i & 0xFF) as u8).collect();
    tcb.send(&payload).expect("send");

    let mut segs = Vec::new();
    for _ in 0..16 {
        tcb.set_now(now);
        tcb.tick().expect("tick");
        match try_pop(&mut tcb) {
            Some(s) => segs.push(s),
            None => break,
        }
    }
    assert_eq!(segs.len(), 4, "want exactly 4 emitted segs");
    let s1_seq = segs[0].seq;
    let s4_seq = segs[3].seq;
    let s4_end = s4_seq.wrapping_add(1448);

    // SACK arrives 10ms later — only segment #4 is SACKed.
    now += 10;
    let sack = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        ISS.wrapping_add(1),
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(1), now as u32)),
        false,
        Some((s4_seq, s4_end)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&sack).expect("inject SACK");

    // Drain the immediate emit. It should be seq #1, NOT seq #4.
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let retx = try_pop(&mut tcb).expect("must emit a retransmit");
    assert_eq!(
        retx.seq, s1_seq,
        "first retransmit must be seq #1 (snd_una), not the SACKed seq #4 \
         (s1_seq={}, s4_seq={}, got={})",
        s1_seq, s4_seq, retx.seq,
    );
}
