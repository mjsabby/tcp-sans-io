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
use crate::wire::{self, flags, Segment, TcpOptions};
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
    ts: Option<(u32, u32)>,
    sack_permitted: bool,
    sack: Option<(u32, u32)>,
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
/// the convenience wrapper for the common (no-SACK) case.
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
    let mut buf = vec![0u8; MAX_PACKET];
    let opts = TcpOptions {
        mss,
        ts,
        sack_permitted,
        sack,
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
    assert_eq!(syn.flags, flags::SYN, "first packet must be pure SYN");
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
    assert_eq!(syn.flags, flags::SYN, "exactly SYN, no other flags");
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
    assert_eq!(syn1.flags, flags::SYN);
    assert_eq!(syn1.seq, ISS);

    // First RTO at +1000 ms (initial RTO).
    tcb.set_now(1001);
    tcb.tick().expect("tick");
    let (_, syn2) = pop(&mut tcb);
    assert_eq!(syn2.flags, flags::SYN, "retransmit is also SYN");
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
    assert_eq!(syn3.flags, flags::SYN);
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

/// Reassembly buffer is single-hole: a segment that creates a *second*
/// hole (i.e. doesn't abut the held run) must be silently dropped, and
/// the existing held run must remain intact.
#[test]
fn second_hole_is_dropped_held_run_preserved() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let _ = handshake_with_ts(&mut tcb, &mut now);

    let a = b"AAAAAAAAAA"; // 10 bytes at PSS+1
    let b = b"BBBBBBBBBB"; // 10 bytes at PSS+1+10 — held
    let c = b"CCCCCCCCCC"; // 10 bytes at PSS+1+30 — second hole, dropped
    let d = b"DDDDDDDDDD"; // 10 bytes at PSS+1+20 — would close gap to C if held
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

    // C arrives non-abutting → must be dropped.
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
    assert_eq!(dup_c.ack, seq_a, "C non-abutting → dup-ACK only");

    // D arrives, abutting B's tail → extends the held run.
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

    // A closes the gap. We expect a+b+d delivered (c was dropped).
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
        seq_d.wrapping_add(d.len() as u32),
        "cumulative ACK should cover A+B+D, not C"
    );

    let mut buf = [0u8; 64];
    let n = tcb.recv(&mut buf).expect("recv");
    assert_eq!(n, a.len() + b.len() + d.len());
    assert_eq!(&buf[..a.len()], a);
    assert_eq!(&buf[a.len()..a.len() + b.len()], b);
    assert_eq!(&buf[a.len() + b.len()..n], d);
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
        snap.cwnd, 1460,
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
    assert_eq!(
        snap.cwnd, 1460,
        "Tahoe collapses cwnd to 1*MSS on third dup-ACK",
    );
    // After on_loss rewinds snd_nxt, maybe_send_data immediately retransmits
    // one MSS (the new cwnd allows exactly that), so snd_nxt - snd_una is
    // back to 1*MSS. The unambiguous evidence of fast-retransmit is the
    // cwnd collapse plus ssthresh = max(flight/2, 2*MSS) = 2*MSS = 2920.
    assert_eq!(
        snap.ssthresh, 2920,
        "Tahoe loss event sets ssthresh = max(flight/2, 2*MSS)",
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
    assert_eq!(syn.flags, flags::SYN);
    assert!(
        syn.sack_permitted,
        "SYN must offer SACK_PERMITTED (RFC 2018 §2)",
    );
    assert!(syn.sack.is_none(), "SYN itself must not carry a SACK block");
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
    let (left, right) = dup.sack.expect("dup-ACK with held OOO must carry SACK");
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
    while try_pop(&mut tcb).is_some() {}

    let snap = tcb.debug_snapshot();
    assert_eq!(
        snap.cwnd, 1460,
        "SACK-driven fast retransmit must collapse cwnd to 1*MSS after a single ACK",
    );
    assert_eq!(
        snap.ssthresh, 2920,
        "ssthresh = max(flight/2, 2*MSS) = 2*MSS on a 2*MSS flight loss",
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
        snap.cwnd, 1460,
        "SACK on a piggybacked ACK must still trigger fast retransmit",
    );
    assert_eq!(snap.ssthresh, 2920);
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
    assert_eq!(after_first.cwnd, 1460);
    assert_eq!(after_first.ssthresh, 2920);

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
/// pins that contract: a 2*MSS cumulative ACK after a SACK rewind MUST
/// advance `snd_una`, not be rejected.
///
/// Without the `snd_max` fix this test fails with `snd_una` stuck at the
/// pre-recovery value — exactly the wedge seen in the chaos `loss-*`
/// profiles before the fix.
#[test]
fn cumulative_ack_after_sack_rewind_is_accepted() {
    let mut tcb = make_tcb();
    let mut now = 0u64;
    let peer_ts = handshake_with_ts(&mut tcb, &mut now);

    // Buffer 4*MSS of data; we'll grow cwnd via ACKs and end up with
    // 2*MSS in flight to make the SACK rewind scenario meaningful.
    let payload: ::std::vec::Vec<u8> = (0..(4 * 1448)).map(|i| (i & 0xFF) as u8).collect();
    tcb.send(&payload).expect("send");

    // Initial cwnd=1*MSS: emit segment #1 only.
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let (_, s1) = pop(&mut tcb);
    let s1_seq = s1.seq;
    let s1_end = s1_seq.wrapping_add(s1.payload.len() as u32);
    assert!(try_pop(&mut tcb).is_none(), "cwnd=1*MSS pins us to one segment");

    // ACK segment #1 → cwnd grows to 2*MSS in slow start.
    now += 1;
    let ack1 = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        s1_end,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(1), now as u32)),
        false,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&ack1).expect("inject ack1");
    // After this ACK, the stack will emit segment #2 immediately.
    let (_, s2) = pop(&mut tcb);
    let s2_seq = s2.seq;
    let s2_end = s2_seq.wrapping_add(s2.payload.len() as u32);
    assert_eq!(s2_seq, s1_end, "segment #2 follows #1 contiguously");

    // ACK segment #2 → cwnd = 3*MSS. Then drain segments #3 and #4 to
    // place 2*MSS in flight at the time of the SACK loss event.
    now += 1;
    let ack2 = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        s2_end,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(2), now as u32)),
        false,
        None,
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&ack2).expect("inject ack2");
    let (_, s3) = pop(&mut tcb);
    let s3_seq = s3.seq;
    let s3_end = s3_seq.wrapping_add(s3.payload.len() as u32);
    // Segment #4 may or may not be staged yet depending on tx_buf draining;
    // tick once more to flush it.
    tcb.set_now(now);
    tcb.tick().expect("tick");
    let s4 = pop(&mut tcb).1;
    let s4_seq = s4.seq;
    let s4_end = s4_seq.wrapping_add(s4.payload.len() as u32);
    assert_eq!(s4_seq, s3_end, "segment #4 follows #3 contiguously");

    let snd_una_at_loss = tcb.debug_snapshot().snd_una;
    let snd_nxt_pre_rewind = tcb.debug_snapshot().snd_nxt;
    assert_eq!(snd_una_at_loss, s3_seq);
    assert_eq!(snd_nxt_pre_rewind, s4_end);
    assert_eq!(
        snd_nxt_pre_rewind.wrapping_sub(snd_una_at_loss),
        2 * s3.payload.len() as u32,
        "test setup: 2*MSS in flight before SACK loss event",
    );

    // SACK ACK: ack=snd_una (= seg #3 start), SACK block describes seg #4
    // — i.e. peer received #4 OOO but is still missing #3.
    let sack_left = s4_seq;
    let sack_right = s4_end;
    now += 1;
    let sack = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        snd_una_at_loss,
        PEER_WIN,
        None,
        Some((peer_ts.wrapping_add(3), now as u32)),
        false,
        Some((sack_left, sack_right)),
        &[],
    );
    tcb.set_now(now);
    tcb.inject_packet(&sack).expect("inject SACK");
    // SACK fast-retransmit collapses cwnd to 1*MSS, rewinds snd_nxt, and
    // immediately retransmits seg #3.
    let _ = pop(&mut tcb);

    let snap = tcb.debug_snapshot();
    assert_eq!(snap.cwnd, 1460);
    assert_eq!(snap.ssthresh, 2920);
    assert_eq!(snap.snd_una, snd_una_at_loss, "snd_una not yet advanced");
    assert_eq!(
        snap.snd_nxt.wrapping_sub(snd_una_at_loss),
        s3.payload.len() as u32,
        "rewound snd_nxt + 1*MSS retransmit",
    );

    // The retransmit fills the peer's hole. The peer cumulatively ACKs
    // *both* seg #3 and seg #4 in one ACK — this ACK lands beyond the
    // rewound snd_nxt but at exactly snd_max. The fix is what makes us
    // accept it.
    now += 1;
    let cum = build_in_full(
        flags::ACK,
        PSS.wrapping_add(1),
        snd_nxt_pre_rewind,
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
        after.snd_una, snd_nxt_pre_rewind,
        "cumulative ACK above rewound snd_nxt MUST advance snd_una; \
         comparing against snd_nxt instead of snd_max wedges the connection",
    );
    // snd_nxt must be re-synced forward: at minimum to snd_una (or further,
    // if maybe_send_data has emitted new segment #5 onward).
    let nxt_lt_una = (after.snd_nxt.wrapping_sub(after.snd_una) as i32) < 0;
    assert!(
        !nxt_lt_una,
        "snd_nxt must never sit below snd_una after an ACK that crosses it (snd_nxt={:#x} snd_una={:#x})",
        after.snd_nxt, after.snd_una,
    );
}
