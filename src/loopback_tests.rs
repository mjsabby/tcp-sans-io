//! In-memory loopback harness.
//!
//! These tests live behind `cfg(test)` so the production crate stays `no_std`
//! and allocator-free. Inside the test crate we have `std` and can use `Vec`
//! freely for ergonomics.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate std;

use std::vec;
use std::vec::Vec;

use crate::error::TcpError;
use crate::tcb::{events, Endpoint, Tcb, TcbConfig};
use crate::wire::{self, flags, TcpOptions};
use crate::{State, MAX_PACKET};

const CLIENT_IP: [u8; 4] = [10, 0, 0, 1];
const SERVER_IP: [u8; 4] = [10, 0, 0, 2];
const CLIENT_PORT: u16 = 49152;
const SERVER_PORT: u16 = 80;
const SERVER_ISS: u32 = 0x9000_0000;
const CLIENT_ISS: u32 = 0x1000_0000;

// ---------------------------------------------------------------------------
// Test peer — a deliberately minimal, hand-rolled "server".
//
// Lifecycle is tracked with three booleans rather than a state enum so that
// simultaneous-close and crossed-FIN cases fall out naturally.
// ---------------------------------------------------------------------------

struct TestPeer {
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
    peer_mss: u16,
    ts_enabled: bool,
    ts_recent: u32,
    /// Window the peer advertises in every outgoing segment. Knob for the
    /// zero-window-persist test.
    advertised_window: u16,
    received: Vec<u8>,

    handshake_done: bool,
    our_fin_sent: bool,
    our_fin_seq: u32,
    our_fin_acked: bool,
    their_fin_received: bool,

    ip_id: u16,
    now_ms: u64,
    /// Indices of outbound packets to suppress (simulated loss).
    drop_indices: Vec<usize>,
    out_count: usize,
}

impl TestPeer {
    fn new() -> Self {
        Self {
            snd_nxt: SERVER_ISS,
            snd_una: SERVER_ISS,
            rcv_nxt: 0,
            peer_mss: 536,
            ts_enabled: false,
            ts_recent: 0,
            advertised_window: 65_535,
            received: Vec::new(),
            handshake_done: false,
            our_fin_sent: false,
            our_fin_seq: 0,
            our_fin_acked: false,
            their_fin_received: false,
            ip_id: 0,
            now_ms: 0,
            drop_indices: Vec::new(),
            out_count: 0,
        }
    }

    fn is_open(&self) -> bool {
        self.handshake_done && !self.is_fully_closed()
    }

    fn is_fully_closed(&self) -> bool {
        self.our_fin_sent && self.our_fin_acked && self.their_fin_received
    }

    fn ts_val(&self) -> u32 {
        self.now_ms as u32
    }

    fn data_options(&self) -> TcpOptions {
        if self.ts_enabled {
            TcpOptions {
                mss: None,
                ts: Some((self.ts_val(), self.ts_recent)),
                ..TcpOptions::NONE
            }
        } else {
            TcpOptions::NONE
        }
    }

    fn emit(
        &mut self,
        flag_bits: u8,
        seq: u32,
        ack: u32,
        opts: &TcpOptions,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; MAX_PACKET];
        let n = wire::emit(
            &mut buf,
            SERVER_IP,
            CLIENT_IP,
            SERVER_PORT,
            CLIENT_PORT,
            seq,
            ack,
            flag_bits,
            self.advertised_window,
            opts,
            payload,
            self.ip_id,
            wire::ecn::NOT_ECT,
        )
        .expect("peer emit");
        self.ip_id = self.ip_id.wrapping_add(1);
        buf.truncate(n);

        let idx = self.out_count;
        self.out_count += 1;
        if self.drop_indices.contains(&idx) {
            return None;
        }
        Some(buf)
    }

    fn handle(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        let seg = match wire::parse(packet) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        if let Some((tsval, _)) = seg.options.ts {
            self.ts_recent = tsval;
        }
        let mut out = Vec::new();

        // ---- Handshake (Listen → SYN-ACK) -------------------------------
        if !self.handshake_done {
            if seg.has(flags::SYN) && !seg.has(flags::ACK) {
                if let Some(mss) = seg.options.mss {
                    self.peer_mss = mss;
                }
                if seg.options.ts.is_some() {
                    self.ts_enabled = true;
                }
                self.rcv_nxt = seg.seq.wrapping_add(1);
                self.snd_una = self.snd_nxt;
                let opts = TcpOptions {
                    mss: Some(1460),
                    ts: if self.ts_enabled {
                        Some((self.ts_val(), self.ts_recent))
                    } else {
                        None
                    },
                    ..TcpOptions::NONE
                };
                if let Some(p) = self.emit(
                    flags::SYN | flags::ACK,
                    self.snd_nxt,
                    self.rcv_nxt,
                    &opts,
                    &[],
                ) {
                    out.push(p);
                }
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.handshake_done = true;
            }
            return out;
        }

        if self.is_fully_closed() {
            return out;
        }

        // ---- ACK processing ---------------------------------------------
        if seg.has(flags::ACK) {
            let ack = seg.ack;
            if !seq_gt(ack, self.snd_nxt) && seq_ge(ack, self.snd_una) {
                self.snd_una = ack;
            }
            if self.our_fin_sent && !self.our_fin_acked && seq_gt(self.snd_una, self.our_fin_seq) {
                self.our_fin_acked = true;
            }
        }

        // ---- Data --------------------------------------------------------
        if !seg.payload.is_empty() && !self.their_fin_received {
            if seg.seq == self.rcv_nxt {
                self.received.extend_from_slice(seg.payload);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                let opts = self.data_options();
                if let Some(p) = self.emit(flags::ACK, self.snd_nxt, self.rcv_nxt, &opts, &[]) {
                    out.push(p);
                }
            } else {
                // Out-of-order: emit dup-ACK at current rcv_nxt so the client
                // can fast-retransmit.
                let opts = self.data_options();
                if let Some(p) = self.emit(flags::ACK, self.snd_nxt, self.rcv_nxt, &opts, &[]) {
                    out.push(p);
                }
            }
        }

        // ---- FIN --------------------------------------------------------
        if seg.has(flags::FIN) && !self.their_fin_received {
            let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
            if fin_seq == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.their_fin_received = true;
                let opts = self.data_options();
                if let Some(p) = self.emit(flags::ACK, self.snd_nxt, self.rcv_nxt, &opts, &[]) {
                    out.push(p);
                }
            } else {
                // FIN ahead of in-order data → dup-ACK.
                let opts = self.data_options();
                if let Some(p) = self.emit(flags::ACK, self.snd_nxt, self.rcv_nxt, &opts, &[]) {
                    out.push(p);
                }
            }
        }
        out
    }

    fn send_data(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if !self.is_open() || self.our_fin_sent {
            return None;
        }
        let seq = self.snd_nxt;
        let opts = self.data_options();
        let pkt = self.emit(flags::ACK | flags::PSH, seq, self.rcv_nxt, &opts, data);
        self.snd_nxt = self.snd_nxt.wrapping_add(data.len() as u32);
        pkt
    }

    fn close(&mut self) -> Option<Vec<u8>> {
        if !self.is_open() || self.our_fin_sent {
            return None;
        }
        self.our_fin_seq = self.snd_nxt;
        self.our_fin_sent = true;
        let opts = self.data_options();
        let pkt = self.emit(
            flags::FIN | flags::ACK,
            self.snd_nxt,
            self.rcv_nxt,
            &opts,
            &[],
        );
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        pkt
    }
}

#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
#[inline]
fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

// ---------------------------------------------------------------------------
// Pump helpers
// ---------------------------------------------------------------------------

fn drain_client(client: &mut Tcb, now_ms: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; MAX_PACKET];
    loop {
        client.set_now(now_ms);
        client.tick().expect("tick");
        let n = client.extract_packet(&mut buf).expect("extract");
        if n == 0 {
            break;
        }
        let slice = buf.get(..n).expect("range");
        out.push(slice.to_vec());
    }
    out
}

fn make_client() -> Tcb {
    let cfg = TcbConfig {
        local: Endpoint {
            ip: CLIENT_IP,
            port: CLIENT_PORT,
        },
        remote: Endpoint {
            ip: SERVER_IP,
            port: SERVER_PORT,
        },
        iss: CLIENT_ISS,
        initial_rto_ms: 1000,
    };
    Tcb::new(cfg).expect("tcb")
}

fn handshake(client: &mut Tcb, peer: &mut TestPeer, now: &mut u64) {
    client.set_now(*now);
    client.connect().expect("connect");

    let pkts = drain_client(client, *now);
    assert_eq!(pkts.len(), 1, "exactly one SYN expected");
    *now += 5;
    peer.now_ms = *now;
    let syn_ack = peer.handle(&pkts[0]);
    assert_eq!(syn_ack.len(), 1);

    *now += 5;
    client.set_now(*now);
    client.inject_packet(&syn_ack[0]).expect("inject SYN-ACK");
    let pkts = drain_client(client, *now);
    assert_eq!(pkts.len(), 1, "exactly one ACK after SYN-ACK");
    let _ = peer.handle(&pkts[0]);

    assert_eq!(client.state(), State::Established);
    assert!(peer.handshake_done);
}

// ---------------------------------------------------------------------------
// Existing baseline tests
// ---------------------------------------------------------------------------

#[test]
fn handshake_completes_and_negotiates_options() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;

    handshake(&mut client, &mut peer, &mut now);

    assert!(peer.ts_enabled, "peer should see client's TS option");
    assert_eq!(peer.peer_mss, 1460);
    assert!(client.poll() & events::ESTABLISHED != 0);
    assert!(client.poll() & events::WRITABLE != 0);
}

#[test]
fn client_sends_request_peer_sends_response() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let n = client.send(req).expect("send");
    assert_eq!(n, req.len());
    now += 1;
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1);
    now += 1;
    peer.now_ms = now;
    let acks = peer.handle(&pkts[0]);
    assert_eq!(acks.len(), 1);
    assert_eq!(peer.received, req);

    now += 1;
    client.set_now(now);
    client.inject_packet(&acks[0]).expect("inject ack");
    assert!(client.poll() & events::TX_PENDING == 0);

    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    now += 1;
    peer.now_ms = now;
    let pkt = peer.send_data(resp).expect("peer send");
    now += 1;
    client.set_now(now);
    client.inject_packet(&pkt).expect("inject resp");

    let mut got = vec![0u8; 256];
    let read = client.recv(&mut got).expect("recv");
    assert_eq!(read, resp.len());
    let read_slice = got.get(..read).expect("slice");
    assert_eq!(read_slice, resp);
}

#[test]
fn active_close_from_client() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    client.set_now(now);
    client.close().expect("close");
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1);
    assert_eq!(client.state(), State::FinWait1);

    now += 5;
    peer.now_ms = now;
    let acks = peer.handle(&pkts[0]);
    assert_eq!(acks.len(), 1);
    now += 1;
    client.set_now(now);
    client.inject_packet(&acks[0]).expect("inject ack-of-fin");
    assert_eq!(client.state(), State::FinWait2);

    now += 5;
    peer.now_ms = now;
    let peer_fin = peer.close().expect("peer close");
    now += 1;
    client.set_now(now);
    client.inject_packet(&peer_fin).expect("inject peer fin");
    assert_eq!(client.state(), State::TimeWait);

    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1);
    let _ = peer.handle(&pkts[0]);
    assert!(peer.is_fully_closed());

    now += 60_001;
    client.set_now(now);
    client.tick().expect("tick");
    assert_eq!(client.state(), State::Closed);
}

#[test]
fn passive_close_then_local_close() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    now += 1;
    peer.now_ms = now;
    let peer_fin = peer.close().expect("peer close");
    now += 1;
    client.set_now(now);
    client.inject_packet(&peer_fin).expect("inject");
    assert_eq!(client.state(), State::CloseWait);

    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1);
    let _ = peer.handle(&pkts[0]);
    assert!(peer.our_fin_acked);
    assert!(!peer.their_fin_received);

    now += 1;
    client.set_now(now);
    client.close().expect("close");
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1);
    assert_eq!(client.state(), State::LastAck);

    now += 1;
    peer.now_ms = now;
    let acks = peer.handle(&pkts[0]);
    assert!(peer.is_fully_closed());
    assert_eq!(acks.len(), 1);
    now += 1;
    client.set_now(now);
    client.inject_packet(&acks[0]).expect("inject");
    assert_eq!(client.state(), State::Closed);
}

#[test]
fn rto_retransmit_drops_cwnd() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    peer.drop_indices.push(peer.out_count);

    let req = b"hello";
    client.send(req).expect("send");
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1);
    now += 1;
    peer.now_ms = now;
    let acks = peer.handle(&pkts[0]);
    assert!(acks.is_empty(), "peer's ACK was dropped");
    assert_eq!(peer.received, req);

    peer.received.clear();
    peer.rcv_nxt = peer.rcv_nxt.wrapping_sub(req.len() as u32);

    now += 2_000;
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1, "expected one retransmit");
    now += 1;
    peer.now_ms = now;
    let acks = peer.handle(&pkts[0]);
    assert_eq!(acks.len(), 1);
    assert_eq!(peer.received, req);
    now += 1;
    client.set_now(now);
    client.inject_packet(&acks[0]).expect("inject");

    client.send(b"again").expect("send2");
    now += 1;
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1);
    now += 1;
    peer.now_ms = now;
    let _ = peer.handle(&pkts[0]);
    assert!(peer.received.ends_with(b"again"));
}

#[test]
fn bulk_transfer_round_trip() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    let total = 32 * 1024;
    let payload: Vec<u8> = (0..total).map(|i| (i as u8).wrapping_mul(31)).collect();
    let mut sent = 0usize;
    while sent < payload.len() {
        let chunk = payload.get(sent..).expect("range");
        let n = client.send(chunk).expect("send");
        sent += n;
        if n == 0 {
            break;
        }
    }
    assert_eq!(sent, payload.len());

    let mut iters = 0usize;
    while peer.received.len() < payload.len() && iters < 1000 {
        iters += 1;
        now += 1;
        let pkts = drain_client(&mut client, now);
        if pkts.is_empty() {
            now += 50;
            continue;
        }
        for pkt in &pkts {
            now += 1;
            peer.now_ms = now;
            let acks = peer.handle(pkt);
            for a in acks {
                now += 1;
                client.set_now(now);
                client.inject_packet(&a).expect("inject ack");
            }
        }
    }
    assert!(iters < 1000, "did not converge in 1000 iters");
    assert_eq!(peer.received.len(), payload.len());
    assert_eq!(peer.received, payload);
}

#[test]
fn rejects_ip_fragment() {
    let mut peer = TestPeer::new();
    peer.handshake_done = true;
    peer.ts_enabled = true;
    peer.rcv_nxt = CLIENT_ISS.wrapping_add(1);
    let mut buf = vec![0u8; MAX_PACKET];
    let n = wire::emit(
        &mut buf,
        SERVER_IP,
        CLIENT_IP,
        SERVER_PORT,
        CLIENT_PORT,
        SERVER_ISS,
        CLIENT_ISS.wrapping_add(1),
        flags::ACK,
        65_535,
        &TcpOptions::NONE,
        &[],
        0,
        wire::ecn::NOT_ECT,
    )
    .expect("emit");
    buf.truncate(n);
    let b = buf.get_mut(6).expect("ip flags byte");
    *b |= 0x20;
    let ip = buf.get_mut(..20).expect("ip hdr");
    ip[10] = 0;
    ip[11] = 0;
    let csum = ones_complement_csum(ip);
    ip[10] = (csum >> 8) as u8;
    ip[11] = csum as u8;

    let mut client = make_client();
    client.set_now(0);
    client.connect().expect("connect");
    let _ = drain_client(&mut client, 0);
    let err = client.inject_packet(&buf).unwrap_err();
    assert_eq!(err, TcpError::MalformedPacket);
}

fn ones_complement_csum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let hi = *data.get(i).expect("hi") as u32;
        let lo = *data.get(i + 1).expect("lo") as u32;
        sum = sum.wrapping_add((hi << 8) | lo);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((*data.get(i).expect("byte") as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ===========================================================================
// Harder tests
// ===========================================================================

/// Three duplicate ACKs of `snd_una` should fire a fast-retransmit loss
/// event under PRR (RFC 6937): `ssthresh = max(FlightSize/2, 2*MSS)`,
/// `snd_nxt → snd_una`, immediate retransmit of one MSS. (Cwnd is NOT
/// collapsed to 1*MSS — that was the old Tahoe behavior, replaced by
/// PRR-SSRB pacing.)
#[test]
fn three_dup_acks_trigger_tahoe_fast_retransmit() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    // Send a chunk; the client emits one segment under cwnd=1MSS.
    client.send(b"first segment of data").expect("send");
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1);
    let original = wire::parse(&pkts[0]).expect("parse");
    let snd_una = original.seq; // == client.snd_una before this send

    // Hand-craft three identical pure ACKs of snd_una. Peer's snd_nxt is
    // SERVER_ISS+1 after the handshake.
    let mut dups: Vec<Vec<u8>> = Vec::new();
    for _ in 0..3 {
        peer.now_ms = now;
        let opts = peer.data_options();
        let p = peer
            .emit(flags::ACK, peer.snd_nxt, snd_una, &opts, &[])
            .expect("emit dup");
        dups.push(p);
    }

    now += 1;
    client.set_now(now);
    client.inject_packet(&dups[0]).expect("d1");
    let mid = drain_client(&mut client, now);
    assert!(mid.is_empty(), "no retransmit after 1st dup-ACK");

    client.inject_packet(&dups[1]).expect("d2");
    let mid = drain_client(&mut client, now);
    assert!(mid.is_empty(), "no retransmit after 2nd dup-ACK");

    client.inject_packet(&dups[2]).expect("d3");
    let after = drain_client(&mut client, now);
    assert_eq!(after.len(), 1, "expected fast retransmit after 3rd dup-ACK");
    let retx = wire::parse(&after[0]).expect("parse retx");
    assert_eq!(
        retx.seq, snd_una,
        "retransmission should start at snd_una, not snd_nxt"
    );
    assert_eq!(retx.payload, original.payload);
}

/// Client and peer both call `close()` before either side's FIN arrives.
/// Client must transit `FinWait1 → Closing → TimeWait → Closed`.
#[test]
fn simultaneous_close_via_closing_state() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    // Client closes; emits FIN.
    client.set_now(now);
    client.close().expect("close");
    let client_pkts = drain_client(&mut client, now);
    assert_eq!(client_pkts.len(), 1);
    assert_eq!(client.state(), State::FinWait1);

    // Before delivering client's FIN, peer also closes.
    now += 1;
    peer.now_ms = now;
    let peer_fin = peer.close().expect("peer close");

    // Client receives peer's FIN → Closing.
    now += 1;
    client.set_now(now);
    client.inject_packet(&peer_fin).expect("inject peer fin");
    assert_eq!(client.state(), State::Closing);

    // Client emits ACK of peer's FIN.
    let client_acks = drain_client(&mut client, now);
    assert_eq!(client_acks.len(), 1);

    // Peer receives client's FIN → ACKs it.
    now += 1;
    peer.now_ms = now;
    let peer_acks = peer.handle(&client_pkts[0]);
    assert_eq!(peer_acks.len(), 1);
    // And processes our ACK of its FIN.
    let _ = peer.handle(&client_acks[0]);
    assert!(peer.is_fully_closed());

    // Inject peer's ACK of our FIN; client → TimeWait.
    now += 1;
    client.set_now(now);
    client.inject_packet(&peer_acks[0]).expect("inject ack");
    assert_eq!(client.state(), State::TimeWait);

    // 2*MSL later → Closed.
    now += 60_001;
    client.set_now(now);
    client.tick().expect("tick");
    assert_eq!(client.state(), State::Closed);
}

/// Peer advertises `window=0`; client should arm the persist timer, fire a
/// 1-byte probe at the deadline, then resume sending after the window opens.
#[test]
fn zero_window_persist_probes() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    peer.advertised_window = 0; // closed window from the start
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    client.send(b"data").expect("send");

    // No data should leave while snd_wnd == 0.
    let pkts = drain_client(&mut client, now);
    assert!(pkts.is_empty(), "must not send when window=0");

    // Advance past the persist deadline (≈ rto_ms ≈ 1s default).
    now += 2_000;
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1, "expected zero-window probe");
    let probe = wire::parse(&pkts[0]).expect("parse probe");
    assert_eq!(probe.payload.len(), 1, "probe should be exactly 1 byte");

    // Open the window: peer ACKs the probe with a non-zero window.
    peer.advertised_window = 4_096;
    now += 1;
    peer.now_ms = now;
    let acks = peer.handle(&pkts[0]);
    assert_eq!(acks.len(), 1);
    now += 1;
    client.set_now(now);
    client
        .inject_packet(&acks[0])
        .expect("inject window update");

    // Remaining 3 bytes should now flow.
    now += 1;
    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1, "remaining bytes after window opens");
    let parsed = wire::parse(&pkts[0]).expect("parse data");
    assert_eq!(parsed.payload.len(), 3);
    now += 1;
    peer.now_ms = now;
    let _ = peer.handle(&pkts[0]);
    assert_eq!(peer.received, b"data");
}

/// In-window but out-of-order data must produce an immediate duplicate
/// ACK (RFC 5681 §3.2). The bytes themselves are buffered in the
/// single-hole reassembly queue and delivered atomically when the gap
/// closes — i.e. the sender doesn't have to retransmit data we already
/// have.
#[test]
fn out_of_order_segment_is_buffered_and_delivered_after_gap_fills() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    // Three contiguous segments: A, B, C. We deliver them out of order:
    // C first (creates the held run), then B (extends the held run back),
    // then A (closes the gap; everything drains atomically).
    let a = b"AAAAA";
    let b = b"BBBBB";
    let c = b"CCCCC";
    let seq_a = peer.snd_nxt;
    let seq_b = seq_a.wrapping_add(a.len() as u32);
    let seq_c = seq_b.wrapping_add(b.len() as u32);

    // ---- Inject C (OOO) ---------------------------------------------------
    let opts = peer.data_options();
    peer.now_ms = now;
    let pkt_c = peer
        .emit(flags::ACK | flags::PSH, seq_c, peer.rcv_nxt, &opts, c)
        .expect("emit C");
    now += 1;
    client.set_now(now);
    client.inject_packet(&pkt_c).expect("inject C");

    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1, "OOO C must elicit a dup-ACK");
    let parsed = wire::parse(&pkts[0]).expect("parse");
    assert_eq!(parsed.ack, seq_a, "dup-ACK keeps ack at rcv_nxt");
    assert_eq!(parsed.payload.len(), 0);

    let mut rbuf = [0u8; 32];
    assert_eq!(
        client.recv(&mut rbuf).expect("recv"),
        0,
        "C is held in reassembly, not yet delivered"
    );

    // ---- Inject B (still OOO, but abuts the held run on the front) -------
    let opts = peer.data_options();
    let pkt_b = peer
        .emit(flags::ACK | flags::PSH, seq_b, peer.rcv_nxt, &opts, b)
        .expect("emit B");
    now += 1;
    client.set_now(now);
    client.inject_packet(&pkt_b).expect("inject B");

    let pkts = drain_client(&mut client, now);
    assert_eq!(pkts.len(), 1, "still OOO → another dup-ACK");
    let parsed = wire::parse(&pkts[0]).expect("parse");
    assert_eq!(parsed.ack, seq_a);

    assert_eq!(
        client.recv(&mut rbuf).expect("recv"),
        0,
        "B+C still held, gap to A not yet closed"
    );

    // ---- Inject A (gap-filler) → expect B and C delivered atomically -----
    let opts = peer.data_options();
    let pkt_a = peer
        .emit(flags::ACK | flags::PSH, seq_a, peer.rcv_nxt, &opts, a)
        .expect("emit A");
    now += 1;
    client.set_now(now);
    client.inject_packet(&pkt_a).expect("inject A");

    // Cumulative ACK must now cover the whole run.
    let pkts = drain_client(&mut client, now);
    let last = pkts.last().expect("at least one ACK");
    let parsed = wire::parse(last).expect("parse");
    assert_eq!(
        parsed.ack,
        seq_c.wrapping_add(c.len() as u32),
        "cumulative ACK must cover A+B+C"
    );

    let n = client.recv(&mut rbuf).expect("recv");
    assert_eq!(
        n,
        a.len() + b.len() + c.len(),
        "all three segments delivered"
    );
    let s = rbuf.get(..n).expect("range");
    assert_eq!(&s[..a.len()], a);
    assert_eq!(&s[a.len()..a.len() + b.len()], b);
    assert_eq!(&s[a.len() + b.len()..], c);
}

/// A peer-sent RST aborts the connection: `Closed`, errors surface to recv.
#[test]
fn rst_aborts_connection() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    let opts = peer.data_options();
    peer.now_ms = now;
    let rst = peer
        .emit(
            flags::RST | flags::ACK,
            peer.snd_nxt,
            peer.rcv_nxt,
            &opts,
            &[],
        )
        .expect("emit RST");

    now += 1;
    client.set_now(now);
    client.inject_packet(&rst).expect("inject RST");

    assert_eq!(client.state(), State::Closed);
    assert!(client.poll() & events::ERROR != 0);

    let mut buf = [0u8; 16];
    let err = client.recv(&mut buf).unwrap_err();
    assert_eq!(err, TcpError::ConnectionReset);
}

/// 32 KiB transfer with a couple of mid-stream packet drops on the
/// client-to-peer path. Recovery may go via fast-retransmit or RTO; either
/// way the bytes must arrive intact.
#[test]
fn bulk_transfer_with_loss_recovers() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    let total = 32 * 1024;
    let payload: Vec<u8> = (0..total).map(|i| (i as u8).wrapping_mul(53)).collect();
    let mut sent = 0usize;
    while sent < payload.len() {
        let chunk = payload.get(sent..).expect("range");
        let n = client.send(chunk).expect("send");
        sent += n;
        if n == 0 {
            break;
        }
    }
    assert_eq!(sent, payload.len());

    // Drop a sparse handful of segments on the client→peer wire. Indices
    // count outbound client segments only.
    let drops: [usize; 3] = [4, 11, 23];
    let mut client_tx_idx = 0usize;

    let mut iters = 0usize;
    while peer.received.len() < payload.len() && iters < 5_000 {
        iters += 1;
        now += 1;
        let pkts = drain_client(&mut client, now);
        if pkts.is_empty() {
            // Maybe waiting for RTO. Advance a real chunk of time.
            now += 100;
            continue;
        }
        for pkt in &pkts {
            let idx = client_tx_idx;
            client_tx_idx += 1;
            if drops.contains(&idx) {
                continue; // simulated loss
            }
            now += 1;
            peer.now_ms = now;
            let acks = peer.handle(pkt);
            for a in acks {
                now += 1;
                client.set_now(now);
                client.inject_packet(&a).expect("inject ack");
            }
        }
    }
    assert!(iters < 5_000, "lossy bulk transfer did not converge");
    assert_eq!(peer.received.len(), payload.len());
    assert_eq!(peer.received, payload);
}

/// 256 KiB transfer with deterministic-pseudorandom 1% packet loss in the
/// client→peer direction. Mirrors what the gVisor chaos test exercises
/// for the OUTBOUND direction. If this wedges, RTO recovery is broken.
#[test]
fn bulk_transfer_with_random_1pct_loss_recovers() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    let total = 256 * 1024;
    let payload: Vec<u8> = (0..total).map(|i| (i as u8).wrapping_mul(53)).collect();

    // xorshift64* — tiny deterministic PRNG, no external deps.
    let mut rng_state: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let mut rand_pct = || -> u32 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        (rng_state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32 % 100
    };

    let mut sent = 0usize;
    let mut iters = 0usize;
    let mut wallclock_idle = 0usize;
    let max_iters = 200_000;
    while peer.received.len() < payload.len() && iters < max_iters {
        iters += 1;

        // Refill the send ring whenever the app-side has more to push.
        while sent < payload.len() {
            let chunk = payload.get(sent..).expect("range");
            match client.send(chunk) {
                Ok(0) => break,
                Ok(n) => sent += n,
                Err(TcpError::WouldBlock) => break,
                Err(e) => panic!("send: {e:?}"),
            }
        }

        now += 1;
        let pkts = drain_client(&mut client, now);
        if pkts.is_empty() {
            wallclock_idle += 1;
            // Advance time so RTO can fire. RTO_MIN_MS = 200.
            now += 50;
            continue;
        }
        wallclock_idle = 0;

        for pkt in &pkts {
            // 1% drop probability on the client→peer path.
            if rand_pct() < 1 {
                continue;
            }
            now += 1;
            peer.now_ms = now;
            let acks = peer.handle(pkt);
            for a in acks {
                now += 1;
                client.set_now(now);
                client.inject_packet(&a).expect("inject ack");
            }
        }
    }
    assert!(
        iters < max_iters,
        "wedged: sent={} received={}/{} iters={} idle={}",
        sent,
        peer.received.len(),
        payload.len(),
        iters,
        wallclock_idle,
    );
    assert_eq!(peer.received.len(), payload.len());
    assert_eq!(peer.received, payload);
}

/// Bidirectional bulk transfer (client→peer 64 KiB and peer→client 64 KiB)
/// with deterministic-pseudorandom 1% drops on the client→peer direction.
/// This stresses RTO recovery on the cdylib's send side while it's also
/// receiving and ACKing peer-originated data — same shape as the gVisor
/// chaos test's outbound channel.
#[test]
fn bidirectional_bulk_with_outbound_loss_recovers() {
    let mut client = make_client();
    let mut peer = TestPeer::new();
    let mut now = 1_000u64;
    handshake(&mut client, &mut peer, &mut now);

    let total = 64 * 1024;
    let cli_payload: Vec<u8> = (0..total).map(|i| (i as u8).wrapping_mul(53)).collect();
    let srv_payload: Vec<u8> = (0..total).map(|i| (i as u8).wrapping_mul(31)).collect();

    let mut rng_state: u64 = 0xCAFE_BEEF_DEAD_F00D;
    let mut rand_pct = || -> u32 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        (rng_state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32 % 100
    };

    let mut cli_sent = 0usize;
    let mut srv_sent = 0usize;
    let mut cli_received_from_peer: Vec<u8> = Vec::with_capacity(total);
    let mut iters = 0usize;
    let max_iters = 200_000;

    while (peer.received.len() < cli_payload.len()
        || cli_received_from_peer.len() < srv_payload.len())
        && iters < max_iters
    {
        iters += 1;

        // App pushes more outbound bytes when ring has space.
        while cli_sent < cli_payload.len() {
            let chunk = cli_payload.get(cli_sent..).expect("range");
            match client.send(chunk) {
                Ok(0) => break,
                Ok(n) => cli_sent += n,
                Err(TcpError::WouldBlock) => break,
                Err(e) => panic!("send: {e:?}"),
            }
        }

        // App pulls inbound bytes.
        let mut rbuf = [0u8; 4096];
        loop {
            match client.recv(&mut rbuf) {
                Ok(0) => break,
                Ok(n) => cli_received_from_peer.extend_from_slice(rbuf.get(..n).expect("range")),
                Err(TcpError::ConnectionClosed) => break,
                Err(e) => panic!("recv: {e:?}"),
            }
        }

        now += 1;
        let pkts = drain_client(&mut client, now);

        if pkts.is_empty() && srv_sent >= srv_payload.len() {
            // Idle: maybe waiting for RTO. Advance time so RTO can fire.
            now += 50;
            continue;
        }

        for pkt in &pkts {
            // 1% drop on client→peer.
            if rand_pct() < 1 {
                continue;
            }
            now += 1;
            peer.now_ms = now;
            let acks = peer.handle(pkt);
            for a in acks {
                now += 1;
                client.set_now(now);
                client.inject_packet(&a).expect("inject ack");
            }
        }

        // Peer also pushes its bulk stream when its app has more.
        if srv_sent < srv_payload.len() {
            let take = core::cmp::min(536, srv_payload.len() - srv_sent);
            let chunk = srv_payload.get(srv_sent..srv_sent + take).expect("range");
            if let Some(p) = peer.send_data(chunk) {
                srv_sent += take;
                now += 1;
                client.set_now(now);
                client.inject_packet(&p).expect("inject peer data");
            } else {
                // peer.send_data should have returned Some unless conn closed.
                srv_sent += take;
            }
        }
    }
    assert!(
        iters < max_iters,
        "wedged: cli_sent={} peer_recv={}/{} srv_sent={} cli_recv={}/{} iters={}",
        cli_sent,
        peer.received.len(),
        cli_payload.len(),
        srv_sent,
        cli_received_from_peer.len(),
        srv_payload.len(),
        iters,
    );
    assert_eq!(peer.received, cli_payload);
    assert_eq!(cli_received_from_peer, srv_payload);
}
