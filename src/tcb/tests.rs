//! Internal TCB regression tests (timers, lifecycle, invariants).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::boxed::Box;
use std::vec::Vec;

use super::{events, Endpoint, Tcb, TcbConfig, MAX_RETRANSMITS, MAX_SYN_RETRIES};
use crate::wire::{self, flags, SackBlocks, TcpOptions};
use crate::{State, TcpError, MAX_PACKET};

const PEER_ISS: u32 = 7_000_000;

fn cfg(iss: u32) -> TcbConfig {
    TcbConfig {
        local: Endpoint {
            ip: [10, 0, 0, 1],
            port: 49152,
        },
        remote: Endpoint {
            ip: [10, 0, 0, 2],
            port: 80,
        },
        iss,
        initial_rto_ms: 1000,
    }
}

fn peer_pkt(seq: u32, ack: u32, fl: u8, win: u16, opts: &TcpOptions, payload: &[u8]) -> Vec<u8> {
    let mut b = std::vec![0u8; MAX_PACKET + payload.len()];
    let n = wire::emit(
        &mut b,
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        80,
        49152,
        seq,
        ack,
        fl,
        win,
        opts,
        payload,
        1,
        wire::ecn::NOT_ECT,
    )
    .unwrap();
    b.truncate(n);
    b
}

fn drain(t: &mut Tcb) -> Vec<(u32, u32, u8, usize)> {
    let mut out = Vec::new();
    let mut buf = [0u8; MAX_PACKET];
    while let Ok(n) = t.extract_packet(&mut buf) {
        if n == 0 {
            break;
        }
        let s = wire::parse(&buf[..n]).unwrap();
        out.push((s.seq, s.ack, s.flags, s.payload.len()));
    }
    out
}

/// Established client (no timestamps/SACK, so packets are easy to script).
fn established() -> Box<Tcb> {
    established_with(|_| {})
}

/// [`established`], with `setup` applied before the TCB connects.
fn established_with(setup: impl FnOnce(&mut Tcb)) -> Box<Tcb> {
    let mut t = Box::new(Tcb::new(cfg(1000)).unwrap());
    setup(&mut t);
    t.set_now(0);
    t.connect().unwrap();
    drain(&mut t);
    let o = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    t.set_now(10);
    t.inject_packet(&peer_pkt(
        PEER_ISS,
        1001,
        flags::SYN | flags::ACK,
        65535,
        &o,
        &[],
    ))
    .unwrap();
    drain(&mut t);
    assert_eq!(t.state(), State::Established);
    t
}

fn ack(t: &mut Tcb, ack: u32, win: u16) {
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        ack,
        flags::ACK,
        win,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
}

/// Fire armed timers until `pred` holds or `max` timer events pass.
fn run_timers(t: &mut Tcb, max: usize, pred: impl Fn(&Tcb) -> bool) -> usize {
    for i in 0..max {
        if pred(t) {
            return i;
        }
        let Some(d) = t.debug_next_deadline().or(t.time_wait_deadline.get()) else {
            return i;
        };
        t.set_now(d.max(t.now_ms) + 1);
        t.tick().unwrap();
        drain(t);
    }
    max
}

#[test]
fn init_in_place_over_garbage_matches_new() {
    use core::mem::MaybeUninit;
    let mut slot: Box<MaybeUninit<Tcb>> = Box::new_uninit();
    // SAFETY: scribble garbage over the storage first; init must not rely on it.
    unsafe {
        core::ptr::write_bytes(
            slot.as_mut_ptr().cast::<u8>(),
            0xA5,
            core::mem::size_of::<Tcb>(),
        );
        Tcb::init_in_place(slot.as_mut_ptr(), cfg(1000)).unwrap();
    }
    // SAFETY: fully initialised above.
    let mut a = unsafe { slot.assume_init() };
    let mut b = Box::new(Tcb::new(cfg(1000)).unwrap());
    for t in [&mut a, &mut b] {
        t.set_now(5);
        t.connect().unwrap();
    }
    let mut pa = [0u8; MAX_PACKET];
    let mut pb = [0u8; MAX_PACKET];
    let na = a.extract_packet(&mut pa).unwrap();
    let nb = b.extract_packet(&mut pb).unwrap();
    assert_eq!(
        &pa[..na],
        &pb[..nb],
        "in-place init must produce an identical SYN"
    );
    assert_eq!(a.stats(), b.stats());
    a.debug_validate_invariants().unwrap();
}

#[test]
fn r2_aborts_after_max_retransmits_without_ack() {
    let mut t = established();
    t.set_user_timeout(0); // isolate R2 from USER TIMEOUT
    t.send(&[0xAB; 1000]).unwrap();
    t.tick().unwrap();
    drain(&mut t);
    run_timers(&mut t, 100, |t| t.state() == State::Closed);
    assert_eq!(t.state(), State::Closed);
    assert_eq!(t.error, Some(TcpError::ConnectionReset));
    assert_eq!(t.stats.rto_count, u32::from(MAX_RETRANSMITS));
}

#[test]
fn r2_counter_resets_on_ack_progress() {
    let mut t = established();
    t.set_user_timeout(0);
    t.send(&[0xAB; 4000]).unwrap();
    t.tick().unwrap();
    drain(&mut t);
    run_timers(&mut t, usize::from(MAX_RETRANSMITS) - 2, |_| false);
    assert!(t.rtx_count > 0);
    ack(&mut t, 1001 + 1460, 65535);
    assert_eq!(t.rtx_count, 0, "proof of life resets R2");
    assert_eq!(t.state(), State::Established);
}

#[test]
fn syn_sent_gives_up_after_syn_retries() {
    let mut t = Box::new(Tcb::new(cfg(1000)).unwrap());
    t.set_now(0);
    t.connect().unwrap();
    drain(&mut t);
    run_timers(&mut t, 50, |t| t.state() == State::Closed);
    assert_eq!(t.state(), State::Closed);
    assert_eq!(t.error, Some(TcpError::ConnectionReset));
    assert_eq!(t.stats.segs_out, u64::from(MAX_SYN_RETRIES) + 1);
}

#[test]
fn silent_peer_during_close_is_aborted() {
    let mut t = established();
    t.set_user_timeout(0);
    t.close().unwrap();
    assert_eq!(t.state(), State::FinWait1);
    run_timers(&mut t, 100, |t| t.state() == State::Closed);
    assert_eq!(t.state(), State::Closed);
}

#[test]
fn lost_fin_is_retransmitted() {
    let mut t = established();
    t.close().unwrap();
    let fin = drain(&mut t);
    assert_eq!(fin.len(), 1);
    assert!(fin[0].2 & flags::FIN != 0);
    // The FIN is lost; the next timer event must resend it at the same seq.
    t.set_now(t.debug_next_deadline().unwrap() + 1);
    t.tick().unwrap();
    let again = drain(&mut t);
    assert!(again
        .iter()
        .any(|p| p.2 & flags::FIN != 0 && p.0 == fin[0].0));
    t.debug_validate_invariants().unwrap();
}

#[test]
fn fin_is_sent_into_a_zero_window() {
    let mut t = established();
    ack(&mut t, 1001, 0);
    t.close().unwrap();
    let out = drain(&mut t);
    assert!(
        out.iter().any(|p| p.2 & flags::FIN != 0),
        "FIN owes no window"
    );
}

#[test]
fn retransmitted_fin_restarts_time_wait() {
    let mut t = established();
    t.close().unwrap();
    drain(&mut t);
    // Peer ACKs our FIN and sends its own.
    t.set_now(100);
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        1002,
        flags::ACK | flags::FIN,
        65535,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(t.state(), State::TimeWait);
    drain(&mut t);
    // 50 s later the peer retransmits its FIN (our ACK was lost).
    t.set_now(50_100);
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        1002,
        flags::ACK | flags::FIN,
        65535,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    let re = drain(&mut t);
    assert_eq!(re.len(), 1, "re-ACK the FIN");
    // A FIN with an unacceptable ACK may be blind injection: it must not
    // restart 2·MSL, which would let a forger pin the TCB indefinitely.
    t.set_now(55_000);
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        1002 + 100_000,
        flags::ACK | flags::FIN,
        65535,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    t.set_now(100 + 60_001);
    t.tick().unwrap();
    assert_eq!(t.state(), State::TimeWait, "2*MSL restarted");
    t.set_now(50_100 + 60_001);
    t.tick().unwrap();
    assert_eq!(t.state(), State::Closed);
}

/// Our FIN ACKed in LAST_ACK used to wipe the receive ring, so bytes the
/// peer sent (and we ACKed) before its FIN vanished and `recv` reported a
/// clean EOF. Neither that nor a RST may drop them: the peer's stream was
/// already complete, exactly as when TIME_WAIT expires.
#[test]
fn unread_data_survives_the_close_from_last_ack() {
    for closing_flag in [flags::ACK, flags::RST] {
        let mut t = established();
        t.set_now(20);
        t.inject_packet(&peer_pkt(
            PEER_ISS + 1,
            1001,
            flags::ACK | flags::FIN,
            65535,
            &TcpOptions::NONE,
            b"unread response",
        ))
        .unwrap();
        t.close().unwrap();
        assert_eq!(t.state(), State::LastAck);
        drain(&mut t);
        t.inject_packet(&peer_pkt(
            PEER_ISS + 17,
            1002,
            closing_flag,
            65535,
            &TcpOptions::NONE,
            &[],
        ))
        .unwrap();
        assert_eq!(t.state(), State::Closed);
        assert_eq!(t.poll() & events::ERROR, 0);
        let mut buf = [0u8; 64];
        assert_eq!(t.recv(&mut buf), Ok(15));
        assert_eq!(&buf[..15], b"unread response");
        assert_eq!(t.recv(&mut buf), Err(TcpError::ConnectionClosed));
    }
}

/// SND.UNA returns to ISS after every 2^32 bytes. A SYN inferred from
/// `SND.UNA == ISS` then shifted every send-ring offset by one: a 4096-byte
/// write went out as 4097 bytes, the wrong ones, and the ACK consumed the
/// queue off by one. Moves 4 GiB through the public API, so release only.
#[test]
#[cfg_attr(debug_assertions, ignore = "moves 4 GiB; run with --release")]
fn data_is_byte_exact_after_snd_una_laps_back_to_iss() {
    let mut t = established();
    let fill = [0x5a_u8; 64 * 1024];
    let mut buf = [0u8; MAX_PACKET];
    // Data starts at ISS + 1, so 2^32 - 1 bytes bring SND.UNA back to ISS.
    let lap = u64::from(u32::MAX);
    let (mut queued, mut now) = (0u64, 10u64);
    while queued < lap || t.snd_una != t.snd_nxt {
        now += 1;
        t.set_now(now);
        let n = (lap - queued).min(fill.len() as u64) as usize;
        if let Ok(w) = t.send(&fill[..n]) {
            queued += w as u64;
        }
        t.tick().unwrap();
        while t.extract_packet(&mut buf).unwrap() != 0 {}
        let nxt = t.snd_nxt;
        ack(&mut t, nxt, 65535);
    }
    assert_eq!((t.snd_una, t.snd_nxt), (t.iss, t.iss), "one full lap");

    let pattern: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(t.send(&pattern), Ok(pattern.len()));
    t.tick().unwrap();
    let mut sent = Vec::new();
    loop {
        let n = t.extract_packet(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        let s = wire::parse(&buf[..n]).unwrap();
        assert_eq!(s.seq, t.iss.wrapping_add(sent.len() as u32));
        sent.extend_from_slice(s.payload);
    }
    assert_eq!(sent, pattern, "the lap must not invent or shift bytes");
    t.debug_validate_invariants().unwrap();
    let end = t.iss.wrapping_add(4096);
    ack(&mut t, end, 65535);
    assert_eq!(
        t.send_ring.len(),
        0,
        "the ACK consumes exactly what was sent"
    );
    t.debug_validate_invariants().unwrap();
}

fn peer_seg(t: &mut Tcb, seq: u32, ack: u32, fl: u8, payload: &[u8]) {
    t.inject_packet(&peer_pkt(
        seq,
        ack,
        flags::ACK | fl,
        65535,
        &TcpOptions::NONE,
        payload,
    ))
    .unwrap();
}

/// RFC 9293 §3.10.7.4 steps 7–8: nothing at or after the peer's FIN is part
/// of its stream. A second FIN used to advance RCV.NXT again, so our ACKs
/// and FIN acknowledged a byte the peer never sent, and in TIME-WAIT its
/// genuine FIN retransmission drew that bogus ACK.
#[test]
fn fin_after_the_peers_fin_is_ignored() {
    let fin = PEER_ISS + 1;
    let mut t = established();
    t.set_now(100);
    peer_seg(&mut t, fin, 1001, flags::FIN, &[]);
    assert_eq!(t.state(), State::CloseWait);
    peer_seg(&mut t, fin + 1, 1001, flags::FIN, &[]);
    assert_eq!(t.rcv_nxt, fin + 1);
    drain(&mut t);
    t.close().unwrap();
    let out = drain(&mut t);
    assert!(out.iter().all(|p| p.1 == fin + 1), "{out:?}");

    let mut t = established();
    t.close().unwrap();
    drain(&mut t);
    t.set_now(100);
    peer_seg(&mut t, fin, 1002, flags::FIN, &[]);
    assert_eq!(t.state(), State::TimeWait);
    peer_seg(&mut t, fin + 1, 1002, flags::FIN, &[]);
    drain(&mut t);
    t.set_now(5_000);
    peer_seg(&mut t, fin, 1002, flags::FIN, &[]); // genuine retransmission
    let re = drain(&mut t);
    assert_eq!(re.len(), 1);
    assert_eq!(re[0].1, fin + 1);
}

/// A retransmitted FIN lies wholly below RCV.NXT, so step 1 rejects it,
/// yet it may carry the only ACK of our FIN. Linux and BSD still process
/// the ACK field of a segment ending at or after the ACK we last sent, so
/// CLOSING and LAST-ACK finish without waiting for our FIN's RTO.
#[test]
fn ack_on_a_retransmitted_fin_is_processed() {
    let fin = PEER_ISS + 1;
    let mut t = established();
    t.close().unwrap();
    drain(&mut t);
    t.set_now(100);
    peer_seg(&mut t, fin, 1001, flags::FIN, &[]); // the FINs cross
    assert_eq!(t.state(), State::Closing);
    drain(&mut t);
    t.set_now(150);
    peer_seg(&mut t, fin, 1002, flags::FIN, &[]);
    assert_eq!(t.state(), State::TimeWait);
    let re = drain(&mut t);
    assert_eq!(re.len(), 1, "the retransmitted FIN is re-ACKed");
    assert_eq!(re[0].1, fin + 1);

    let mut t = established();
    t.set_now(100);
    peer_seg(&mut t, fin, 1001, flags::FIN, &[]);
    t.close().unwrap();
    assert_eq!(t.state(), State::LastAck);
    drain(&mut t);
    t.set_now(150);
    peer_seg(&mut t, fin, 1002, flags::FIN, &[]);
    assert_eq!(t.state(), State::Closed);
}

/// Segments the peer sends in TIME-WAIT are proof of life, so they re-arm
/// the keepalive clock: a FIN it re-sends because our ACK was lost (its ACK
/// field is processed) or a pure ACK. When 2·MSL expires the CLOSED TCB
/// must still report no deadline, or an event-driven host keeps waking for
/// a dead connection.
#[test]
fn time_wait_expiry_leaves_no_timer_after_peer_segments() {
    let fin = PEER_ISS + 1;
    for (seq, fl) in [(fin, flags::FIN), (fin + 1, 0)] {
        let mut t = established();
        t.close().unwrap();
        drain(&mut t);
        t.set_now(100);
        peer_seg(&mut t, fin, 1002, flags::FIN, &[]);
        assert_eq!(t.state(), State::TimeWait);
        drain(&mut t);
        t.set_now(1_000);
        peer_seg(&mut t, seq, 1002, fl, &[]);
        let expiry = t.next_deadline().expect("2*MSL armed");
        t.set_now(expiry);
        t.tick().unwrap();
        assert_eq!(t.state(), State::Closed);
        assert_eq!(t.next_deadline(), None, "flags {fl:#x}");
    }
}

/// RFC 9293 processes segments in SEG.SEQ order, so a FIN held beyond
/// RCV.NXT takes effect only when RCV.NXT reaches it. Data processed ahead
/// of it that covers its sequence number shows it was not the end of the
/// stream (a forged FIN, say), and the FIN is dropped, as Linux drops a
/// fully covered FIN: in-order data, or out-of-order data from a segment
/// that starts no later than the FIN's, whichever arrives first.
#[test]
fn held_fin_is_overridden_by_data_processed_ahead_of_it() {
    let d = PEER_ISS + 1;
    let mut buf = [0u8; 512];

    let mut t = established();
    peer_seg(&mut t, d + 50, 1001, flags::FIN, &[]);
    peer_seg(&mut t, d, 1001, 0, &[1; 100]);
    assert_eq!((t.state(), t.rcv_nxt), (State::Established, d + 100));
    assert_eq!(t.recv(&mut buf), Ok(100));
    t.debug_validate_invariants().unwrap();
    peer_seg(&mut t, d + 100, 1001, flags::FIN, &[]);
    assert_eq!(t.state(), State::CloseWait, "the real FIN still closes");

    // A bare FIN at d+150 and a FIN after text from d+120, against data
    // [d+100, d+200) arriving before or after the FIN.
    for (fin_start, data_first) in [(150, false), (150, true), (120, false), (120, true)] {
        let mut t = established();
        let fin_text = std::vec![3u8; 150 - fin_start as usize];
        if data_first {
            peer_seg(&mut t, d + 100, 1001, 0, &[2; 100]);
        }
        peer_seg(&mut t, d + fin_start, 1001, flags::FIN, &fin_text);
        if !data_first {
            peer_seg(&mut t, d + 100, 1001, 0, &[2; 100]);
        }
        t.debug_validate_invariants().unwrap();
        peer_seg(&mut t, d, 1001, 0, &[1; 100]);
        assert_eq!(
            (t.state(), t.rcv_nxt),
            (State::Established, d + 200),
            "FIN segment from d+{fin_start}, data first: {data_first}"
        );
        t.debug_validate_invariants().unwrap();
    }
}

/// The other half of SEG.SEQ order: data from a segment that starts after
/// the FIN's segment is processed after the FIN, so the FIN ends the stream
/// and the data past it is purged, in either arrival order. That includes
/// an in-order FIN segment and data parked beyond its FIN, where the FIN
/// used to be lost.
#[test]
fn fin_segment_wins_over_data_that_starts_after_it() {
    let d = PEER_ISS + 1;
    let mut buf = [0u8; 512];
    for data_first in [false, true] {
        let mut t = established();
        if data_first {
            peer_seg(&mut t, d + 130, 1001, 0, &[9; 100]);
        }
        peer_seg(&mut t, d + 100, 1001, flags::FIN, &[2; 50]);
        if !data_first {
            peer_seg(&mut t, d + 130, 1001, 0, &[9; 100]);
        }
        peer_seg(&mut t, d, 1001, 0, &[1; 100]);
        assert_eq!(
            (t.state(), t.rcv_nxt),
            (State::CloseWait, d + 151),
            "data first: {data_first}"
        );
        assert_eq!(t.recv(&mut buf), Ok(150));
        t.debug_validate_invariants().unwrap();
    }

    let mut t = established();
    peer_seg(&mut t, d + 50, 1001, 0, &[9; 100]);
    peer_seg(&mut t, d, 1001, flags::FIN, &[1; 100]);
    assert_eq!((t.state(), t.rcv_nxt), (State::CloseWait, d + 101));
    assert_eq!(t.recv(&mut buf), Ok(100));
    assert_eq!(&buf[..100], &[1u8; 100][..]);
    t.debug_validate_invariants().unwrap();
}

/// An out-of-order FIN is consumed once, when the gap closes: with a
/// single ACK (it used to be two, or one plus a redundant delayed ACK for a
/// bare FIN), never skipped by bytes queued past it (they were delivered
/// and the FIN lost), and never displaced by a later, higher FIN.
#[test]
fn out_of_order_fin_is_consumed_once_and_never_skipped() {
    let d = PEER_ISS + 1;
    let mut t = established();
    peer_seg(&mut t, d + 100, 1001, flags::FIN, &[2; 100]);
    drain(&mut t);
    peer_seg(&mut t, d, 1001, 0, &[1; 100]);
    let out = drain(&mut t);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!((out[0].1, t.state()), (d + 201, State::CloseWait));

    let mut t = established();
    peer_seg(&mut t, d + 100, 1001, flags::FIN, &[]);
    drain(&mut t);
    peer_seg(&mut t, d, 1001, 0, &[1; 100]);
    assert_eq!(drain(&mut t).len(), 1);
    t.set_now(t.now_ms + 500);
    t.tick().unwrap();
    assert!(drain(&mut t).is_empty(), "redundant delayed ACK");

    let mut buf = [0u8; 512];
    let mut t = established();
    peer_seg(&mut t, d + 100, 1001, flags::FIN, &[2; 100]);
    peer_seg(&mut t, d + 200, 1001, 0, &[3; 100]);
    peer_seg(&mut t, d, 1001, 0, &[1; 100]);
    assert_eq!(t.state(), State::CloseWait);
    assert_eq!(
        t.recv(&mut buf).unwrap(),
        200,
        "bytes past the FIN delivered"
    );
    t.debug_validate_invariants().unwrap();

    let mut t = established();
    peer_seg(&mut t, d + 100, 1001, flags::FIN, &[]);
    peer_seg(&mut t, d + 300, 1001, flags::FIN, &[]);
    peer_seg(&mut t, d, 1001, 0, &[1; 100]);
    assert_eq!(t.state(), State::CloseWait);
    assert_eq!(t.rcv_nxt, d + 101);
}

#[test]
fn keepalive_reaps_vanished_idle_peer_and_spares_live_one() {
    let mut t = established();
    t.set_keepalive(1_000, 100, 3);
    run_timers(&mut t, 20, |t| t.state() == State::Closed);
    assert_eq!(t.state(), State::Closed, "vanished idle peer reaped");

    let mut t = established();
    t.set_keepalive(1_000, 100, 3);
    for _ in 0..20 {
        let d = t.debug_next_deadline().unwrap();
        t.set_now(d + 1);
        t.tick().unwrap();
        for (seq, _, _, len) in drain(&mut t) {
            assert_eq!(len, 0);
            assert_eq!(seq, 1000, "keepalive probe uses SND.NXT - 1");
            ack(&mut t, 1001, 65535); // live peer answers
        }
    }
    assert_eq!(t.state(), State::Established);
}

/// As in Linux, keepalive probes an idle connection in any synchronized
/// state but TIME_WAIT, so a peer that vanishes after a half close is reaped
/// too. In CLOSE_WAIT the peer's stream is complete and nothing of ours is in
/// flight, so the connection closes without an error and unread bytes stay
/// readable until EOF; in FIN_WAIT_2 it aborts. A live peer that answers
/// keeps the connection, and a listener gets no keepalive wakeups.
#[test]
fn keepalive_probes_idle_half_closed_connections() {
    let d = PEER_ISS + 1;
    let mut buf = [0u8; 64];

    let mut t = established();
    t.set_keepalive(1_000, 100, 3);
    peer_seg(&mut t, d, 1001, flags::FIN, b"response");
    assert_eq!(t.state(), State::CloseWait);
    drain(&mut t);
    run_timers(&mut t, 20, |t| t.state() == State::Closed);
    assert_eq!(t.state(), State::Closed, "vanished half-closed peer reaped");
    assert_eq!(t.poll() & events::ERROR, 0);
    assert_eq!(t.recv(&mut buf), Ok(8));
    assert_eq!(&buf[..8], b"response");
    assert_eq!(t.recv(&mut buf), Err(TcpError::ConnectionClosed));

    let mut t = established();
    t.set_keepalive(1_000, 100, 3);
    peer_seg(&mut t, d, 1001, flags::FIN, &[]);
    drain(&mut t);
    let mut probes = 0;
    for _ in 0..20 {
        let due = t.debug_next_deadline().unwrap();
        t.set_now(due + 1);
        t.tick().unwrap();
        for (seq, _, _, len) in drain(&mut t) {
            assert_eq!((seq, len), (1000, 0), "keepalive probe");
            probes += 1;
            peer_seg(&mut t, d + 1, 1001, 0, &[]); // live peer answers
        }
    }
    assert!(probes > 0, "an idle CLOSE_WAIT is probed");
    assert_eq!(t.state(), State::CloseWait, "a live peer keeps it open");

    let mut t = established();
    t.set_keepalive(1_000, 100, 3);
    t.set_fin_wait2_timeout(0);
    t.close().unwrap();
    drain(&mut t);
    peer_seg(&mut t, d, 1002, 0, &[]);
    assert_eq!(t.state(), State::FinWait2);
    run_timers(&mut t, 20, |t| t.state() == State::Closed);
    assert_eq!(t.state(), State::Closed);
    assert_ne!(t.poll() & events::ERROR, 0, "FIN_WAIT_2 reap is an abort");

    let mut t: Box<Tcb> = Box::new(Tcb::new(cfg(5000)).unwrap());
    t.set_now(0);
    t.set_secret(&[3; 16]);
    t.listen().unwrap();
    t.set_keepalive(1_000, 100, 3);
    assert_eq!(t.next_deadline(), None, "no keepalive wakeups in LISTEN");
}

#[test]
fn keepalive_can_be_disabled() {
    let mut t = established();
    t.set_keepalive(0, 0, 0);
    assert_eq!(t.debug_next_deadline(), None);
}

#[test]
fn user_timeout_disabled_allows_indefinite_zero_window() {
    let mut t = established();
    t.set_user_timeout(0);
    ack(&mut t, 1001, 0);
    t.send(&[1; 100]).unwrap();
    t.tick().unwrap();
    for _ in 0..200 {
        let d = t.debug_next_deadline().unwrap();
        t.set_now(d + 1);
        t.tick().unwrap();
        if !drain(&mut t).is_empty() {
            ack(&mut t, 1001, 0); // probe answered, window still shut
        }
    }
    assert_eq!(t.state(), State::Established);
    t.debug_check_liveness().unwrap();
}

#[test]
fn user_timeout_rearmed_by_full_segment_progress() {
    let mut t = established();
    t.set_user_timeout(10_000);
    t.send(&[1; 100_000]).unwrap();
    let mut acked = 1001u32;
    for k in 1..=30u64 {
        t.set_now(10 + k * 5_000);
        t.tick().unwrap();
        for (seq, _, _, len) in drain(&mut t) {
            if len > 0 && seq == acked {
                acked += len as u32;
            }
        }
        ack(&mut t, acked, 65535);
    }
    assert_eq!(
        t.state(),
        State::Established,
        "steady progress keeps it alive"
    );
}

#[test]
fn close_from_syn_rcvd_keeps_invariants() {
    let mut t = Box::new(Tcb::new(cfg(5000)).unwrap());
    t.set_now(0);
    t.set_secret(&[3; 16]);
    t.listen().unwrap();
    let o = TcpOptions {
        mss: Some(1460),
        ..TcpOptions::NONE
    };
    t.inject_packet(&peer_pkt(PEER_ISS, 0, flags::SYN, 65535, &o, &[]))
        .unwrap();
    drain(&mut t);
    assert_eq!(t.state(), State::SynRcvd);
    let iss = t.iss;
    t.close().unwrap();
    assert_eq!(t.state(), State::FinWait1);
    t.debug_validate_invariants().unwrap();
    // An ACK covering the SYN-ACK and the FIN completes our side of the close.
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        iss + 2,
        flags::ACK,
        65535,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(t.state(), State::FinWait2);
    t.debug_validate_invariants().unwrap();
}

#[test]
fn connect_after_reset_starts_clean() {
    let mut t = established();
    t.send(&[1; 100]).unwrap();
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        0,
        flags::RST,
        0,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(t.state(), State::Closed);
    t.set_now(1_000);
    t.connect().unwrap();
    assert_eq!(t.error, None);
    assert_eq!(t.send_ring.len(), 0);
    assert!(t.rtx.is_empty());
    t.debug_validate_invariants().unwrap();
}

#[test]
fn liveness_oracle_flags_dead_ack_clock_and_stuck_persist() {
    let mut t = established();
    t.send(&[1; 3000]).unwrap();
    t.tick().unwrap();
    drain(&mut t);
    t.debug_check_liveness().unwrap();
    t.rto_deadline = super::Deadline::OFF;
    t.tlp_deadline = super::Deadline::OFF;
    t.rack_deadline = super::Deadline::OFF;
    assert!(t.debug_check_liveness().is_err());

    let mut t = established();
    ack(&mut t, 1001, 0);
    t.send(&[1; 10]).unwrap();
    t.tick().unwrap();
    t.debug_check_liveness().unwrap();
    t.persist_deadline = super::Deadline::OFF;
    assert!(t.debug_check_liveness().is_err());
}

#[test]
fn partial_ack_inside_a_segment_then_retransmit_is_well_formed() {
    let mut t = established();
    t.send(&[7; 1000]).unwrap();
    t.tick().unwrap();
    drain(&mut t);
    ack(&mut t, 1001 + 600, 65535); // ACK lands inside the segment
    t.debug_validate_invariants().unwrap();
    t.set_now(t.debug_next_deadline().unwrap() + 1);
    t.tick().unwrap();
    let out = drain(&mut t);
    assert!(out.iter().any(|p| p.3 > 0));
    for (seq, _, _, len) in out {
        if len > 0 {
            assert_eq!(seq, 1601, "resend starts at SND.UNA");
            assert_eq!(len, 400, "and carries exactly the unacknowledged tail");
        }
    }
}

#[test]
fn sack_blocks_never_push_a_segment_over_the_mss() {
    // Bidirectional transfer with held out-of-order data: data segments must
    // still fit the MSS (SACK blocks are dropped from full segments).
    let mut t = Box::new(Tcb::new(cfg(1000)).unwrap());
    t.set_now(0);
    t.connect().unwrap();
    drain(&mut t);
    let o = TcpOptions {
        mss: Some(1460),
        ts: Some((1, 0)),
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
        ..TcpOptions::NONE
    };
    t.inject_packet(&peer_pkt(
        PEER_ISS,
        1001,
        flags::SYN | flags::ACK,
        65535,
        &o,
        &[],
    ))
    .unwrap();
    drain(&mut t);
    let tso = TcpOptions {
        ts: Some((2, 0)),
        ..TcpOptions::NONE
    };
    for k in [2u32, 4, 6] {
        t.inject_packet(&peer_pkt(
            PEER_ISS + 1 + k * 100,
            1001,
            flags::ACK,
            65535,
            &tso,
            &[1; 100],
        ))
        .unwrap();
    }
    drain(&mut t);
    t.send(&[9; 20_000]).unwrap();
    t.tick().unwrap();
    let mut buf = [0u8; MAX_PACKET];
    while let Ok(n) = t.extract_packet(&mut buf) {
        if n == 0 {
            break;
        }
        let s = wire::parse(&buf[..n]).unwrap();
        assert!(
            s.payload.len() + s.options.encoded_len() <= 1460,
            "segment exceeds MSS"
        );
    }
}

#[test]
fn next_deadline_is_never_stale_after_tick() {
    // Keepalive comes due while the connection is not probe-able (peer
    // closed its half; we hold CLOSE_WAIT with unsent data): tick must not
    // leave a past deadline armed, or an event-driven host would spin.
    let mut t = established();
    t.set_keepalive(1_000, 100, 3);
    t.set_user_timeout(0);
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        1001,
        flags::ACK | flags::FIN,
        0,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(t.state(), State::CloseWait);
    t.send(&[1; 10]).unwrap();
    for _ in 0..50 {
        let d = t.next_deadline().expect("persist / keepalive armed");
        t.set_now(d);
        t.tick().unwrap();
        drain(&mut t);
        let next = t.next_deadline().unwrap();
        assert!(next > d, "deadline {next} not after tick at {d}");
    }
    assert_eq!(t.state(), State::CloseWait);
}

#[test]
fn next_deadline_covers_time_wait_and_is_none_when_closed() {
    let mut t = established();
    t.close().unwrap();
    drain(&mut t);
    t.set_now(100);
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        1002,
        flags::ACK | flags::FIN,
        65535,
        &TcpOptions::NONE,
        &[],
    ))
    .unwrap();
    assert_eq!(t.state(), State::TimeWait);
    let d = t.next_deadline().unwrap();
    assert_eq!(d, 100 + 60_000);
    t.set_now(d);
    t.tick().unwrap();
    assert_eq!(t.state(), State::Closed);
    assert_eq!(t.next_deadline(), None);
}

/// Established client that negotiated SACK (no timestamps).
fn established_sack() -> Box<Tcb> {
    let mut t = Box::new(Tcb::new(cfg(1000)).unwrap());
    t.set_now(0);
    t.connect().unwrap();
    drain(&mut t);
    let o = TcpOptions {
        mss: Some(1460),
        sack_permitted: true,
        ..TcpOptions::NONE
    };
    t.set_now(10);
    t.inject_packet(&peer_pkt(
        PEER_ISS,
        1001,
        flags::SYN | flags::ACK,
        65535,
        &o,
        &[],
    ))
    .unwrap();
    drain(&mut t);
    assert_eq!(t.state(), State::Established);
    t
}

#[test]
fn recovery_started_by_a_large_cumulative_ack_does_not_overshoot_prr() {
    // Eight segments in flight. One ACK cumulatively acknowledges three of
    // them and SACKs four more, so segment 3 is lost at once (DupThresh
    // segments SACKed above it). PRR must size the reduction from the
    // flight *before* that ACK, because it also counts the ACK's delivered
    // bytes; otherwise prr_delivered / RecoverFS exceeds 1 and later ACKs
    // release unearned data.
    let mut t = established_sack();
    t.send(&[5; 8 * 1460]).unwrap();
    t.set_now(20);
    t.tick().unwrap();
    assert_eq!(drain(&mut t).len(), 8);
    t.send(&[6; 8 * 1460]).unwrap(); // plenty of new data to tempt it
    let seg = |k: u32| 1001 + k * 1460;
    let sack = TcpOptions {
        sack: SackBlocks::one(seg(4), seg(8)),
        ..TcpOptions::NONE
    };
    t.set_now(60);
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        seg(3),
        flags::ACK,
        65535,
        &sack,
        &[],
    ))
    .unwrap();
    let first = drain(&mut t);
    assert!(
        first.iter().any(|p| p.0 == seg(3) && p.3 == 1460),
        "fast retransmit: {first:?} {:?}",
        t.stats()
    );
    assert_eq!(t.stats().ssthresh, 4 * 1460, "half of the 8-segment flight");
    // The same ACK again carries no new information: nothing may be sent.
    t.set_now(61);
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1,
        seg(3),
        flags::ACK,
        65535,
        &sack,
        &[],
    ))
    .unwrap();
    let again = drain(&mut t);
    assert!(
        again.iter().all(|p| p.3 == 0),
        "information-free duplicate ACK released data: {again:?}"
    );
    t.debug_validate_invariants().unwrap();
}

// ---------------------------------------------------------------------------
// Buffer sizing (`tune.rs`)
// ---------------------------------------------------------------------------

/// Peer stream byte `i` (relative to the first data byte after the SYN).
fn peer_byte(i: u32) -> u8 {
    (i.wrapping_mul(2_654_435_761) >> 24) as u8
}

fn peer_data(t: &mut Tcb, off: u32, len: u32) {
    let payload: Vec<u8> = (off..off + len).map(peer_byte).collect();
    t.inject_packet(&peer_pkt(
        PEER_ISS + 1 + off,
        1001,
        flags::ACK,
        65535,
        &TcpOptions::NONE,
        &payload,
    ))
    .unwrap();
}

/// Read everything readable and check it continues the peer's stream at
/// `*at`.
fn read_peer(t: &mut Tcb, at: &mut u32) {
    let mut buf = [0u8; 4096];
    while let Ok(n) = t.recv(&mut buf) {
        if n == 0 {
            break;
        }
        for (k, &b) in buf[..n].iter().enumerate() {
            assert_eq!(
                b,
                peer_byte(*at + k as u32),
                "stream byte {}",
                *at + k as u32
            );
        }
        *at += n as u32;
    }
}

/// Payload of every staged data segment, in order.
fn drain_payload(t: &mut Tcb) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; MAX_PACKET];
    while let Ok(n) = t.extract_packet(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(wire::parse(&buf[..n]).unwrap().payload);
    }
    out
}

/// A TCB that never calls `set_buffer_limits` keeps fixed `BUF`-byte rings.
#[test]
fn rings_are_fixed_at_buf_by_default() {
    let mut t = established();
    assert_eq!(t.buffer_capacity(), (crate::BUF_CAP, crate::BUF_CAP));
    assert_eq!(t.send(&[1; 5000]), Ok(5000));
    assert_eq!(t.send_ring.room(), t.send_ring.free());
    assert_eq!(t.recv_ring.room(), t.recv_ring.free());
    t.debug_validate_invariants().unwrap();
}

#[test]
fn buffer_limits_are_normalised_validated_and_reset_by_reinit() {
    use crate::BUF_CAP;
    let mut t: Box<Tcb> = Box::new(Tcb::new(cfg(1000)).unwrap());
    assert_eq!(
        t.set_buffer_limits(8192, 4096, 0, 0),
        Err(TcpError::InvalidState)
    );
    assert_eq!(
        t.buffer_capacity(),
        (BUF_CAP, BUF_CAP),
        "rejected: no change"
    );
    t.set_buffer_limits(0, 5000, 9000, usize::MAX).unwrap();
    assert_eq!(
        (t.snd_buf_min, t.snd_buf_max, t.rcv_buf_min, t.rcv_buf_max),
        (4096, 4096, 8192, BUF_CAP)
    );
    assert_eq!(
        t.buffer_capacity(),
        (4096, super::INITIAL_RING_CAP.min(BUF_CAP)),
        "a closed TCB moves to the initial capacities at once"
    );
    t.debug_validate_invariants().unwrap();
    t.reinit(cfg(2000));
    assert_eq!(t.buffer_capacity(), (BUF_CAP, BUF_CAP));
    assert_eq!((t.snd_buf_min, t.rcv_buf_max), (BUF_CAP, BUF_CAP));
    t.debug_validate_invariants().unwrap();
}

/// Lowering the receive maximum mid-connection never takes back window
/// already advertised: the right edge of every ACK stays put until the
/// peer has used the promised space, then the ring shrinks.
#[test]
fn a_receive_shrink_never_retracts_the_advertised_window() {
    use super::seq_ge;
    let mut t = established();
    t.set_buffer_limits(crate::BUF_CAP, crate::BUF_CAP, 4096, 16384)
        .unwrap();
    assert_eq!(
        t.buffer_capacity().1,
        crate::BUF_CAP,
        "65535 bytes promised"
    );
    let mut edge = t.rcv_adv_edge;
    let (mut off, mut read) = (0u32, 0u32);
    for i in 0..80u64 {
        t.set_now(20 + i);
        peer_data(&mut t, off, 1000);
        off += 1000;
        read_peer(&mut t, &mut read);
        t.tick().unwrap();
        let mut buf = [0u8; MAX_PACKET];
        while let Ok(n) = t.extract_packet(&mut buf) {
            if n == 0 {
                break;
            }
            let s = wire::parse(&buf[..n]).unwrap();
            let right = s.ack.wrapping_add(u32::from(s.window));
            assert!(seq_ge(right, edge), "window retracted at {i}");
            assert!(
                right == edge || right.wrapping_sub(s.ack) <= 16384,
                "offered past the 16 KiB target"
            );
            edge = right;
        }
        t.debug_validate_invariants().unwrap();
    }
    assert_eq!(read, off, "every byte delivered");
    assert_eq!(t.buffer_capacity().1, 16384, "the promise was used up");
}

/// Space lent by `send_reserve` never moves: a shrink waits for the commit.
#[test]
fn a_loan_holds_back_a_send_shrink() {
    let mut t = established();
    let (a, _) = t.send_reserve(3000).unwrap();
    assert_eq!(a.len(), 3000);
    a.fill(0x77);
    t.set_buffer_limits(4096, 4096, crate::BUF_CAP, crate::BUF_CAP)
        .unwrap();
    assert_eq!(t.buffer_capacity().0, crate::BUF_CAP, "lent space moved");
    t.debug_validate_invariants().unwrap();
    assert_eq!(t.send_commit(3000), Ok(3000));
    assert_eq!(t.buffer_capacity().0, 4096, "the commit let it shrink");
    assert_eq!(
        t.send(&[0x88; 2000]),
        Ok(1096),
        "only the target is offered"
    );
    assert_eq!(t.send_reserve(10).err(), Some(TcpError::WouldBlock), "full");
    t.set_now(20);
    t.tick().unwrap();
    let mut want = std::vec![0x77u8; 3000];
    want.extend_from_slice(&[0x88; 1096]);
    assert_eq!(drain_payload(&mut t), want);
    t.debug_validate_invariants().unwrap();
}

/// Out-of-order bytes parked in the receive ring survive its growth, and
/// come out in order once the hole is filled.
#[test]
fn parked_out_of_order_data_survives_growth() {
    use crate::BUF_CAP;
    let mut t = established_with(|t| {
        t.set_buffer_limits(BUF_CAP, BUF_CAP, 8192, 8192).unwrap();
    });
    assert_eq!(t.buffer_capacity().1, 8192);
    let mut read = 0;
    t.set_now(20);
    peer_data(&mut t, 1000, 1000); // parked at [1000, 2000)
    let big = 65536.min(BUF_CAP);
    t.set_buffer_limits(BUF_CAP, BUF_CAP, big, big).unwrap();
    assert_eq!(t.buffer_capacity().1, big, "growing is always safe");
    peer_data(&mut t, 0, 1000);
    read_peer(&mut t, &mut read);
    assert_eq!(read, 2000);
    t.debug_validate_invariants().unwrap();
}

/// A shrink applies as soon as the window promised and the parked span fit,
/// without waiting for the hole, and the parked bytes survive the move.
#[test]
fn a_shrink_applies_around_parked_out_of_order_data() {
    use crate::BUF_CAP;
    let mut t = established_with(|t| {
        t.set_buffer_limits(BUF_CAP, BUF_CAP, 8192, 8192).unwrap();
    });
    t.set_buffer_limits(BUF_CAP, BUF_CAP, 4096, 4096).unwrap();
    assert_eq!(t.buffer_capacity().1, 8192, "8192 bytes promised");
    t.set_now(20);
    peer_data(&mut t, 6000, 1000); // parked at [6000, 7000)
    for k in 0..4 {
        peer_data(&mut t, k * 1460, 1460.min(5000 - k * 1460));
        drain(&mut t);
    }
    assert_eq!(t.buffer_capacity().1, 8192, "5000 unread bytes");
    let mut read = 0;
    read_peer(&mut t, &mut read);
    assert_eq!(read, 5000);
    assert_eq!(
        t.buffer_capacity().1,
        4096,
        "3192 promised + parked at +1000..+2000 fit"
    );
    assert!(!t.ooo.is_empty(), "data still parked");
    t.debug_validate_invariants().unwrap();
    peer_data(&mut t, 5000, 1000);
    read_peer(&mut t, &mut read);
    assert_eq!(read, 7000, "parked bytes delivered in order");
    t.debug_validate_invariants().unwrap();
}

/// `reclaimable` lists only storage the TCB will not read: whole empty
/// rings, ring space past the capacity, and idle egress slots — never lent
/// space or staged packets.
#[test]
fn reclaimable_lists_only_storage_the_tcb_will_not_read() {
    use crate::{BUF_CAP, MAX_PACKET};
    let slots = crate::tx_ring::TX_RING_CAP * MAX_PACKET;
    let mut t = established_with(|t| {
        t.set_buffer_limits(4096, 65536, 4096, 65536).unwrap();
    });
    // Past the (initial) capacity: none with `small-buffers`' 32 KiB rings.
    let past = BUF_CAP - super::INITIAL_RING_CAP.min(BUF_CAP);
    let lens = |t: &mut Tcb| t.reclaimable().map(|s| s.len());
    assert_eq!(lens(&mut t), [BUF_CAP, BUF_CAP, slots], "all empty");
    assert_eq!(t.send(&[1; 100]), Ok(100));
    assert_eq!(lens(&mut t)[0], past, "past the send capacity");
    let _ = t.send_reserve(10).unwrap();
    assert_eq!(lens(&mut t)[0], 0, "a loan hides the send ring");
    assert_eq!(t.send_commit(0), Ok(0));
    t.set_now(20);
    t.tick().unwrap();
    assert_eq!(lens(&mut t)[2], 0, "staged packets hide the egress slots");
    drain(&mut t);
    peer_data(&mut t, 3000, 500);
    assert_eq!(lens(&mut t)[1], past, "parked data keeps the ring");
    // Whatever the host does to those bytes, the stream is unaffected.
    for s in t.reclaimable() {
        s.fill(0xA5);
    }
    peer_data(&mut t, 0, 3000);
    let mut read = 0;
    read_peer(&mut t, &mut read);
    assert_eq!(read, 3500);
    let n = t.send_ring.len();
    let sent: Vec<u8> = drain_payload(&mut t);
    assert!(sent.iter().all(|&b| b == 1), "send ring bytes intact");
    assert!(sent.len() <= n);
    t.debug_validate_invariants().unwrap();
}

#[test]
fn init_in_place_zeroed_matches_init_in_place() {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::new::<Tcb>();
    // SAFETY: zeroed storage of `Tcb`'s layout, owned by the box from here.
    let mut a = unsafe {
        let p = alloc_zeroed(layout).cast::<Tcb>();
        assert!(!p.is_null());
        Tcb::init_in_place_zeroed(p, cfg(1000)).unwrap();
        Box::from_raw(p)
    };
    let mut b = Box::new(Tcb::new(cfg(1000)).unwrap());
    for t in [&mut a, &mut b] {
        t.set_now(5);
        t.connect().unwrap();
    }
    let mut pa = [0u8; MAX_PACKET];
    let mut pb = [0u8; MAX_PACKET];
    let na = a.extract_packet(&mut pa).unwrap();
    let nb = b.extract_packet(&mut pb).unwrap();
    assert_eq!(&pa[..na], &pb[..nb]);
    assert_eq!(a.stats(), b.stats());
    a.debug_validate_invariants().unwrap();
}

/// The buffer invariants `debug_validate_invariants` checks are live: each
/// one trips on the state it guards against.
#[test]
fn buffer_invariants_catch_what_they_guard_against() {
    let fresh = || {
        established_with(|t| {
            t.set_buffer_limits(4096, 65536, 4096, 65536).unwrap();
        })
    };
    let mut t = fresh();
    t.debug_validate_invariants().unwrap();
    t.snd_buf_min = 3000;
    assert_eq!(
        t.debug_validate_invariants(),
        Err("buffer limits out of range")
    );
    let mut t = fresh();
    t.recv_ring.set_target(2048);
    assert_eq!(
        t.debug_validate_invariants(),
        Err("ring target outside its limits")
    );
    let mut t = fresh();
    t.rcv_adv_edge = t.rcv_nxt.wrapping_add(70_000);
    assert_eq!(
        t.debug_validate_invariants(),
        Err("advertised window exceeds the receive buffer")
    );
    let mut t = fresh();
    let _ = t.send_reserve(1000).unwrap();
    t.send_lent = 100_000;
    assert_eq!(
        t.debug_validate_invariants(),
        Err("lent send space exceeds the free space")
    );
}

/// Ring storage must be a power of two, whichever way the TCB is built.
#[test]
fn a_ring_size_that_is_not_a_power_of_two_is_refused() {
    use std::alloc::{alloc_zeroed, dealloc, Layout};
    assert!(matches!(Tcb::<3>::new(cfg(1)), Err(TcpError::Overflow)));
    let layout = Layout::new::<Tcb<3>>();
    // SAFETY: zeroed storage of `Tcb<3>`'s layout; refused, so never a TCB.
    unsafe {
        let p = alloc_zeroed(layout).cast::<Tcb<3>>();
        assert!(!p.is_null());
        assert_eq!(
            Tcb::init_in_place_zeroed(p, cfg(1)),
            Err(TcpError::Overflow)
        );
        dealloc(p.cast(), layout);
    }
}
