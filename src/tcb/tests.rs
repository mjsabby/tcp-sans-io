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

use super::{Endpoint, Tcb, TcbConfig, MAX_RETRANSMITS, MAX_SYN_RETRIES};
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
    let mut t = Box::new(Tcb::new(cfg(1000)).unwrap());
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
    t.set_now(100 + 60_001);
    t.tick().unwrap();
    assert_eq!(t.state(), State::TimeWait, "2*MSL restarted");
    t.set_now(50_100 + 60_001);
    t.tick().unwrap();
    assert_eq!(t.state(), State::Closed);
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
