//! Coverage-guided fuzzing of the **client send / retransmit** machinery.
//!
//! The `tcb_inject_sequence` target starts in `Listen` and never sends, so
//! the RACK / TLP / RFC 6675 selective-retransmit code — where the
//! sequence-arithmetic buffer-offset bugs live — is essentially
//! unreachable there. This target instead drives the active-open data
//! path end to end:
//!
//!   1. `connect()` and complete a scripted handshake (the peer SYN-ACK
//!      advertises SACK_PERMITTED so the SACK/RACK recovery paths light
//!      up).
//!   2. Feed application bytes with `send()`.
//!   3. Let the fuzzer choose, for each step: how much to send, how far
//!      to advance the clock (to fire delayed-ACK / TLP / RTO timers), the
//!      *cumulative-ACK offset* (frequently landing **inside** an
//!      in-flight segment — the partial-ACK case), and an optional SACK
//!      block above it.
//!
//! Oracles:
//! * internal errors (`Overflow`, `BufferTooSmall` with harness-sized
//!   buffers) must never escape the API,
//! * the TCB's own debug invariants must hold after every operation,
//! * every emitted packet must parse and must be local -> peer,
//! * bogus ACKs above `snd_max` must not advance/consume send state,
//! * duplicate pure ACKs must be idempotent with respect to sequence state,
//! * output per step is bounded (no ACK/output storm),
//! * a small no-loss sub-session converges after data + FIN are ACKed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::wire::{self, flags, SackBlocks, TcpOptions};
use tcp_sans_io::tcb::DebugSnapshot;
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError, MAX_PACKET};

const C_IP: [u8; 4] = [10, 0, 0, 1];
const S_IP: [u8; 4] = [10, 0, 0, 2];
const C_PORT: u16 = 49152;
const S_PORT: u16 = 80;
const OUR_ISS: u32 = 0x1000_0000;
const PEER_ISS: u32 = 0x9000_0000;
const PEER_WIN: u16 = 0xFFFF;

/// Panic iff a call surfaced an internal invariant code;
/// otherwise hand back the value (or `None` for legitimate errors).
#[track_caller]
fn no_internal<T>(r: Result<T, TcpError>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(TcpError::Overflow) => {
            panic!("internal TcpError::Overflow escaped across the API boundary")
        }
        Err(TcpError::BufferTooSmall) => {
            panic!("internal TcpError::BufferTooSmall escaped with MAX_PACKET buffers")
        }
        Err(_) => None,
    }
}

#[track_caller]
fn check(tcb: &Tcb) {
    if let Err(e) = tcb.debug_validate_invariants() {
        panic!("TCB invariant failed: {e}");
    }
}

fn allowed_transition(prev: State, next: State) -> bool {
    use State::*;
    if prev == next {
        return true;
    }
    matches!(
        (prev, next),
        (Closed, SynSent | Listen)
            | (Listen, SynRcvd | Closed)
            | (SynRcvd, Established | Listen | FinWait1 | Closed)
            | (SynSent, Established | Closed)
            | (Established, FinWait1 | CloseWait | Closed)
            | (FinWait1, FinWait2 | Closing | TimeWait | Closed)
            | (FinWait2, TimeWait | Closed)
            | (Closing, TimeWait | Closed)
            | (TimeWait, Closed)
            | (CloseWait, LastAck | Closed)
            | (LastAck, Closed)
    )
}

#[track_caller]
fn observe_state(prev: &mut State, tcb: &Tcb) {
    let next = tcb.state();
    if !allowed_transition(*prev, next) {
        panic!("illegal TCP state transition: {:?} -> {:?}", *prev, next);
    }
    *prev = next;
    check(tcb);
}

/// Serialize a peer -> cdylib datagram.
fn peer_pkt(seq: u32, ack: u32, fl: u8, opts: &TcpOptions, payload: &[u8]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; MAX_PACKET];
    match wire::emit(
        &mut buf, S_IP, C_IP, S_PORT, C_PORT, seq, ack, fl, PEER_WIN, opts, payload, 1, 0,
    ) {
        Ok(n) => {
            buf.truncate(n);
            Some(buf)
        }
        Err(_) => None,
    }
}

/// Drain every staged egress packet, folding the highest (seq+len) we see
/// into `hi` so the harness knows the stack's current snd_nxt high-water.
fn drain(tcb: &mut Tcb, hi: &mut u32, prev_state: &mut State) {
    let mut out = [0u8; MAX_PACKET];
    for _ in 0..128 {
        match no_internal(tcb.extract_packet(&mut out)) {
            Some(0) | None => break,
            Some(n) => {
                let seg = wire::parse(&out[..n]).expect("self-emitted packet must parse");
                assert_eq!(seg.src_ip, C_IP, "emitted packet has wrong source IP");
                assert_eq!(seg.dst_ip, S_IP, "emitted packet has wrong destination IP");
                assert_eq!(seg.src_port, C_PORT, "emitted packet has wrong source port");
                assert_eq!(seg.dst_port, S_PORT, "emitted packet has wrong destination port");
                // seq_len() counts SYN/FIN, so `hi` advances past a FIN
                // and the peer can ACK it to reach TIME_WAIT/CLOSED.
                let end = seg.seq.wrapping_add(seg.seq_len());
                if (end.wrapping_sub(*hi) as i32) > 0 {
                    *hi = end;
                }
                observe_state(prev_state, tcb);
            }
        }
    }
    match no_internal(tcb.extract_packet(&mut out)) {
        Some(0) | None => {}
        Some(_) => panic!("unbounded output: more than 128 packets in one drain"),
    }
}

#[track_caller]
fn assert_sender_core_unchanged(before: DebugSnapshot, after: DebugSnapshot, why: &str) {
    assert_eq!(after.snd_una, before.snd_una, "{why}: snd_una changed");
    assert_eq!(after.snd_nxt, before.snd_nxt, "{why}: snd_nxt changed");
    assert_eq!(after.snd_wnd, before.snd_wnd, "{why}: snd_wnd changed");
    assert_eq!(
        after.send_ring_len, before.send_ring_len,
        "{why}: send ring length changed",
    );
    assert_eq!(after.state, before.state, "{why}: state changed");
}

fn ack_packet(ack: u32, sack: SackBlocks) -> Option<Vec<u8>> {
    let opts = TcpOptions {
        mss: None,
        wscale: None,
        ts: None,
        sack_permitted: false,
        sack,
    };
    peer_pkt(PEER_ISS.wrapping_add(1), ack, flags::ACK, &opts, &[])
}

fn make_tcb() -> Option<Tcb> {
    Tcb::new(TcbConfig {
        local: Endpoint { ip: C_IP, port: C_PORT },
        remote: Endpoint { ip: S_IP, port: S_PORT },
        iss: OUR_ISS,
        initial_rto_ms: 1000,
    })
    .ok()
}

fn complete_handshake(tcb: &mut Tcb, now: &mut u64, hi: &mut u32, prev_state: &mut State) -> bool {
    tcb.set_now(*now);
    observe_state(prev_state, tcb);
    if no_internal(tcb.connect()).is_none() {
        return false;
    }
    observe_state(prev_state, tcb);
    no_internal(tcb.tick());
    drain(tcb, hi, prev_state);

    // SYN-ACK advertising MSS + SACK_PERMITTED (no TS, so RTT falls back to
    // the per-RTO probe and TLP's PTO uses the 10 ms floor — fine for us).
    let synack_opts = TcpOptions {
        mss: Some(1460),
        wscale: None,
        ts: None,
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    let Some(p) = peer_pkt(
        PEER_ISS,
        OUR_ISS.wrapping_add(1),
        flags::SYN | flags::ACK,
        &synack_opts,
        &[],
    ) else {
        return false;
    };
    no_internal(tcb.inject_packet(&p));
    observe_state(prev_state, tcb);
    no_internal(tcb.tick());
    drain(tcb, hi, prev_state);
    true
}

fn no_loss_liveness(data: &[u8]) {
    let Some(mut tcb) = make_tcb() else { return };
    let mut now = 0u64;
    let mut hi = OUR_ISS.wrapping_add(1);
    let mut prev_state = State::Closed;
    if !complete_handshake(&mut tcb, &mut now, &mut hi, &mut prev_state) {
        return;
    }

    let mut i = 0usize;
    for _ in 0..4 {
        let n = 1 + (data.get(i).copied().unwrap_or(1) as usize % 16) * 64;
        i += 1;
        let chunk = vec![0xCD; n];
        no_internal(tcb.send(&chunk));
        observe_state(&mut prev_state, &tcb);
        now = now.saturating_add(1);
        tcb.set_now(now);
        no_internal(tcb.tick());
        drain(&mut tcb, &mut hi, &mut prev_state);

        if let Some(p) = ack_packet(hi, SackBlocks::EMPTY) {
            no_internal(tcb.inject_packet(&p));
            observe_state(&mut prev_state, &tcb);
            drain(&mut tcb, &mut hi, &mut prev_state);
        }
    }

    no_internal(tcb.close());
    observe_state(&mut prev_state, &tcb);
    now = now.saturating_add(1);
    tcb.set_now(now);
    no_internal(tcb.tick());
    drain(&mut tcb, &mut hi, &mut prev_state);

    if let Some(p) = ack_packet(hi, SackBlocks::EMPTY) {
        no_internal(tcb.inject_packet(&p));
        observe_state(&mut prev_state, &tcb);
        drain(&mut tcb, &mut hi, &mut prev_state);
    }

    let snap = tcb.debug_snapshot();
    assert_eq!(snap.send_ring_len, 0, "no-loss session left send bytes queued");
    assert_eq!(snap.snd_una, snap.snd_nxt, "no-loss session did not ACK all sent seqs");
    assert_eq!(
        tcb.state(),
        State::FinWait2,
        "own FIN ACK should leave active closer in FIN-WAIT-2",
    );
}

fuzz_target!(|data: &[u8]| {
    if data.first().copied().unwrap_or(0) & 1 == 0 {
        no_loss_liveness(data);
    }

    let Some(mut tcb) = make_tcb() else { return };

    let mut now: u64 = 0;
    let mut hi = OUR_ISS.wrapping_add(1);
    let mut prev_state = State::Closed;
    if !complete_handshake(&mut tcb, &mut now, &mut hi, &mut prev_state) {
        return;
    }

    let data_opts = TcpOptions {
        mss: None,
        wscale: None,
        ts: None,
        sack_permitted: false,
        sack: SackBlocks::EMPTY,
    };

    let mut acked = OUR_ISS.wrapping_add(1);
    let mut i = 0usize;
    let mut closed = false;
    let next = |i: &mut usize| -> u8 {
        let b = data.get(*i).copied().unwrap_or(0);
        *i += 1;
        b
    };

    // Bound the number of steps so a pathological input can't spin forever.
    let mut steps = 0u32;
    while i < data.len() && steps < 4096 {
        steps += 1;
        let op = next(&mut i);

        // 1. Offer application data (0..~2 KiB).
        let send_len = ((op as usize) & 0x1F) * 64;
        if send_len > 0 {
            let chunk = vec![0xABu8; send_len];
            no_internal(tcb.send(&chunk));
            observe_state(&mut prev_state, &tcb);
        }

        // 1b. Half-close from our side once the fuzzer asks for it, so the
        //     FIN / FIN-retransmit / TIME_WAIT teardown paths (and the
        //     initial-retransmit `snd_max - snd_una` accounting that counts
        //     the phantom FIN byte) are exercised too.
        if !closed && op & 0x20 != 0 {
            no_internal(tcb.close());
            closed = true;
            observe_state(&mut prev_state, &tcb);
        }

        // 2. Advance the clock and emit.
        now = now.saturating_add(next(&mut i) as u64);
        tcb.set_now(now);
        check(&tcb);
        no_internal(tcb.tick());
        drain(&mut tcb, &mut hi, &mut prev_state);

        // 3. Cumulative ACK at a fuzzer-chosen offset (frequently inside an
        //    in-flight segment) with an optional SACK block above it.
        let span = hi.wrapping_sub(acked);
        if (span as i32) > 0 {
            let frac = next(&mut i) as u32;
            let new_ack = acked.wrapping_add(span.wrapping_mul(frac) / 256);
            let mut sack = SackBlocks::EMPTY;
            if next(&mut i) & 1 == 1 {
                let above = hi.wrapping_sub(new_ack);
                if (above as i32) > 2 {
                    let lo = new_ack.wrapping_add(1 + (next(&mut i) as u32 % above));
                    let mut r = lo.wrapping_add(1 + (next(&mut i) as u32) * 8);
                    if (r.wrapping_sub(hi) as i32) > 0 {
                        r = hi;
                    }
                    if (lo.wrapping_sub(r) as i32) < 0 {
                        sack = SackBlocks::one(lo, r);
                    }
                }
            }
            let opts = TcpOptions { sack, ..data_opts };
            if let Some(p) = peer_pkt(PEER_ISS.wrapping_add(1), new_ack, flags::ACK, &opts, &[]) {
                no_internal(tcb.inject_packet(&p));
                observe_state(&mut prev_state, &tcb);
                drain(&mut tcb, &mut hi, &mut prev_state);
            }
            if (new_ack.wrapping_sub(acked) as i32) > 0 {
                acked = new_ack;
            }

            // Duplicate pure ACK idempotence: one duplicate ACK with no SACK
            // must not advance sequence state or consume send bytes. Restrict
            // to dup_ack_count=0 so this oracle doesn't intentionally become
            // the third dup-ACK fast-retransmit trigger.
            let before_dup = tcb.debug_snapshot();
            if before_dup.dup_ack_count == 0 {
                if let Some(p) = ack_packet(acked, SackBlocks::EMPTY) {
                    no_internal(tcb.inject_packet(&p));
                    observe_state(&mut prev_state, &tcb);
                    let after_dup = tcb.debug_snapshot();
                    assert_sender_core_unchanged(before_dup, after_dup, "duplicate pure ACK");
                    drain(&mut tcb, &mut hi, &mut prev_state);
                }
            }
        }

        // ACK above snd_max must not advance sender state or consume data.
        if op & 0x80 != 0 {
            let before_bad = tcb.debug_snapshot();
            let bad_ack = hi.wrapping_add(1 + next(&mut i) as u32);
            if let Some(p) = ack_packet(bad_ack, SackBlocks::EMPTY) {
                no_internal(tcb.inject_packet(&p));
                observe_state(&mut prev_state, &tcb);
                let after_bad = tcb.debug_snapshot();
                assert_sender_core_unchanged(before_bad, after_bad, "ACK above snd_max");
                drain(&mut tcb, &mut hi, &mut prev_state);
            }
        }

        // 4. Sometimes jump the clock to fire TLP (>=10 ms) / RTO (>=200 ms)
        //    on the current tail.
        if op & 0x40 != 0 {
            now = now.saturating_add(11 + op as u64);
            tcb.set_now(now);
            check(&tcb);
            no_internal(tcb.tick());
            drain(&mut tcb, &mut hi, &mut prev_state);
        }

        // 5. Keep the receive side drained.
        let mut rbuf = [0u8; 2048];
        no_internal(tcb.recv(&mut rbuf));
        observe_state(&mut prev_state, &tcb);
    }
});
