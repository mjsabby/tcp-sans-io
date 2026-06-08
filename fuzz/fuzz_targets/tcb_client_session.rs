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
//! Oracle: the internal `TcpError::Overflow` code must never escape across
//! the API on any reachable state. A blind RNG struggles to reach the
//! partial-ACK-then-TLP state that triggered the `tcp_tick: -9`
//! regression; libFuzzer's coverage feedback is far better at steering
//! into it, which is the whole reason this target exists.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::wire::{self, flags, SackBlocks, TcpOptions};
use tcp_sans_io::{Endpoint, Tcb, TcbConfig, TcpError, MAX_PACKET};

const C_IP: [u8; 4] = [10, 0, 0, 1];
const S_IP: [u8; 4] = [10, 0, 0, 2];
const C_PORT: u16 = 49152;
const S_PORT: u16 = 80;
const OUR_ISS: u32 = 0x1000_0000;
const PEER_ISS: u32 = 0x9000_0000;
const PEER_WIN: u16 = 0xFFFF;

/// Panic iff a call surfaced the internal `Overflow` invariant code;
/// otherwise hand back the value (or `None` for legitimate errors).
#[track_caller]
fn no_overflow<T>(r: Result<T, TcpError>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(TcpError::Overflow) => {
            panic!("internal TcpError::Overflow escaped across the API boundary")
        }
        Err(_) => None,
    }
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
fn drain(tcb: &mut Tcb, hi: &mut u32) {
    let mut out = [0u8; MAX_PACKET];
    loop {
        match no_overflow(tcb.extract_packet(&mut out)) {
            Some(0) | None => break,
            Some(n) => {
                if let Ok(seg) = wire::parse(&out[..n]) {
                    // seq_len() counts SYN/FIN, so `hi` advances past a FIN
                    // and the peer can ACK it to reach TIME_WAIT/CLOSED.
                    let end = seg.seq.wrapping_add(seg.seq_len());
                    if (end.wrapping_sub(*hi) as i32) > 0 {
                        *hi = end;
                    }
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut tcb: Tcb = match Tcb::new(TcbConfig {
        local: Endpoint { ip: C_IP, port: C_PORT },
        remote: Endpoint { ip: S_IP, port: S_PORT },
        iss: OUR_ISS,
        initial_rto_ms: 1000,
    }) {
        Ok(t) => t,
        Err(_) => return,
    };

    let mut now: u64 = 0;
    tcb.set_now(now);
    if tcb.connect().is_err() {
        return;
    }
    let mut hi = OUR_ISS.wrapping_add(1);
    no_overflow(tcb.tick());
    drain(&mut tcb, &mut hi);

    // SYN-ACK advertising MSS + SACK_PERMITTED (no TS, so RTT falls back to
    // the per-RTO probe and TLP's PTO uses the 10 ms floor — fine for us).
    let synack_opts = TcpOptions {
        mss: Some(1460),
        wscale: None,
        ts: None,
        sack_permitted: true,
        sack: SackBlocks::EMPTY,
    };
    match peer_pkt(
        PEER_ISS,
        OUR_ISS.wrapping_add(1),
        flags::SYN | flags::ACK,
        &synack_opts,
        &[],
    ) {
        Some(p) => {
            no_overflow(tcb.inject_packet(&p));
        }
        None => return,
    }
    no_overflow(tcb.tick());
    drain(&mut tcb, &mut hi);

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
            no_overflow(tcb.send(&chunk));
        }

        // 1b. Half-close from our side once the fuzzer asks for it, so the
        //     FIN / FIN-retransmit / TIME_WAIT teardown paths (and the
        //     initial-retransmit `snd_max - snd_una` accounting that counts
        //     the phantom FIN byte) are exercised too.
        if !closed && op & 0x20 != 0 {
            no_overflow(tcb.close());
            closed = true;
        }

        // 2. Advance the clock and emit.
        now = now.saturating_add(next(&mut i) as u64);
        tcb.set_now(now);
        no_overflow(tcb.tick());
        drain(&mut tcb, &mut hi);

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
                no_overflow(tcb.inject_packet(&p));
                drain(&mut tcb, &mut hi);
            }
            if (new_ack.wrapping_sub(acked) as i32) > 0 {
                acked = new_ack;
            }
        }

        // 4. Sometimes jump the clock to fire TLP (>=10 ms) / RTO (>=200 ms)
        //    on the current tail.
        if op & 0x40 != 0 {
            now = now.saturating_add(11 + op as u64);
            tcb.set_now(now);
            no_overflow(tcb.tick());
            drain(&mut tcb, &mut hi);
        }

        // 5. Keep the receive side drained.
        let mut rbuf = [0u8; 2048];
        no_overflow(tcb.recv(&mut rbuf));
    }
});
