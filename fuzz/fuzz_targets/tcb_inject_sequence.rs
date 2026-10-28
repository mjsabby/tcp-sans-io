//! Fuzz the TCB against arbitrary byte streams.
//!
//! Splits the fuzzer input into ≤ MAX_PACKET-sized chunks and feeds
//! each one into a fresh Tcb (started in Listen). The Tcb must never
//! panic on any input — internal errors are fine but UB / panics /
//! infinite loops are bugs.
//!
//! Raw mutations essentially never satisfy both the IPv4 header checksum
//! and the TCP checksum, so a chunk that looks like an IPv4/TCP header is
//! first addressed to the TCB's local endpoint and given a correct IPv4
//! header checksum, and is injected through the checksum-trusting entry
//! point (`inject_packet_l4_csum_trusted`). Everything after the fixed
//! header bytes — flags, sequence numbers, options, payload — is still
//! raw fuzzer data, so the whole acceptance path is reachable rather than
//! only the parser's reject branch.
//!
//! Between injects we also tick the clock forward so timer paths
//! get exercised against the injected segments.
//!
//! Oracles:
//! * internal errors (`Overflow`, `BufferTooSmall` with harness-sized
//!   buffers) must never escape the API,
//! * the TCB's own debug invariants must hold after every operation,
//! * every emitted packet must parse and must come from the local endpoint,
//! * output per step is bounded (no ACK/output storm),
//! * state transitions must stay on legal TCP edges.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::wire;
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError, MAX_PACKET};

/// Panic iff a call surfaced an internal invariant code.
#[track_caller]
fn no_internal<T>(r: Result<T, TcpError>) -> Result<T, TcpError> {
    match r {
        Err(TcpError::Overflow) => {
            panic!("internal TcpError::Overflow escaped across the API boundary")
        }
        Err(TcpError::BufferTooSmall) => {
            panic!("internal TcpError::BufferTooSmall escaped with MAX_PACKET buffers")
        }
        other => other,
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

/// Livelock oracle: at a fixed clock with nothing injected, the stack must
/// stop emitting within a bounded number of tick+drain cycles. A spin here
/// would otherwise hang the process with no crash artifact.
fn settle(tcb: &mut Tcb, prev: &mut State) {
    for _ in 0..4096 {
        let _ = no_internal(tcb.tick());
        observe_state(prev, tcb);
        let mut out = [0u8; MAX_PACKET];
        let mut emitted = false;
        for _ in 0..256 {
            match no_internal(tcb.extract_packet(&mut out)) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    emitted = true;
                    observe_state(prev, tcb);
                }
            }
        }
        if !emitted {
            return;
        }
    }
    panic!("livelock: stack never quiesced at a fixed clock with no input");
}

/// Monotonic-progress oracle for the cumulative cursors. Only enforced
/// while the connection stays synchronized: a listener that reverted to
/// LISTEN (RST, SYN-ACK budget, half-open replacement) and accepted a new
/// SYN legitimately starts a new sequence space.
#[track_caller]
fn assert_monotonic(prev: &mut Option<(u32, u32)>, tcb: &Tcb) {
    let s = tcb.debug_snapshot();
    if !tcb.state().is_synchronized() {
        *prev = None;
        return;
    }
    let Some(p) = *prev else {
        *prev = Some((s.snd_una, s.rcv_nxt));
        return;
    };
    assert!(
        (s.snd_una.wrapping_sub(p.0) as i32) >= 0,
        "snd_una regressed: {} -> {}",
        p.0,
        s.snd_una,
    );
    assert!(
        (s.rcv_nxt.wrapping_sub(p.1) as i32) >= 0,
        "rcv_nxt regressed: {} -> {}",
        p.1,
        s.rcv_nxt,
    );
    *prev = Some((s.snd_una, s.rcv_nxt));
}

const LOCAL_IP: [u8; 4] = [10, 0, 0, 1];
const PEER_IP: [u8; 4] = [10, 0, 0, 2];

/// Point a chunk that starts like an IPv4/TCP datagram at the TCB's local
/// endpoint and give it a valid IPv4 header checksum. Anything that is not
/// shaped like one is left alone (the parser must reject it cleanly).
fn address_to_local(p: &mut [u8]) {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return;
    }
    let ihl = usize::from(p[0] & 0x0F) * 4;
    if ihl < 20 || p.len() < ihl + 4 {
        return;
    }
    p[9] = 6; // TCP
    p[16..20].copy_from_slice(&LOCAL_IP);
    p[ihl + 2..ihl + 4].copy_from_slice(&8080u16.to_be_bytes());
    p[10] = 0;
    p[11] = 0;
    let mut sum = 0u32;
    for w in p[..ihl].chunks(2) {
        sum += u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

fn make_tcb() -> Tcb {
    let mut tcb = Tcb::new(TcbConfig {
        local: Endpoint {
            ip: LOCAL_IP,
            port: 8080,
        },
        remote: Endpoint {
            ip: PEER_IP,
            port: 0,
        },
        iss: 0xDEAD_BEEF,
        initial_rto_ms: 1000,
    })
    .unwrap();
    // The harness jumps the clock arbitrarily; disable the on-by-default
    // wall-clock aborts (USER TIMEOUT and keepalive) so neither can fire mid-
    // sequence on the compressed virtual clock (both are unit-tested separately).
    tcb.set_user_timeout(0);
    tcb.set_keepalive(0, 0, 0);
    tcb
}

fuzz_target!(|data: &[u8]| {
    let mut tcb = make_tcb();
    if tcb.listen().is_err() {
        return;
    }
    let mut prev_state = State::Closed;
    observe_state(&mut prev_state, &tcb);
    let mut now_ms: u64 = 0;
    tcb.set_now(now_ms);
    check(&tcb);
    let mut mono: Option<(u32, u32)> = None;

    // Chunk the input as (length-prefixed) packets. Use the first
    // byte of each chunk as length-1 (so chunk lengths are 1..256
    // bytes — short enough to fit within MAX_PACKET, long enough to
    // be a credible TCP segment).
    let mut i = 0;
    while i < data.len() {
        let want = (data[i] as usize) + 1;
        i += 1;
        let take = want.min(data.len() - i);
        let chunk = &data[i..i + take];
        i += take;

        // Inject. Errors are fine (malformed / not-for-us) — except the
        // internal Overflow code, which signals a sequence-arithmetic
        // buffer-bounds bug.
        let mut pkt = chunk.to_vec();
        address_to_local(&mut pkt);
        let _ = no_internal(tcb.inject_packet_l4_csum_trusted(&pkt));
        observe_state(&mut prev_state, &tcb);
        // Drain any reply packets the stack staged.
        let mut out = [0u8; MAX_PACKET];
        let mut drained = 0u32;
        for _ in 0..32 {
            let r = no_internal(tcb.extract_packet(&mut out));
            match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    drained += 1;
                    let seg = wire::parse(&out[..n]).expect("self-emitted packet must parse");
                    assert_eq!(seg.src_ip, LOCAL_IP, "emitted packet has wrong source IP");
                    assert_eq!(seg.src_port, 8080, "emitted packet has wrong source port");
                }
            }
            observe_state(&mut prev_state, &tcb);
        }
        if drained == 32 {
            match no_internal(tcb.extract_packet(&mut out)) {
                Ok(0) | Err(_) => {}
                Ok(_) => panic!("unbounded output: more than 32 packets in one fuzz step"),
            }
        }
        // Advance time. Use the next byte (if any) as a 0..=255 ms
        // delta so we cover a variety of timer-firing windows.
        let delta = if i < data.len() {
            let d = data[i] as u64;
            i += 1;
            d
        } else {
            1
        };
        now_ms = now_ms.saturating_add(delta);
        tcb.set_now(now_ms);
        check(&tcb);
        let _ = no_internal(tcb.tick());
        observe_state(&mut prev_state, &tcb);

        // Livelock + monotonic oracles at the (now fixed) clock.
        settle(&mut tcb, &mut prev_state);
        assert_monotonic(&mut mono, &tcb);
    }
});
