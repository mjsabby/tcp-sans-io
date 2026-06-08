//! Fuzz `Tcb::inject_packet` against arbitrary byte streams.
//!
//! Splits the fuzzer input into ≤ MAX_PACKET-sized chunks and feeds
//! each one through `inject_packet` on a fresh Tcb (started in
//! Listen). The Tcb must never panic on any input — internal errors
//! are fine but UB / panics / infinite loops are bugs.
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

const LOCAL_IP: [u8; 4] = [10, 0, 0, 1];
const PEER_IP: [u8; 4] = [10, 0, 0, 2];

fn make_tcb() -> Tcb {
    Tcb::new(TcbConfig {
        local: Endpoint { ip: LOCAL_IP, port: 8080 },
        remote: Endpoint { ip: PEER_IP, port: 0 },
        iss: 0xDEAD_BEEF,
        initial_rto_ms: 1000,
    })
    .unwrap()
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
        let _ = no_internal(tcb.inject_packet(chunk));
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
                    assert_eq!(
                        seg.src_port, 8080,
                        "emitted packet has wrong source port"
                    );
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
    }
});
