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
//! Oracle: `TcpError::Overflow` is an *internal* invariant-violation
//! code (a buffer offset/length computed from sequence arithmetic went
//! out of range). It must be unreachable from any inbound packet or
//! timer tick, so we treat it as a hard failure rather than swallowing
//! it like the legitimate protocol errors (`NotForUs`, `MalformedPacket`,
//! `WouldBlock`, …). This is the check that would have caught the TLP
//! partial-ACK `tcp_tick: -9` regression.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::{Endpoint, Tcb, TcbConfig, TcpError};

/// Panic iff a call surfaced the internal `Overflow` invariant code.
#[track_caller]
fn assert_not_overflow<T>(r: Result<T, TcpError>) {
    if let Err(TcpError::Overflow) = r {
        panic!("internal TcpError::Overflow escaped across the API boundary");
    }
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
    let mut now_ms: u64 = 0;
    tcb.set_now(now_ms);

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
        assert_not_overflow(tcb.inject_packet(chunk));
        // Drain any reply packets the stack staged.
        let mut out = [0u8; 1500];
        for _ in 0..32 {
            let r = tcb.extract_packet(&mut out);
            assert_not_overflow(r);
            match r {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
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
        assert_not_overflow(tcb.tick());
    }
});
