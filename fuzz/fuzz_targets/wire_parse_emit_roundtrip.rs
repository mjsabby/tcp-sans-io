//! Fuzz `wire::emit` ∘ `wire::parse` round-trip invariants.
//!
//! For any successfully-parsed packet, re-emitting it with the SAME
//! 5-tuple, seq/ack/flags/window/options/payload should produce a
//! packet that re-parses to a Segment with the same logical fields
//! (modulo IP ID, which the emitter assigns).
//!
//! We don't require BYTEWISE equality of the re-emit — different
//! option orderings or NOP padding choices are wire-legal differences
//! that don't matter to TCP semantics. We do require the SECOND
//! parse to succeed and produce the same observable state.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::wire::{self, ecn};

fuzz_target!(|data: &[u8]| {
    // Pass 1: parse arbitrary input.
    let seg = match wire::parse(data) {
        Ok(s) => s,
        Err(_) => return, // not a valid packet — nothing to round-trip
    };

    // Re-emit the parsed segment with the same logical fields.
    let mut buf = [0u8; 1500];
    let n = match wire::emit(
        &mut buf,
        seg.src_ip,
        seg.dst_ip,
        seg.src_port,
        seg.dst_port,
        seg.seq,
        seg.ack,
        seg.flags,
        seg.window,
        &seg.options,
        seg.payload,
        0, // ip_id — we don't compare
        ecn::NOT_ECT,
    ) {
        Ok(n) => n,
        Err(_) => return, // legitimate emit failure (e.g., payload too big after options)
    };

    // Pass 2: parse the re-emitted buffer.
    let seg2 = match wire::parse(&buf[..n]) {
        Ok(s) => s,
        Err(e) => panic!("re-parse failed: {:?}", e),
    };

    // Invariants that must hold across the round trip.
    assert_eq!(seg.src_ip, seg2.src_ip, "src_ip changed");
    assert_eq!(seg.dst_ip, seg2.dst_ip, "dst_ip changed");
    assert_eq!(seg.src_port, seg2.src_port, "src_port changed");
    assert_eq!(seg.dst_port, seg2.dst_port, "dst_port changed");
    assert_eq!(seg.seq, seg2.seq, "seq changed");
    assert_eq!(seg.ack, seg2.ack, "ack changed");
    assert_eq!(seg.flags, seg2.flags, "flags changed");
    assert_eq!(seg.window, seg2.window, "window changed");
    assert_eq!(seg.payload, seg2.payload, "payload changed");
    // Option semantics: each option that the first parse identified
    // must reappear in the re-parse.
    assert_eq!(seg.options.mss, seg2.options.mss, "MSS option changed");
    assert_eq!(seg.options.wscale, seg2.options.wscale, "WSCALE option changed");
    assert_eq!(seg.options.ts, seg2.options.ts, "TS option changed");
    assert_eq!(seg.options.sack_permitted, seg2.options.sack_permitted, "SACK_PERMITTED changed");
    // SACK blocks: same count + same ranges.
    assert_eq!(
        seg.options.sack.as_slice(),
        seg2.options.sack.as_slice(),
        "SACK blocks changed",
    );
});
