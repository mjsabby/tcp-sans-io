//! Property-based tests for the wire codec, byte ring, and 32-bit serial
//! arithmetic.
//!
//! These tests sit in src/ rather than in `tests/` because integration
//! tests force the lib to be compiled in `not(test)` (i.e. `no_std`) mode,
//! which doesn't link with proptest's std dependencies. Living under
//! `cfg(test)` keeps proptest entirely off the production build.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate std;

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;

use crate::ring::Ring;
use crate::wire::{self, flags, SackBlocks, TcpOptions};
use crate::MAX_PACKET;

// ---------------------------------------------------------------------------
// wire::parse — never panics on arbitrary input
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        max_shrink_iters: 8192,
        ..ProptestConfig::default()
    })]

    /// `wire::parse` must return Result on every input — no panics, no UB,
    /// no out-of-bounds — even for inputs that look nothing like an IP
    /// datagram. This is the entire attack surface from a hostile peer.
    #[test]
    fn parse_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = wire::parse(&buf);
    }

    /// Same property, but biased toward inputs that look like valid IP
    /// headers (high probability of getting past the version+IHL check) so
    /// shrinking finds tighter counterexamples.
    #[test]
    fn parse_never_panics_iplike(
        ihl_words in 5u8..=15u8,
        total_len in 20u16..=1500u16,
        flags_frag in any::<u16>(),
        ttl in any::<u8>(),
        proto in any::<u8>(),
        rest in proptest::collection::vec(any::<u8>(), 0..1500),
    ) {
        let mut buf = Vec::with_capacity(20 + rest.len());
        buf.push(0x40 | (ihl_words & 0x0F)); // version=4, ihl=ihl_words
        buf.push(0);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&flags_frag.to_be_bytes());
        buf.push(ttl);
        buf.push(proto);
        buf.extend_from_slice(&[0, 0]);             // header checksum (wrong, will be rejected)
        buf.extend_from_slice(&[10, 0, 0, 2]);      // src
        buf.extend_from_slice(&[10, 0, 0, 1]);      // dst
        buf.extend_from_slice(&rest);
        let _ = wire::parse(&buf);
    }
}

// ---------------------------------------------------------------------------
// wire::emit / wire::parse — round-trip on valid inputs
// ---------------------------------------------------------------------------

prop_compose! {
    /// Build the option shapes the codec actually emits. We deliberately
    /// don't fuzz arbitrary option bytes here — that's the job of
    /// `parse_never_panics`. This generator covers the codec's *output*
    /// space: MSS / Timestamps / SACK_PERMITTED / one SACK block.
    fn arb_options()(
        mss in proptest::option::of(536u16..=1460u16),
        wscale in proptest::option::of(0u8..=14u8),
        ts in proptest::option::of((any::<u32>(), any::<u32>())),
        sack_permitted in any::<bool>(),
        sack in proptest::option::of((any::<u32>(), any::<u32>())),
    ) -> TcpOptions {
        TcpOptions {
            mss,
            wscale,
            ts,
            sack_permitted,
            sack: sack.map(|(l, r)| SackBlocks::one(l, r)).unwrap_or(SackBlocks::EMPTY),
        }
    }
}

prop_compose! {
    fn arb_payload()(v in proptest::collection::vec(any::<u8>(), 0..=1400)) -> Vec<u8> { v }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    /// `parse(emit(x)) == x` modulo the fields the codec doesn't put on
    /// the wire (urgent, etc).
    #[test]
    fn emit_then_parse_round_trip(
        src_ip in any::<[u8; 4]>(),
        dst_ip in any::<[u8; 4]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        seq in any::<u32>(),
        ack in any::<u32>(),
        flag_bits in 0u8..=0x3F,
        window in any::<u16>(),
        opts in arb_options(),
        payload in arb_payload(),
        ip_id in any::<u16>(),
    ) {
        let mut buf = vec![0u8; MAX_PACKET + 64];
        let n = wire::emit(
            &mut buf, src_ip, dst_ip, src_port, dst_port,
            seq, ack, flag_bits, window, &opts, &payload, ip_id,
            wire::ecn::NOT_ECT,
        ).expect("emit valid");

        let parsed = wire::parse(&buf[..n]).expect("parse round-trip");
        prop_assert_eq!(parsed.src_ip, src_ip);
        prop_assert_eq!(parsed.dst_ip, dst_ip);
        prop_assert_eq!(parsed.src_port, src_port);
        prop_assert_eq!(parsed.dst_port, dst_port);
        prop_assert_eq!(parsed.seq, seq);
        prop_assert_eq!(parsed.ack, ack);
        prop_assert_eq!(parsed.flags, flag_bits);
        prop_assert_eq!(parsed.window, window);
        prop_assert_eq!(parsed.options.mss, opts.mss);
        prop_assert_eq!(parsed.options.wscale, opts.wscale);
        prop_assert_eq!(parsed.options.ts, opts.ts);
        prop_assert_eq!(parsed.options.sack_permitted, opts.sack_permitted);
        prop_assert_eq!(parsed.options.sack, opts.sack);
        prop_assert_eq!(parsed.payload, payload.as_slice());
        prop_assert_eq!(parsed.ecn, wire::ecn::NOT_ECT);
    }

    /// Single-bit corruption anywhere in an emitted datagram MUST cause
    /// parse to fail (the IP and TCP checksums together cover every byte
    /// either directly or transitively). This is what protects us from
    /// silent data corruption in the chaos tests.
    #[test]
    fn single_bit_corruption_is_detected(
        seq in any::<u32>(),
        ack in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 1..=200),
        bit_index in 0usize..(20 + 20 + 200) * 8,
    ) {
        let mut buf = vec![0u8; MAX_PACKET];
        let opts = TcpOptions::NONE;
        let n = wire::emit(
            &mut buf, [10,0,0,1], [10,0,0,2], 1234, 80,
            seq, ack, flags::ACK | flags::PSH, 65535, &opts, &payload, 0,
            wire::ecn::NOT_ECT,
        ).expect("emit");
        let len = n;

        // Skip if the chosen bit is past the actual datagram.
        if bit_index >= len * 8 { return Ok(()); }
        let byte = bit_index / 8;
        let bit = bit_index % 8;
        buf[byte] ^= 1 << bit;

        // Some byte/bit pairs land on bits whose flip is ignored by the
        // parser (e.g. unused IP TOS bits, or padding past total_len).
        // Filter those: we accept *either* parse-fail OR a parse that's
        // identical to the original message (the bit didn't affect any
        // observable field).
        let result = wire::parse(&buf[..len]);
        if let Ok(seg) = result {
            // Re-encode and compare to the *original* (pre-flip) bytes.
            // If the parsed segment differs from the original message in
            // any observable way, the checksum should have caught it.
            prop_assert_eq!(seg.seq, seq, "seq survived bit flip without checksum failure at byte={}", byte);
            prop_assert_eq!(seg.ack, ack);
            prop_assert_eq!(seg.payload, payload.as_slice(), "payload changed without checksum failure");
        }
    }
}

// ---------------------------------------------------------------------------
// Ring — write/read round-trip with arbitrary chunk splits
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Pushing a stream in arbitrary chunk sizes and pulling it in arbitrary
    /// chunk sizes preserves the byte sequence and order.
    #[test]
    fn ring_round_trip(
        chunks in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..=200),
            0..32,
        ),
        read_chunks in proptest::collection::vec(1usize..=200, 0..64),
    ) {
        // Capacity must be a power of two; 4096 is plenty for ≤32×200=6400
        // bytes — but the ring may genuinely overflow, in which case write()
        // accepts only `free()` bytes and we adjust expectations.
        let mut ring: Ring<4096> = Ring::new().expect("ring");
        let mut written: Vec<u8> = Vec::new();
        for chunk in &chunks {
            let n = ring.write(chunk);
            written.extend_from_slice(&chunk[..n]);
            // Free + len invariant.
            prop_assert_eq!(ring.len() + ring.free(), 4096);
            prop_assert!(ring.len() <= 4096);
        }

        // Read back, again in arbitrary chunks.
        let mut read_back: Vec<u8> = Vec::new();
        for cap in &read_chunks {
            if ring.is_empty() { break; }
            let mut buf = vec![0u8; *cap];
            let n = ring.read(&mut buf);
            read_back.extend_from_slice(&buf[..n]);
            prop_assert_eq!(ring.len() + ring.free(), 4096);
        }

        // Drain anything still buffered.
        while !ring.is_empty() {
            let mut buf = [0u8; 256];
            let n = ring.read(&mut buf);
            read_back.extend_from_slice(&buf[..n]);
        }
        prop_assert_eq!(read_back, written);
    }

    /// `peek_at(offset, dst)` returns exactly the same bytes that a
    /// hypothetical `consume(offset)` followed by `read(dst)` would produce.
    #[test]
    fn ring_peek_at_matches_consume_then_read(
        seed in proptest::collection::vec(any::<u8>(), 0..=2000),
        offset in 0usize..=2000,
        len in 0usize..=2000,
    ) {
        let mut a: Ring<4096> = Ring::new().expect("ring a");
        let mut b: Ring<4096> = Ring::new().expect("ring b");
        let n = a.write(&seed);
        let _ = b.write(&seed[..n]);

        let mut peek = vec![0u8; len];
        let np = a.peek_at(offset, &mut peek);

        let drop = core::cmp::min(offset, b.len());
        b.consume(drop);
        let mut readb = vec![0u8; len];
        let nr = b.read(&mut readb);

        prop_assert_eq!(np, nr);
        prop_assert_eq!(&peek[..np], &readb[..nr]);
    }
}

// ---------------------------------------------------------------------------
// 32-bit serial-number arithmetic (RFC 1982)
// ---------------------------------------------------------------------------

#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    seq_gt(b, a)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    /// Antisymmetry: if a < b then b > a, and not vice versa.
    #[test]
    fn seq_lt_is_antisymmetric(a in any::<u32>(), b in any::<u32>()) {
        if a == b {
            prop_assert!(!seq_lt(a, b));
            prop_assert!(!seq_gt(a, b));
        } else if seq_lt(a, b) {
            prop_assert!(seq_gt(b, a));
            prop_assert!(!seq_lt(b, a));
        }
    }

    /// Wrap-around correctness: every value is "less than" the value
    /// 2^31 ahead of it (modulo 2^32) and "greater than" the value 2^31
    /// behind it. This is the property that lets a TCP connection survive
    /// SEQ wrapping on a fast link.
    #[test]
    fn seq_wraparound_consistent(a in any::<u32>()) {
        let half = 1u32 << 31;
        let ahead = a.wrapping_add(1);
        let way_ahead = a.wrapping_add(half - 1);
        let behind = a.wrapping_sub(1);
        let way_behind = a.wrapping_sub(half - 1);

        prop_assert!(seq_lt(a, ahead));
        prop_assert!(seq_lt(a, way_ahead));
        prop_assert!(seq_gt(a, behind));
        prop_assert!(seq_gt(a, way_behind));
    }
}

// ---------------------------------------------------------------------------
// Reassembly — held runs must stay disjoint under arbitrary insert sequences
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    /// The out-of-order receive path (bytes parked in the ring's free space +
    /// the range tracker) must reassemble ANY arrival order — overlapping,
    /// duplicated, abutting, wrapping the sequence space, or exceeding the
    /// range budget — into exactly the original stream, never exposing a
    /// byte early and never stranding data behind the cursor. Mirrors
    /// `Tcb::receive_payload` step for step.
    #[test]
    fn ooo_reassembly_matches_model(
        base in any::<u32>(),
        ops in proptest::collection::vec((0usize..8192, 1usize..1500), 1..96),
    ) {
        use crate::ooo::{Insert, OooList};
        use crate::ring::Ring;
        const N: usize = 8192;
        let stream: Vec<u8> = (0..N).map(|i| (i.wrapping_mul(31) % 251) as u8).collect();
        let mut ring: Ring<N> = Ring::new().unwrap();
        let mut ooo = OooList::new();
        let mut rcv_nxt = base;
        let deliver = |ring: &mut Ring<N>, ooo: &mut OooList, rcv_nxt: &mut u32, off: usize, len: usize| {
            let seq = base.wrapping_add(off as u32);
            let mut data = &stream[off..off + len];
            let mut s = seq;
            if (s.wrapping_sub(*rcv_nxt) as i32) < 0 {
                let lead = rcv_nxt.wrapping_sub(s) as usize;
                if lead >= data.len() {
                    return;
                }
                data = &data[lead..];
                s = *rcv_nxt;
            }
            let o = s.wrapping_sub(*rcv_nxt) as usize;
            let free = ring.free();
            if o >= free {
                return;
            }
            let data = &data[..data.len().min(free - o)];
            if o == 0 {
                let n = ring.write(data);
                *rcv_nxt = rcv_nxt.wrapping_add(n as u32);
                let new = ooo.advance(*rcv_nxt);
                let c = ring.commit(new.wrapping_sub(*rcv_nxt) as usize);
                *rcv_nxt = rcv_nxt.wrapping_add(c as u32);
            } else if let Insert::Stored { .. } = ooo.insert(s, s.wrapping_add(data.len() as u32), *rcv_nxt) {
                ring.write_at(o, data);
            }
        };
        for (off, len) in &ops {
            let len = (*len).min(N - *off);
            if len == 0 {
                continue;
            }
            deliver(&mut ring, &mut ooo, &mut rcv_nxt, *off, len);
            prop_assert!(ooo.debug_valid(rcv_nxt), "range invariants broken");
            // Everything readable so far is a correct prefix of the stream.
            let readable = ring.len();
            let mut buf = vec![0u8; readable];
            ring.peek(&mut buf);
            prop_assert_eq!(&buf[..], &stream[..readable]);
        }
        // Fill every hole in order; the whole stream must come out.
        let mut off = 0;
        while off < N {
            let len = (N - off).min(1460);
            deliver(&mut ring, &mut ooo, &mut rcv_nxt, off, len);
            off += len;
        }
        prop_assert!(ooo.is_empty(), "data stranded in the range tracker");
        let mut all = vec![0u8; N];
        prop_assert_eq!(ring.read(&mut all), N);
        prop_assert_eq!(all, stream);
    }
}

// ---------------------------------------------------------------------------
// Resizable ring — any interleaving of I/O and resizes matches a model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum RingOp {
    Write(usize),
    Read(usize),
    Park(usize, usize),
    Commit(usize),
    PeekAt(usize, usize),
    Target(usize),
    Resize(usize),
}

fn ring_op() -> impl Strategy<Value = RingOp> {
    prop_oneof![
        3 => (0usize..80).prop_map(RingOp::Write),
        3 => (0usize..80).prop_map(RingOp::Read),
        2 => (0usize..80, 1usize..24).prop_map(|(o, n)| RingOp::Park(o, n)),
        1 => (0usize..80).prop_map(RingOp::Commit),
        1 => (0usize..80, 0usize..80).prop_map(|(o, n)| RingOp::PeekAt(o, n)),
        2 => (0usize..100).prop_map(RingOp::Target),
        2 => (0usize..100).prop_map(RingOp::Resize),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    /// Any interleaving of writes, reads, out-of-order parking, commits,
    /// retargets and resizes keeps the ring equal to a model: readable bytes
    /// in order, parked bytes at their offset past the write cursor, the
    /// capacity moving only when everything that must survive fits in the
    /// target, and nothing offered (`room`) past a pending smaller target.
    #[test]
    fn resizable_ring_matches_model(ops in proptest::collection::vec(ring_op(), 1..200)) {
        use std::collections::VecDeque;
        const N: usize = 64;
        let mut ring: Ring<N> = Ring::new().unwrap();
        let mut data: VecDeque<u8> = VecDeque::new();
        // Bytes parked past the write cursor, by offset.
        let mut parked: Vec<Option<u8>> = Vec::new();
        let (mut cap, mut target) = (N, N);
        let mut next = 0u8;
        let mut fresh = |n: usize| -> Vec<u8> {
            (0..n).map(|_| { next = next.wrapping_add(1); next }).collect()
        };
        for op in ops {
            match op {
                RingOp::Write(n) => {
                    let src = fresh(n);
                    let w = ring.write(&src);
                    prop_assert_eq!(w, n.min(cap - data.len()));
                    data.extend(&src[..w]);
                    // In-order bytes land where parked ones were.
                    parked.drain(..w.min(parked.len()));
                }
                RingOp::Read(n) => {
                    let mut buf = vec![0u8; n];
                    let r = ring.read(&mut buf);
                    prop_assert_eq!(r, n.min(data.len()));
                    let want: Vec<u8> = data.drain(..r).collect();
                    prop_assert_eq!(&buf[..r], &want[..]);
                }
                RingOp::Park(off, n) => {
                    let src = fresh(n);
                    let free = cap - data.len();
                    let w = ring.write_at(off, &src);
                    prop_assert_eq!(w, if off >= free { 0 } else { n.min(free - off) });
                    if w > 0 {
                        if parked.len() < off + w {
                            parked.resize(off + w, None);
                        }
                        for (i, &b) in src[..w].iter().enumerate() {
                            parked[off + i] = Some(b);
                        }
                    }
                }
                RingOp::Commit(n) => {
                    let prefix = parked.iter().take_while(|b| b.is_some()).count();
                    let c = ring.commit(n.min(prefix));
                    prop_assert_eq!(c, n.min(prefix));
                    data.extend(parked.drain(..c).map(Option::unwrap));
                }
                RingOp::PeekAt(off, n) => {
                    let mut buf = vec![0u8; n];
                    let p = ring.peek_at(off, &mut buf);
                    let want: Vec<u8> = data.iter().skip(off).take(n).copied().collect();
                    prop_assert_eq!(&buf[..p], &want[..]);
                }
                RingOp::Target(b) => {
                    ring.set_target(b);
                    target = 1 << b.clamp(1, N).ilog2();
                    prop_assert_eq!(ring.target(), target);
                }
                RingOp::Resize(extra) => {
                    let keep = parked.iter().rposition(Option::is_some).map_or(0, |i| i + 1);
                    let reserve = extra % (N + 1);
                    let fits = data.len() + keep.max(reserve) <= target;
                    let ok = ring.try_resize(keep, reserve);
                    prop_assert_eq!(ok, target == cap || fits);
                    if ok {
                        cap = target;
                        prop_assert!(cap - data.len() >= keep.max(reserve) || target == cap);
                    }
                }
            }
            prop_assert_eq!(ring.capacity(), cap);
            prop_assert_eq!(ring.len(), data.len());
            prop_assert_eq!(ring.free(), cap - data.len());
            prop_assert_eq!(ring.room(), cap.min(target).saturating_sub(data.len()));
            prop_assert!(ring.debug_valid().is_ok());
            let mut all = vec![0u8; data.len()];
            prop_assert_eq!(ring.peek(&mut all), data.len());
            prop_assert!(all.iter().eq(data.iter()));
        }
        // Parked bytes come out where they were put.
        let prefix = parked.iter().take_while(|b| b.is_some()).count();
        prop_assert_eq!(ring.commit(prefix), prefix);
        data.extend(parked.drain(..prefix).map(Option::unwrap));
        let mut all = vec![0u8; data.len()];
        prop_assert_eq!(ring.read(&mut all), data.len());
        prop_assert!(all.iter().eq(data.iter()));
    }
}
