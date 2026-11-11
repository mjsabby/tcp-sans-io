//! Loss recovery against a peer without SACK (NewReno, RFC 6582).

use super::*;

/// What a lossy transfer to a scripted receiver cost.
#[derive(Debug, Default, Clone, Copy)]
struct Cost {
    /// Data segments the path dropped.
    drops: u32,
    /// Segments retransmitted, and those among them whose bytes the
    /// receiver already held in full when they left.
    retrans: u32,
    needless: u32,
    fast_recoveries: u32,
    rtos: u32,
    done_ms: u64,
}

/// Send `total` bytes to a receiver without SACK or timestamps that ACKs
/// every segment at once (a duplicate ACK for each one out of order), over
/// a 20 ms round trip dropping `loss_pct` percent of packets each way.
fn lossy_transfer(seed: u64, total: usize, loss_pct: u64) -> Cost {
    let mut x = seed | 1;
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let (mut c, iss) = client();
    drain(&mut c);
    c.set_now(10);
    let synack = pkt(
        SRV,
        A,
        5000,
        iss + 1,
        flags::SYN | flags::ACK,
        65535,
        &syn_opts(None, false, None),
        &[],
    );
    c.inject_packet(&synack).unwrap();
    drain(&mut c);
    let base = iss.wrapping_add(1);
    let data: Vec<u8> = (0..total).map(|i| (i * 31 % 251) as u8).collect();
    let mut have = vec![false; total];
    let mut rcv_nxt = 0usize; // offset from `base`
    let mut queued = 0usize;
    // (arrival time, offset, len) toward the receiver; (time, ack) back.
    let mut to_rcv: Vec<(u64, usize, usize)> = Vec::new();
    let mut to_snd: Vec<(u64, u32)> = Vec::new();
    let mut cost = Cost::default();
    let mut now = 10u64;
    while rcv_nxt < total {
        now += 1;
        assert!(now < 3_600_000, "stalled: {cost:?}");
        c.set_now(now);
        // The receiver takes what arrives, in order, and ACKs each segment.
        while to_rcv.first().is_some_and(|&(t, _, _)| t <= now) {
            let (_, off, len) = to_rcv.remove(0);
            have[off..off + len].iter_mut().for_each(|b| *b = true);
            while rcv_nxt < total && have[rcv_nxt] {
                rcv_nxt += 1;
            }
            if rnd(100) >= loss_pct {
                to_snd.push((now + 10, base.wrapping_add(rcv_nxt as u32)));
            }
        }
        while to_snd.first().is_some_and(|&(t, _)| t <= now) {
            let (_, ack) = to_snd.remove(0);
            let p = pkt(SRV, A, 5001, ack, flags::ACK, 65535, &TcpOptions::NONE, &[]);
            c.inject_packet(&p).unwrap();
        }
        if queued < total {
            queued += c.send(&data[queued..]).unwrap_or(0);
        }
        c.tick().unwrap();
        c.debug_validate_invariants().unwrap();
        let mut buf = [0u8; MAX_PACKET];
        loop {
            let n = c.extract_packet(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            let s = wire::parse(&buf[..n]).unwrap();
            if s.payload.is_empty() {
                continue;
            }
            let off = s.seq.wrapping_sub(base) as usize;
            let len = s.payload.len();
            assert_eq!(s.payload, &data[off..off + len], "wrong bytes on the wire");
            if have[off..off + len].iter().all(|&b| b) {
                cost.needless += 1;
            }
            if rnd(100) < loss_pct {
                cost.drops += 1;
            } else {
                to_rcv.push((now + 10, off, len));
            }
        }
    }
    let st = c.stats();
    cost.retrans = st.segs_retrans as u32;
    cost.fast_recoveries = st.fast_recoveries;
    cost.rtos = st.rto_count;
    cost.done_ms = now;
    cost
}

/// After a timeout, late duplicate ACKs for segments sent before it used
/// to be credited as deliveries, clocking out copies of data the receiver
/// already held; the duplicate ACKs those copies drew arrived just as the
/// episode ended and started a spurious fast recovery (the problem RFC
/// 6582's `recover` test exists for). Against a peer without SACK the
/// stack retransmitted nearly twice what the path had dropped.
#[test]
fn recovery_without_sack_does_not_resend_what_the_receiver_holds() {
    let mut sum = Cost::default();
    for seed in 1..=40u64 {
        let c = lossy_transfer(seed * 0x9E37_79B9, 400_000, 5);
        sum.drops += c.drops;
        sum.retrans += c.retrans;
        sum.needless += c.needless;
        sum.fast_recoveries += c.fast_recoveries;
        sum.rtos += c.rtos;
        sum.done_ms += c.done_ms;
    }
    std::eprintln!("non-SACK, 5% loss, 40 x 400 KB: {sum:?}");
    assert!(sum.drops > 400, "the path dropped data: {sum:?}");
    assert!(
        sum.retrans * 10 <= sum.drops * 13,
        "retransmissions far beyond what was lost: {sum:?}"
    );
    assert!(
        sum.needless * 5 <= sum.drops,
        "needless retransmissions: {sum:?}"
    );
}
