//! Loss recovery measured against a scripted receiver: a bulk sender, a
//! receiver that ACKs every segment at once (a duplicate ACK for each one
//! out of order) and sends no SACK, over a path that keeps packets in
//! order. The path can drop packets, stall, and change its delay.

use super::*;

/// The path and the peer of one transfer.
#[derive(Clone, Copy)]
struct Path {
    seed: u64,
    /// Bytes to transfer; the run also ends at `stop_ms`.
    total: usize,
    stop_ms: u64,
    /// Percent of packets dropped, each way.
    loss_pct: u64,
    /// One-way delay, and a later value it steps to at a given time.
    delay_ms: u64,
    step: Option<(u64, u64)>,
    /// Nothing is delivered from `.0` for `.1` ms (order is kept).
    stall: Option<(u64, u64)>,
    /// The peer uses timestamps.
    ts: bool,
    /// The peer offers a 1 MiB window (window scaling) instead of 64 KiB.
    big_window: bool,
}

impl Path {
    const fn new(seed: u64, total: usize) -> Self {
        Self {
            seed,
            total,
            stop_ms: 3_600_000,
            loss_pct: 0,
            delay_ms: 10,
            step: None,
            stall: None,
            ts: false,
            big_window: false,
        }
    }

    /// When a packet leaving at `now` arrives, behind `last` (FIFO).
    fn arrival(&self, now: u64, last: u64) -> u64 {
        let delay = match self.step {
            Some((at, d)) if now >= at => d,
            _ => self.delay_ms,
        };
        let mut t = (now + delay).max(last);
        if let Some((at, len)) = self.stall {
            if (at..at + len).contains(&t) {
                t = at + len;
            }
        }
        t
    }
}

/// What a transfer cost.
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
    /// Bytes delivered in order, when the run ended, and SRTT then.
    delivered: usize,
    done_ms: u64,
    srtt_ms: u32,
}

fn byte_at(i: usize) -> u8 {
    (i * 31 % 251) as u8
}

fn transfer(p: Path) -> Cost {
    let mut x = p.seed | 1;
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let (mut c, iss) = client();
    let syn = drain(&mut c).remove(0);
    c.set_now(10);
    let mut o = syn_opts(None, false, None);
    let win = if p.big_window {
        o.wscale = Some(7);
        8192 // << 7: 1 MiB
    } else {
        65535
    };
    if p.ts {
        o.ts = Some((1, syn.opts.ts.unwrap().0));
    }
    c.inject_packet(&pkt(
        SRV,
        A,
        5000,
        iss + 1,
        flags::SYN | flags::ACK,
        win,
        &o,
        &[],
    ))
    .unwrap();
    drain(&mut c);
    let base = iss.wrapping_add(1);
    let mut have = vec![false; p.total];
    let mut rcv_nxt = 0usize; // offset from `base`
    let mut queued = 0usize;
    let mut ts_recent = 0u32;
    // (arrival, offset, len, TSval) toward the receiver; (arrival, ack,
    // TSecr) back. Both stay in arrival order.
    let mut to_rcv: std::collections::VecDeque<(u64, usize, usize, u32)> = Default::default();
    let mut to_snd: std::collections::VecDeque<(u64, u32, u32)> = Default::default();
    let (mut last_fwd, mut last_back) = (0u64, 0u64);
    let mut cost = Cost::default();
    let mut chunk = [0u8; 8192];
    let mut now = 10u64;
    while rcv_nxt < p.total && now < p.stop_ms {
        now += 1;
        c.set_now(now);
        // The receiver takes what arrives, in order, and ACKs each segment.
        while to_rcv.front().is_some_and(|&(t, ..)| t <= now) {
            let (_, off, len, tsval) = to_rcv.pop_front().unwrap();
            if off <= rcv_nxt {
                ts_recent = tsval; // RFC 7323 §4.3: covers the left edge
            }
            have[off..off + len].iter_mut().for_each(|b| *b = true);
            while rcv_nxt < p.total && have[rcv_nxt] {
                rcv_nxt += 1;
            }
            if rnd(100) >= p.loss_pct {
                last_back = p.arrival(now, last_back);
                to_snd.push_back((last_back, base.wrapping_add(rcv_nxt as u32), ts_recent));
            }
        }
        while to_snd.front().is_some_and(|&(t, ..)| t <= now) {
            let (_, ack, tsecr) = to_snd.pop_front().unwrap();
            let o = if p.ts {
                ts(now as u32, tsecr)
            } else {
                TcpOptions::NONE
            };
            c.inject_packet(&pkt(SRV, A, 5001, ack, flags::ACK, win, &o, &[]))
                .unwrap();
        }
        while queued < p.total {
            let n = chunk.len().min(p.total - queued);
            for (k, b) in chunk[..n].iter_mut().enumerate() {
                *b = byte_at(queued + k);
            }
            let w = c.send(&chunk[..n]).unwrap_or(0);
            queued += w;
            if w < n {
                break;
            }
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
            assert!(
                s.payload
                    .iter()
                    .enumerate()
                    .all(|(k, &b)| b == byte_at(off + k)),
                "wrong bytes on the wire at {off}"
            );
            if have[off..off + len].iter().all(|&b| b) {
                cost.needless += 1;
            }
            if rnd(100) < p.loss_pct {
                cost.drops += 1;
            } else {
                last_fwd = p.arrival(now, last_fwd);
                let tsval = s.options.ts.map_or(0, |(v, _)| v);
                to_rcv.push_back((last_fwd, off, len, tsval));
            }
        }
    }
    let st = c.stats();
    cost.retrans = st.segs_retrans as u32;
    cost.fast_recoveries = st.fast_recoveries;
    cost.rtos = st.rto_count;
    cost.delivered = rcv_nxt;
    cost.done_ms = now;
    cost.srtt_ms = st.srtt_ms;
    cost
}

fn sum(costs: impl Iterator<Item = Cost>) -> Cost {
    costs.fold(Cost::default(), |mut a, c| {
        a.drops += c.drops;
        a.retrans += c.retrans;
        a.needless += c.needless;
        a.fast_recoveries += c.fast_recoveries;
        a.rtos += c.rtos;
        a.delivered += c.delivered;
        a.done_ms += c.done_ms;
        a
    })
}

/// After a timeout, the first ACK often jumps over data the receiver held
/// all along. Counting those bytes grew the window at once, and duplicate
/// ACKs for segments sent before the timeout were credited as deliveries:
/// together they released a burst of copies of segments the receiver held
/// too. Against a peer without SACK the stack resent nearly twice what the
/// path had dropped.
#[test]
fn lossy_path_without_sack_resends_little_the_receiver_holds() {
    let s = sum((1..=40u64).map(|seed| {
        transfer(Path {
            loss_pct: 5,
            ..Path::new(seed, 400_000)
        })
    }));
    std::eprintln!("MODEL lossy: no SACK, 5% loss, 40 x 400 KB: {s:?}");
    assert_eq!(s.delivered, 40 * 400_000);
    assert!(s.drops > 400, "the path dropped data: {s:?}");
    assert!(
        s.retrans * 10 <= s.drops * 13,
        "far beyond what was lost: {s:?}"
    );
    assert!(s.needless * 5 <= s.drops, "needless retransmissions: {s:?}");
    assert!(s.rtos <= 45, "timeouts: {s:?}");
}

/// One spurious timeout (the path stalls for 400 ms, losing nothing) used
/// to start retransmissions that never stopped: the copies the timeout
/// resent drew duplicate ACKs that arrived just as its recovery ended and
/// started a fast retransmit, in which every ACK was "partial" and resent
/// another segment the receiver held, drawing the next duplicate ACKs.
/// About one retransmission per delivered segment, for good, with the
/// window pinned at one segment.
#[test]
fn spurious_timeout_without_sack_does_not_retransmit_forever() {
    for (ts, big_window) in [(false, false), (true, false), (false, true), (true, true)] {
        let c = transfer(Path {
            delay_ms: 25,
            stall: Some((2_000, 400)),
            stop_ms: 30_000,
            ts,
            big_window,
            ..Path::new(7, 200_000_000)
        });
        std::eprintln!("MODEL stall: no SACK, ts {ts}, big window {big_window}, 30 s: {c:?}");
        assert_eq!(c.drops, 0);
        // One flight resent by the timeout, and little more.
        let flight = if big_window { 730 } else { 45 };
        assert!(c.retrans <= flight, "ts {ts}, big {big_window}: {c:?}");
        // 64 KiB per 50 ms round trip for 28 s, less the stall's recovery.
        assert!(c.delivered > 25_000_000, "ts {ts}, big {big_window}: {c:?}");
    }
}

/// Without timestamps a retransmitted segment gives no RTT sample (Karn).
/// When the path's delay rises above the timeout, every segment is resent
/// before its ACK arrives, so the only way out is the backoff: it must
/// stand until a segment sent once is acknowledged and measured. Ending it
/// on any ACK of new data left the timeout at its stale value for good
/// (69 timeouts and 1 MB in a minute, where 5 MB fit).
#[test]
fn timeout_learns_a_path_that_became_slower_without_timestamps() {
    let c = transfer(Path {
        delay_ms: 25,
        step: Some((2_000, 400)),
        stop_ms: 62_000,
        ..Path::new(3, 60_000_000)
    });
    std::eprintln!("MODEL step: no SACK, no TS, RTT 50 -> 800 ms at 2 s, 60 s: {c:?}");
    assert!(c.srtt_ms > 600, "SRTT never learned the new path: {c:?}");
    assert!(c.rtos <= 12, "{c:?}");
    // 64 KiB per 800 ms round trip for a minute is 4.9 MB.
    assert!(c.delivered > 3_500_000, "{c:?}");
}
