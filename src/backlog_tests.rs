//! The listener's backlog of pending handshakes (see `tcb/backlog.rs`).

use super::*;

fn backlog_listener() -> Box<Tcb> {
    let mut t = listener();
    t.set_listen_backlog(usize::MAX);
    t
}

/// The options a client without timestamps offers (the Windows default).
fn win_syn(src: Ep, seq: u32) -> Vec<u8> {
    syn(src, seq, &syn_opts(None, true, Some(7)))
}

fn bare_ack(src: Ep, seq: u32, ack: u32, win: u16) -> Vec<u8> {
    pkt(src, SRV, seq, ack, flags::ACK, win, &TcpOptions::NONE, &[])
}

fn rst(src: Ep, seq: u32) -> Vec<u8> {
    pkt(src, SRV, seq, 0, flags::RST, 0, &TcpOptions::NONE, &[])
}

/// Handshakes that overlap used to fall to cookies, which cannot carry
/// window scaling or SACK without timestamps. The backlog holds them
/// statefully, and the host's next listener adopts those still pending
/// when one completes.
#[test]
fn overlapping_handshakes_keep_their_options_without_timestamps() {
    let mut s = backlog_listener();
    s.inject_packet(&win_syn(A, 100)).unwrap();
    let sa = drain(&mut s).remove(0);
    s.inject_packet(&win_syn(B, 200)).unwrap();
    let sb = drain(&mut s).remove(0);
    assert_eq!(
        (sb.dst, sb.flags, sb.ack, sb.ip_id),
        (B, flags::SYN | flags::ACK, 201, 0)
    );
    assert!(
        sb.opts.wscale.is_some() && sb.opts.sack_permitted,
        "kept statefully"
    );
    assert_eq!((s.remote(), s.pending_half_opens()), (Some(ep(A)), 1));

    // B completes first: the TCB becomes B's connection, A stays pending.
    s.set_now(10);
    s.inject_packet(&bare_ack(B, 201, sb.seq + 1, 1000))
        .unwrap();
    assert_eq!((s.state(), s.remote()), (State::Established, Some(ep(B))));
    assert_eq!(s.stats().snd_wnd, 1000 << 7, "window scaling negotiated");
    assert_eq!(s.pending_half_opens(), 1);
    s.debug_validate_invariants().unwrap();

    // The host's next listener adopts A's half-open and completes it.
    let mut n = backlog_listener();
    n.set_now(11);
    assert_eq!(n.adopt_half_opens(&mut s), 1);
    assert_eq!(s.pending_half_opens(), 0);
    assert_eq!((n.state(), n.remote()), (State::SynRcvd, Some(ep(A))));
    n.set_now(20);
    n.inject_packet(&bare_ack(A, 101, sa.seq + 1, 2000))
        .unwrap();
    assert_eq!((n.state(), n.remote()), (State::Established, Some(ep(A))));
    assert_eq!(n.stats().snd_wnd, 2000 << 7);
    n.debug_validate_invariants().unwrap();
    assert!(drain(&mut n).iter().all(|o| o.flags & flags::RST == 0));
}

/// A pending half-open has its SYN-ACK retransmitted on its own timer and
/// repeated for a retransmitted SYN (a cookie SYN-ACK was sent once); its
/// budget spent, it is dropped, and the listener returns to LISTEN.
#[test]
fn pending_half_opens_are_retransmitted_and_expire() {
    let mut s = backlog_listener();
    s.inject_packet(&win_syn(A, 100)).unwrap();
    s.set_now(100);
    s.inject_packet(&win_syn(B, 200)).unwrap();
    let first = drain(&mut s);
    let sb = first.iter().find(|o| o.dst == B).unwrap().seq;
    assert_eq!(s.next_deadline(), Some(1000));

    // The same SYN again: the same SYN-ACK. A new ISN starts over.
    s.inject_packet(&win_syn(B, 200)).unwrap();
    let again = drain(&mut s);
    assert_eq!((again.len(), again[0].seq, again[0].ack), (1, sb, 201));
    s.inject_packet(&win_syn(B, 900)).unwrap();
    let anew = drain(&mut s);
    assert_eq!((anew.len(), anew[0].ack), (1, 901));
    assert_eq!(s.pending_half_opens(), 1);

    let mut to_b = 0;
    let mut now = 100u64;
    while let Some(due) = s.next_deadline() {
        assert!(due > now, "busy timer at {now}");
        now = due;
        s.set_now(now);
        s.tick().unwrap();
        to_b += drain(&mut s).iter().filter(|o| o.dst == B).count();
        assert!(now < 200_000);
    }
    assert_eq!(to_b, 5, "SYN-ACK retransmissions to the pending peer");
    assert_eq!((s.state(), s.pending_half_opens()), (State::Listen, 0));
}

/// When the slot's half-open ends (an exact RST here), a pending one takes
/// the slot; an exact RST from a pending peer drops just its record.
#[test]
fn pending_half_open_takes_a_freed_slot() {
    let mut s = backlog_listener();
    s.inject_packet(&win_syn(A, 100)).unwrap();
    s.inject_packet(&win_syn(B, 200)).unwrap();
    s.inject_packet(&win_syn(X, 300)).unwrap();
    let out = drain(&mut s);
    let sb = out.iter().find(|o| o.dst == B).unwrap().seq;
    assert_eq!(s.pending_half_opens(), 2);

    let _ = s.inject_packet(&rst(X, 999));
    assert_eq!(s.pending_half_opens(), 2, "an inexact RST changes nothing");
    let _ = s.inject_packet(&rst(X, 301));
    assert_eq!(s.pending_half_opens(), 1);

    s.inject_packet(&rst(A, 101)).unwrap();
    assert_eq!((s.state(), s.remote()), (State::SynRcvd, Some(ep(B))));
    assert_eq!(s.pending_half_opens(), 0);
    s.inject_packet(&bare_ack(B, 201, sb + 1, 500)).unwrap();
    assert_eq!(s.state(), State::Established);
    assert_eq!(s.stats().snd_wnd, 500 << 7);
}

/// A flood fills the backlog; further SYNs get cookies (as on Linux), a
/// cookie client still gets through, and once the flood's half-opens have
/// gone unanswered for an RTO they yield their records to new SYNs.
#[test]
fn full_backlog_falls_back_to_cookies_and_recycles_stale_records() {
    let mut s = backlog_listener();
    for k in 0..9u32 {
        s.inject_packet(&win_syn(([198, 18, 3, k as u8], 7000), k))
            .unwrap();
    }
    assert_eq!(drain(&mut s).len(), 9);
    assert_eq!(s.pending_half_opens(), 8);

    // The tenth: a cookie, no state.
    s.inject_packet(&syn(B, 200, &syn_opts(Some(900), true, Some(7))))
        .unwrap();
    let sb = drain(&mut s).remove(0);
    assert_eq!(s.pending_half_opens(), 8);
    let mut c = backlog_listener();
    c.set_now(5);
    c.inject_packet(&pkt(
        B,
        SRV,
        201,
        sb.seq + 1,
        flags::ACK,
        65535,
        &ts(901, sb.opts.ts.unwrap().0),
        &[],
    ))
    .unwrap();
    assert_eq!(
        c.state(),
        State::Established,
        "the cookie completes anywhere"
    );

    // An RTO later the flood's records are stale: a new client gets one.
    s.set_now(1000);
    s.tick().unwrap();
    drain(&mut s);
    s.inject_packet(&win_syn(A, 100)).unwrap();
    let sa = drain(&mut s).remove(0);
    assert!(sa.opts.wscale.is_some(), "held statefully");
    assert_eq!(s.pending_half_opens(), 8);
    s.inject_packet(&bare_ack(A, 101, sa.seq + 1, 700)).unwrap();
    assert_eq!((s.state(), s.remote()), (State::Established, Some(ep(A))));
    assert_eq!(s.stats().snd_wnd, 700 << 7);
}

/// Random SYNs, ACKs and RSTs from many peers, with ticks in between: the
/// invariants hold, the backlog never exceeds its size, no timer is left
/// in the past, and a listener back in LISTEN holds nothing pending.
#[test]
fn backlog_survives_a_hostile_multi_peer_mix() {
    let mut x = 0x1234_5678_9abc_def1u64;
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let mut established = 0;
    for _ in 0..300 {
        let mut s = backlog_listener();
        let mut now = 0u64;
        let mut seen: Vec<(Ep, u32)> = Vec::new(); // peer, our last SYN-ACK seq
        for _ in 0..400 {
            now += rnd(400);
            s.set_now(now);
            let p = ([198, 18, 4, rnd(14) as u8], 6000 + rnd(2) as u16);
            let known = seen.iter().rev().find(|(e, _)| *e == p).map(|&(_, q)| q);
            let isn = rnd(3) as u32 * 1000;
            let r = match rnd(6) {
                0 | 1 => s.inject_packet(&win_syn(p, isn)),
                2 => s.inject_packet(&syn(p, isn, &syn_opts(Some(5), true, None))),
                3 => {
                    let ack = known.unwrap_or(77).wrapping_add(1);
                    s.inject_packet(&bare_ack(p, isn + 1, ack, 100))
                }
                4 => s.inject_packet(&rst(p, isn + 1)),
                _ => s.tick(),
            };
            assert_ne!(r, Err(TcpError::Overflow));
            for o in drain(&mut s) {
                if o.flags & flags::SYN != 0 {
                    seen.push((o.dst, o.seq));
                }
            }
            s.debug_validate_invariants().unwrap();
            assert!(s.pending_half_opens() <= 8);
            if s.state() == State::Established {
                established += 1;
                break;
            }
            s.tick().unwrap();
            drain(&mut s);
            if let Some(d) = s.next_deadline() {
                assert!(d > now, "deadline {d} not after {now}");
            }
            if s.state() == State::Listen {
                assert_eq!(s.pending_half_opens(), 0, "pending without a slot");
            }
        }
    }
    assert!(
        established > 100,
        "the mix completes handshakes: {established}"
    );
}

type Small = Tcb<16384>;

fn small_listener(now: u64, backlog: usize) -> Box<Small> {
    let mut t: Box<Small> = Box::new(
        Small::new(TcbConfig {
            local: ep(SRV),
            remote: ep(([0; 4], 0)),
            iss: 5,
            initial_rto_ms: 1000,
        })
        .unwrap(),
    );
    t.set_secret(&[0x42; 16]);
    t.set_listen_backlog(backlog);
    t.set_now(now);
    t.listen().unwrap();
    t
}

/// 200 clients without timestamps (window scaling and SACK offered)
/// arrive over 3 s, RTT 4-80 ms, at a host that keeps one listener and
/// sets up the next, adopting what is pending, whenever one becomes a
/// connection. Returns (clients connected with their options, resets).
fn two_hundred_clients(backlog: usize) -> (usize, usize) {
    const N: usize = 200;
    let client = |i: usize| -> Ep { ([10, 9, 0, i as u8 + 1], 30_000 + i as u16) };
    let rtt = |i: usize| 4 + (i as u64 * 37) % 77;
    // (arrival time at the server, packet)
    let mut to_server: Vec<(u64, Vec<u8>)> = Vec::new();
    for i in 0..N {
        let t = (i as u64 * 3000) / N as u64;
        to_server.push((t + rtt(i) / 2, win_syn(client(i), 1000 + i as u32)));
    }
    let mut conns: Vec<Box<Small>> = Vec::new();
    let mut l = small_listener(0, backlog);
    let mut resets = 0usize;
    let mut acked = vec![false; N];
    let mut buf = [0u8; MAX_PACKET];
    for now in 0..6000u64 {
        let mut due: Vec<Vec<u8>> = Vec::new();
        to_server.retain(|(t, p)| {
            if *t <= now {
                due.push(p.clone());
                false
            } else {
                true
            }
        });
        l.set_now(now);
        l.tick().unwrap();
        for p in due {
            let seg = wire::parse(&p).unwrap();
            let src = Endpoint {
                ip: seg.src_ip,
                port: seg.src_port,
            };
            if conns.iter().any(|c| c.remote() == Some(src)) {
                continue;
            }
            let _ = l.inject_packet(&p);
            if l.state() == State::Established {
                let mut next = small_listener(now, backlog);
                next.adopt_half_opens(&mut l);
                conns.push(core::mem::replace(&mut l, next));
            }
        }
        // The server's packets: a SYN-ACK is answered an RTT later.
        let mut out: Vec<(Ep, u8, u32)> = Vec::new();
        for t in core::iter::once(&mut l).chain(conns.iter_mut()) {
            loop {
                let n = t.extract_packet(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                let o = wire::parse(&buf[..n]).unwrap();
                out.push(((o.dst_ip, o.dst_port), o.flags, o.seq));
            }
        }
        for (dst, fl, seq) in out {
            let Some(i) = (0..N).find(|&i| client(i) == dst) else {
                continue;
            };
            if fl & flags::RST != 0 {
                resets += 1;
            } else if fl & flags::SYN != 0 && !acked[i] {
                acked[i] = true;
                let ack = bare_ack(client(i), 1001 + i as u32, seq + 1, 1000);
                to_server.push((now + rtt(i), ack));
            }
        }
    }
    let good = (0..N)
        .filter(|&i| {
            conns.iter().any(|c| {
                c.remote() == Some(ep(client(i)))
                    && c.state() == State::Established
                    && c.stats().snd_wnd == 1000 << 7
            })
        })
        .count();
    (good, resets)
}

/// The scenario the backlog is for: every one of 200 overlapping clients
/// connects with its options and none is reset. Without the backlog (one
/// half-open per listener) most go through cookies and lose their options.
#[test]
fn two_hundred_overlapping_clients_all_connect_with_their_options() {
    assert_eq!(two_hundred_clients(8), (200, 0));
    let (good, _) = two_hundred_clients(0);
    assert!(
        good < 150,
        "without a backlog only {good} keep their options"
    );
}
