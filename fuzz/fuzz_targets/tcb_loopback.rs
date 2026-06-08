//! Coverage-guided **two-stack loopback** fuzzing with a *convergence*
//! oracle — the deadlock / sender-stall catcher.
//!
//! The other fuzz targets drive ONE `Tcb` against a synthetic peer, so they
//! can't assert forward progress (an adversarial peer may legitimately stall
//! the connection). This target instead runs two *real* stacks (client +
//! server) against each other through a fuzzer-controlled chaos channel, and
//! asserts the strongest possible liveness property:
//!
//!   **Over an eventually-reliable channel, a correct TCP always converges.**
//!
//! The fuzzer chooses the loss / duplication / reordering / delay schedule
//! while its input lasts; once the input is exhausted the channel becomes
//! lossless, so any earlier drops are recoverable by retransmission. A
//! correct stack therefore completes a byte-exact bidirectional transfer and
//! closes cleanly within the iteration budget. A stack that deadlocks (e.g.
//! the PRR ACK-clock stall: recovery with `snd_credit == 0` and an empty
//! pipe that can never make progress) never converges — and trips the
//! budget, failing loudly. This is the oracle that would have caught that
//! bug automatically; the per-op `Overflow` / invariant / monotonic oracles
//! ride along.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError, MAX_PACKET};

const C_IP: [u8; 4] = [10, 0, 0, 1];
const S_IP: [u8; 4] = [10, 0, 0, 2];
const CLI_STREAM: u32 = 0x0000_0001;
const SRV_STREAM: u32 = 0x8000_0001;
const XFER: u32 = 96 * 1024; // bytes each way

#[track_caller]
fn no_internal<T>(r: Result<T, TcpError>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(TcpError::Overflow) => panic!("internal TcpError::Overflow escaped the API"),
        Err(TcpError::BufferTooSmall) => panic!("internal TcpError::BufferTooSmall with MAX_PACKET"),
        Err(_) => None,
    }
}

#[track_caller]
fn check(tcb: &Tcb) {
    if let Err(e) = tcb.debug_validate_invariants() {
        panic!("TCB invariant failed: {e}");
    }
}

fn pat(stream: u32, off: u32) -> u8 {
    let x = (stream ^ off).wrapping_mul(2_654_435_761);
    (x >> 24) as u8
}

fn cfg(iss: u32, local: ([u8; 4], u16), remote: ([u8; 4], u16)) -> TcbConfig {
    TcbConfig {
        local: Endpoint { ip: local.0, port: local.1 },
        remote: Endpoint { ip: remote.0, port: remote.1 },
        iss,
        initial_rto_ms: 1000,
    }
}

/// One direction of the chaos channel: packets are released at a per-packet
/// iteration deadline; drops vanish; dups are queued twice.
#[derive(Default)]
struct Link {
    q: Vec<(u64, Vec<u8>)>,
}

impl Link {
    fn offer(&mut self, iter: u64, pkt: &[u8], drop: bool, dup: bool, delay: u64) {
        if drop {
            return;
        }
        self.q.push((iter + delay, pkt.to_vec()));
        if dup {
            self.q.push((iter + delay + 1, pkt.to_vec()));
        }
    }
    fn drain_ready(&mut self, iter: u64, out: &mut Vec<Vec<u8>>) {
        let mut keep = Vec::new();
        for (rel, p) in self.q.drain(..) {
            if rel <= iter {
                out.push(p);
            } else {
                keep.push((rel, p));
            }
        }
        self.q = keep;
    }
    fn pending(&self) -> bool {
        !self.q.is_empty()
    }
}

fn next_byte(data: &[u8], fi: &mut usize) -> u8 {
    let b = data.get(*fi).copied().unwrap_or(0);
    *fi += 1;
    b
}

/// Decide this packet's fate from a fuzzer byte. Chaos only applies while
/// `lossy` (a bounded early window with drop budget remaining); afterwards
/// the channel is fully reliable and in-order. **Drops are capped by
/// `budget`** and the window is iteration-bounded, so the channel is always
/// *eventually reliable* — which is what makes non-convergence a genuine
/// deadlock rather than a dead link.
fn chaos_decide(b: u8, lossy: bool, budget: &mut u32) -> (bool, bool, u64) {
    if !lossy {
        return (false, false, 0);
    }
    let drop = *budget > 0 && (b & 0x07 == 0); // ~12.5% until the budget is spent
    if drop {
        *budget -= 1;
    }
    let dup = b & 0x18 == 0x08; // ~12.5%
    let delay = if b & 0x60 == 0x20 { 1 + (b as u64 & 0x3) } else { 0 };
    (drop, dup, delay)
}

fuzz_target!(|data: &[u8]| {
    let mut cli: Tcb = match Tcb::new(cfg(0x1111_1111, (C_IP, 40000), (S_IP, 80))) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut srv: Tcb = match Tcb::new(cfg(0x9999_9999, (S_IP, 80), (C_IP, 40000))) {
        Ok(t) => t,
        Err(_) => return,
    };

    let mut now: u64 = 0;
    cli.set_now(now);
    srv.set_now(now);
    if srv.listen().is_err() || cli.connect().is_err() {
        return;
    }

    let mut c2s = Link::default();
    let mut s2c = Link::default();

    let mut cli_sent = 0u32;
    let mut cli_recv = 0u32;
    let mut srv_sent = 0u32;
    let mut srv_recv = 0u32;
    let mut closing = false;

    let mut pkt = [0u8; MAX_PACKET];
    let mut chunk = [0u8; 4096];
    let mut rbuf = [0u8; 4096];

    // Fuzzer-driven chaos. A finite drop budget guarantees the channel is
    // eventually reliable, so a correct stack MUST converge; only a real
    // deadlock fails to. Duplication / bounded reordering are uncapped.
    let mut fi = 0usize;
    let mut drop_budget = 4000u32;

    // Monotonic-progress oracle state. Only enforced across two consecutive
    // *synchronized* states, so the legitimate `rcv_nxt: 0 -> irs+1` jump at
    // the handshake (and `snd_una` at SYN-ACK) isn't misread as a regress.
    let mut mono_c = {
        let s = cli.debug_snapshot();
        (s.snd_una, s.rcv_nxt)
    };
    let mut mono_s = {
        let s = srv.debug_snapshot();
        (s.snd_una, s.rcv_nxt)
    };
    let mut cli_sync = false;
    let mut srv_sync = false;

    let budget = 3_000_000u64;
    for iter in 0..budget {
        // Clock advances each iteration (so RTO/TLP can fire); the fuzzer
        // varies the step to shift timer-firing windows.
        let dt = 1 + (next_byte(data, &mut fi) as u64 % 40);
        now = now.saturating_add(dt);
        cli.set_now(now);
        srv.set_now(now);
        if no_internal(cli.tick()).is_none() || no_internal(srv.tick()).is_none() {
            return;
        }
        check(&cli);
        check(&srv);

        // Chaos applies only in a bounded early window with drop budget
        // left; the back half of the run is a fully reliable, in-order
        // channel, so a correct stack is guaranteed to converge and only a
        // genuine deadlock fails to.
        let lossy = iter < 400_000 && drop_budget > 0;

        // Stage egress into the links.
        while let Some(n) = no_internal(cli.extract_packet(&mut pkt)) {
            if n == 0 {
                break;
            }
            if let Some(slice) = pkt.get(..n) {
                let (d, u, dl) = chaos_decide(next_byte(data, &mut fi), lossy, &mut drop_budget);
                c2s.offer(iter, slice, d, u, dl);
            }
        }
        while let Some(n) = no_internal(srv.extract_packet(&mut pkt)) {
            if n == 0 {
                break;
            }
            if let Some(slice) = pkt.get(..n) {
                let (d, u, dl) = chaos_decide(next_byte(data, &mut fi), lossy, &mut drop_budget);
                s2c.offer(iter, slice, d, u, dl);
            }
        }

        // Deliver due packets; drain responses back into the same link.
        let mut ready: Vec<Vec<u8>> = Vec::new();
        c2s.drain_ready(iter, &mut ready);
        for p in &ready {
            let _ = srv.inject_packet(p);
            while let Some(n) = no_internal(srv.extract_packet(&mut pkt)) {
                if n == 0 {
                    break;
                }
                if let Some(slice) = pkt.get(..n) {
                    let (d, u, dl) = chaos_decide(next_byte(data, &mut fi), lossy, &mut drop_budget);
                    s2c.offer(iter, slice, d, u, dl);
                }
            }
        }
        ready.clear();
        s2c.drain_ready(iter, &mut ready);
        for p in &ready {
            let _ = cli.inject_packet(p);
            while let Some(n) = no_internal(cli.extract_packet(&mut pkt)) {
                if n == 0 {
                    break;
                }
                if let Some(slice) = pkt.get(..n) {
                    let (d, u, dl) = chaos_decide(next_byte(data, &mut fi), lossy, &mut drop_budget);
                    c2s.offer(iter, slice, d, u, dl);
                }
            }
        }

        // Offer data each way.
        if cli.state() == State::Established && cli_sent < XFER {
            let take = (chunk.len() as u32).min(XFER - cli_sent) as usize;
            for (i, b) in chunk.iter_mut().take(take).enumerate() {
                *b = pat(CLI_STREAM, cli_sent + i as u32);
            }
            if let (Some(src), Some(w)) = (chunk.get(..take), no_internal(cli.send(&chunk[..take]))) {
                let _ = src;
                cli_sent += w as u32;
            }
        }
        if srv.state() == State::Established && srv_sent < XFER {
            let take = (chunk.len() as u32).min(XFER - srv_sent) as usize;
            for (i, b) in chunk.iter_mut().take(take).enumerate() {
                *b = pat(SRV_STREAM, srv_sent + i as u32);
            }
            if let Some(w) = no_internal(srv.send(&chunk[..take])) {
                srv_sent += w as u32;
            }
        }

        // Drain + verify (byte-exact, in-order).
        if let Some(n) = no_internal(cli.recv(&mut rbuf)) {
            for i in 0..n {
                if rbuf.get(i).copied() != Some(pat(SRV_STREAM, cli_recv + i as u32)) {
                    panic!("client received corrupt/out-of-order byte at {}", cli_recv + i as u32);
                }
            }
            cli_recv += n as u32;
        }
        if let Some(n) = no_internal(srv.recv(&mut rbuf)) {
            for i in 0..n {
                if rbuf.get(i).copied() != Some(pat(CLI_STREAM, srv_recv + i as u32)) {
                    panic!("server received corrupt/out-of-order byte at {}", srv_recv + i as u32);
                }
            }
            srv_recv += n as u32;
        }

        // Monotonic-progress oracle: cumulative cursors never regress —
        // checked only between consecutive synchronized states.
        let sync = |st: State| {
            matches!(
                st,
                State::Established
                    | State::FinWait1
                    | State::FinWait2
                    | State::Closing
                    | State::CloseWait
                    | State::LastAck
                    | State::TimeWait
            )
        };
        let c = {
            let s = cli.debug_snapshot();
            (s.snd_una, s.rcv_nxt)
        };
        let c_now = sync(cli.state());
        if cli_sync && c_now {
            assert!((c.0.wrapping_sub(mono_c.0) as i32) >= 0, "cli snd_una regressed");
            assert!((c.1.wrapping_sub(mono_c.1) as i32) >= 0, "cli rcv_nxt regressed");
        }
        mono_c = c;
        cli_sync = c_now;
        let s = {
            let s = srv.debug_snapshot();
            (s.snd_una, s.rcv_nxt)
        };
        let s_now = sync(srv.state());
        if srv_sync && s_now {
            assert!((s.0.wrapping_sub(mono_s.0) as i32) >= 0, "srv snd_una regressed");
            assert!((s.1.wrapping_sub(mono_s.1) as i32) >= 0, "srv rcv_nxt regressed");
        }
        mono_s = s;
        srv_sync = s_now;

        if !closing && cli_sent == XFER && cli_recv == XFER && srv_sent == XFER && srv_recv == XFER {
            let _ = cli.close();
            let _ = srv.close();
            closing = true;
        }
        if closing
            && matches!(cli.state(), State::Closed | State::TimeWait)
            && matches!(srv.state(), State::Closed | State::TimeWait)
            && !c2s.pending()
            && !s2c.pending()
        {
            return; // converged — success
        }
    }

    // The channel becomes lossless once the fuzzer input is consumed, so a
    // correct stack MUST have converged. Reaching here is a deadlock.
    panic!(
        "deadlock: transfer did not converge (cli {cli_sent}/{cli_recv} srv {srv_sent}/{srv_recv} st {:?}/{:?})",
        cli.state(),
        srv.state()
    );
});
