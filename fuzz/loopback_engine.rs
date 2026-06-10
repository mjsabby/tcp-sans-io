//! Shared two-stack loopback engine behind the *convergence* oracle — the
//! deadlock / sender-stall catcher. Generic over ring capacity (`BUF`) so a
//! target can trade transfer size for raw exec/s: a tiny `BUF` keeps windows
//! small, so slow-start and loss-recovery churn constantly and the fuzzer
//! reaches the credit/flight/hole edge states (where deadlocks live) in a
//! fraction of the iterations a megabyte ring would need.
//!
//! See `tcb_loopback.rs` for the full oracle rationale. The property is:
//! **over an eventually-reliable channel a correct TCP always converges**, and
//! a liveness oracle (`debug_check_liveness`) additionally trips the instant a
//! black-hole forms (outstanding data with no retransmit timer, or queued data
//! under a zero window with no persist timer).

use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError, MAX_PACKET};

const C_IP: [u8; 4] = [10, 0, 0, 1];
const S_IP: [u8; 4] = [10, 0, 0, 2];
const CLI_STREAM: u32 = 0x0000_0001;
const SRV_STREAM: u32 = 0x8000_0001;

#[track_caller]
fn no_internal<T>(r: Result<T, TcpError>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(TcpError::Overflow) => panic!("internal TcpError::Overflow escaped the API"),
        Err(TcpError::BufferTooSmall) => {
            panic!("internal TcpError::BufferTooSmall with MAX_PACKET")
        }
        Err(_) => None,
    }
}

#[track_caller]
fn check<const BUF: usize>(tcb: &Tcb<BUF>) {
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
        local: Endpoint {
            ip: local.0,
            port: local.1,
        },
        remote: Endpoint {
            ip: remote.0,
            port: remote.1,
        },
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
/// `lossy`; afterwards the channel is fully reliable and in-order. Drops are
/// capped by `budget` and the window is iteration-bounded, so the channel is
/// always *eventually reliable* — which is what makes non-convergence a
/// genuine deadlock rather than a dead link.
fn chaos_decide(b: u8, lossy: bool, budget: &mut u32) -> (bool, bool, u64) {
    if !lossy {
        return (false, false, 0);
    }
    let drop = *budget > 0 && (b & 0x07 == 0); // ~12.5% until the budget is spent
    if drop {
        *budget -= 1;
    }
    let dup = b & 0x18 == 0x08; // ~12.5%
    let delay = if b & 0x60 == 0x20 {
        1 + (b as u64 & 0x3)
    } else {
        0
    };
    (drop, dup, delay)
}

/// Run one fuzz input: a byte-exact `xfer`-bytes-each-way bidirectional
/// transfer plus a clean close between two real `Tcb<BUF>` stacks, over a
/// fuzzer-driven (but eventually-reliable) chaos channel. `send_cap` bounds
/// the per-call application write so a small ring sees natural backpressure.
pub fn run<const BUF: usize>(data: &[u8], xfer: u32, send_cap: usize) {
    let mut cli: Tcb<BUF> = match Tcb::new(cfg(0x1111_1111, (C_IP, 40000), (S_IP, 80))) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut srv: Tcb<BUF> = match Tcb::new(cfg(0x9999_9999, (S_IP, 80), (C_IP, 40000))) {
        Ok(t) => t,
        Err(_) => return,
    };

    let mut now: u64 = 0;
    cli.set_now(now);
    srv.set_now(now);
    // Both stacks are honest here, and the harness fast-forwards the clock to
    // each armed timer at quiescence — compressing virtual time in a way that
    // does not reflect real elapsed time. The on-by-default wall-clock aborts
    // (USER TIMEOUT's no-progress abort, and keepalive's vanished-peer abort)
    // would therefore fire spuriously against these honest, live stacks, so
    // both are disabled: this oracle detects genuine stalls via the convergence
    // and liveness checks instead. (Both have their own unit/conformance tests.)
    cli.set_user_timeout(0);
    srv.set_user_timeout(0);
    cli.set_keepalive(0, 0, 0);
    srv.set_keepalive(0, 0, 0);
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
    let cap = send_cap.min(chunk.len());

    let mut fi = 0usize;
    let mut drop_budget = 4000u32;

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
    let mut both_established = false;
    // True iff the *previous* iteration left both links empty. The liveness
    // oracle is only evaluated then: the top-of-loop tick was the stack's sole
    // chance to act, with no inbound packet able to rescue it.
    let mut prev_quiescent = false;
    // Consecutive quiescent iterations each stack has spent in the black-hole
    // shape (outstanding data, no timer). A *transient* — e.g. the one-tick
    // gap after `process_ack` clears the RTO on `snd_una == snd_nxt`, before
    // the next tick resends — clears in 1–2 iterations and resets the streak.
    // A genuine deadlock (PRR `snd_credit == 0`, lost FIN) is permanent and
    // marches the streak to the limit. The instantaneous shapes are identical
    // (`snd_nxt < snd_max`, no timer), so only persistence can tell them apart.
    let mut cli_stall = 0u32;
    let mut srv_stall = 0u32;
    const LIVENESS_STALL_LIMIT: u32 = 16_384;

    let budget = 3_000_000u64;
    for iter in 0..budget {
        let dt = 1 + (next_byte(data, &mut fi) as u64 % 40);
        now = now.saturating_add(dt);
        cli.set_now(now);
        srv.set_now(now);
        if no_internal(cli.tick()).is_none() || no_internal(srv.tick()).is_none() {
            return;
        }
        check(&cli);
        check(&srv);

        // Liveness oracle, evaluated only when the *previous* iteration left
        // the wire silent (both links empty). The tick above was then the
        // stack's sole opportunity to act, with no inbound packet able to
        // rescue it: if it staged no output (tx ring still empty) yet holds
        // unacked data with no retransmit timer — or window-blocked data with
        // no persist timer — the ACK clock is dead. When the tick *did* make
        // progress, `debug_check_liveness` self-skips on the staged egress, so
        // the benign post-ACK `snd_una == snd_nxt` timer-clear (the next tick
        // re-sends and re-arms) is never misflagged.
        // Liveness oracle, evaluated only when the *previous* iteration left
        // the wire silent (both links empty) so the tick above was the stack's
        // sole chance to act with no inbound packet able to rescue it. We do
        // NOT panic on a single observation: the black-hole shape (outstanding
        // data, no retransmit timer) is instantaneously identical to the benign
        // post-ACK RTO-clear that the next tick resends through. Only a streak
        // that survives `LIVENESS_STALL_LIMIT` consecutive quiescent iterations
        // — which a real deadlock does and a transient never does — is failed,
        // pinpointing the wedged stack far sooner than the convergence budget.
        if prev_quiescent {
            match cli.debug_check_liveness() {
                Err(e) => {
                    cli_stall += 1;
                    if cli_stall >= LIVENESS_STALL_LIMIT {
                        panic!("client {e}: stalled {cli_stall} quiescent iters (st {:?} sent {cli_sent} recv {cli_recv})", cli.state());
                    }
                }
                Ok(()) => cli_stall = 0,
            }
            match srv.debug_check_liveness() {
                Err(e) => {
                    srv_stall += 1;
                    if srv_stall >= LIVENESS_STALL_LIMIT {
                        panic!("server {e}: stalled {srv_stall} quiescent iters (st {:?} sent {srv_sent} recv {srv_recv})", srv.state());
                    }
                }
                Ok(()) => srv_stall = 0,
            }
        } else {
            cli_stall = 0;
            srv_stall = 0;
        }
        if cli.state() == State::Established && srv.state() == State::Established {
            both_established = true;
        }
        // Chaos applies only while fuzzer input remains (once it is consumed
        // the channel is lossless and in-order, so earlier drops are always
        // recoverable — this is what makes non-convergence a genuine deadlock
        // rather than a dead link), within a bounded early window, with drop
        // budget left, and only after the handshake has completed.
        let input_left = fi < data.len();
        // Chaos stresses the *data* path. Once the close handshake starts we
        // make the channel reliable: a dropped FIN/FIN-ACK combined with the
        // harness fast-forwarding the clock can expire a peer's 2·MSL TIME_WAIT
        // before the other side's FIN is acknowledged, and — because this stack
        // deliberately does not RST segments on an unknown connection
        // (anti-reflection) — the closer would then wait on an R2-style abort
        // this library leaves to the host. That is a close-policy corner, not
        // the data-path deadlock class this oracle targets. Bugs rooted in
        // *latched* state (e.g. a zero window carried over from the data phase)
        // still reproduce, since the latch happens before `closing`.
        //
        // Chaos is also bounded in *virtual time* (`now < CHAOS_MS`). The
        // harness fast-forwards the clock to each RTO at quiescence, so an
        // unbounded loss window would let a single segment's retransmits be
        // dropped enough times in a row to trip the production R2 retransmit
        // cap (RFC 9293 §3.8.3) — aborting a connection whose peer is in fact
        // alive. With the RTO back-off, a bounded window admits only a handful
        // of consecutive drops, well under the R2 budget, so R2 stays reserved
        // for genuinely vanished peers (which this two-live-stack model never
        // has). CHAOS_MS is comfortably below the R2 abort time (~200 s).
        const CHAOS_MS: u64 = 30_000;
        let lossy = input_left
            && iter < 400_000
            && now < CHAOS_MS
            && drop_budget > 0
            && both_established
            && !closing;

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
                    let (d, u, dl) =
                        chaos_decide(next_byte(data, &mut fi), lossy, &mut drop_budget);
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
                    let (d, u, dl) =
                        chaos_decide(next_byte(data, &mut fi), lossy, &mut drop_budget);
                    c2s.offer(iter, slice, d, u, dl);
                }
            }
        }

        // Offer data each way.
        if cli.state() == State::Established && cli_sent < xfer {
            let take = (cap as u32).min(xfer - cli_sent) as usize;
            for (i, b) in chunk.iter_mut().take(take).enumerate() {
                *b = pat(CLI_STREAM, cli_sent + i as u32);
            }
            if let Some(w) = no_internal(cli.send(&chunk[..take])) {
                cli_sent += w as u32;
            }
        }
        if srv.state() == State::Established && srv_sent < xfer {
            let take = (cap as u32).min(xfer - srv_sent) as usize;
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
                    panic!(
                        "client received corrupt/out-of-order byte at {}",
                        cli_recv + i as u32
                    );
                }
            }
            cli_recv += n as u32;
        }
        if let Some(n) = no_internal(srv.recv(&mut rbuf)) {
            for i in 0..n {
                if rbuf.get(i).copied() != Some(pat(CLI_STREAM, srv_recv + i as u32)) {
                    panic!(
                        "server received corrupt/out-of-order byte at {}",
                        srv_recv + i as u32
                    );
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
            assert!(
                (c.0.wrapping_sub(mono_c.0) as i32) >= 0,
                "cli snd_una regressed"
            );
            assert!(
                (c.1.wrapping_sub(mono_c.1) as i32) >= 0,
                "cli rcv_nxt regressed"
            );
        }
        mono_c = c;
        cli_sync = c_now;
        let s = {
            let s = srv.debug_snapshot();
            (s.snd_una, s.rcv_nxt)
        };
        let s_now = sync(srv.state());
        if srv_sync && s_now {
            assert!(
                (s.0.wrapping_sub(mono_s.0) as i32) >= 0,
                "srv snd_una regressed"
            );
            assert!(
                (s.1.wrapping_sub(mono_s.1) as i32) >= 0,
                "srv rcv_nxt regressed"
            );
        }
        mono_s = s;
        srv_sync = s_now;

        if !closing && cli_sent == xfer && cli_recv == xfer && srv_sent == xfer && srv_recv == xfer
        {
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

        // Fast-forward dead time. When nothing is on the wire either way, the
        // only thing that can break the silence is a timer; jump the clock
        // straight to the earliest armed deadline so a long RTO/persist
        // back-off costs one iteration instead of hundreds. This frees the
        // iteration budget for deeper exploration and exposes a *missing*
        // timer as non-convergence in a fraction of the runtime. The empty
        // links also arm the liveness oracle for next iteration's tick.
        let quiescent = !c2s.pending() && !s2c.pending();
        if quiescent {
            let nd = [cli.debug_next_deadline(), srv.debug_next_deadline()]
                .into_iter()
                .flatten()
                .min();
            if let Some(d) = nd {
                if d > now {
                    now = d;
                }
            }
        }
        prev_quiescent = quiescent;
    }

    // The channel becomes lossless once the fuzzer input is consumed, so a
    // correct stack MUST have converged. Reaching here is a deadlock.
    panic!(
        "deadlock: transfer did not converge (cli {cli_sent}/{cli_recv} srv {srv_sent}/{srv_recv} st {:?}/{:?})",
        cli.state(),
        srv.state()
    );
}
