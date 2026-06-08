//! Standalone self-loopback conformance harness for tcp-sans-io.
//!
//! Certifies an integration **without any external reference stack**: it
//! drives two instances of the stack against each other through the exact
//! C ABI a foreign binding uses (`tcp_init`, `tcp_inject_packet`,
//! `tcp_tick`, `tcp_extract_packet`, `tcp_send`, `tcp_recv`, `tcp_close`,
//! `tcp_destroy`), over an in-memory channel that can inject loss,
//! duplication and reordering, and verifies a byte-exact bidirectional
//! transfer plus a clean close.
//!
//! Run it directly (Rust integrators):  `cargo run --release`
//! It exits 0 on PASS, 1 on FAIL. Port the ~200 lines below into your own
//! binding's test suite to self-certify in your language — the algorithm
//! (and the pass criterion: matching digests both ways) is the contract.

use std::alloc::{alloc, dealloc, Layout};

use tcp_sans_io::ffi::{
    tcp_abi_version, tcp_close, tcp_connect, tcp_destroy, tcp_extract_packet, tcp_handle_align,
    tcp_handle_size, tcp_init, tcp_inject_packet, tcp_listen, tcp_max_packet, tcp_recv, tcp_selftest,
    tcp_send, tcp_state, tcp_tick, TcpStreamHandle,
};

const ST_ESTABLISHED: u8 = 2;
const ST_CLOSED: u8 = 0;
const ST_TIME_WAIT: u8 = 6;

/// Host-allocated handle following the documented storage pattern:
/// allocate `tcp_handle_size()` bytes at `tcp_handle_align()`, hand the
/// pointer to `tcp_init`, free after `tcp_destroy`.
struct Handle {
    ptr: *mut TcpStreamHandle,
    layout: Layout,
}

impl Handle {
    fn new(local_ip: [u8; 4], lport: u16, remote_ip: [u8; 4], rport: u16, iss: u32) -> Handle {
        let size = tcp_handle_size();
        let align = tcp_handle_align();
        let layout = Layout::from_size_align(size, align).expect("layout");
        // SAFETY: non-zero size from the ABI; we own this block until drop.
        let ptr = unsafe { alloc(layout) } as *mut TcpStreamHandle;
        assert!(!ptr.is_null(), "allocation failed");
        // SAFETY: ptr is freshly allocated, correctly sized and aligned.
        let rc = unsafe {
            tcp_init(
                ptr,
                local_ip.as_ptr(),
                lport,
                remote_ip.as_ptr(),
                rport,
                iss,
                1000,
            )
        };
        assert_eq!(rc, 0, "tcp_init failed: {rc}");
        Handle { ptr, layout }
    }

    fn state(&self) -> u8 {
        tcp_state(self.ptr)
    }

    fn connect(&self, now: u64) {
        assert_eq!(tcp_connect(self.ptr, now), 0);
    }

    fn listen(&self, now: u64) {
        assert_eq!(tcp_listen(self.ptr, now), 0);
    }

    fn tick(&self, now: u64) {
        let rc = tcp_tick(self.ptr, now);
        assert!(rc == 0, "tcp_tick returned {rc}");
    }

    fn close(&self, now: u64) {
        let rc = tcp_close(self.ptr, now);
        assert!(rc == 0, "tcp_close returned {rc}");
    }

    fn inject(&self, pkt: &[u8], now: u64) {
        // Errors (NOT_FOR_US / MALFORMED) are benign on a chaos channel.
        // SAFETY: pkt is a valid readable slice.
        let _ = unsafe { tcp_inject_packet(self.ptr, pkt.as_ptr(), pkt.len(), now) };
    }

    /// Drain one staged packet; returns None when the egress ring is empty.
    fn extract(&self, buf: &mut [u8]) -> Option<usize> {
        let mut n: usize = 0;
        // SAFETY: buf is writable for buf.len(); out param is a local.
        let rc = unsafe { tcp_extract_packet(self.ptr, buf.as_mut_ptr(), buf.len(), &mut n) };
        assert!(rc == 0, "tcp_extract_packet returned {rc}");
        if n == 0 {
            None
        } else {
            Some(n)
        }
    }

    /// Buffer application bytes; returns the count accepted (0 on WOULD_BLOCK).
    fn send(&self, data: &[u8]) -> usize {
        let mut w: usize = 0;
        // SAFETY: data readable; out param local.
        let rc = unsafe { tcp_send(self.ptr, data.as_ptr(), data.len(), &mut w) };
        // -6 == WOULD_BLOCK is fine (ring full); other negatives are bugs.
        assert!(rc == 0 || rc == -6, "tcp_send returned {rc}");
        w
    }

    /// Copy received bytes out; returns count (0 if none / closed).
    fn recv(&self, buf: &mut [u8]) -> usize {
        let mut r: usize = 0;
        // SAFETY: buf writable; out param local.
        let rc = unsafe { tcp_recv(self.ptr, buf.as_mut_ptr(), buf.len(), &mut r) };
        // -8 == CONNECTION_CLOSED is normal EOF.
        assert!(rc == 0 || rc == -8, "tcp_recv returned {rc}");
        r
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: ptr was produced by tcp_init into our allocation.
        unsafe {
            tcp_destroy(self.ptr);
            dealloc(self.ptr as *mut u8, self.layout);
        }
    }
}

/// Deterministic per-offset byte generator (matches the built-in selftest
/// idea): any drop/dup/reorder that survives changes a verified byte.
fn pat(stream: u32, offset: u32) -> u8 {
    let x = (stream ^ offset).wrapping_mul(2_654_435_761);
    (x >> 24) as u8
}

/// Tiny deterministic PRNG (xorshift64*) so failures reproduce exactly.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

/// A one-direction lossy/reordering/duplicating link. Packets are released
/// after a per-packet delay (in iterations); drops vanish; dups are queued
/// twice. Pathological patterns recover via the stack's retransmission.
#[derive(Default)]
struct Link {
    queue: Vec<(u64, Vec<u8>)>, // (release_iter, bytes)
}

#[derive(Clone, Copy)]
struct Chaos {
    drop_p: f64,
    dup_p: f64,
    reorder_p: f64,
}

impl Link {
    fn offer(&mut self, iter: u64, pkt: &[u8], c: &Chaos, rng: &mut Rng) {
        if c.drop_p > 0.0 && rng.chance(c.drop_p) {
            return; // dropped — sender will retransmit
        }
        let delay = if c.reorder_p > 0.0 && rng.chance(c.reorder_p) {
            2 + (rng.next() % 3) // hold a few iterations so later packets pass
        } else {
            0
        };
        self.queue.push((iter + delay, pkt.to_vec()));
        if c.dup_p > 0.0 && rng.chance(c.dup_p) {
            self.queue.push((iter + delay + 1, pkt.to_vec()));
        }
    }

    fn drain_ready(&mut self, iter: u64, out: &mut Vec<Vec<u8>>) {
        let mut keep = Vec::new();
        for (rel, p) in self.queue.drain(..) {
            if rel <= iter {
                out.push(p);
            } else {
                keep.push((rel, p));
            }
        }
        self.queue = keep;
    }

    fn pending(&self) -> bool {
        !self.queue.is_empty()
    }
}

/// Run one bidirectional `xfer`-bytes-each-way transfer over `chaos`.
/// Returns Ok(()) on a byte-exact, cleanly-closed transfer.
fn run_transfer(name: &str, xfer: u32, chaos: Chaos, seed: u64) -> Result<(), String> {
    const CLI: u32 = 0x0000_0001;
    const SRV: u32 = 0x8000_0001;
    let cli = Handle::new([10, 0, 0, 1], 40000, [10, 0, 0, 2], 80, 0x1111_1111);
    let srv = Handle::new([10, 0, 0, 2], 80, [10, 0, 0, 1], 40000, 0x9999_9999);

    let mut now: u64 = 0;
    cli.connect(now);
    srv.listen(now);

    let mut c2s = Link::default();
    let mut s2c = Link::default();
    let mut rng = Rng(seed | 1);

    let mut cli_sent = 0u32;
    let mut cli_recv = 0u32;
    let mut srv_sent = 0u32;
    let mut srv_recv = 0u32;
    let mut closing = false;

    let cap = tcp_max_packet();
    let mut pbuf = vec![0u8; cap];
    let mut chunk = vec![0u8; 8192];
    let mut rbuf = vec![0u8; 8192];

    let budget = 50_000_000u64; // generous; turns any wedge into a clear failure
    for iter in 0..budget {
        now += 1;
        cli.tick(now);
        srv.tick(now);

        // Stage egress into the chaos links.
        while let Some(n) = cli.extract(&mut pbuf) {
            c2s.offer(iter, &pbuf[..n], &chaos, &mut rng);
        }
        while let Some(n) = srv.extract(&mut pbuf) {
            s2c.offer(iter, &pbuf[..n], &chaos, &mut rng);
        }

        // Deliver whatever is due, then immediately drain the response.
        let mut ready: Vec<Vec<u8>> = Vec::new();
        c2s.drain_ready(iter, &mut ready);
        for p in &ready {
            srv.inject(p, now);
            while let Some(n) = srv.extract(&mut pbuf) {
                s2c.offer(iter, &pbuf[..n], &chaos, &mut rng);
            }
        }
        ready.clear();
        s2c.drain_ready(iter, &mut ready);
        for p in &ready {
            cli.inject(p, now);
            while let Some(n) = cli.extract(&mut pbuf) {
                c2s.offer(iter, &pbuf[..n], &chaos, &mut rng);
            }
        }

        // Offer more data each way.
        if cli.state() == ST_ESTABLISHED && cli_sent < xfer {
            let take = (chunk.len() as u32).min(xfer - cli_sent) as usize;
            for (i, b) in chunk[..take].iter_mut().enumerate() {
                *b = pat(CLI, cli_sent + i as u32);
            }
            cli_sent += cli.send(&chunk[..take]) as u32;
        }
        if srv.state() == ST_ESTABLISHED && srv_sent < xfer {
            let take = (chunk.len() as u32).min(xfer - srv_sent) as usize;
            for (i, b) in chunk[..take].iter_mut().enumerate() {
                *b = pat(SRV, srv_sent + i as u32);
            }
            srv_sent += srv.send(&chunk[..take]) as u32;
        }

        // Drain + verify.
        let n = cli.recv(&mut rbuf);
        for i in 0..n {
            if rbuf[i] != pat(SRV, cli_recv + i as u32) {
                return Err(format!("{name}: client byte mismatch at {}", cli_recv + i as u32));
            }
        }
        cli_recv += n as u32;
        let n = srv.recv(&mut rbuf);
        for i in 0..n {
            if rbuf[i] != pat(CLI, srv_recv + i as u32) {
                return Err(format!("{name}: server byte mismatch at {}", srv_recv + i as u32));
            }
        }
        srv_recv += n as u32;

        if !closing
            && cli_sent == xfer
            && cli_recv == xfer
            && srv_sent == xfer
            && srv_recv == xfer
        {
            cli.close(now);
            srv.close(now);
            closing = true;
        }
        if closing
            && matches!(cli.state(), ST_CLOSED | ST_TIME_WAIT)
            && matches!(srv.state(), ST_CLOSED | ST_TIME_WAIT)
            && !c2s.pending()
            && !s2c.pending()
        {
            return Ok(());
        }
    }

    Err(format!(
        "{name}: did not converge (cli {cli_sent}/{cli_recv}, srv {srv_sent}/{srv_recv}, state {} {})",
        cli.state(),
        srv.state()
    ))
}

fn main() {
    // `tcp_init` materialises a full ~2.15 MiB `Tcb` (default inline 1 MiB
    // rings) while writing it into the host storage block, so the *calling
    // thread* needs a few MiB of stack headroom. Real FFI hosts either run
    // on a generous stack (Python/.NET main threads are several MiB) or
    // build the cdylib with the `heap-buffers` feature. We make the
    // requirement explicit by running on a 16 MiB stack.
    let handle = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .expect("spawn");
    let failures = handle.join().expect("join");

    if failures == 0 {
        println!("\nPASS — integration is conformant.");
        std::process::exit(0);
    } else {
        println!("\nFAIL — {failures} check(s) failed.");
        std::process::exit(1);
    }
}

fn run() -> u32 {
    let mut failures = 0u32;

    println!("ABI version: {}", tcp_abi_version());
    println!("MAX_PACKET:  {}", tcp_max_packet());

    // 0. Built-in linkage/health smoke test.
    let rc = tcp_selftest();
    if rc == 0 {
        println!("[ OK ] tcp_selftest() built-in smoke");
    } else {
        println!("[FAIL] tcp_selftest() returned {rc}");
        failures += 1;
    }

    // 1..N. Full bidirectional transfers over increasingly hostile links.
    let scenarios: &[(&str, Chaos)] = &[
        ("clean", Chaos { drop_p: 0.0, dup_p: 0.0, reorder_p: 0.0 }),
        ("loss-2pct", Chaos { drop_p: 0.02, dup_p: 0.0, reorder_p: 0.0 }),
        ("reorder-2pct", Chaos { drop_p: 0.0, dup_p: 0.0, reorder_p: 0.02 }),
        ("dup-1pct", Chaos { drop_p: 0.0, dup_p: 0.01, reorder_p: 0.0 }),
        (
            "kitchen-sink",
            Chaos { drop_p: 0.01, dup_p: 0.01, reorder_p: 0.01 },
        ),
    ];
    let xfer = 256 * 1024;
    for (i, (name, chaos)) in scenarios.iter().enumerate() {
        match run_transfer(name, xfer, *chaos, 0xC0FFEE ^ (i as u64)) {
            Ok(()) => println!("[ OK ] {name}: {} KiB each way, digests match", xfer >> 10),
            Err(e) => {
                println!("[FAIL] {e}");
                failures += 1;
            }
        }
    }

    failures
}
