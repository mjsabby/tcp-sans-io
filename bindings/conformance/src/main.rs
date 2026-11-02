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
//!
//! Every scenario also runs with *elastic* handles: zero-filled storage
//! initialised by `tcp_init_zeroed`, autotuned buffers
//! (`tcp_set_buffer_limits`), and every span `tcp_reclaimable` lists
//! overwritten after every step — the stream must stay byte exact. On Linux
//! the elastic handles finally release those spans with
//! `madvise(MADV_DONTNEED)`, and `mincore` shows how little of each handle
//! stays resident.

use std::alloc::{alloc, dealloc, Layout};

use tcp_sans_io::ffi::{
    tcp_abi_version, tcp_close, tcp_connect, tcp_destroy, tcp_extract_packet,
    tcp_get_buffer_sizes, tcp_handle_align, tcp_handle_size, tcp_init, tcp_init_zeroed,
    tcp_inject_packet, tcp_listen, tcp_max_packet, tcp_reclaimable, tcp_recv, tcp_selftest,
    tcp_send, tcp_set_buffer_limits, tcp_set_secret, tcp_state, tcp_tick, TcpSpan,
    TcpStreamHandle,
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
    elastic: bool,
}

impl Handle {
    /// `elastic`: zero-filled storage (`alloc_zeroed`, i.e. `calloc`, whose
    /// large blocks are untouched zero pages) initialised by
    /// `tcp_init_zeroed`, with buffers autotuned between 4 KiB and the
    /// maximum, so only the pages the rings use are ever touched.
    fn new(
        local_ip: [u8; 4],
        lport: u16,
        remote_ip: [u8; 4],
        rport: u16,
        iss: u32,
        elastic: bool,
    ) -> Handle {
        let size = tcp_handle_size();
        let align = tcp_handle_align();
        let layout = Layout::from_size_align(size, align).expect("layout");
        // SAFETY: non-zero size from the ABI; we own this block until drop.
        let ptr = unsafe {
            if elastic {
                vm::alloc_zeroed(layout)
            } else {
                alloc(layout)
            }
        } as *mut TcpStreamHandle;
        assert!(!ptr.is_null(), "allocation failed");
        let init = if elastic { tcp_init_zeroed } else { tcp_init };
        // SAFETY: ptr is freshly allocated, correctly sized and aligned (and
        // all zero for `tcp_init_zeroed`).
        let rc = unsafe {
            init(
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
        if elastic {
            // SAFETY: live handle owned by this wrapper.
            let rc = unsafe { tcp_set_buffer_limits(ptr, 4096, usize::MAX, 4096, usize::MAX) };
            assert_eq!(rc, 0, "tcp_set_buffer_limits failed: {rc}");
        }
        Handle {
            ptr,
            layout,
            elastic,
        }
    }

    /// Storage the stack will not read before writing it again: overwrite
    /// it (`release == false`; the transfer must not notice), or on Linux
    /// hand its whole pages back to the kernel.
    fn reclaim(&self, release: bool) {
        let mut spans = [TcpSpan {
            ptr: std::ptr::null_mut(),
            len: 0,
        }; 3];
        // SAFETY: live handle; `spans` holds 3 writable entries.
        let n = unsafe { tcp_reclaimable(self.ptr, spans.as_mut_ptr(), spans.len()) };
        assert!((0..=3).contains(&n), "tcp_reclaimable returned {n}");
        for s in &spans[..n as usize] {
            if release {
                // SAFETY: the stack lent these bytes until its next call.
                unsafe { vm::release(s.ptr, s.len) };
            } else {
                // SAFETY: as above; overwriting them is allowed. Only the
                // first page or so, so that this check does not itself make
                // storage the rings never use resident.
                unsafe { std::ptr::write_bytes(s.ptr, 0xA5, s.len.min(4096)) };
            }
        }
    }

    /// Current (send, receive) ring capacities.
    fn sizes(&self) -> (usize, usize) {
        let (mut snd, mut rcv) = (0, 0);
        // SAFETY: live handle; out params are locals.
        assert_eq!(unsafe { tcp_get_buffer_sizes(self.ptr, &mut snd, &mut rcv) }, 0);
        (snd, rcv)
    }

    /// Bytes of the handle's storage resident in memory (whole pages).
    fn resident(&self) -> Option<usize> {
        // SAFETY: the handle storage spans `layout.size()` bytes.
        unsafe { vm::resident(self.ptr as *const u8, self.layout.size()) }
    }

    fn state(&self) -> u8 {
        // SAFETY: `self.ptr` is a live handle owned by this wrapper.
        unsafe { tcp_state(self.ptr) }
    }

    fn connect(&self, now: u64) {
        // SAFETY: live handle owned by this wrapper.
        assert_eq!(unsafe { tcp_connect(self.ptr, now) }, 0);
    }

    fn listen(&self, now: u64) {
        // A listener requires a secret; this in-process harness needs no
        // unpredictability, so a fixed one is fine.
        let secret = [0x5au8; 16];
        // SAFETY: live handle owned by this wrapper; `secret` is 16 bytes.
        assert_eq!(unsafe { tcp_set_secret(self.ptr, secret.as_ptr()) }, 0);
        // SAFETY: live handle owned by this wrapper.
        assert_eq!(unsafe { tcp_listen(self.ptr, now) }, 0);
    }

    fn tick(&self, now: u64) {
        // SAFETY: live handle owned by this wrapper.
        let rc = unsafe { tcp_tick(self.ptr, now) };
        assert!(rc == 0, "tcp_tick returned {rc}");
    }

    fn close(&self, now: u64) {
        // SAFETY: live handle owned by this wrapper.
        let rc = unsafe { tcp_close(self.ptr, now) };
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
            if self.elastic {
                vm::free(self.ptr as *mut u8, self.layout);
            } else {
                dealloc(self.ptr as *mut u8, self.layout);
            }
        }
    }
}

/// Page-level memory control for elastic handles (Linux; elsewhere the
/// spans are only overwritten and residency is not measured).
mod vm {
    use std::alloc::Layout;

    #[cfg(target_os = "linux")]
    extern "C" {
        fn madvise(addr: *mut std::ffi::c_void, len: usize, advice: i32) -> i32;
        fn mincore(addr: *mut std::ffi::c_void, len: usize, vec: *mut u8) -> i32;
        fn sysconf(name: i32) -> std::ffi::c_long;
        fn mmap(
            addr: *mut std::ffi::c_void,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            off: i64,
        ) -> *mut std::ffi::c_void;
        fn munmap(addr: *mut std::ffi::c_void, len: usize) -> i32;
    }

    /// Zero-filled storage whose pages are backed only once touched: a fresh
    /// anonymous mapping on Linux (`calloc` may hand out recycled heap
    /// memory, zeroed by touching every page).
    ///
    /// # Safety
    /// `layout` must have a non-zero size; free with [`free`].
    pub unsafe fn alloc_zeroed(layout: Layout) -> *mut u8 {
        #[cfg(target_os = "linux")]
        {
            const PROT_READ_WRITE: i32 = 0x1 | 0x2;
            const MAP_PRIVATE_ANONYMOUS: i32 = 0x02 | 0x20;
            assert!(layout.align() <= page());
            // SAFETY: a new private anonymous mapping (page aligned).
            let p = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    layout.size(),
                    PROT_READ_WRITE,
                    MAP_PRIVATE_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p as isize == -1 {
                std::ptr::null_mut()
            } else {
                p.cast()
            }
        }
        #[cfg(not(target_os = "linux"))]
        // SAFETY: forwarded caller contract.
        unsafe {
            std::alloc::alloc_zeroed(layout)
        }
    }

    /// # Safety
    /// `p` came from [`alloc_zeroed`] with this `layout`.
    pub unsafe fn free(p: *mut u8, layout: Layout) {
        #[cfg(target_os = "linux")]
        // SAFETY: the mapping made by `alloc_zeroed`.
        unsafe {
            munmap(p.cast(), layout.size());
        }
        #[cfg(not(target_os = "linux"))]
        // SAFETY: forwarded caller contract.
        unsafe {
            std::alloc::dealloc(p, layout)
        }
    }

    #[cfg(target_os = "linux")]
    fn page() -> usize {
        const SC_PAGESIZE: i32 = 30;
        // SAFETY: plain query.
        unsafe { sysconf(SC_PAGESIZE) as usize }
    }

    /// Release the whole pages inside `[p, p + len)` (`MADV_DONTNEED`: they
    /// read back as zeros, backed by memory again only once written).
    ///
    /// # Safety
    /// The caller may discard the contents of `[p, p + len)`.
    pub unsafe fn release(p: *mut u8, len: usize) {
        #[cfg(target_os = "linux")]
        {
            const MADV_DONTNEED: i32 = 4;
            let pg = page();
            let start = (p as usize).next_multiple_of(pg);
            let end = (p as usize + len) / pg * pg;
            if end > start {
                // SAFETY: whole pages the caller may discard.
                let rc = unsafe { madvise(start as *mut _, end - start, MADV_DONTNEED) };
                assert_eq!(rc, 0, "madvise failed");
            }
        }
        #[cfg(not(target_os = "linux"))]
        // SAFETY: the caller may discard (so overwrite) these bytes.
        unsafe {
            std::ptr::write_bytes(p, 0, len)
        };
    }

    /// Resident bytes of the pages overlapping `[p, p + len)`.
    ///
    /// # Safety
    /// `[p, p + len)` must be mapped.
    pub unsafe fn resident(p: *const u8, len: usize) -> Option<usize> {
        #[cfg(target_os = "linux")]
        {
            let pg = page();
            let start = p as usize / pg * pg;
            let end = (p as usize + len).next_multiple_of(pg);
            let mut v = vec![0u8; (end - start) / pg];
            // SAFETY: mapped range (caller contract); one byte per page.
            let rc = unsafe { mincore(start as *mut _, end - start, v.as_mut_ptr()) };
            (rc == 0).then(|| v.iter().filter(|&&b| b & 1 != 0).count() * pg)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (p, len);
            None
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
/// Returns a memory summary on a byte-exact, cleanly-closed transfer.
fn run_transfer(
    name: &str,
    xfer: u32,
    chaos: Chaos,
    seed: u64,
    elastic: bool,
) -> Result<String, String> {
    const CLI: u32 = 0x0000_0001;
    const SRV: u32 = 0x8000_0001;
    // Fixed ISS values keep this certifier byte-for-byte reproducible.
    // Do NOT copy that into a production integration: the host contract
    // (RFC 6528) requires a CSPRNG-derived `iss` per connection.
    let cli = Handle::new([10, 0, 0, 1], 40000, [10, 0, 0, 2], 80, 0x1111_1111, elastic);
    let srv = Handle::new([10, 0, 0, 2], 80, [10, 0, 0, 1], 40000, 0x9999_9999, elastic);
    let mut peak = (0usize, 0usize);
    let mut open_resident = None;

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

        if elastic {
            // Whatever the host does to reclaimable storage between calls,
            // the streams must not notice.
            cli.reclaim(false);
            srv.reclaim(false);
            let (c, s) = (cli.sizes(), srv.sizes());
            peak = (peak.0.max(c.0).max(s.0), peak.1.max(c.1).max(s.1));
        }

        if !closing
            && cli_sent == xfer
            && cli_recv == xfer
            && srv_sent == xfer
            && srv_recv == xfer
        {
            // Residency of a connection that has just moved its data.
            open_resident = cli.resident().zip(srv.resident());
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
            if elastic {
                cli.reclaim(true);
                srv.reclaim(true);
            }
            let size = tcp_handle_size();
            return Ok(match (cli.resident(), srv.resident(), open_resident) {
                (Some(c), Some(s), Some((oc, os))) => {
                    if elastic && c.max(s) > size / 4 {
                        return Err(format!(
                            "{name}: {} KiB of a {} KiB handle still resident",
                            c.max(s) >> 10,
                            size >> 10
                        ));
                    }
                    let rings = if elastic {
                        format!(", rings peaked at {} / {} KiB", peak.0 >> 10, peak.1 >> 10)
                    } else {
                        String::new()
                    };
                    let closed = if elastic { "closed, released" } else { "closed" };
                    format!(
                        "resident of 2 x {} KiB: open {} + {} KiB, {closed} {} + {} KiB{rings}",
                        size >> 10,
                        oc >> 10,
                        os >> 10,
                        c >> 10,
                        s >> 10
                    )
                }
                _ => String::from("residency not measured on this platform"),
            });
        }
    }

    Err(format!(
        "{name}: did not converge (cli {cli_sent}/{cli_recv}, srv {srv_sent}/{srv_recv}, state {} {})",
        cli.state(),
        srv.state()
    ))
}

fn main() {
    // `tcp_init` builds the ~2.15 MiB `Tcb` in place in the host's storage
    // block (`Tcb::init_in_place`) and `tcp_selftest` uses 16 KiB rings, so
    // no FFI host needs a large stack. The 16 MiB thread is only headroom.
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
    for elastic in [false, true] {
        for (i, (name, chaos)) in scenarios.iter().enumerate() {
            let label = if elastic { "elastic " } else { "" };
            match run_transfer(name, xfer, *chaos, 0xC0FFEE ^ (i as u64), elastic) {
                Ok(mem) => println!(
                    "[ OK ] {label}{name}: {} KiB each way, digests match; {mem}",
                    xfer >> 10
                ),
                Err(e) => {
                    println!("[FAIL] {label}{e}");
                    failures += 1;
                }
            }
        }
    }

    failures
}
