//! C ABI surface.
//!
//! The host language interacts with the stack through an opaque
//! `TcpStreamHandle` pointer. Every function has a stable, conservative
//! signature suitable for `dllimport` / `ctypes` / P/Invoke / cgo.
//!
//! Conventions:
//! * Returns `>= 0` on success (often a byte count, or `0` for ok).
//! * Returns one of the negative [`crate::error::TcpError`] codes on failure.
//! * Pointers to non-self buffers are read-only unless the parameter is named
//!   `out_*`.
//! * A NULL buffer pointer is accepted only together with a zero length.
//!
//! ## Memory ownership (zero-allocation)
//! The crate is `#![no_std]` with no global allocator. Storage for a
//! connection handle is supplied by the host: query the required size /
//! alignment via [`tcp_handle_size`] and [`tcp_handle_align`], allocate
//! that block in the host language, and pass it to [`tcp_init`], which
//! initialises it **in place** (it never builds the ~2 MiB handle on the
//! caller's stack, so it is safe on small thread stacks). Release the memory
//! in the host after [`tcp_destroy`].
//!
//! ## Safety
//! Every function taking a handle is `unsafe`: the handle must be NULL or
//! point to storage initialised by [`tcp_init`] (a magic word rejects
//! destroyed or never-initialised storage, but cannot make an arbitrary
//! pointer valid), and a handle must not be used from two threads at once.

use core::ptr::NonNull;

use crate::error::TcpError;
use crate::tcb::{Endpoint, Tcb, TcbConfig, TcbStats};

/// Opaque, FFI-safe handle. Hosts only ever see `*mut TcpStreamHandle`.
#[repr(C)]
pub struct TcpStreamHandle {
    /// Magic word — guards against double-init / use-after-destroy.
    magic: u32,
    inner: Tcb,
}

const MAGIC_LIVE: u32 = 0x5443_5031; // "TCP1"
const MAGIC_DEAD: u32 = 0x4445_4144; // "DEAD"

// ---------------------------------------------------------------------------
// Storage sizing — host queries these before allocating.
// ---------------------------------------------------------------------------

/// Size in bytes of one [`TcpStreamHandle`]. Host must allocate at least this.
#[no_mangle]
pub extern "C" fn tcp_handle_size() -> usize {
    core::mem::size_of::<TcpStreamHandle>()
}

/// Required alignment for a [`TcpStreamHandle`] storage block.
#[no_mangle]
pub extern "C" fn tcp_handle_align() -> usize {
    core::mem::align_of::<TcpStreamHandle>()
}

/// Stable ABI version. Increment on any breaking change to this surface.
/// Additive functions (new setters) do not change it.
#[no_mangle]
pub extern "C" fn tcp_abi_version() -> u32 {
    2
}

/// Maximum size in bytes of a single IPv4+TCP datagram the stack can emit
/// (1500). Size every extract buffer at least this large.
#[no_mangle]
pub extern "C" fn tcp_max_packet() -> usize {
    crate::MAX_PACKET
}

/// Built-in self-conformance smoke test: two in-process stacks perform a
/// byte-exact bidirectional transfer and clean close. Returns `0` on
/// success or a negative `crate::selftest::result` stage code. Runs on the
/// caller's stack (see `crate::selftest` for the footprint).
#[no_mangle]
pub extern "C" fn tcp_selftest() -> i32 {
    crate::selftest::self_conformance()
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Initialise a fresh handle in caller-provided storage.
///
/// * `storage` — at least `tcp_handle_size()` bytes, aligned to
///   `tcp_handle_align()` (misaligned storage returns `InvalidState`).
/// * `local_ip` / `remote_ip` — four network-order IPv4 octets each.
/// * `iss` — initial send sequence (use a CSPRNG, RFC 6528).
/// * `initial_rto_ms` — starting retransmission timeout (e.g. 1000).
///
/// # Safety
/// `storage` must be writable for `tcp_handle_size()` bytes and must not
/// hold a live handle. `local_ip` / `remote_ip` must each point to four
/// readable bytes (or be NULL, which returns `NullPointer`).
#[no_mangle]
pub unsafe extern "C" fn tcp_init(
    storage: *mut TcpStreamHandle,
    local_ip: *const u8,
    local_port: u16,
    remote_ip: *const u8,
    remote_port: u16,
    iss: u32,
    initial_rto_ms: u32,
) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        init_handle(
            storage,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            iss,
            initial_rto_ms,
            false,
        )
    }
}

/// [`tcp_init`] for storage that is already all zero bytes — from `calloc`,
/// or a fresh anonymous `mmap` — which it then does not zero again. Ring
/// storage a connection never uses is never touched, so with autotuned
/// buffers ([`tcp_set_buffer_limits`]) a handle's memory follows its ring
/// capacities rather than `tcp_handle_size()`.
///
/// # Safety
/// As [`tcp_init`], and all `tcp_handle_size()` bytes at `storage` must be
/// zero.
#[no_mangle]
pub unsafe extern "C" fn tcp_init_zeroed(
    storage: *mut TcpStreamHandle,
    local_ip: *const u8,
    local_port: u16,
    remote_ip: *const u8,
    remote_port: u16,
    iss: u32,
    initial_rto_ms: u32,
) -> i32 {
    // SAFETY: forwarded caller contract (including the all-zero storage).
    unsafe {
        init_handle(
            storage,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            iss,
            initial_rto_ms,
            true,
        )
    }
}

/// # Safety
/// As [`tcp_init`]; with `zeroed`, all `tcp_handle_size()` bytes at
/// `storage` must be zero.
#[allow(clippy::too_many_arguments)]
unsafe fn init_handle(
    storage: *mut TcpStreamHandle,
    local_ip: *const u8,
    local_port: u16,
    remote_ip: *const u8,
    remote_port: u16,
    iss: u32,
    initial_rto_ms: u32,
    zeroed: bool,
) -> i32 {
    if storage.is_null() {
        return TcpError::NullPointer.as_code();
    }
    if storage.cast::<u8>().align_offset(tcp_handle_align()) != 0 {
        return TcpError::InvalidState.as_code();
    }
    // SAFETY: per the contract, the IP pointers are NULL or 4 readable bytes.
    let (Some(local), Some(remote)) = (unsafe { read_ip(local_ip) }, unsafe { read_ip(remote_ip) })
    else {
        return TcpError::NullPointer.as_code();
    };
    let cfg = TcbConfig {
        local: Endpoint {
            ip: local,
            port: local_port,
        },
        remote: Endpoint {
            ip: remote,
            port: remote_port,
        },
        iss,
        initial_rto_ms,
    };
    // SAFETY: `storage` is non-null, aligned (checked above) and writable for
    // one handle (caller contract); with `zeroed`, all of it is zero. The
    // magic is written last so a failed init never leaves a "live" handle.
    unsafe {
        core::ptr::addr_of_mut!((*storage).magic).write(MAGIC_DEAD);
        let inner = core::ptr::addr_of_mut!((*storage).inner);
        let r = if zeroed {
            Tcb::init_in_place_zeroed(inner, cfg)
        } else {
            Tcb::init_in_place(inner, cfg)
        };
        if let Err(e) = r {
            return e.as_code();
        }
        core::ptr::addr_of_mut!((*storage).magic).write(MAGIC_LIVE);
    }
    0
}

/// Tear down a handle: invalidates the magic guard and releases anything the
/// TCB itself owns (the rings under the `heap-buffers` feature; nothing in
/// the default inline build). The storage block stays owned by the host,
/// which frees it afterwards. Safe to call with NULL.
///
/// # Safety
/// `handle` must be NULL or have been initialised by [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_destroy(handle: *mut TcpStreamHandle) -> i32 {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: non-null, and initialised by `tcp_init` (caller contract).
    if unsafe { magic(handle) } != MAGIC_LIVE {
        return TcpError::InvalidState.as_code();
    }
    // SAFETY: the live magic proves `inner` was initialised by `tcp_init`
    // and not dropped since; the dead magic written first keeps every entry
    // point (a second `tcp_destroy` included) from touching it again.
    unsafe {
        core::ptr::addr_of_mut!((*handle).magic).write(MAGIC_DEAD);
        core::ptr::drop_in_place(core::ptr::addr_of_mut!((*handle).inner));
    }
    0
}

// ---------------------------------------------------------------------------
// Connection control
// ---------------------------------------------------------------------------

/// Active open (`CLOSED` → `SYN_SENT`).
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_connect(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.connect()
        })
    }
}

/// Passive open (`CLOSED` → `LISTEN`); the remote is wildcarded until a SYN
/// arrives. Requires [`tcp_set_secret`] (or [`tcp_set_cookie_secret`]) first;
/// `InvalidState` otherwise. While the single half-open slot is busy, SYNs
/// from other peers are answered with SYN cookies.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_listen(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.listen()
        })
    }
}

/// Install (or rotate to) an explicit 128-bit SYN-cookie key (RFC 4987);
/// without it the key is derived from [`tcp_set_secret`]. Cookies issued
/// under the previous key stay valid.
///
/// # Safety
/// `handle` as above; `secret` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn tcp_set_cookie_secret(
    handle: *mut TcpStreamHandle,
    secret: *const u8,
) -> i32 {
    // SAFETY: caller contract.
    let Some(buf) = (unsafe { read16(secret) }) else {
        return TcpError::NullPointer.as_code();
    };
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_cookie_secret(&buf);
            Ok(())
        })
    }
}

/// Install a 128-bit host secret (CSPRNG output). Keys the per-connection
/// TCP timestamp offset (so timestamps do not reveal the host clock),
/// passive-open ISNs and, unless one was installed explicitly, the SYN-cookie
/// key. Call before `tcp_connect` / `tcp_listen`; required by `tcp_listen`,
/// strongly recommended for internet-facing use.
///
/// # Safety
/// `handle` as above; `secret` must point to 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn tcp_set_secret(handle: *mut TcpStreamHandle, secret: *const u8) -> i32 {
    // SAFETY: caller contract.
    let Some(buf) = (unsafe { read16(secret) }) else {
        return TcpError::NullPointer.as_code();
    };
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_secret(&buf);
            Ok(())
        })
    }
}

/// Set the IPv4 path MTU (576..=1500, clamped) before the handshake. The
/// MSS advertised and the largest datagram emitted follow it — e.g. 1420
/// behind a default WireGuard interface. `InvalidState` after the open.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_set_mtu(handle: *mut TcpStreamHandle, mtu: u16) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe { with_handle(handle, |h| h.set_mtu(mtu)) }
}

/// Report a reduced path MTU mid-connection (e.g. from an ICMP
/// "fragmentation needed" the host received). Shrinks the segment size and
/// retransmits in-flight segments that no longer fit.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_update_pmtu(
    handle: *mut TcpStreamHandle,
    now_ms: u64,
    mtu: u16,
) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.update_pmtu(mtu);
            Ok(())
        })
    }
}

/// Graceful close (FIN after queued data). Idempotent.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_close(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.close()
        })
    }
}

/// Reconfigure or disable (`idle_ms == 0`) keepalive. On by default
/// (10 min idle / 60 s interval / 4 probes).
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_set_keepalive(
    handle: *mut TcpStreamHandle,
    now_ms: u64,
    idle_ms: u32,
    intvl_ms: u32,
    count: u8,
) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.set_keepalive(idle_ms, intvl_ms, count);
            Ok(())
        })
    }
}

/// Set the RFC 9293 §3.8.3 USER TIMEOUT (`0` disables; default 5 min):
/// abort after this long without a full segment acknowledged while send work
/// is outstanding (zero-window persist and sub-MSS trickles do not count).
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_set_user_timeout(
    handle: *mut TcpStreamHandle,
    now_ms: u64,
    user_timeout_ms: u32,
) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.set_user_timeout(user_timeout_ms);
            Ok(())
        })
    }
}

/// Set the FIN_WAIT_2 timeout (`0` disables; default 60 s): once our FIN is
/// ACKed, the peer must FIN within this long or the connection is reset. Only
/// the application reading data (`tcp_recv`) restarts it.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_set_fin_wait2_timeout(
    handle: *mut TcpStreamHandle,
    now_ms: u64,
    timeout_ms: u32,
) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.set_fin_wait2_timeout(timeout_ms);
            Ok(())
        })
    }
}

/// Abort: queue a RST+ACK, drop all state, surface `ConnectionReset`.
/// Drain the egress ring once afterwards to emit the RST.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_abort(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.abort()
        })
    }
}

/// Current state (`State` discriminant) or `0xFF` for an invalid handle.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_state(handle: *const TcpStreamHandle) -> u8 {
    // SAFETY: forwarded caller contract.
    match unsafe { validate(handle) } {
        Some(h) => h.inner.state() as u8,
        None => 0xFF,
    }
}

/// Absolute time (on the host's `now_ms` clock) at which [`tcp_tick`] next
/// has timer work, or `UINT64_MAX` when no timer is armed (or the handle is
/// invalid). Event-driven hosts sleep until the earlier of this and the next
/// inbound packet. After `tcp_send`, or after draining a full egress ring,
/// call `tcp_tick` directly: those are not timer events.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_next_deadline(handle: *const TcpStreamHandle) -> u64 {
    // SAFETY: forwarded caller contract.
    match unsafe { validate(handle) } {
        Some(h) => h.inner.next_deadline().unwrap_or(u64::MAX),
        None => u64::MAX,
    }
}

/// Bitmask of `TCP_EV_*` flags; `0` for an invalid handle.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_poll(handle: *const TcpStreamHandle) -> u32 {
    // SAFETY: forwarded caller contract.
    match unsafe { validate(handle) } {
        Some(h) => h.inner.poll(),
        None => 0,
    }
}

/// Drive timers and stage newly sendable segments.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_tick(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.tick()
        })
    }
}

// ---------------------------------------------------------------------------
// App ⇄ TCP buffers
// ---------------------------------------------------------------------------

/// Queue application bytes. `*out_written` receives the count accepted;
/// returns `WouldBlock` if the send ring is full.
///
/// # Safety
/// `handle` as above. `data` must point to `len` readable bytes (or be NULL
/// with `len == 0`); `out_written` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn tcp_send(
    handle: *mut TcpStreamHandle,
    data: *const u8,
    len: usize,
    out_written: *mut usize,
) -> i32 {
    // SAFETY: caller contract on `data`/`len`.
    let Some(slice) = (unsafe { in_slice(data, len) }) else {
        return TcpError::NullPointer.as_code();
    };
    // SAFETY: forwarded caller contract (including `out_written`).
    unsafe {
        with_handle(handle, |h| {
            let n = h.send(slice)?;
            write_out(out_written, n);
            Ok(())
        })
    }
}

/// Copy received bytes into `buf`; `*out_read` receives the count.
///
/// # Safety
/// `handle` as above. `buf` must point to `cap` writable bytes (or be NULL
/// with `cap == 0`); `out_read` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn tcp_recv(
    handle: *mut TcpStreamHandle,
    buf: *mut u8,
    cap: usize,
    out_read: *mut usize,
) -> i32 {
    // SAFETY: caller contract on `buf`/`cap`.
    let Some(slice) = (unsafe { out_slice(buf, cap) }) else {
        return TcpError::NullPointer.as_code();
    };
    // SAFETY: forwarded caller contract (including `out_read`).
    unsafe {
        with_handle(handle, |h| {
            let n = h.recv(slice)?;
            write_out(out_read, n);
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// TCP ⇄ network datagrams
// ---------------------------------------------------------------------------

/// Feed one inbound IPv4+TCP datagram (checksums verified).
///
/// # Safety
/// `handle` as above. `packet` must point to `len` readable bytes (or be
/// NULL with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn tcp_inject_packet(
    handle: *mut TcpStreamHandle,
    packet: *const u8,
    len: usize,
    now_ms: u64,
) -> i32 {
    // SAFETY: caller contract on `packet`/`len`.
    let Some(slice) = (unsafe { in_slice(packet, len) }) else {
        return TcpError::NullPointer.as_code();
    };
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_now(now_ms);
            h.inject_packet(slice)
        })
    }
}

/// Pop at most one outbound datagram into `buf`. `*out_written` receives the
/// byte count (0 if nothing is pending); `BufferTooSmall` leaves it staged.
///
/// # Safety
/// `handle` as above. `buf` must point to `cap` writable bytes (or be NULL
/// with `cap == 0`); `out_written` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn tcp_extract_packet(
    handle: *mut TcpStreamHandle,
    buf: *mut u8,
    cap: usize,
    out_written: *mut usize,
) -> i32 {
    // SAFETY: caller contract on `buf`/`cap`.
    let Some(slice) = (unsafe { out_slice(buf, cap) }) else {
        return TcpError::NullPointer.as_code();
    };
    // SAFETY: forwarded caller contract (including `out_written`).
    unsafe {
        with_handle(handle, |h| {
            let n = h.extract_packet(slice)?;
            write_out(out_written, n);
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Buffer sizing and memory
// ---------------------------------------------------------------------------

/// Bound the send and receive ring capacities (bytes; each clamped to
/// `4096..=BUF_CAP` and rounded down to a power of two). Equal bounds pin a
/// ring's capacity; distinct ones autotune it between them, starting each
/// connection at 64 KiB (clamped). The default pins both at `BUF_CAP`, the
/// fixed buffers of a handle that never calls this. A raised minimum
/// applies at once; under a lowered maximum no new window or send space is
/// offered beyond it and the ring shrinks once its contents and the window
/// already advertised fit. Call before `tcp_connect` / `tcp_listen` to open
/// at the initial capacity. `InvalidState` if a minimum exceeds its maximum.
///
/// # Safety
/// `handle` must be NULL or a live handle from [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_set_buffer_limits(
    handle: *mut TcpStreamHandle,
    snd_min: usize,
    snd_max: usize,
    rcv_min: usize,
    rcv_max: usize,
) -> i32 {
    // SAFETY: forwarded caller contract.
    unsafe {
        with_handle(handle, |h| {
            h.set_buffer_limits(snd_min, snd_max, rcv_min, rcv_max)
        })
    }
}

/// Current send and receive ring capacities, in bytes.
///
/// # Safety
/// `handle` as above; `out_snd` / `out_rcv` must each be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn tcp_get_buffer_sizes(
    handle: *const TcpStreamHandle,
    out_snd: *mut usize,
    out_rcv: *mut usize,
) -> i32 {
    // SAFETY: forwarded caller contract.
    let Some(h) = (unsafe { validate(handle) }) else {
        return TcpError::InvalidState.as_code();
    };
    let (snd, rcv) = h.inner.buffer_capacity();
    // SAFETY: caller-owned out parameters (or NULL).
    unsafe {
        write_out(out_snd, snd);
        write_out(out_rcv, rcv);
    }
    0
}

/// One span of handle storage (see [`tcp_reclaimable`]).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TcpSpan {
    pub ptr: *mut u8,
    pub len: usize,
}

/// List up to `cap` non-empty spans of the handle's storage that the stack
/// will not read before writing them again (at most 3: ring space past each
/// ring's capacity or a whole empty ring, and the egress slots when nothing
/// is staged); returns how many were written. A host that backs handles with
/// lazily allocated memory (`tcp_init_zeroed` over `calloc` / `mmap`) may
/// release the whole pages inside them — e.g. `madvise(MADV_DONTNEED)` once
/// a connection has been idle for a while — or overwrite them; they are
/// faulted back in when used. Valid until the next call on the handle.
///
/// # Safety
/// `handle` as above; `out` must point to `cap` writable `TcpSpan`s (or be
/// NULL with `cap == 0`).
#[no_mangle]
pub unsafe extern "C" fn tcp_reclaimable(
    handle: *mut TcpStreamHandle,
    out: *mut TcpSpan,
    cap: usize,
) -> i32 {
    if cap != 0 && out.is_null() {
        return TcpError::NullPointer.as_code();
    }
    let mut n = 0usize;
    // SAFETY: forwarded caller contract; `out` holds `cap` spans.
    let r = unsafe {
        with_handle(handle, |h| {
            for s in h.reclaimable().into_iter().filter(|s| !s.is_empty()) {
                if n == cap {
                    break;
                }
                let span = TcpSpan {
                    ptr: s.as_mut_ptr(),
                    len: s.len(),
                };
                // SAFETY: `n < cap` spans fit at `out` (caller contract).
                out.add(n).write_unaligned(span);
                n += 1;
            }
            Ok(())
        })
    };
    if r != 0 {
        return r;
    }
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// Copy per-connection counters (`TcpStats` in the header) into `*out`.
///
/// # Safety
/// `handle` as above; `out` must point to a writable `TcbStats`.
#[no_mangle]
pub unsafe extern "C" fn tcp_get_stats(handle: *const TcpStreamHandle, out: *mut TcbStats) -> i32 {
    // SAFETY: forwarded caller contract.
    let Some(h) = (unsafe { validate(handle) }) else {
        return TcpError::InvalidState.as_code();
    };
    let Some(p) = NonNull::new(out) else {
        return TcpError::NullPointer.as_code();
    };
    // SAFETY: caller-owned out parameter of the right type.
    unsafe { p.as_ptr().write_unaligned(h.inner.stats()) };
    0
}

/// Diagnostic-only state snapshot (not part of the stable ABI).
///
/// # Safety
/// `handle` as above; `out` must point to a writable `DebugSnapshot`.
#[no_mangle]
pub unsafe extern "C" fn tcp_debug_snapshot(
    handle: *const TcpStreamHandle,
    out: *mut crate::tcb::DebugSnapshot,
) -> i32 {
    // SAFETY: forwarded caller contract.
    let Some(h) = (unsafe { validate(handle) }) else {
        return TcpError::InvalidState.as_code();
    };
    let Some(p) = NonNull::new(out) else {
        return TcpError::NullPointer.as_code();
    };
    // SAFETY: caller-owned out parameter of the right type.
    unsafe { p.as_ptr().write_unaligned(h.inner.debug_snapshot()) };
    0
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// # Safety
/// `p` must be NULL or point to four readable bytes.
unsafe fn read_ip(p: *const u8) -> Option<[u8; 4]> {
    let nn = NonNull::new(p.cast_mut())?;
    let mut a = [0u8; 4];
    // SAFETY: caller contract — four readable bytes.
    unsafe { core::ptr::copy_nonoverlapping(nn.as_ptr(), a.as_mut_ptr(), 4) };
    Some(a)
}

/// # Safety
/// `p` must be NULL or point to sixteen readable bytes.
unsafe fn read16(p: *const u8) -> Option<[u8; 16]> {
    let nn = NonNull::new(p.cast_mut())?;
    let mut a = [0u8; 16];
    // SAFETY: caller contract — sixteen readable bytes.
    unsafe { core::ptr::copy_nonoverlapping(nn.as_ptr(), a.as_mut_ptr(), 16) };
    Some(a)
}

/// Borrow an input buffer. `None` for a NULL pointer with non-zero length.
/// A zero length never touches the pointer (NULL is fine).
///
/// # Safety
/// For `len > 0`, `p` must point to `len` readable bytes valid for `'a`.
unsafe fn in_slice<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    let nn = NonNull::new(p.cast_mut())?;
    // SAFETY: non-null, `len` readable bytes (caller contract).
    Some(unsafe { core::slice::from_raw_parts(nn.as_ptr(), len) })
}

/// Borrow an output buffer (see [`in_slice`]).
///
/// # Safety
/// For `len > 0`, `p` must point to `len` writable bytes valid for `'a`.
unsafe fn out_slice<'a>(p: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    let nn = NonNull::new(p)?;
    // SAFETY: non-null, `len` writable bytes (caller contract).
    Some(unsafe { core::slice::from_raw_parts_mut(nn.as_ptr(), len) })
}

/// # Safety
/// `p` must be NULL or writable for one `usize`.
unsafe fn write_out(p: *mut usize, v: usize) {
    if let Some(nn) = NonNull::new(p) {
        // SAFETY: caller contract.
        unsafe { nn.as_ptr().write_unaligned(v) };
    }
}

/// The handle's magic word, read without forming a reference to the handle:
/// after `tcp_destroy` its `inner` has been dropped.
///
/// # Safety
/// `handle` must be non-null and point to storage initialised by
/// [`tcp_init`].
unsafe fn magic(handle: *const TcpStreamHandle) -> u32 {
    // SAFETY: caller contract; `magic` is a plain `u32` field.
    unsafe { core::ptr::addr_of!((*handle).magic).read() }
}

/// # Safety
/// `handle` must be NULL or point to storage initialised by [`tcp_init`].
unsafe fn validate<'a>(handle: *const TcpStreamHandle) -> Option<&'a TcpStreamHandle> {
    // SAFETY: caller contract; only a live handle is borrowed.
    if handle.is_null() || unsafe { magic(handle) } != MAGIC_LIVE {
        return None;
    }
    // SAFETY: caller contract.
    unsafe { handle.as_ref() }
}

/// # Safety
/// `handle` must be NULL or point to storage initialised by [`tcp_init`],
/// not aliased for the duration of the call.
unsafe fn with_handle<F>(handle: *mut TcpStreamHandle, f: F) -> i32
where
    F: FnOnce(&mut Tcb) -> Result<(), TcpError>,
{
    // SAFETY: caller contract; only a live handle is borrowed.
    if handle.is_null() || unsafe { magic(handle) } != MAGIC_LIVE {
        return TcpError::NullPointer.as_code();
    }
    // SAFETY: caller contract.
    let Some(h) = (unsafe { handle.as_mut() }) else {
        return TcpError::NullPointer.as_code();
    };
    match f(&mut h.inner) {
        Ok(()) => 0,
        Err(e) => e.as_code(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    extern crate std;

    use super::*;
    use std::alloc::{alloc_zeroed, dealloc, Layout};

    /// Buffer limits, sizes and reclaimable spans through the C ABI, on
    /// zeroed storage initialised by `tcp_init_zeroed`.
    #[test]
    fn buffer_sizing_through_the_c_abi() {
        let layout = Layout::from_size_align(tcp_handle_size(), tcp_handle_align()).unwrap();
        let ip = [10u8, 0, 0, 1];
        let empty = TcpSpan {
            ptr: core::ptr::null_mut(),
            len: 0,
        };
        // SAFETY: zeroed storage of the documented size and alignment,
        // initialised once, destroyed once, then freed.
        unsafe {
            let storage = alloc_zeroed(layout);
            assert!(!storage.is_null());
            let h: *mut TcpStreamHandle = storage.cast();
            assert_eq!(
                tcp_init_zeroed(h, ip.as_ptr(), 1, ip.as_ptr(), 2, 7, 1000),
                0
            );
            let (mut snd, mut rcv) = (0usize, 0usize);
            assert_eq!(tcp_get_buffer_sizes(h, &mut snd, &mut rcv), 0);
            assert_eq!((snd, rcv), (crate::BUF_CAP, crate::BUF_CAP));
            assert_eq!(
                tcp_set_buffer_limits(h, 8192, 4096, 0, 0),
                TcpError::InvalidState.as_code()
            );
            assert_eq!(tcp_set_buffer_limits(h, 0, usize::MAX, 0, usize::MAX), 0);
            assert_eq!(tcp_get_buffer_sizes(h, &mut snd, core::ptr::null_mut()), 0);
            assert_eq!(snd, crate::INITIAL_RING_CAP.min(crate::BUF_CAP));

            let mut spans = [empty; 4];
            assert_eq!(tcp_reclaimable(h, spans.as_mut_ptr(), spans.len()), 3);
            #[cfg(not(feature = "heap-buffers"))]
            for s in &spans[..3] {
                let (lo, p) = (storage as usize, s.ptr as usize);
                assert!(
                    p >= lo && p + s.len <= lo + layout.size(),
                    "outside the handle"
                );
            }
            for s in &spans[..3] {
                core::ptr::write_bytes(s.ptr, 0xA5, s.len);
            }
            assert_eq!(tcp_reclaimable(h, spans.as_mut_ptr(), 1), 1);
            assert_eq!(tcp_reclaimable(h, core::ptr::null_mut(), 0), 0);
            assert_eq!(
                tcp_reclaimable(h, core::ptr::null_mut(), 1),
                TcpError::NullPointer.as_code()
            );
            assert!(tcp_reclaimable(core::ptr::null_mut(), spans.as_mut_ptr(), 3) < 0);
            assert!(tcp_set_buffer_limits(core::ptr::null_mut(), 0, 0, 0, 0) < 0);
            assert!(tcp_get_buffer_sizes(core::ptr::null(), &mut snd, &mut rcv) < 0);
            assert_eq!(tcp_destroy(h), 0);
            assert!(tcp_get_buffer_sizes(h, &mut snd, &mut rcv) < 0, "destroyed");
            dealloc(storage, layout);
        }
    }
}
