//! C ABI surface.
//!
//! The host language interacts with the stack through an opaque
//! `TcpStreamHandle` pointer. Every function has a stable, conservative
//! signature suitable for `dllimport` / `ctypes` / P/Invoke.
//!
//! Conventions:
//! * Returns `>= 0` on success (often a byte count, or `0` for ok).
//! * Returns one of the negative [`crate::error::TcpError`] codes on failure.
//! * Pointers to non-self buffers are read-only unless the parameter is named
//!   `out_*`.
//!
//! ## Memory ownership (zero-allocation)
//! The crate is `#![no_std]` with no global allocator. Storage for a
//! connection handle is supplied by the host: query the required size /
//! alignment via [`tcp_handle_size`] and [`tcp_handle_align`], allocate
//! that block in the host language (e.g. `Marshal.AllocHGlobal` in C#,
//! `ctypes.create_string_buffer` in Python), and pass it in to
//! [`tcp_init`]. Release the memory in the host after [`tcp_destroy`].

use core::ptr::NonNull;

use crate::error::TcpError;
use crate::tcb::{Endpoint, Tcb, TcbConfig};

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
#[no_mangle]
pub extern "C" fn tcp_abi_version() -> u32 {
    2
}

/// Maximum size in bytes of a single IPv4+TCP datagram the stack can
/// emit. Hosts size their per-TCB extract buffer using this. Currently
/// 1500 (IPv4 fixed 20 + TCP fixed 20 + MSS 1460).
#[no_mangle]
pub extern "C" fn tcp_max_packet() -> usize {
    crate::MAX_PACKET
}

/// Built-in self-conformance smoke test. Drives two in-process instances
/// of the stack through a byte-exact bidirectional bulk transfer and a
/// clean close — no storage, transport, clock, or reference peer required.
///
/// Returns `0` ([`crate::selftest::result::OK`]) on success, or a negative
/// `crate::selftest::result` code identifying the failure stage. A binding
/// should call this once after loading the library to confirm the link /
/// ABI / calling convention are correct and the core is healthy before
/// wiring up a real connection.
///
/// Cost: runs entirely on the caller's stack (~256 KiB) for well under a
/// millisecond; it does not touch the passed-in handle storage and takes
/// no arguments.
#[no_mangle]
pub extern "C" fn tcp_selftest() -> i32 {
    crate::selftest::self_conformance()
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Initialise a fresh handle in caller-provided storage.
///
/// * `storage` — block of at least `tcp_handle_size()` bytes, aligned to
///   `tcp_handle_align()`. Must remain valid until [`tcp_destroy`] is called.
/// * `local_ip` / `remote_ip` — pointers to four contiguous bytes (IPv4
///   network-order octets).
/// * `iss` — caller-supplied initial send sequence (use a CSPRNG).
/// * `initial_rto_ms` — starting retransmission timeout (e.g. 1000).
///
/// Returns `0` on success or a negative [`TcpError`] code.
///
/// # Safety
/// `storage` must be writable for at least `tcp_handle_size()` bytes and
/// aligned to `tcp_handle_align()`. `local_ip` and `remote_ip` must each
/// point to four readable bytes (or be null — null returns `NullPointer`).
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
    // SAFETY: caller guarantees `storage` points to writable, properly aligned
    // memory of at least `tcp_handle_size()` bytes (or is null).
    let slot = match unsafe { storage.as_mut() } {
        Some(s) => s,
        None => return TcpError::NullPointer.as_code(),
    };
    let local = match read_ip(local_ip) {
        Some(v) => v,
        None => return TcpError::NullPointer.as_code(),
    };
    let remote = match read_ip(remote_ip) {
        Some(v) => v,
        None => return TcpError::NullPointer.as_code(),
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
    match Tcb::new(cfg) {
        Ok(inner) => {
            // SAFETY: `slot` is exclusive and writable; we overwrite without
            // dropping prior contents (the caller guarantees the storage is
            // fresh / not currently holding a live `TcpStreamHandle`).
            unsafe {
                core::ptr::write(
                    slot as *mut TcpStreamHandle,
                    TcpStreamHandle {
                        magic: MAGIC_LIVE,
                        inner,
                    },
                );
            }
            0
        }
        Err(e) => e.as_code(),
    }
}

/// Tear down a handle. The storage block itself is owned by the host; this
/// only invalidates the magic guard. Safe to call with NULL.
///
/// # Safety
/// `handle` must have been produced by [`tcp_init`].
#[no_mangle]
pub unsafe extern "C" fn tcp_destroy(handle: *mut TcpStreamHandle) -> i32 {
    // SAFETY: per the function-level safety contract, `handle` is either null
    // or points to a live handle initialised by `tcp_init`.
    let h = match unsafe { handle.as_mut() } {
        Some(h) => h,
        None => return 0,
    };
    if h.magic != MAGIC_LIVE {
        return TcpError::InvalidState.as_code();
    }
    h.magic = MAGIC_DEAD;
    // No drop glue is required — `Tcb` contains only POD fields and fixed
    // arrays. We keep this explicit so future non-trivial fields force an audit.
    0
}

// ---------------------------------------------------------------------------
// Connection control
// ---------------------------------------------------------------------------

/// Initiate the active open (transitions `CLOSED` → `SYN_SENT`).
#[no_mangle]
pub extern "C" fn tcp_connect(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    with_handle(handle, |h| {
        h.set_now(now_ms);
        h.connect()
    })
}

/// Initiate a passive open (transitions `CLOSED` → `LISTEN`). The remote
/// endpoint configured at [`tcp_init`] is wildcarded — the next inbound
/// SYN will pin a remote and drive the handshake. Idempotent on repeat.
///
/// SYN flood resistance: the listener will only ever hold one half-open
/// at a time, with at most a small number of SYN-ACK retransmits before
/// reverting to LISTEN. For full statelessness against blind floods,
/// install a 16-byte cookie secret with [`tcp_set_cookie_secret`] before
/// calling this.
#[no_mangle]
pub extern "C" fn tcp_listen(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    with_handle(handle, |h| {
        h.set_now(now_ms);
        h.listen()
    })
}

/// Install a 128-bit secret enabling stateless SYN cookies (RFC 4987).
/// Once set, an inbound SYN in `LISTEN` is answered with a stateless
/// cookie SYN-ACK; the third ACK is validated by recomputing the cookie
/// from the secret + 5-tuple + a coarse time bucket. No per-half-open
/// state is held until the connection is fully established.
///
/// Pass a high-entropy secret (CSPRNG output). Rotating the secret
/// invalidates outstanding cookies — the peer will retransmit the SYN.
///
/// # Safety
/// `secret` must point to at least 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn tcp_set_cookie_secret(
    handle: *mut TcpStreamHandle,
    secret: *const u8,
) -> i32 {
    if secret.is_null() {
        return TcpError::NullPointer.as_code();
    }
    with_handle(handle, |h| {
        // SAFETY: caller guarantees `secret` points to at least 16 readable
        // bytes; we copy into a local buffer before storing.
        let mut buf = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(secret, buf.as_mut_ptr(), 16);
        }
        h.set_cookie_secret(&buf);
        Ok(())
    })
}

/// Begin a graceful close. Idempotent.
#[no_mangle]
pub extern "C" fn tcp_close(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    with_handle(handle, |h| {
        h.set_now(now_ms);
        h.close()
    })
}

/// Reconfigure (or disable) TCP keepalive (RFC 9293 §3.8.4) on this
/// connection. After `idle_ms` of inbound silence on an *idle* ESTABLISHED
/// connection (nothing in flight — outstanding data is already covered by the
/// retransmit timeout), up to `count` probes are sent `intvl_ms` apart; if
/// none is answered the connection is aborted as a vanished peer (surfaced via
/// `tcp_poll`'s ERROR bit and `tcp_recv` returning `ConnectionReset`, with no
/// RST emitted). Any inbound segment resets the idle timer. **On by default**
/// (10 min idle / 60 s interval / 4 probes ≈ 14 min to reap a vanished idle
/// peer), so an abandoned connection cannot pin its buffers indefinitely; pass
/// `idle_ms == 0` to disable. Additive ABI: hosts built against an older
/// version simply never call it and keep the default.
#[no_mangle]
pub extern "C" fn tcp_set_keepalive(
    handle: *mut TcpStreamHandle,
    now_ms: u64,
    idle_ms: u32,
    intvl_ms: u32,
    count: u8,
) -> i32 {
    with_handle(handle, |h| {
        h.set_now(now_ms);
        h.set_keepalive(idle_ms, intvl_ms, count);
        Ok(())
    })
}

/// Set the RFC 9293 §3.8.3 USER TIMEOUT: the maximum time the connection may
/// go without forward progress (its `snd_una` advancing) while it still has
/// unacknowledged send data, before it is aborted (`ConnectionReset` via
/// `tcp_poll` ERROR / `tcp_recv`, no RST). **On by default** (5 minutes), so
/// the zero-window / dribbled-ACK denial-of-service — an alive-but-stalling
/// peer that pins a TCB by answering probes while never opening its window —
/// is bounded out of the box. Resets only on real progress, so it is immune to
/// that proof-of-life trick (which the R2 retransmit budget is not). Pass
/// `0` to disable. Additive ABI: older hosts simply never call it and keep the
/// default.
#[no_mangle]
pub extern "C" fn tcp_set_user_timeout(
    handle: *mut TcpStreamHandle,
    now_ms: u64,
    user_timeout_ms: u32,
) -> i32 {
    with_handle(handle, |h| {
        h.set_now(now_ms);
        h.set_user_timeout(user_timeout_ms);
        Ok(())
    })
}

/// Abort the connection by emitting a TCP RST. Unlike [`tcp_close`]
/// (graceful FIN), this is an immediate teardown: a RST+ACK segment is
/// queued in the TX ring, the TCB transitions to `CLOSED`, all buffered
/// data is dropped, and the connection surfaces `ConnectionReset` via
/// [`tcp_poll`]'s `ERROR` flag. Idempotent on already-`CLOSED` TCBs;
/// no wire effect in `LISTEN` / `SYN_SENT`. After calling this, the
/// caller should drain the TX ring once (via [`tcp_extract_packet`]) to
/// emit the RST, then call [`tcp_destroy`].
#[no_mangle]
pub extern "C" fn tcp_abort(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    with_handle(handle, |h| {
        h.set_now(now_ms);
        h.abort()
    })
}

/// Returns the current connection state as a [`crate::state::State`]
/// discriminant, or `0xFF` if the handle is invalid.
#[no_mangle]
pub extern "C" fn tcp_state(handle: *const TcpStreamHandle) -> u8 {
    match validate(handle) {
        Some(h) => h.inner.state() as u8,
        None => 0xFF,
    }
}

/// Returns a bitmask of [`crate::tcb::events`] flags. `0` if invalid.
#[no_mangle]
pub extern "C" fn tcp_poll(handle: *const TcpStreamHandle) -> u32 {
    match validate(handle) {
        Some(h) => h.inner.poll(),
        None => 0,
    }
}

/// Drive timers (RTO, TIME_WAIT) and stage any newly emittable segment.
#[no_mangle]
pub extern "C" fn tcp_tick(handle: *mut TcpStreamHandle, now_ms: u64) -> i32 {
    with_handle(handle, |h| {
        h.set_now(now_ms);
        h.tick()
    })
}

// ---------------------------------------------------------------------------
// App ⇄ TCP buffers
// ---------------------------------------------------------------------------

/// Push application bytes into the send ring. `*out_written` receives the
/// number of bytes accepted; returns `WouldBlock` if the ring is full.
///
/// # Safety
/// `data` must point to at least `len` readable bytes (or be null with
/// `len == 0`). `out_written` must be writable for `usize` (or be null).
#[no_mangle]
pub unsafe extern "C" fn tcp_send(
    handle: *mut TcpStreamHandle,
    data: *const u8,
    len: usize,
    out_written: *mut usize,
) -> i32 {
    if data.is_null() && len != 0 {
        return TcpError::NullPointer.as_code();
    }
    with_handle(handle, |h| {
        // SAFETY: caller guarantees `data` points to `len` readable bytes.
        let slice = unsafe { core::slice::from_raw_parts(data, len) };
        let n = h.send(slice)?;
        if let Some(p) = NonNull::new(out_written) {
            // SAFETY: caller-owned out parameter, write is single-word.
            unsafe { core::ptr::write(p.as_ptr(), n) };
        }
        Ok(())
    })
}

/// Drain bytes from the receive ring into `buf`. `*out_read` receives the
/// count actually copied (may be 0).
///
/// # Safety
/// `buf` must point to at least `cap` writable bytes (or be null with
/// `cap == 0`). `out_read` must be writable for `usize` (or be null).
#[no_mangle]
pub unsafe extern "C" fn tcp_recv(
    handle: *mut TcpStreamHandle,
    buf: *mut u8,
    cap: usize,
    out_read: *mut usize,
) -> i32 {
    if buf.is_null() && cap != 0 {
        return TcpError::NullPointer.as_code();
    }
    with_handle(handle, |h| {
        // SAFETY: caller guarantees `buf` points to `cap` writable bytes.
        let slice = unsafe { core::slice::from_raw_parts_mut(buf, cap) };
        let n = h.recv(slice)?;
        if let Some(p) = NonNull::new(out_read) {
            // SAFETY: caller-owned out parameter, write is single-word.
            unsafe { core::ptr::write(p.as_ptr(), n) };
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// TCP ⇄ WireGuard datagrams
// ---------------------------------------------------------------------------

/// Feed an inbound IPv4+TCP datagram into the state machine.
///
/// # Safety
/// `packet` must point to at least `len` readable bytes (or be null with
/// `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn tcp_inject_packet(
    handle: *mut TcpStreamHandle,
    packet: *const u8,
    len: usize,
    now_ms: u64,
) -> i32 {
    if packet.is_null() && len != 0 {
        return TcpError::NullPointer.as_code();
    }
    with_handle(handle, |h| {
        h.set_now(now_ms);
        // SAFETY: caller guarantees the buffer is valid for `len` bytes.
        let slice = unsafe { core::slice::from_raw_parts(packet, len) };
        h.inject_packet(slice)
    })
}

/// Drain at most one outbound IPv4+TCP datagram into `buf`. `*out_written`
/// receives the byte count (0 if nothing pending). Returns `BufferTooSmall`
/// if the staged packet does not fit.
///
/// # Safety
/// `buf` must point to at least `cap` writable bytes (or be null with
/// `cap == 0`). `out_written` must be writable for `usize` (or be null).
#[no_mangle]
pub unsafe extern "C" fn tcp_extract_packet(
    handle: *mut TcpStreamHandle,
    buf: *mut u8,
    cap: usize,
    out_written: *mut usize,
) -> i32 {
    if buf.is_null() && cap != 0 {
        return TcpError::NullPointer.as_code();
    }
    with_handle(handle, |h| {
        // SAFETY: caller guarantees `buf` points to `cap` writable bytes.
        let slice = unsafe { core::slice::from_raw_parts_mut(buf, cap) };
        let n = h.extract_packet(slice)?;
        if let Some(p) = NonNull::new(out_written) {
            // SAFETY: caller-owned out parameter, write is single-word.
            unsafe { core::ptr::write(p.as_ptr(), n) };
        }
        Ok(())
    })
}

/// Diagnostic-only: copy a compact internal-state snapshot into `*out`.
/// Layout matches `crate::tcb::DebugSnapshot`. Used by integration tests
/// to surface internal state when the protocol wedges; not part of the
/// stable ABI.
///
/// # Safety
/// `out` must point to a writable [`crate::tcb::DebugSnapshot`].
#[no_mangle]
pub unsafe extern "C" fn tcp_debug_snapshot(
    handle: *const TcpStreamHandle,
    out: *mut crate::tcb::DebugSnapshot,
) -> i32 {
    let Some(h) = validate(handle) else {
        return TcpError::InvalidState.as_code();
    };
    let Some(p) = NonNull::new(out) else {
        return TcpError::NullPointer.as_code();
    };
    let snap = h.inner.debug_snapshot();
    // SAFETY: caller-owned out parameter; write is plain-data POD.
    unsafe { core::ptr::write(p.as_ptr(), snap) };
    0
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[inline]
fn read_ip(p: *const u8) -> Option<[u8; 4]> {
    let nn = NonNull::new(p as *mut u8)?;
    // SAFETY: per FFI contract, `p` points to ≥ 4 readable bytes.
    let s = unsafe { core::slice::from_raw_parts(nn.as_ptr() as *const u8, 4) };
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Some(a)
}

fn validate<'a>(handle: *const TcpStreamHandle) -> Option<&'a TcpStreamHandle> {
    // SAFETY: caller guarantees `handle` is a valid live pointer or null.
    let h = unsafe { handle.as_ref() }?;
    if h.magic != MAGIC_LIVE {
        return None;
    }
    Some(h)
}

fn validate_mut<'a>(handle: *mut TcpStreamHandle) -> Option<&'a mut TcpStreamHandle> {
    // SAFETY: caller guarantees `handle` is a valid live pointer or null.
    let h = unsafe { handle.as_mut() }?;
    if h.magic != MAGIC_LIVE {
        return None;
    }
    Some(h)
}

#[inline]
fn with_handle<F>(handle: *mut TcpStreamHandle, f: F) -> i32
where
    F: FnOnce(&mut Tcb) -> Result<(), TcpError>,
{
    let h = match validate_mut(handle) {
        Some(h) => h,
        None => return TcpError::NullPointer.as_code(),
    };
    match f(&mut h.inner) {
        Ok(()) => 0,
        Err(e) => e.as_code(),
    }
}
