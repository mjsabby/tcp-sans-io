//! Transmission Control Block (TCB) and the sans-I/O state machine.
//!
//! `Tcb` owns one connection's RFC 9293 sequence variables, its fixed-size
//! send and receive rings, the loss-recovery machinery (per-segment
//! retransmission queue, RACK-TLP, PRR-Reno), and every timer. It does no
//! I/O: inputs are a host-supplied monotonic clock (`now_ms`), inbound IPv4
//! datagrams and application bytes; outputs are outbound datagrams staged in
//! an egress ring and application bytes.
//!
//! The implementation is split by concern:
//!
//! * `input`  — segment acceptance and the per-state receive logic,
//! * `ack`    — acknowledgment processing, SACK/D-SACK, RACK, recovery,
//! * `output` — transmission (new data, retransmissions, FIN, probes),
//! * `timers` — `tick()`: RTO, TLP, RACK reorder, persist, keepalive, …,
//! * `cookie` — SYN cookies, keyed hashing, timestamp offsets.

mod ack;
mod cookie;
mod input;
mod output;
#[cfg(test)]
mod tests;
mod timers;

#[cfg(test)]
pub(crate) use cookie::COOKIE_TIME_BUCKET_MS;

use crate::congestion::{self, Reno};
use crate::error::TcpError;
use crate::ooo::OooList;
use crate::rack::Rack;
use crate::ring::Ring;
use crate::rtx_queue::RtxQueue;
use crate::state::State;
use crate::tx_ring::TxRing;
use crate::wire;
use crate::BUF_CAP;

/// 4-tuple endpoint identifying one side of a connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: [u8; 4],
    pub port: u16,
}

/// User-supplied parameters at connection creation.
#[derive(Copy, Clone, Debug)]
pub struct TcbConfig {
    pub local: Endpoint,
    pub remote: Endpoint,
    /// Initial Send Sequence number. Hosts should pass a high-entropy value
    /// (RFC 6528) — the stack itself has no RNG.
    pub iss: u32,
    /// Initial RTO in milliseconds (RFC 6298 recommends 1000).
    pub initial_rto_ms: u32,
}

/// Bit-flags returned by [`Tcb::poll`] so async runtimes can wake the right
/// task. Stable values — part of the FFI contract.
pub mod events {
    pub const READABLE: u32 = 1 << 0;
    pub const WRITABLE: u32 = 1 << 1;
    pub const ESTABLISHED: u32 = 1 << 2;
    pub const PEER_CLOSED: u32 = 1 << 3;
    pub const CLOSED: u32 = 1 << 4;
    pub const TX_PENDING: u32 = 1 << 5;
    pub const ERROR: u32 = 1 << 6;
    /// TCB is in `LISTEN`, ready to accept the next inbound SYN.
    pub const LISTENING: u32 = 1 << 7;
    /// Half-open: a SYN was accepted and the SYN-ACK is in flight; the
    /// matching ACK has not yet arrived.
    pub const HALF_OPEN: u32 = 1 << 8;
}

/// 2*MSL — RFC 793 specifies 2 minutes; 60 s as Linux (`TCP_TIMEWAIT_LEN`).
const TIME_WAIT_MS: u64 = 60_000;
const RTO_MAX_MS: u32 = 60_000;
const RTO_MIN_MS: u32 = 200;
/// Delayed-ACK quantum (Linux default is 40 ms; RFC 5681 caps at 500 ms).
const DELAYED_ACK_MS: u64 = 40;
/// Peer MSS assumed when the SYN carries no MSS option (RFC 9293 §3.7.1).
const DEFAULT_PEER_MSS: u16 = 536;
/// Smallest peer MSS honoured. A peer may legitimately ask for tiny
/// segments, but each costs a full header and a retransmission-queue slot;
/// the floor bounds that per-byte amplification (Linux `tcp_min_snd_mss`).
const MIN_PEER_MSS: u16 = 64;
/// Accepted IPv4 MTU range for [`Tcb::set_mtu`] / [`Tcb::update_pmtu`].
pub const MIN_MTU: u16 = 576;
pub const MAX_MTU: u16 = crate::MAX_PACKET as u16;
/// IPv4 + TCP fixed headers.
const HDR_LEN: u16 = 40;
/// Minimum TLP probe timeout (RFC 8985 §7.2).
const TLP_MIN_PTO_MS: u64 = 10;
/// Worst-case delayed-ACK time added to the PTO when one segment is in
/// flight (RFC 8985 `WCDelAckT`).
const TLP_WC_DELACK_MS: u64 = 200;
/// SYN-ACK retransmissions in `SYN_RCVD` before reverting to `LISTEN`.
const MAX_SYN_RCVD_RETRIES: u8 = 5;
/// SYN retransmissions in `SYN_SENT` before giving up (Linux `tcp_syn_retries`).
const MAX_SYN_RETRIES: u8 = 6;
/// RFC 9293 §3.8.3 "R2": consecutive retransmission timeouts (or unanswered
/// zero-window probes) with no proof of life before the connection aborts.
/// Reset by any acceptable ACK. No RST is sent: the peer is presumed gone.
const MAX_RETRANSMITS: u8 = 10;
/// Default RFC 9293 §3.8.3 USER TIMEOUT: maximum time without *meaningful*
/// forward progress (at least one full segment acknowledged) while send work
/// is outstanding. Window-starved trickles and zero-window persist do not
/// count as progress, which bounds slow-reader / "Sockstress" pinning.
const DEFAULT_USER_TIMEOUT_MS: u32 = 300_000;
/// Default keepalive (RFC 9293 §3.8.4) for fully idle connections.
const DEFAULT_KEEPALIVE_IDLE_MS: u32 = 600_000;
const DEFAULT_KEEPALIVE_INTVL_MS: u32 = 60_000;
const DEFAULT_KEEPALIVE_COUNT: u8 = 4;
/// Default FIN_WAIT_2 timeout (Linux `tcp_fin_timeout`): after our FIN is
/// acknowledged, the peer has this long (refreshed by any data it sends) to
/// send its own FIN before the connection is reset.
const DEFAULT_FIN_WAIT2_TIMEOUT_MS: u32 = 60_000;
/// Minimum spacing of responses to unacceptable / suspicious segments
/// (RFC 5961 §7 challenge ACKs, out-of-window dup ACKs, RSTs to stray
/// ACKs). Per connection, as Linux `tcp_invalid_ratelimit`; prevents ACK
/// storms and reflection at line rate.
const OOW_RATELIMIT_MS: u64 = 500;
/// RFC 7323 §5.5: `TS.Recent` older than 24 days is no longer trusted.
const PAWS_IDLE_MS: u64 = 24 * 24 * 60 * 60 * 1000;
/// Path-MTU black-hole detection (RFC 4821 spirit, Linux `tcp_mtu_probing`):
/// after this many consecutive RTOs of an over-sized segment, clamp the MSS.
const BLACKHOLE_RTO_STEP1: u8 = 3;
const BLACKHOLE_RTO_STEP2: u8 = 5;
const BLACKHOLE_MSS1: u16 = 1024;
const BLACKHOLE_MSS2: u16 = DEFAULT_PEER_MSS;

/// Window Scale shift count (RFC 7323 §2) we advertise, derived from the
/// receive-ring capacity: the minimal scale that lets us advertise the
/// whole ring (`buf >> shift` must fit the 16-bit window field).
const fn local_ws_shift(buf: usize) -> u8 {
    let mut shift = 0u8;
    while (buf >> shift) > u16::MAX as usize && shift < 14 {
        shift += 1;
    }
    shift
}

/// A timer deadline whose all-zero bit pattern means "disarmed" (so a
/// zero-filled `Tcb` is valid — see [`Tcb::init_in_place`]).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Deadline(u64);

impl Deadline {
    pub(crate) const OFF: Self = Self(0);
    #[inline]
    pub(crate) fn at(t: u64) -> Self {
        Self(t.saturating_add(1))
    }
    #[inline]
    pub(crate) fn get(self) -> Option<u64> {
        self.0.checked_sub(1)
    }
    #[inline]
    pub(crate) fn is_armed(self) -> bool {
        self.0 != 0
    }
    #[inline]
    pub(crate) fn due(self, now: u64) -> bool {
        matches!(self.get(), Some(d) if now >= d)
    }
}

/// Compact internal-state snapshot intended only for diagnostic logging.
/// Layout is C-compatible so it can be exposed to FFI consumers.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DebugSnapshot {
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub rcv_nxt: u32,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub rto_ms: u32,
    pub rto_deadline: u64,
    pub now_ms: u64,
    pub send_ring_len: u32,
    pub recv_ring_len: u32,
    pub oo_start: u32,
    pub oo_len: u32,
    pub tx_len: u32,
    pub pending_ack: bool,
    pub dup_ack_count: u8,
    pub state: u8,
}

/// Per-connection counters for observability and benchmarking (comparable
/// to Linux `TCP_INFO`). C-compatible; exposed through `tcp_get_stats`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TcbStats {
    /// Segments emitted (all kinds).
    pub segs_out: u64,
    /// Segments accepted for processing (passed the 4-tuple filter).
    pub segs_in: u64,
    /// Payload bytes transmitted, including retransmissions.
    pub bytes_sent: u64,
    /// Payload bytes retransmitted.
    pub bytes_retrans: u64,
    /// In-order payload bytes delivered into the receive ring.
    pub bytes_received: u64,
    /// Duplicate payload bytes received (already held).
    pub dup_bytes_received: u64,
    /// Data segments retransmitted (RACK, dup-ACK, RTO or TLP).
    pub segs_retrans: u64,
    /// ACKs carrying a D-SACK block (a spurious retransmission by us).
    pub dsacks_received: u64,
    /// Fast-recovery episodes entered.
    pub fast_recoveries: u32,
    /// Retransmission timeouts.
    pub rto_count: u32,
    /// Tail loss probes sent.
    pub tlp_count: u32,
    /// Out-of-order segments dropped because the range tracker was full.
    pub ooo_drops: u32,
    /// Responses suppressed by the out-of-window rate limiter.
    pub oow_suppressed: u32,
    pub srtt_ms: u32,
    pub rttvar_ms: u32,
    pub min_rtt_ms: u32,
    pub rto_ms: u32,
    pub cwnd: u32,
    pub ssthresh: u32,
    /// RFC 6675 bytes in flight.
    pub pipe: u32,
    /// Current maximum payload bytes per segment.
    pub mss: u32,
    pub snd_wnd: u32,
    pub rcv_wnd: u32,
    /// `congestion::CaState` discriminant.
    pub ca_state: u8,
    pub state: u8,
    pub _reserved: [u8; 2],
}

// The C header mirrors `TcbStats` byte for byte.
const _: () = assert!(core::mem::size_of::<TcbStats>() == 128);

/// Per-connection state.
pub struct Tcb<const BUF: usize = BUF_CAP> {
    state: State,
    local: Endpoint,
    remote: Endpoint,

    // ---- Send sequence space (RFC 9293 §3.3.1). `snd_nxt` is the highest
    // sequence number sent + 1 and is never rewound: retransmissions are
    // driven from the retransmission queue.
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    /// Largest window the peer has ever advertised (RFC 5961 §5 MAX.SND.WND;
    /// also the sender-SWS reference, RFC 9293 §3.8.6.2.1).
    max_snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    iss: u32,
    /// Host-provided ISS from the config (restored on reset).
    cfg_iss: u32,

    // ---- Receive sequence space.
    rcv_nxt: u32,
    rcv_wnd: u32,
    irs: u32,
    /// Right edge (`ack + window`) last advertised; never moves left.
    rcv_adv_edge: u32,
    /// ACK value of the last segment we sent (RFC 7323 `Last.ACK.sent`).
    last_ack_sent: u32,

    // ---- Negotiated options.
    mtu: u16,
    local_mss: u16,
    peer_mss: u16,
    /// Path-MTU cap on the MSS (lowered by `update_pmtu` / black-hole).
    pmtu_mss: u16,
    ts_enabled: bool,
    ts_recent: u32,
    ts_recent_stamp: u64,
    /// Per-connection timestamp offset (RFC 7323 §5.4): TSval = clock + off.
    ts_offset: u32,
    /// Both sides offered Window Scale (RFC 7323 §2.2); scaling applies
    /// in both directions (possibly with a zero shift).
    ws_ok: bool,
    snd_wscale: u8,
    rcv_wscale: u8,
    sack_enabled: bool,
    ecn_enabled: bool,
    ce_observed: bool,
    send_cwr_pending: bool,

    // ---- Loss recovery.
    rtx: RtxQueue,
    rack: Rack,
    rack_deadline: Deadline,
    tlp_deadline: Deadline,
    tlp_end_seq: Option<u32>,
    tlp_is_retrans: bool,
    /// Duplicate-ACK counter (RFC 6582 NewReno; RFC 6675 DupThresh fallback
    /// when a SACK connection receives block-less duplicate ACKs).
    dup_acks: u8,
    /// Without SACK, each duplicate ACK is assumed to have delivered one
    /// segment (RFC 6937 §3 / Linux "reno SACK"): bytes counted that way,
    /// subtracted from `pipe` until the cumulative ACK covers them.
    reno_sacked: u32,
    cc: Reno,
    /// Sender was cwnd-limited in the current round (gates cwnd growth).
    cwnd_limited: bool,
    cwnd_limited_seq: u32,
    /// Highest `pipe` observed this round (slow-start cwnd-limited test).
    pipe_hiwat: u32,
    /// Time of the last new-data transmission (idle restart, RFC 5681 §4.1).
    last_data_send_ms: u64,
    /// Time of the SYN / SYN-ACK transmission (handshake RTT sample).
    syn_xmit_ms: u64,
    syn_retransmitted: bool,

    // ---- Buffers.
    send_ring: Ring<BUF>,
    recv_ring: Ring<BUF>,
    /// Out-of-order ranges parked in `recv_ring`'s free space.
    ooo: OooList,
    /// A FIN seen beyond `RCV.NXT` (processed when the gap closes).
    ooo_fin: Option<u32>,
    /// D-SACK block to report on the next ACK (RFC 2883).
    dsack: Option<(u32, u32)>,

    // ---- RTT / RTO (RFC 6298).
    now_ms: u64,
    init_rto_ms: u32,
    rto_ms: u32,
    srtt_ms: u32,
    rttvar_ms: u32,
    rtt_first_sample: bool,
    rto_deadline: Deadline,
    /// Consecutive RTOs / unanswered probes with no proof of life (R2).
    rtx_count: u8,

    // ---- Delayed ACK.
    pending_ack: bool,
    delayed_ack_count: u8,
    ack_deadline: Deadline,

    // ---- Persist / sender-SWS override timer.
    persist_deadline: Deadline,
    persist_backoff_ms: u32,

    // ---- Close.
    fin_sent: bool,
    fin_seq: u32,
    time_wait_deadline: Deadline,
    fin_wait2_timeout_ms: u32,
    fin_wait2_deadline: Deadline,
    error: Option<TcpError>,

    // ---- Egress staging.
    tx_ring: TxRing,
    ip_id: u16,

    // ---- Passive open.
    is_listener: bool,
    syn_rcvd_retries: u8,

    // ---- Keepalive (RFC 9293 §3.8.4).
    keepalive_idle_ms: u32,
    keepalive_intvl_ms: u32,
    keepalive_count: u8,
    keepalive_probes: u8,
    keepalive_deadline: Deadline,

    // ---- USER TIMEOUT (RFC 9293 §3.8.3).
    user_timeout_ms: u32,
    user_timeout_deadline: Deadline,
    /// Bytes acknowledged since the USER TIMEOUT was last re-armed.
    ut_progress: u32,

    // ---- Abuse resistance.
    /// Time of the last rate-limited response (0 bit pattern = never).
    last_oow_ms: Deadline,

    // ---- Secrets.
    cookie_secret: [u8; 16],
    cookie_secret_set: bool,
    /// Secret replaced by the last [`Tcb::set_cookie_secret`] call; cookies
    /// minted under it stay valid until `prev_cookie_until` (two buckets).
    prev_cookie_secret: [u8; 16],
    prev_cookie_until: Deadline,
    secret: [u8; 16],
    secret_set: bool,

    stats: TcbStats,
}

#[inline]
pub(crate) fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
#[inline]
pub(crate) fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}
#[inline]
pub(crate) fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}
#[inline]
pub(crate) fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
/// `lo <= x < hi` in sequence space.
#[inline]
pub(crate) fn seq_in_range(x: u32, lo: u32, hi_exclusive: u32) -> bool {
    x.wrapping_sub(lo) < hi_exclusive.wrapping_sub(lo)
}

impl<const BUF: usize> Tcb<BUF> {
    /// Window-scale shift advertised for this ring capacity (compile-time).
    const WS: u8 = local_ws_shift(BUF);

    /// Construct a TCB in the `CLOSED` state.
    pub fn new(cfg: TcbConfig) -> Result<Self, TcpError> {
        let mut slot = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: `slot` is exclusively owned, properly aligned storage for
        // one `Self`; `init_in_place` fully initialises it on success.
        unsafe {
            Self::init_in_place(slot.as_mut_ptr(), cfg)?;
            Ok(slot.assume_init())
        }
    }

    /// Initialise a TCB directly in caller-provided storage, without ever
    /// materialising a `Tcb` on the stack (a default `Tcb` is ~2.1 MiB, more
    /// than many thread stacks hold). This is what `tcp_init` uses.
    ///
    /// # Safety
    /// `p` must be valid for writes of `size_of::<Self>()` bytes and aligned
    /// to `align_of::<Self>()`. Any previous value is overwritten without
    /// being dropped.
    pub unsafe fn init_in_place(p: *mut Self, cfg: TcbConfig) -> Result<(), TcpError> {
        if BUF == 0 || (BUF & (BUF - 1)) != 0 {
            return Err(TcpError::Overflow);
        }
        // SAFETY: the caller guarantees `p` is valid and aligned for one
        // `Self`. Zero-filling makes every field a valid value except the
        // ones written explicitly below: every other field is an integer,
        // bool, byte array, `Deadline` (zero = disarmed) or an all-integer
        // struct, and the `State`/`CaState` enums use 0 for their initial
        // variant. `Option` fields are written explicitly (their `None`
        // encoding is not guaranteed to be all-zero). Only then is a
        // reference created.
        unsafe {
            core::ptr::write_bytes(p, 0, 1);
            core::ptr::addr_of_mut!((*p).state).write(State::Closed);
            core::ptr::addr_of_mut!((*p).error).write(None);
            core::ptr::addr_of_mut!((*p).tlp_end_seq).write(None);
            core::ptr::addr_of_mut!((*p).ooo_fin).write(None);
            core::ptr::addr_of_mut!((*p).dsack).write(None);
            core::ptr::addr_of_mut!((*p).cc).write(Reno::new(congestion::INITIAL_WINDOW));
            #[cfg(feature = "heap-buffers")]
            {
                core::ptr::addr_of_mut!((*p).send_ring).write(Ring::new()?);
                core::ptr::addr_of_mut!((*p).recv_ring).write(Ring::new()?);
            }
            (*p).setup(cfg);
        }
        Ok(())
    }

    /// Assign every field its post-construction value (ring storage is
    /// reused, only its indices are reset).
    fn setup(&mut self, cfg: TcbConfig) {
        self.local = cfg.local;
        self.remote = cfg.remote;
        self.cfg_iss = cfg.iss;
        self.iss = cfg.iss;
        self.init_rto_ms = cfg.initial_rto_ms.clamp(RTO_MIN_MS, RTO_MAX_MS);
        self.mtu = MAX_MTU;
        self.local_mss = MAX_MTU - HDR_LEN;
        self.is_listener = false;
        self.cookie_secret = [0; 16];
        self.cookie_secret_set = false;
        self.prev_cookie_secret = [0; 16];
        self.prev_cookie_until = Deadline::OFF;
        self.secret = [0; 16];
        self.secret_set = false;
        self.now_ms = 0;
        self.ip_id = (cfg.iss >> 16) as u16 ^ cfg.iss as u16;
        self.keepalive_idle_ms = DEFAULT_KEEPALIVE_IDLE_MS;
        self.keepalive_intvl_ms = DEFAULT_KEEPALIVE_INTVL_MS;
        self.keepalive_count = DEFAULT_KEEPALIVE_COUNT;
        self.user_timeout_ms = DEFAULT_USER_TIMEOUT_MS;
        self.fin_wait2_timeout_ms = DEFAULT_FIN_WAIT2_TIMEOUT_MS;
        self.reset_connection_state();
        self.state = State::Closed;
    }

    /// Re-point an existing TCB at a new 5-tuple / ISS and reset it to the
    /// post-`new` `CLOSED` shape **in place**, reusing the ring storage — no
    /// allocation and no multi-MiB copy. Lets a pool recycle TCBs.
    pub fn reinit(&mut self, cfg: TcbConfig) {
        self.setup(cfg);
    }

    /// Reset all per-connection state, keeping the endpoints, knobs and
    /// secrets. Used by `connect`, `listen` and the passive-open paths.
    fn reset_connection_state(&mut self) {
        self.iss = self.cfg_iss;
        self.snd_una = self.iss;
        self.snd_nxt = self.iss;
        self.snd_wnd = 0;
        self.max_snd_wnd = 0;
        self.snd_wl1 = 0;
        self.snd_wl2 = 0;
        self.rcv_nxt = 0;
        self.rcv_wnd = BUF as u32;
        self.irs = 0;
        self.rcv_adv_edge = 0;
        self.last_ack_sent = 0;
        self.local_mss = self.mtu.saturating_sub(HDR_LEN);
        self.peer_mss = DEFAULT_PEER_MSS;
        self.pmtu_mss = self.local_mss;
        self.ts_enabled = false;
        self.ts_recent = 0;
        self.ts_recent_stamp = 0;
        self.ts_offset = 0;
        self.ws_ok = false;
        self.snd_wscale = 0;
        self.rcv_wscale = 0;
        self.sack_enabled = false;
        self.ecn_enabled = false;
        self.ce_observed = false;
        self.send_cwr_pending = false;
        self.rtx.clear();
        self.rack = Rack::new();
        self.rack_deadline = Deadline::OFF;
        self.tlp_deadline = Deadline::OFF;
        self.tlp_end_seq = None;
        self.tlp_is_retrans = false;
        self.dup_acks = 0;
        self.reno_sacked = 0;
        self.cc = Reno::new(congestion::initial_window(u32::from(self.local_mss)));
        self.cwnd_limited = false;
        self.cwnd_limited_seq = self.iss;
        self.pipe_hiwat = 0;
        self.last_data_send_ms = self.now_ms;
        self.syn_xmit_ms = 0;
        self.syn_retransmitted = false;
        self.send_ring.clear();
        self.recv_ring.clear();
        self.ooo.clear();
        self.ooo_fin = None;
        self.dsack = None;
        self.rto_ms = self.init_rto_ms;
        self.srtt_ms = 0;
        self.rttvar_ms = 0;
        self.rtt_first_sample = false;
        self.rto_deadline = Deadline::OFF;
        self.rtx_count = 0;
        self.pending_ack = false;
        self.delayed_ack_count = 0;
        self.ack_deadline = Deadline::OFF;
        self.persist_deadline = Deadline::OFF;
        self.persist_backoff_ms = 0;
        self.fin_sent = false;
        self.fin_seq = 0;
        self.time_wait_deadline = Deadline::OFF;
        self.fin_wait2_deadline = Deadline::OFF;
        self.error = None;
        self.tx_ring.clear();
        self.syn_rcvd_retries = 0;
        self.keepalive_probes = 0;
        self.keepalive_deadline = Deadline::OFF;
        self.user_timeout_deadline = Deadline::OFF;
        self.ut_progress = 0;
        self.last_oow_ms = Deadline::OFF;
        self.stats = TcbStats::default();
    }

    /// Revert from a half-open passive state back to `LISTEN` (or `CLOSED`
    /// if this TCB was never a listener).
    fn reset_to_listen_or_closed(&mut self) {
        let return_to_listen = self.is_listener;
        self.reset_connection_state();
        self.remote = Endpoint {
            ip: [0u8; 4],
            port: 0,
        };
        self.state = if return_to_listen {
            State::Listen
        } else {
            State::Closed
        };
    }

    // ---------------------------------------------------------------------
    // Introspection
    // ---------------------------------------------------------------------

    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    /// Compact debug snapshot (diagnostic only).
    pub fn debug_snapshot(&self) -> DebugSnapshot {
        DebugSnapshot {
            snd_una: self.snd_una,
            snd_nxt: self.snd_nxt,
            snd_wnd: self.snd_wnd,
            rcv_nxt: self.rcv_nxt,
            cwnd: self.cc.cwnd,
            ssthresh: self.cc.ssthresh,
            rto_ms: self.rto_ms,
            rto_deadline: self.rto_deadline.get().unwrap_or(u64::MAX),
            now_ms: self.now_ms,
            send_ring_len: self.send_ring.len() as u32,
            recv_ring_len: self.recv_ring.len() as u32,
            oo_start: self.ooo.first_start().unwrap_or(0),
            oo_len: self.ooo.held_bytes(),
            tx_len: self.tx_ring.peek_head_len().unwrap_or(0) as u32,
            pending_ack: self.pending_ack,
            dup_ack_count: self.dup_acks,
            state: self.state as u8,
        }
    }

    /// Per-connection counters (see [`TcbStats`]).
    pub fn stats(&self) -> TcbStats {
        let mut s = self.stats;
        s.srtt_ms = self.srtt_ms;
        s.rttvar_ms = self.rttvar_ms;
        s.min_rtt_ms = self.rack.min_rtt.get().unwrap_or(0);
        s.rto_ms = self.rto_ms;
        s.cwnd = self.cc.cwnd;
        s.ssthresh = self.cc.ssthresh;
        s.pipe = self.pipe();
        s.mss = self.mss_payload();
        s.snd_wnd = self.snd_wnd;
        s.rcv_wnd = self.rcv_wnd;
        s.ca_state = self.cc.state() as u8;
        s.state = self.state as u8;
        s
    }

    /// Internal consistency checks for tests and fuzz targets (`std` only).
    #[cfg(any(test, feature = "std"))]
    pub fn debug_validate_invariants(&self) -> Result<(), &'static str> {
        if seq_lt(self.snd_nxt, self.snd_una) {
            return Err("snd_nxt is behind snd_una");
        }
        let syn_phantom = u32::from(self.syn_outstanding());
        let data_una = self.snd_una.wrapping_add(syn_phantom);
        if self.state.is_synchronized() {
            self.rtx.debug_valid(data_una, self.snd_nxt)?;
            let covered = self.snd_nxt.wrapping_sub(data_una);
            if !self.rtx.is_empty() || covered != 0 {
                let first = self.rtx.get(0).map(|s| s.start);
                if first != Some(data_una) {
                    return Err("rtx queue does not start at SND.UNA");
                }
            }
            let fin = u32::from(self.fin_sent && seq_lt(self.snd_una, self.snd_nxt));
            let data_out = covered.saturating_sub(fin);
            if data_out as usize > self.send_ring.len() {
                return Err("outstanding data exceeds buffered data");
            }
        }
        if self.fin_sent {
            if self.fin_seq.wrapping_add(1) != self.snd_nxt {
                return Err("FIN is not the last sequence number sent");
            }
            if !matches!(
                self.state,
                State::FinWait1
                    | State::FinWait2
                    | State::Closing
                    | State::TimeWait
                    | State::LastAck
                    | State::Closed
            ) {
                return Err("fin_sent set in non-closing state");
            }
            if matches!(self.state, State::FinWait2 | State::TimeWait)
                && seq_le(self.snd_una, self.fin_seq)
            {
                return Err("state requires our FIN to be ACKed");
            }
        }
        if self.rto_deadline.is_armed() && self.snd_una == self.snd_nxt {
            return Err("RTO armed with no outstanding sequence space");
        }
        if !self.ooo.debug_valid(self.rcv_nxt) {
            return Err("out-of-order ranges invalid");
        }
        if let Some(e) = self.ooo_last_end() {
            if e.wrapping_sub(self.rcv_nxt) as usize > self.recv_ring.free() {
                return Err("out-of-order data beyond the receive buffer");
            }
        }
        if let Some(n) = self.tx_ring.peek_head_len() {
            if n > crate::MAX_PACKET {
                return Err("staged packet exceeds MAX_PACKET");
            }
        }
        Ok(())
    }

    /// Liveness oracle: outstanding work implies a timer that will act on
    /// it. Call at rest (egress drained, after a `tick`).
    #[cfg(any(test, feature = "std"))]
    pub fn debug_check_liveness(&self) -> Result<(), &'static str> {
        if self.tx_ring.peek_head_len().is_some() || self.state == State::Closed {
            return Ok(());
        }
        if self.snd_una != self.snd_nxt
            && !self.rto_deadline.is_armed()
            && !self.tlp_deadline.is_armed()
            && !self.rack_deadline.is_armed()
        {
            return Err("liveness: outstanding data with no retransmit timer");
        }
        if self.state.can_send()
            && self.unsent_bytes() > 0
            && self.snd_una == self.snd_nxt
            && !self.persist_deadline.is_armed()
        {
            return Err("liveness: data queued with nothing in flight and no persist timer");
        }
        Ok(())
    }

    /// Absolute host time (ms) at which [`Self::tick`] next has timer work,
    /// or `None` when nothing is armed. Event-driven hosts sleep until the
    /// earlier of this and the next inbound packet, then call `tick()`.
    /// Only timers `tick()` will act on are reported, so after a `tick()`
    /// at `now` the result is always later than `now` (no busy-looping).
    ///
    /// Not timer-driven (call `tick()` yourself): transmitting data queued
    /// by [`Self::send`], and resuming output after a full egress ring was
    /// drained.
    pub fn next_deadline(&self) -> Option<u64> {
        if self.state == State::Closed {
            return None;
        }
        let ack = if self.pending_ack {
            self.ack_deadline
        } else {
            Deadline::OFF
        };
        let fin2 = if self.state == State::FinWait2 {
            self.fin_wait2_deadline
        } else {
            Deadline::OFF
        };
        [
            self.time_wait_deadline,
            fin2,
            self.rto_deadline,
            self.tlp_deadline,
            self.rack_deadline,
            self.persist_deadline,
            ack,
            self.keepalive_deadline,
            self.user_timeout_deadline,
        ]
        .into_iter()
        .filter_map(Deadline::get)
        .min()
    }

    /// Earliest output-producing armed deadline (excludes TIME_WAIT expiry).
    #[cfg(any(test, feature = "std"))]
    pub fn debug_next_deadline(&self) -> Option<u64> {
        [
            self.rto_deadline,
            self.tlp_deadline,
            self.rack_deadline,
            self.persist_deadline,
            self.ack_deadline,
            self.keepalive_deadline,
            self.fin_wait2_deadline,
        ]
        .into_iter()
        .filter_map(Deadline::get)
        .min()
    }

    // ---------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------

    /// Update the host clock. Called before every tick / packet operation.
    #[inline]
    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// Reconfigure (or disable, `idle_ms == 0`) keepalive (RFC 9293 §3.8.4)
    /// for fully idle `ESTABLISHED` connections. On by default.
    pub fn set_keepalive(&mut self, idle_ms: u32, intvl_ms: u32, count: u8) {
        self.keepalive_idle_ms = idle_ms;
        self.keepalive_intvl_ms = intvl_ms.max(1);
        self.keepalive_count = count;
        self.keepalive_probes = 0;
        self.keepalive_deadline = if idle_ms == 0 || self.state != State::Established {
            Deadline::OFF
        } else {
            Deadline::at(self.now_ms.saturating_add(u64::from(idle_ms)))
        };
    }

    /// Set the RFC 9293 §3.8.3 USER TIMEOUT (`0` disables): the connection
    /// aborts after this long without a full segment's worth of data being
    /// acknowledged while send work is outstanding. Zero-window persist and
    /// sub-MSS trickles do not count as progress.
    pub fn set_user_timeout(&mut self, ms: u32) {
        self.user_timeout_ms = ms;
        self.ut_progress = 0;
        self.user_timeout_deadline = if ms == 0 || !self.has_send_work() {
            Deadline::OFF
        } else {
            Deadline::at(self.now_ms.saturating_add(u64::from(ms)))
        };
    }

    /// Set the FIN_WAIT_2 timeout (`0` disables). Once our FIN is ACKed, the
    /// peer must send its FIN within this long (refreshed whenever it sends
    /// data); otherwise the connection is reset.
    pub fn set_fin_wait2_timeout(&mut self, ms: u32) {
        self.fin_wait2_timeout_ms = ms;
        self.fin_wait2_deadline = if ms != 0 && self.state == State::FinWait2 {
            Deadline::at(self.now_ms.saturating_add(u64::from(ms)))
        } else {
            Deadline::OFF
        };
    }

    /// Set the IPv4 MTU of the path toward the peer (clamped to
    /// [`MIN_MTU`]..=[`MAX_MTU`]). Determines the MSS we advertise and the
    /// largest datagram we emit; e.g. 1420 behind a default WireGuard
    /// interface. Only allowed before the handshake (`CLOSED` / `LISTEN`).
    pub fn set_mtu(&mut self, mtu: u16) -> Result<(), TcpError> {
        if !matches!(self.state, State::Closed | State::Listen) {
            return Err(TcpError::InvalidState);
        }
        self.mtu = mtu.clamp(MIN_MTU, MAX_MTU);
        self.local_mss = self.mtu - HDR_LEN;
        self.pmtu_mss = self.local_mss;
        self.cc = Reno::new(congestion::initial_window(u32::from(self.local_mss)));
        Ok(())
    }

    /// Report a smaller path MTU (e.g. from an ICMP "fragmentation needed"
    /// the host received, or out-of-band knowledge). Lowers the segment
    /// size for the rest of the connection and retransmits in-flight
    /// segments that no longer fit (they were most likely dropped).
    pub fn update_pmtu(&mut self, mtu: u16) {
        let mss = mtu.clamp(MIN_MTU, MAX_MTU) - HDR_LEN;
        if mss >= self.pmtu_mss {
            return;
        }
        self.pmtu_mss = mss;
        if self.state.is_synchronized() {
            let limit = self.mss_payload();
            for i in 0..self.rtx.len() {
                if let Some(s) = self.rtx.get(i).copied() {
                    if s.payload_len() > limit {
                        self.rtx.mark_lost(i);
                    }
                }
            }
            let _ = self.maybe_send_data();
        }
    }

    /// Install a 128-bit host secret (from a CSPRNG). Keys the per-connection
    /// timestamp offset (so TSval does not reveal the host clock, RFC 7323
    /// §5.4) and, on listeners without cookies, per-SYN ISNs (RFC 6528).
    pub fn set_secret(&mut self, secret: &[u8; 16]) {
        self.secret = *secret;
        self.secret_set = true;
    }

    /// Configure a 128-bit secret that switches a listener into stateless
    /// SYN-cookie mode (RFC 4987). Also used as the host secret if
    /// [`Tcb::set_secret`] was not called.
    ///
    /// Calling it again rotates the secret: cookies minted under the
    /// previous one stay valid for two time buckets (128 s, longer than any
    /// cookie's own lifetime), so handshakes in flight across a rotation
    /// still complete. Only the immediately preceding secret is kept.
    pub fn set_cookie_secret(&mut self, secret: &[u8; 16]) {
        if self.cookie_secret_set && self.cookie_secret != *secret {
            self.prev_cookie_secret = self.cookie_secret;
            self.prev_cookie_until = Deadline::at(
                self.now_ms
                    .saturating_add(2 * cookie::COOKIE_TIME_BUCKET_MS),
            );
        }
        self.cookie_secret = *secret;
        self.cookie_secret_set = true;
    }

    // ---------------------------------------------------------------------
    // Connection control
    // ---------------------------------------------------------------------

    /// Active open: `CLOSED` → `SYN_SENT`. The SYN offers MSS, Window Scale,
    /// Timestamps, SACK-permitted and ECN (RFC 3168 §6.1.1).
    pub fn connect(&mut self) -> Result<(), TcpError> {
        if self.state != State::Closed {
            return Err(TcpError::InvalidState);
        }
        self.is_listener = false;
        self.reset_connection_state();
        self.ts_offset = self.ts_offset_for(self.remote);
        self.state = State::SynSent;
        self.syn_xmit_ms = self.now_ms;
        if self.emit_syn()? {
            self.snd_nxt = self.iss.wrapping_add(1);
            self.arm_rto();
        }
        Ok(())
    }

    /// Passive open: `CLOSED` → `LISTEN` (also allowed from `LISTEN` and
    /// `TIME_WAIT`). The remote endpoint is wildcarded until a SYN arrives.
    ///
    /// Without a cookie secret the listener holds one half-open connection
    /// at a time; a half-open whose SYN-ACK has already needed a retransmit
    /// is replaced by a SYN from a new peer, so a spoofed SYN cannot lock
    /// the listener. With [`Tcb::set_cookie_secret`] the listener answers
    /// SYNs statelessly and keeps no state until the handshake completes.
    pub fn listen(&mut self) -> Result<(), TcpError> {
        match self.state {
            State::Closed | State::Listen | State::TimeWait => {}
            _ => return Err(TcpError::InvalidState),
        }
        self.remote = Endpoint {
            ip: [0u8; 4],
            port: 0,
        };
        self.is_listener = true;
        self.reset_connection_state();
        self.state = State::Listen;
        Ok(())
    }

    /// Queue application data. Returns bytes accepted (`WouldBlock` if the
    /// send ring is full). Bytes are transmitted on the next `tick` /
    /// inbound ACK.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, TcpError> {
        if !self.state.can_send() {
            return Err(TcpError::InvalidState);
        }
        let written = self.send_ring.write(data);
        if written == 0 && !data.is_empty() {
            return Err(TcpError::WouldBlock);
        }
        Ok(written)
    }

    /// Copy received in-order data out. Returns `ConnectionClosed` once the
    /// ring is empty and the peer has FINned, `ConnectionReset` after an
    /// abort.
    pub fn recv(&mut self, dst: &mut [u8]) -> Result<usize, TcpError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let n = self.recv_ring.read(dst);
        if n > 0 {
            self.maybe_send_window_update()?;
        }
        if n == 0 {
            match self.state {
                State::Closed
                | State::CloseWait
                | State::LastAck
                | State::Closing
                | State::TimeWait => return Err(TcpError::ConnectionClosed),
                _ => {}
            }
        }
        Ok(n)
    }

    /// Begin a graceful close (FIN after all queued data). Idempotent.
    pub fn close(&mut self) -> Result<(), TcpError> {
        match self.state {
            State::Established => self.state = State::FinWait1,
            State::CloseWait => self.state = State::LastAck,
            // RFC 9293 §3.10.4: CLOSE in SYN-RECEIVED with nothing queued
            // sends a FIN and enters FIN-WAIT-1.
            State::SynRcvd => self.state = State::FinWait1,
            State::Closed
            | State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::LastAck => return Ok(()),
            State::SynSent | State::Listen => {
                self.is_listener = false;
                self.reset_connection_state();
                self.state = State::Closed;
                return Ok(());
            }
        }
        self.maybe_send_data()
    }

    /// Abort: queue `RST+ACK` (seq = SND.NXT, ack = RCV.NXT) and drop all
    /// state. Local-only in `LISTEN` / `SYN_SENT`. Idempotent on `CLOSED`.
    pub fn abort(&mut self) -> Result<(), TcpError> {
        match self.state {
            State::Closed => return Ok(()),
            State::Listen | State::SynSent => {
                self.is_listener = false;
            }
            _ => {
                let _ = self.emit_ctl(
                    wire::flags::RST | wire::flags::ACK,
                    self.snd_nxt,
                    self.rcv_nxt,
                )?;
            }
        }
        self.abort_local();
        Ok(())
    }

    /// Tear the connection down locally (no RST): R2 / USER TIMEOUT /
    /// keepalive aborts, and the tail of `abort`. Surfaces `ConnectionReset`.
    fn abort_local(&mut self) {
        self.state = State::Closed;
        self.error = Some(TcpError::ConnectionReset);
        self.release_buffers_and_timers();
    }

    /// Enter `CLOSED` cleanly (no error) — e.g. our FIN ACKed in `LAST_ACK`.
    fn close_clean(&mut self) {
        self.state = State::Closed;
        self.release_buffers_and_timers();
    }

    fn release_buffers_and_timers(&mut self) {
        self.send_ring.clear();
        self.recv_ring.clear();
        self.ooo.clear();
        self.ooo_fin = None;
        self.rtx.clear();
        self.snd_nxt = self.snd_una;
        self.fin_sent = false;
        self.disarm_timers();
    }

    /// Disarm every timer, so `next_deadline()` reports nothing for a TCB
    /// that has no further work (`CLOSED`).
    pub(super) fn disarm_timers(&mut self) {
        self.rto_deadline = Deadline::OFF;
        self.time_wait_deadline = Deadline::OFF;
        self.fin_wait2_deadline = Deadline::OFF;
        self.persist_deadline = Deadline::OFF;
        self.ack_deadline = Deadline::OFF;
        self.rack_deadline = Deadline::OFF;
        self.tlp_deadline = Deadline::OFF;
        self.tlp_end_seq = None;
        self.keepalive_deadline = Deadline::OFF;
        self.keepalive_probes = 0;
        self.user_timeout_deadline = Deadline::OFF;
        self.pending_ack = false;
    }

    /// Aggregate event flags for the host async runtime.
    pub fn poll(&self) -> u32 {
        let mut ev = 0;
        if !self.recv_ring.is_empty() {
            ev |= events::READABLE;
        }
        if self.state.can_send() && self.send_ring.free() > 0 {
            ev |= events::WRITABLE;
        }
        if matches!(self.state, State::Established) {
            ev |= events::ESTABLISHED;
        }
        if matches!(
            self.state,
            State::CloseWait | State::LastAck | State::Closing | State::TimeWait
        ) {
            ev |= events::PEER_CLOSED;
        }
        if matches!(self.state, State::Closed) {
            ev |= events::CLOSED;
        }
        if matches!(self.state, State::Listen) {
            ev |= events::LISTENING;
        }
        if matches!(self.state, State::SynRcvd) {
            ev |= events::HALF_OPEN;
        }
        if !self.tx_ring.is_empty() {
            ev |= events::TX_PENDING;
        }
        if self.error.is_some() {
            ev |= events::ERROR;
        }
        ev
    }

    /// Pop one staged outbound datagram into `out` (0 when none pending).
    /// `out` must hold at least [`crate::MAX_PACKET`] bytes.
    pub fn extract_packet(&mut self, out: &mut [u8]) -> Result<usize, TcpError> {
        self.tx_ring.pop_into(out)
    }

    /// Feed an inbound IPv4+TCP datagram (checksums verified).
    pub fn inject_packet(&mut self, packet: &[u8]) -> Result<(), TcpError> {
        let seg = wire::parse(packet)?;
        self.inject_segment(&seg)
    }

    /// Like [`Self::inject_packet`] but skips TCP checksum verification, for
    /// hosts whose source already vouches for L4 integrity (checksum
    /// offload). Never use for packets from an untrusted wire.
    pub fn inject_packet_l4_csum_trusted(&mut self, packet: &[u8]) -> Result<(), TcpError> {
        let seg = wire::parse_opts(packet, false)?;
        self.inject_segment(&seg)
    }

    /// Drive timers and push more data (see [`Self::next_deadline`]).
    pub fn tick(&mut self) -> Result<(), TcpError> {
        self.run_timers()
    }

    // ---------------------------------------------------------------------
    // Shared helpers
    // ---------------------------------------------------------------------

    /// Our SYN (or SYN-ACK) is still unacknowledged.
    #[inline]
    fn syn_outstanding(&self) -> bool {
        self.snd_una == self.iss && self.snd_nxt != self.iss
    }

    /// Sequence number of the first byte in the send ring.
    #[inline]
    fn data_una(&self) -> u32 {
        self.snd_una.wrapping_add(u32::from(self.syn_outstanding()))
    }

    /// Bytes queued by the application but not yet sent.
    fn unsent_bytes(&self) -> u32 {
        let sent_data = self
            .snd_nxt
            .wrapping_sub(self.data_una())
            .saturating_sub(u32::from(self.fin_sent));
        (self.send_ring.len() as u32).saturating_sub(sent_data)
    }

    /// Unacknowledged sequence space plus unsent data.
    fn has_send_work(&self) -> bool {
        self.snd_una != self.snd_nxt || self.unsent_bytes() > 0
    }

    /// RFC 6675 `pipe`.
    fn pipe(&self) -> u32 {
        let outstanding = self.snd_nxt.wrapping_sub(self.data_una());
        self.rtx.pipe(outstanding).saturating_sub(self.reno_sacked)
    }

    /// Largest TCP payload per segment (MSS minus the always-present
    /// timestamp option).
    fn mss_payload(&self) -> u32 {
        let cap = self.local_mss.min(self.peer_mss).min(self.pmtu_mss);
        let ts = if self.ts_enabled { 12 } else { 0 };
        u32::from(cap).saturating_sub(ts).max(1)
    }

    #[cfg(any(test, feature = "std"))]
    fn ooo_last_end(&self) -> Option<u32> {
        self.ooo.last_end()
    }

    /// Rate limiter for responses to unacceptable / suspicious segments.
    /// Returns `true` if a response may be sent now.
    fn oow_allowed(&mut self) -> bool {
        if let Some(last) = self.last_oow_ms.get() {
            if self.now_ms >= last && self.now_ms - last < OOW_RATELIMIT_MS {
                self.stats.oow_suppressed = self.stats.oow_suppressed.saturating_add(1);
                return false;
            }
        }
        self.last_oow_ms = Deadline::at(self.now_ms);
        true
    }

    /// Rate-limited pure ACK (challenge ACKs, replies to old / out-of-window
    /// segments, ACKs of unsent data).
    fn send_oow_ack(&mut self) -> Result<(), TcpError> {
        if self.oow_allowed() {
            self.send_pure_ack()?;
        }
        Ok(())
    }

    fn arm_rto(&mut self) {
        self.rto_deadline = Deadline::at(self.now_ms.saturating_add(u64::from(self.rto_ms)));
    }

    /// RFC 6298 §2 SRTT/RTTVAR/RTO update.
    fn update_rtt(&mut self, r_ms: u32) {
        let r = r_ms.max(1);
        if !self.rtt_first_sample {
            self.srtt_ms = r;
            self.rttvar_ms = (r / 2).max(1);
            self.rtt_first_sample = true;
        } else {
            let diff = self.srtt_ms.abs_diff(r);
            self.rttvar_ms = (3u32.saturating_mul(self.rttvar_ms).saturating_add(diff)) / 4;
            self.srtt_ms = (7u32.saturating_mul(self.srtt_ms).saturating_add(r)) / 8;
        }
        let rto = self
            .srtt_ms
            .saturating_add(core::cmp::max(1, self.rttvar_ms.saturating_mul(4)));
        self.rto_ms = rto.clamp(RTO_MIN_MS, RTO_MAX_MS);
        self.rack.sample_rtt(self.now_ms, r);
    }

    #[inline]
    fn ts_val(&self) -> u32 {
        (self.now_ms as u32).wrapping_add(self.ts_offset)
    }

    /// Map a TSecr we sent back onto the host millisecond clock.
    #[inline]
    fn tsecr_to_ms(&self, tsecr: u32) -> u32 {
        tsecr.wrapping_sub(self.ts_offset)
    }

    #[inline]
    fn scale_peer_window(&self, w: u16) -> u32 {
        u32::from(w) << self.snd_wscale
    }
}
