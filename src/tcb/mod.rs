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
/// Longest a TCB may stay in `TIME_WAIT`. A retransmitted FIN restarts the
/// 2·MSL timer (RFC 9293 §3.10.7.4), but never past this cap after entry, so
/// a peer re-sending its FIN cannot hold the (≈2 MiB) TCB indefinitely.
const TIME_WAIT_MAX_MS: u64 = 2 * TIME_WAIT_MS;
const RTO_MAX_MS: u32 = 60_000;
const RTO_MIN_MS: u32 = 200;
/// The first data RTO when the handshake gave no RTT sample (a SYN or
/// SYN-ACK resent without timestamps, or a cookie): Linux
/// `TCP_TIMEOUT_FALLBACK`, RFC 6298 §5.7.
const RTO_FALLBACK_MS: u32 = 3_000;
/// Delayed-ACK quantum (Linux default is 40 ms; RFC 5681 caps at 500 ms).
const DELAYED_ACK_MS: u64 = 40;
/// [`Tcb::ack_pushed`] bits (Linux `ICSK_ACK_PUSHED`, `ICSK_ACK_PUSHED2`).
const ACK_PUSHED: u8 = 1;
const ACK_PUSHED2: u8 = 2;
/// Most segments quickack mode ACKs at once (Linux `TCP_MAX_QUICKACKS`).
const MAX_QUICKACKS: u8 = 16;
/// Receive MSS assumed before a full segment arrives (Linux
/// `TCP_MSS_DEFAULT`, the initial `icsk_ack.rcv_mss`).
const RCV_MSS_INITIAL: u16 = 536;
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
/// acknowledged, the peer has this long to send its own FIN before the
/// connection is reset. Only the application reading received data restarts
/// it; the peer's data alone does not, so a trickling peer cannot pin a TCB
/// the host has already closed.
const DEFAULT_FIN_WAIT2_TIMEOUT_MS: u32 = 60_000;
/// Minimum spacing of responses to unacceptable / suspicious segments
/// (RFC 5961 §7 challenge ACKs, out-of-window dup ACKs, RSTs to stray
/// ACKs). Per connection, as Linux `tcp_invalid_ratelimit`; prevents ACK
/// storms and reflection at line rate.
const OOW_RATELIMIT_MS: u64 = 500;
/// `TS.Recent` idle this long is no longer trusted (Linux `TCP_PAWS_WRAP`,
/// `INT_MAX / USEC_PER_SEC` seconds): the peer's clock may tick in
/// microseconds (Linux `tcp_usec_ts`), lapping half the 32-bit space that
/// soon.
const PAWS_IDLE_MS: u64 = (i32::MAX as u64 / 1_000_000) * 1000;
/// Path-MTU black-hole detection (RFC 4821 spirit, Linux `tcp_mtu_probing`):
/// after this many consecutive RTOs of an over-sized segment, clamp the MSS.
const BLACKHOLE_RTO_STEP1: u8 = 3;
const BLACKHOLE_RTO_STEP2: u8 = 5;
const BLACKHOLE_MSS1: u16 = 1024;
const BLACKHOLE_MSS2: u16 = DEFAULT_PEER_MSS;
/// After a black-hole clamp, one segment at the next larger size probes the
/// path (RFC 4821 spirit): the first probe goes this long after the clamp, a
/// failed probe doubles the interval up to `PMTU_PROBE_MAX_MS`. A clamp
/// caused by a plain outage is therefore undone within seconds.
const PMTU_PROBE_MIN_MS: u32 = 10_000;
const PMTU_PROBE_MAX_MS: u32 = 600_000;

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
    /// MSS cap in force before a black-hole clamp (0: no clamp to undo).
    pmtu_restore_mss: u16,
    /// MSS cap the in-flight probe segment was sized for.
    pmtu_probe_mss: u16,
    /// A probe segment `[pmtu_probe_start, pmtu_probe_end)` is in flight.
    pmtu_probe_inflight: bool,
    pmtu_probe_start: u32,
    pmtu_probe_end: u32,
    /// Earliest time (ms) the next probe may be sent.
    pmtu_probe_at: u64,
    /// Current probe interval (ms).
    pmtu_probe_backoff_ms: u32,
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
    /// An ECT or CE data segment arrived (Linux `TCP_ECN_SEEN`): a Not-ECT
    /// one after it is likely a retransmission.
    ecn_seen: bool,
    send_cwr_pending: bool,

    // ---- Loss recovery.
    rtx: RtxQueue,
    rack: Rack,
    rack_deadline: Deadline,
    tlp_deadline: Deadline,
    tlp_end_seq: Option<u32>,
    tlp_is_retrans: bool,
    /// Sequence space the retransmission timer marked lost (`[SND.UNA,
    /// SND.NXT)` at the timeout, extended by repeated ones): its resends
    /// are the timer's, so their D-SACKs show a delay, not reordering.
    rto_span: Option<(u32, u32)>,
    /// F-RTO step 2.b (Linux `REXMIT_NEW`): the ACK just processed asks the
    /// next send to put out new data, Nagle aside, rather than
    /// presumed-lost segments.
    frto_new: bool,
    /// Step 2.b's new data went out: nothing is resent until the next ACK
    /// tells whether the timeout was spurious (Linux `tcp_xmit_recovery`
    /// returns before `tcp_xmit_retransmit_queue`).
    frto_hold: bool,
    /// Duplicate-ACK counter (RFC 6582 NewReno; RFC 6675 DupThresh fallback
    /// when a SACK connection receives block-less duplicate ACKs).
    dup_acks: u8,
    /// Without SACK, each duplicate ACK is assumed to have delivered one
    /// segment (RFC 6937 §3 / Linux "reno SACK"): bytes counted that way,
    /// subtracted from `pipe` until the cumulative ACK covers them.
    reno_sacked: u32,
    /// Segments reported duplicate by the D-SACKs believed so far (cf. Linux
    /// `dsack_dups`); never more than `stats.segs_retrans`.
    dsack_segs: u64,
    cc: Reno,
    /// Sender was cwnd-limited in the current round (gates cwnd growth;
    /// Linux `is_cwnd_limited`).
    cwnd_limited: bool,
    /// `SND.NXT` that closes the current round (Linux `cwnd_usage_seq`).
    cwnd_limited_seq: u32,
    /// Highest `pipe` sent into this round (Linux `max_packets_out`).
    pipe_hiwat: u32,
    /// The last send attempt stopped at cwnd (transient, per attempt).
    cwnd_hit: bool,
    /// Most in flight since the window was last full, and when it was
    /// last full or decayed (Linux `snd_cwnd_used`, `snd_cwnd_stamp`).
    cwnd_used: u32,
    cwnd_stamp_ms: u64,
    /// Time of the last new-data transmission (idle restart, RFC 5681 §4.1).
    last_data_send_ms: u64,
    /// `TCP_NODELAY`: send sub-MSS segments at once instead of holding them
    /// while an earlier one is unacknowledged (Nagle, Minshall's variant
    /// as in Linux; on by default).
    nodelay: bool,
    /// End of the last sub-MSS segment sent (Linux `snd_sml`).
    snd_sml: u32,
    /// End of the last segment sent with PSH (Linux `pushed_seq`).
    pushed_seq: u32,
    /// Time of the SYN / SYN-ACK transmission (handshake RTT sample).
    syn_xmit_ms: u64,
    syn_retransmitted: bool,
    /// Our SYN (or SYN-ACK) occupies sequence number ISS and is not yet
    /// acknowledged. Tracked explicitly: `SND.UNA == ISS` alone cannot tell,
    /// because SND.UNA returns to ISS after every 2^32 bytes sent.
    syn_unacked: bool,
    /// Sequence space acknowledged since ISS (SYN, data and FIN), like
    /// Linux's `bytes_acked`: an acceptable ACK never reaches below it.
    snd_acked: u64,

    // ---- Buffers.
    send_ring: Ring<BUF>,
    /// Bytes of `send_ring`'s free space lent out by `send_reserve` (0: no
    /// loan), and the connection (`conn_gen`) they were lent for.
    send_lent: usize,
    send_lent_conn: u32,
    /// Bumped for every new connection (`reset_connection_state`).
    conn_gen: u32,
    recv_ring: Ring<BUF>,
    /// Out-of-order ranges parked in `recv_ring`'s free space.
    ooo: OooList,
    /// The peer's FIN while it lies beyond `RCV.NXT`. RFC 9293 processes
    /// segments in SEG.SEQ order, so it takes effect only once `RCV.NXT`
    /// reaches it, and data processed ahead of it that covers its sequence
    /// number overrides it (see `input.rs`).
    ooo_fin: Option<HeldFin>,
    /// D-SACK block to report on the next ACK (RFC 2883).
    dsack: Option<(u32, u32)>,

    // ---- RTT / RTO (RFC 6298, Linux `tcp_rtt_estimator`).
    now_ms: u64,
    init_rto_ms: u32,
    rto_ms: u32,
    srtt_ms: u32,
    rttvar_ms: u32,
    rtt_first_sample: bool,
    /// SRTT ×8 and its mean deviation ×4, in ms (Linux `srtt_us`,
    /// `mdev_us`): fixed point, so sub-millisecond steps accumulate.
    srtt_x8: u32,
    mdev_x4: u32,
    /// Largest `mdev_x4` this round trip, and the variation the RTO adds
    /// (Linux `mdev_max_us`, `rttvar_us`; never below `RTO_MIN_MS`).
    mdev_max_x4: u32,
    rttvar_x4: u32,
    /// `SND.NXT` when the current RTT round began (Linux `rtt_seq`).
    rtt_seq: u32,
    rto_deadline: Deadline,
    /// Consecutive timeouts (SYN or data) without an ACK of new data (R2;
    /// Linux `icsk_retransmits`): what black-hole detection counts too.
    rtx_count: u8,
    /// Consecutive window probes without any answer (Linux
    /// `icsk_probes_out`): persist probes, and timeouts into a zero window.
    /// A peer that keeps answering keeps a zero window open indefinitely
    /// (RFC 1122 §4.2.2.17).
    probes_out: u8,

    // ---- Delayed ACK.
    pending_ack: bool,
    delayed_ack_count: u8,
    ack_deadline: Deadline,
    /// Linux `ICSK_ACK_PUSHED` / `ICSK_ACK_PUSHED2` for the held ACK: a
    /// short or pushed segment ended a write (two short ones), so a read
    /// that empties the receive queue sends the ACK at once
    /// (`__tcp_cleanup_rbuf`).
    ack_pushed: u8,
    /// Interactive connection (Linux pingpong mode): we sent data within a
    /// delayed-ACK interval of receiving some, so a held ACK can wait to
    /// ride on the reply. Left when a delayed ACK had to fire on its own.
    pingpong: bool,
    /// Linux `icsk_ack.quick`: segments of new data still to ACK at once
    /// (quickack mode) unless the connection is interactive; spent one per
    /// ACK sent while one was owed.
    quick_acks: u8,
    /// When in-order data last arrived (Linux `icsk_ack.lrcvtime`); `None`
    /// before the first, when Linux's `ato` is still 0 and sending cannot
    /// make the connection interactive.
    last_data_recv_ms: Option<u64>,
    /// Receive MSS estimate (Linux `icsk_ack.rcv_mss`): the largest
    /// segment seen, at most our MSS; 0 until established.
    rcv_mss: u16,
    /// Size of the last in-order segment that was shorter than `rcv_mss`
    /// yet looked full-sized (Linux `icsk_ack.last_seg_size`); two in a row
    /// of one size lower `rcv_mss` to it.
    last_seg_size: u16,

    // ---- Persist / sender-SWS override timer.
    persist_deadline: Deadline,
    persist_backoff_ms: u32,

    // ---- Close.
    fin_sent: bool,
    fin_seq: u32,
    time_wait_deadline: Deadline,
    /// When `TIME_WAIT` was entered (bounds its restarts).
    time_wait_since_ms: u64,
    fin_wait2_timeout_ms: u32,
    fin_wait2_deadline: Deadline,
    /// The application read in `FIN_WAIT_2`: the next `tick` restarts the
    /// timeout from its own time.
    fin_wait2_read: bool,
    error: Option<TcpError>,
    /// `(SEQ, ACK)` of the connection's final RST, owed while the egress
    /// ring was full: staged as soon as the host takes a packet out.
    owed_rst: Option<(u32, u32)>,

    // ---- Egress staging.
    tx_ring: TxRing,
    /// Host back-pressure (see [`Tcb::set_egress_paused`]).
    egress_paused: bool,
    /// Leave TCP checksums to the host (see [`Tcb::set_tx_csum_offload`]).
    tx_csum_offload: bool,
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
    /// Current SYN-cookie key: installed by `set_cookie_secret`, or derived
    /// from the host secret. `cookie_secret_set` = a cookie key is available.
    cookie_secret: [u8; 16],
    cookie_secret_set: bool,
    /// The cookie key came from `set_cookie_secret` (not derived).
    cookie_secret_explicit: bool,
    /// A cookie SYN-ACK was sent under the current key.
    cookie_secret_used: bool,
    /// The key before the last rotation, kept while cookies issued under it
    /// can still be valid (until `prev_cookie_until_ms`).
    prev_cookie_secret: [u8; 16],
    prev_cookie_secret_set: bool,
    prev_cookie_until_ms: u64,
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

/// A FIN that arrived beyond `RCV.NXT`, with the first sequence number of
/// the segment that carried it (the FIN itself for a bare FIN), which is
/// its place in SEG.SEQ processing order, and its recency among the
/// out-of-order ranges for SACK reporting.
#[derive(Clone, Copy, Debug)]
struct HeldFin {
    start: u32,
    seq: u32,
    tag: u32,
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
        // variant. `Option` fields, and the structs holding one (`Rack`,
        // `Reno`), are written explicitly (the `None` encoding is not
        // guaranteed to be all-zero). Only then is a reference created.
        unsafe {
            core::ptr::write_bytes(p, 0, 1);
            core::ptr::addr_of_mut!((*p).state).write(State::Closed);
            core::ptr::addr_of_mut!((*p).error).write(None);
            core::ptr::addr_of_mut!((*p).owed_rst).write(None);
            core::ptr::addr_of_mut!((*p).tlp_end_seq).write(None);
            core::ptr::addr_of_mut!((*p).rto_span).write(None);
            core::ptr::addr_of_mut!((*p).ooo_fin).write(None);
            core::ptr::addr_of_mut!((*p).dsack).write(None);
            core::ptr::addr_of_mut!((*p).last_data_recv_ms).write(None);
            core::ptr::addr_of_mut!((*p).rack).write(Rack::new());
            core::ptr::addr_of_mut!((*p).cc).write(Reno::new(congestion::INITIAL_WINDOW));
            #[cfg(feature = "heap-buffers")]
            {
                // Allocate both before writing either, so a failed second
                // allocation drops the first instead of leaking it.
                let send_ring = Ring::new()?;
                let recv_ring = Ring::new()?;
                core::ptr::addr_of_mut!((*p).send_ring).write(send_ring);
                core::ptr::addr_of_mut!((*p).recv_ring).write(recv_ring);
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
        self.cookie_secret_explicit = false;
        self.cookie_secret_used = false;
        self.prev_cookie_secret = [0; 16];
        self.prev_cookie_secret_set = false;
        self.prev_cookie_until_ms = 0;
        self.secret = [0; 16];
        self.secret_set = false;
        self.now_ms = 0;
        self.egress_paused = false;
        self.tx_csum_offload = false;
        self.send_lent = 0;
        self.send_lent_conn = 0;
        self.conn_gen = 0;
        self.keepalive_idle_ms = DEFAULT_KEEPALIVE_IDLE_MS;
        self.keepalive_intvl_ms = DEFAULT_KEEPALIVE_INTVL_MS;
        self.keepalive_count = DEFAULT_KEEPALIVE_COUNT;
        self.user_timeout_ms = DEFAULT_USER_TIMEOUT_MS;
        self.fin_wait2_timeout_ms = DEFAULT_FIN_WAIT2_TIMEOUT_MS;
        self.nodelay = false;
        // Not per connection: what is staged may be for other peers (a
        // listener's cookie SYN-ACKs and RSTs), and the limit on replies to
        // stray segments must survive listener transitions.
        self.tx_ring.clear();
        self.last_oow_ms = Deadline::OFF;
        self.reset_connection_state();
        self.state = State::Closed;
    }

    /// Re-point an existing TCB at a new 5-tuple / ISS and reset it to the
    /// post-`new` `CLOSED` shape **in place**, reusing the ring storage — no
    /// allocation and no multi-MiB copy. Lets a pool recycle TCBs.
    pub fn reinit(&mut self, cfg: TcbConfig) {
        self.setup(cfg);
    }

    /// Start this connection's IP ID counter from its ISS (keyed per 4-tuple
    /// on passive opens, drawn by the host from a CSPRNG on active ones):
    /// each connection numbers only its own packets, as Linux's per-socket
    /// `inet_id` (random at connect and accept), never sharing a counter
    /// across peers.
    pub(super) fn seed_ip_id(&mut self) {
        self.ip_id = (self.iss >> 16) as u16 ^ self.iss as u16;
    }

    /// Reset all per-connection state, keeping the endpoints, knobs and
    /// secrets. Used by `connect`, `listen` and the passive-open paths.
    fn reset_connection_state(&mut self) {
        self.conn_gen = self.conn_gen.wrapping_add(1);
        self.iss = self.cfg_iss;
        self.seed_ip_id();
        self.snd_una = self.iss;
        self.snd_nxt = self.iss;
        self.snd_wnd = 0;
        self.max_snd_wnd = 0;
        self.snd_wl1 = 0;
        self.rcv_nxt = 0;
        self.rcv_wnd = BUF as u32;
        self.irs = 0;
        self.rcv_adv_edge = 0;
        self.last_ack_sent = 0;
        self.local_mss = self.mtu.saturating_sub(HDR_LEN);
        self.peer_mss = DEFAULT_PEER_MSS;
        self.pmtu_mss = self.local_mss;
        self.pmtu_restore_mss = 0;
        self.pmtu_probe_mss = 0;
        self.pmtu_probe_inflight = false;
        self.pmtu_probe_start = 0;
        self.pmtu_probe_end = 0;
        self.pmtu_probe_at = 0;
        self.pmtu_probe_backoff_ms = 0;
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
        self.ecn_seen = false;
        self.send_cwr_pending = false;
        self.rtx.clear();
        self.rack = Rack::new();
        self.rack_deadline = Deadline::OFF;
        self.tlp_deadline = Deadline::OFF;
        self.tlp_end_seq = None;
        self.tlp_is_retrans = false;
        self.rto_span = None;
        self.frto_new = false;
        self.frto_hold = false;
        self.dup_acks = 0;
        self.reno_sacked = 0;
        self.dsack_segs = 0;
        self.cc = Reno::new(congestion::initial_window(u32::from(self.local_mss)));
        self.cwnd_limited = false;
        self.cwnd_limited_seq = self.iss;
        self.pipe_hiwat = 0;
        self.cwnd_hit = false;
        self.cwnd_used = 0;
        self.cwnd_stamp_ms = self.now_ms;
        self.last_data_send_ms = self.now_ms;
        self.snd_sml = self.iss;
        self.pushed_seq = self.iss;
        self.syn_xmit_ms = 0;
        self.syn_retransmitted = false;
        self.syn_unacked = false;
        self.snd_acked = 0;
        self.send_ring.clear();
        self.recv_ring.clear();
        self.ooo.clear();
        self.ooo_fin = None;
        self.dsack = None;
        self.rto_ms = self.init_rto_ms;
        self.srtt_ms = 0;
        self.rttvar_ms = 0;
        self.rtt_first_sample = false;
        self.srtt_x8 = 0;
        self.mdev_x4 = 0;
        self.mdev_max_x4 = 0;
        self.rttvar_x4 = 0;
        self.rtt_seq = 0;
        self.rto_deadline = Deadline::OFF;
        self.rtx_count = 0;
        self.probes_out = 0;
        self.pending_ack = false;
        self.delayed_ack_count = 0;
        self.ack_deadline = Deadline::OFF;
        self.persist_deadline = Deadline::OFF;
        self.persist_backoff_ms = 0;
        self.ack_pushed = 0;
        self.pingpong = false;
        self.quick_acks = 0;
        self.last_data_recv_ms = None;
        self.rcv_mss = 0;
        self.last_seg_size = 0;
        self.fin_sent = false;
        self.fin_seq = 0;
        self.time_wait_deadline = Deadline::OFF;
        self.time_wait_since_ms = 0;
        self.fin_wait2_deadline = Deadline::OFF;
        self.fin_wait2_read = false;
        self.error = None;
        self.owed_rst = None;
        self.syn_rcvd_retries = 0;
        self.keepalive_probes = 0;
        self.keepalive_deadline = Deadline::OFF;
        self.user_timeout_deadline = Deadline::OFF;
        self.ut_progress = 0;
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
        if self.syn_unacked && (self.snd_una != self.iss || self.snd_nxt == self.iss) {
            return Err("SYN marked unacknowledged but SND.UNA/SND.NXT disagree");
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
        if let Some(h) = self.ooo_fin {
            if !self.state.can_recv() || !seq_gt(h.seq, self.rcv_nxt) {
                return Err("stale out-of-order FIN");
            }
            if seq_gt(h.start, h.seq) {
                return Err("out-of-order FIN precedes its own segment");
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
        if ((self.state.can_send() && self.unsent_bytes() > 0) || self.fin_owed())
            && self.snd_una == self.snd_nxt
            && !self.persist_deadline.is_armed()
        {
            return Err("liveness: data or FIN queued with nothing in flight and no persist timer");
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
    /// by [`Self::send`], resuming output after a full egress ring was
    /// drained, and resuming after [`Self::set_egress_paused`] (output owed
    /// while paused — an ACK, a keepalive probe — is not reported here).
    pub fn next_deadline(&self) -> Option<u64> {
        // ACKs and keepalives wait for egress room: while it is paused or
        // the ring is full (the host drains, then ticks), they are not a
        // reason to wake.
        let blocked = self.egress_full();
        let ack = if self.pending_ack && !blocked {
            self.ack_deadline
        } else {
            Deadline::OFF
        };
        let keepalive = if blocked {
            Deadline::OFF
        } else {
            self.keepalive_deadline
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
            keepalive,
            self.user_timeout_deadline,
        ]
        .into_iter()
        .filter_map(Deadline::get)
        .min()
    }

    /// Whether nothing more can be staged: the egress ring is full or the
    /// host paused egress (diagnostic only).
    #[cfg(any(test, feature = "std"))]
    pub fn debug_egress_full(&self) -> bool {
        self.egress_full()
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

    /// Host back-pressure on the egress path (like Linux TCP Small Queues):
    /// while paused the TCB stages no data, FIN, retransmission, pure ACK or
    /// probe, so each segment — and its ACK, window, timestamp, RTT sample
    /// and loss timers — is built when the host can actually send it rather
    /// than aging in the egress ring. SYN, SYN-ACK and RST are exempt.
    ///
    /// Packets staged before the pause stay extractable: drain them first.
    /// Timers keep running — RTO (and R2), USER TIMEOUT, FIN_WAIT_2 and
    /// TIME_WAIT still expire — but output they owe waits: an ACK or
    /// keepalive probe goes out on the first `tick()` after resuming, the
    /// persist timer retries one RTO later, and a tail-loss probe waits
    /// until one PTO after the resume (the peer only then starts draining
    /// what queued up), but never past the RTO. Resume after
    /// [`Self::set_now`], then `tick()`.
    ///
    /// Pause before the device queue toward the peer overflows (at about
    /// half its capacity, or a millisecond of data) and resume once it falls
    /// below a quarter: a queue that never overflows forces no loss.
    #[inline]
    pub fn set_egress_paused(&mut self, paused: bool) {
        if self.egress_paused && !paused && self.tlp_deadline.is_armed() {
            self.maybe_arm_tlp();
        }
        self.egress_paused = paused;
    }

    /// TCP checksum offload: segments staged from now on carry only the
    /// pseudo-header sum in the TCP checksum field (Linux's
    /// CHECKSUM_PARTIAL) instead of the full checksum, saving a pass over
    /// every payload byte. The host must complete it before a peer that
    /// verifies sees the segment (sum the TCP header and payload, this field
    /// included, and store the complement: what a NIC with checksum offload
    /// does), or hand the segment to a receiver that accepts partial
    /// checksums, such as a virtio-net driver told
    /// `VIRTIO_NET_HDR_F_NEEDS_CSUM`. IPv4 header checksums stay complete.
    /// Off by default and after [`Self::reinit`].
    #[inline]
    pub fn set_tx_csum_offload(&mut self, on: bool) {
        self.tx_csum_offload = on;
    }

    /// Reconfigure (or disable, `idle_ms == 0`) keepalive (RFC 9293 §3.8.4).
    /// On by default. As in Linux it probes a fully idle connection in any
    /// synchronized state but `TIME_WAIT`: `ESTABLISHED`, and the half-closed
    /// `CLOSE_WAIT` and `FIN_WAIT_2`, since a peer can vanish after a half
    /// close. While data or our FIN is in flight or queued, the
    /// retransmission, persist and USER TIMEOUT timers own liveness instead.
    pub fn set_keepalive(&mut self, idle_ms: u32, intvl_ms: u32, count: u8) {
        self.keepalive_idle_ms = idle_ms;
        self.keepalive_intvl_ms = intvl_ms.max(1);
        self.keepalive_count = count;
        self.keepalive_probes = 0;
        self.keepalive_deadline = if idle_ms == 0 || !self.keepalive_applies() {
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
    /// peer must send its FIN within this long; otherwise the connection is
    /// reset. The application reading received data restarts the timeout
    /// (the host still wants the peer's half); the peer's data alone does not.
    pub fn set_fin_wait2_timeout(&mut self, ms: u32) {
        self.fin_wait2_timeout_ms = ms;
        self.fin_wait2_deadline = if ms != 0 && self.state == State::FinWait2 {
            Deadline::at(self.now_ms.saturating_add(u64::from(ms)))
        } else {
            Deadline::OFF
        };
    }

    /// `TCP_NODELAY`. By default (as Linux) a segment shorter than the MSS
    /// is held while an earlier short one is unacknowledged (Nagle,
    /// RFC 9293 §3.7.4, in Minshall's variant), so a stream of small
    /// writes coalesces. `true` sends every segment as soon as the windows
    /// allow; turning it on also releases anything held, at the next
    /// [`Tcb::tick`].
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
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
    /// the host received). Lowers the segment size and retransmits in-flight
    /// segments that no longer fit (they were most likely dropped) without
    /// reducing the congestion window: a smaller MTU is not congestion
    /// (Linux `tcp_simple_retransmit`). Like a route's learned PMTU (Linux
    /// `ip_rt_mtu_expires`), a reduction holds for 10 minutes; then one
    /// segment probes the size before it, so a path that grew back, or a
    /// forged report, does not cap the segment size for good. A link MTU
    /// that never changes belongs in [`Tcb::set_mtu`].
    pub fn update_pmtu(&mut self, mtu: u16) {
        let mss = mtu.clamp(MIN_MTU, MAX_MTU) - HDR_LEN;
        let expires = self.now_ms.saturating_add(u64::from(PMTU_PROBE_MAX_MS));
        if mss < self.pmtu_mss {
            self.pmtu_restore_mss = self.pmtu_restore_mss.max(self.pmtu_mss);
            self.pmtu_mss = mss;
            self.pmtu_probe_inflight = false;
            self.pmtu_probe_backoff_ms = PMTU_PROBE_MAX_MS;
            self.pmtu_probe_at = expires;
            if self.state.is_synchronized() {
                self.simple_retransmit();
                let _ = self.maybe_send_data();
            }
            return;
        }
        if mss == self.pmtu_mss {
            // The size in use, reported again (a probe above it did not
            // fit): it holds for another 10 minutes. The probe stays
            // marked, so its loss is a failed probe rather than congestion
            // (Linux leaves `icsk_mtup.probe_size` to the loss detection).
            if self.pmtu_restore_mss != 0 {
                self.pmtu_probe_backoff_ms = PMTU_PROBE_MAX_MS;
                self.pmtu_probe_at = expires;
            }
            return;
        }
        // Above the size in use: never probe beyond it.
        self.pmtu_restore_mss = self.pmtu_restore_mss.min(mss);
        if self.pmtu_restore_mss <= self.pmtu_mss {
            self.pmtu_restore_mss = 0;
            self.pmtu_probe_inflight = false;
        }
    }

    /// [`Self::update_pmtu`] for an ICMP "fragmentation needed": taken only
    /// if the sequence number the ICMP quotes from our segment lies in
    /// `[SND.UNA, SND.NXT]` (Linux `tcp_v4_err`, RFC 5927 §4.1), so an
    /// off-path forger who knows the 4-tuple must also hit the flight; each
    /// smaller report resends what no longer fits. `NotForUs` otherwise, or
    /// before the handshake started.
    pub fn update_pmtu_icmp(&mut self, mtu: u16, quoted_seq: u32) -> Result<(), TcpError> {
        let in_flight =
            quoted_seq.wrapping_sub(self.snd_una) <= self.snd_nxt.wrapping_sub(self.snd_una);
        if matches!(self.state, State::Closed | State::Listen) || !in_flight {
            return Err(TcpError::NotForUs);
        }
        self.update_pmtu(mtu);
        Ok(())
    }

    /// Install a 128-bit host secret (from a CSPRNG). Keys the per-connection
    /// timestamp offset (so TSval does not reveal the host clock, RFC 7323
    /// §5.4) and per-SYN ISNs on listeners (RFC 6528). Unless
    /// [`Tcb::set_cookie_secret`] installed an explicit cookie key, it also
    /// derives the SYN-cookie key a listener falls back to while its
    /// half-open slot is busy. [`Tcb::listen`] requires this (or a cookie
    /// secret).
    pub fn set_secret(&mut self, secret: &[u8; 16]) {
        self.secret = *secret;
        self.secret_set = true;
        if !self.cookie_secret_explicit {
            self.install_cookie_key(cookie::derive_cookie_key(secret), false);
        }
    }

    /// Install (or rotate to) an explicit 128-bit SYN-cookie key (RFC 4987),
    /// from a CSPRNG. A listener holds one half-open handshake statefully and
    /// answers further SYNs with cookies while that slot is busy. Cookies
    /// issued under the previous key stay valid for their normal 64–128 s
    /// lifetime, so rotating no more often than every ~2 minutes never breaks
    /// a handshake in progress. A listener set up within 128 s of a rotation
    /// takes those cookies too if given the previous key first, then the
    /// current one. Also used as the host secret if [`Tcb::set_secret`] was
    /// not called.
    pub fn set_cookie_secret(&mut self, secret: &[u8; 16]) {
        self.install_cookie_key(*secret, true);
        self.cookie_secret_explicit = true;
    }

    /// Make `key` the current cookie key. The old one keeps validating for
    /// the lifetime of the cookies issued under it (two time buckets from
    /// now), except a derived key that an explicit one replaces before any
    /// cookie went out under it (the usual setup order, `set_secret` then
    /// `set_cookie_secret`): every forged cookie ACK would pay for a second
    /// key for nothing.
    fn install_cookie_key(&mut self, key: [u8; 16], explicit: bool) {
        let rotation = self.cookie_secret_used || self.cookie_secret_explicit == explicit;
        if self.cookie_secret_set && self.cookie_secret != key && rotation {
            self.prev_cookie_secret = self.cookie_secret;
            self.prev_cookie_secret_set = true;
            self.prev_cookie_until_ms = self
                .now_ms
                .saturating_add(2 * cookie::COOKIE_TIME_BUCKET_MS);
        }
        if self.cookie_secret != key {
            self.cookie_secret_used = false;
        }
        self.cookie_secret = key;
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
            self.syn_unacked = true;
            self.arm_rto();
        }
        Ok(())
    }

    /// Passive open: `CLOSED` → `LISTEN` (also allowed from `LISTEN` and
    /// `TIME_WAIT`). The remote endpoint is wildcarded until a SYN arrives.
    ///
    /// Requires a secret ([`Tcb::set_secret`] or [`Tcb::set_cookie_secret`]);
    /// returns `InvalidState` otherwise. Without one, every connection the
    /// listener accepts would get the same ISN and a TSval equal to the host
    /// clock.
    ///
    /// The listener holds one half-open connection at a time, statefully, so
    /// it keeps every option the client offers. While that slot is busy, SYNs
    /// from other peers are answered with SYN cookies (no state). Their valid
    /// cookie ACKs come back as [`TcpError::ListenerBusy`] while the half-open
    /// is live: inject the same datagram into a fresh listener set up like
    /// this one, which becomes that peer's connection. A half-open whose
    /// SYN-ACK already needed a retransmit yields its slot to such an ACK,
    /// and to a SYN from a new peer, so spoofed SYNs cannot lock the
    /// listener out. Any listener holding the cookie key takes a cookie ACK,
    /// so the listener the host sets up after this one becomes a connection
    /// takes those of its cookies.
    pub fn listen(&mut self) -> Result<(), TcpError> {
        match self.state {
            State::Closed | State::Listen | State::TimeWait => {}
            _ => return Err(TcpError::InvalidState),
        }
        if !self.secret_set && !self.cookie_secret_set {
            return Err(TcpError::InvalidState);
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
    /// send ring is full, or lent out by [`Self::send_reserve`]). Bytes are
    /// transmitted on the next `tick` / inbound ACK.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, TcpError> {
        if !self.state.can_send() {
            return Err(TcpError::InvalidState);
        }
        if self.send_lent != 0 {
            return Err(TcpError::WouldBlock);
        }
        let written = self.send_ring.write(data);
        if written == 0 && !data.is_empty() {
            return Err(TcpError::WouldBlock);
        }
        Ok(written)
    }

    /// Lend the send ring's free space to the host to fill in place (a
    /// socket `read` straight into it, say) instead of copying the data in
    /// through [`Self::send`]. Returns up to `max` bytes as two slices; the
    /// second is empty unless the space wraps the end of the ring. Fill a
    /// prefix (the first slice first), then call [`Self::send_commit`].
    ///
    /// Write the slices while you hold them: they borrow the TCB. Until the
    /// commit the loan stays out across other calls, whatever happens to
    /// the connection meanwhile: the TCB neither reads nor writes the lent
    /// bytes, and `send` returns `WouldBlock` (`poll` drops `WRITABLE`), so
    /// what was written stays as written. Do not keep raw pointers into them
    /// to write after another call, though (an asynchronous receive
    /// completing into them, for one): every call takes `&mut self`, which
    /// Rust's aliasing rules (Stacked Borrows, as Miri checks) let assume
    /// nothing else writes the TCB, rings included, so such a write is
    /// undefined behavior even though the TCB never looks. Commit, with 0 if
    /// need be, before `reinit` or dropping the TCB. One loan at a time:
    /// `InvalidState` while one is out or when the connection cannot send,
    /// `WouldBlock` when the ring is full or `max` is 0. (Rust API only.)
    pub fn send_reserve(&mut self, max: usize) -> Result<(&mut [u8], &mut [u8]), TcpError> {
        if self.send_lent != 0 || !self.state.can_send() {
            return Err(TcpError::InvalidState);
        }
        let (a, b) = self.send_ring.free_regions(max);
        let n = a.len() + b.len();
        if n == 0 {
            return Err(TcpError::WouldBlock);
        }
        self.send_lent = n;
        self.send_lent_conn = self.conn_gen;
        Ok((a, b))
    }

    /// End the loan from [`Self::send_reserve`], appending its first `n`
    /// bytes (clipped to the loan) to the stream as `send` would. Returns
    /// the bytes appended; `n == 0` just ends the loan. `InvalidState` if no
    /// loan is out, or if the connection it was lent for has since closed,
    /// reset or been replaced: its bytes are then dropped.
    pub fn send_commit(&mut self, n: usize) -> Result<usize, TcpError> {
        let lent = core::mem::take(&mut self.send_lent);
        if lent == 0 || self.send_lent_conn != self.conn_gen || !self.state.can_send() {
            return Err(TcpError::InvalidState);
        }
        Ok(self.send_ring.commit(n.min(lent)))
    }

    /// Copy received in-order data out. Returns `ConnectionClosed` once the
    /// ring is empty and the peer has FINned, `ConnectionReset` after a
    /// reset, a timeout or an abort (after a reset or a timeout, only once
    /// the bytes received before it are read). In `FIN_WAIT_2`, consuming
    /// data restarts the FIN_WAIT_2 timeout.
    pub fn recv(&mut self, dst: &mut [u8]) -> Result<usize, TcpError> {
        if let Some(e) = self.error {
            // A reset or a timeout keeps the bytes already received
            // readable; the error follows the last of them (as Linux
            // `recvmsg`).
            if self.state == State::Closed && !self.recv_ring.is_empty() {
                return Ok(self.recv_ring.read(dst));
            }
            return Err(e);
        }
        let n = self.recv_ring.read(dst);
        if n > 0 {
            // `recv` takes no clock, so `now_ms` may be a turn old: the next
            // `tick` restarts the FIN_WAIT_2 timeout from its own time.
            if self.state == State::FinWait2 && self.fin_wait2_timeout_ms != 0 {
                self.fin_wait2_read = true;
            }
            // Linux `__tcp_cleanup_rbuf`: a read that empties the receive
            // queue sends a held ACK at once if a short or pushed segment
            // ended a write — unless the connection is interactive, where
            // the reply will carry it — and after two short ones anyway. A
            // peer holding its next small write for that ACK (Nagle) would
            // otherwise wait out the delayed-ACK timer.
            let pushed = self.ack_pushed & ACK_PUSHED2 != 0
                || (self.ack_pushed & ACK_PUSHED != 0 && !self.pingpong);
            if self.pending_ack && pushed && self.recv_ring.is_empty() {
                self.send_pure_ack()?;
            } else {
                self.maybe_send_window_update()?;
            }
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
            // sends a FIN and enters FIN-WAIT-1. Closed by the application,
            // a listener's half-open never returns to LISTEN.
            State::SynRcvd => {
                self.is_listener = false;
                self.state = State::FinWait1;
            }
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

    /// Abort: queue `RST+ACK` (seq = SND.NXT, ack = RCV.NXT) behind whatever
    /// is still staged (with the egress ring full, as soon as the host
    /// extracts a packet) and drop all state, received bytes not yet read
    /// included. Local-only in `LISTEN` / `SYN_SENT`. Idempotent on
    /// `CLOSED`.
    pub fn abort(&mut self) -> Result<(), TcpError> {
        match self.state {
            State::Closed => return Ok(()),
            State::Listen | State::SynSent => {
                self.is_listener = false;
            }
            _ => {
                self.emit_final_rst()?;
            }
        }
        self.recv_ring.clear();
        self.abort_local();
        Ok(())
    }

    /// Tear the connection down locally (no RST): R2 / USER TIMEOUT /
    /// keepalive aborts, and the tail of `abort`. Surfaces `ConnectionReset`
    /// once the bytes already received are read: Linux `tcp_done` purges
    /// only the write queue, and `tcp_recvmsg` returns queued data ahead of
    /// the error.
    fn abort_local(&mut self) {
        self.state = State::Closed;
        self.error = Some(TcpError::ConnectionReset);
        self.release_buffers_and_timers();
    }

    /// Enter `CLOSED` cleanly (no error): our FIN ACKed in `LAST_ACK`, or a
    /// RST in `CLOSING` / `LAST_ACK` / `TIME_WAIT`. The peer's FIN has been
    /// received in each of these, so its byte stream is complete: bytes
    /// already received stay readable (as after `TIME_WAIT` expiry), and
    /// `recv` reports EOF only once they are drained.
    fn close_clean(&mut self) {
        self.state = State::Closed;
        self.release_buffers_and_timers();
    }

    /// Drop all send-side and timer state, and anything parked beyond
    /// `RCV.NXT`. In-order received bytes are left to the caller.
    fn release_buffers_and_timers(&mut self) {
        self.send_ring.clear();
        self.ooo.clear();
        self.ooo_fin = None;
        self.rtx.clear();
        self.snd_nxt = self.snd_una;
        self.syn_unacked = false;
        self.fin_sent = false;
        self.disarm_timers();
    }

    /// Disarm every timer: a `CLOSED` TCB has no further work, so
    /// `next_deadline()` must not wake the host for it.
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
        if self.state.can_send() && self.send_ring.free() > 0 && self.send_lent == 0 {
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
        let n = self.tx_ring.pop_into(out)?;
        if self.owed_rst.is_some() {
            self.stage_owed_rst();
        }
        Ok(n)
    }

    /// Pop one staged outbound datagram and lend it to `f` instead of
    /// copying it out (`None` when none is pending).
    pub fn extract_packet_with<R>(&mut self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let r = self.tx_ring.pop_with(f);
        if self.owed_rst.is_some() {
            self.stage_owed_rst();
        }
        r
    }

    /// Stage the final RST a full egress ring held back, now that a packet
    /// left it.
    #[cold]
    #[inline(never)]
    fn stage_owed_rst(&mut self) {
        if let Some((seq, ack)) = self.owed_rst {
            if !matches!(
                self.emit_ctl(wire::flags::RST | wire::flags::ACK, seq, ack),
                Ok(false)
            ) {
                self.owed_rst = None;
            }
        }
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
        self.syn_unacked
    }

    /// Sequence number of the first byte in the send ring.
    #[inline]
    fn data_una(&self) -> u32 {
        self.snd_una.wrapping_add(u32::from(self.syn_outstanding()))
    }

    /// Bytes queued by the application but not yet sent.
    #[inline]
    fn unsent_bytes(&self) -> u32 {
        let sent_data = self
            .snd_nxt
            .wrapping_sub(self.data_una())
            .saturating_sub(u32::from(self.fin_sent));
        (self.send_ring.len() as u32).saturating_sub(sent_data)
    }

    /// Nothing more may be staged: the ring is full or the host paused us.
    #[inline]
    fn egress_full(&self) -> bool {
        self.egress_paused || self.tx_ring.is_full()
    }

    /// Unacknowledged sequence space plus unsent data or FIN.
    fn has_send_work(&self) -> bool {
        self.snd_una != self.snd_nxt || self.unsent_bytes() > 0 || self.fin_owed()
    }

    /// The states keepalive runs in, as in Linux: every synchronized state
    /// but `TIME_WAIT`. `FIN_WAIT_1`, `CLOSING` and `LAST_ACK` always have
    /// our FIN to deliver, so only `ESTABLISHED`, `CLOSE_WAIT` and
    /// `FIN_WAIT_2` are ever idle enough to probe.
    fn keepalive_applies(&self) -> bool {
        matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::FinWait2
                | State::Closing
                | State::LastAck
        )
    }

    /// RFC 6675 `pipe`.
    #[inline]
    fn pipe(&self) -> u32 {
        let outstanding = self.snd_nxt.wrapping_sub(self.data_una());
        self.rtx.pipe(outstanding).saturating_sub(self.reno_sacked)
    }

    /// Largest TCP payload per segment (MSS minus the always-present
    /// timestamp option).
    #[inline]
    fn mss_payload(&self) -> u32 {
        let cap = self.local_mss.min(self.peer_mss).min(self.pmtu_mss);
        let ts = if self.ts_enabled { 12 } else { 0 };
        u32::from(cap).saturating_sub(ts).max(1)
    }

    /// Payload of a full-sized new segment: the MSS less the room of the
    /// SACK blocks owed to the peer (Linux `tcp_current_mss`), so data
    /// segments carry them too, not only pure ACKs. Encoded, timestamps
    /// plus n blocks take 12 + 8n bytes (timestamps alone 12), n blocks
    /// alone 4 + 8n, within the 40-byte option space.
    #[inline]
    fn data_mss(&self) -> u32 {
        let mss = self.mss_payload();
        let owed = if self.sack_enabled {
            usize::from(self.dsack.is_some())
                + self.ooo.len()
                + usize::from(self.ooo_fin.is_some_and(|h| !self.ooo.ends_at(h.seq)))
        } else {
            0
        };
        if owed == 0 {
            return mss;
        }
        let n = owed.min(if self.ts_enabled { 3 } else { 4 }) as u32;
        let room = 8 * n + if self.ts_enabled { 0 } else { 4 };
        mss.saturating_sub(room).max(1)
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

    /// RTT estimator and RTO, as Linux `tcp_rtt_estimator` / `tcp_set_rto`
    /// (RFC 6298 in spirit): SRTT and the mean deviation in fixed point
    /// (×8, ×4), a decrease in RTT moving the deviation with a finer gain,
    /// and RTO = SRTT + the largest 4·deviation of the last round trip, at
    /// least `RTO_MIN_MS` — so a steady path keeps a 200 ms margin rather
    /// than collapsing to SRTT + 1 ms.
    /// RFC 6298 / Linux `tcp_rtt_estimator` with an `r_ms` sample, and
    /// RACK's `min_rtt` with `ca_ms` if given (see `process_ack`).
    fn update_rtt(&mut self, r_ms: u32, ca_ms: Option<u32>) {
        let m = r_ms.max(1);
        if !self.rtt_first_sample {
            self.srtt_x8 = m.saturating_mul(8);
            self.mdev_x4 = m.saturating_mul(2);
            self.rttvar_x4 = self.mdev_x4.max(RTO_MIN_MS);
            self.mdev_max_x4 = self.rttvar_x4;
            self.rtt_seq = self.snd_nxt;
            self.rtt_first_sample = true;
        } else {
            let srtt = i64::from(self.srtt_x8);
            let mut err = i64::from(m) - (srtt >> 3);
            self.srtt_x8 = u32::try_from((srtt + err).max(1)).unwrap_or(u32::MAX);
            let mdev = i64::from(self.mdev_x4);
            if err < 0 {
                err = -err - (mdev >> 2);
                if err > 0 {
                    err >>= 3;
                }
            } else {
                err -= mdev >> 2;
            }
            self.mdev_x4 = u32::try_from((mdev + err).max(0)).unwrap_or(u32::MAX);
            if self.mdev_x4 > self.mdev_max_x4 {
                self.mdev_max_x4 = self.mdev_x4;
                self.rttvar_x4 = self.rttvar_x4.max(self.mdev_max_x4);
            }
            if seq_gt(self.snd_una, self.rtt_seq) {
                if self.mdev_max_x4 < self.rttvar_x4 {
                    self.rttvar_x4 -= (self.rttvar_x4 - self.mdev_max_x4) >> 2;
                }
                self.rtt_seq = self.snd_nxt;
                self.mdev_max_x4 = RTO_MIN_MS;
            }
        }
        self.srtt_ms = (self.srtt_x8 >> 3).max(1);
        self.rttvar_ms = self.mdev_x4 >> 2;
        let rto = (self.srtt_x8 >> 3).saturating_add(self.rttvar_x4);
        self.rto_ms = rto.clamp(RTO_MIN_MS, RTO_MAX_MS);
        if let Some(ca) = ca_ms {
            self.rack.sample_rtt(self.now_ms, ca.max(1));
        }
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
