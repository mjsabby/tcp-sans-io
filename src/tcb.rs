//! Transmission Control Block (TCB) and the sans-I/O state machine.
//!
//! `Tcb` owns:
//! * the connection's RFC 793 sequence-number variables,
//! * fixed-capacity send/receive ring buffers,
//! * the TCP Tahoe congestion controller,
//! * RFC 6298 RTO with Timestamps option (RFC 7323) when negotiated,
//! * a persist-timer for zero-window probing (RFC 1122 §4.2.2.17),
//! * a delayed-ACK timer (RFC 1122 §4.2.3.2),
//! * a 2*MSL `TIME_WAIT` timer.
//!
//! It does no I/O. Inputs are an arbitrary monotonic clock (`now_ms`), inbound
//! IP packets, and application data. Outputs are application data and outbound
//! IP packets, both copied into caller-provided buffers.

use crate::congestion::Tahoe;
use crate::error::TcpError;
use crate::ring::Ring;
use crate::state::State;
use crate::wire::{self, flags, SackBlocks, Segment, TcpOptions};
use crate::{BUF_CAP, MSS};

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

/// 2*MSL — RFC 793 specifies 2 minutes; we use 60 s to keep handles cheap.
const TIME_WAIT_MS: u64 = 60_000;
const RTO_MAX_MS: u32 = 60_000;
const RTO_MIN_MS: u32 = 200;
/// Delayed-ACK quantum (Linux default is 40 ms; RFC 5681 caps at 500 ms).
const DELAYED_ACK_MS: u64 = 40;
/// Default peer MSS when no MSS option arrived in the SYN/SYN-ACK
/// (RFC 1122 §4.2.2.6).
const DEFAULT_PEER_MSS: u16 = 536;

/// Minimum TLP probe timeout per RFC 8985 §7.5.1. Pacifies degenerate
/// "SRTT close to zero" cases where the formula `2*SRTT` would otherwise
/// schedule the probe at essentially zero, racing the original packet.
const TLP_MIN_PTO_MS: u64 = 10;

/// Bounded queue of RACK-marked-lost ranges awaiting retransmission.
/// Sorted lowest-seq first so we retransmit holes in order — matching
/// the RFC 6675 NextSeg discipline that `rxt_seq` relies on.
const RACK_LOST_QUEUE_CAP: usize = 32;

#[derive(Copy, Clone, Debug)]
pub struct RackLostQueue {
    ranges: [(u32, u32); RACK_LOST_QUEUE_CAP],
    len: usize,
}

impl RackLostQueue {
    pub const fn new() -> Self {
        Self {
            ranges: [(0, 0); RACK_LOST_QUEUE_CAP],
            len: 0,
        }
    }
    pub fn clear(&mut self) {
        self.len = 0;
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Insert `(seq_start, seq_end)` if not already covered. Maintains
    /// ascending sort by `seq_start`. Silently drops if full or if the
    /// range is empty after dedup.
    pub fn insert_sorted(&mut self, seq_start: u32, seq_end: u32, una: u32) {
        if seq_le(seq_end, seq_start) {
            return;
        }
        // De-dup: drop if any existing range fully contains this.
        for r in self.ranges.get(..self.len).unwrap_or(&[]) {
            if seq_le(r.0, seq_start) && seq_le(seq_end, r.1) {
                return;
            }
        }
        if self.len == RACK_LOST_QUEUE_CAP {
            return; // drop; RACK will rediscover on next scan
        }
        // Find insertion point (sort by seq_start - una, ascending).
        let mut pos = self.len;
        for i in 0..self.len {
            let r = match self.ranges.get(i) {
                Some(r) => *r,
                None => continue,
            };
            let new_off = seq_start.wrapping_sub(una);
            let cur_off = r.0.wrapping_sub(una);
            if new_off < cur_off {
                pos = i;
                break;
            }
        }
        // Shift right by 1 from pos.
        for i in (pos..self.len).rev() {
            if let (Some(src), Some(dst)) =
                (self.ranges.get(i).copied(), self.ranges.get_mut(i + 1))
            {
                *dst = src;
            }
        }
        if let Some(slot) = self.ranges.get_mut(pos) {
            *slot = (seq_start, seq_end);
            self.len += 1;
        }
    }
    /// Take the lowest-seq range. Returns `None` if empty.
    pub fn take_lowest(&mut self) -> Option<(u32, u32)> {
        if self.len == 0 {
            return None;
        }
        let first = self.ranges.first().copied();
        for i in 1..self.len {
            if let (Some(src), Some(dst)) =
                (self.ranges.get(i).copied(), self.ranges.get_mut(i - 1))
            {
                *dst = src;
            }
        }
        self.len -= 1;
        first
    }
}

impl Default for RackLostQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum number of times we will retransmit a SYN-ACK in `SYN_RCVD` before
/// giving up and reverting to `LISTEN`. With exponential RTO back-off the
/// initial retransmit is at +1*RTO, then +2*RTO, …, so a budget of 5 caps
/// the half-open lifetime at roughly `RTO * (2^6 - 1)` ≈ 63 s for the
/// default 1 s RTO. Single-TCB design ⇒ at most one half-open at a time;
/// this budget is the only adversarial flood the listener has to absorb.
const MAX_SYN_RCVD_RETRIES: u8 = 5;

/// RFC 9293 §3.8.3 "R2": the maximum number of consecutive retransmission
/// timeouts — on data, a SYN, or a FIN — tolerated before a synchronized (or
/// actively-opening) connection is aborted. The counter resets to zero
/// whenever `snd_una` advances, i.e. on any proof the peer is still alive, so
/// only sustained silence trips it. With the capped exponential RTO back-off
/// (RTO_MIN 200 ms, ×2 per timeout, RTO_MAX 60 s) a budget of 10 places the
/// abort at ~200 s of wholly-unacknowledged retransmission for the fastest
/// (RTO_MIN) connections — past the RFC-recommended 100 s floor — and
/// proportionally longer at larger RTTs. `SYN_RCVD` is exempt: it reverts to
/// `LISTEN` under its own [`MAX_SYN_RCVD_RETRIES`] budget instead. The abort
/// is local (no RST is sent — at R2 the peer is presumed unreachable, as Linux
/// does on `tcp_retries2`).
const MAX_RETRANSMITS: u8 = 10;

/// Default RFC 9293 §3.8.3 USER TIMEOUT: the maximum time a connection may go
/// **without forward progress** (i.e. without `snd_una` advancing) while it
/// still has data the peer has not acknowledged, before it is aborted. Unlike
/// the R2 retransmit counter — which resets on *any* sign of life and so only
/// catches a wholly silent peer — this clock resets **only** when `snd_una`
/// advances. That makes it the defence against an *alive-but-stalling* peer:
/// one that keeps ACKing zero-window persist probes (or dribbles duplicate
/// ACKs) to look alive while never opening its window, pinning a TCB and its
/// buffers indefinitely (the classic zero-window / "Sockstress" DoS). On by
/// default at 5 minutes; `set_user_timeout(0)` disables it. Reconfigurable via
/// [`Tcb::set_user_timeout`].
const DEFAULT_USER_TIMEOUT_MS: u32 = 300_000;

/// SYN-cookie time-bucket width (RFC 4987-style). 64 s matches Linux's
/// historical choice. The validator accepts both the current bucket and
/// the previous one, giving cookies a 64-128 s validity window.
const COOKIE_TIME_BUCKET_MS: u64 = 64_000;

/// Eight quantised peer-MSS values that the SYN-cookie's top 3 bits select
/// from. We pick the largest entry that does not exceed the SYN's MSS.
/// Values are conservative interop-friendly defaults — anything above the
/// table maps to the largest entry, anything below to the smallest.
const COOKIE_MSS_TABLE: [u16; 8] = [536, 1300, 1440, 1452, 1460, 1480, 9000, 65495];

/// Window Scale shift count (RFC 7323 §2) we advertise on outbound
/// SYN / SYN-ACK, derived from the receive-ring capacity `buf`: the minimal
/// scale that lets us advertise the full ring without truncation
/// (`buf >> shift` must fit a 16-bit window field, max 65535).
///
/// E.g. `buf = 1 MiB` needs shift ≥ 5 (1MiB >> 5 = 32_768 ≤ 65535; shift 4
/// would give 65_536, overflowing u16). The minimal scale matters because
/// each shift coarsens window granularity by 2x. Evaluated at compile time
/// per `Tcb<BUF>` as the associated const `Tcb::<BUF>::WS`.
const fn local_ws_shift(buf: usize) -> u8 {
    let mut shift = 0u8;
    while (buf >> shift) > u16::MAX as usize {
        shift += 1;
    }
    shift
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

#[derive(Copy, Clone, Debug)]
struct RttProbe {
    /// Smallest seq value the ACK must reach for the probe to count
    /// (i.e. `snd_nxt` after the probed segment was emitted).
    seq: u32,
    sent_at: u64,
    /// Karn's algorithm: invalidated on retransmit.
    valid: bool,
}

/// Per-connection state.
pub struct Tcb<const BUF: usize = BUF_CAP> {
    state: State,

    local: Endpoint,
    remote: Endpoint,

    // ---- Send Sequence Variables (RFC 793 §3.2) ---------------------------
    snd_una: u32, // oldest unacknowledged
    snd_nxt: u32, // next sequence to send
    /// Highest `snd_nxt` value ever reached. Unlike `snd_nxt`, this does
    /// **not** rewind on RTO or SACK-driven fast-retransmit, so it bounds
    /// the set of sequence numbers the peer could legitimately ACK. Used
    /// in place of `snd_nxt` in the RFC 793 §3.4 ACK-acceptability check
    /// (`SND.UNA < SEG.ACK ≤ SND.NXT`): when we rewind `snd_nxt` to start
    /// loss recovery, the peer may have buffered our prior in-flight
    /// segments out-of-order; once recovery's first retransmit fills its
    /// hole, the peer's cumulative ACK lands at the original high seq —
    /// which our rewound `snd_nxt` would otherwise reject as a phantom.
    /// See conformance test `cumulative_ack_after_sack_rewind_is_accepted`.
    snd_max: u32,
    snd_wnd: u32, // peer's advertised window
    iss: u32,     // initial send sequence

    // ---- Receive Sequence Variables --------------------------------------
    rcv_nxt: u32, // next byte expected
    rcv_wnd: u32, // window we advertise
    irs: u32,     // initial receive sequence

    // ---- MSS negotiation -------------------------------------------------
    local_mss: u16,
    peer_mss: u16,

    // ---- Timestamps (RFC 7323) -------------------------------------------
    ts_enabled: bool,
    ts_recent: u32, // most recent peer TSval; echoed as our TSecr

    // ---- Window Scale (RFC 7323 §2) --------------------------------------
    /// Shift count we apply to peer-advertised windows on inbound segments
    /// (i.e. peer's chosen `rcv_wscale`). Set during handshake; remains 0
    /// if the peer didn't offer WS.
    snd_wscale: u8,
    /// Shift count we apply to our own advertised window on outbound
    /// segments. Set to the local window-scale shift iff the peer offered WS in
    /// the handshake (per RFC 7323 §2.2: a TCP must not send WS unless
    /// the peer also did); otherwise 0.
    rcv_wscale: u8,

    // ---- ECN (RFC 3168) --------------------------------------------------
    /// True iff both sides negotiated ECN during the handshake (active SYN
    /// carried CWR+ECE, SYN-ACK carried ECE-only). Once true, all non-SYN
    /// outbound segments carry the ECT(0) codepoint in IP TOS, and the
    /// receiver echoes ECE on observed CE marks; the sender treats ECE as
    /// a congestion signal (enters PRR recovery) and responds with CWR.
    ecn_enabled: bool,
    /// Sticky flag: the most recent inbound segment carried a CE
    /// codepoint, so all outbound ACKs must set ECE until the peer
    /// confirms reaction with CWR. Cleared on receiving CWR.
    ce_observed: bool,
    /// Sticky flag: we received an ECE-marked ACK and entered congestion
    /// recovery in response. The next new-data segment we send must set
    /// the CWR flag to acknowledge.
    send_cwr_pending: bool,

    // ---- SACK (RFC 2018 + RFC 6675) -------------------------------------
    /// True iff both sides offered SACK_PERMITTED in the handshake.
    sack_enabled: bool,
    /// Sender-side SACK scoreboard: tracks SACKed ranges above `snd_una`
    /// reported by the peer. Drives the RFC 6675 NextSeg() selective
    /// retransmit algorithm.
    sack_scoreboard: crate::scoreboard::SackScoreboard,
    /// Cursor in the current recovery episode pointing at the next byte
    /// we should consider retransmitting. Only valid when `cc.in_recovery()`
    /// is true. Set to `snd_una` on recovery entry, advanced past each
    /// retransmitted segment, never moved backward; cumulative ACK bumps
    /// it forward if `snd_una` outruns it.
    rxt_seq: u32,
    /// Total bytes retransmitted in the current recovery episode that
    /// haven't yet been cumulatively ACKed. Folded into pipe estimation
    /// so PRR doesn't under-estimate the in-flight bytes (retransmits
    /// don't advance `snd_nxt`, so naive `(snd_nxt - snd_una) - sacked`
    /// would miss them). Decremented as `snd_una` advances; cleared on
    /// recovery exit.
    rxt_unacked: u32,

    // ---- RACK-TLP (RFC 8985) --------------------------------------------
    /// Per-transmission metadata feeding RACK + TLP. Pushed on every
    /// emission (new data, selective retransmit, TLP probe). Pruned by
    /// cumulative ACK and SACK absorb. Bounded ring; on overflow the
    /// oldest entry is evicted.
    send_queue: crate::send_queue::SendQueue,
    /// RACK state: the most-recently delivered segment's send-ts, end-seq,
    /// RTT sample, and reordering window. Used by `rack::detect_lost` to
    /// classify in-flight segments as either definitely-lost, eligible-
    /// but-too-soon (caller arms a reordering timer), or not-eligible.
    rack: crate::rack::Rack,
    /// RACK reordering timer. Set when a scan finds entries that are
    /// "eligible but not yet past the threshold"; fires in `tick()` to
    /// trigger a fresh scan independent of ACK arrivals.
    rack_deadline: Option<u64>,
    /// Bounded queue of RACK-marked-lost ranges waiting to be
    /// retransmitted. Drained at top priority by `maybe_send_data`.
    /// Ranges are clipped to `[snd_una, snd_max)` minus SACKed bytes
    /// before being added.
    rack_lost_queue: RackLostQueue,
    /// TLP Probe Timeout deadline. Set whenever we emit data with
    /// in-flight > 0; cleared on every fresh ACK; fires a tail probe
    /// before RTO would have.
    tlp_deadline: Option<u64>,
    /// True iff a TLP probe has already fired in the current
    /// "in-flight epoch" (since the last fresh ACK). Single-shot per
    /// RFC 8985 §7.4. Reset when snd_una advances.
    tlp_fired: bool,

    // ---- Buffers ---------------------------------------------------------
    send_ring: Ring<BUF>,
    recv_ring: Ring<BUF>,

    // ---- Out-of-order reassembly (multi-hole, RFC 6675-grade) -----------
    /// Multi-range out-of-order buffer. Holds up to MAX_HOLES disjoint
    /// runs; the receiver emits a SACK option carrying their edges so
    /// an RFC 6675 sender knows which segments to selectively retransmit.
    reasm: crate::reassembly::Reassembly,

    // ---- Tahoe AIMD ------------------------------------------------------
    cc: Tahoe,

    // ---- Timers / RTT estimator ------------------------------------------
    now_ms: u64,
    rto_ms: u32,
    srtt_ms: u32,
    rttvar_ms: u32,
    rtt_first_sample: bool,
    rto_deadline: Option<u64>,
    /// Fallback RTT probe used when peer didn't negotiate Timestamps.
    rtt_probe: Option<RttProbe>,

    // ---- Delayed ACK -----------------------------------------------------
    pending_ack: bool,
    delayed_ack_count: u8,
    ack_deadline: Option<u64>,

    // ---- Persist (zero-window probe) timer -------------------------------
    persist_deadline: Option<u64>,
    persist_backoff_ms: u32,

    // ---- Connection lifecycle flags --------------------------------------
    fin_sent: bool,
    fin_seq: u32,
    time_wait_deadline: Option<u64>,
    error: Option<TcpError>,

    // ---- Outbound IP packet staging area ---------------------------------
    /// Multi-slot egress ring (FIFO). `maybe_send_data` may emit up to
    /// `TX_RING_CAP` back-to-back segments per call; the host drains
    /// them with repeated `extract_packet` calls. Sized to amortize
    /// the FFI round-trip cost of one-packet-per-tick (IW=10 burst +
    /// RACK / RFC 6675 retransmit fan-out fits comfortably).
    tx_ring: crate::tx_ring::TxRing,

    /// Monotonically-increasing IP identification field for emitted packets.
    ip_id: u16,

    // ---- Server-side / passive open --------------------------------------
    /// Set when the TCB has been put into `LISTEN` via [`Tcb::listen`].
    /// Distinguishes the passive-open lifecycle (Listen → SynRcvd →
    /// Established → … → Listen) from the active-open lifecycle (Closed →
    /// SynSent → … → Closed). On a SYN_RCVD retransmit-budget exhaustion,
    /// or on RST during a passive-side handshake, we revert to LISTEN
    /// rather than CLOSED, so the listener immediately becomes usable
    /// again — which is the whole point of having one.
    is_listener: bool,
    /// SYN-ACK retransmit counter while in `SynRcvd`. Capped by
    /// [`MAX_SYN_RCVD_RETRIES`]; on overflow we revert to `Listen`.
    syn_rcvd_retries: u8,
    /// Consecutive RTO firings with no proof of life from the peer — the RFC
    /// 9293 §3.8.3 "R2" counter. Reset to 0 by any acceptable inbound ACK
    /// (`process_ack`), not just a forward-progress one, so a flow-controlled
    /// but live peer is never aborted; once it exceeds [`MAX_RETRANSMITS`] a
    /// truly silent/vanished peer can no longer keep us retransmitting
    /// forever. `SYN_RCVD` uses `syn_rcvd_retries` instead and never touches
    /// this.
    rtx_count: u8,
    // ---- Keepalive (RFC 9293 §3.8.4), opt-in (off unless set_keepalive) ---
    /// Idle time before the first keepalive probe, in ms. `0` disables
    /// keepalive entirely (the default).
    keepalive_idle_ms: u32,
    /// Interval between successive keepalive probes, in ms.
    keepalive_intvl_ms: u32,
    /// Unanswered keepalive probes tolerated before the connection is aborted.
    keepalive_count: u8,
    /// Probes sent in the current idle episode; reset to 0 by any inbound
    /// segment (proof the peer is alive).
    keepalive_probes: u8,
    /// Next keepalive action (probe or abort). Re-armed to `now + idle` on
    /// every inbound segment; `None` when keepalive is disabled or unarmed.
    keepalive_deadline: Option<u64>,
    // ---- USER TIMEOUT (RFC 9293 §3.8.3), on by default -------------------
    /// Max time without `snd_una` advancing while send work is outstanding,
    /// before the connection aborts. `0` disables it. Defaults to
    /// [`DEFAULT_USER_TIMEOUT_MS`]. The no-forward-progress defence against an
    /// alive-but-stalling peer (zero-window DoS), distinct from the R2
    /// any-sign-of-life retransmit budget.
    user_timeout_ms: u32,
    /// Instant at which the no-progress USER TIMEOUT fires. Armed lazily when
    /// unacked send work first appears, re-armed to `now + user_timeout_ms`
    /// whenever `snd_una` advances, cleared when no unacked work remains.
    user_timeout_deadline: Option<u64>,
    /// 128-bit secret used to MAC SYN cookies (RFC 4987). Live only if
    /// `cookie_secret_set` is true. With cookies enabled, a LISTEN TCB
    /// answers an inbound SYN **statelessly**: the SYN-ACK's ISN encodes
    /// a MAC of the 5-tuple + peer SEQ + a coarse time bucket; we keep
    /// no per-connection state until the third ACK validates the cookie.
    /// This is the canonical defence against SYN floods.
    cookie_secret: [u8; 16],
    cookie_secret_set: bool,
}

impl<const BUF: usize> Tcb<BUF> {
    /// Window-scale shift advertised for this ring capacity (compile-time).
    const WS: u8 = local_ws_shift(BUF);

    /// Construct a TCB in the `CLOSED` state.
    pub fn new(cfg: TcbConfig) -> Result<Self, TcpError> {
        Ok(Self {
            state: State::Closed,
            local: cfg.local,
            remote: cfg.remote,
            snd_una: cfg.iss,
            snd_nxt: cfg.iss,
            snd_max: cfg.iss,
            snd_wnd: 0,
            iss: cfg.iss,
            rcv_nxt: 0,
            rcv_wnd: BUF as u32,
            irs: 0,
            local_mss: MSS,
            peer_mss: DEFAULT_PEER_MSS,
            ts_enabled: false,
            ts_recent: 0,
            snd_wscale: 0,
            rcv_wscale: 0,
            ecn_enabled: false,
            ce_observed: false,
            send_cwr_pending: false,
            sack_enabled: false,
            sack_scoreboard: crate::scoreboard::SackScoreboard::new(),
            rxt_seq: 0,
            rxt_unacked: 0,
            send_queue: crate::send_queue::SendQueue::new(),
            rack: crate::rack::Rack::new(),
            rack_deadline: None,
            rack_lost_queue: RackLostQueue::new(),
            tlp_deadline: None,
            tlp_fired: false,
            send_ring: Ring::new()?,
            recv_ring: Ring::new()?,
            reasm: crate::reassembly::Reassembly::new(),
            cc: Tahoe::new(BUF as u32),
            now_ms: 0,
            rto_ms: cfg.initial_rto_ms.clamp(RTO_MIN_MS, RTO_MAX_MS),
            srtt_ms: 0,
            rttvar_ms: 0,
            rtt_first_sample: false,
            rto_deadline: None,
            rtt_probe: None,
            pending_ack: false,
            delayed_ack_count: 0,
            ack_deadline: None,
            persist_deadline: None,
            persist_backoff_ms: 0,
            fin_sent: false,
            fin_seq: 0,
            time_wait_deadline: None,
            error: None,
            tx_ring: crate::tx_ring::TxRing::new(),
            ip_id: 0,
            is_listener: false,
            syn_rcvd_retries: 0,
            rtx_count: 0,
            keepalive_idle_ms: 0,
            keepalive_intvl_ms: 0,
            keepalive_count: 0,
            keepalive_probes: 0,
            keepalive_deadline: None,
            user_timeout_ms: DEFAULT_USER_TIMEOUT_MS,
            user_timeout_deadline: None,
            cookie_secret: [0u8; 16],
            cookie_secret_set: false,
        })
    }

    /// Re-point an existing TCB at a new 5-tuple / ISS and reset it to the
    /// post-`new` `CLOSED` shape **in place**, reusing the already-allocated
    /// ring storage — no allocation and no multi-MiB ring memcpy. This lets a
    /// pool recycle a TCB across connections without freeing/reallocating its
    /// rings. After `reinit` the caller drives it exactly like a fresh TCB:
    /// `set_now`, then `listen` (passive) or `connect` (active).
    pub fn reinit(&mut self, cfg: TcbConfig) {
        self.local = cfg.local;
        self.remote = cfg.remote;
        self.iss = cfg.iss;
        self.rto_ms = cfg.initial_rto_ms.clamp(RTO_MIN_MS, RTO_MAX_MS);
        self.local_mss = MSS;
        self.is_listener = false;
        self.cookie_secret = [0u8; 16];
        self.cookie_secret_set = false;
        self.now_ms = 0;
        self.ip_id = 0;
        // Clears the rings (O(1) index reset; storage retained) and resets
        // every per-connection field to its post-`new` value.
        self.reset_connection_state();
        self.state = State::Closed;
    }

    // ---------------------------------------------------------------------
    // Public host-facing API
    // ---------------------------------------------------------------------

    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    /// Compact debug snapshot. Strictly diagnostic; not part of the
    /// public ABI surface — used by FFI to expose internal state to
    /// integration tests when investigating wedges.
    #[inline]
    pub fn debug_snapshot(&self) -> DebugSnapshot {
        DebugSnapshot {
            snd_una: self.snd_una,
            snd_nxt: self.snd_nxt,
            snd_wnd: self.snd_wnd,
            rcv_nxt: self.rcv_nxt,
            cwnd: self.cc.cwnd,
            ssthresh: self.cc.ssthresh,
            rto_ms: self.rto_ms,
            rto_deadline: self.rto_deadline.unwrap_or(u64::MAX),
            now_ms: self.now_ms,
            send_ring_len: self.send_ring.len() as u32,
            recv_ring_len: self.recv_ring.len() as u32,
            // For ABI compat: oo_start = first hole start (0 if none),
            // oo_len = total bytes held across all holes.
            oo_start: self
                .reasm
                .ready_slot(self.rcv_nxt.wrapping_add(1))
                .map(|(_, s, _)| s)
                .unwrap_or(0),
            oo_len: self.reasm.held_bytes() as u32,
            // For ABI compatibility: report the head packet's length
            // (or 0 if the ring is empty). Hosts that just want a
            // "got bytes pending?" gate keep working unchanged; hosts
            // that care about the queue depth can use `poll()`'s
            // TX_PENDING bit (still toggled by ring non-empty).
            tx_len: self.tx_ring.peek_head_len().unwrap_or(0) as u32,
            pending_ack: self.pending_ack,
            dup_ack_count: self.cc.dup_acks,
            state: self.state as u8,
        }
    }

    /// Expensive-ish internal consistency checks for tests and fuzz targets.
    ///
    /// This is intentionally *not* part of the C ABI and is compiled only for
    /// Rust tests or `feature = "std"` harnesses (the fuzz crate enables
    /// `std`). Keep these assertions semantic rather than implementation-
    /// incidental: a valid peer should never be able to drive the TCB into a
    /// state that makes this return `Err`.
    #[cfg(any(test, feature = "std"))]
    pub fn debug_validate_invariants(&self) -> Result<(), &'static str> {
        if seq_lt(self.snd_max, self.snd_una) {
            return Err("snd_max is behind snd_una");
        }
        if seq_lt(self.snd_nxt, self.snd_una) {
            return Err("snd_nxt is behind snd_una");
        }
        if seq_lt(self.snd_max, self.snd_nxt) {
            return Err("snd_nxt is beyond snd_max");
        }

        let outstanding = self.snd_max.wrapping_sub(self.snd_una);
        let mut phantom = 0u32;

        // SYN/SYN-ACK consume one byte of sequence space but are never stored
        // in the send ring.
        if matches!(self.state, State::SynSent | State::SynRcvd)
            && seq_lt(self.snd_una, self.snd_max)
        {
            phantom = phantom.saturating_add(1);
        }

        if self.fin_sent {
            let fin_end = self.fin_seq.wrapping_add(1);
            if seq_gt(fin_end, self.snd_max) {
                return Err("fin_seq is beyond snd_max");
            }
            // A FIN consumes one byte of sequence space but is not buffered.
            if seq_le(self.snd_una, self.fin_seq) && seq_lt(self.fin_seq, self.snd_max) {
                phantom = phantom.saturating_add(1);
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
            if matches!(
                self.state,
                State::FinWait2 | State::TimeWait | State::Closed
            ) && seq_lt(self.snd_una, fin_end)
            {
                return Err("state requires our FIN to be ACKed");
            }
        }

        let buffered_plus_phantom = (self.send_ring.len() as u32).saturating_add(phantom);
        if outstanding > buffered_plus_phantom {
            return Err("outstanding sequence span exceeds buffered data plus SYN/FIN");
        }

        if let Some(n) = self.tx_ring.peek_head_len() {
            if n > crate::MAX_PACKET {
                return Err("staged packet exceeds MAX_PACKET");
            }
        }

        if self.rto_deadline.is_some() && seq_le(self.snd_max, self.snd_una) {
            return Err("RTO armed with no outstanding sequence space");
        }

        Ok(())
    }

    /// Liveness oracle — the *deadlock* counterpart to
    /// [`Self::debug_validate_invariants`] (which only checks the safe
    /// direction, "a timer implies outstanding data"). This checks the
    /// direction deadlocks actually live in: **outstanding work implies a
    /// timer that will eventually act on it**. Call it at *rest* (after the
    /// host has drained `tx_ring` and run a `tick`); it self-skips while
    /// output is still staged, so progress-in-flight is never misread as a
    /// stall.
    ///
    /// Two black-hole classes are covered, each an invariant a correct stack
    /// must always maintain:
    ///
    /// 1. **Dead ACK clock.** Sequence space that has been sent but not yet
    ///    acknowledged (`snd_una < snd_max`) must always have a
    ///    retransmission timer behind it — RTO, TLP, or RACK. With none, no
    ///    event will ever put those bytes back on the wire, the peer's
    ///    cumulative ACK can never advance, and the connection black-holes.
    ///    This is precisely the shape of the PRR `snd_credit == 0` recovery
    ///    stall and of a lost sole-outstanding FIN.
    ///
    /// 2. **Stalled persist.** Data is queued to send but the peer's window
    ///    is shut (`snd_wnd == 0`) and nothing is in flight to clock it back
    ///    open; a persist probe must be scheduled or the window may never
    ///    reopen.
    #[cfg(any(test, feature = "std"))]
    pub fn debug_check_liveness(&self) -> Result<(), &'static str> {
        // At rest only: staged egress means progress is already pending and
        // resolves the instant the host drains the ring.
        if self.tx_ring.peek_head_len().is_some() {
            return Ok(());
        }
        // Class 1 — dead ACK clock.
        if seq_lt(self.snd_una, self.snd_max)
            && self.rto_deadline.is_none()
            && self.tlp_deadline.is_none()
            && self.rack_deadline.is_none()
        {
            return Err("liveness: outstanding data with no retransmit timer");
        }
        // Class 2 — stalled persist (only meaningful while we may still send).
        if self.state.can_send()
            && self.send_ring.len() != 0
            && self.snd_wnd == 0
            && seq_le(self.snd_max, self.snd_una)
            && self.persist_deadline.is_none()
        {
            return Err("liveness: data queued under zero window with no persist timer");
        }
        Ok(())
    }

    /// Earliest *output-producing* armed deadline — the next instant at which
    /// a tick would put a segment on the wire (RTO / TLP / RACK retransmit,
    /// persist probe, or a delayed ACK). Deliberately excludes the TIME_WAIT
    /// expiry, which produces no wire output and only reaps the slot: a
    /// harness must not fast-forward a peer *out* of TIME_WAIT, or it loses
    /// the 2·MSL window during which TIME_WAIT exists precisely to re-ACK the
    /// other side's retransmitted FIN. `None` if the stack is idle.
    #[cfg(any(test, feature = "std"))]
    pub fn debug_next_deadline(&self) -> Option<u64> {
        [
            self.rto_deadline,
            self.tlp_deadline,
            self.rack_deadline,
            self.persist_deadline,
            self.ack_deadline,
            self.keepalive_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Update the host clock. Called before every tick / packet operation.
    #[inline]
    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// Enable (or reconfigure) TCP keepalive (RFC 9293 §3.8.4) for this
    /// connection. Off by default — it never perturbs the wire unless a host
    /// opts in.
    ///
    /// After `idle_ms` of total inbound silence on an otherwise-idle
    /// `ESTABLISHED` connection — *idle* meaning nothing is in flight, since
    /// outstanding data is already covered by the R2 retransmit timeout — up
    /// to `count` zero-data probes are sent `intvl_ms` apart. The peer must
    /// answer each with an ACK (the probe sits one byte behind `snd_nxt`); if
    /// none of the `count` probes is answered the connection is aborted as a
    /// vanished peer (surfaced as `ConnectionReset`, no RST). Any inbound
    /// segment resets the idle timer and probe count. Pass `idle_ms == 0` to
    /// disable.
    pub fn set_keepalive(&mut self, idle_ms: u32, intvl_ms: u32, count: u8) {
        self.keepalive_idle_ms = idle_ms;
        self.keepalive_intvl_ms = intvl_ms.max(1);
        self.keepalive_count = count;
        self.keepalive_probes = 0;
        self.keepalive_deadline = if idle_ms == 0 {
            None
        } else {
            Some(self.now_ms.wrapping_add(idle_ms as u64))
        };
    }

    /// Set the RFC 9293 §3.8.3 USER TIMEOUT: the maximum time the connection
    /// may go without `snd_una` advancing while it still has unacknowledged
    /// send work, before it is aborted (`ConnectionReset`, no RST). On by
    /// default at [`DEFAULT_USER_TIMEOUT_MS`]; pass `0` to disable.
    ///
    /// This is the no-forward-progress defence and is deliberately independent
    /// of the R2 retransmit budget: R2 resets on any sign of life, so a peer
    /// that keeps ACKing zero-window persist probes (or dribbles duplicate
    /// ACKs) looks alive to R2 forever. The USER TIMEOUT resets only on real
    /// progress, so such a stalling peer cannot pin the TCB past this bound.
    /// Re-arms from the current clock against any outstanding work.
    pub fn set_user_timeout(&mut self, ms: u32) {
        self.user_timeout_ms = ms;
        // Re-arm against current state: if disabled, or there is nothing
        // outstanding, clear; otherwise start a fresh window now.
        let has_work = self.snd_una != self.snd_max || !self.send_ring.is_empty();
        self.user_timeout_deadline = if ms == 0 || !has_work {
            None
        } else {
            Some(self.now_ms.wrapping_add(ms as u64))
        };
    }

    /// Initiate an active open: transitions `Closed` → `SynSent`, queues a SYN
    /// carrying MSS + Window Scale + Timestamps + SACK_PERMITTED options,
    /// and the ECN-Setup flags (CWR + ECE per RFC 3168 §6.1.1).
    pub fn connect(&mut self) -> Result<(), TcpError> {
        if self.state != State::Closed {
            return Err(TcpError::InvalidState);
        }
        self.state = State::SynSent;
        self.snd_una = self.iss;
        // Offer Window Scale (RFC 7323 §2), Timestamps (RFC 7323 §3) and
        // SACK_PERMITTED (RFC 2018). The peer may decline any; each is a
        // no-op if not echoed back in the SYN-ACK. SACK is what keeps lossy
        // bidirectional bulk from wedging on RTO-only recovery — see
        // `process_ack` below.
        let opts = TcpOptions {
            mss: Some(self.local_mss),
            wscale: Some(Self::WS),
            ts: Some((self.ts_val(), 0)),
            sack_permitted: true,
            sack: SackBlocks::EMPTY,
        };
        // RFC 3168 §6.1.1: active opener sets BOTH ECE and CWR on the SYN
        // to advertise ECN-capable. ECN is confirmed iff the SYN-ACK
        // carries ECE without CWR. The SYN itself MUST NOT be ECT-marked
        // — emit_segment enforces that based on the SYN flag.
        // Ring is empty at connect-time so the queue must succeed; we
        // still gate the state advance on the explicit bool for
        // robustness against future reorderings of the connect path.
        if self.emit_segment(
            flags::SYN | flags::ECE | flags::CWR,
            self.iss,
            0,
            &opts,
            &[],
        )? {
            self.snd_nxt = self.iss.wrapping_add(1); // SYN occupies one seq
            self.bump_snd_max();
            self.arm_rto_for(self.snd_nxt);
        }
        Ok(())
    }

    /// Initiate a passive open: transitions `Closed` → `Listen`. The remote
    /// endpoint is wildcarded — `inject_packet` will accept a SYN from any
    /// source and pin the remote on acceptance. Idempotent on repeat.
    ///
    /// SYN flood resistance: by default the listener uses **stateful**
    /// SYN_RCVD with a bounded retransmit budget — at most one half-open
    /// at a time, and at most [`MAX_SYN_RCVD_RETRIES`] SYN-ACK retransmits
    /// before reverting to LISTEN. To get **stateless** SYN-cookie
    /// behaviour (no per-connection state until the third ACK), call
    /// [`Tcb::set_cookie_secret`] before the first SYN arrives.
    pub fn listen(&mut self) -> Result<(), TcpError> {
        // We allow Listen-from-Listen (idempotent), Listen-from-Closed,
        // and Listen-from-TimeWait (the latter is the
        // SO_REUSEADDR-style "drop the 2*MSL wait and re-arm now"
        // semantics that real servers depend on). Anything else means
        // an in-progress connection would be torn down silently — the
        // host should call `close` first.
        match self.state {
            State::Closed | State::Listen | State::TimeWait => {}
            _ => return Err(TcpError::InvalidState),
        }
        // Wildcard the remote so `inject_packet` accepts any source.
        self.remote = Endpoint {
            ip: [0u8; 4],
            port: 0,
        };
        self.is_listener = true;
        self.reset_connection_state();
        self.state = State::Listen;
        Ok(())
    }

    /// Configure a 128-bit secret that switches the listener into
    /// stateless SYN-cookie mode (RFC 4987). Once set, an inbound SYN in
    /// `LISTEN` is answered by a SYN-ACK whose ISN is a MAC of the
    /// 5-tuple, peer SEQ and a coarse time bucket — no state is kept.
    /// The third ACK is validated by recomputing the cookie. The validity
    /// window is `2 * COOKIE_TIME_BUCKET_MS` (≈ 128 s).
    ///
    /// The host should pass a high-entropy secret produced from a CSPRNG.
    /// Rotating the secret invalidates outstanding cookies — fine, the
    /// peer will retransmit the SYN.
    ///
    /// Stateless cookies do **not** preserve all SYN options: peer MSS is
    /// quantised to one of [`COOKIE_MSS_TABLE`]; SACK_PERMITTED is not
    /// preserved (we disable SACK on the resulting connection); peer
    /// Timestamps presence is preserved by echoing the SYN's TSval back
    /// in the SYN-ACK and looking at the third ACK's TS option.
    pub fn set_cookie_secret(&mut self, secret: &[u8; 16]) {
        self.cookie_secret = *secret;
        self.cookie_secret_set = true;
    }

    /// Reset all per-connection state to its post-`Tcb::new` shape, leaving
    /// `local`, `iss`, `local_mss`, `is_listener`, `cookie_secret`, `now_ms`
    /// and `ip_id` intact. Used by `listen` and by the SYN_RCVD-budget-
    /// exhaustion / RST-during-handshake reset paths.
    fn reset_connection_state(&mut self) {
        self.snd_una = self.iss;
        self.snd_nxt = self.iss;
        self.snd_max = self.iss;
        self.snd_wnd = 0;
        self.rcv_nxt = 0;
        self.rcv_wnd = BUF as u32;
        self.irs = 0;
        self.peer_mss = DEFAULT_PEER_MSS;
        self.ts_enabled = false;
        self.ts_recent = 0;
        self.snd_wscale = 0;
        self.rcv_wscale = 0;
        self.ecn_enabled = false;
        self.ce_observed = false;
        self.send_cwr_pending = false;
        self.sack_enabled = false;
        self.sack_scoreboard.clear();
        self.rxt_seq = 0;
        self.rxt_unacked = 0;
        self.send_queue.clear();
        self.rack = crate::rack::Rack::new();
        self.rack_deadline = None;
        self.rack_lost_queue.clear();
        self.tlp_deadline = None;
        self.tlp_fired = false;
        self.rtx_count = 0;
        self.keepalive_probes = 0;
        self.keepalive_deadline = None;
        self.user_timeout_deadline = None;
        self.send_ring.clear();
        self.recv_ring.clear();
        self.reasm.clear();
        self.cc = Tahoe::new(BUF as u32);
        self.rto_deadline = None;
        self.rtt_probe = None;
        self.srtt_ms = 0;
        self.rttvar_ms = 0;
        self.rtt_first_sample = false;
        self.pending_ack = false;
        self.delayed_ack_count = 0;
        self.ack_deadline = None;
        self.persist_deadline = None;
        self.persist_backoff_ms = 0;
        self.fin_sent = false;
        self.fin_seq = 0;
        self.time_wait_deadline = None;
        self.error = None;
        self.tx_ring.clear();
        self.syn_rcvd_retries = 0;
    }

    /// Revert from a half-open passive state back to `LISTEN` (or
    /// `CLOSED` if this TCB was never a listener). Called when the
    /// SYN_RCVD retransmit budget is exhausted, or when a RST during a
    /// passive-side handshake aborts the connection.
    fn reset_to_listen_or_closed(&mut self) {
        let return_to_listen = self.is_listener;
        self.reset_connection_state();
        // Wildcard remote so the listener is ready to accept the next SYN.
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

    /// Push application data into the send ring. Returns bytes written.
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

    /// Pull application data out of the receive ring. Returns bytes read.
    /// Returns `ConnectionClosed` once both the ring is empty and the peer
    /// has FINned (or we have torn down).
    pub fn recv(&mut self, dst: &mut [u8]) -> Result<usize, TcpError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let n = self.recv_ring.read(dst);
        // Reading from the ring frees space, which may let us complete a
        // partial drain that previously stalled on a full ring.
        if n > 0 {
            self.drain_reassembly();
            self.rcv_wnd = self.advertised_window();
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

    /// Begin a graceful close. Idempotent.
    pub fn close(&mut self) -> Result<(), TcpError> {
        match self.state {
            State::Established => self.state = State::FinWait1,
            State::CloseWait => self.state = State::LastAck,
            // RFC 793 §3.10 CLOSE in SYN_RECEIVED with no pending data: form
            // a FIN and enter FIN-WAIT-1. The send ring is empty here (we
            // haven't yet entered Established), so `maybe_send_data` will
            // emit the FIN at `snd_nxt = iss + 1`. Any in-flight SYN-ACK
            // retransmits become moot — the FIN piggybacks the same ACK.
            State::SynRcvd => self.state = State::FinWait1,
            State::Closed
            | State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::LastAck => return Ok(()),
            // No segments have been exchanged yet; both transitions are
            // local and free of wire effects.
            State::SynSent | State::Listen => {
                self.is_listener = false;
                self.state = State::Closed;
                return Ok(());
            }
        }
        // Try to push the FIN immediately if there's room.
        self.maybe_send_data()?;
        Ok(())
    }

    /// Abort the connection by emitting a TCP RST. Unlike [`Tcb::close`]
    /// (which initiates a graceful FIN handshake), this is an immediate
    /// teardown: a `RST+ACK` segment with `seq=snd_nxt` and
    /// `ack=rcv_nxt` is queued in the TX ring for the caller to drain,
    /// the TCB transitions to `CLOSED`, all buffered data is dropped,
    /// and `ConnectionReset` is surfaced via [`Tcb::poll`]'s `ERROR`
    /// flag.
    ///
    /// Intended for hosts that have detected a failure outside the TCB
    /// (e.g. the upstream socket couldn't be reached, the proxy was
    /// killed, a shim-side timeout fired) and need to propagate the
    /// failure to the peer immediately rather than waiting for a
    /// graceful FIN to drain.
    ///
    /// Idempotent: aborting an already-`CLOSED` TCB is a no-op. In
    /// `LISTEN` or `SYN_SENT` there is no peer-known sequence number
    /// the peer would honour, so this is a local-only state
    /// transition (no wire RST). In every other state a `RST+ACK` is
    /// queued — the `ACK` bit makes the segment unconditionally
    /// acceptable to the peer per RFC 5961 §3.2 (in-window ACK
    /// bypasses the bare-RST window-validation check that defeats
    /// blind off-path RST injections).
    ///
    /// All protocol timers (RTO, persist, delayed ACK, TIME-WAIT,
    /// RACK, TLP) are cleared. Send / receive / reassembly buffers
    /// are wiped — any unsent / unread / out-of-order bytes are lost
    /// (that is the entire point of an abort).
    pub fn abort(&mut self) -> Result<(), TcpError> {
        match self.state {
            State::Closed => return Ok(()),
            // No peer-known sequence number to RST against. SYN_SENT
            // peers MAY have observed our SYN, but the RST we'd send
            // (seq=iss, no ACK) is window-validated and easily
            // dropped; treat both as local-only transitions.
            State::Listen | State::SynSent => {
                self.is_listener = false;
            }
            _ => {
                // RFC 5961 §3.2: RST+ACK with an in-window ACK is
                // accepted unconditionally, bypassing the
                // bare-RST window-validation rule. We use snd_nxt
                // for SEG.SEQ and rcv_nxt for SEG.ACK — these are
                // the canonical "fast abort" values.
                let _ = self.emit_segment(
                    flags::RST | flags::ACK,
                    self.snd_nxt,
                    self.rcv_nxt,
                    &TcpOptions::NONE,
                    &[],
                )?;
            }
        }
        self.state = State::Closed;
        self.error = Some(TcpError::ConnectionReset);
        // Drop any unsent / unread / OOO bytes. The caller asked to
        // abort, not to drain.
        self.send_ring.clear();
        self.recv_ring.clear();
        self.reasm.clear();
        // Clear every protocol-level timer so a subsequent `tick`
        // call doesn't drive anything.
        self.rto_deadline = None;
        self.time_wait_deadline = None;
        self.persist_deadline = None;
        self.ack_deadline = None;
        self.rack_deadline = None;
        self.tlp_deadline = None;
        Ok(())
    }

    /// RFC 9293 §3.8.3 R2 abort: tear the connection down locally once the
    /// retransmit budget ([`MAX_RETRANSMITS`]) is spent. Unlike [`Tcb::abort`]
    /// this emits **no** RST — at R2 the peer is presumed unreachable (Linux
    /// behaves the same on `tcp_retries2`), and the deployment's
    /// anti-reflection posture prefers not to spray resets at a silent
    /// endpoint. The failure surfaces as `ConnectionReset` ("aborted locally")
    /// via [`Tcb::poll`] / [`Tcb::recv`].
    fn abort_timed_out(&mut self) {
        self.state = State::Closed;
        self.error = Some(TcpError::ConnectionReset);
        self.send_ring.clear();
        self.recv_ring.clear();
        self.reasm.clear();
        // Nothing is outstanding on a dead connection; collapse the send
        // sequence so the snd_una/snd_nxt/snd_max invariants hold now that the
        // ring is empty.
        self.snd_nxt = self.snd_una;
        self.snd_max = self.snd_una;
        self.fin_sent = false;
        self.rto_deadline = None;
        self.time_wait_deadline = None;
        self.persist_deadline = None;
        self.ack_deadline = None;
        self.rack_deadline = None;
        self.tlp_deadline = None;
        self.keepalive_deadline = None;
        self.keepalive_probes = 0;
        self.user_timeout_deadline = None;
    }

    /// Aggregate event flags for the host async runtime to dispatch on.
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

    /// Drain one queued outbound IP datagram from the egress ring
    /// into `out`. Returns bytes written (0 if nothing pending).
    ///
    /// The ring can hold up to [`crate::tx_ring::TX_RING_CAP`]
    /// packets. The host should call this in a loop until it returns
    /// 0 — that's the contract `inject_packet` relies on (otherwise
    /// responses generated by the injected segment may sit behind
    /// older queued packets and be effectively stale).
    pub fn extract_packet(&mut self, out: &mut [u8]) -> Result<usize, TcpError> {
        self.tx_ring.pop_into(out)
    }

    /// Feed an inbound IPv4+TCP datagram into the state machine.
    ///
    /// Contract: the caller must have drained any pending outbound packet
    /// (via `extract_packet`) before calling this — otherwise responses
    /// generated by this segment may be silently dropped.
    pub fn inject_packet(&mut self, packet: &[u8]) -> Result<(), TcpError> {
        let seg = wire::parse(packet)?;
        // Local side of the 5-tuple must always match. The remote side is
        // skipped only in LISTEN, where the remote is wildcarded — that's
        // the entire point of a passive open.
        if seg.dst_ip != self.local.ip || seg.dst_port != self.local.port {
            return Err(TcpError::NotForUs);
        }
        if !matches!(self.state, State::Listen)
            && (seg.src_ip != self.remote.ip || seg.src_port != self.remote.port)
        {
            return Err(TcpError::NotForUs);
        }
        // Any inbound segment is proof the peer is alive: re-arm the keepalive
        // idle timer and clear the unanswered-probe count.
        if self.keepalive_idle_ms != 0 {
            self.keepalive_probes = 0;
            self.keepalive_deadline = Some(self.now_ms.wrapping_add(self.keepalive_idle_ms as u64));
        }
        self.on_segment(&seg)
    }

    /// Drive timers and try to push more data on the wire.
    pub fn tick(&mut self) -> Result<(), TcpError> {
        // ---- TIME_WAIT expiry -------------------------------------------
        if let Some(deadline) = self.time_wait_deadline {
            if self.now_ms >= deadline {
                self.state = State::Closed;
                self.time_wait_deadline = None;
            }
        }
        // ---- RTO expiry → RFC 5681 §3 collapse --------------------------
        // Note: PRR (RFC 6937 §6) explicitly does not modify RTO behavior;
        // RTO continues to use Tahoe-style cwnd=1*MSS + slow-start re-open.
        if let Some(deadline) = self.rto_deadline {
            if self.now_ms >= deadline {
                // RFC 9293 §3.8.3 (R2): bound retransmissions so a silent or
                // vanished peer cannot keep us retransmitting forever. Every
                // retransmitting state except SYN_RCVD (which reverts to
                // LISTEN under its own budget below) shares this counter; it
                // was reset on the last forward ACK, so reaching the cap means
                // nothing has been acknowledged for the whole back-off window.
                if self.state != State::SynRcvd {
                    self.rtx_count = self.rtx_count.saturating_add(1);
                    if self.rtx_count > MAX_RETRANSMITS {
                        self.abort_timed_out();
                        return Ok(());
                    }
                }
                let flight = self.snd_nxt.wrapping_sub(self.snd_una);
                self.cc.on_rto_loss(flight);
                self.snd_nxt = self.snd_una;
                // RTO means we've lost confidence about what's in flight;
                // SACK information is stale. Clear scoreboard + rxt state
                // so we don't keep skipping "previously SACKed" segments
                // that the peer may have reneged on. Also clear RACK / TLP
                // state per RFC 8985 §5: RTO invalidates time-based loss
                // detection state.
                self.sack_scoreboard.clear();
                self.rxt_seq = self.snd_una;
                self.rxt_unacked = 0;
                self.send_queue.clear();
                self.rack.reset();
                self.rack_deadline = None;
                self.rack_lost_queue.clear();
                self.tlp_deadline = None;
                self.tlp_fired = false;
                // Exponential back-off, capped.
                self.rto_ms = (self.rto_ms.saturating_mul(2)).min(RTO_MAX_MS);
                // Karn: invalidate any in-flight RTT probe.
                if let Some(p) = self.rtt_probe.as_mut() {
                    p.valid = false;
                }
                self.rto_deadline = None;
                // We may need to re-emit SYN if we were retransmitting it.
                if self.state == State::SynSent {
                    let opts = TcpOptions {
                        mss: Some(self.local_mss),
                        wscale: Some(Self::WS),
                        ts: Some((self.ts_val(), 0)),
                        sack_permitted: true,
                        sack: SackBlocks::EMPTY,
                    };
                    // ECN-Setup SYN per RFC 3168 §6.1.1 — same flags as
                    // the initial connect() emission. Ring was just cleared
                    // by the RTO collapse a few lines above, so the queue
                    // attempt will succeed.
                    if self.emit_segment(
                        flags::SYN | flags::ECE | flags::CWR,
                        self.iss,
                        0,
                        &opts,
                        &[],
                    )? {
                        self.snd_nxt = self.iss.wrapping_add(1);
                        self.bump_snd_max();
                        self.arm_rto_for(self.snd_nxt);
                    }
                } else if self.state == State::SynRcvd {
                    // Bounded SYN-ACK retransmit. Once the budget is spent
                    // we revert to LISTEN — the half-open slot is freed
                    // and the listener becomes responsive again. This is
                    // the entire flood-resistance argument for the
                    // stateful path: at most one half-open at a time, and
                    // at most `MAX_SYN_RCVD_RETRIES` retransmits per slot.
                    self.syn_rcvd_retries = self.syn_rcvd_retries.saturating_add(1);
                    if self.syn_rcvd_retries > MAX_SYN_RCVD_RETRIES {
                        self.reset_to_listen_or_closed();
                    } else if self.emit_synack_from_state()? {
                        self.snd_nxt = self.iss.wrapping_add(1);
                        self.bump_snd_max();
                        self.arm_rto_for(self.snd_nxt);
                    }
                }
            }
        }
        // ---- RACK reorder timer (RFC 8985 §6.3) -------------------------
        // RACK might have classified some in-flight segments as
        // "eligible-but-not-old-enough" on the last ACK. When the timer
        // expires, rescan to discover newly-lost ranges.
        if let Some(deadline) = self.rack_deadline {
            if self.now_ms >= deadline {
                self.rack_deadline = None;
                self.run_rack_scan();
            }
        }
        // ---- TLP Probe Timeout (RFC 8985 §7) ----------------------------
        // RTO wins ties: only fire TLP if RTO hasn't fired this tick.
        if let Some(deadline) = self.tlp_deadline {
            if self.now_ms >= deadline {
                self.fire_tlp_probe()?;
            }
        }
        // ---- Persist (zero-window probe) timer --------------------------
        self.check_persist()?;
        // ---- Keepalive (idle-connection vanished-peer probe) ------------
        self.check_keepalive()?;
        // ---- USER TIMEOUT (no-forward-progress abort) -------------------
        self.check_user_timeout();
        if self.state == State::Closed {
            return Ok(());
        }
        // ---- Try to push outbound data / FIN ----------------------------
        // Run BEFORE the delayed-ACK fallback below so the ACK gets
        // piggybacked on a data segment if possible. `maybe_send_data`
        // clears `pending_ack` on each successful data emit.
        self.maybe_send_data()?;
        // ---- Delayed-ACK expiry -----------------------------------------
        // Only fires if `maybe_send_data` above did not already piggyback
        // an ACK on a data segment. Gated on ring having room rather than
        // being empty: a small ACK can ride alongside queued data.
        if self.pending_ack {
            if let Some(d) = self.ack_deadline {
                if self.now_ms >= d && !self.tx_ring.is_full() {
                    self.send_pure_ack()?;
                }
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Sans-I/O segment processing — the heart of the state machine.
    // ---------------------------------------------------------------------

    fn on_segment(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if seg.has(flags::RST) {
            return self.handle_rst(seg);
        }

        match self.state {
            State::Closed => Err(TcpError::InvalidState),
            State::Listen => self.on_segment_listen(seg),
            State::SynSent => self.on_segment_syn_sent(seg),
            State::SynRcvd => self.on_segment_syn_rcvd(seg),
            State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing
            | State::LastAck
            | State::TimeWait => self.on_segment_synchronised(seg),
        }
    }

    fn handle_rst(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        // Acceptability: in SYN_SENT, RST is valid only if it ACKs our SYN.
        if matches!(self.state, State::SynSent) && (!seg.has(flags::ACK) || seg.ack != self.snd_nxt)
        {
            return Err(TcpError::NotForUs);
        }
        // RFC 793 §3.4: a RST in LISTEN is silently discarded — there is no
        // connection to abort and acting on it would let an attacker who
        // can spoof RSTs prevent any peer from completing a handshake.
        if matches!(self.state, State::Listen) {
            return Ok(());
        }
        // SYN_RCVD: RST aborts the half-open. RFC 9293 §3.10.7.4 requires
        // SEG.SEQ to be inside our receive window for the RST to be
        // accepted; otherwise drop. This denies blind off-path RST attacks.
        if matches!(self.state, State::SynRcvd) {
            if !self.in_window(seg.seq, 0) {
                return Ok(());
            }
            // Recycle the slot back to LISTEN if we're a passive listener,
            // CLOSED otherwise. Don't surface the RST as an error in the
            // listener case — it's a routine "no connection here" signal.
            if self.is_listener {
                self.reset_to_listen_or_closed();
                return Ok(());
            }
            self.error = Some(TcpError::ConnectionReset);
            self.state = State::Closed;
            self.rto_deadline = None;
            return Ok(());
        }
        self.error = Some(TcpError::ConnectionReset);
        self.state = State::Closed;
        self.rto_deadline = None;
        self.time_wait_deadline = None;
        self.persist_deadline = None;
        self.ack_deadline = None;
        Ok(())
    }

    fn on_segment_syn_sent(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if !seg.has(flags::SYN) {
            return Err(TcpError::NotForUs);
        }
        if seg.has(flags::ACK) {
            if seg.ack != self.snd_nxt {
                let _ = self.emit_segment(flags::RST, seg.ack, 0, &TcpOptions::NONE, &[])?;
                return Ok(());
            }
            // SYN-ACK accepted → ESTABLISHED.
            self.irs = seg.seq;
            self.rcv_nxt = seg.seq.wrapping_add(1);
            self.snd_una = seg.ack;
            self.rtx_count = 0;
            // RFC 7323 §2.3: SYN-ACK window field is NEVER scaled.
            self.snd_wnd = seg.window as u32;

            // Negotiate options.
            if let Some(mss) = seg.options.mss {
                self.peer_mss = mss.max(DEFAULT_PEER_MSS);
            }
            // Window Scale: only honour it if the peer offered WS in
            // their SYN-ACK. Per RFC 7323 §2.2, scaling is bidirectional
            // and gated on both sides offering the option. We always offer
            // it on the active SYN, so the peer's choice is the only
            // variable; if peer omits it, both directions stay unscaled.
            if let Some(peer_ws) = seg.options.wscale {
                self.snd_wscale = peer_ws.min(14);
                self.rcv_wscale = Self::WS;
            }
            if let Some((tsval, tsecr)) = seg.options.ts {
                self.ts_enabled = true;
                self.ts_recent = tsval;
                // SYN-ACK's TSecr echoes our SYN's TSval — first RTT sample.
                if tsecr != 0 {
                    self.update_rtt_from_ts_echo(tsecr);
                }
            }
            // SACK is symmetric: both peers must signal SACK_PERMITTED in
            // their SYN/SYN-ACK. We always offer it, so the peer's choice
            // is the only variable. RFC 2018 §2.
            self.sack_enabled = seg.options.sack_permitted;
            // ECN-Setup confirmation: RFC 3168 §6.1.1 says the SYN-ACK
            // confirms ECN iff it carries ECE *without* CWR (the active
            // opener set CWR+ECE on the SYN; a confirming server clears
            // CWR and keeps ECE). Any other combination disables ECN.
            self.ecn_enabled = seg.has(flags::ECE) && !seg.has(flags::CWR);
            // Fallback probe (no-TS path) is also satisfied by this ACK.
            self.process_ack_rtt(seg.ack);
            self.rto_deadline = None;
            self.rtt_probe = None;

            self.state = State::Established;
            self.send_pure_ack()?;
        } else {
            // Pure SYN → simultaneous open. Not supported in client-only mode.
            let _ = self.emit_segment(
                flags::RST,
                0,
                seg.seq.wrapping_add(1),
                &TcpOptions::NONE,
                &[],
            )?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // LISTEN — passive open. Adversarial-input hardening.
    //
    // RFC 793 §3.10 prescribes specific responses for each segment type
    // arriving in LISTEN. We follow the spec where it improves
    // robustness, and *deviate* (silently dropping instead of RSTing)
    // where the spec's RST response would amplify reflection attacks:
    //
    //   * RST           — drop. (RFC 793: drop. Same.)
    //   * SYN+ACK       — RST. (RFC 793: RST seq=ack ack=0.)
    //   * Bare ACK      — drop, unless cookies are enabled and the ACK
    //                     validates as the third leg of a cookie
    //                     handshake. (RFC 793: RST seq=ack ack=0. We
    //                     drop instead so an attacker spamming ACKs
    //                     gets *no response* — they can't use us as a
    //                     reflection amplifier.)
    //   * FIN-only or any other seg without SYN — drop silently.
    //   * SYN           — accept. With cookies disabled, we transition
    //                     to SYN_RCVD and emit a SYN-ACK. With cookies
    //                     enabled, we emit a stateless cookie SYN-ACK
    //                     and stay in LISTEN.
    // ---------------------------------------------------------------------
    fn on_segment_listen(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        // Bare ACK (no SYN): possibly a SYN-cookie third ACK; otherwise drop.
        if seg.has(flags::ACK) && !seg.has(flags::SYN) {
            if self.cookie_secret_set {
                // try_promote_via_cookie internally falls through to
                // on_segment_synchronised on success; on validation
                // failure we silently drop.
                let _ = self.try_promote_via_cookie(seg)?;
            }
            return Ok(());
        }
        // SYN+ACK in LISTEN — invalid, send RST per RFC.
        if seg.has(flags::SYN) && seg.has(flags::ACK) {
            let _ = self.emit_segment(flags::RST, seg.ack, 0, &TcpOptions::NONE, &[])?;
            return Ok(());
        }
        // Anything other than a pure SYN at this point is dropped silently.
        if !seg.has(flags::SYN) {
            return Ok(());
        }
        // Pure SYN.
        if self.cookie_secret_set {
            self.emit_cookie_synack(seg)
        } else {
            self.accept_syn_stateful(seg)
        }
    }

    /// Stateful passive-open path: pin the remote, transition to SYN_RCVD,
    /// emit SYN-ACK using `self.iss` as our ISN, arm the SYN-ACK retransmit
    /// timer.
    fn accept_syn_stateful(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        // Wipe per-connection state — we may be recycling a slot from a
        // previous closed connection.
        self.reset_connection_state();

        // Pin the remote and absorb peer's SYN options.
        self.remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        // RFC 7323 §2.3: SYN window field is NEVER scaled.
        self.snd_wnd = seg.window as u32;
        if let Some(mss) = seg.options.mss {
            self.peer_mss = mss.max(DEFAULT_PEER_MSS);
        }
        // Window Scale: per RFC 7323 §2.2, we can only send WS in our
        // SYN-ACK if the peer offered it in their SYN. If they did, record
        // their shift count for inbound windows and enable our outbound
        // scaling; otherwise both directions stay unscaled.
        if let Some(peer_ws) = seg.options.wscale {
            self.snd_wscale = peer_ws.min(14);
            self.rcv_wscale = Self::WS;
        }
        if let Some((tsval, _)) = seg.options.ts {
            self.ts_enabled = true;
            self.ts_recent = tsval;
        }
        self.sack_enabled = seg.options.sack_permitted;
        // ECN-Setup negotiation (passive side, RFC 3168 §6.1.1): the
        // peer's SYN must carry BOTH CWR and ECE; we then confirm by
        // setting only ECE on our SYN-ACK (handled in
        // emit_synack_from_state).
        self.ecn_enabled = seg.has(flags::ECE) && seg.has(flags::CWR);
        self.snd_una = self.iss;
        self.snd_nxt = self.iss;
        self.snd_max = self.iss;
        self.rcv_wnd = self.advertised_window();

        // Emit SYN-ACK. We optimistically advance snd_nxt/snd_max and
        // transition state even if the ring is currently full — the RTO
        // path will re-emit on the next tick, and accept_syn_stateful is
        // entered from a fresh inject so the ring should normally have
        // room.
        let queued = self.emit_synack_from_state()?;
        self.snd_nxt = self.iss.wrapping_add(1);
        self.bump_snd_max();

        self.state = State::SynRcvd;
        self.syn_rcvd_retries = 0;
        self.arm_rto_for(self.snd_nxt);
        let _ = queued;
        Ok(())
    }

    /// Stateless cookie path: compute a SYN-cookie ISN, emit a SYN-ACK
    /// directly without touching connection state, and remain in LISTEN.
    /// The third ACK will recover all state by validating the cookie.
    fn emit_cookie_synack(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if self.tx_ring.is_full() {
            // Caller hasn't drained — the peer will retry.
            return Ok(());
        }
        let peer_mss = seg
            .options
            .mss
            .map(|m| m.max(DEFAULT_PEER_MSS))
            .unwrap_or(DEFAULT_PEER_MSS);
        let mss_idx = cookie_mss_index(peer_mss);
        let bucket = self.now_ms / COOKIE_TIME_BUCKET_MS;
        let cookie = self.compute_cookie(bucket, seg.src_ip, seg.src_port, mss_idx, seg.seq);

        // Emit SYN-ACK with seq=cookie, ack=peer_seq+1, MSS option, and TS
        // echo if peer offered TS. We deliberately do not echo
        // SACK_PERMITTED here: cookies don't preserve it across the
        // half-open gap, and a peer expecting SACK on a connection that
        // doesn't actually have it just sees its SACK blocks ignored.
        // For the same reason we omit Window Scale: the cookie has no
        // bits to encode the peer's WS shift, so cookie-promoted
        // connections always run unscaled.
        let ack = seg.seq.wrapping_add(1);
        let opts = TcpOptions {
            mss: Some(self.local_mss),
            wscale: None,
            ts: seg
                .options
                .ts
                .map(|(peer_tsval, _)| (self.ts_val(), peer_tsval)),
            sack_permitted: false,
            sack: SackBlocks::EMPTY,
        };
        let win = u16::try_from(self.advertised_window().min(u16::MAX as u32)).unwrap_or(u16::MAX);
        // Direct emit so we don't mutate any per-connection state — staying
        // in LISTEN is the whole point of this path. IP TOS is NOT_ECT:
        // SYN-ACK segments MUST NOT be ECT-marked (RFC 3168 §6.1.1), and
        // cookie-promoted connections don't negotiate ECN anyway.
        let local_ip = self.local.ip;
        let src_ip = seg.src_ip;
        let local_port = self.local.port;
        let src_port = seg.src_port;
        let ip_id = self.ip_id;
        let queued = self.tx_ring.push_with(|buf| {
            wire::emit(
                buf,
                local_ip,
                src_ip,
                local_port,
                src_port,
                cookie,
                ack,
                flags::SYN | flags::ACK,
                win,
                &opts,
                &[],
                ip_id,
                wire::ecn::NOT_ECT,
            )
        })?;
        if queued {
            self.ip_id = self.ip_id.wrapping_add(1);
        }
        Ok(())
    }

    /// Validate a bare ACK as the third leg of a SYN-cookie handshake. On
    /// success, populate connection state from the cookie and transition
    /// to ESTABLISHED, then dispatch the segment through
    /// `on_segment_synchronised` so any piggybacked payload / FIN is
    /// processed normally. Returns `Ok(true)` on successful promotion,
    /// `Ok(false)` if the cookie did not validate (segment was silently
    /// dropped).
    fn try_promote_via_cookie(&mut self, seg: &Segment<'_>) -> Result<bool, TcpError> {
        // The third ACK has SEG.SEQ = peer_seq + 1, SEG.ACK = cookie + 1.
        // Recover candidates and check both the current and previous time
        // bucket so a slow third ACK that arrives just past a bucket
        // rollover still validates.
        let cookie = seg.ack.wrapping_sub(1);
        let mss_idx = ((cookie >> 29) & 0x7) as u8;
        let peer_seq = seg.seq.wrapping_sub(1);
        let now_bucket = self.now_ms / COOKIE_TIME_BUCKET_MS;
        let buckets = [now_bucket, now_bucket.wrapping_sub(1)];
        let mut matched = false;
        for &bucket in &buckets {
            let expected = self.compute_cookie(bucket, seg.src_ip, seg.src_port, mss_idx, peer_seq);
            if expected == cookie {
                matched = true;
                break;
            }
        }
        if !matched {
            return Ok(false);
        }

        // Cookie is valid — recover connection state and promote to
        // ESTABLISHED, skipping SYN_RCVD entirely (the cookie *is* the
        // half-open state).
        self.reset_connection_state();
        self.remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        self.peer_mss = cookie_mss_from_index(mss_idx).max(DEFAULT_PEER_MSS);
        self.irs = peer_seq;
        self.rcv_nxt = peer_seq.wrapping_add(1);
        self.iss = cookie;
        self.snd_una = seg.ack;
        self.snd_nxt = seg.ack;
        self.snd_max = seg.ack;
        // Cookie path runs unscaled (snd_wscale == 0), so this is just
        // `seg.window as u32` — but go through the helper for symmetry
        // with the rest of the codebase.
        self.snd_wnd = self.scale_peer_window(seg.window);
        // Inherit the third ACK's TS, if any. Cookie mode does not
        // negotiate SACK — see emit_cookie_synack for the reasoning.
        if let Some((tsval, _)) = seg.options.ts {
            self.ts_enabled = true;
            self.ts_recent = tsval;
        }
        self.rcv_wnd = self.advertised_window();
        self.state = State::Established;
        self.on_segment_synchronised(seg)?;
        Ok(true)
    }

    /// Emit a SYN-ACK using the currently-negotiated connection state
    /// (`self.iss`, `self.rcv_nxt`, `self.peer_mss`, `self.ts_enabled`,
    /// `self.sack_enabled`, `self.rcv_wscale`, `self.ecn_enabled`). Used
    /// by both the initial accept-SYN path and the SYN-ACK RTO retransmit
    /// path.
    fn emit_synack_from_state(&mut self) -> Result<bool, TcpError> {
        let opts = TcpOptions {
            mss: Some(self.local_mss),
            // Echo WS only if peer offered it (rcv_wscale was set non-zero
            // in accept_syn_stateful in that case). RFC 7323 §2.2.
            wscale: if self.rcv_wscale > 0 {
                Some(self.rcv_wscale)
            } else {
                None
            },
            ts: if self.ts_enabled {
                Some((self.ts_val(), self.ts_recent))
            } else {
                None
            },
            sack_permitted: self.sack_enabled,
            sack: SackBlocks::EMPTY,
        };
        // RFC 3168 §6.1.1: confirming SYN-ACK carries ECE without CWR.
        let extra_flags = if self.ecn_enabled { flags::ECE } else { 0 };
        self.emit_segment(
            flags::SYN | flags::ACK | extra_flags,
            self.iss,
            self.rcv_nxt,
            &opts,
            &[],
        )
    }

    // ---------------------------------------------------------------------
    // SYN_RCVD — half-open passive state. Adversarial-input hardening.
    //
    // RFC 793 / 9293 §3.10.7.4 prescribes specific behaviour. Highlights
    // and additional defences:
    //
    //   * Off-path SYNs from a different remote: dropped by the 5-tuple
    //     filter in `inject_packet` (we pinned the remote on accept).
    //   * SYN retransmit from the same remote with the same SEQ:
    //     idempotent — re-emit the SYN-ACK. Different SEQ from the same
    //     remote: drop (the peer is misbehaving).
    //   * SYN+ACK: invalid in SYN_RCVD on the listener side — we never
    //     issued an active SYN. Send RST.
    //   * ACK with SEG.ACK ≠ ISS+1 or SEG.SEQ ≠ rcv_nxt: drop or RST.
    //     Critically, this denies blind off-path completion attacks: an
    //     attacker who can't observe our ISS can't forge a valid third
    //     ACK in a 32-bit space, so the listener won't be promoted to
    //     ESTABLISHED on bogus traffic.
    //   * RST: handled by `handle_rst` — must be in receive window,
    //     reverts to LISTEN (or CLOSED) without surfacing an error.
    // ---------------------------------------------------------------------
    fn on_segment_syn_rcvd(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        // SYN+ACK arriving in SYN_RCVD on the passive side is invalid —
        // we did not initiate the connection. RST per RFC 793.
        if seg.has(flags::SYN) && seg.has(flags::ACK) {
            let _ = self.emit_segment(flags::RST, seg.ack, 0, &TcpOptions::NONE, &[])?;
            return Ok(());
        }
        // SYN retransmit: idempotent if SEQ matches our recorded `irs`.
        if seg.has(flags::SYN) {
            if seg.seq == self.irs {
                let _ = self.emit_synack_from_state()?;
                return Ok(());
            }
            // Different-SEQ SYN from the *same* peer: silently drop. This
            // is degenerate behaviour the attacker can't gain from.
            return Ok(());
        }
        // No ACK ⇒ no further useful work; drop.
        if !seg.has(flags::ACK) {
            return Ok(());
        }
        // ACK acceptability — RFC 9293 §3.10.7.4: SND.UNA < SEG.ACK ≤ SND.NXT.
        // Here SND.UNA == ISS, SND.NXT == ISS+1, so the only acceptable ACK
        // value is ISS+1. Anything else gets a RST.
        if seg.ack != self.iss.wrapping_add(1) {
            let _ = self.emit_segment(flags::RST, seg.ack, 0, &TcpOptions::NONE, &[])?;
            return Ok(());
        }
        // SEG.SEQ must equal rcv_nxt for the third ACK (the SYN consumed
        // sequence space, so the next byte is irs+1).
        if !self.in_window(seg.seq, seg.payload.len() as u32) {
            // Out-of-window — drop. The peer will eventually retransmit.
            return Ok(());
        }
        if seg.seq != self.rcv_nxt {
            // In-window but not at rcv_nxt — duplicate / future. Drop;
            // the peer will retransmit when our ACK reaches them.
            return Ok(());
        }

        // Valid third ACK — transition to ESTABLISHED.
        self.snd_una = seg.ack;
        // Third ACK is no longer a SYN segment, so peer's window field is
        // scaled per the negotiated `snd_wscale` (0 if WS wasn't offered).
        self.snd_wnd = self.scale_peer_window(seg.window);
        self.rto_deadline = None;
        self.rtt_probe = None;
        self.syn_rcvd_retries = 0;
        self.state = State::Established;

        // The third ACK may carry payload or even a FIN — let the normal
        // synchronised path handle it. (process_ack will see seg.ack ==
        // snd_una, dup-ACK accounting fires but no fast retransmit since
        // snd_nxt == snd_una; window is updated.)
        self.on_segment_synchronised(seg)
    }

    // ---------------------------------------------------------------------
    // SYN cookies (RFC 4987) — keyed-MAC ISN encoding for stateless LISTEN.
    // ---------------------------------------------------------------------

    /// 32-bit cookie format: top 3 bits encode the peer-MSS index into
    /// [`COOKIE_MSS_TABLE`]; bottom 29 bits are a SipHash-2-4 truncation
    /// of (time_bucket, peer_ip, peer_port, local_ip, local_port,
    /// peer_seq, mss_idx). The MAC is keyed by `self.cookie_secret`.
    /// 29 bits of MAC give an attacker a 1-in-2^29 forgery probability
    /// per attempt, which combined with the 64 s bucket window is
    /// adequate for blind-flood resistance.
    fn compute_cookie(
        &self,
        bucket: u64,
        peer_ip: [u8; 4],
        peer_port: u16,
        mss_idx: u8,
        peer_seq: u32,
    ) -> u32 {
        let mut buf = [0u8; 25];
        let bucket_be = bucket.to_be_bytes();
        let peer_port_be = peer_port.to_be_bytes();
        let local_port_be = self.local.port.to_be_bytes();
        let peer_seq_be = peer_seq.to_be_bytes();
        if let Some(d) = buf.get_mut(0..8) {
            d.copy_from_slice(&bucket_be);
        }
        if let Some(d) = buf.get_mut(8..12) {
            d.copy_from_slice(&peer_ip);
        }
        if let Some(d) = buf.get_mut(12..14) {
            d.copy_from_slice(&peer_port_be);
        }
        if let Some(d) = buf.get_mut(14..18) {
            d.copy_from_slice(&self.local.ip);
        }
        if let Some(d) = buf.get_mut(18..20) {
            d.copy_from_slice(&local_port_be);
        }
        if let Some(d) = buf.get_mut(20..24) {
            d.copy_from_slice(&peer_seq_be);
        }
        if let Some(d) = buf.get_mut(24..25) {
            d.copy_from_slice(&[mss_idx]);
        }
        let mac = siphash24(&self.cookie_secret, &buf);
        let macbits = (mac as u32) & 0x1FFF_FFFF; // 29 bits
        ((mss_idx as u32 & 0x7) << 29) | macbits
    }

    fn on_segment_synchronised(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        // Update peer's TSval (if any) before the acceptability test so that
        // a retransmit of an in-window ACK still refreshes ts_recent.
        if self.ts_enabled {
            if let Some((tsval, _)) = seg.options.ts {
                // Coarse PAWS-lite: only advance ts_recent forward.
                if seq_ge(tsval, self.ts_recent) {
                    self.ts_recent = tsval;
                }
            }
        }

        // RFC 3168 §6.1.2: a CE-marked inbound segment must cause us to
        // echo ECE on subsequent ACKs until the peer responds with CWR.
        // RFC 3168 §6.1.3: a CWR-marked inbound segment clears our
        // CE-sticky state. These checks are gated on ECN being negotiated
        // — middleboxes can spuriously set ECN bits on connections that
        // never opted in, and we must ignore them.
        if self.ecn_enabled {
            if seg.ecn == wire::ecn::CE {
                self.ce_observed = true;
            }
            if seg.has(flags::CWR) {
                self.ce_observed = false;
            }
        }

        // Sequence-number acceptability test (RFC 793 §3.3 / RFC 9293
        // §3.10.7.4 step 1).
        if !self.in_window(seg.seq, seg.payload.len() as u32) {
            // The segment is unacceptable, so none of its payload may be
            // accepted. But an *old duplicate* — one ending at or before
            // RCV.NXT — can still carry a cumulative ACK that advances
            // SND.UNA; that is exactly what a duplicate ACK is (RFC 5681
            // §3.2). In a bidirectional transfer, once both directions rewind
            // SND.NXT below the peer's RCV.NXT after loss, *every* pure ACK is
            // "old" at the peer. Dropping the ACK field wholesale then wedges
            // both senders: each retransmits a fully-received segment forever,
            // never sees its own data acknowledged, so cwnd never reopens.
            // Process the ACK first, then reply with the mandated duplicate
            // ACK. `process_ack` clamps to SND.MAX, so a blind or stale ACK
            // can never acknowledge data we did not send.
            let ends_at_or_before_rcv_nxt =
                seq_le(seg.seq.wrapping_add(seg.payload.len() as u32), self.rcv_nxt);
            if ends_at_or_before_rcv_nxt && seg.has(flags::ACK) {
                self.process_ack(seg)?;
            }
            self.send_pure_ack()?;
            return Ok(());
        }

        let prev_rcv_nxt = self.rcv_nxt;
        let mut filled_gap = false;

        // ---- Process ACK -------------------------------------------------
        if seg.has(flags::ACK) {
            self.process_ack(seg)?;
        }

        // ---- Process payload --------------------------------------------
        // In-order: write directly to the receive ring, then drain any
        // held OOO run that the new bytes may now connect.
        // Out-of-order: buffer in the single-hole reassembly queue (if it
        // abuts the held run) so the sender doesn't have to retransmit
        // the bytes we already received.
        if !seg.payload.is_empty() && self.state.can_recv() {
            if seg.seq == self.rcv_nxt {
                let written = self.recv_ring.write(seg.payload);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(written as u32);
                if written == seg.payload.len() && self.drain_reassembly() > 0 {
                    filled_gap = true;
                }
            } else if seq_gt(seg.seq, self.rcv_nxt) {
                self.accept_oo_segment(seg.seq, seg.payload);
            }
            self.rcv_wnd = self.advertised_window();
        }

        // ---- Process FIN -------------------------------------------------
        if seg.has(flags::FIN) {
            // FIN consumes one sequence number; only honour it if all
            // preceding bytes have been received.
            let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
            if fin_seq == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.advance_state_on_remote_fin();
            }
        }

        // ---- Schedule (or send) ACK -------------------------------------
        let advanced = self.rcv_nxt != prev_rcv_nxt;
        let carried_seq = !seg.payload.is_empty() || seg.has(flags::FIN);
        if advanced {
            // FIN or filled-gap → immediate ACK (RFC 5681 §4.2).
            // Otherwise fall through to delayed-ACK logic.
            if seg.has(flags::FIN) || filled_gap {
                self.send_pure_ack()?;
            } else {
                self.delayed_ack_count = self.delayed_ack_count.saturating_add(1);
                self.pending_ack = true;
                if self.delayed_ack_count >= 2 {
                    self.send_pure_ack()?;
                } else if self.ack_deadline.is_none() {
                    self.ack_deadline = Some(self.now_ms.wrapping_add(DELAYED_ACK_MS));
                }
            }
        } else if carried_seq {
            // In-window segment that consumed sequence space but we couldn't
            // accept it (out-of-order data, FIN before all data, duplicate
            // retransmit). RFC 5681 §3.2 mandates an immediate duplicate ACK.
            self.send_pure_ack()?;
        }

        // ---- Push more data, if cwnd / window allow ---------------------
        self.maybe_send_data()?;
        Ok(())
    }

    fn advance_state_on_remote_fin(&mut self) {
        self.state = match self.state {
            State::Established => State::CloseWait,
            State::FinWait1 => State::Closing,
            State::FinWait2 => {
                self.time_wait_deadline = Some(self.now_ms.wrapping_add(TIME_WAIT_MS));
                State::TimeWait
            }
            other => other,
        };
    }

    /// Buffer an out-of-order in-window segment in the multi-hole
    /// reassembler. Returns `true` if any bytes were absorbed.
    fn accept_oo_segment(&mut self, seq: u32, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }
        // Must be strictly after rcv_nxt; the in-order path handles equality.
        if !seq_gt(seq, self.rcv_nxt) {
            return false;
        }
        self.reasm.insert(seq, payload, self.rcv_nxt) > 0
    }

    /// Drain any contiguous OOO run abutting `rcv_nxt` into the receive
    /// ring. Returns total bytes drained (may chain across multiple
    /// reassembly slots if merging revealed a long run). Stops if the
    /// recv_ring fills.
    fn drain_reassembly(&mut self) -> usize {
        let mut total = 0usize;
        let mut drain_guard = 0u32;
        while let Some((slot_idx, slot_start, slot_len)) = self.reasm.ready_slot(self.rcv_nxt) {
            // At most `MAX_HOLES` distinct slots can be drained; each
            // iteration either fully commits one slot (and frees it) or
            // breaks on a full ring. The budget guards against a future
            // `ready_slot` that could keep returning a slot the loop
            // doesn't make progress on.
            if crate::loop_budget_exhausted(
                &mut drain_guard,
                crate::reassembly::MAX_HOLES as u32 + 2,
                "drain_reassembly",
            ) {
                break;
            }
            // Sanity: the ready_slot should match rcv_nxt exactly.
            if slot_start != self.rcv_nxt {
                break;
            }
            let bytes = self.reasm.slot_bytes(slot_idx);
            let to_write = bytes.get(..slot_len).unwrap_or(bytes);
            let written = self.recv_ring.write(to_write);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(written as u32);
            self.reasm.commit_drain(slot_idx, written);
            total += written;
            // Break on a full ring (`written < slot_len`) OR on a degenerate
            // zero-length slot (`written == 0` with `slot_len == 0`): the
            // latter would otherwise leave `rcv_nxt` unchanged and have
            // `ready_slot` return the same slot forever — an infinite loop.
            if written == 0 || written < slot_len {
                break; // ring full or degenerate empty slot
            }
        }
        if total > 0 {
            self.rcv_wnd = self.advertised_window();
        }
        total
    }

    /// Bytes we can advertise as available. Held OOO bytes already consumed
    /// receive-buffer headroom, so subtract them from the ring's free space.
    #[inline]
    fn advertised_window(&self) -> u32 {
        let free = self.recv_ring.free();
        free.saturating_sub(self.reasm.held_bytes()) as u32
    }

    fn process_ack(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        let ack = seg.ack;

        // ACK of data we never sent → bare ACK and drop. Compare against
        // `snd_max` (high-water mark of sequence numbers we've put on the
        // wire), **not** the live `snd_nxt`: an RTO or SACK fast-retransmit
        // rewinds `snd_nxt` to `snd_una`, but segments emitted before the
        // rewind may still arrive at the peer and be cumulatively ACKed.
        // Comparing against `snd_nxt` here was a real wedge — the post-
        // recovery cumulative ACK landed beyond it and got rejected as a
        // phantom, leaving `snd_una` frozen for the rest of the connection.
        if seq_gt(ack, self.snd_max) {
            self.send_pure_ack()?;
            return Ok(());
        }
        // Proof of life: any acceptable ACK (even a duplicate / zero-window
        // probe response) shows the peer is still there, so the RFC 9293
        // §3.8.3 R2 "vanished peer" budget starts over. On the symmetric paths
        // this stack targets (WireGuard tunnels), a total absence of ACKs is
        // the only reliable signal that the peer is truly gone — a peer that
        // is merely flow-controlled keeps answering, and must not be aborted.
        self.rtx_count = 0;

        // RFC 3168 §6.1.2: an ECE-marked ACK is a congestion signal. Enter
        // PRR recovery (same response as a 3-dup-ACK / SACK trigger) and
        // arm CWR on the next new-data segment. Gate on `!in_recovery` to
        // avoid stacking multiple ECE-driven cwnd reductions within a
        // single recovery episode.
        if self.ecn_enabled
            && seg.has(flags::ECE)
            && !self.cc.in_recovery()
            && seq_gt(self.snd_nxt, self.snd_una)
        {
            let flight = self.snd_nxt.wrapping_sub(self.snd_una);
            self.cc.enter_recovery(flight, self.snd_max);
            self.send_cwr_pending = true;
        }

        // ---- Absorb inbound SACK blocks (regardless of dup/advancing) ----
        // RFC 6675 §5: SACK information on EVERY acceptable ACK updates the
        // scoreboard. The scoreboard's add_range method clips invalid /
        // out-of-window blocks defensively.
        //
        // Compute newly-SACKed bytes BEFORE inserting into the scoreboard,
        // so RACK only fires on fresh delivery evidence and not on repeated
        // SACK blocks (RFC 8985: stale SACKs must not bump RACK markers).
        let mut newly_sacked: u32 = 0;
        let mut latest_sack_send_ts: u64 = 0;
        let mut latest_sack_end_seq: u32 = 0;
        if self.sack_enabled {
            for (l, r) in seg.options.sack.as_slice().iter().copied() {
                let new_bytes =
                    self.sack_scoreboard
                        .bytes_newly_covered(l, r, self.snd_una, self.snd_max);
                if new_bytes > 0 {
                    newly_sacked = newly_sacked.saturating_add(new_bytes);
                    // RACK marker: among the newly-SACKed bytes, find the
                    // send_queue entry that contains the right edge.
                    // That's the segment "delivered" by this SACK block.
                    let probe_seq = r.wrapping_sub(1);
                    if let Some(entry) = self.send_queue.find_latest_covering(probe_seq) {
                        if entry.send_ts_ms > latest_sack_send_ts
                            || (entry.send_ts_ms == latest_sack_send_ts
                                && seq_gt(entry.seq_end, latest_sack_end_seq))
                        {
                            latest_sack_send_ts = entry.send_ts_ms;
                            latest_sack_end_seq = entry.seq_end;
                        }
                    }
                }
                self.sack_scoreboard
                    .add_range(l, r, self.snd_una, self.snd_max);
            }
            if latest_sack_send_ts > 0 {
                self.rack
                    .update_on_delivery(latest_sack_send_ts, latest_sack_end_seq, self.now_ms);
            }
        }

        if seq_le(ack, self.snd_una) {
            // Duplicate ACK regime. Two distinct fast-retransmit triggers
            // may apply, both gated on `ack == snd_una` and an unchanged
            // peer window:
            //
            // 1. **RFC 5681 §3.2 dup-ACK** — pure ACK (no payload, no FIN),
            //    counted on `cc.on_dup_ack`. This requires three of these
            //    to fire. The empty-payload requirement is essential: in
            //    bidirectional bulk, the peer's piggybacked ACKs naturally
            //    sit at our static `snd_una` between RTTs (peer outpaces
            //    our ACK schedule), and counting those would trigger a
            //    spurious fast-retransmit and collapse cwnd.
            //
            // 2. **RFC 2018 / RFC 6675 SACK** — any ACK (pure OR
            //    piggybacked) that carries a SACK block is authoritative
            //    evidence that data above `snd_una` was received, so a
            //    hole exists. We enter recovery on the first SACK-bearing
            //    ACK (more aggressive than RFC 6675's strict IsLost
            //    trigger). `cc.in_recovery()` then guards against
            //    re-entering until the current recovery episode exits.
            //
            // The window-unchanged condition is implicitly enforced by
            // `update_send_window` happening after this branch returns;
            // a window update by itself does not count as a dup-ACK.
            if ack == self.snd_una
                && seq_gt(self.snd_max, self.snd_una)
                && self.scale_peer_window(seg.window) == self.snd_wnd
                && !self.cc.in_recovery()
            {
                let sack_trigger = self.sack_enabled && !seg.options.sack.is_empty();
                let pure_dup = seg.payload.is_empty() && !seg.has(flags::FIN);
                let trigger = if sack_trigger {
                    true
                } else if pure_dup {
                    self.cc.on_dup_ack()
                } else {
                    false
                };
                if trigger {
                    // RFC 6937 PRR + RFC 6675 selective retransmit:
                    // * enter_recovery captures FULL flight (snd_max -
                    //   snd_una) so ssthresh halves the real in-flight.
                    // * Do NOT rewind snd_nxt — the scoreboard-driven
                    //   NextSeg() in maybe_send_data finds the right
                    //   sequence to retransmit instead.
                    let flight = self.snd_max.wrapping_sub(self.snd_una);
                    self.cc.enter_recovery(flight, self.snd_max);
                    self.rxt_seq = self.snd_una;
                    self.rxt_unacked = 0;
                    if let Some(p) = self.rtt_probe.as_mut() {
                        p.valid = false;
                    }
                    self.arm_rto_for(self.snd_una);
                }
            }
            // ---- RACK loss detection + PRR credit on dup-ACK -----------
            // Even on duplicate ACKs, SACK-bearing ones deliver new bytes
            // that PRR must credit (otherwise snd_credit can stall mid-
            // recovery) and that RACK can use for time-based loss
            // detection independent of dup-ACK / scoreboard triggers.
            if newly_sacked > 0 {
                let outstanding = self.snd_max.wrapping_sub(self.snd_una);
                let sacked = self.sack_scoreboard.sacked_bytes();
                let pipe = outstanding
                    .saturating_sub(sacked)
                    .saturating_add(self.rxt_unacked);
                self.cc.on_ack_in_recovery(newly_sacked, pipe);
            }
            self.run_rack_scan();
            // Even duplicate ACKs may carry a window update.
            self.update_send_window(seg.window);
            return Ok(());
        }

        let prev_una = self.snd_una;
        let acked = ack.wrapping_sub(prev_una);
        // RFC 6937: cwnd inflation is suppressed during recovery. The PRR
        // budget (snd_credit) takes over; on recovery exit, cwnd is reset
        // to ssthresh. So `cc.on_ack` is intentionally a no-op while
        // `cc.in_recovery()` is true.
        self.cc.on_ack(acked);

        // FIN seq accounting: if this ACK is the one that crosses fin_seq,
        // it acknowledges a synthetic byte (the FIN) — don't drain it from
        // the send ring (it was never put there).
        let mut payload_acked = acked;
        if self.fin_sent
            && seq_le(prev_una, self.fin_seq)
            && seq_gt(ack, self.fin_seq)
            && payload_acked > 0
        {
            payload_acked = payload_acked.saturating_sub(1);
        }
        self.send_ring.consume(payload_acked as usize);
        self.snd_una = ack;
        // Real forward progress re-arms the no-progress USER TIMEOUT: a fresh
        // window if work remains, disarmed once everything is acknowledged.
        // (R2's `rtx_count` was already reset above by this acceptable ACK;
        // the USER TIMEOUT deliberately keys on *advancement*, not mere
        // liveness, so a stalling peer can't keep it alive.)
        if self.user_timeout_ms != 0 {
            let has_work = self.snd_una != self.snd_max || !self.send_ring.is_empty();
            self.user_timeout_deadline = if has_work {
                Some(self.now_ms.wrapping_add(self.user_timeout_ms as u64))
            } else {
                None
            };
        }
        // If a prior RTO rewound `snd_nxt` to `snd_una`, but the peer's
        // first cumulative ACK after recovery jumps over the rewound
        // point (because the peer had buffered our pre-rewind segments
        // out-of-order), our `snd_nxt` could now sit **behind** the new
        // `snd_una`. Pull it forward; the bytes between old `snd_nxt`
        // and `snd_una` are evidently already on the wire and
        // acknowledged, so we shouldn't re-emit them.
        if seq_gt(self.snd_una, self.snd_nxt) {
            self.snd_nxt = self.snd_una;
        }
        // ---- Scoreboard cleanup on cumulative ACK -----------------------
        self.sack_scoreboard.prune_below(self.snd_una);

        // Also use cumulative ACK as a RACK delivery signal: the segment
        // whose end_seq matches the new snd_una was just delivered.
        if let Some(entry) = self
            .send_queue
            .find_latest_covering(self.snd_una.wrapping_sub(1))
        {
            self.rack
                .update_on_delivery(entry.send_ts_ms, entry.seq_end, self.now_ms);
        }
        // Drop send_queue entries fully covered by cumulative ACK + SACK.
        self.send_queue.prune(self.snd_una, &self.sack_scoreboard);
        // Drop rack_lost_queue entries that snd_una has overtaken.
        self.drop_acked_rack_lost();

        // ---- PRR accounting + retransmit cursor maintenance -------------
        // RFC 6675 retransmits are at the bottom of in-flight, so cumulative
        // bytes are consumed by them first. Subtract the overlap.
        if self.rxt_unacked > 0 {
            let drain = core::cmp::min(acked, self.rxt_unacked);
            self.rxt_unacked = self.rxt_unacked.saturating_sub(drain);
        }
        // Pull rxt_seq forward if snd_una outran it.
        if seq_gt(self.snd_una, self.rxt_seq) {
            self.rxt_seq = self.snd_una;
        }
        // ---- PRR per-ACK update / recovery exit -------------------------
        // Order matters: update DeliveredData *before* exit check so the
        // ACK that crosses recovery_point still credits prr_delivered.
        // Pipe (RFC 6675 §6.1, simplified):
        //   pipe = (snd_max - snd_una) - sacked_bytes + rxt_unacked
        // We use snd_max (not snd_nxt) because retransmits don't advance
        // snd_nxt; snd_max is the true high-water of bytes ever sent.
        let outstanding = self.snd_max.wrapping_sub(self.snd_una);
        let sacked = self.sack_scoreboard.sacked_bytes();
        let pipe = outstanding
            .saturating_sub(sacked)
            .saturating_add(self.rxt_unacked);
        // PRR's `delivered_data` is the cumulative new acked bytes for
        // this ACK. (A stricter accounting would also add newly-SACKed
        // bytes, but we approximate.)
        self.cc.on_ack_in_recovery(acked, pipe);
        if self.cc.check_exit_recovery(self.snd_una) {
            // Recovery is over — clean up scoreboard and rxt state.
            self.sack_scoreboard.clear();
            self.rxt_unacked = 0;
            self.rack_lost_queue.clear();
        }

        // RACK loss detection on cumulative ACK: may discover holes the
        // SACK info just confirmed are lost.
        self.run_rack_scan();

        // TLP single-shot reset: a fresh ACK that advances snd_una clears
        // the "TLP already fired" guard so we can probe again on the next
        // in-flight epoch.
        if acked > 0 {
            self.tlp_fired = false;
        }
        self.tlp_deadline = None; // will be re-armed on next emit if needed

        // RTT update: prefer Timestamps echo; fall back to per-RTO probe.
        if self.ts_enabled {
            if let Some((_, tsecr)) = seg.options.ts {
                if tsecr != 0 {
                    self.update_rtt_from_ts_echo(tsecr);
                }
            }
        } else {
            self.process_ack_rtt(ack);
        }

        if self.snd_una == self.snd_nxt {
            self.rto_deadline = None;
            self.rtt_probe = None;
        } else {
            self.arm_rto_for(self.snd_nxt);
        }

        // FIN ACK transitions.
        if self.fin_sent && self.snd_una == self.fin_seq.wrapping_add(1) {
            self.state = match self.state {
                State::FinWait1 => State::FinWait2,
                State::Closing => {
                    self.time_wait_deadline = Some(self.now_ms.wrapping_add(TIME_WAIT_MS));
                    State::TimeWait
                }
                State::LastAck => State::Closed,
                other => other,
            };
        }

        self.update_send_window(seg.window);
        Ok(())
    }

    fn update_send_window(&mut self, window: u16) {
        self.snd_wnd = self.scale_peer_window(window);
        if self.snd_wnd > 0 {
            // Window opened — cancel persist timer.
            self.persist_deadline = None;
            self.persist_backoff_ms = 0;
        }
    }

    /// Drain as many outbound segments as the egress ring can hold,
    /// subject to cwnd / peer-window / PRR-credit constraints. Called
    /// from `tick`, `close`, and `on_segment_synchronised`.
    ///
    /// The loop terminates when either:
    /// * the egress ring fills up (host must drain before more can be
    ///   queued), or
    /// * `maybe_send_one` reports no further segment is eligible.
    fn maybe_send_data(&mut self) -> Result<(), TcpError> {
        if !matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::Closing
                | State::LastAck
        ) {
            return Ok(());
        }
        let mut emit_guard = 0u32;
        while !self.tx_ring.is_full() {
            // The loop terminates when the egress ring fills or
            // `maybe_send_one` reports nothing eligible. Each `Ok(true)`
            // pushes exactly one segment into `tx_ring`, so correct
            // operation needs at most `TX_RING_CAP` iterations; the budget
            // is a backstop against a `maybe_send_one` that ever returns
            // `Ok(true)` without consuming ring space.
            if crate::loop_budget_exhausted(
                &mut emit_guard,
                crate::tx_ring::TX_RING_CAP as u32 + 2,
                "maybe_send_data",
            ) {
                break;
            }
            if !self.maybe_send_one()? {
                break;
            }
        }
        Ok(())
    }

    /// Attempt to emit ONE segment in priority order. Returns:
    /// * `Ok(true)`  — a segment was queued; caller should re-enter.
    /// * `Ok(false)` — no eligible segment (cwnd/PRR/window/data
    ///   constraints, or the ring filled mid-emit); caller should
    ///   stop looping.
    /// * `Err(_)` on a hard fault.
    fn maybe_send_one(&mut self) -> Result<bool, TcpError> {
        let mss_payload = self.effective_payload_mss() as u32;

        // ---- PRR ACK-clock deadlock guard (RFC 6675 §5) -----------------
        // PRR's `snd_credit` paces sends during recovery, but it is only
        // replenished by incoming ACKs. If the pipe has fully drained
        // (`flight == 0`, i.e. `snd_nxt == snd_una`) while credit is `0`,
        // recovery can never make progress: the lost segment at `snd_una`
        // can't be retransmitted (the RFC 6675 retransmit is credit-clamped
        // to 0 bytes), so no ACK arrives, so credit is never replenished —
        // a permanent stall with data buffered and the window wide open.
        // Exit recovery so the standard path re-sends `snd_una` and restarts
        // the ACK clock; `cwnd` is already reduced to `ssthresh`, so the
        // congestion response is preserved.
        if self.cc.in_recovery() && self.snd_nxt == self.snd_una && self.cc.snd_credit() == 0 {
            self.cc.force_exit_recovery();
        }

        // ---- Priority 0: RACK-marked-lost retransmits -------------------
        // RACK detects loss via time + later-delivery evidence; results
        // queue into `rack_lost_queue` sorted lowest-seq first. Drain
        // one entry per call (the caller will re-enter on the next tick
        // if more remain), clipped to current snd_una/snd_max and
        // un-SACKed bytes only.
        if !self.rack_lost_queue.is_empty() && self.cc.in_recovery() {
            let credit = self.cc.snd_credit();
            if let Some((seq, end)) = self.rack_lost_queue.take_lowest() {
                // Clip to [snd_una, snd_max).
                let lo = if seq_lt(seq, self.snd_una) {
                    self.snd_una
                } else {
                    seq
                };
                let hi = if seq_gt(end, self.snd_max) {
                    self.snd_max
                } else {
                    end
                };
                if seq_lt(lo, hi) {
                    // Find the first un-SACKed sub-range within [lo, hi).
                    let (sub_lo, sub_hi) = self
                        .sack_scoreboard
                        .first_unsacked_subrange(lo, hi)
                        .unwrap_or((lo, hi));
                    let len = sub_hi.wrapping_sub(sub_lo);
                    let bytes = core::cmp::min(len, core::cmp::min(credit, mss_payload)) as usize;
                    if bytes > 0 {
                        return self.emit_data_at(sub_lo, bytes);
                    }
                }
            }
        }

        // ---- Priority 1: RFC 6675 selective retransmit during recovery ----
        //
        // If we're in fast recovery, send the next lost segment. Two phases:
        //
        // 1. **First retransmit**: on recovery entry, unconditionally
        //    retransmit the segment at snd_una (the "obvious hole" — peer
        //    SACKed data above it). Detected by rxt_unacked == 0 and
        //    rxt_seq == snd_una. Skips the IsLost check, matching the
        //    Linux / RFC 6675 §5 "first retransmit is at HighACK+1"
        //    convention.
        //
        // 2. **Subsequent retransmits**: NextSeg identifies further holes
        //    that satisfy IsLost (≥ DupThresh*MSS sacked above them).
        //
        // This path does NOT honour the (snd_nxt - snd_una) >= cwnd gate
        // — that gate would block retransmits while cwnd is "full" of
        // in-flight data the peer can't ACK because of the hole. PRR's
        // snd_credit is the only flow control here.
        if self.cc.in_recovery() {
            let credit = self.cc.snd_credit();
            // Phase 1: initial retransmit at snd_una if not yet done.
            let initial_due = self.rxt_unacked == 0
                && self.rxt_seq == self.snd_una
                && seq_gt(self.snd_max, self.snd_una);
            if initial_due {
                let outstanding = self.snd_max.wrapping_sub(self.snd_una);
                let bytes =
                    core::cmp::min(outstanding, core::cmp::min(credit, mss_payload)) as usize;
                if bytes > 0 {
                    return self.emit_data_at(self.snd_una, bytes);
                }
            } else if self.sack_enabled {
                // Phase 2: NextSeg-driven selective retransmit.
                if let Some((rxt_seq, rxt_len)) =
                    self.sack_scoreboard
                        .next_seg(self.rxt_seq, self.snd_max, mss_payload)
                {
                    let bytes =
                        core::cmp::min(rxt_len, core::cmp::min(credit, mss_payload)) as usize;
                    if bytes > 0 {
                        return self.emit_data_at(rxt_seq, bytes);
                    }
                }
            }
        }

        let flight = self.snd_nxt.wrapping_sub(self.snd_una);
        let allowed = self.cc.allowed(self.snd_wnd);

        // A FIN is a pure control segment: it occupies one sequence number but
        // carries no data, so — unlike a data segment — it owes no receive
        // window and is bound by neither the peer's advertised window nor
        // cwnd / PRR credit. Emit it here, *before* the window gates below.
        // Otherwise a simultaneous close in which the peer's window is
        // momentarily 0 (and never refreshed, because the peer has nothing
        // left to send and so emits no window update) wedges forever in
        // FIN_WAIT_2 / CLOSING with the FIN never reaching the wire. This only
        // fires once the send ring is fully drained, so it never preempts data
        // or a retransmit.
        if self.try_emit_fin()? {
            return Ok(true);
        }

        // ---- Zero-window: arm persist timer instead of sending ----------
        if self.snd_wnd == 0 {
            let unsent = (self.send_ring.len() as u32).saturating_sub(flight);
            if unsent > 0 && self.persist_deadline.is_none() {
                self.persist_backoff_ms = self.rto_ms;
                self.persist_deadline =
                    Some(self.now_ms.wrapping_add(self.persist_backoff_ms as u64));
            }
            return Ok(false);
        }

        if flight >= allowed {
            return Ok(false);
        }
        // Per-segment send budget = min(cwnd-flight, peer_wnd-flight,
        //                               PRR snd_credit, unsent, mss).
        // Outside recovery, snd_credit is u32::MAX (a no-op clamp).
        let window = core::cmp::min(allowed - flight, self.cc.snd_credit());
        let unsent = (self.send_ring.len() as u32).saturating_sub(flight);
        let payload_bytes = core::cmp::min(window, core::cmp::min(unsent, mss_payload)) as usize;

        if payload_bytes > 0 {
            // Stack-local scratch sized for the worst case (no TS).
            let mut tmp = [0u8; MSS as usize];
            let slice = tmp.get_mut(..payload_bytes).ok_or(TcpError::Overflow)?;
            let copied = self.send_ring.peek_at(flight as usize, slice);
            if copied != payload_bytes {
                return Err(TcpError::Overflow);
            }
            let seq = self.snd_nxt;
            let payload_slice = tmp.get(..payload_bytes).ok_or(TcpError::Overflow)?;
            let opts = self.data_options();
            let queued = self.emit_segment(
                flags::ACK | flags::PSH,
                seq,
                self.rcv_nxt,
                &opts,
                payload_slice,
            )?;
            if !queued {
                return Ok(false);
            }
            self.snd_nxt = self.snd_nxt.wrapping_add(payload_bytes as u32);
            self.bump_snd_max();
            // Account for PRR send credit consumption (no-op outside recovery).
            self.cc.on_send(payload_bytes as u32);
            // RACK: record this transmission so future ACKs can derive its
            // send timestamp for time-based loss detection.
            self.send_queue
                .push(seq, payload_bytes as u32, self.now_ms, false);
            // Piggybacked ACK clears delayed-ACK state.
            self.pending_ack = false;
            self.delayed_ack_count = 0;
            self.ack_deadline = None;
            if self.rto_deadline.is_none() {
                self.arm_rto_for(self.snd_nxt);
            }
            // TLP: arm whenever in-flight > 0 after this emission.
            self.arm_tlp();
            return Ok(true);
        }

        // The closing FIN is a pure control segment handled up front by
        // `try_emit_fin` (before the window gates), so nothing remains here.
        Ok(false)
    }

    /// Emit (or retransmit) the connection-closing FIN if one is owed and all
    /// buffered data has already been sent. A pure FIN carries no payload, so
    /// — unlike a data segment — it is bound by neither the peer's receive
    /// window nor cwnd / PRR credit and must go out even into a zero window.
    ///
    /// The FIN occupies a single sequence number immediately past all buffered
    /// data. Gating on `snd_nxt == fin_at` (rather than `!fin_sent`) makes one
    /// path cover BOTH the first emission and a retransmission after an RTO
    /// rewound `snd_nxt` back onto the FIN's sequence — without it, a FIN that
    /// is the sole outstanding segment would never be resent (the RTO path
    /// only re-emits SYN/SYN-ACK), stalling the close forever. A FIN still in
    /// flight has `snd_nxt == fin_seq + 1`, so it is never spuriously resent;
    /// an ACKed FIN has `snd_una > fin_seq`, so `fin_at` no longer matches.
    fn try_emit_fin(&mut self) -> Result<bool, TcpError> {
        let fin_at = if self.fin_sent {
            self.fin_seq
        } else {
            self.snd_nxt
        };
        let need_fin = matches!(
            self.state,
            State::FinWait1 | State::Closing | State::LastAck
        ) && self.send_ring.is_empty()
            && self.snd_nxt == fin_at;
        if !need_fin {
            return Ok(false);
        }
        let opts = self.data_options();
        let queued = self.emit_segment(
            flags::FIN | flags::ACK,
            self.snd_nxt,
            self.rcv_nxt,
            &opts,
            &[],
        )?;
        if !queued {
            return Ok(false);
        }
        if !self.fin_sent {
            // First emission only: pin the FIN's sequence and charge one byte
            // of (PRR) send credit. Retransmits must not re-charge or re-pin.
            self.fin_seq = self.snd_nxt;
            self.cc.on_send(1);
            self.fin_sent = true;
        }
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.bump_snd_max();
        self.pending_ack = false;
        self.delayed_ack_count = 0;
        self.ack_deadline = None;
        if self.rto_deadline.is_none() {
            self.arm_rto_for(self.snd_nxt);
        }
        Ok(true)
    }

    /// Emit `bytes` of data from the send ring starting at sequence `seq`.
    /// Used by the RFC 6675 selective-retransmit path. The bytes lie at
    /// offset `(seq - snd_una)` from the head of the send ring. Updates
    /// `rxt_seq`, `rxt_unacked`, and the PRR send credit; does NOT advance
    /// `snd_nxt` (retransmits never do).
    ///
    /// Returns `Ok(true)` if the segment was queued, `Ok(false)` if the
    /// egress ring is full (caller must back off; bookkeeping is not
    /// advanced in that case).
    fn emit_data_at(&mut self, seq: u32, bytes: usize) -> Result<bool, TcpError> {
        let offset = seq.wrapping_sub(self.snd_una) as usize;
        // Never read past the buffered data. Retransmit byte counts are
        // derived from `snd_max`-relative spans (e.g. the RFC 6675 initial
        // retransmit uses `snd_max - snd_una`), and `snd_max` counts the
        // phantom FIN sequence that the send ring does not hold. When the
        // FIN is the only thing outstanding the ring is empty, so a caller
        // can ask to retransmit one byte with nothing buffered — or, after
        // a wrapped offset (seq < snd_una), a byte far past the head. Clamp
        // to what the ring actually holds; retransmitting unbuffered bytes
        // (the FIN included — it is re-sent as a FIN, not as data) is never
        // correct. Returning `Ok(false)` here leaves the caller's
        // bookkeeping untouched, exactly as an egress-ring-full backoff
        // would. This is the single choke point that makes the whole class
        // of "sequence math used as a buffer offset" faults non-fatal.
        let bytes = core::cmp::min(bytes, self.send_ring.len().saturating_sub(offset));
        if bytes == 0 {
            return Ok(false);
        }
        let mut tmp = [0u8; MSS as usize];
        let slice = tmp.get_mut(..bytes).ok_or(TcpError::Overflow)?;
        let copied = self.send_ring.peek_at(offset, slice);
        if copied != bytes {
            return Err(TcpError::Overflow);
        }
        let payload_slice = tmp.get(..bytes).ok_or(TcpError::Overflow)?;
        let opts = self.data_options();
        let queued = self.emit_segment(
            flags::ACK | flags::PSH,
            seq,
            self.rcv_nxt,
            &opts,
            payload_slice,
        )?;
        if !queued {
            return Ok(false);
        }
        // Account: PRR snd_credit, rxt_unacked, and the rxt cursor.
        self.cc.on_send(bytes as u32);
        self.rxt_unacked = self.rxt_unacked.saturating_add(bytes as u32);
        // Only advance rxt_seq when the retransmit is at or above the
        // cursor — RACK may queue lower-seq retransmits that NextSeg
        // still needs to revisit.
        let end = seq.wrapping_add(bytes as u32);
        if seq_ge(seq, self.rxt_seq) {
            self.rxt_seq = end;
        }
        // RACK bookkeeping: every transmission goes into the send_queue
        // so RACK can later judge "was this segment sent long ago?"
        self.send_queue.push(seq, bytes as u32, self.now_ms, true);
        // Piggybacked ACK clears delayed-ACK state.
        self.pending_ack = false;
        self.delayed_ack_count = 0;
        self.ack_deadline = None;
        if self.rto_deadline.is_none() {
            self.arm_rto_for(self.snd_max);
        }
        // TLP: re-arm whenever in-flight > 0 after this emission.
        self.arm_tlp();
        Ok(true)
    }

    // ---------------------------------------------------------------------
    // RACK-TLP helpers (RFC 8985)
    // ---------------------------------------------------------------------

    /// Arm the TLP timer at `now + max(2*SRTT, TLP_MIN_PTO_MS)` iff:
    ///  * there's data in flight,
    ///  * TLP hasn't already fired this in-flight epoch,
    ///  * the peer window is non-zero (persist timer is the right tool
    ///    for zero-window probing, not TLP).
    fn arm_tlp(&mut self) {
        if self.tlp_fired {
            return;
        }
        if seq_le(self.snd_max, self.snd_una) {
            return;
        }
        if self.snd_wnd == 0 {
            return;
        }
        let srtt = self.srtt_ms.max(1) as u64;
        let pto = (2 * srtt).max(TLP_MIN_PTO_MS);
        self.tlp_deadline = Some(self.now_ms.wrapping_add(pto));
    }

    /// Run RACK loss detection against the current send_queue. Newly
    /// lost ranges are inserted into `rack_lost_queue`; the soonest
    /// reorder deadline (if any) is recorded in `rack_deadline` so
    /// `tick()` can re-run the scan when wall-clock advances enough.
    ///
    /// Also: the first RACK-detected loss enters PRR recovery exactly
    /// like a SACK trigger would. This is what gives RACK its main win
    /// on lossy-with-reordering paths.
    fn run_rack_scan(&mut self) {
        // Refresh reo_wnd from current SRTT estimate.
        if self.srtt_ms > 0 {
            self.rack.set_reo_wnd_from_srtt(self.srtt_ms);
        }
        let scan = crate::rack::detect_lost(&self.rack, &self.send_queue, self.now_ms);

        // Enter recovery on first RACK-detected loss, if not already.
        if !scan.lost.is_empty() && !self.cc.in_recovery() && seq_gt(self.snd_max, self.snd_una) {
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            self.cc.enter_recovery(flight, self.snd_max);
            self.rxt_seq = self.snd_una;
            self.rxt_unacked = 0;
            if let Some(p) = self.rtt_probe.as_mut() {
                p.valid = false;
            }
            self.arm_rto_for(self.snd_una);
        }

        // Queue lost ranges (sorted lowest-first inside the queue).
        let una = self.snd_una;
        for (l, r) in scan.lost.as_slice().iter().copied() {
            self.rack_lost_queue.insert_sorted(l, r, una);
        }

        // Re-arm reorder timer if any entries are eligible-but-not-old-enough.
        self.rack_deadline = scan.next_deadline;
    }

    /// Drop entries in rack_lost_queue that snd_una has overtaken.
    fn drop_acked_rack_lost(&mut self) {
        let una = self.snd_una;
        let mut new_q = RackLostQueue::new();
        for k in 0..self.rack_lost_queue.len {
            let r = match self.rack_lost_queue.ranges.get(k) {
                Some(r) => *r,
                None => continue,
            };
            if seq_le(r.1, una) {
                continue; // fully ACKed
            }
            // Clip left edge to snd_una.
            let lo = if seq_lt(r.0, una) { una } else { r.0 };
            new_q.insert_sorted(lo, r.1, una);
        }
        self.rack_lost_queue = new_q;
    }

    /// Fire a TLP probe: retransmit the highest-seq un-SACKed segment
    /// currently in flight. If no such segment exists (everything is
    /// SACKed or already cumulative-ACKed), the TLP is a no-op — the
    /// next ACK will tell us so. Sets `tlp_fired` so we don't probe
    /// again in this in-flight epoch.
    fn fire_tlp_probe(&mut self) -> Result<(), TcpError> {
        self.tlp_deadline = None;
        if self.tx_ring.is_full() {
            return Ok(()); // host hasn't drained — let RTO handle it
        }
        let entry = match self.send_queue.highest_unsacked(&self.sack_scoreboard) {
            Some(e) => e,
            None => {
                self.tlp_fired = true;
                return Ok(());
            }
        };
        // Clamp the probe to the still-unacked window. `prune` deliberately
        // keeps partially cumulative-ACKed entries whole (RACK needs the
        // original send-ts for the unacked tail), so `seq_start` can sit
        // below `snd_una`. Probing from that raw `seq_start` would make
        // `emit_data_at` compute a wrapped offset below the send-ring head
        // and trip its overflow guard (`copied != bytes`), surfacing a
        // spurious `Overflow` from `tcp_tick`. Probe `[max(seq_start,
        // snd_una), seq_end)` instead — a valid tail probe in every case.
        let start = if seq_lt(entry.seq_start, self.snd_una) {
            self.snd_una
        } else {
            entry.seq_start
        };
        if seq_le(entry.seq_end, start) {
            // Nothing unacked remains in this entry (fully ACKed since the
            // last prune); the probe is spent for this in-flight epoch.
            self.tlp_fired = true;
            return Ok(());
        }
        let len = entry.seq_end.wrapping_sub(start);
        let mss_payload = self.effective_payload_mss() as u32;
        let bytes = core::cmp::min(len, mss_payload) as usize;
        if bytes == 0 {
            self.tlp_fired = true;
            return Ok(());
        }
        // Probe payload mirrors the original segment's bytes. Only flip
        // `tlp_fired` if the probe was actually queued — otherwise the
        // next tick should retry.
        if self.emit_data_at(start, bytes)? {
            self.tlp_fired = true;
        }
        // RTO must remain armed (TLP is a probe, not a replacement for
        // RTO). emit_data_at already calls arm_rto_for if needed.
        Ok(())
    }

    fn check_persist(&mut self) -> Result<(), TcpError> {
        let deadline = match self.persist_deadline {
            Some(d) => d,
            None => return Ok(()),
        };
        if self.now_ms < deadline || self.tx_ring.is_full() {
            return Ok(());
        }
        // Probe with one byte beyond snd_una if we have unsent data.
        let flight = self.snd_nxt.wrapping_sub(self.snd_una);
        let unsent = (self.send_ring.len() as u32).saturating_sub(flight);
        if unsent > 0 {
            let mut byte = [0u8; 1];
            let off = flight as usize;
            let copied = self.send_ring.peek_at(off, &mut byte);
            if copied != 1 {
                return Err(TcpError::Overflow);
            }
            let seq = self.snd_nxt;
            let opts = self.data_options();
            let queued =
                self.emit_segment(flags::ACK | flags::PSH, seq, self.rcv_nxt, &opts, &byte)?;
            if queued {
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.bump_snd_max();
                if self.rto_deadline.is_none() {
                    self.arm_rto_for(self.snd_nxt);
                }
            }
        }
        // Exponential back-off, capped at RTO_MAX_MS.
        let next = self.persist_backoff_ms.saturating_mul(2);
        self.persist_backoff_ms = next.clamp(RTO_MIN_MS, RTO_MAX_MS);
        self.persist_deadline = Some(self.now_ms.wrapping_add(self.persist_backoff_ms as u64));
        Ok(())
    }

    /// RFC 9293 §3.8.4 keepalive: probe an *idle* ESTABLISHED connection to
    /// discover a vanished peer that no other timer would catch. Opt-in
    /// (`keepalive_idle_ms == 0` ⇒ disabled). Only runs when the connection is
    /// truly idle — nothing in flight (`snd_una == snd_max`) *and* nothing
    /// queued (`send_ring` empty); a connection with send work is covered by
    /// the R2 retransmit budget and the no-progress USER TIMEOUT instead. The
    /// probe is a zero-data ACK one byte behind `snd_nxt`, which the peer must
    /// answer (RFC 1122 §4.2.3.6); it carries no new sequence space, so it
    /// neither advances send state nor arms the RTO. After `keepalive_count`
    /// unanswered probes the peer is declared gone and the connection is
    /// aborted locally.
    fn check_keepalive(&mut self) -> Result<(), TcpError> {
        if self.keepalive_idle_ms == 0
            || self.state != State::Established
            || self.snd_una != self.snd_max
            || !self.send_ring.is_empty()
        {
            return Ok(());
        }
        let deadline = match self.keepalive_deadline {
            Some(d) => d,
            None => return Ok(()),
        };
        if self.now_ms < deadline {
            return Ok(());
        }
        if self.keepalive_probes >= self.keepalive_count {
            // None of the probes was answered — the peer has vanished.
            self.abort_timed_out();
            return Ok(());
        }
        let opts = self.data_options();
        let queued = self.emit_segment(
            flags::ACK,
            self.snd_nxt.wrapping_sub(1),
            self.rcv_nxt,
            &opts,
            &[],
        )?;
        if queued {
            self.keepalive_probes = self.keepalive_probes.saturating_add(1);
            self.keepalive_deadline =
                Some(self.now_ms.wrapping_add(self.keepalive_intvl_ms as u64));
        }
        Ok(())
    }

    /// RFC 9293 §3.8.3 USER TIMEOUT: abort a connection that has made no
    /// forward progress (`snd_una` not advancing) for `user_timeout_ms` while
    /// it still has unacknowledged send work. Unlike R2 (which any sign of
    /// life resets) and keepalive (idle connections only), this fires even
    /// against a peer that is demonstrably alive but stalling — the
    /// zero-window / dribbled-duplicate-ACK DoS — because only real progress
    /// re-arms it. Armed lazily here when work first appears, re-armed on
    /// progress in `process_ack`, disarmed when work drains.
    fn check_user_timeout(&mut self) {
        if self.user_timeout_ms == 0 {
            self.user_timeout_deadline = None;
            return;
        }
        let has_work = self.snd_una != self.snd_max || !self.send_ring.is_empty();
        if !has_work {
            self.user_timeout_deadline = None;
            return;
        }
        match self.user_timeout_deadline {
            None => {
                self.user_timeout_deadline =
                    Some(self.now_ms.wrapping_add(self.user_timeout_ms as u64));
            }
            Some(deadline) => {
                if self.now_ms >= deadline {
                    self.abort_timed_out();
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Emission helpers
    // ---------------------------------------------------------------------

    fn send_pure_ack(&mut self) -> Result<(), TcpError> {
        if self.tx_ring.is_full() {
            return Ok(());
        }
        let opts = self.data_options();
        if self.emit_segment(flags::ACK, self.snd_nxt, self.rcv_nxt, &opts, &[])? {
            self.pending_ack = false;
            self.delayed_ack_count = 0;
            self.ack_deadline = None;
        }
        Ok(())
    }

    fn emit_segment(
        &mut self,
        flag_bits: u8,
        seq: u32,
        ack: u32,
        options: &TcpOptions,
        payload: &[u8],
    ) -> Result<bool, TcpError> {
        if self.tx_ring.is_full() {
            // Caller hasn't drained the ring — the retransmit timer or
            // a subsequent ACK-clocked send will redrive us. Return
            // false so state-mutating callers (snd_nxt, FIN bookkeeping,
            // send_queue.push, ...) know not to advance their state.
            return Ok(false);
        }
        // RFC 7323 §2.3: the Window field in SYN segments (including
        // SYN-ACK) is NEVER scaled. Only post-handshake segments shift
        // by `rcv_wscale`.
        let is_syn = (flag_bits & flags::SYN) != 0;
        let window = self.outbound_window(is_syn);

        // ---- ECN feedback bits (RFC 3168 §6) ----------------------------
        // ECE on ACKs while we've seen a CE; CWR on the next new data
        // segment after the sender has reacted to a peer's ECE.
        let mut adjusted_flags = flag_bits;
        if self.ecn_enabled && !is_syn && (flag_bits & flags::ACK) != 0 {
            if self.ce_observed {
                adjusted_flags |= flags::ECE;
            }
            // CWR is set on the FIRST new-data segment after entering
            // recovery in response to an ECE. We approximate "new data"
            // by checking payload.len() > 0 — pure ACKs don't trigger
            // the peer to clear its ce_observed.
            if self.send_cwr_pending && !payload.is_empty() {
                adjusted_flags |= flags::CWR;
                self.send_cwr_pending = false;
            }
        }

        // IP-layer ECN codepoint (RFC 3168 §6.1.1):
        //   * SYN / SYN-ACK MUST NOT be ECT-marked.
        //   * Once ECN is negotiated, all other segments use ECT(0).
        let ecn_codepoint = if self.ecn_enabled && !is_syn {
            wire::ecn::ECT_0
        } else {
            wire::ecn::NOT_ECT
        };

        // Capture per-emit context outside the closure to avoid
        // borrowing `self` mutably twice.
        let src_ip = self.local.ip;
        let dst_ip = self.remote.ip;
        let src_port = self.local.port;
        let dst_port = self.remote.port;
        let ip_id = self.ip_id;
        let queued = self.tx_ring.push_with(|buf| {
            wire::emit(
                buf,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq,
                ack,
                adjusted_flags,
                window,
                options,
                payload,
                ip_id,
                ecn_codepoint,
            )
        })?;
        if queued {
            self.ip_id = self.ip_id.wrapping_add(1);
        }
        Ok(queued)
    }

    // ---------------------------------------------------------------------
    // Timing / RTT / windowing helpers
    // ---------------------------------------------------------------------

    fn data_options(&self) -> TcpOptions {
        // Attach SACK blocks describing held out-of-order runs, if SACK was
        // negotiated and we have any. RFC 2018 §4: SACK blocks are sent on
        // dup-ACKs **and** on regular ACKs while data is being held; either
        // is fine because the peer's sender ignores SACK blocks below
        // `snd_una` anyway.
        //
        // With TS enabled the option budget caps us at 3 SACK blocks (TS=10
        // + 3*8+2=26 + NOPs = 38 ≤ 40); without TS we can fit 4.
        let mut sack = SackBlocks::EMPTY;
        if self.sack_enabled {
            let max_blocks = if self.ts_enabled { 3 } else { 4 };
            self.reasm.fill_sack_blocks(&mut sack, max_blocks);
        }
        if self.ts_enabled {
            TcpOptions {
                mss: None,
                wscale: None,
                ts: Some((self.ts_val(), self.ts_recent)),
                sack_permitted: false,
                sack,
            }
        } else if !sack.is_empty() {
            TcpOptions {
                mss: None,
                wscale: None,
                ts: None,
                sack_permitted: false,
                sack,
            }
        } else {
            TcpOptions::NONE
        }
    }

    #[inline]
    fn ts_val(&self) -> u32 {
        // Lower 32 bits of the host clock — wraps every ~49 days.
        self.now_ms as u32
    }

    /// Apply the peer's negotiated Window Scale to the raw 16-bit window
    /// field, yielding the true byte count of bytes the peer can accept.
    /// Per RFC 7323 §2.3 callers must NOT use this for SYN/SYN-ACK
    /// segments — those windows are always unscaled on the wire.
    #[inline]
    fn scale_peer_window(&self, w: u16) -> u32 {
        // Shift count is bounded to 14 by both parser and negotiator,
        // so this never overflows u32 (16 + 14 = 30 bits).
        (w as u32) << self.snd_wscale
    }

    /// Compute the wire-format window field for an outbound segment.
    /// `is_syn_segment` selects the unscaled form (SYN / SYN-ACK) per
    /// RFC 7323 §2.3.
    fn outbound_window(&self, is_syn_segment: bool) -> u16 {
        let raw = self.advertised_window();
        let scaled = if is_syn_segment {
            raw
        } else {
            raw >> self.rcv_wscale
        };
        u16::try_from(scaled.min(u16::MAX as u32)).unwrap_or(u16::MAX)
    }

    fn effective_payload_mss(&self) -> usize {
        let cap = core::cmp::min(self.local_mss, self.peer_mss) as usize;
        // Reserve space for whatever options data_options() will actually
        // emit on this segment. With TS alone that's 12 bytes; with TS +
        // SACK (a held OOO run pending) it's 20 bytes.
        let opt = self.data_options().encoded_len();
        // Ensure we never produce a > MAX_PACKET datagram.
        let stack_cap = MSS as usize;
        cap.saturating_sub(opt).min(stack_cap)
    }

    fn arm_rto_for(&mut self, probe_seq: u32) {
        self.rto_deadline = Some(self.now_ms.wrapping_add(self.rto_ms as u64));
        if !self.ts_enabled && self.rtt_probe.is_none() {
            self.rtt_probe = Some(RttProbe {
                seq: probe_seq,
                sent_at: self.now_ms,
                valid: true,
            });
        }
    }

    /// Bump the high-water mark `snd_max` to track the latest `snd_nxt`.
    /// Called after every site that advances `snd_nxt`. The wrap-aware
    /// comparison handles connections that survive past 2^32 bytes.
    #[inline]
    fn bump_snd_max(&mut self) {
        if seq_gt(self.snd_nxt, self.snd_max) {
            self.snd_max = self.snd_nxt;
        }
    }

    /// RFC 6298 §2 SRTT/RTTVAR/RTO update.
    fn update_rtt(&mut self, r_ms: u32) {
        if !self.rtt_first_sample {
            self.srtt_ms = r_ms.max(1);
            self.rttvar_ms = (r_ms / 2).max(1);
            self.rtt_first_sample = true;
        } else {
            let diff = self.srtt_ms.abs_diff(r_ms);
            // RTTVAR = 0.75 * RTTVAR + 0.25 * |SRTT - R|
            self.rttvar_ms = (3u32.saturating_mul(self.rttvar_ms).saturating_add(diff)) / 4;
            // SRTT = 0.875 * SRTT + 0.125 * R
            self.srtt_ms = (7u32.saturating_mul(self.srtt_ms).saturating_add(r_ms)) / 8;
        }
        let g = 1u32; // clock granularity (ms)
        let rto = self
            .srtt_ms
            .saturating_add(core::cmp::max(g, self.rttvar_ms.saturating_mul(4)));
        self.rto_ms = rto.clamp(RTO_MIN_MS, RTO_MAX_MS);
    }

    fn update_rtt_from_ts_echo(&mut self, tsecr: u32) {
        let now = self.ts_val();
        let r = now.wrapping_sub(tsecr);
        // Sanity cap on the upper end (clock skew or wrap). On the lower
        // end we clamp r=0 to 1ms — sub-millisecond RTTs are real on
        // loopback / LAN, and `update_rtt` already treats 1ms as the
        // smallest meaningful sample (initial RTTVAR = R/2 = 0 otherwise).
        if r > 60_000 {
            return;
        }
        self.update_rtt(r.max(1));
    }

    fn process_ack_rtt(&mut self, ack: u32) {
        let probe = match self.rtt_probe {
            Some(p) => p,
            None => return,
        };
        if !probe.valid {
            self.rtt_probe = None;
            return;
        }
        if !seq_ge(ack, probe.seq) {
            return;
        }
        let r = (self.now_ms.saturating_sub(probe.sent_at)) as u32;
        self.rtt_probe = None;
        if r > 0 {
            self.update_rtt(r);
        }
    }

    fn in_window(&self, seq: u32, len: u32) -> bool {
        let wnd = self.rcv_wnd.max(1);
        if len == 0 {
            seq == self.rcv_nxt || seq_in_range(seq, self.rcv_nxt, self.rcv_nxt.wrapping_add(wnd))
        } else {
            let last = seq.wrapping_add(len - 1);
            seq_in_range(seq, self.rcv_nxt, self.rcv_nxt.wrapping_add(wnd))
                || seq_in_range(last, self.rcv_nxt, self.rcv_nxt.wrapping_add(wnd))
        }
    }
}

// ---------------------------------------------------------------------
// 32-bit serial-number arithmetic (RFC 1982).
// ---------------------------------------------------------------------

#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[inline]
fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
fn seq_in_range(x: u32, lo: u32, hi_exclusive: u32) -> bool {
    x.wrapping_sub(lo) < hi_exclusive.wrapping_sub(lo)
}

// ---------------------------------------------------------------------
// SYN-cookie helpers (only relevant when `cookie_secret_set` is true).
// ---------------------------------------------------------------------

/// Largest entry in [`COOKIE_MSS_TABLE`] not exceeding `peer_mss`. The
/// returned index fits in 3 bits.
fn cookie_mss_index(peer_mss: u16) -> u8 {
    let mut best = 0u8;
    let mut i = 0;
    while i < COOKIE_MSS_TABLE.len() {
        let entry = match COOKIE_MSS_TABLE.get(i) {
            Some(v) => *v,
            None => break,
        };
        if entry <= peer_mss {
            best = i as u8;
        }
        i += 1;
    }
    best & 0x7
}

/// Recover a peer-MSS value from a 3-bit cookie index. Out-of-range
/// indices clamp to the smallest entry — defensive, since the index is
/// extracted from peer-controlled bits.
fn cookie_mss_from_index(idx: u8) -> u16 {
    match COOKIE_MSS_TABLE.get((idx & 0x7) as usize) {
        Some(v) => *v,
        None => DEFAULT_PEER_MSS,
    }
}

/// SipHash-2-4 keyed PRF (Aumasson & Bernstein 2012). Used as the MAC
/// underlying our SYN cookies. Stand-alone implementation so the crate
/// stays `#![no_std]`-clean and dependency-free.
///
/// SipHash gives 64-bit security against forgery; we truncate to 29 bits
/// in the cookie format, so an off-path blind attacker has a 1-in-2^29
/// forgery probability per attempt.
fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let &[k00, k01, k02, k03, k04, k05, k06, k07, k10, k11, k12, k13, k14, k15, k16, k17] = key;
    let k0 = u64::from_le_bytes([k00, k01, k02, k03, k04, k05, k06, k07]);
    let k1 = u64::from_le_bytes([k10, k11, k12, k13, k14, k15, k16, k17]);
    let mut v0 = 0x736f_6d65_7073_6575u64 ^ k0;
    let mut v1 = 0x646f_7261_6e64_6f6du64 ^ k1;
    let mut v2 = 0x6c79_6765_6e65_7261u64 ^ k0;
    let mut v3 = 0x7465_6462_7974_6573u64 ^ k1;

    let mut chunks = data.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(chunk);
        let m = u64::from_le_bytes(arr);
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }
    let rem = chunks.remainder();
    let mut tail = [0u8; 8];
    if let Some(dst) = tail.get_mut(..rem.len()) {
        dst.copy_from_slice(rem);
    }
    if let Some(slot) = tail.get_mut(7) {
        *slot = (data.len() & 0xff) as u8;
    }
    let last = u64::from_le_bytes(tail);

    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;
    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(test)]
mod siphash_tests {
    use super::siphash24;

    /// Standard test vector from the SipHash reference (Appendix A of the
    /// 2012 paper): key = 0x00..0f, message = 0x00..0e (15 bytes), output
    /// 0xa129ca6149be45e5.
    #[test]
    fn vector_15_bytes() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let msg: [u8; 15] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e,
        ];
        assert_eq!(siphash24(&key, &msg), 0xa129_ca61_49be_45e5);
    }

    /// Empty-message vector: 0x726fdb47dd0e0e31.
    #[test]
    fn vector_empty() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        assert_eq!(siphash24(&key, &[]), 0x726f_db47_dd0e_0e31);
    }
}

#[cfg(test)]
mod retransmit_overflow_regression {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::{Endpoint, Tcb, TcbConfig};
    use crate::State;

    fn cfg(iss: u32) -> TcbConfig {
        TcbConfig {
            local: Endpoint {
                ip: [10, 0, 0, 1],
                port: 49152,
            },
            remote: Endpoint {
                ip: [10, 0, 0, 2],
                port: 80,
            },
            iss,
            initial_rto_ms: 1000,
        }
    }

    /// Regression for the `kitchen-sink` chaos failure surfaced as
    /// `tcp_tick: -9` (`TcpError::Overflow`).
    ///
    /// `SendQueue::prune` deliberately keeps a *partially* cumulative-ACKed
    /// entry whole (RACK needs the original send-ts for the unacked tail),
    /// so the highest un-SACKed entry can have `seq_start < snd_una`. A TLP
    /// firing in that state used to feed the raw `seq_start` to
    /// `emit_data_at`, whose `seq.wrapping_sub(snd_una)` offset wrapped far
    /// past the send-ring head; `peek_at` then returned 0, tripping the
    /// `copied != bytes` overflow guard. The probe must instead start at
    /// `snd_una` and carry only the still-unacked tail.
    #[test]
    fn tlp_probe_on_partially_acked_tail_does_not_overflow() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");

        // Synthesize an ESTABLISHED connection where a single 1000-byte
        // segment [2000, 3000) was transmitted and recorded, then a later
        // cumulative ACK landed at 2600 — strictly inside it. Its prefix
        // [2000, 2600) is gone from the send ring; the tail [2600, 3000)
        // (400 bytes) is still in flight at the ring head.
        tcb.state = State::Established;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 5_000;
        tcb.snd_una = 2_600;
        tcb.snd_nxt = 3_000;
        tcb.snd_max = 3_000;
        let copied = tcb.send_ring.write(&[0xAB; 400]);
        assert_eq!(copied, 400, "send ring must hold the 400-byte unacked tail");
        // The full original segment, recorded before the partial ACK
        // pruned snd_una forward — seq_start (2000) sits below snd_una.
        tcb.send_queue.push(2_000, 1_000, 1, false);

        // Arm the TLP so this tick fires the probe immediately.
        tcb.srtt_ms = 5;
        tcb.now_ms = 100;
        tcb.tlp_deadline = Some(100);
        tcb.tlp_fired = false;

        // Before the fix this returned Err(TcpError::Overflow) (-9).
        tcb.tick()
            .expect("tick must not overflow on a partially-acked TLP tail");

        // The staged probe must cover the unacked tail only: start at
        // snd_una (2600), never at the entry's original seq_start (2000).
        let mut buf = [0u8; crate::MAX_PACKET];
        let n = tcb.extract_packet(&mut buf).expect("extract");
        assert!(n > 0, "a TLP probe should have been staged");
        let seg = crate::wire::parse(&buf[..n]).expect("parse probe");
        assert_eq!(seg.seq, 2_600, "probe must start at snd_una, not seq_start");
        assert_eq!(
            seg.payload.len(),
            400,
            "probe carries exactly the unacked tail",
        );
    }

    /// Regression for the FIN-teardown variant found by the
    /// `tcb_client_session` fuzzer (also `tcp_tick: -9`).
    ///
    /// The RFC 6675 initial retransmit sizes itself from `snd_max - snd_una`,
    /// which counts the phantom FIN sequence. When the FIN is the only thing
    /// outstanding (all data ACKed → send ring empty) and recovery is entered
    /// (e.g. three dup-ACKs at `fin_seq`), that path called
    /// `emit_data_at(snd_una, 1)` against an empty ring, so `peek_at` returned
    /// 0 and the `copied != bytes` guard tripped `Overflow`. `emit_data_at`
    /// now clamps the request to the bytes the ring actually holds.
    #[test]
    fn initial_retransmit_with_only_fin_outstanding_does_not_overflow() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");

        // All data ACKed, only the FIN in flight: snd_una == fin_seq,
        // snd_max == fin_seq + 1, send ring empty.
        let fin = 5_000u32;
        tcb.state = State::FinWait1;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = fin;
        tcb.snd_nxt = fin.wrapping_add(1);
        tcb.snd_max = fin.wrapping_add(1);
        tcb.fin_sent = true;
        tcb.fin_seq = fin;

        // Enter recovery exactly as three dup-ACKs at fin_seq would, so the
        // initial retransmit fires with outstanding = snd_max - snd_una = 1
        // (the phantom FIN byte, nothing behind it in the ring).
        tcb.cc.enter_recovery(1, fin.wrapping_add(1));
        tcb.rxt_seq = fin;
        tcb.rxt_unacked = 0;
        tcb.now_ms = 100;

        // Before the emit_data_at clamp this returned Err(Overflow) (-9).
        tcb.tick()
            .expect("tick must not overflow when only the FIN is outstanding");
    }

    /// Liveness regression: a FIN that is the *sole* outstanding segment and
    /// gets lost must be retransmitted on RTO. Previously the RTO path only
    /// re-emitted SYN/SYN-ACK and `need_fin` gated on `!fin_sent`, so the
    /// FIN was never resent and the close stalled forever.
    #[test]
    fn lost_fin_is_retransmitted_after_rto() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");

        let fin = 5_000u32;
        tcb.state = State::FinWait1;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = fin;
        tcb.snd_nxt = fin.wrapping_add(1);
        tcb.snd_max = fin.wrapping_add(1);
        tcb.fin_sent = true;
        tcb.fin_seq = fin;
        // FIN is in flight behind an armed RTO that is now due (it was lost).
        tcb.rto_ms = 200;
        tcb.rto_deadline = Some(50);
        tcb.now_ms = 100;

        tcb.tick().expect("tick");

        // The RTO rewinds snd_nxt onto fin_seq, and the FIN block resends it.
        let mut buf = [0u8; crate::MAX_PACKET];
        let n = tcb.extract_packet(&mut buf).expect("extract");
        assert!(n > 0, "a FIN retransmit should have been staged");
        let seg = crate::wire::parse(&buf[..n]).expect("parse");
        assert!(
            seg.has(crate::wire::flags::FIN),
            "retransmit must carry the FIN flag",
        );
        assert_eq!(seg.seq, fin, "FIN retransmit sits at fin_seq");
        assert_eq!(
            tcb.snd_nxt,
            fin.wrapping_add(1),
            "snd_nxt advances past the FIN again",
        );
    }

    /// Regression for the PRR ACK-clock deadlock found by the standalone
    /// conformance harness (`bindings/conformance`) driving cdylib⇄cdylib
    /// under combined loss+reorder+dup.
    ///
    /// State: ESTABLISHED, in fast recovery with `snd_credit == 0`, the pipe
    /// fully drained (`snd_nxt == snd_una`, so `flight == 0`), but a segment
    /// at `snd_una` is still un-ACKed (`snd_max > snd_una`) and the send ring
    /// holds data. The RFC 6675 retransmit was credit-clamped to 0 bytes, so
    /// the lost segment could never be resent; no ACK would arrive to
    /// replenish PRR credit, so recovery never progressed — a permanent stall
    /// with the window wide open. `maybe_send_one` now force-exits recovery in
    /// this state and re-sends `snd_una` to restart the ACK clock.
    #[test]
    fn prr_empty_pipe_zero_credit_does_not_deadlock() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        let una = 5_000u32;
        tcb.snd_una = una;
        tcb.snd_nxt = una; // flight == 0: nothing newly in flight
        tcb.snd_max = una.wrapping_add(2_000); // 2000 bytes sent-but-unacked (lost)
        let n = tcb.send_ring.write(&[0x5A; 8_000]);
        assert_eq!(n, 8_000, "send ring must hold the unacked + unsent data");

        // Drive PRR into recovery and exhaust the send credit, mirroring the
        // post-RTO re-entry that produced the wedge.
        tcb.cc.enter_recovery(2_000, tcb.snd_max);
        let c = tcb.cc.snd_credit();
        tcb.cc.on_send(c);
        assert_eq!(tcb.cc.snd_credit(), 0);
        assert!(tcb.cc.in_recovery());
        tcb.rxt_seq = una;
        tcb.rxt_unacked = 0;
        tcb.now_ms = 1_000;

        // Before the guard this emitted nothing (deadlock).
        tcb.tick().expect("tick");
        let mut buf = [0u8; crate::MAX_PACKET];
        let m = tcb.extract_packet(&mut buf).expect("extract");
        assert!(m > 0, "stack must emit a segment to restart the ACK clock");
        let seg = crate::wire::parse(&buf[..m]).expect("parse");
        assert_eq!(
            seg.seq, una,
            "the emitted segment must start at snd_una (the lost data)",
        );
        assert!(!seg.payload.is_empty(), "it must carry the buffered bytes");
        assert!(
            !tcb.cc.in_recovery(),
            "the empty-pipe/zero-credit recovery must have been force-exited",
        );
        assert!(
            tcb.debug_check_liveness().is_ok(),
            "after the force-exit a retransmit timer must be armed (live again)",
        );
    }

    /// The liveness oracle (`debug_check_liveness`) must flag a dead ACK
    /// clock: sequence space that is sent-but-unacknowledged with *no*
    /// retransmit timer behind it can never be re-sent, so the peer's ACK
    /// never comes. This is the unit-level proof the oracle is non-vacuous —
    /// the same shape the loopback fuzzer catches end-to-end.
    #[test]
    fn liveness_oracle_flags_outstanding_data_with_no_timer() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 7_000; // 2000 bytes sent-but-unacked

        // Healthy: a retransmit timer is armed over the outstanding data.
        tcb.rto_deadline = Some(1_200);
        tcb.tlp_deadline = None;
        tcb.rack_deadline = None;
        assert!(
            tcb.debug_check_liveness().is_ok(),
            "armed RTO over outstanding data is live",
        );

        // Black hole: every retransmit timer disarmed while data is unacked.
        tcb.rto_deadline = None;
        assert_eq!(
            tcb.debug_check_liveness(),
            Err("liveness: outstanding data with no retransmit timer"),
        );

        // TLP or RACK alone is enough to keep the ACK clock alive.
        tcb.tlp_deadline = Some(1_100);
        assert!(tcb.debug_check_liveness().is_ok());
        tcb.tlp_deadline = None;
        tcb.rack_deadline = Some(1_050);
        assert!(tcb.debug_check_liveness().is_ok());

        // Fully acknowledged: no outstanding data, vacuously live.
        tcb.rack_deadline = None;
        tcb.snd_una = tcb.snd_max;
        assert!(
            tcb.debug_check_liveness().is_ok(),
            "no outstanding data is vacuously live",
        );
    }

    /// The liveness oracle must also flag a stalled persist: data queued to
    /// send under a slammed-shut peer window with nothing in flight and no
    /// persist timer can never make progress.
    #[test]
    fn liveness_oracle_flags_zero_window_without_persist() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000; // nothing in flight
        tcb.snd_wnd = 0; // peer advertised a zero window
        let n = tcb.send_ring.write(&[0x5A; 1_000]);
        assert_eq!(n, 1_000, "send ring must hold the window-blocked data");

        tcb.persist_deadline = None;
        assert_eq!(
            tcb.debug_check_liveness(),
            Err("liveness: data queued under zero window with no persist timer"),
        );

        // A scheduled persist probe will reopen the window: live again.
        tcb.persist_deadline = Some(1_500);
        assert!(tcb.debug_check_liveness().is_ok());
    }

    /// Reproduces the bidirectional small-window deadlock surfaced by the
    /// `tcb_loopback_small` fuzz target. In a two-way transfer, once *both*
    /// directions rewind `snd_nxt` below the peer's `rcv_nxt` after loss,
    /// every pure ACK arrives "old" (`SEG.SEQ < RCV.NXT`). Such a segment is
    /// unacceptable per RFC 9293 §3.10.7.4 step 1, but its cumulative ACK must
    /// still be processed (it is exactly a duplicate ACK, RFC 5681 §3.2). The
    /// pre-fix code dropped the whole segment, freezing `snd_una`, starving
    /// cwnd of ACKs, and making both senders retransmit already-received data
    /// forever.
    #[test]
    fn old_duplicate_ack_still_advances_snd_una() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.snd_wnd = 65_535;
        // We put [5000, 7048) on the wire (snd_max = 7048); an RTO rewound
        // snd_nxt to 6460 (one segment resent), so snd_una still lags.
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 6_460;
        tcb.snd_max = 7_048;
        let n = tcb.send_ring.write(&[0xAB; 2_048]);
        assert_eq!(n, 2_048, "send ring must hold the outstanding bytes");
        // Our receive side has already advanced (we got the peer's data).
        tcb.rcv_nxt = 9_000;
        tcb.rcv_wnd = 8_192;

        // Peer's pure ACK: SEQ = 8700 (300 below our rcv_nxt → an old
        // duplicate), ACK = 7048 (acknowledges *all* our outstanding data).
        let opts = crate::wire::TcpOptions::NONE;
        let mut buf = [0u8; crate::MAX_PACKET];
        let len = crate::wire::emit(
            &mut buf,
            [10, 0, 0, 2], // src = remote
            [10, 0, 0, 1], // dst = local
            80,
            49152,
            8_700, // SEQ below our rcv_nxt: old duplicate
            7_048, // ACK covers snd_max
            crate::wire::flags::ACK,
            65_535,
            &opts,
            &[],
            1,
            crate::wire::ecn::NOT_ECT,
        )
        .expect("emit");
        tcb.inject_packet(&buf[..len]).expect("inject");

        assert_eq!(
            tcb.snd_una, 7_048,
            "an old-duplicate pure ACK must still advance snd_una to the acked high-water",
        );
    }

    /// Reproduces the simultaneous-close deadlock surfaced by the
    /// `tcb_loopback_small` fuzz target. A pure FIN owes no receive-window
    /// space, so it must be emitted even when the peer's advertised window is
    /// 0. Pre-fix, `maybe_send_one` took the zero-window persist early-return
    /// before ever reaching the FIN, so a close in which the peer's window was
    /// momentarily 0 (and never refreshed, because the peer had nothing left
    /// to send) wedged forever in CLOSING / FIN_WAIT_2 with the FIN never on
    /// the wire.
    #[test]
    fn fin_is_emitted_into_a_zero_window() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::FinWait1;
        tcb.snd_wnd = 0; // peer advertised a zero window
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000; // all data acked → send ring empty
        tcb.rcv_nxt = 9_000;
        tcb.now_ms = 1_000;

        tcb.tick().expect("tick");
        let mut buf = [0u8; crate::MAX_PACKET];
        let n = tcb.extract_packet(&mut buf).expect("extract");
        assert!(n > 0, "a FIN must be emitted even into a zero window");
        let seg = crate::wire::parse(&buf[..n]).expect("parse");
        assert!(
            seg.has(crate::wire::flags::FIN),
            "the emitted segment must carry FIN",
        );
        assert_eq!(seg.seq, 5_000, "the FIN sits at snd_nxt");
        assert!(tcb.fin_sent, "fin_sent must be pinned after emission");
        assert_eq!(tcb.fin_seq, 5_000, "fin_seq must record the FIN's sequence");
    }

    /// RFC 9293 §3.8.3 (R2): a synchronized connection whose peer goes silent
    /// must abort after `MAX_RETRANSMITS` unacknowledged retransmission
    /// timeouts rather than retransmit forever.
    #[test]
    fn r2_aborts_after_max_retransmits_without_ack() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.set_user_timeout(0); // isolate R2 (count-based) from USER TIMEOUT
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 6_460;
        tcb.snd_max = 6_460; // one 1460-byte segment in flight, unacked
        let n = tcb.send_ring.write(&[0xAB; 1_460]);
        assert_eq!(n, 1_460);
        tcb.now_ms = 0;
        tcb.rto_ms = 200;
        tcb.arm_rto_for(tcb.snd_nxt);

        let mut fired = 0u32;
        let mut buf = [0u8; crate::MAX_PACKET];
        for _ in 0..(super::MAX_RETRANSMITS as u32 + 5) {
            let dl = tcb.debug_snapshot().rto_deadline;
            if dl == u64::MAX {
                break; // no RTO armed
            }
            tcb.set_now(dl + 1);
            tcb.tick().expect("tick");
            fired += 1;
            if tcb.state() == State::Closed {
                break;
            }
            while tcb.extract_packet(&mut buf).expect("extract") > 0 {}
        }

        assert_eq!(
            fired,
            super::MAX_RETRANSMITS as u32 + 1,
            "abort must fire exactly one timeout past the budget",
        );
        assert_eq!(tcb.state(), State::Closed, "R2 must abort the connection");
        assert_eq!(
            tcb.error,
            Some(crate::TcpError::ConnectionReset),
            "the R2 abort surfaces as a local reset",
        );
    }

    /// The R2 counter resets on any forward ACK progress, so a peer that keeps
    /// acknowledging — however slowly — is never spuriously aborted.
    #[test]
    fn r2_counter_resets_on_ack_progress() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.set_user_timeout(0); // isolate R2 from USER TIMEOUT
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 6_460;
        tcb.snd_max = 6_460;
        let n = tcb.send_ring.write(&[0xAB; 1_460]);
        assert_eq!(n, 1_460);
        tcb.now_ms = 0;
        tcb.rto_ms = 200;
        tcb.arm_rto_for(tcb.snd_nxt);

        // Fire a few RTOs short of the budget — no abort yet.
        let mut buf = [0u8; crate::MAX_PACKET];
        for _ in 0..(super::MAX_RETRANSMITS as u32 - 2) {
            let dl = tcb.debug_snapshot().rto_deadline;
            tcb.set_now(dl + 1);
            tcb.tick().expect("tick");
            while tcb.extract_packet(&mut buf).expect("extract") > 0 {}
        }
        assert!(tcb.rtx_count > 0, "the counter should have accrued");
        assert_eq!(tcb.state(), State::Established, "must not have aborted yet");

        // A cumulative ACK advancing snd_una proves the peer is alive.
        let opts = crate::wire::TcpOptions::NONE;
        let mut pkt = [0u8; crate::MAX_PACKET];
        let len = crate::wire::emit(
            &mut pkt,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            49152,
            9_000, // seq == our rcv_nxt
            5_730, // acks 730 of the outstanding bytes
            crate::wire::flags::ACK,
            65_535,
            &opts,
            &[],
            1,
            crate::wire::ecn::NOT_ECT,
        )
        .expect("emit");
        tcb.inject_packet(&pkt[..len]).expect("inject");

        assert_eq!(tcb.snd_una, 5_730, "the ACK must have advanced snd_una");
        assert_eq!(
            tcb.rtx_count, 0,
            "forward ACK progress must reset the R2 retransmit counter",
        );
    }

    fn drain_all(tcb: &mut Tcb) -> bool {
        let mut buf = [0u8; crate::MAX_PACKET];
        let mut emitted = false;
        while tcb.extract_packet(&mut buf).expect("extract") > 0 {
            emitted = true;
        }
        emitted
    }

    fn inject_peer_ack(tcb: &mut Tcb, seq: u32, ack: u32) {
        inject_peer_ack_win(tcb, seq, ack, 65_535);
    }

    fn inject_peer_ack_win(tcb: &mut Tcb, seq: u32, ack: u32, window: u16) {
        let opts = crate::wire::TcpOptions::NONE;
        let mut pkt = [0u8; crate::MAX_PACKET];
        let len = crate::wire::emit(
            &mut pkt,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            49152,
            seq,
            ack,
            crate::wire::flags::ACK,
            window,
            &opts,
            &[],
            1,
            crate::wire::ecn::NOT_ECT,
        )
        .expect("emit");
        tcb.inject_packet(&pkt[..len]).expect("inject");
    }

    /// Drive RTO firings (no inbound traffic) until the connection aborts or a
    /// generous cap is hit; returns the number of timeouts that fired.
    fn run_rtos_until_closed(tcb: &mut Tcb) -> u32 {
        let mut fired = 0u32;
        for _ in 0..(super::MAX_RETRANSMITS as u32 + 5) {
            let dl = tcb.debug_snapshot().rto_deadline;
            if dl == u64::MAX {
                break;
            }
            tcb.set_now(dl + 1);
            tcb.tick().expect("tick");
            fired += 1;
            if tcb.state() == State::Closed {
                break;
            }
            drain_all(tcb);
        }
        fired
    }

    /// Vanished peer on the **connect** path: an unanswered SYN must time out
    /// (R2 applies to SYN_SENT) rather than retransmit forever.
    #[test]
    fn r2_aborts_silent_peer_during_connect() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.set_now(0);
        tcb.set_user_timeout(0); // isolate R2 from USER TIMEOUT
        tcb.connect().expect("connect");
        assert_eq!(tcb.state(), State::SynSent);
        drain_all(&mut tcb);

        let fired = run_rtos_until_closed(&mut tcb);
        assert_eq!(
            tcb.state(),
            State::Closed,
            "connect to a silent peer must time out"
        );
        assert_eq!(fired, super::MAX_RETRANSMITS as u32 + 1);
    }

    /// Vanished peer on the **close** path: an unanswered FIN must time out
    /// rather than leave us in FIN_WAIT_1 forever.
    #[test]
    fn r2_aborts_silent_peer_during_close() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.set_user_timeout(0); // isolate R2 from USER TIMEOUT
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000;
        tcb.now_ms = 0;
        tcb.rto_ms = 200;
        tcb.close().expect("close");
        assert_eq!(tcb.state(), State::FinWait1);
        drain_all(&mut tcb);

        run_rtos_until_closed(&mut tcb);
        assert_eq!(
            tcb.state(),
            State::Closed,
            "a silent peer during close must time out"
        );
    }

    /// Proof-of-life isolation: with the USER TIMEOUT disabled, the **R2**
    /// retransmit counter alone must never abort a peer that keeps answering
    /// (even with non-advancing zero-window / duplicate ACKs) — R2's job is to
    /// catch a *silent* peer, and any sign of life resets it. (The
    /// no-forward-progress abort of such a stalling-but-alive peer is the USER
    /// TIMEOUT's job, covered separately.)
    #[test]
    fn r2_survives_flow_controlled_alive_peer() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.set_user_timeout(0); // isolate R2: USER TIMEOUT would otherwise abort
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 6_460;
        tcb.snd_max = 6_460;
        let _ = tcb.send_ring.write(&[0xAB; 1_460]);
        tcb.now_ms = 0;
        tcb.rto_ms = 200;
        tcb.arm_rto_for(tcb.snd_nxt);

        for _ in 0..(super::MAX_RETRANSMITS as u32 * 3) {
            let dl = tcb.debug_snapshot().rto_deadline;
            tcb.set_now(dl + 1);
            tcb.tick().expect("tick");
            drain_all(&mut tcb);
            // Peer answers each retransmit with a duplicate ACK (no progress).
            inject_peer_ack(&mut tcb, 9_000, 5_000);
            assert_ne!(
                tcb.state(),
                State::Closed,
                "an answering peer must not be aborted"
            );
        }
        assert_eq!(tcb.state(), State::Established);
        assert!(tcb.rtx_count <= 1, "each answer resets the R2 counter");
    }

    /// Keepalive catches a vanished peer on an **idle** connection that no
    /// other timer would notice (nothing in flight, both sides quiet).
    #[test]
    fn keepalive_aborts_vanished_idle_peer() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000; // idle: nothing in flight
        tcb.set_now(0);
        tcb.set_keepalive(1_000, 200, 3);

        let mut probes = 0u32;
        for _ in 0..10 {
            let dl = match tcb.debug_next_deadline() {
                Some(d) => d,
                None => break,
            };
            tcb.set_now(dl + 1);
            tcb.tick().expect("tick");
            if drain_all(&mut tcb) {
                probes += 1;
            }
            if tcb.state() == State::Closed {
                break;
            }
        }
        assert_eq!(
            tcb.state(),
            State::Closed,
            "keepalive must abort a vanished idle peer"
        );
        assert_eq!(
            probes, 3,
            "exactly keepalive_count probes precede the abort"
        );
    }

    /// A peer that answers keepalive probes is alive: the connection must
    /// survive indefinitely.
    #[test]
    fn keepalive_survives_responding_peer() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000;
        tcb.set_now(0);
        tcb.set_keepalive(1_000, 200, 3);

        for _ in 0..20 {
            let dl = tcb.debug_next_deadline().expect("keepalive armed");
            tcb.set_now(dl + 1);
            tcb.tick().expect("tick");
            drain_all(&mut tcb);
            // Peer answers the probe — proof of life.
            inject_peer_ack(&mut tcb, 9_000, 5_000);
            assert_ne!(tcb.state(), State::Closed, "an answering peer must survive");
        }
        assert_eq!(tcb.state(), State::Established);
    }

    /// Keepalive is off by default: an idle connection is left completely
    /// alone (no probes, no abort) no matter how much time passes.
    #[test]
    fn keepalive_off_by_default_leaves_idle_connection_alone() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000;

        for i in 0..50u64 {
            tcb.set_now((i + 1) * 100_000); // advance 100 s per tick
            tcb.tick().expect("tick");
            assert!(!drain_all(&mut tcb), "no probes when keepalive is disabled");
            assert_eq!(tcb.state(), State::Established, "idle connection persists");
        }
    }

    /// The headline attack: a peer that is demonstrably **alive** (it ACKs
    /// every zero-window persist probe, so R2 never fires) but **never opens
    /// its window** must not pin the connection forever. The no-progress USER
    /// TIMEOUT aborts it.
    #[test]
    fn user_timeout_aborts_alive_but_stalling_zero_window_peer() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000;
        tcb.snd_wnd = 0; // peer's window is slammed shut
        let n = tcb.send_ring.write(&[0xAB; 4_000]);
        assert_eq!(n, 4_000, "we have data we cannot send");
        tcb.set_now(0);
        tcb.set_user_timeout(10_000); // 10 s no-progress budget for the test

        // Prime the persist timer (the first tick arms it on the zero window).
        tcb.tick().expect("tick");
        drain_all(&mut tcb);

        let mut probed = false;
        for _ in 0..2_000 {
            let dl = tcb
                .debug_next_deadline()
                .expect("a timer is always armed here");
            tcb.set_now(dl + 1);
            tcb.tick().expect("tick");
            if tcb.state() == State::Closed {
                break;
            }
            // The peer answers the persist probe — proof of life (resets R2) —
            // but keeps advertising a zero window, so no progress is made.
            if drain_all(&mut tcb) {
                probed = true;
            }
            inject_peer_ack_win(&mut tcb, 9_000, 5_000, 0);
            assert_eq!(
                tcb.rtx_count, 0,
                "the answered probe keeps R2 from ever firing"
            );
        }
        assert!(
            probed,
            "the stack must have sent at least one zero-window probe"
        );
        assert_eq!(
            tcb.state(),
            State::Closed,
            "an alive-but-stalling peer must hit the USER TIMEOUT",
        );
        assert_eq!(tcb.error, Some(crate::TcpError::ConnectionReset));
        assert!(
            tcb.now_ms >= 10_000,
            "abort must not fire before the no-progress budget elapses",
        );
    }

    /// The USER TIMEOUT re-arms on real forward progress, so a peer that keeps
    /// genuinely advancing `snd_una` — however slowly — is never aborted.
    #[test]
    fn user_timeout_resets_on_forward_progress() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.snd_wnd = 65_535;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000;
        tcb.set_now(0);
        tcb.set_user_timeout(10_000);

        let mut una = 5_000u32;
        // 30 rounds of slow-but-real progress, each well within the budget but
        // collectively far past it: the connection must survive.
        for r in 0..30u64 {
            let _ = tcb.send_ring.write(&[0xCD; 100]);
            tcb.set_now(r * 8_000 + 1); // 8 s between rounds (< 10 s budget)
            tcb.tick().expect("tick");
            drain_all(&mut tcb);
            una = una.wrapping_add(100); // peer acknowledges the new bytes
            inject_peer_ack_win(&mut tcb, 9_000, una, 65_535);
            assert_eq!(
                tcb.state(),
                State::Established,
                "progress must keep it alive"
            );
        }
        assert!(
            tcb.now_ms > 10_000,
            "we ran well past a single budget window"
        );
    }

    /// `set_user_timeout(0)` disables the no-progress abort entirely: a stalled
    /// connection then persists indefinitely (host opted out of the defence).
    #[test]
    fn user_timeout_disabled_allows_indefinite_stall() {
        let mut tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        tcb.state = State::Established;
        tcb.rcv_nxt = 9_000;
        tcb.snd_una = 5_000;
        tcb.snd_nxt = 5_000;
        tcb.snd_max = 5_000;
        tcb.snd_wnd = 0;
        let _ = tcb.send_ring.write(&[0xAB; 4_000]);
        tcb.set_now(0);
        tcb.set_user_timeout(0); // disabled

        // Prime the persist timer, then stall indefinitely.
        tcb.tick().expect("tick");
        drain_all(&mut tcb);

        for _ in 0..200 {
            let dl = tcb.debug_next_deadline().expect("persist stays armed");
            tcb.set_now(dl + 1);
            tcb.tick().expect("tick");
            drain_all(&mut tcb);
            inject_peer_ack_win(&mut tcb, 9_000, 5_000, 0);
            assert_eq!(tcb.state(), State::Established, "no abort when disabled");
        }
        assert!(tcb.now_ms > 10_000_000, "ran for a very long virtual time");
    }

    /// USER TIMEOUT is on by default at `DEFAULT_USER_TIMEOUT_MS`.
    #[test]
    fn user_timeout_on_by_default() {
        let tcb: Tcb = Tcb::new(cfg(1000)).expect("tcb");
        assert_eq!(tcb.user_timeout_ms, super::DEFAULT_USER_TIMEOUT_MS);
        assert_eq!(super::DEFAULT_USER_TIMEOUT_MS, 300_000);
    }
}
