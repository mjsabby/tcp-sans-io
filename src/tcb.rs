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
use crate::wire::{self, flags, Segment, TcpOptions};
use crate::{BUF_CAP, MAX_PACKET, MSS, REASM_CAP};

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

/// Maximum number of times we will retransmit a SYN-ACK in `SYN_RCVD` before
/// giving up and reverting to `LISTEN`. With exponential RTO back-off the
/// initial retransmit is at +1*RTO, then +2*RTO, …, so a budget of 5 caps
/// the half-open lifetime at roughly `RTO * (2^6 - 1)` ≈ 63 s for the
/// default 1 s RTO. Single-TCB design ⇒ at most one half-open at a time;
/// this budget is the only adversarial flood the listener has to absorb.
const MAX_SYN_RCVD_RETRIES: u8 = 5;

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
/// SYN / SYN-ACK. Chosen as the minimal scale that lets us advertise the
/// full receive ring without truncation: `BUF_CAP / 2^LOCAL_WS_SHIFT`
/// must fit in a 16-bit window field (max 65535).
///
/// With `BUF_CAP = 1 MiB` we need shift ≥ 5 (1MiB >> 5 = 32_768 ≤ 65535;
/// shift = 4 would give 65_536 which overflows u16). Picking the minimal
/// scale matters because each shift coarsens the window granularity by
/// 2x — at shift=5 we advertise in 32-byte units, which is fine for
/// MSS-class transfers.
const LOCAL_WS_SHIFT: u8 = 5;

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
pub struct Tcb {
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
    /// segments. Set to [`LOCAL_WS_SHIFT`] iff the peer offered WS in
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

    // ---- SACK (RFC 2018) -------------------------------------------------
    /// True iff both sides offered SACK_PERMITTED in the handshake.
    sack_enabled: bool,
    /// `snd_una` value at which SACK-driven fast-retransmit last fired.
    /// Used to suppress repeated triggers within a single recovery epoch:
    /// while `snd_una` hasn't advanced past this point, additional SACK-
    /// bearing dup-ACKs are noted but don't keep collapsing `cwnd`. RFC
    /// 6675 §5 calls the equivalent state "the recovery-point check".
    sack_recovery_seq: Option<u32>,

    // ---- Buffers ---------------------------------------------------------
    send_ring: Ring<BUF_CAP>,
    recv_ring: Ring<BUF_CAP>,

    // ---- Out-of-order reassembly (single-hole) ---------------------------
    /// Bytes held ahead of `rcv_nxt`, sitting at sequence numbers
    /// `[oo_start, oo_start + oo_len)`. Capacity is fixed at
    /// [`REASM_CAP`]; segments that don't abut the held run are dropped
    /// (sender will retransmit). When the gap fills, the held run is
    /// flushed into `recv_ring` atomically.
    oo_buf: [u8; REASM_CAP],
    oo_start: u32,
    oo_len: usize,

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
    /// At most one packet is queued at a time; the host is expected to
    /// drain via `extract_packet` before requesting another tick.
    tx_buf: [u8; MAX_PACKET],
    tx_len: usize,

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
    /// 128-bit secret used to MAC SYN cookies (RFC 4987). Live only if
    /// `cookie_secret_set` is true. With cookies enabled, a LISTEN TCB
    /// answers an inbound SYN **statelessly**: the SYN-ACK's ISN encodes
    /// a MAC of the 5-tuple + peer SEQ + a coarse time bucket; we keep
    /// no per-connection state until the third ACK validates the cookie.
    /// This is the canonical defence against SYN floods.
    cookie_secret: [u8; 16],
    cookie_secret_set: bool,
}

impl Tcb {
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
            rcv_wnd: BUF_CAP as u32,
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
            sack_recovery_seq: None,
            send_ring: Ring::new()?,
            recv_ring: Ring::new()?,
            oo_buf: [0u8; REASM_CAP],
            oo_start: 0,
            oo_len: 0,
            cc: Tahoe::new(BUF_CAP as u32),
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
            tx_buf: [0u8; MAX_PACKET],
            tx_len: 0,
            ip_id: 0,
            is_listener: false,
            syn_rcvd_retries: 0,
            cookie_secret: [0u8; 16],
            cookie_secret_set: false,
        })
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
            oo_start: self.oo_start,
            oo_len: self.oo_len as u32,
            tx_len: self.tx_len as u32,
            pending_ack: self.pending_ack,
            dup_ack_count: self.cc.dup_acks,
            state: self.state as u8,
        }
    }

    /// Update the host clock. Called before every tick / packet operation.
    #[inline]
    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
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
            wscale: Some(LOCAL_WS_SHIFT),
            ts: Some((self.ts_val(), 0)),
            sack_permitted: true,
            sack: None,
        };
        // RFC 3168 §6.1.1: active opener sets BOTH ECE and CWR on the SYN
        // to advertise ECN-capable. ECN is confirmed iff the SYN-ACK
        // carries ECE without CWR. The SYN itself MUST NOT be ECT-marked
        // — emit_segment enforces that based on the SYN flag.
        self.emit_segment(
            flags::SYN | flags::ECE | flags::CWR,
            self.iss,
            0,
            &opts,
            &[],
        )?;
        self.snd_nxt = self.iss.wrapping_add(1); // SYN occupies one seq
        self.bump_snd_max();
        self.arm_rto_for(self.snd_nxt);
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
        // We allow Listen-from-Listen (idempotent) and Listen-from-Closed.
        // Anything else means an in-progress connection would be torn down
        // silently — the host should call `close` first.
        match self.state {
            State::Closed | State::Listen => {}
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
        self.rcv_wnd = BUF_CAP as u32;
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
        self.sack_recovery_seq = None;
        self.send_ring.clear();
        self.recv_ring.clear();
        self.oo_start = 0;
        self.oo_len = 0;
        self.cc = Tahoe::new(BUF_CAP as u32);
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
        self.tx_len = 0;
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
        if self.tx_len > 0 {
            ev |= events::TX_PENDING;
        }
        if self.error.is_some() {
            ev |= events::ERROR;
        }
        ev
    }

    /// Drain a queued outbound IP datagram into `out`. Returns bytes written
    /// (0 if nothing pending). After successful drain, the staging area is
    /// freed and the host should call [`Tcb::tick`] to ask for more.
    pub fn extract_packet(&mut self, out: &mut [u8]) -> Result<usize, TcpError> {
        if self.tx_len == 0 {
            return Ok(0);
        }
        if out.len() < self.tx_len {
            return Err(TcpError::BufferTooSmall);
        }
        let dst = out.get_mut(..self.tx_len).ok_or(TcpError::BufferTooSmall)?;
        let src = self
            .tx_buf
            .get(..self.tx_len)
            .ok_or(TcpError::BufferTooSmall)?;
        dst.copy_from_slice(src);
        let n = self.tx_len;
        self.tx_len = 0;
        Ok(n)
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
                let flight = self.snd_nxt.wrapping_sub(self.snd_una);
                self.cc.on_rto_loss(flight);
                self.snd_nxt = self.snd_una;
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
                        wscale: Some(LOCAL_WS_SHIFT),
                        ts: Some((self.ts_val(), 0)),
                        sack_permitted: true,
                        sack: None,
                    };
                    // ECN-Setup SYN per RFC 3168 §6.1.1 — same flags as
                    // the initial connect() emission.
                    self.emit_segment(
                        flags::SYN | flags::ECE | flags::CWR,
                        self.iss,
                        0,
                        &opts,
                        &[],
                    )?;
                    self.snd_nxt = self.iss.wrapping_add(1);
                    self.bump_snd_max();
                    self.arm_rto_for(self.snd_nxt);
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
                    } else {
                        self.emit_synack_from_state()?;
                        self.snd_nxt = self.iss.wrapping_add(1);
                        self.bump_snd_max();
                        self.arm_rto_for(self.snd_nxt);
                    }
                }
            }
        }
        // ---- Delayed-ACK expiry -----------------------------------------
        if self.pending_ack {
            if let Some(d) = self.ack_deadline {
                if self.now_ms >= d && self.tx_len == 0 {
                    self.send_pure_ack()?;
                }
            }
        }
        // ---- Persist (zero-window probe) timer --------------------------
        self.check_persist()?;
        // ---- Try to push outbound data / FIN ----------------------------
        if self.tx_len == 0 {
            self.maybe_send_data()?;
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
                self.emit_segment(flags::RST, seg.ack, 0, &TcpOptions::NONE, &[])?;
                return Ok(());
            }
            // SYN-ACK accepted → ESTABLISHED.
            self.irs = seg.seq;
            self.rcv_nxt = seg.seq.wrapping_add(1);
            self.snd_una = seg.ack;
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
                self.rcv_wscale = LOCAL_WS_SHIFT;
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
            self.emit_segment(
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
            self.emit_segment(flags::RST, seg.ack, 0, &TcpOptions::NONE, &[])?;
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
            self.rcv_wscale = LOCAL_WS_SHIFT;
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

        // Emit SYN-ACK.
        self.emit_synack_from_state()?;
        self.snd_nxt = self.iss.wrapping_add(1);
        self.bump_snd_max();

        self.state = State::SynRcvd;
        self.syn_rcvd_retries = 0;
        self.arm_rto_for(self.snd_nxt);
        Ok(())
    }

    /// Stateless cookie path: compute a SYN-cookie ISN, emit a SYN-ACK
    /// directly without touching connection state, and remain in LISTEN.
    /// The third ACK will recover all state by validating the cookie.
    fn emit_cookie_synack(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if self.tx_len > 0 {
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
            sack: None,
        };
        let win =
            u16::try_from(self.advertised_window().min(u16::MAX as u32)).unwrap_or(u16::MAX);
        // Direct emit so we don't mutate any per-connection state — staying
        // in LISTEN is the whole point of this path. IP TOS is NOT_ECT:
        // SYN-ACK segments MUST NOT be ECT-marked (RFC 3168 §6.1.1), and
        // cookie-promoted connections don't negotiate ECN anyway.
        let n = wire::emit(
            &mut self.tx_buf,
            self.local.ip,
            seg.src_ip,
            self.local.port,
            seg.src_port,
            cookie,
            ack,
            flags::SYN | flags::ACK,
            win,
            &opts,
            &[],
            self.ip_id,
            wire::ecn::NOT_ECT,
        )?;
        self.ip_id = self.ip_id.wrapping_add(1);
        self.tx_len = n;
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
            let expected =
                self.compute_cookie(bucket, seg.src_ip, seg.src_port, mss_idx, peer_seq);
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
    fn emit_synack_from_state(&mut self) -> Result<(), TcpError> {
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
            sack: None,
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
            self.emit_segment(flags::RST, seg.ack, 0, &TcpOptions::NONE, &[])?;
            return Ok(());
        }
        // SYN retransmit: idempotent if SEQ matches our recorded `irs`.
        if seg.has(flags::SYN) {
            if seg.seq == self.irs {
                self.emit_synack_from_state()?;
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
            self.emit_segment(flags::RST, seg.ack, 0, &TcpOptions::NONE, &[])?;
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

        // Sequence-number acceptability test (RFC 793 §3.3).
        if !self.in_window(seg.seq, seg.payload.len() as u32) {
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

    /// Buffer an out-of-order in-window segment in the single-hole reassembly
    /// queue. Returns `true` if any bytes were absorbed.
    ///
    /// We only accept payloads that abut the held run (or form the first
    /// run): segments that would create a second hole are dropped, and
    /// retransmission recovers them. This is a deliberate simplification —
    /// see [`REASM_CAP`](crate::REASM_CAP).
    fn accept_oo_segment(&mut self, seq: u32, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }
        // Must be strictly after rcv_nxt; the in-order path handles equality.
        if !seq_gt(seq, self.rcv_nxt) {
            return false;
        }

        if self.oo_len == 0 {
            // First OOO segment: clip to capacity and store.
            let n = payload.len().min(REASM_CAP);
            let dst = match self.oo_buf.get_mut(..n) {
                Some(d) => d,
                None => return false,
            };
            let src = match payload.get(..n) {
                Some(s) => s,
                None => return false,
            };
            dst.copy_from_slice(src);
            self.oo_start = seq;
            self.oo_len = n;
            return n > 0;
        }

        let held_end = self.oo_start.wrapping_add(self.oo_len as u32);

        // Append: new segment abuts (or duplicates the trailing edge of)
        // the held run.
        if seq == held_end {
            let space = REASM_CAP.saturating_sub(self.oo_len);
            let n = payload.len().min(space);
            if n == 0 {
                return false;
            }
            let off = self.oo_len;
            let dst = match self.oo_buf.get_mut(off..off + n) {
                Some(d) => d,
                None => return false,
            };
            let src = match payload.get(..n) {
                Some(s) => s,
                None => return false,
            };
            dst.copy_from_slice(src);
            self.oo_len += n;
            return true;
        }

        // Prepend: new segment ends right where the held run begins.
        let new_end = seq.wrapping_add(payload.len() as u32);
        if new_end == self.oo_start {
            let prepend = payload.len();
            let new_total = prepend.saturating_add(self.oo_len).min(REASM_CAP);
            // Held bytes we can still keep after shifting right by `prepend`.
            let kept = new_total.saturating_sub(prepend);
            if kept > 0 && prepend < REASM_CAP {
                self.oo_buf.copy_within(0..kept, prepend);
            }
            let n = prepend.min(REASM_CAP);
            let dst = match self.oo_buf.get_mut(..n) {
                Some(d) => d,
                None => return false,
            };
            let src = match payload.get(..n) {
                Some(s) => s,
                None => return false,
            };
            dst.copy_from_slice(src);
            self.oo_start = seq;
            self.oo_len = new_total;
            return true;
        }

        // Anything else (gap or unrelated) is dropped — single-hole only.
        false
    }

    /// If `rcv_nxt` now equals `oo_start`, flush the held OOO run into the
    /// receive ring. Returns the number of bytes drained.
    fn drain_reassembly(&mut self) -> usize {
        if self.oo_len == 0 || self.rcv_nxt != self.oo_start {
            return 0;
        }
        let src = match self.oo_buf.get(..self.oo_len) {
            Some(s) => s,
            None => return 0,
        };
        let written = self.recv_ring.write(src);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(written as u32);
        if written < self.oo_len {
            // Partial drain (recv_ring filled): keep the remainder.
            self.oo_buf.copy_within(written..self.oo_len, 0);
            self.oo_len -= written;
            self.oo_start = self.oo_start.wrapping_add(written as u32);
        } else {
            self.oo_len = 0;
            self.oo_start = 0;
        }
        self.rcv_wnd = self.advertised_window();
        written
    }

    /// Bytes we can advertise as available. Held OOO bytes already consumed
    /// receive-buffer headroom, so subtract them from the ring's free space.
    #[inline]
    fn advertised_window(&self) -> u32 {
        let free = self.recv_ring.free();
        free.saturating_sub(self.oo_len) as u32
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
            // 2. **RFC 2018 SACK** — any ACK (pure OR piggybacked) that
            //    carries a SACK block. The block is authoritative evidence
            //    that data above `snd_una` was received, so a hole exists
            //    and we should retransmit immediately. We don't need three
            //    duplicates; one SACK ACK is enough. The repeat-suppression
            //    flag (`sack_recovery_seq`) prevents repeated cwnd
            //    collapses inside one recovery epoch.
            //
            // The window-unchanged condition is implicitly enforced by
            // `update_send_window` happening after this branch returns;
            // a window update by itself does not count as a dup-ACK.
            if ack == self.snd_una
                && seq_gt(self.snd_nxt, self.snd_una)
                && self.scale_peer_window(seg.window) == self.snd_wnd
            {
                let sack_trigger = self.sack_enabled
                    && seg.options.sack.is_some()
                    && self.sack_recovery_seq != Some(self.snd_una);
                let pure_dup = seg.payload.is_empty() && !seg.has(flags::FIN);
                let trigger = if sack_trigger {
                    true
                } else if pure_dup {
                    self.cc.on_dup_ack()
                } else {
                    false
                };
                if trigger {
                    let flight = self.snd_nxt.wrapping_sub(self.snd_una);
                    // PRR Fast Recovery (RFC 6937): don't collapse cwnd to 1*MSS;
                    // ssthresh = FlightSize/2 and per-ACK pacing handles the rest.
                    // Recovery point is the high-water snd_max so a slow cumulative
                    // ACK doesn't prematurely exit recovery.
                    self.cc.enter_recovery(flight, self.snd_max);
                    self.snd_nxt = self.snd_una;
                    if let Some(p) = self.rtt_probe.as_mut() {
                        p.valid = false;
                    }
                    self.arm_rto_for(self.snd_una);
                    if sack_trigger {
                        self.sack_recovery_seq = Some(self.snd_una);
                    }
                }
            }
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
        // If a prior RTO or SACK-driven fast-retransmit rewound `snd_nxt`
        // to `snd_una`, but the peer's first cumulative ACK after recovery
        // jumps over the rewound point (because the peer had buffered our
        // pre-rewind segments out-of-order), our `snd_nxt` could now sit
        // **behind** the new `snd_una`. Pull it forward; the bytes between
        // old `snd_nxt` and `snd_una` are evidently already on the wire
        // and acknowledged, so we shouldn't re-emit them.
        if seq_gt(self.snd_una, self.snd_nxt) {
            self.snd_nxt = self.snd_una;
        }
        // ---- PRR per-ACK update / recovery exit -------------------------
        // Order matters: update DeliveredData *before* exit check so the
        // ACK that crosses recovery_point still credits prr_delivered.
        // `pipe` estimate: without an RFC 6675 SACK scoreboard we use
        // post-advance `snd_nxt - snd_una`, which is conservative.
        let pipe = self.snd_nxt.wrapping_sub(self.snd_una);
        self.cc.on_ack_in_recovery(acked, pipe);
        let _ = self.cc.check_exit_recovery(self.snd_una);
        // A fresh ACK ends the current SACK-driven recovery epoch, if any.
        // The next SACK-bearing dup-ACK at the new `snd_una` is then again
        // eligible to trigger fast-retransmit.
        self.sack_recovery_seq = None;

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

    /// Either send queued data, or, if the local app has called `close` and
    /// the buffer has drained, send a FIN.
    fn maybe_send_data(&mut self) -> Result<(), TcpError> {
        if self.tx_len > 0 {
            return Ok(());
        }
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

        let flight = self.snd_nxt.wrapping_sub(self.snd_una);
        let allowed = self.cc.allowed(self.snd_wnd);

        // ---- Zero-window: arm persist timer instead of sending ----------
        if self.snd_wnd == 0 {
            let unsent = (self.send_ring.len() as u32).saturating_sub(flight);
            if unsent > 0 && self.persist_deadline.is_none() {
                self.persist_backoff_ms = self.rto_ms;
                self.persist_deadline =
                    Some(self.now_ms.wrapping_add(self.persist_backoff_ms as u64));
            }
            return Ok(());
        }

        if flight >= allowed {
            return Ok(());
        }
        // Per-segment send budget = min(cwnd-flight, peer_wnd-flight,
        //                               PRR snd_credit, unsent, mss).
        // Outside recovery, snd_credit is u32::MAX (a no-op clamp).
        let window = core::cmp::min(allowed - flight, self.cc.snd_credit());
        let unsent = (self.send_ring.len() as u32).saturating_sub(flight);
        let mss_payload = self.effective_payload_mss();
        let payload_bytes =
            core::cmp::min(window, core::cmp::min(unsent, mss_payload as u32)) as usize;

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
            self.emit_segment(
                flags::ACK | flags::PSH,
                seq,
                self.rcv_nxt,
                &opts,
                payload_slice,
            )?;
            self.snd_nxt = self.snd_nxt.wrapping_add(payload_bytes as u32);
            self.bump_snd_max();
            // Account for PRR send credit consumption (no-op outside recovery).
            self.cc.on_send(payload_bytes as u32);
            // Piggybacked ACK clears delayed-ACK state.
            self.pending_ack = false;
            self.delayed_ack_count = 0;
            self.ack_deadline = None;
            if self.rto_deadline.is_none() {
                self.arm_rto_for(self.snd_nxt);
            }
            return Ok(());
        }

        // Nothing to send → maybe transmit FIN. Outside recovery `window`
        // is unconstrained by PRR; inside recovery the FIN consumes one
        // sequence number and one byte of credit.
        let need_fin = matches!(
            self.state,
            State::FinWait1 | State::Closing | State::LastAck
        ) && !self.fin_sent
            && self.send_ring.is_empty()
            && window > 0;
        if need_fin {
            self.fin_seq = self.snd_nxt;
            let opts = self.data_options();
            self.emit_segment(
                flags::FIN | flags::ACK,
                self.snd_nxt,
                self.rcv_nxt,
                &opts,
                &[],
            )?;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.bump_snd_max();
            self.cc.on_send(1);
            self.fin_sent = true;
            self.pending_ack = false;
            self.delayed_ack_count = 0;
            self.ack_deadline = None;
            if self.rto_deadline.is_none() {
                self.arm_rto_for(self.snd_nxt);
            }
        }
        Ok(())
    }

    fn check_persist(&mut self) -> Result<(), TcpError> {
        let deadline = match self.persist_deadline {
            Some(d) => d,
            None => return Ok(()),
        };
        if self.now_ms < deadline || self.tx_len > 0 {
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
            self.emit_segment(flags::ACK | flags::PSH, seq, self.rcv_nxt, &opts, &byte)?;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.bump_snd_max();
            if self.rto_deadline.is_none() {
                self.arm_rto_for(self.snd_nxt);
            }
        }
        // Exponential back-off, capped at RTO_MAX_MS.
        let next = self.persist_backoff_ms.saturating_mul(2);
        self.persist_backoff_ms = next.clamp(RTO_MIN_MS, RTO_MAX_MS);
        self.persist_deadline = Some(self.now_ms.wrapping_add(self.persist_backoff_ms as u64));
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Emission helpers
    // ---------------------------------------------------------------------

    fn send_pure_ack(&mut self) -> Result<(), TcpError> {
        if self.tx_len > 0 {
            return Ok(());
        }
        let opts = self.data_options();
        self.emit_segment(flags::ACK, self.snd_nxt, self.rcv_nxt, &opts, &[])?;
        self.pending_ack = false;
        self.delayed_ack_count = 0;
        self.ack_deadline = None;
        Ok(())
    }

    fn emit_segment(
        &mut self,
        flag_bits: u8,
        seq: u32,
        ack: u32,
        options: &TcpOptions,
        payload: &[u8],
    ) -> Result<(), TcpError> {
        if self.tx_len > 0 {
            // Caller hasn't drained the previous packet — the retransmit
            // timer or a subsequent ACK-clocked send will redrive us.
            return Ok(());
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

        let n = wire::emit(
            &mut self.tx_buf,
            self.local.ip,
            self.remote.ip,
            self.local.port,
            self.remote.port,
            seq,
            ack,
            adjusted_flags,
            window,
            options,
            payload,
            self.ip_id,
            ecn_codepoint,
        )?;
        self.ip_id = self.ip_id.wrapping_add(1);
        self.tx_len = n;
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Timing / RTT / windowing helpers
    // ---------------------------------------------------------------------

    fn data_options(&self) -> TcpOptions {
        // Attach a single SACK block describing the held out-of-order run,
        // if SACK was negotiated and we have one. RFC 2018 §4: SACK blocks
        // are sent on dup-ACKs **and** on regular ACKs while data is being
        // held; either is fine because the peer's sender ignores SACK
        // blocks below `snd_una` anyway.
        let sack = if self.sack_enabled && self.oo_len > 0 {
            let left = self.oo_start;
            let right = self.oo_start.wrapping_add(self.oo_len as u32);
            Some((left, right))
        } else {
            None
        };
        if self.ts_enabled {
            TcpOptions {
                mss: None,
                wscale: None,
                ts: Some((self.ts_val(), self.ts_recent)),
                sack_permitted: false,
                sack,
            }
        } else if sack.is_some() {
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
