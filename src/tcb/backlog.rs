//! A listener's backlog of pending handshakes.
//!
//! A TCB is one connection, so a listener can hold one handshake in its own
//! state (`SYN_RCVD`: "the slot"). With nothing else, every handshake that
//! overlaps another fell to SYN cookies, which cannot carry window scaling
//! or SACK without timestamps and cannot repeat a SYN-ACK. The backlog
//! keeps up to [`BACKLOG`] further half-opens as small records beside the
//! slot: each remembers its peer, sequence numbers and options, has its
//! SYN-ACK retransmitted on its own timer, and is moved into the slot when
//! its peer's ACK arrives (the slot's half-open takes its place in the
//! table). Cookies are then what they are on Linux: the answer once the
//! backlog is full.
//!
//! When a handshake completes, the TCB becomes that connection and the
//! half-opens still pending in it stop being served: the host moves them to
//! its next listener with [`Tcb::adopt_half_opens`]. A host that does not
//! loses nothing it had before the backlog existed: every SYN-ACK is a
//! cookie (see `cookie.rs`), so such a client's ACK completes statelessly
//! at the next listener, unless it offered options no cookie carries.

use super::{
    Deadline, Endpoint, Tcb, DEFAULT_PEER_MSS, MAX_SYN_RCVD_RETRIES, MIN_PEER_MSS, RTO_MAX_MS,
};
use crate::error::TcpError;
use crate::state::State;
use crate::wire::{self, flags, SackBlocks, Segment, TcpOptions};

/// Half-opens a listener holds beside the one in its slot.
pub const BACKLOG: usize = 8;

/// [`HalfOpen::wscale`] when the client offered no window scaling.
const NO_WSCALE: u8 = 0xFF;

/// One pending handshake: what the client's SYN said and what our SYN-ACK
/// answered. All-zero is an unused record (so a zero-filled TCB is valid).
#[derive(Copy, Clone, Debug)]
pub(super) struct HalfOpen {
    used: bool,
    remote: Endpoint,
    /// The client's ISN and ours.
    irs: u32,
    iss: u32,
    ts_offset: u32,
    /// The client's TSval (if `ts`).
    ts_recent: u32,
    /// When our first SYN-ACK left, and when the next is due.
    syn_ms: u64,
    deadline: u64,
    /// The SYN's (unscaled) window and MSS.
    wnd: u16,
    mss: u16,
    wscale: u8,
    ts: bool,
    sack: bool,
    ecn: bool,
    /// SYN-ACK retransmissions so far.
    retries: u8,
}

impl HalfOpen {
    const UNUSED: Self = Self {
        used: false,
        remote: Endpoint {
            ip: [0; 4],
            port: 0,
        },
        irs: 0,
        iss: 0,
        ts_offset: 0,
        ts_recent: 0,
        syn_ms: 0,
        deadline: 0,
        wnd: 0,
        mss: 0,
        wscale: 0,
        ts: false,
        sack: false,
        ecn: false,
        retries: 0,
    };
}

impl<const BUF: usize, const RTX: usize, const TXQ: usize> Tcb<BUF, RTX, TXQ> {
    /// Drop every pending half-open (the TCB stops being, or starts over
    /// as, a listener).
    pub(super) fn backlog_clear(&mut self) {
        self.backlog = [HalfOpen::UNUSED; BACKLOG];
    }

    /// How many half-opens a listener may hold beside its slot (default and
    /// most: [`BACKLOG`]; 0 answers every overlapping SYN with a cookie).
    /// Lowering it does not drop half-opens already held.
    pub fn set_listen_backlog(&mut self, n: usize) {
        self.backlog_limit = n.min(BACKLOG) as u8;
    }

    /// Pending half-opens held beside the slot (diagnostic).
    pub fn pending_half_opens(&self) -> usize {
        self.backlog.iter().filter(|h| h.used).count()
    }

    fn backlog_find(&self, remote: Endpoint) -> Option<usize> {
        self.backlog
            .iter()
            .position(|h| h.used && h.remote == remote)
    }

    /// A record for a new half-open: an unused one within the limit, else
    /// the one whose SYN-ACK went unanswered longest (most retransmissions,
    /// at least one): typically a spoofed source.
    fn backlog_room(&self) -> Option<usize> {
        let limit = usize::from(self.backlog_limit);
        let held = self.backlog.iter().filter(|h| h.used).count();
        if held < limit {
            return self.backlog.iter().position(|h| !h.used);
        }
        self.backlog_stale().map(|(i, _)| i)
    }

    /// Whether a half-open with this ISS completes from its ACK alone if
    /// its record is lost: its SYN-ACK was a cookie (see `cookie.rs`).
    fn cookie_carried(&self, iss: u32) -> bool {
        self.cookie_secret_set && (iss >> 30) as u8 != super::cookie::COOKIE_STATEFUL_ONLY
    }

    /// A record whose half-open completes by its cookie without it (of any
    /// age; the most retransmitted, then the oldest), to give to one that
    /// cannot.
    fn backlog_carried(&self) -> Option<usize> {
        self.backlog
            .iter()
            .enumerate()
            .filter(|(_, h)| h.used && self.cookie_carried(h.iss))
            .max_by_key(|(_, h)| (h.retries, core::cmp::Reverse(h.syn_ms)))
            .map(|(i, _)| i)
    }

    /// The record to give up for a new half-open: one whose SYN-ACK already
    /// went unanswered (at least one retransmission), preferring one that
    /// still completes by its cookie, then the most retransmissions.
    fn backlog_stale(&self) -> Option<(usize, HalfOpen)> {
        self.backlog
            .iter()
            .enumerate()
            .filter(|(_, h)| h.used && h.retries >= 1)
            .max_by_key(|(_, h)| (self.cookie_carried(h.iss), h.retries))
            .map(|(i, h)| (i, *h))
    }

    fn backlog_put(&mut self, i: usize, h: HalfOpen) {
        if let Some(slot) = self.backlog.get_mut(i) {
            *slot = h;
        }
    }

    fn backoff_for(&self, retries: u8) -> u64 {
        u64::from(self.init_rto_ms)
            .saturating_mul(1u64 << u32::from(retries.min(16)))
            .min(u64::from(RTO_MAX_MS))
    }

    /// The half-open a SYN starts: our ISN (a cookie where a cookie can
    /// carry the client's options) and what the SYN offered.
    fn half_open_from_syn(&mut self, seg: &Segment<'_>) -> HalfOpen {
        let remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        let (iss, ts_offset) = match self.stateful_cookie_iss(seg) {
            Some(iss) => (iss, self.current_cookie_ts_offset(remote)),
            None => (
                self.passive_iss(remote, seg.seq),
                self.ts_offset_for(remote),
            ),
        };
        HalfOpen {
            used: true,
            remote,
            irs: seg.seq,
            iss,
            ts_offset,
            ts_recent: seg.options.ts.map_or(0, |(v, _)| v),
            syn_ms: self.now_ms,
            deadline: self.now_ms.saturating_add(self.backoff_for(0)),
            wnd: seg.window,
            mss: seg
                .options
                .mss
                .unwrap_or(DEFAULT_PEER_MSS)
                .max(MIN_PEER_MSS),
            wscale: seg.options.wscale.map_or(NO_WSCALE, |w| w.min(14)),
            ts: seg.options.ts.is_some(),
            sack: seg.options.sack_permitted,
            ecn: seg.has(flags::ECE) && seg.has(flags::CWR),
            retries: 0,
        }
    }

    /// The slot's half-open as a record (the TCB is a listener in
    /// `SYN_RCVD`).
    fn slot_as_half_open(&self) -> HalfOpen {
        HalfOpen {
            used: true,
            remote: self.remote,
            irs: self.irs,
            iss: self.iss,
            ts_offset: self.ts_offset,
            ts_recent: self.ts_recent,
            syn_ms: self.syn_xmit_ms,
            deadline: self
                .rto_deadline
                .get()
                .unwrap_or_else(|| self.now_ms.saturating_add(u64::from(self.rto_ms))),
            wnd: u16::try_from(self.snd_wnd).unwrap_or(u16::MAX),
            mss: self.peer_mss,
            wscale: if self.ws_ok {
                self.snd_wscale
            } else {
                NO_WSCALE
            },
            ts: self.ts_enabled,
            sack: self.sack_enabled,
            ecn: self.ecn_enabled,
            retries: self.syn_rcvd_retries,
        }
    }

    /// Make `h` the slot's half-open: the TCB's own `SYN_RCVD` state, as
    /// `accept_syn_stateful` leaves it after sending the SYN-ACK.
    fn load_half_open(&mut self, h: HalfOpen) {
        self.reset_connection_state();
        self.remote = h.remote;
        self.iss = h.iss;
        self.ts_offset = h.ts_offset;
        self.seed_ip_id();
        self.snd_una = h.iss;
        self.snd_acked = 0;
        self.snd_nxt = h.iss.wrapping_add(1);
        self.syn_unacked = true;
        self.irs = h.irs;
        self.rcv_nxt = h.irs.wrapping_add(1);
        self.last_ack_sent = self.rcv_nxt;
        // The SYN-ACK offered the (unscaled) free space: never shrink it.
        let offered = self.recv_ring.free().min(usize::from(u16::MAX)) as u32;
        self.rcv_adv_edge = self.rcv_nxt.wrapping_add(offered);
        self.snd_wnd = u32::from(h.wnd);
        self.max_snd_wnd = self.snd_wnd;
        self.snd_wl1 = h.irs;
        self.snd_wl2 = 0;
        self.peer_mss = h.mss;
        if h.wscale != NO_WSCALE {
            self.ws_ok = true;
            self.snd_wscale = h.wscale;
            self.rcv_wscale = Self::WS;
        }
        if h.ts {
            self.ts_enabled = true;
            self.ts_recent = h.ts_recent;
            self.ts_recent_stamp = h.syn_ms;
        }
        self.sack_enabled = h.sack;
        self.ecn_enabled = h.ecn;
        self.state = State::SynRcvd;
        self.syn_rcvd_retries = h.retries;
        self.syn_xmit_ms = h.syn_ms;
        self.syn_retransmitted = h.retries > 0;
        self.rto_ms = u32::try_from(self.backoff_for(h.retries)).unwrap_or(RTO_MAX_MS);
        self.rto_deadline = Deadline::at(h.deadline);
    }

    /// SYN-ACK for a half-open held in the table: built from the record,
    /// as the slot's is from the TCB's state. IP ID 0, like every packet a
    /// listener sends a would-be peer.
    fn emit_half_open_synack(&mut self, h: &HalfOpen) -> Result<(), TcpError> {
        if self.tx_ring.is_full() {
            return Ok(()); // the timer, or the client's next SYN, repeats it
        }
        let ws = (h.wscale != NO_WSCALE).then_some(h.wscale);
        let opts = TcpOptions {
            mss: Some(self.local_mss),
            wscale: ws.map(|_| Self::WS),
            ts: h.ts.then(|| {
                (
                    self.cookie_tsval(h.ts_offset, ws, h.sack, h.ecn),
                    h.ts_recent,
                )
            }),
            sack_permitted: h.sack,
            sack: SackBlocks::EMPTY,
        };
        let win =
            u16::try_from(self.recv_ring.free().min(usize::from(u16::MAX))).unwrap_or(u16::MAX);
        let fl = flags::SYN | flags::ACK | if h.ecn { flags::ECE } else { 0 };
        let (local_ip, local_port) = (self.local.ip, self.local.port);
        let (seq, ack, remote) = (h.iss, h.irs.wrapping_add(1), h.remote);
        let full_csum = !self.tx_csum_offload;
        let queued = self.tx_ring.push_with(|buf| {
            wire::emit_with(
                buf,
                local_ip,
                remote.ip,
                local_port,
                remote.port,
                seq,
                ack,
                fl,
                win,
                &opts,
                0,
                |_| true,
                0,
                wire::ecn::NOT_ECT,
                full_csum,
            )
        })?;
        if queued {
            self.stats.segs_out = self.stats.segs_out.saturating_add(1);
        }
        Ok(())
    }

    /// A SYN from a peer other than the slot's, at a listener in
    /// `SYN_RCVD`. `Ok(true)` if the backlog took it (a new half-open, or
    /// the SYN-ACK of one it holds, repeated); `Ok(false)` if it is full of
    /// half-opens still within their first RTO: the caller falls back.
    pub(super) fn backlog_syn(&mut self, seg: &Segment<'_>) -> Result<bool, TcpError> {
        let remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        let i = match self.backlog_find(remote) {
            Some(i) => {
                // Its SYN again: our SYN-ACK was lost. With another ISN the
                // client may have started over, or the SYN is spoofed (it
                // takes only the 4-tuple): while the SYN-ACK has not gone
                // unanswered, the record stands and the SYN-ACK is repeated.
                // A client that did start over answers it with a RST, which
                // frees the record for its next SYN; a spoofer cannot.
                // After an unanswered RTO the new SYN starts the record over.
                let fresh = |h: &HalfOpen| h.irs == seg.seq || h.retries == 0;
                if let Some(h) = self.backlog.get(i).copied().filter(fresh) {
                    self.emit_half_open_synack(&h)?;
                    return Ok(true);
                }
                i
            }
            // No unused or stale record: a client no cookie can carry
            // takes the record of one that completes by its cookie anyway.
            None => match self.backlog_room().or_else(|| {
                (!super::cookie::cookie_can_carry(seg))
                    .then(|| self.backlog_carried())
                    .flatten()
            }) {
                // The half-open that gives up its record has its cookie left.
                Some(i) => {
                    if self.backlog.get(i).is_some_and(|h| h.used) {
                        self.note_cookie_pressure();
                    }
                    i
                }
                None => return Ok(false),
            },
        };
        let h = self.half_open_from_syn(seg);
        self.backlog_put(i, h);
        self.emit_half_open_synack(&h)?;
        Ok(true)
    }

    /// A RST from a peer other than the slot's: at exactly its half-open's
    /// `RCV.NXT` (RFC 5961 §3.2, as in `SYN_RCVD`) it ends that half-open.
    pub(super) fn backlog_rst(&mut self, seg: &Segment<'_>) -> bool {
        let remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        if let Some(i) = self.backlog_find(remote) {
            if let Some(h) = self.backlog.get_mut(i) {
                if seg.seq == h.irs.wrapping_add(1) {
                    h.used = false;
                    return true;
                }
            }
        }
        false
    }

    /// An ACK of a table half-open's SYN-ACK: move that half-open into the
    /// slot (the slot's goes to the table in its place), for `on_syn_rcvd`
    /// to complete as it does the slot's. Returns whether one matched.
    pub(super) fn backlog_take_for_ack(&mut self, seg: &Segment<'_>) -> bool {
        let remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        let Some(i) = self.backlog_find(remote) else {
            return false;
        };
        let Some(h) = self.backlog.get(i).copied() else {
            return false;
        };
        if seg.ack != h.iss.wrapping_add(1) {
            return false;
        }
        let slot = self.slot_as_half_open();
        self.backlog_put(i, slot);
        self.load_half_open(h);
        true
    }

    /// The slot is about to be given to a cookie connection: keep its
    /// half-open in the table if there is room, and forget any record of
    /// the peer the cookie belongs to.
    pub(super) fn backlog_keep_slot(&mut self, cookie_peer: Endpoint) {
        if let Some(i) = self.backlog_find(cookie_peer) {
            self.backlog_put(i, HalfOpen::UNUSED);
        }
        if self.state == State::SynRcvd && self.is_listener {
            let slot = self.slot_as_half_open();
            // An unused record; else, for a half-open that needs one (no
            // cookie carries its options), the record of one that does not,
            // of any age; else a stale one, but never a half-open that
            // needs its record for one that does not.
            let needs = !self.cookie_carried(slot.iss);
            let room = self
                .backlog
                .iter()
                .position(|h| !h.used)
                .or_else(|| needs.then(|| self.backlog_carried()).flatten())
                .or_else(|| {
                    self.backlog_stale()
                        .filter(|(_, h)| self.cookie_carried(h.iss) || needs)
                        .map(|(i, _)| i)
                });
            // Whichever half-open loses its place has its cookie left.
            if room.is_none_or(|i| self.backlog.get(i).is_some_and(|h| h.used)) {
                self.note_cookie_pressure();
            }
            if let Some(i) = room {
                self.backlog_put(i, slot);
            }
        }
    }

    /// The slot's half-open ended (RST, SYN-ACK budget spent) and the TCB
    /// is back in `LISTEN`: the oldest pending half-open takes the slot.
    pub(super) fn backlog_refill_slot(&mut self) {
        if self.state != State::Listen || !self.is_listener {
            return;
        }
        let next = self
            .backlog
            .iter()
            .enumerate()
            .filter(|(_, h)| h.used)
            .min_by_key(|(_, h)| h.syn_ms)
            .map(|(i, h)| (i, *h));
        if let Some((i, h)) = next {
            self.backlog_put(i, HalfOpen::UNUSED);
            self.load_half_open(h);
        }
    }

    /// Retransmit the SYN-ACKs that are due; a half-open whose budget is
    /// spent is dropped.
    pub(super) fn backlog_timers(&mut self) -> Result<(), TcpError> {
        let now = self.now_ms;
        for i in 0..BACKLOG {
            let Some(mut h) = self.backlog.get(i).copied() else {
                continue;
            };
            if !h.used || now < h.deadline {
                continue;
            }
            h.retries = h.retries.saturating_add(1);
            if h.retries > MAX_SYN_RCVD_RETRIES {
                self.backlog_put(i, HalfOpen::UNUSED);
                continue;
            }
            h.deadline = now.saturating_add(self.backoff_for(h.retries));
            self.backlog_put(i, h);
            self.emit_half_open_synack(&h)?;
        }
        Ok(())
    }

    /// When the earliest table SYN-ACK is due (a listener in `SYN_RCVD`).
    pub(super) fn backlog_deadline(&self) -> Option<u64> {
        if self.state != State::SynRcvd || !self.is_listener {
            return None;
        }
        self.backlog
            .iter()
            .filter(|h| h.used)
            .map(|h| h.deadline)
            .min()
    }

    /// Move the half-opens still pending in `from` — a listener that has
    /// become a connection (or closed) — into this listener, which goes on
    /// serving them: their SYN-ACK retransmissions, and their ACKs when the
    /// host routes them here. Returns how many were taken (those that find
    /// no room within this listener's backlog stay in `from`; one for a
    /// peer either TCB already has is dropped). Call it when setting up the
    /// listener that replaces `from`, right after [`Tcb::listen`] and
    /// before routing packets to it; both must share the local endpoint and
    /// secrets. Nothing is taken from a TCB that is still listening.
    ///
    /// Hosts should always call this: a pending client left behind has only
    /// its cookie, which completes the handshake only if the client's first
    /// segment arrives first and intact, and not at all for a client that
    /// offered window scaling, SACK or ECN without timestamps.
    pub fn adopt_half_opens(&mut self, from: &mut Self) -> usize {
        let listening = |t: &Self| matches!(t.state, State::Listen | State::SynRcvd);
        if !self.is_listener
            || !listening(self)
            || self.local != from.local
            || (from.is_listener && listening(from))
        {
            return 0;
        }
        // Handshakes that depended on their cookie at `from` still do here.
        self.cookie_until_ms = self.cookie_until_ms.max(from.cookie_until_ms);
        let mut taken = 0;
        let limit = usize::from(self.backlog_limit);
        // Oldest first; each round frees a record of `from` or stops.
        while let Some((fi, h)) = from
            .backlog
            .iter()
            .enumerate()
            .filter(|(_, h)| h.used)
            .min_by_key(|(_, h)| h.syn_ms)
            .map(|(i, h)| (i, *h))
        {
            // A half-open for a peer `from` is connected to, or one this
            // listener already holds, is stale: drop it.
            let known = h.remote == from.remote
                || (self.state == State::SynRcvd && h.remote == self.remote)
                || self.backlog_find(h.remote).is_some();
            if !known {
                if self.state == State::Listen {
                    self.load_half_open(h);
                } else {
                    let held = self.backlog.iter().filter(|s| s.used).count();
                    let Some(i) = self
                        .backlog
                        .iter()
                        .position(|s| !s.used)
                        .filter(|_| held < limit)
                    else {
                        // Those left behind have their cookies.
                        self.note_cookie_pressure();
                        break;
                    };
                    self.backlog_put(i, h);
                }
                taken += 1;
            }
            if let Some(rec) = from.backlog.get_mut(fi) {
                rec.used = false;
            }
        }
        taken
    }
}
