//! SYN cookies (RFC 4987), keyed hashing and per-connection secrets.
//!
//! The cookie ISN carries a 2-bit MSS index, the parity of its 64 s time
//! bucket and a 29-bit SipHash MAC of the 4-tuple, the peer's ISN, the
//! bucket and the MSS index. A forged ACK therefore gets one guess per key
//! (2⁻²⁹, as Linux): the cookie names its bucket.
//! When the peer offers timestamps, the SYN-ACK's TSval additionally
//! encodes the peer's window scale, SACK-permitted and ECN in its low 6
//! bits (as Linux does), so a cookie-promoted connection keeps window
//! scaling and SACK. They are read back only from a TSecr that echoes a
//! TSval the SYN-ACK could have carried; a TSopt the SYN-ACK did not offer
//! echoes nothing of ours and is ignored (RFC 7323 §3.2).
//!
//! Listeners are hybrid: the slot and the backlog (see `backlog.rs`) hold
//! half-opens statefully (keeping every option), and cookies answer SYNs
//! once those are taken. A stateful SYN-ACK is a cookie as well, so a
//! half-open that loses its place (to another peer's cookie ACK, to a new
//! SYN once its SYN-ACK went unanswered, or left behind in a listener that
//! became a connection) still completes from its ACK alone, at whichever
//! listener gets it. Only a client that offered window scaling, SACK or ECN
//! without timestamps cannot: nothing carries those options, so its ISN
//! says so (MSS index 3) and its ACK is refused with a RST instead of
//! becoming a connection that disagrees with the client about them.
//! Any listener holding the key takes a cookie ACK, whenever it comes
//! (Linux only within two minutes of the listener's last overflow,
//! `tcp_synq_no_recent_overflow`): one connection per TCB, so the listener
//! that sent the cookie has often become a connection by then, and the
//! host's next listener must take it. A cookie validates against the
//! current key and, after a rotation, the previous one while cookies
//! issued under it can still be valid. The key is either installed
//! explicitly or derived from the host secret.

use super::{seq_gt, Endpoint, Tcb, DEFAULT_PEER_MSS, MIN_PEER_MSS};
use crate::error::TcpError;
use crate::state::State;
use crate::wire::{self, flags, SackBlocks, Segment, TcpOptions};

/// SYN-cookie time-bucket width; cookies validate for the current and the
/// previous bucket (64–128 s).
pub(super) const COOKIE_TIME_BUCKET_MS: u64 = 64_000;

/// Quantised peer-MSS values selectable by the cookie's top 2 bits (our own
/// segments carry at most 1460 bytes anyway).
const COOKIE_MSS_TABLE: [u16; 3] = [536, 1300, 1460];

/// The fourth MSS index: the ISN of a stateful half-open whose options no
/// cookie can carry (see the module docs). It never validates as a cookie.
pub(super) const COOKIE_STATEFUL_ONLY: u8 = 3;

/// Low TSval bits used to carry SYN options through a cookie handshake.
const TS_OPT_BITS: u32 = 6;
const TS_OPT_MASK: u32 = (1 << TS_OPT_BITS) - 1;
const TS_OPT_WS_MASK: u32 = 0x0F; // 0..=14 peer shift, 15 = no window scaling
const TS_OPT_SACK: u32 = 0x10;
const TS_OPT_ECN: u32 = 0x20;

/// Oldest TSval a cookie SYN-ACK still being answered can have carried:
/// the cookie's two buckets plus the TSval's option-bit rounding (and its
/// step back from 0).
const COOKIE_TS_MAX_AGE: u32 = 2 * COOKIE_TIME_BUCKET_MS as u32 + (2 << TS_OPT_BITS);

/// Options recovered from a validated cookie.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct CookieOpts {
    pub mss: u16,
    pub wscale: Option<u8>,
    pub sack: bool,
    pub ecn: bool,
    /// Validated with the key in force before the last rotation.
    pub prev_key: bool,
    /// The ACK echoes the TSval of our cookie SYN-ACK: both ends have
    /// timestamps on.
    pub ts: bool,
}

impl<const BUF: usize, const RTX: usize, const TXQ: usize> Tcb<BUF, RTX, TXQ> {
    /// The keyed secret for per-connection derivations, if any.
    fn host_key(&self) -> Option<&[u8; 16]> {
        if self.secret_set {
            Some(&self.secret)
        } else if self.cookie_secret_set {
            Some(&self.cookie_secret)
        } else {
            None
        }
    }

    fn tuple_hash(
        key: &[u8; 16],
        local: Endpoint,
        remote: Endpoint,
        domain: u8,
        extra: u32,
    ) -> u64 {
        let mut buf = [0u8; 17];
        let parts: [&[u8]; 6] = [
            &local.ip,
            &local.port.to_be_bytes(),
            &remote.ip,
            &remote.port.to_be_bytes(),
            &[domain],
            &extra.to_be_bytes(),
        ];
        let mut at = 0usize;
        for p in parts {
            if let Some(d) = buf.get_mut(at..at + p.len()) {
                d.copy_from_slice(p);
            }
            at += p.len();
        }
        siphash24(key, buf.get(..at).unwrap_or(&buf))
    }

    /// Per-connection timestamp offset (RFC 7323 §5.4), keyed by the host
    /// secret so TSval reveals neither the host clock nor a cross-connection
    /// correlator. Without a secret the offset is 0: any unkeyed derivation
    /// (e.g. from the ISS, which the peer sees) would be trivially undone,
    /// so pretending otherwise would only hide the weakness. Hosts facing
    /// untrusted peers should call [`Tcb::set_secret`].
    pub(super) fn ts_offset_for(&self, remote: Endpoint) -> u32 {
        match self.host_key() {
            Some(k) => self.ts_offset_with(k, remote),
            None => 0,
        }
    }

    fn ts_offset_with(&self, key: &[u8; 16], remote: Endpoint) -> u32 {
        Self::tuple_hash(key, self.local, remote, b'T', 0) as u32
    }

    /// The timestamp offset of a cookie SYN-ACK to `remote`: keyed by the
    /// cookie key that issued it (the previous one after a rotation), so
    /// the TSecr check and the promoted connection's TSvals agree with the
    /// SYN-ACK whatever happened to the host secret since.
    fn cookie_ts_offset(&self, remote: Endpoint, prev_key: bool) -> u32 {
        let key = if prev_key {
            &self.prev_cookie_secret
        } else {
            &self.cookie_secret
        };
        self.ts_offset_with(key, remote)
    }

    /// RFC 6528 ISN for a passive open when a host secret is installed:
    /// keyed hash of the 4-tuple and the peer's ISN plus a 4 µs-rate clock,
    /// so every half-open (including a replacement) gets a fresh,
    /// unpredictable ISN. Without a secret the host-supplied ISS is used.
    pub(super) fn passive_iss(&self, remote: Endpoint, peer_isn: u32) -> u32 {
        match self.host_key() {
            Some(k) => {
                let h = Self::tuple_hash(k, self.local, remote, b'I', peer_isn) as u32;
                h.wrapping_add((self.now_ms as u32).wrapping_mul(250))
            }
            None => self.cfg_iss,
        }
    }

    /// ISS for an active open after the first on this TCB (the host's
    /// `iss` served that one): keyed like [`Self::passive_iss`], so it is
    /// unpredictable and never repeats the previous connection's. `None`
    /// without a secret.
    pub(super) fn next_active_iss(&self) -> Option<u32> {
        let k = self.host_key()?;
        let h = Self::tuple_hash(k, self.local, self.remote, b'A', self.cfg_iss) as u32;
        Some(h.wrapping_add((self.now_ms as u32).wrapping_mul(250)))
    }

    /// 32-bit cookie: top 2 bits = MSS index, then the parity of `bucket`,
    /// then a 29-bit MAC.
    pub(super) fn compute_cookie(
        &self,
        key: &[u8; 16],
        bucket: u64,
        remote: Endpoint,
        mss_idx: u8,
        peer_seq: u32,
    ) -> u32 {
        let mut buf = [0u8; 25];
        let fields: [&[u8]; 7] = [
            &bucket.to_be_bytes(),
            &remote.ip,
            &remote.port.to_be_bytes(),
            &self.local.ip,
            &self.local.port.to_be_bytes(),
            &peer_seq.to_be_bytes(),
            &[mss_idx & 0x3],
        ];
        let mut at = 0usize;
        for f in fields {
            if let Some(d) = buf.get_mut(at..at + f.len()) {
                d.copy_from_slice(f);
            }
            at += f.len();
        }
        let mac = siphash24(key, &buf);
        let macbits = (mac as u32) & 0x1FFF_FFFF;
        ((u32::from(mss_idx) & 0x3) << 30) | (((bucket & 1) as u32) << 29) | macbits
    }

    /// The TSval of a cookie SYN-ACK: the clock (plus `ts_off`) with its
    /// low bits replaced by the client's window scale, SACK-permitted and
    /// ECN, rounded so it never runs ahead of the clock.
    pub(super) fn cookie_tsval(
        &self,
        ts_off: u32,
        wscale: Option<u8>,
        sack: bool,
        ecn: bool,
    ) -> u32 {
        let now_ts = (self.now_ms as u32).wrapping_add(ts_off);
        let mut bits = match wscale {
            Some(ws) => u32::from(ws.min(14)),
            None => TS_OPT_WS_MASK,
        };
        if sack {
            bits |= TS_OPT_SACK;
        }
        if ecn {
            bits |= TS_OPT_ECN;
        }
        let mut tsval = (now_ts & !TS_OPT_MASK) | bits;
        if seq_gt(tsval, now_ts) {
            tsval = tsval.wrapping_sub(1 << TS_OPT_BITS);
        }
        // A TSecr of 0 echoes nothing (RFC 7323 §4.3), so never send a
        // TSval of 0: the echo turns timestamps on.
        if tsval == 0 {
            tsval = 0u32.wrapping_sub(1 << TS_OPT_BITS);
        }
        tsval
    }

    /// The ISN of a stateful half-open for the SYN `seg`: a cookie, so the
    /// half-open completes statelessly should it lose the slot, or, if the
    /// client offered options no cookie can carry (window scaling, SACK or
    /// ECN without timestamps), an ISN marked as not being one. `None`
    /// without a cookie key.
    pub(super) fn stateful_cookie_iss(&mut self, seg: &Segment<'_>) -> Option<u32> {
        if !self.cookie_secret_set {
            return None;
        }
        let remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        let ecn = seg.has(flags::ECE) && seg.has(flags::CWR);
        let carried = seg.options.ts.is_some()
            || (seg.options.wscale.is_none() && !seg.options.sack_permitted && !ecn);
        let mss_idx = if carried {
            let peer_mss = seg
                .options
                .mss
                .filter(|&m| m != 0)
                .unwrap_or(DEFAULT_PEER_MSS)
                .max(MIN_PEER_MSS);
            cookie_mss_index(peer_mss)
        } else {
            COOKIE_STATEFUL_ONLY
        };
        let bucket = self.now_ms / COOKIE_TIME_BUCKET_MS;
        self.cookie_secret_used = true;
        Some(self.compute_cookie(&self.cookie_secret, bucket, remote, mss_idx, seg.seq))
    }

    /// The timestamp offset a cookie SYN-ACK to `remote` uses under the
    /// current key (the stateful SYN-ACK uses it too, being a cookie).
    pub(super) fn current_cookie_ts_offset(&self, remote: Endpoint) -> u32 {
        self.cookie_ts_offset(remote, false)
    }

    /// Answer a SYN statelessly with a cookie SYN-ACK (the listener's
    /// half-open slot is busy).
    pub(super) fn emit_cookie_synack(&mut self, seg: &Segment<'_>) -> Result<(), TcpError> {
        if self.tx_ring.is_full() {
            return Ok(()); // host has not drained; the peer will retry
        }
        let remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        let peer_mss = seg
            .options
            .mss
            .filter(|&m| m != 0)
            .unwrap_or(DEFAULT_PEER_MSS)
            .max(MIN_PEER_MSS);
        let mss_idx = cookie_mss_index(peer_mss);
        let bucket = self.now_ms / COOKIE_TIME_BUCKET_MS;
        let cookie = self.compute_cookie(&self.cookie_secret, bucket, remote, mss_idx, seg.seq);

        // Options can only be preserved through the cookie via TSval bits.
        let ts_off = self.cookie_ts_offset(remote, false);
        let peer_ecn = seg.has(flags::ECE) && seg.has(flags::CWR);
        let (ts, wscale, sack_ok, ecn) = match seg.options.ts {
            Some((peer_tsval, _)) => {
                let tsval = self.cookie_tsval(
                    ts_off,
                    seg.options.wscale,
                    seg.options.sack_permitted,
                    peer_ecn,
                );
                (
                    Some((tsval, peer_tsval)),
                    seg.options.wscale.map(|_| Self::WS),
                    seg.options.sack_permitted,
                    peer_ecn,
                )
            }
            None => (None, None, false, false),
        };
        let opts = TcpOptions {
            mss: Some(self.local_mss),
            wscale,
            ts,
            sack_permitted: sack_ok,
            sack: SackBlocks::EMPTY,
        };
        let win =
            u16::try_from(self.recv_ring.free().min(usize::from(u16::MAX))).unwrap_or(u16::MAX);
        let fl = flags::SYN | flags::ACK | if ecn { flags::ECE } else { 0 };
        let (local_ip, local_port) = (self.local.ip, self.local.port);
        let ack = seg.seq.wrapping_add(1);
        let full_csum = !self.tx_csum_offload;
        // IP ID 0, as Linux's SYN-ACKs: the listener numbers no packet it
        // sends to strangers, so nobody can count them (an idle scan).
        let queued = self.tx_ring.push_with(|buf| {
            wire::emit_with(
                buf,
                local_ip,
                remote.ip,
                local_port,
                remote.port,
                cookie,
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
            self.cookie_secret_used = true;
        }
        Ok(())
    }

    /// Validate a bare ACK as the third leg of a cookie handshake. Never
    /// mutates state, so a busy listener can check before giving up its
    /// half-open. One guess per key: the cookie names its time bucket (its
    /// parity).
    pub(super) fn validate_cookie(&self, seg: &Segment<'_>) -> Option<CookieOpts> {
        if !self.cookie_secret_set {
            return None;
        }
        let remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        let cookie = seg.ack.wrapping_sub(1);
        let mss_idx = ((cookie >> 30) & 0x3) as u8;
        if mss_idx == COOKIE_STATEFUL_ONLY {
            return None;
        }
        let parity = u64::from((cookie >> 29) & 1);
        let peer_seq = seg.seq.wrapping_sub(1);
        let now_bucket = self.now_ms / COOKIE_TIME_BUCKET_MS;
        let bucket = if now_bucket & 1 == parity {
            now_bucket
        } else {
            now_bucket.checked_sub(1)?
        };
        let issued_with =
            |key: &[u8; 16]| self.compute_cookie(key, bucket, remote, mss_idx, peer_seq) == cookie;
        let prev_valid = self.prev_cookie_secret_set && self.now_ms < self.prev_cookie_until_ms;
        let prev_key = if issued_with(&self.cookie_secret) {
            false
        } else if prev_valid && issued_with(&self.prev_cookie_secret) {
            true
        } else {
            return None;
        };
        // Timestamps were negotiated only if the TSecr echoes a TSval our
        // SYN-ACK could have carried; a stray TSopt (the SYN-ACK offered
        // none) echoes nothing of ours and is ignored (RFC 7323 §3.2).
        let now_ts = (self.now_ms as u32).wrapping_add(self.cookie_ts_offset(remote, prev_key));
        let echo = seg
            .options
            .ts
            .filter(|&(_, e)| e != 0 && now_ts.wrapping_sub(e) <= COOKIE_TS_MAX_AGE);
        let opts = decode_ts_opts(echo)?;
        Some(CookieOpts {
            mss: cookie_mss_from_index(mss_idx),
            prev_key,
            ts: echo.is_some(),
            ..opts
        })
    }

    /// Validate a bare ACK in `LISTEN` as a cookie handshake's third leg and,
    /// on success, promote (see [`Self::promote_via_cookie`]).
    pub(super) fn try_promote_via_cookie(&mut self, seg: &Segment<'_>) -> Result<bool, TcpError> {
        match self.validate_cookie(seg) {
            Some(opts) => self.promote_via_cookie(seg, opts).map(|()| true),
            None => Ok(false),
        }
    }

    /// Recover the connection state a validated cookie encodes, enter
    /// `ESTABLISHED`, and process the segment normally.
    pub(super) fn promote_via_cookie(
        &mut self,
        seg: &Segment<'_>,
        opts: CookieOpts,
    ) -> Result<(), TcpError> {
        let remote = Endpoint {
            ip: seg.src_ip,
            port: seg.src_port,
        };
        let cookie = seg.ack.wrapping_sub(1);
        let peer_seq = seg.seq.wrapping_sub(1);

        self.reset_connection_state();
        self.remote = remote;
        // Keep the SYN-ACK's offset, or our TSvals would jump and the
        // peer's PAWS would discard them.
        self.ts_offset = self.cookie_ts_offset(remote, opts.prev_key);
        self.iss = cookie;
        self.seed_ip_id();
        self.irs = peer_seq;
        self.rcv_nxt = peer_seq.wrapping_add(1);
        self.snd_una = seg.ack;
        self.snd_acked = u64::from(seg.ack.wrapping_sub(cookie));
        self.snd_nxt = seg.ack;
        self.peer_mss = opts.mss.max(MIN_PEER_MSS);
        if let Some(ws) = opts.wscale {
            self.ws_ok = true;
            self.snd_wscale = ws;
            self.rcv_wscale = Self::WS;
        }
        // Timestamps only if the ACK echoes our SYN-ACK's (RFC 7323 §3.2).
        if let Some((tsval, _)) = seg.options.ts.filter(|_| opts.ts) {
            self.ts_enabled = true;
            self.ts_recent = tsval;
            self.ts_recent_stamp = self.now_ms;
            self.sack_enabled = opts.sack;
            self.ecn_enabled = opts.ecn;
        }
        // RTT samples believe no TSecr from before our first data segment,
        // and none of those predates this promotion.
        self.syn_xmit_ms = self.now_ms;
        self.snd_wnd = self.scale_peer_window(seg.window);
        self.max_snd_wnd = self.snd_wnd;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        // The SYN-ACK offered the (unscaled) free space: never shrink it.
        let offered = self.recv_ring.free().min(usize::from(u16::MAX)) as u32;
        self.rcv_adv_edge = self.rcv_nxt.wrapping_add(offered);
        self.last_ack_sent = self.rcv_nxt;
        self.cc =
            crate::congestion::Reno::new(crate::congestion::initial_window(self.mss_payload()));
        self.state = State::Established;
        self.on_established();
        self.on_synchronized(seg)
    }
}

/// SYN-cookie key derived from the host secret (domain-separated from the
/// timestamp-offset and ISN hashes), so a listener with only a host secret
/// still answers SYNs statelessly while its half-open slot is busy.
pub(super) fn derive_cookie_key(secret: &[u8; 16]) -> [u8; 16] {
    let lo = siphash24(secret, b"tcp-sans-io syn-cookie key 0").to_le_bytes();
    let hi = siphash24(secret, b"tcp-sans-io syn-cookie key 1").to_le_bytes();
    let mut key = [0u8; 16];
    for (d, s) in key.iter_mut().zip(lo.iter().chain(hi.iter())) {
        *d = *s;
    }
    key
}

/// Decode the option bits a cookie SYN-ACK hid in its TSval, from the third
/// ACK's TSecr. No timestamps → no preserved options.
fn decode_ts_opts(ts: Option<(u32, u32)>) -> Option<CookieOpts> {
    let base = CookieOpts {
        mss: DEFAULT_PEER_MSS,
        wscale: None,
        sack: false,
        ecn: false,
        prev_key: false,
        ts: false,
    };
    // No timestamps, or a zero TSecr (nothing echoed): no preserved options.
    let Some((_, tsecr)) = ts.filter(|&(_, e)| e != 0) else {
        return Some(base);
    };
    let bits = tsecr & TS_OPT_MASK;
    let ws = bits & TS_OPT_WS_MASK;
    let wscale = match ws {
        TS_OPT_WS_MASK => None,
        0..=14 => Some(ws as u8),
        _ => return None,
    };
    Some(CookieOpts {
        wscale,
        sack: bits & TS_OPT_SACK != 0,
        ecn: bits & TS_OPT_ECN != 0,
        ..base
    })
}

/// Largest table entry not exceeding `peer_mss` (never the fourth index).
fn cookie_mss_index(peer_mss: u16) -> u8 {
    let mut best = 0u8;
    for (i, &m) in COOKIE_MSS_TABLE.iter().enumerate() {
        if m <= peer_mss {
            best = i as u8;
        }
    }
    best
}

fn cookie_mss_from_index(idx: u8) -> u16 {
    COOKIE_MSS_TABLE
        .get(usize::from(idx & 0x3))
        .copied()
        .unwrap_or(DEFAULT_PEER_MSS)
}

/// SipHash-2-4 (Aumasson & Bernstein). Dependency-free, `no_std`.
pub(crate) fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let &[k00, k01, k02, k03, k04, k05, k06, k07, k10, k11, k12, k13, k14, k15, k16, k17] = key;
    let k0 = u64::from_le_bytes([k00, k01, k02, k03, k04, k05, k06, k07]);
    let k1 = u64::from_le_bytes([k10, k11, k12, k13, k14, k15, k16, k17]);
    let mut v0 = 0x736f_6d65_7073_6575u64 ^ k0;
    let mut v1 = 0x646f_7261_6e64_6f6du64 ^ k1;
    let mut v2 = 0x6c79_6765_6e65_7261u64 ^ k0;
    let mut v3 = 0x7465_6462_7974_6573u64 ^ k1;

    let (chunks, rem) = data.as_chunks::<8>();
    for chunk in chunks {
        let m = u64::from_le_bytes(*chunk);
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }
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
    for _ in 0..4 {
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    }
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
mod tests {
    use super::*;

    /// SipHash-2-4 reference vectors (paper, Appendix A).
    #[test]
    fn siphash_reference_vectors() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let msg: [u8; 15] = core::array::from_fn(|i| i as u8);
        assert_eq!(siphash24(&key, &msg), 0xa129_ca61_49be_45e5);
        assert_eq!(siphash24(&key, &[]), 0x726f_db47_dd0e_0e31);
    }

    #[test]
    fn ts_option_bits_round_trip() {
        let o = decode_ts_opts(Some((1, 0x1234_5600 | 7 | TS_OPT_SACK))).unwrap_or(CookieOpts {
            mss: 0,
            wscale: None,
            sack: false,
            ecn: false,
            prev_key: false,
            ts: false,
        });
        assert_eq!((o.wscale, o.sack, o.ecn), (Some(7), true, false));
        let none = decode_ts_opts(Some((1, TS_OPT_WS_MASK)));
        assert_eq!(none.map(|o| o.wscale), Some(None));
        assert_eq!(decode_ts_opts(None).map(|o| o.sack), Some(false));
    }
}
