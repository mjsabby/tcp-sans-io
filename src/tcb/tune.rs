//! Send / receive buffer sizing: [`Tcb::set_buffer_limits`], autotuning, and
//! [`Tcb::reclaimable`].
//!
//! Each ring's capacity is a power of two between limits the host sets,
//! pinned at `BUF` by default (fixed-size rings, as before the limits
//! existed). Between distinct limits it follows what the connection uses,
//! measured once per round (one smoothed RTT, at least 1 ms):
//!
//! * receive: twice the bytes per round both received and read by the
//!   application (dynamic right-sizing, as Linux's receive autotuning, whose
//!   growth headroom it also adds), so a sender in slow start is not held
//!   back by our window — reads alone would spike when a repaired hole
//!   releases parked data, arrivals alone follow whatever window a slow
//!   reader is offered;
//! * send: twice the usable window `min(cwnd, SND.WND)` while the application
//!   finds the ring full; otherwise the ring's peak occupancy, with headroom
//!   up to twice the usable window but never more than twice that peak.
//!
//! A ring grows as soon as a round needs more, to the next power of two. It
//! shrinks at most once per epoch (8 RTTs, at least 1 s), to the epoch's
//! largest need, and only when that breaks no promise: a receive ring keeps
//! room for the window already advertised, everything parked out of order
//! and a FIN held beyond `RCV.NXT`; a send ring keeps its data and never moves
//! while lent out (`send_reserve`). Until then the smaller target already
//! bounds what is newly offered — window to the peer, ring space to the
//! application (`Ring::room`).
//!
//! The rings' storage stays `BUF` bytes each, of which only the first
//! `capacity` bytes are ever touched. A host that backs the TCB with lazily
//! allocated memory (`calloc`, `mmap`; see [`Tcb::init_in_place_zeroed`])
//! therefore pays for the capacity rather than `BUF`, and
//! [`Tcb::reclaimable`] lists the storage it may hand back.

use super::{seq_gt, Tcb};
use crate::error::TcpError;
use crate::state::State;

/// Smallest ring capacity [`Tcb::set_buffer_limits`] accepts (or `BUF`, if
/// smaller).
pub const MIN_RING_CAP: usize = 4096;
/// Capacity an autotuned ring starts each connection with (clamped to its
/// limits).
pub const INITIAL_RING_CAP: usize = 64 * 1024;
/// A shrink is considered at most once per epoch: at least this long...
const EPOCH_MIN_MS: u64 = 1000;
/// ...and at least this many smoothed RTTs.
const EPOCH_RTTS: u64 = 8;

/// Autotuning measurements. All-zero is a valid (if stale) start.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Tune {
    /// Start of the current round.
    round_start_ms: u64,
    /// Bytes the application read this round; new bytes received (in order
    /// or parked out of order) before it; and the largest per-RTT receive
    /// rate of the epoch's earlier rounds.
    rcv_read: u64,
    rcv_mark: u64,
    rcv_max: u64,
    /// The application offered more than the send ring took this round.
    snd_blocked: bool,
    /// Largest send-ring occupancy seen this round.
    snd_len_peak: usize,
    /// Start of the current epoch, and the largest needs of its rounds.
    epoch_start_ms: u64,
    rcv_need: u64,
    snd_need: u64,
}

impl Tune {
    pub(super) fn start(now_ms: u64) -> Self {
        Self {
            round_start_ms: now_ms,
            epoch_start_ms: now_ms,
            ..Self::default()
        }
    }

    /// The application read `n` bytes.
    pub(super) fn on_app_read(&mut self, n: usize) {
        self.rcv_read = self.rcv_read.saturating_add(n as u64);
    }

    /// The application wrote (`blocked`: and had more than fit); the send
    /// ring now holds `len` bytes.
    pub(super) fn on_app_write(&mut self, blocked: bool, len: usize) {
        self.snd_blocked |= blocked;
        self.snd_len_peak = self.snd_len_peak.max(len);
    }
}

/// `bytes` as a capacity bound for a `buf`-byte ring: clamped to
/// `MIN_RING_CAP.min(buf)..=buf`, rounded down to a power of two.
fn bound(bytes: usize, buf: usize) -> usize {
    let b = bytes.max(MIN_RING_CAP.min(buf)).min(buf);
    b.checked_ilog2().map_or(1, |l| 1 << l)
}

/// Capacity a ring with these limits starts a connection with.
pub(super) fn initial_cap(min: usize, max: usize) -> usize {
    INITIAL_RING_CAP.max(min).min(max)
}

/// Smallest power of two in `min..=max` (both powers of two) holding `need`
/// bytes, or `max`.
fn fit(need: u64, min: usize, max: usize) -> usize {
    let need = usize::try_from(need).unwrap_or(usize::MAX);
    if need <= min {
        min
    } else if need >= max {
        max
    } else {
        need.checked_next_power_of_two().map_or(max, |p| p.min(max))
    }
}

impl<const BUF: usize> Tcb<BUF> {
    /// Bound the send and receive ring capacities to `*_min..=*_max` bytes,
    /// each clamped to [`MIN_RING_CAP`]`.min(BUF)..=BUF` and rounded down to a
    /// power of two. Equal bounds pin a ring's capacity; distinct ones let it
    /// be autotuned between them — growing with the connection's
    /// bandwidth-delay product, shrinking once it needs less — starting each
    /// connection at [`INITIAL_RING_CAP`] (clamped). The default pins both
    /// rings at `BUF`, the fixed buffers of a TCB that never calls this;
    /// [`Self::reinit`] restores it.
    ///
    /// Takes effect at once where it safely can: a ring grows to a raised
    /// minimum immediately (unless lent out by [`Self::send_reserve`]); under
    /// a lowered maximum no new window or send space is offered beyond it,
    /// and the ring shrinks once its data and the window already advertised
    /// fit. Set limits before [`Self::connect`] / [`Self::listen`] to open at
    /// the initial capacity. `InvalidState` if a minimum exceeds its maximum.
    ///
    /// Memory only follows the capacity if the TCB's storage is backed
    /// lazily: see [`Self::init_in_place_zeroed`] and [`Self::reclaimable`].
    pub fn set_buffer_limits(
        &mut self,
        snd_min: usize,
        snd_max: usize,
        rcv_min: usize,
        rcv_max: usize,
    ) -> Result<(), TcpError> {
        if snd_min > snd_max || rcv_min > rcv_max {
            return Err(TcpError::InvalidState);
        }
        self.snd_buf_min = bound(snd_min, BUF);
        self.snd_buf_max = bound(snd_max, BUF);
        self.rcv_buf_min = bound(rcv_min, BUF);
        self.rcv_buf_max = bound(rcv_max, BUF);
        let idle = matches!(self.state, State::Closed | State::Listen);
        let place = |target: usize, min: usize, max: usize| {
            if idle {
                initial_cap(min, max)
            } else {
                target.max(min).min(max)
            }
        };
        let snd = place(self.send_ring.target(), self.snd_buf_min, self.snd_buf_max);
        let rcv = place(self.recv_ring.target(), self.rcv_buf_min, self.rcv_buf_max);
        self.send_ring.set_target(snd);
        self.recv_ring.set_target(rcv);
        self.apply_buffer_targets();
        Ok(())
    }

    /// Current capacities of the send and receive rings, in bytes.
    pub fn buffer_capacity(&self) -> (usize, usize) {
        (self.send_ring.capacity(), self.recv_ring.capacity())
    }

    /// Storage the TCB will not read before writing it again: ring space past
    /// each ring's capacity, a whole ring that holds nothing, and the egress
    /// slots when no packet is staged. A host that backs the TCB with lazily
    /// allocated memory may release the whole pages inside these slices (for
    /// example `madvise(MADV_DONTNEED)`) — say once a connection has been
    /// idle for a while — or overwrite them freely; touched again, they are
    /// faulted back in. Ring space lent out by [`Self::send_reserve`] is never
    /// included. The slices are only valid until the next call on the TCB.
    pub fn reclaimable(&mut self) -> [&mut [u8]; 3] {
        let parked = self.beyond_rcv_nxt(self.ooo.last_end());
        let send: &mut [u8] = if self.send_lent == 0 {
            self.send_ring.spare_mut(0)
        } else {
            &mut []
        };
        [
            send,
            self.recv_ring.spare_mut(parked),
            self.tx_ring.spare_mut(),
        ]
    }

    /// After each call that changes what the rings hold (`inject_packet`,
    /// `tick`, `recv`): autotune when the limits allow, move the capacities
    /// as far as is safe, and announce a receive window that grew.
    pub(super) fn tune_buffers(&mut self) -> Result<(), TcpError> {
        let rcv_before = self.recv_ring.capacity();
        let tunable = self.snd_buf_min < self.snd_buf_max || self.rcv_buf_min < self.rcv_buf_max;
        if tunable && self.state.is_synchronized() {
            self.tune_measure();
        }
        self.apply_buffer_targets();
        if self.recv_ring.capacity() > rcv_before {
            self.maybe_send_window_update()?;
        }
        Ok(())
    }

    /// Close the round if one RTT has passed: raise targets the round needs,
    /// and at the end of an epoch lower them to the epoch's largest need.
    fn tune_measure(&mut self) {
        let now = self.now_ms;
        let len = self.send_ring.len();
        self.tune.snd_len_peak = self.tune.snd_len_peak.max(len);
        let rtt = u64::from(self.srtt_ms.max(1));
        let elapsed = now.saturating_sub(self.tune.round_start_ms);
        if elapsed < rtt {
            return;
        }
        let t = self.tune;
        // The receive rate: bytes both received and read this round. Reads
        // alone spike when a repaired hole releases the data parked behind
        // it; arrivals alone follow whatever window a slow reader is offered.
        let mark = self.rcv_mark();
        let rcv = t.rcv_read.min(mark.saturating_sub(t.rcv_mark));
        // Per RTT, doubled so that the next round of a sender in slow start
        // fits; plus twice what the rate grew past its earlier peak (at most
        // the rate again): the ACKs of this round already release the next,
        // larger one before the round is measured. Linux
        // `tcp_rcv_space_adjust` adds the same growth-proportional headroom.
        let rcv_rtt = rcv.saturating_mul(rtt) / elapsed;
        let growth = rcv_rtt.saturating_sub(t.rcv_max).min(rcv_rtt);
        let rcv_need = rcv_rtt.saturating_add(growth).saturating_mul(2);
        // The send ring holds what is in flight plus the application's
        // backlog. Held back by a full ring, the application needs twice the
        // usable window; otherwise its peak occupancy, plus headroom up to
        // twice the usable window, and never more than twice that peak.
        let usable = u64::from(self.cc.cwnd.min(self.snd_wnd));
        let peak = t.snd_len_peak as u64;
        let snd_need = if t.snd_blocked {
            usable.saturating_mul(2)
        } else {
            peak.max(usable.saturating_mul(2))
                .min(peak.saturating_mul(2))
        };
        let rcv = fit(rcv_need, self.rcv_buf_min, self.rcv_buf_max);
        if rcv > self.recv_ring.target() {
            self.recv_ring.set_target(rcv);
        }
        // Only an application held back by a full ring grows it; otherwise a
        // round may at most cancel a pending shrink.
        let mut snd = fit(snd_need, self.snd_buf_min, self.snd_buf_max);
        if !t.snd_blocked {
            snd = snd.min(self.send_ring.capacity());
        }
        if snd > self.send_ring.target() {
            self.send_ring.set_target(snd);
        }
        let epoch = EPOCH_MIN_MS.max(EPOCH_RTTS.saturating_mul(rtt));
        // After a quiet spell as long as an epoch, earlier needs are stale.
        let (rcv_prior, snd_prior) = if elapsed >= epoch {
            (0, 0)
        } else {
            (t.rcv_need, t.snd_need)
        };
        let mut next = Tune {
            round_start_ms: now,
            rcv_read: 0,
            rcv_mark: mark,
            rcv_max: t.rcv_max.max(rcv_rtt),
            snd_blocked: false,
            snd_len_peak: len,
            epoch_start_ms: t.epoch_start_ms,
            rcv_need: rcv_prior.max(rcv_need),
            snd_need: snd_prior.max(snd_need),
        };
        if now.saturating_sub(t.epoch_start_ms) >= epoch {
            let rcv = fit(next.rcv_need, self.rcv_buf_min, self.rcv_buf_max);
            if rcv < self.recv_ring.target() {
                self.recv_ring.set_target(rcv);
            }
            let snd = fit(next.snd_need, self.snd_buf_min, self.snd_buf_max);
            if snd < self.send_ring.target() {
                self.send_ring.set_target(snd);
            }
            // A steady rate is not growth in the next epoch either.
            next.epoch_start_ms = now;
            next.rcv_max = rcv_rtt;
            next.rcv_need = 0;
            next.snd_need = 0;
        }
        self.tune = next;
    }

    /// Move each ring's capacity to its target where nothing is lost: the
    /// receive ring keeps the window already advertised, the out-of-order
    /// data parked in it and room up to a FIN held beyond `RCV.NXT`; the send
    /// ring keeps its data, and never moves while space in it is lent out.
    pub(super) fn apply_buffer_targets(&mut self) {
        if self.send_ring.target() == self.send_ring.capacity()
            && self.recv_ring.target() == self.recv_ring.capacity()
        {
            return; // nothing pending (always so with pinned limits)
        }
        let parked = self.beyond_rcv_nxt(self.ooo.last_end());
        let promised = self.beyond_rcv_nxt(Some(self.rcv_adv_edge));
        let fin = self.beyond_rcv_nxt(self.ooo_fin.map(|h| h.seq));
        let _ = self.recv_ring.try_resize(parked, promised.max(fin));
        if self.send_lent == 0 {
            let _ = self.send_ring.try_resize(0, 0);
        }
    }

    /// New bytes received so far, in order or parked out of order.
    fn rcv_mark(&self) -> u64 {
        self.stats
            .bytes_received
            .saturating_add(u64::from(self.ooo.held_bytes()))
    }

    /// Bytes from `RCV.NXT` up to `seq` (0 unless `seq` lies beyond it).
    fn beyond_rcv_nxt(&self, seq: Option<u32>) -> usize {
        match seq {
            Some(s) if seq_gt(s, self.rcv_nxt) => s.wrapping_sub(self.rcv_nxt) as usize,
            _ => 0,
        }
    }

    /// Buffer-sizing invariants, for [`Self::debug_validate_invariants`].
    #[cfg(any(test, feature = "std"))]
    pub(super) fn debug_validate_buffers(&self) -> Result<(), &'static str> {
        self.send_ring.debug_valid()?;
        self.recv_ring.debug_valid()?;
        for (min, max, target) in [
            (self.snd_buf_min, self.snd_buf_max, self.send_ring.target()),
            (self.rcv_buf_min, self.rcv_buf_max, self.recv_ring.target()),
        ] {
            if !min.is_power_of_two() || !max.is_power_of_two() || min > max || max > BUF {
                return Err("buffer limits out of range");
            }
            if target < min || target > max {
                return Err("ring target outside its limits");
            }
        }
        // Every byte of window advertised is backed by free receive space,
        // up to the rounding of a scaled window (less than one unit).
        let promised = self.beyond_rcv_nxt(Some(self.rcv_adv_edge));
        let slack = (1usize << self.rcv_wscale) - 1;
        if promised > self.recv_ring.free().saturating_add(slack) {
            return Err("advertised window exceeds the receive buffer");
        }
        // A live loan lies inside the send ring's free space.
        if self.send_lent != 0
            && self.send_lent_conn == self.conn_gen
            && self.send_lent > self.send_ring.free()
        {
            return Err("lent send space exceeds the free space");
        }
        Ok(())
    }
}
