//! Multi-packet egress staging ring.
//!
//! Replaces the single-packet `tx_buf` slot that historically capped
//! the stack at one emitted packet per host extract/inject cycle. With
//! a 32-slot ring (48 KiB per connection), `maybe_send_data` can emit
//! up to 32 back-to-back segments before yielding back to the host —
//! enough to drain a typical burst (IW=10, congestion-window growth
//! after each ACK, RACK / RFC 6675 retransmit fan-out) without the
//! ping-pong overhead of one FFI round-trip per packet.
//!
//! The ring is strict FIFO: the host's `tcp_extract_packet` pops from
//! the head; emit paths push at the tail. TCP relies on
//! roughly-monotonic delivery order for ACK clocking and SACK
//! interpretation, so we never reorder internally.
//!
//! ## Sizing
//!
//! 32 slots × `MAX_PACKET` (1500 B) = 48 KiB per connection. This
//! adds ~2 % to the per-Tcb footprint (already ~2.1 MiB from the two
//! 1 MiB rings + RACK send queue). The ring is intentionally small
//! relative to the BDP cap `BUF_CAP / MSS ≈ 720` segments: the host
//! is expected to drain the ring at every wakeup, so we only need
//! enough buffering to amortize syscall overhead within a single
//! tick / inject cycle.
//!
//! ## Invariants
//!
//! * `head + len` (mod `TX_RING_CAP`) == `tail` (computed; not
//!   stored).
//! * `len <= TX_RING_CAP`.
//! * Slots in `[head .. head + len)` hold valid packet bytes;
//!   slots outside are uninitialized as far as the consumer is
//!   concerned.
//! * Each in-use slot's `len` is in `1 ..= MAX_PACKET`.

use crate::error::TcpError;
use crate::MAX_PACKET;

/// Number of staging slots in the egress ring. Sized for one full
/// IW=10 burst plus RACK / RFC 6675 retransmit fan-out, with a
/// comfortable safety margin.
pub const TX_RING_CAP: usize = 32;

/// A single packet slot. `len` is the number of valid bytes in `buf`
/// (always `<= MAX_PACKET`).
#[derive(Copy, Clone)]
struct Slot {
    buf: [u8; MAX_PACKET],
    len: u16,
}

impl Slot {
    const fn new() -> Self {
        Self {
            buf: [0u8; MAX_PACKET],
            len: 0,
        }
    }
}

/// Bounded FIFO ring of outbound packet slots.
pub struct TxRing {
    slots: [Slot; TX_RING_CAP],
    head: usize,
    len: usize,
}

impl TxRing {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::new(); TX_RING_CAP],
            head: 0,
            len: 0,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == TX_RING_CAP
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Reset the ring (used on RST / hard close). Doesn't zero the
    /// backing slot bytes — `len = 0` makes them logically dead.
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// Peek the length of the head packet, if any. Useful for the
    /// FFI to size-check the caller's buffer before popping.
    #[inline]
    pub fn peek_head_len(&self) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        self.slots.get(self.head).map(|s| s.len as usize)
    }

    /// Stage a new packet by invoking `f` to write into the tail
    /// slot's buffer. Returns:
    ///
    /// * `Ok(true)` if a slot was available and `f` reported a
    ///   non-zero, in-range length.
    /// * `Ok(false)` if the ring is full — caller may decide whether
    ///   to retry later or drop the emission.
    /// * `Err(_)` if `f` itself returned an error, or if it reported
    ///   a length outside `1 ..= MAX_PACKET`.
    ///
    /// The closure receives an exclusive `&mut [u8]` of exactly
    /// `MAX_PACKET` bytes (the slot's full buffer) and must return
    /// the number of bytes it actually wrote.
    pub fn push_with<F>(&mut self, f: F) -> Result<bool, TcpError>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, TcpError>,
    {
        if self.len == TX_RING_CAP {
            return Ok(false);
        }
        let tail = (self.head + self.len) % TX_RING_CAP;
        let slot = self.slots.get_mut(tail).ok_or(TcpError::Overflow)?;
        let n = f(&mut slot.buf)?;
        if n == 0 || n > MAX_PACKET {
            return Err(TcpError::Overflow);
        }
        slot.len = n as u16;
        self.len += 1;
        Ok(true)
    }

    /// Pop the head packet's bytes into `out`. Returns the number of
    /// bytes copied, or 0 if the ring is empty.
    ///
    /// Returns `BufferTooSmall` if `out` is shorter than the head
    /// packet — the slot is left in place so the caller can retry
    /// with a larger buffer.
    pub fn pop_into(&mut self, out: &mut [u8]) -> Result<usize, TcpError> {
        if self.len == 0 {
            return Ok(0);
        }
        let slot = self.slots.get(self.head).ok_or(TcpError::Overflow)?;
        let n = slot.len as usize;
        if out.len() < n {
            return Err(TcpError::BufferTooSmall);
        }
        let src = slot.buf.get(..n).ok_or(TcpError::Overflow)?;
        let dst = out.get_mut(..n).ok_or(TcpError::BufferTooSmall)?;
        dst.copy_from_slice(src);
        self.head = (self.head + 1) % TX_RING_CAP;
        self.len -= 1;
        Ok(n)
    }
}

impl Default for TxRing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn empty_ring_pops_nothing() {
        let mut r = TxRing::new();
        let mut buf = [0u8; MAX_PACKET];
        assert_eq!(r.pop_into(&mut buf).unwrap(), 0);
        assert!(r.is_empty());
        assert!(!r.is_full());
        assert_eq!(r.peek_head_len(), None);
    }

    #[test]
    fn push_then_pop_roundtrips_bytes() {
        let mut r = TxRing::new();
        assert!(r
            .push_with(|b| {
                b[..3].copy_from_slice(b"abc");
                Ok(3)
            })
            .unwrap());
        assert_eq!(r.len(), 1);
        assert_eq!(r.peek_head_len(), Some(3));
        let mut out = [0u8; 32];
        assert_eq!(r.pop_into(&mut out).unwrap(), 3);
        assert_eq!(&out[..3], b"abc");
        assert!(r.is_empty());
    }

    #[test]
    fn fills_to_capacity_then_refuses() {
        let mut r = TxRing::new();
        for i in 0..TX_RING_CAP {
            assert!(r
                .push_with(|b| {
                    b[0] = i as u8;
                    Ok(1)
                })
                .unwrap());
        }
        assert!(r.is_full());
        // 33rd push: ring full, returns false (not Err).
        assert!(!r
            .push_with(|b| {
                b[0] = 0xFF;
                Ok(1)
            })
            .unwrap());
        assert_eq!(r.len(), TX_RING_CAP);
    }

    #[test]
    fn fifo_order_preserved() {
        let mut r = TxRing::new();
        for i in 0..5u8 {
            r.push_with(|b| {
                b[0] = i;
                Ok(1)
            })
            .unwrap();
        }
        let mut out = [0u8; 8];
        for i in 0..5u8 {
            assert_eq!(r.pop_into(&mut out).unwrap(), 1);
            assert_eq!(out[0], i);
        }
        assert!(r.is_empty());
    }

    #[test]
    fn push_with_zero_length_errors() {
        let mut r = TxRing::new();
        assert!(matches!(r.push_with(|_| Ok(0)), Err(TcpError::Overflow)));
        assert!(r.is_empty());
    }

    #[test]
    fn push_with_oversize_length_errors() {
        let mut r = TxRing::new();
        assert!(matches!(
            r.push_with(|_| Ok(MAX_PACKET + 1)),
            Err(TcpError::Overflow)
        ));
        assert!(r.is_empty());
    }

    #[test]
    fn pop_into_small_buffer_returns_error_and_keeps_slot() {
        let mut r = TxRing::new();
        r.push_with(|b| {
            b[..4].copy_from_slice(b"data");
            Ok(4)
        })
        .unwrap();
        let mut small = [0u8; 2];
        assert!(matches!(
            r.pop_into(&mut small),
            Err(TcpError::BufferTooSmall)
        ));
        assert_eq!(r.len(), 1, "slot kept on error");
        let mut big = [0u8; 8];
        assert_eq!(r.pop_into(&mut big).unwrap(), 4);
        assert_eq!(&big[..4], b"data");
    }

    #[test]
    fn clear_drops_all_pending() {
        let mut r = TxRing::new();
        for _ in 0..3 {
            r.push_with(|b| {
                b[0] = 1;
                Ok(1)
            })
            .unwrap();
        }
        r.clear();
        assert!(r.is_empty());
        let mut out = [0u8; 8];
        assert_eq!(r.pop_into(&mut out).unwrap(), 0);
    }

    #[test]
    fn ring_wraps_correctly_under_sustained_push_pop() {
        let mut r = TxRing::new();
        let mut buf = [0u8; 8];
        // Push 10, pop 10, push 30, pop 30 — exercises wraparound.
        for i in 0..10u8 {
            r.push_with(|b| {
                b[0] = i;
                Ok(1)
            })
            .unwrap();
        }
        for i in 0..10u8 {
            r.pop_into(&mut buf).unwrap();
            assert_eq!(buf[0], i);
        }
        for i in 0..30u8 {
            r.push_with(|b| {
                b[0] = i;
                Ok(1)
            })
            .unwrap();
        }
        for i in 0..30u8 {
            r.pop_into(&mut buf).unwrap();
            assert_eq!(buf[0], i);
        }
        assert!(r.is_empty());
    }
}
