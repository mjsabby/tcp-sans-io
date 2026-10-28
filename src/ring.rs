//! Fixed-capacity, zero-allocation byte ring buffer.
//!
//! Used for both the application-facing send and receive queues. Capacity is
//! statically chosen via const generics so the ring itself lives inside the
//! [`crate::tcb::Tcb`] without ever touching an allocator.

use crate::error::TcpError;

/// SPSC byte ring with capacity `N`. `N` *must* be a power of two — this is
/// checked at construction time so the modulo can be a cheap mask.
pub struct Ring<const N: usize> {
    #[cfg(feature = "heap-buffers")]
    buf: alloc::boxed::Box<[u8]>, // always length N; allocated off the stack
    #[cfg(not(feature = "heap-buffers"))]
    buf: [u8; N],
    head: usize, // read cursor (next byte to read)
    tail: usize, // write cursor (next byte to write)
    len: usize,  // bytes currently stored
}

impl<const N: usize> Ring<N> {
    /// Construct an empty ring. Returns `Overflow` if `N` is not a power of
    /// two or is zero — both invariants the index math relies on.
    #[cfg(not(feature = "heap-buffers"))]
    pub const fn new() -> Result<Self, TcpError> {
        if N == 0 || (N & (N - 1)) != 0 {
            return Err(TcpError::Overflow);
        }
        Ok(Self {
            buf: [0u8; N],
            head: 0,
            tail: 0,
            len: 0,
        })
    }

    /// Heap-backed construction: the allocator zeroes the `N`-byte buffer in
    /// place, so no `[u8; N]` is ever materialized on the stack. This is what
    /// lets `Box::new(Tcb::new())` avoid a multi-MiB stack temporary in debug
    /// builds (no RVO). Returns `Overflow` on bad `N` or allocation failure.
    #[cfg(feature = "heap-buffers")]
    pub fn new() -> Result<Self, TcpError> {
        if N == 0 || (N & (N - 1)) != 0 {
            return Err(TcpError::Overflow);
        }
        let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        v.try_reserve_exact(N).map_err(|_| TcpError::Overflow)?;
        v.resize(N, 0);
        Ok(Self {
            buf: v.into_boxed_slice(),
            head: 0,
            tail: 0,
            len: 0,
        })
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub const fn free(&self) -> usize {
        N - self.len
    }

    /// Append as many bytes from `src` as will fit. Returns the number copied.
    pub fn write(&mut self, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.free());
        if n == 0 {
            return 0;
        }
        let mask = N - 1;
        let first = core::cmp::min(n, N - (self.tail & mask));
        // SAFETY-equivalent: bounds are derived from `mask` + `min`, both safe.
        let tail_off = self.tail & mask;
        if let (Some(dst), Some(s)) = (
            self.buf.get_mut(tail_off..tail_off + first),
            src.get(..first),
        ) {
            dst.copy_from_slice(s);
        }
        if n > first {
            let rem = n - first;
            if let (Some(dst), Some(s)) = (self.buf.get_mut(..rem), src.get(first..first + rem)) {
                dst.copy_from_slice(s);
            }
        }
        self.tail = self.tail.wrapping_add(n);
        self.len += n;
        n
    }

    /// Copy up to `dst.len()` bytes out, advancing the read cursor.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let n = self.peek(dst);
        self.consume(n);
        n
    }

    /// Copy up to `dst.len()` bytes out *without* advancing the cursor.
    pub fn peek(&self, dst: &mut [u8]) -> usize {
        let n = core::cmp::min(dst.len(), self.len);
        if n == 0 {
            return 0;
        }
        let mask = N - 1;
        let head_off = self.head & mask;
        let first = core::cmp::min(n, N - head_off);
        if let (Some(d), Some(s)) = (
            dst.get_mut(..first),
            self.buf.get(head_off..head_off + first),
        ) {
            d.copy_from_slice(s);
        }
        if n > first {
            let rem = n - first;
            if let (Some(d), Some(s)) = (dst.get_mut(first..first + rem), self.buf.get(..rem)) {
                d.copy_from_slice(s);
            }
        }
        n
    }

    /// Like [`Self::peek`], but starts at `offset` bytes from the read cursor.
    /// Used by the sender to read unsent / in-flight bytes without consuming.
    pub fn peek_at(&self, offset: usize, dst: &mut [u8]) -> usize {
        if offset >= self.len {
            return 0;
        }
        let available = self.len - offset;
        let n = core::cmp::min(dst.len(), available);
        if n == 0 {
            return 0;
        }
        let mask = N - 1;
        let start = (self.head.wrapping_add(offset)) & mask;
        let first = core::cmp::min(n, N - start);
        if let (Some(d), Some(s)) = (dst.get_mut(..first), self.buf.get(start..start + first)) {
            d.copy_from_slice(s);
        }
        if n > first {
            let rem = n - first;
            if let (Some(d), Some(s)) = (dst.get_mut(first..first + rem), self.buf.get(..rem)) {
                d.copy_from_slice(s);
            }
        }
        n
    }

    /// Write `src` into the free region at `offset` bytes past the write
    /// cursor **without** making it readable. Used to park out-of-order
    /// receive data at its final position: the receive window is exactly the
    /// free region, so any in-window segment has a slot here. Bytes that
    /// would fall past the free region are clipped. Returns bytes written.
    pub fn write_at(&mut self, offset: usize, src: &[u8]) -> usize {
        let free = self.free();
        if offset >= free {
            return 0;
        }
        let n = core::cmp::min(src.len(), free - offset);
        if n == 0 {
            return 0;
        }
        let mask = N - 1;
        let start = self.tail.wrapping_add(offset) & mask;
        let first = core::cmp::min(n, N - start);
        if let (Some(dst), Some(s)) = (self.buf.get_mut(start..start + first), src.get(..first)) {
            dst.copy_from_slice(s);
        }
        if n > first {
            let rem = n - first;
            if let (Some(dst), Some(s)) = (self.buf.get_mut(..rem), src.get(first..first + rem)) {
                dst.copy_from_slice(s);
            }
        }
        n
    }

    /// Make `n` bytes past the write cursor readable. They must already hold
    /// valid data (written by [`Self::write_at`]). Clipped to free space;
    /// returns the number of bytes committed.
    pub fn commit(&mut self, n: usize) -> usize {
        let n = core::cmp::min(n, self.free());
        self.tail = self.tail.wrapping_add(n);
        self.len += n;
        n
    }

    /// Drop `n` bytes from the head. Saturates at `len`.
    pub fn consume(&mut self, n: usize) {
        let n = core::cmp::min(n, self.len);
        self.head = self.head.wrapping_add(n);
        self.len -= n;
    }

    /// Discard all stored bytes. Buffer contents are not zeroed (the
    /// previous bytes simply become unreachable as `len` returns to 0);
    /// callers that need the storage zeroed must do so explicitly.
    /// Used when a TCB reverts from `SynRcvd` back to `Listen` so a fresh
    /// connection inherits empty rings without re-allocating.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::Ring;

    #[test]
    fn write_at_then_commit_reassembles_across_wrap() {
        let mut r: Ring<16> = Ring::new().unwrap();
        // Advance the cursors so the free region wraps the end of storage.
        assert_eq!(r.write(&[0u8; 12]), 12);
        let mut sink = [0u8; 12];
        assert_eq!(r.read(&mut sink), 12);
        // Park bytes 4..10 out of order, then fill 0..4 in order.
        assert_eq!(r.write_at(4, &[4, 5, 6, 7, 8, 9]), 6);
        assert_eq!(r.len(), 0, "parked bytes are not readable yet");
        assert_eq!(r.write(&[0, 1, 2, 3]), 4);
        assert_eq!(r.commit(6), 6);
        let mut out = [0u8; 10];
        assert_eq!(r.read(&mut out), 10);
        assert_eq!(out, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn write_at_clips_to_free_space() {
        let mut r: Ring<8> = Ring::new().unwrap();
        assert_eq!(r.write(&[1, 2, 3]), 3);
        assert_eq!(
            r.write_at(4, &[9; 10]),
            1,
            "only offset 4 of 5 free bytes fits"
        );
        assert_eq!(
            r.write_at(5, &[9]),
            0,
            "offset at/after free space is rejected"
        );
        assert_eq!(r.commit(100), 5, "commit is clipped to free space");
        assert_eq!(r.free(), 0);
    }
}
