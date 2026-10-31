//! Zero-allocation byte ring buffer with a resizable capacity.
//!
//! Used for both the application-facing send and receive queues. The storage
//! (`N` bytes, statically chosen via const generics) lives inside the
//! [`crate::tcb::Tcb`] without ever touching an allocator, and is a
//! *reservation*: the ring only ever reads or writes its first
//! [`Ring::capacity`] bytes, a power of two that [`Ring::try_resize`] moves
//! toward [`Ring::target`]. Storage past the capacity is never touched, so
//! when the host backs the TCB with lazily allocated memory the resident size
//! follows the capacity rather than `N`. The default (all-zero) state uses all
//! of `N`: a ring that is never resized behaves exactly like a fixed one.

use crate::error::TcpError;

/// SPSC byte ring over `N` bytes of storage. `N` *must* be a power of two —
/// this is checked at construction time so the modulo can be a cheap mask.
pub struct Ring<const N: usize> {
    #[cfg(feature = "heap-buffers")]
    buf: alloc::boxed::Box<[u8]>, // always length N; allocated off the stack
    #[cfg(not(feature = "heap-buffers"))]
    buf: [u8; N],
    head: usize, // read cursor (next byte to read)
    tail: usize, // write cursor (next byte to write)
    len: usize,  // bytes currently stored
    /// Capacity in use is `N >> shift`; 0 (the all-zero state) is all of `N`.
    shift: u8,
    /// Capacity to converge to: `N >> target_shift`.
    target_shift: u8,
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
            shift: 0,
            target_shift: 0,
        })
    }

    /// Heap-backed construction: the allocator zeroes the `N`-byte buffer, so
    /// no `[u8; N]` is ever materialized on the stack. This is what lets
    /// `Box::new(Tcb::new())` avoid a multi-MiB stack temporary in debug
    /// builds (no RVO). The zeroing path (`calloc`) hands large allocations
    /// out as untouched zero pages, so storage past the capacity is never
    /// backed by memory. Returns `Overflow` on bad `N` or allocation failure.
    #[cfg(feature = "heap-buffers")]
    pub fn new() -> Result<Self, TcpError> {
        if N == 0 || (N & (N - 1)) != 0 {
            return Err(TcpError::Overflow);
        }
        let layout = core::alloc::Layout::array::<u8>(N).map_err(|_| TcpError::Overflow)?;
        // SAFETY: `layout` has a non-zero size (`N > 0` is checked above).
        let p = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if p.is_null() {
            return Err(TcpError::Overflow);
        }
        // SAFETY: `p` is a fresh, zero-initialised allocation of `N` bytes
        // made with the layout `Box<[u8]>` frees it with (`[u8; N]`).
        let buf = unsafe { alloc::boxed::Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, N)) };
        Ok(Self {
            buf,
            head: 0,
            tail: 0,
            len: 0,
            shift: 0,
            target_shift: 0,
        })
    }

    /// Bytes of storage in use (a power of two, at most `N`).
    #[inline]
    pub const fn capacity(&self) -> usize {
        N >> self.shift
    }

    /// The capacity [`Self::try_resize`] moves to (see [`Self::set_target`]).
    #[inline]
    pub const fn target(&self) -> usize {
        N >> self.target_shift
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Free space within the current capacity: what may be written now.
    #[inline]
    pub const fn free(&self) -> usize {
        self.capacity().saturating_sub(self.len)
    }

    /// Free space within both the capacity and the target: what may be
    /// *offered* (advertised to a peer, accepted from an application) while
    /// a smaller target waits to take effect. Equals [`Self::free`] unless a
    /// shrink is pending.
    #[inline]
    pub const fn room(&self) -> usize {
        let cap = self.capacity();
        let target = self.target();
        let limit = if target < cap { target } else { cap };
        limit.saturating_sub(self.len)
    }

    /// Ask for a capacity of `bytes`, clamped to `1..=N` and rounded down to a
    /// power of two. It takes effect at the next successful
    /// [`Self::try_resize`]; until then [`Self::room`] already honours a
    /// smaller target.
    pub fn set_target(&mut self, bytes: usize) {
        let b = bytes.clamp(1, N);
        let log_b = b.checked_ilog2().unwrap_or(0);
        let log_n = N.checked_ilog2().unwrap_or(0);
        self.target_shift = u8::try_from(log_n.saturating_sub(log_b)).unwrap_or(0);
    }

    /// Move the capacity to the target, if everything that must survive fits
    /// in it: the readable bytes, `keep` bytes parked past the write cursor
    /// whose contents must be preserved (see [`Self::write_at`]), and
    /// `reserve` bytes of free space past the readable bytes that must stay
    /// writable (a window already promised to a peer). Returns whether the
    /// capacity now equals the target.
    ///
    /// Bytes keep their offsets from the cursors, so offsets the caller holds
    /// ([`Self::peek_at`], [`Self::write_at`]) stay valid; their storage
    /// addresses do not, so never resize while space lent out through
    /// [`Self::free_regions`] is still being filled. Nothing moves when the
    /// live bytes already sit below the new boundary without wrapping;
    /// otherwise they move to the start of the storage, at most one
    /// capacity's worth of copying.
    pub fn try_resize(&mut self, keep: usize, reserve: usize) -> bool {
        let cap = self.capacity();
        let new = self.target();
        if new == cap {
            return true;
        }
        let span = self.len.saturating_add(keep);
        if span > cap || self.len.saturating_add(keep.max(reserve)) > new {
            return false;
        }
        let at = self.head & (cap - 1);
        let base = if at.saturating_add(span) <= cap.min(new) {
            at // already below both boundaries: nothing moves
        } else if at + span <= cap {
            // Contiguous but above the new (smaller) boundary.
            if let Some(s) = self.buf.get_mut(..cap) {
                s.copy_within(at..at + span, 0);
            }
            0
        } else {
            // Wraps the end of the storage in use: rotate it to the front.
            if let Some(s) = self.buf.get_mut(..cap) {
                s.rotate_left(at);
            }
            0
        };
        self.head = base;
        self.tail = base + self.len;
        self.shift = self.target_shift;
        true
    }

    /// Storage the ring will not read before writing it again, for a host to
    /// release (for example `madvise(MADV_DONTNEED)` on the whole pages
    /// inside it) or overwrite freely: all of it when the ring holds nothing
    /// (no readable bytes and `keep == 0` parked bytes), otherwise everything
    /// past the capacity. Free space lent out through [`Self::free_regions`]
    /// is the caller's to exclude.
    pub fn spare_mut(&mut self, keep: usize) -> &mut [u8] {
        let from = if self.len == 0 && keep == 0 {
            0
        } else {
            self.capacity()
        };
        self.buf.get_mut(from..).unwrap_or_default()
    }

    /// Internal consistency (tests and fuzz targets).
    #[cfg(any(test, feature = "std"))]
    pub fn debug_valid(&self) -> Result<(), &'static str> {
        let log_n = N.checked_ilog2().unwrap_or(0);
        if u32::from(self.shift) > log_n || u32::from(self.target_shift) > log_n {
            return Err("ring capacity shift out of range");
        }
        if self.len > self.capacity() {
            return Err("ring holds more than its capacity");
        }
        if self.tail.wrapping_sub(self.head) != self.len {
            return Err("ring cursors disagree with its length");
        }
        Ok(())
    }

    /// Append as many bytes from `src` as will fit. Returns the number copied.
    pub fn write(&mut self, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.free());
        if n == 0 {
            return 0;
        }
        let cap = self.capacity();
        let mask = cap - 1;
        let first = core::cmp::min(n, cap - (self.tail & mask));
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
        let cap = self.capacity();
        let head_off = self.head & (cap - 1);
        let first = core::cmp::min(n, cap - head_off);
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
        let cap = self.capacity();
        let start = (self.head.wrapping_add(offset)) & (cap - 1);
        let first = core::cmp::min(n, cap - start);
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
        let cap = self.capacity();
        let start = self.tail.wrapping_add(offset) & (cap - 1);
        let first = core::cmp::min(n, cap - start);
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
    /// valid data (written by [`Self::write_at`] or through
    /// [`Self::free_regions`]). Clipped to free space; returns the number of
    /// bytes committed.
    pub fn commit(&mut self, n: usize) -> usize {
        let n = core::cmp::min(n, self.free());
        self.tail = self.tail.wrapping_add(n);
        self.len += n;
        n
    }

    /// The free space past the write cursor, up to `max` bytes, as at most
    /// two slices: the second is empty unless the space wraps the end of the
    /// storage. Bytes written there become readable through [`Self::commit`].
    pub fn free_regions(&mut self, max: usize) -> (&mut [u8], &mut [u8]) {
        let n = core::cmp::min(max, self.free());
        let cap = self.capacity();
        let start = self.tail & (cap - 1);
        let first = core::cmp::min(n, cap - start);
        let wrapped = n - first;
        match self.buf.split_at_mut_checked(start) {
            Some((before, after)) => (
                after.get_mut(..first).unwrap_or_default(),
                before.get_mut(..wrapped).unwrap_or_default(),
            ),
            None => (&mut [], &mut []),
        }
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
    /// connection inherits empty rings without re-allocating. The capacity
    /// and target are kept.
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

    #[test]
    fn free_regions_split_where_the_free_space_wraps() {
        let mut r: Ring<16> = Ring::new().unwrap();
        assert_eq!(r.write(&[0xaa; 12]), 12);
        let mut sink = [0u8; 10];
        assert_eq!(r.read(&mut sink), 10);
        let (a, b) = r.free_regions(100);
        assert_eq!(
            (a.len(), b.len()),
            (4, 10),
            "all 14 free bytes, split at the end"
        );
        a.copy_from_slice(&[1, 2, 3, 4]);
        b[..3].copy_from_slice(&[5, 6, 7]);
        assert_eq!(r.commit(7), 7);
        let mut out = [0u8; 9];
        assert_eq!(r.read(&mut out), 9);
        assert_eq!(out, [0xaa, 0xaa, 1, 2, 3, 4, 5, 6, 7]);
        let (a, b) = r.free_regions(3);
        assert_eq!((a.len(), b.len()), (3, 0), "clipped to max");
    }

    /// Ring holding the stream bytes `from..to` (byte `i` is `i as u8`).
    fn push(r: &mut Ring<16>, from: u8, to: u8) {
        let bytes: std::vec::Vec<u8> = (from..to).collect();
        assert_eq!(r.write(&bytes), bytes.len());
    }

    fn drain(r: &mut Ring<16>) -> std::vec::Vec<u8> {
        let mut out = [0u8; 16];
        let n = r.read(&mut out);
        out[..n].to_vec()
    }

    #[test]
    fn a_new_ring_uses_all_of_its_storage() {
        let r: Ring<16> = Ring::new().unwrap();
        assert_eq!(
            (r.capacity(), r.target(), r.free(), r.room()),
            (16, 16, 16, 16)
        );
        r.debug_valid().unwrap();
    }

    #[test]
    fn set_target_rounds_down_to_a_power_of_two_within_the_storage() {
        let mut r: Ring<16> = Ring::new().unwrap();
        for (ask, want) in [(0, 1), (1, 1), (3, 2), (4, 4), (9, 8), (16, 16), (999, 16)] {
            r.set_target(ask);
            assert_eq!(r.target(), want, "set_target({ask})");
            assert_eq!(r.capacity(), 16, "only try_resize moves the capacity");
        }
    }

    #[test]
    fn growing_rotates_wrapped_bytes_and_keeps_parked_ones() {
        let mut r: Ring<16> = Ring::new().unwrap();
        r.set_target(8);
        assert!(r.try_resize(0, 0));
        push(&mut r, 0, 6);
        let mut sink = [0u8; 4];
        assert_eq!(r.read(&mut sink), 4);
        push(&mut r, 6, 11); // bytes 4..11 wrap the 8-byte storage
        assert_eq!(r.write_at(0, &[11]), 1, "park byte 11 past the tail");
        r.set_target(16);
        assert!(r.try_resize(1, 0));
        assert_eq!((r.capacity(), r.head), (16, 0), "rotated to the front");
        r.debug_valid().unwrap();
        assert_eq!(r.commit(1), 1);
        assert_eq!(drain(&mut r), (4..12).collect::<std::vec::Vec<u8>>());
    }

    #[test]
    fn shrinking_copies_contiguous_bytes_below_the_new_boundary() {
        let mut r: Ring<16> = Ring::new().unwrap();
        push(&mut r, 0, 10);
        let mut sink = [0u8; 8];
        assert_eq!(r.read(&mut sink), 8);
        r.set_target(4);
        assert!(r.try_resize(0, 0));
        assert_eq!((r.capacity(), r.head, r.free()), (4, 0, 2));
        push(&mut r, 10, 12);
        assert_eq!(r.write(&[0]), 0, "full at the new capacity");
        assert_eq!(drain(&mut r), [8, 9, 10, 11]);
    }

    #[test]
    fn shrinking_moves_nothing_when_the_bytes_already_fit() {
        let mut r: Ring<16> = Ring::new().unwrap();
        push(&mut r, 0, 5);
        let mut sink = [0u8; 2];
        assert_eq!(r.read(&mut sink), 2);
        r.set_target(8);
        assert!(r.try_resize(0, 0));
        assert_eq!((r.capacity(), r.head, r.tail), (8, 2, 5), "in place");
        assert_eq!(drain(&mut r), [2, 3, 4]);
    }

    #[test]
    fn shrinking_rotates_bytes_that_wrap() {
        let mut r: Ring<16> = Ring::new().unwrap();
        push(&mut r, 0, 14);
        let mut sink = [0u8; 12];
        assert_eq!(r.read(&mut sink), 12);
        push(&mut r, 14, 17); // 12..17 wraps the 16-byte storage
        r.set_target(8);
        assert!(r.try_resize(0, 0));
        assert_eq!((r.capacity(), r.head), (8, 0));
        assert_eq!(drain(&mut r), [12, 13, 14, 15, 16]);
    }

    #[test]
    fn a_shrink_waits_for_data_parked_bytes_and_promised_space() {
        let mut r: Ring<16> = Ring::new().unwrap();
        push(&mut r, 0, 6);
        r.set_target(4);
        assert_eq!((r.room(), r.free()), (0, 10), "nothing new is offered");
        assert!(!r.try_resize(0, 0), "6 readable bytes exceed 4");
        let mut sink = [0u8; 3];
        assert_eq!(r.read(&mut sink), 3);
        assert_eq!(r.room(), 1);
        assert!(!r.try_resize(0, 2), "3 + 2 promised bytes exceed 4");
        assert!(!r.try_resize(2, 0), "3 + 2 parked bytes exceed 4");
        assert!(r.try_resize(1, 1));
        assert_eq!((r.capacity(), r.free(), r.room()), (4, 1, 1));
        assert_eq!(drain(&mut r), [3, 4, 5]);
        r.set_target(8);
        assert!(
            !r.try_resize(5, 0),
            "a parked span past the capacity is refused"
        );
        assert!(r.try_resize(4, 0));
    }

    /// The consistency check is live: it trips on each corruption it guards.
    #[test]
    fn debug_valid_reports_corrupt_state() {
        let mut r: Ring<16> = Ring::new().unwrap();
        r.shift = 5;
        assert_eq!(r.debug_valid(), Err("ring capacity shift out of range"));
        r.shift = 0;
        r.len = 17;
        assert_eq!(r.debug_valid(), Err("ring holds more than its capacity"));
        r.len = 0;
        r.tail = 1;
        assert_eq!(
            r.debug_valid(),
            Err("ring cursors disagree with its length")
        );
        r.tail = 0;
        r.debug_valid().unwrap();
    }

    #[test]
    fn spare_storage_is_all_of_an_empty_ring_else_what_lies_past_the_capacity() {
        let mut r: Ring<16> = Ring::new().unwrap();
        assert_eq!(r.spare_mut(0).len(), 16);
        r.set_target(4);
        assert!(r.try_resize(0, 0));
        assert_eq!(r.spare_mut(0).len(), 16, "empty");
        assert_eq!(
            r.spare_mut(1).len(),
            12,
            "parked bytes live in the capacity"
        );
        push(&mut r, 0, 1);
        r.spare_mut(0).fill(0xA5);
        push(&mut r, 1, 4);
        assert_eq!(drain(&mut r), [0, 1, 2, 3], "spare bytes are never read");
    }
}
