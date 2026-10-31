//! The resizable byte ring against a model: any sequence of writes, reads,
//! out-of-order parking, commits, lent-space fills, peeks, retargets and
//! resizes keeps the ring's readable bytes, parked bytes, capacity, free
//! space and room equal to a straightforward model — the property
//! `property_tests::resizable_ring_matches_model` samples, explored here
//! with coverage guidance over three storage sizes. Every step also
//! overwrites the storage `spare_mut` reports as dead, which must never
//! surface in the stream.

#![no_main]

use std::collections::VecDeque;

use libfuzzer_sys::fuzz_target;
use tcp_sans_io::ring::Ring;

struct In<'a> {
    d: &'a [u8],
    i: usize,
}

impl In<'_> {
    fn u8(&mut self) -> u8 {
        let v = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        v
    }
    /// A size in `0..=2 * n`, biased toward small values and `n` itself.
    fn size(&mut self, n: usize) -> usize {
        match self.u8() {
            b @ 0..=191 => usize::from(b) % (n + 1),
            b @ 192..=223 => n.saturating_sub(usize::from(b - 192)),
            b => n + usize::from(b) % (n + 1),
        }
    }
    fn done(&self) -> bool {
        self.i >= self.d.len()
    }
}

fn run<const N: usize>(data: &[u8]) {
    let mut inp = In { d: data, i: 0 };
    let mut ring: Ring<N> = Ring::new().unwrap();
    let mut data: VecDeque<u8> = VecDeque::new();
    // Bytes parked past the write cursor, by offset.
    let mut parked: Vec<Option<u8>> = Vec::new();
    let (mut cap, mut target) = (N, N);
    let mut next = 0u8;
    let mut fresh = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                next = next.wrapping_add(1);
                next
            })
            .collect()
    };
    for _ in 0..512 {
        if inp.done() {
            break;
        }
        match inp.u8() % 9 {
            0 => {
                let src = fresh(inp.size(N));
                let w = ring.write(&src);
                assert_eq!(w, src.len().min(cap - data.len()), "write count");
                data.extend(&src[..w]);
                parked.drain(..w.min(parked.len()));
            }
            1 => {
                let mut buf = vec![0u8; inp.size(N)];
                let r = ring.read(&mut buf);
                assert_eq!(r, buf.len().min(data.len()), "read count");
                let want: Vec<u8> = data.drain(..r).collect();
                assert_eq!(&buf[..r], &want[..], "read bytes");
            }
            2 => {
                let off = inp.size(N);
                let src = fresh(inp.size(N / 2 + 1));
                let free = cap - data.len();
                let w = ring.write_at(off, &src);
                let want = if off >= free {
                    0
                } else {
                    src.len().min(free - off)
                };
                assert_eq!(w, want, "write_at count");
                if w > 0 {
                    if parked.len() < off + w {
                        parked.resize(off + w, None);
                    }
                    for (i, &b) in src[..w].iter().enumerate() {
                        parked[off + i] = Some(b);
                    }
                }
            }
            3 => {
                let n = inp.size(N);
                let prefix = parked.iter().take_while(|b| b.is_some()).count();
                let c = ring.commit(n.min(prefix));
                assert_eq!(c, n.min(prefix), "commit count");
                data.extend(parked.drain(..c).map(Option::unwrap));
            }
            4 => {
                // Fill lent free space in place, then commit part of it.
                let max = inp.size(N);
                let fill = inp.size(N);
                let src = fresh(fill);
                let (a, b) = ring.free_regions(max);
                let lent = a.len() + b.len();
                assert_eq!(lent, max.min(cap - data.len()), "lent space");
                let n = fill.min(lent);
                let first = n.min(a.len());
                a[..first].copy_from_slice(&src[..first]);
                b[..n - first].copy_from_slice(&src[first..n]);
                assert_eq!(ring.commit(n), n);
                data.extend(&src[..n]);
                parked.drain(..n.min(parked.len()));
            }
            5 => {
                let off = inp.size(N);
                let mut buf = vec![0u8; inp.size(N)];
                let p = ring.peek_at(off, &mut buf);
                let want: Vec<u8> = data.iter().skip(off).take(buf.len()).copied().collect();
                assert_eq!(&buf[..p], &want[..], "peek_at bytes");
            }
            6 => {
                let b = inp.size(N);
                ring.set_target(b);
                target = 1 << b.clamp(1, N).ilog2();
                assert_eq!(ring.target(), target);
            }
            7 => {
                let keep = parked
                    .iter()
                    .rposition(Option::is_some)
                    .map_or(0, |i| i + 1);
                let reserve = inp.size(N);
                let fits = data.len() + keep.max(reserve) <= target;
                let ok = ring.try_resize(keep, reserve);
                assert_eq!(ok, target == cap || fits, "resize decision");
                if ok {
                    cap = target;
                }
            }
            _ => {
                // Dead storage may be overwritten at will.
                let keep = parked
                    .iter()
                    .rposition(Option::is_some)
                    .map_or(0, |i| i + 1);
                let spare = ring.spare_mut(keep);
                let want = if data.is_empty() && keep == 0 { N } else { N - cap };
                assert_eq!(spare.len(), want, "spare span");
                spare.fill(0xA5);
            }
        }
        assert_eq!(ring.capacity(), cap);
        assert_eq!(ring.len(), data.len());
        assert_eq!(ring.free(), cap - data.len());
        assert_eq!(ring.room(), cap.min(target).saturating_sub(data.len()));
        ring.debug_valid().unwrap();
        let mut all = vec![0u8; data.len()];
        assert_eq!(ring.peek(&mut all), data.len());
        assert!(all.iter().eq(data.iter()), "readable bytes diverged");
    }
    // Parked bytes come out where they were put.
    let prefix = parked.iter().take_while(|b| b.is_some()).count();
    assert_eq!(ring.commit(prefix), prefix);
    data.extend(parked.drain(..prefix).map(Option::unwrap));
    let mut all = vec![0u8; data.len()];
    assert_eq!(ring.read(&mut all), data.len());
    assert!(all.iter().eq(data.iter()), "parked bytes diverged");
}

fuzz_target!(|data: &[u8]| {
    let (Some(&sel), rest) = (data.first(), data.get(1..).unwrap_or(&[])) else {
        return;
    };
    match sel % 3 {
        0 => run::<8>(rest),
        1 => run::<64>(rest),
        _ => run::<1024>(rest),
    }
});
