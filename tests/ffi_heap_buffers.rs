//! `tcp_destroy` must release what the TCB owns. Under `heap-buffers` the
//! two rings are boxed, and destroy used to only flip the magic guard,
//! leaking both (2 MiB per handle by default) on every connection churned.
//! A counting global allocator needs its own test binary:
//!
//! `cargo test --release --features std,heap-buffers --test ffi_heap_buffers`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::alloc::{alloc, dealloc, GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use tcp_sans_io::ffi::{tcp_destroy, tcp_handle_align, tcp_handle_size, tcp_init};
use tcp_sans_io::BUF_CAP;

/// Live allocations of exactly one ring's size.
static LIVE_RINGS: AtomicIsize = AtomicIsize::new(0);

struct CountRings;

// SAFETY: every call is forwarded unchanged to `System`.
unsafe impl GlobalAlloc for CountRings {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded caller contract.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() && layout.size() == BUF_CAP {
            LIVE_RINGS.fetch_add(1, Ordering::SeqCst);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        if layout.size() == BUF_CAP {
            LIVE_RINGS.fetch_sub(1, Ordering::SeqCst);
        }
        // SAFETY: forwarded caller contract.
        unsafe { System.dealloc(p, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountRings = CountRings;

#[test]
fn tcp_destroy_releases_heap_buffers() {
    let layout = Layout::from_size_align(tcp_handle_size(), tcp_handle_align()).unwrap();
    let ip = [10u8, 0, 0, 1];
    let before = LIVE_RINGS.load(Ordering::SeqCst);
    for _ in 0..3 {
        // SAFETY: storage of the documented size and alignment, initialised
        // by `tcp_init`, destroyed once and only then freed.
        unsafe {
            let storage = alloc(layout);
            assert!(!storage.is_null());
            let h = storage.cast();
            assert_eq!(tcp_init(h, ip.as_ptr(), 1, ip.as_ptr(), 2, 7, 1000), 0);
            assert_eq!(LIVE_RINGS.load(Ordering::SeqCst) - before, 2);
            assert_eq!(tcp_destroy(h), 0);
            assert_ne!(tcp_destroy(h), 0, "a second destroy is rejected");
            dealloc(storage, layout);
        }
        assert_eq!(
            LIVE_RINGS.load(Ordering::SeqCst) - before,
            0,
            "rings leaked past tcp_destroy"
        );
    }
}
