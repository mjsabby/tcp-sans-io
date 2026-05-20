//! Fuzz `wire::parse` against arbitrary bytes.
//!
//! The contract is: `parse` must never panic on any input — the entire
//! adversarial surface from hostile peers funnels through this function.
//! Errors are fine; panics, infinite loops, or memory-safety violations
//! are bugs.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tcp_sans_io::wire::parse(data);
});
