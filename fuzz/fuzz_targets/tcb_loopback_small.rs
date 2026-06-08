//! Small-ring variant of the two-stack loopback convergence / deadlock oracle.
//!
//! With 8 KiB rings the send/receive windows stay tiny, so every transfer is a
//! continuous slow-start + loss-recovery churn that drives the stack through
//! the credit / flight / reassembly-hole edge states — where deadlocks hide —
//! in a fraction of the iterations (and many times the exec/s) of the
//! megabyte-ring `tcb_loopback`. The oracle is identical: eventual-reliability
//! convergence plus the per-step liveness (no black-hole) check.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../loopback_engine.rs"]
mod engine;

fuzz_target!(|data: &[u8]| {
    engine::run::<8192>(data, 48 * 1024, 1024);
});
