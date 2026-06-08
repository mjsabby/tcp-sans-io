//! Coverage-guided **two-stack loopback** fuzzing with a *convergence* oracle
//! — the deadlock / sender-stall catcher. The full rationale and the generic
//! engine live in `../loopback_engine.rs`.
//!
//! This is the production-sized variant: megabyte rings, so it also exercises
//! ring wrap-around and large in-flight windows. The companion
//! `tcb_loopback_small` target shrinks the rings to hammer the slow-start /
//! loss-recovery / small-window edge states far faster.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../loopback_engine.rs"]
mod engine;

fuzz_target!(|data: &[u8]| {
    engine::run::<{ tcp_sans_io::BUF_CAP }>(data, 96 * 1024, 4096);
});
