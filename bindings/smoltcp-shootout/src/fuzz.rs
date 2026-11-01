//! Robustness: a deterministic mutation fuzzer feeds the same stream of
//! malformed and hostile segments to a listener and to an established
//! connection of each stack, counting panics and (for tcp-sans-io, which
//! exposes them) internal-invariant violations.

use std::cell::Cell;
use std::panic::{self, AssertUnwindSafe};

use crate::net::Rng;
use crate::pkt::{self, Build, ACK, FIN, PSH, RST, SYN};
use crate::probes::Lab;
use crate::report::Table;
use crate::sim::MS;
use crate::stacks::{Pkt, Spec};

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Silences panic messages only while a stack processes fuzzed input (a
/// harness panic still prints); the default hook returns on drop.
struct QuietHook;

impl QuietHook {
    fn install() -> Self {
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                prev(info);
            }
        }));
        QuietHook
    }
}

impl Drop for QuietHook {
    fn drop(&mut self) {
        // take_hook panics on a panicking thread; the wrapper is harmless
        // there anyway, as it only stays quiet inside `quietly`.
        if !std::thread::panicking() {
            drop(panic::take_hook());
        }
    }
}

fn quietly(f: impl FnOnce()) -> std::thread::Result<()> {
    QUIET.with(|q| q.set(true));
    let r = panic::catch_unwind(AssertUnwindSafe(f));
    QUIET.with(|q| q.set(false));
    r
}

pub struct FuzzResult {
    pub spec: Spec,
    pub packets: u64,
    pub panics: u64,
    pub first_panic: Option<(String, Vec<u8>)>,
    pub invariant_breaks: u64,
    pub resets: u64,
}

fn near(rng: &mut Rng, x: u32) -> u32 {
    match rng.below(5) {
        0 => x,
        1 => x.wrapping_add(rng.below(1 << 16) as u32),
        2 => x.wrapping_sub(rng.below(1 << 16) as u32),
        3 => x.wrapping_add(rng.below(4) as u32).wrapping_sub(2),
        _ => rng.next() as u32,
    }
}

/// One hostile segment for the connection `l` describes.
fn gen(rng: &mut Rng, l: &mut Lab) -> Vec<u8> {
    let flags = match rng.below(8) {
        0 => rng.next() as u8,
        1 => SYN,
        2 => RST,
        3 => RST | ACK,
        4 => FIN | ACK,
        5 => SYN | ACK,
        _ => ACK | PSH,
    };
    let mut b: Build = l.seg(flags);
    b.seq = near(rng, l.snd_nxt);
    b.ack = near(rng, l.rcv_nxt);
    b.win = rng.next() as u16;
    if rng.below(4) == 0 {
        b.mss = Some(rng.next() as u16);
    }
    if rng.below(4) == 0 {
        b.ws = Some(rng.below(20) as u8);
    }
    b.sack_ok = rng.below(4) == 0;
    if rng.below(3) == 0 {
        b.ts = Some((near(rng, l.tsval()), near(rng, l.ts_recent)));
    }
    for _ in 0..rng.below(4) {
        let a = near(rng, l.rcv_nxt);
        b.sacks.push((a, a.wrapping_add(rng.below(1 << 15) as u32)));
    }
    let len = match rng.below(4) {
        0 => rng.below(1400) as usize,
        1 => rng.below(8) as usize,
        _ => 0,
    };
    b.payload = (0..len).map(|_| rng.next() as u8).collect();
    let mut p = b.emit();
    match rng.below(10) {
        // Byte flips, mostly with checksums repaired so they reach TCP.
        5..=7 => {
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(p.len() as u64) as usize;
                p[i] ^= 1 + rng.below(255) as u8;
            }
            if rng.below(10) != 0 {
                pkt::fix_checksums(&mut p);
            }
        }
        // Truncated or padded datagrams.
        8 => {
            if rng.below(2) == 0 {
                p.truncate(rng.below(p.len() as u64 + 1) as usize);
            } else {
                p.extend((0..rng.below(64)).map(|_| rng.next() as u8));
            }
        }
        // Garbage in the option area, any data offset.
        9 if p.len() >= 40 => {
            p[32] = (rng.below(16) as u8) << 4;
            let end = p.len().min(60);
            for b in &mut p[40..end] {
                *b = rng.next() as u8;
            }
            pkt::fix_checksums(&mut p);
        }
        _ => {}
    }
    p
}

fn fresh(spec: Spec, listen: bool) -> Lab {
    if listen {
        return Lab::server(spec);
    }
    Lab::established(spec).unwrap_or_else(|_| Lab::server(spec))
}

pub fn run(spec: Spec, n: u64, seed: u64) -> FuzzResult {
    let mut r = FuzzResult {
        spec,
        packets: 0,
        panics: 0,
        first_panic: None,
        invariant_breaks: 0,
        resets: 0,
    };
    let _hook = QuietHook::install();
    for listen in [true, false] {
        let mut rng = Rng::new(seed ^ u64::from(listen));
        let mut l = fresh(spec, listen);
        for i in 0..n / 2 {
            let p = gen(&mut rng, &mut l);
            let now = l.now;
            let res = quietly(|| {
                l.sut.input(now, Pkt::from_slice(&p));
                l.sut.poll(now);
                let mut out = Vec::new();
                l.sut.drain(&mut out);
                // Let timers run now and then, on whatever state the
                // segment left behind.
                if i % 64 == 63 {
                    l.advance(MS);
                    l.take();
                }
            });
            r.packets += 1;
            if let Err(e) = res {
                r.panics += 1;
                if r.first_panic.is_none() {
                    let msg = e
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_default();
                    r.first_panic = Some((msg, p.clone()));
                }
                l = fresh(spec, listen);
                continue;
            }
            if l.sut.invariants().is_err() {
                r.invariant_breaks += 1;
                l = fresh(spec, listen);
                continue;
            }
            // A fuzzed segment may legitimately end or move the connection
            // (an exact RST, a valid FIN, accepted data): start over.
            let st = l.sut.state();
            let lost = if listen {
                st != crate::stacks::St::Listen && st != crate::stacks::St::SynRcvd
            } else {
                st != crate::stacks::St::Established
            };
            if lost || i % 4096 == 4095 {
                r.resets += u64::from(lost && l.sut.was_reset());
                l = fresh(spec, listen);
            }
        }
    }
    r
}

pub fn print(res: &[FuzzResult]) {
    let mut t = Table::new([
        "Stack",
        "Segments",
        "Panics",
        "Invariant violations",
        "Connections reset by a fuzzed segment",
    ]);
    for r in res {
        t.row([
            r.spec.label(),
            r.packets.to_string(),
            r.panics.to_string(),
            if r.spec.is_ours() {
                r.invariant_breaks.to_string()
            } else {
                "n/a".into()
            },
            r.resets.to_string(),
        ]);
    }
    t.print();
    for r in res {
        if let Some((msg, p)) = &r.first_panic {
            let hex: String = p.iter().map(|b| format!("{b:02x}")).collect();
            println!("- {} first panic: {msg}\n  input: {hex}", r.spec.label());
        }
    }
    println!();
}
