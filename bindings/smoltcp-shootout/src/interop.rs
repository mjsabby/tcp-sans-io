//! Interop matrix: both stacks against each other in both roles (and each
//! against itself as a baseline), across impaired links and connection
//! lifecycle variations. A case passes when both byte streams arrive intact
//! (verified against the generator), both sides see EOF and both reach
//! CLOSED / TIME_WAIT without a reset — or, for the abort case, when the
//! reset is seen and both sides are closed.

use crate::net::LinkCfg;
use crate::report::{secs, Table};
use crate::sim::{self, App, ClosePolicy, Goal, Outcome, Scenario, Sim, KIB, MIB, MS, SEC};
use crate::stacks::{self, Opts, Spec};

pub struct Case {
    pub name: &'static str,
    pub what: &'static str,
    make: fn(Spec, Spec) -> (Scenario, Goal),
}

const LAN: LinkCfg = LinkCfg::new(5, 100, 1000);

fn base(c: Spec, s: Spec, link: LinkCfg, up: u64, down: u64) -> Scenario {
    let mut sc = Scenario::new(c, s, link);
    sc.client_app = App::sender(up);
    sc.server_app = App::sender(down);
    sc
}

fn small(s: Spec) -> Spec {
    if s.is_ours() {
        Spec::Ours64k
    } else {
        s.with_buf(64 * 1024)
    }
}

fn tiny_smol(s: Spec) -> Spec {
    if s.is_ours() {
        s
    } else {
        s.with_buf(4 * 1024)
    }
}

/// ISS within 1 MiB below 2^32 on both sides, so both streams wrap early.
fn near_wrap(isn: u32) -> bool {
    isn >= u32::MAX - MIB as u32
}

fn wrap_seeds(sc: &mut Scenario) -> Result<(), String> {
    let copts = |seed| Opts {
        local: (sim::CLIENT_IP, sim::CLIENT_PORT),
        remote: (sim::SERVER_IP, sim::SERVER_PORT),
        seed,
        mtu: 1500,
    };
    let mut out = Vec::new();
    let found = (0..200_000u64).find(|&seed| {
        let mut st = stacks::build(sc.client, &copts(seed));
        st.connect(0);
        st.drain(&mut out);
        let iss = out
            .first()
            .and_then(|p| crate::pkt::parse(p))
            .map(|s| s.seq);
        out.clear();
        iss.is_some_and(near_wrap)
    });
    sc.client_seed = found.ok_or("no client seed with a wrapping ISS")?;
    let found = (0..200_000u64).find(|&seed| {
        sc.server_seed = seed;
        let mut sim = Sim::new(sc);
        sim.check_invariants = false;
        sim.run(Goal::SynAck, 10 * SEC).is_ok() && sim.rev.stats.isn().is_some_and(near_wrap)
    });
    sc.server_seed = found.ok_or("no server seed with a wrapping ISS")?;
    Ok(())
}

pub fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "clean",
            what: "1 MiB each way; 10 ms RTT, 100 Mbit/s",
            make: |c, s| (base(c, s, LAN, MIB, MIB), Goal::CleanClose),
        },
        Case {
            name: "loss 2%",
            what: "2% random loss both ways",
            make: |c, s| (base(c, s, LAN.loss(20_000), MIB, MIB), Goal::CleanClose),
        },
        Case {
            name: "reorder 3%",
            what: "3% of packets held back 3 ms, both ways",
            make: |c, s| {
                (
                    base(c, s, LAN.reorder(30_000, 3), MIB, MIB),
                    Goal::CleanClose,
                )
            },
        },
        Case {
            name: "duplicate 2%",
            what: "2% of packets delivered twice",
            make: |c, s| (base(c, s, LAN.dup(20_000), MIB, MIB), Goal::CleanClose),
        },
        Case {
            name: "corrupt 1%",
            what: "1% of packets get a flipped byte (checksums must catch it)",
            make: |c, s| (base(c, s, LAN.corrupt(10_000), MIB, MIB), Goal::CleanClose),
        },
        Case {
            name: "kitchen sink",
            what: "1% loss, 1% reorder, 1% duplicate, 0.5% corrupt, both ways",
            make: |c, s| {
                let l = LAN
                    .loss(10_000)
                    .reorder(10_000, 2)
                    .dup(10_000)
                    .corrupt(5_000);
                (base(c, s, l, MIB, MIB), Goal::CleanClose)
            },
        },
        Case {
            name: "ACK loss 20%",
            what: "2 MiB upload; 20% of the reverse path lost",
            make: |c, s| {
                let mut sc = base(c, s, LAN, 2 * MIB, 0);
                sc.rev = LAN.loss(200_000);
                (sc, Goal::CleanClose)
            },
        },
        Case {
            name: "SYN, SYN-ACK lost",
            what: "first SYN and first SYN-ACK dropped",
            make: |c, s| {
                (
                    base(c, s, LAN.drop_syns(1), 64 * KIB, 64 * KIB),
                    Goal::CleanClose,
                )
            },
        },
        Case {
            name: "server MTU 576",
            what: "server MSS 536: both directions must honour it",
            make: |c, s| {
                let mut sc = base(c, s, LAN, 256 * KIB, 256 * KIB);
                sc.server_mtu = 576;
                (sc, Goal::CleanClose)
            },
        },
        Case {
            name: "slow reader",
            what: "64 KiB buffers; 1 MiB to a 100 KB/s reader (zero windows)",
            make: |c, s| {
                let mut sc = base(small(c), small(s), LAN, MIB, 0);
                sc.server_app.read_rate = Some(100);
                (sc, Goal::CleanClose)
            },
        },
        Case {
            name: "4 KiB smoltcp window",
            what: "smoltcp with 4 KiB buffers; 256 KiB each way",
            make: |c, s| {
                (
                    base(tiny_smol(c), tiny_smol(s), LAN, 256 * KIB, 256 * KIB),
                    Goal::CleanClose,
                )
            },
        },
        Case {
            name: "half-close",
            what: "64 KiB request + FIN, then 1 MiB response + FIN",
            make: |c, s| {
                let mut sc = base(c, s, LAN, 64 * KIB, MIB);
                sc.client_app.close = ClosePolicy::AfterSend;
                sc.server_app.respond_after_eof = true;
                sc.server_app.close = ClosePolicy::AfterSend;
                (sc, Goal::CleanClose)
            },
        },
        Case {
            name: "simultaneous close",
            what: "64 KiB each way, then both FIN at t=200 ms (FINs cross)",
            make: |c, s| {
                let mut sc = base(c, s, LAN, 64 * KIB, 64 * KIB);
                sc.client_app.close = ClosePolicy::At(200 * MS);
                sc.server_app.close = ClosePolicy::At(200 * MS);
                (sc, Goal::CleanClose)
            },
        },
        Case {
            name: "sequence wrap",
            what: "both ISNs within 1 MiB of 2^32; 2 MiB each way, 1% loss",
            make: |c, s| {
                (
                    base(c, s, LAN.loss(10_000), 2 * MIB, 2 * MIB),
                    Goal::CleanClose,
                )
            },
        },
        Case {
            name: "no timestamps",
            what: "smoltcp without its TS generator (its default); 1% loss",
            make: |c, s| {
                (
                    base(
                        c.with_ts(false),
                        s.with_ts(false),
                        LAN.loss(10_000),
                        MIB,
                        MIB,
                    ),
                    Goal::CleanClose,
                )
            },
        },
        Case {
            name: "peer aborts",
            what: "server aborts (RST) after 256 KiB of a 1 MiB upload",
            make: |c, s| {
                let mut sc = base(c, s, LAN, MIB, 0);
                sc.client_app.close = ClosePolicy::Never;
                sc.server_app.abort_after = Some(256 * KIB);
                (sc, Goal::Reset)
            },
        },
    ]
}

pub fn pairings() -> Vec<(Spec, Spec)> {
    vec![
        (Spec::Ours, Spec::SMOL),
        (Spec::SMOL, Spec::Ours),
        (Spec::Ours, Spec::Ours),
        (Spec::SMOL, Spec::SMOL),
    ]
}

pub struct Res {
    pub case: &'static str,
    pub client: Spec,
    pub server: Spec,
    pub out: Outcome,
}

pub fn run_case(case: &Case, c: Spec, s: Spec) -> Outcome {
    let (mut sc, goal) = (case.make)(c, s);
    if case.name == "sequence wrap" {
        if let Err(e) = wrap_seeds(&mut sc) {
            return Outcome {
                error: Some(e),
                ..Outcome::default()
            };
        }
    }
    sim::run(&sc, goal)
}

pub fn run() -> Vec<Res> {
    let mut res = Vec::new();
    for case in cases() {
        for (c, s) in pairings() {
            let out = run_case(&case, c, s);
            res.push(Res {
                case: case.name,
                client: c,
                server: s,
                out,
            });
        }
    }
    res
}

/// One case, one pairing, in detail (optionally with a packet trace).
pub fn diag(name: &str, c: Spec, s: Spec, trace: bool) {
    let Some(case) = cases().into_iter().find(|k| k.name == name) else {
        eprintln!("no such case: {name}");
        return;
    };
    let (mut sc, goal) = (case.make)(c, s);
    if case.name == "sequence wrap" {
        if let Err(e) = wrap_seeds(&mut sc) {
            eprintln!("{e}");
            return;
        }
    }
    sc.trace = trace;
    let o = sim::run(&sc, goal);
    println!(
        "{} ({} → {}): {}",
        case.name,
        c.label(),
        s.label(),
        case.what
    );
    print_outcome(&o);
}

/// Everything known about one run.
pub fn print_outcome(o: &Outcome) {
    println!("  result: {}", o.error.as_deref().unwrap_or("ok"));
    println!(
        "  end states: client {:?}{}, server {:?}{}",
        o.client_state,
        if o.client_reset { " (reset)" } else { "" },
        o.server_state,
        if o.server_reset { " (reset)" } else { "" }
    );
    let t = |x: Option<u64>| x.map_or("-".into(), |v| format!("{:.3} s", v as f64 / 1e6));
    let settled = if o.unsettled {
        format!("not within {} s", sim::SETTLE / SEC)
    } else {
        t(o.settled_at)
    };
    println!(
        "  established {}  c→s done {}  s→c done {}  settled {settled}  closed {}",
        t(o.established_at),
        t(o.fwd_done),
        t(o.rev_done),
        t(o.closed_at)
    );
    for (dir, w) in [("c→s", &o.fwd), ("s→c", &o.rev)] {
        println!(
            "  {dir}: {} pkts, {} data ({} B), {} retx ({} B), {} B delivered twice, \
             {} dropped ({} data), {} corrupted, {} duplicated, SYN {} FIN {} RST {}",
            w.pkts,
            w.data_pkts,
            w.payload,
            w.retx_pkts,
            w.retx_bytes,
            w.dup_delivered,
            w.drops,
            w.data_drops,
            w.corrupted,
            w.duplicated,
            w.syn,
            w.fin,
            w.rst
        );
    }
    for (who, st) in [("client", &o.client_stats), ("server", &o.server_stats)] {
        if let Some(st) = st {
            println!("  {who} stats: {st:?}");
        }
    }
}

fn cell(o: &Outcome) -> String {
    if !o.ok() {
        return "❌".into();
    }
    let rtx = o.fwd.retx_pkts + o.rev.retx_pkts;
    match o.transfer_secs() {
        Some(t) => format!("✅ {} · {rtx} rtx", secs(t)),
        None => "✅".into(),
    }
}

pub fn print(res: &[Res]) {
    let pairs = pairings();
    let mut head = vec!["Case (client → server)".to_string()];
    head.extend(
        pairs
            .iter()
            .map(|(c, s)| format!("{} → {}", c.label(), s.label())),
    );
    let mut t = Table::new(head);
    for case in cases() {
        let mut row = vec![format!("**{}**: {}", case.name, case.what)];
        for (c, s) in &pairs {
            let r = res
                .iter()
                .find(|r| r.case == case.name && r.client == *c && r.server == *s);
            row.push(r.map_or("–".into(), |r| cell(&r.out)));
        }
        t.row(row);
    }
    t.print();
    println!("Times run from ESTABLISHED to the last byte delivered (virtual); rtx counts data segments that resent sequence space, both directions, as seen on the wire.\n");
    for r in res.iter().filter(|r| !r.out.ok()) {
        println!(
            "- ❌ {} ({} → {}): {}",
            r.case,
            r.client.label(),
            r.server.label(),
            r.out.error.as_deref().unwrap_or("")
        );
    }
    println!();
}
