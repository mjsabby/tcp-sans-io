//! tcp-sans-io vs smoltcp: correctness, interop and performance.
//!
//! See `--help`. Every section except `cpu` runs in virtual time and is
//! deterministic.

mod fuzz;
mod interop;
mod net;
mod perf;
mod pkt;
mod probes;
mod report;
mod sim;
mod stacks;

use stacks::{Cc, Spec};

const HELP: &str = "\
usage: shootout [--check] [--only SECTIONS] [--quick]
       shootout --case NAME [--pair CLIENT,SERVER] [--trace]
       shootout --profile NAME [--pair SENDER,RECEIVER] [--seed N] [--trace]
       shootout --probe NAME [--stack STACK]      (PROBE_TRACE=1 for packets)

  --check          CI gate: probes, interop and fuzz; exit 1 if tcp-sans-io
                   fails anything (smoltcp's results are reported only)
  --only LIST      comma-separated: probes, interop, fuzz, sim, cpu, memory
  --quick          fewer seeds / smaller transfers in fuzz, sim and cpu
  --case NAME      run one interop case in detail
  --profile NAME   run one goodput profile in detail
  --probe NAME     run one RFC probe
  --pair C,S       stacks for --case (default ours,smol) or --profile
                   (default ours,ours)
  --stack STACK    stack for --probe (default ours)
  --trace          print every packet
  stacks: ours, ours64k, smol, smol-reno, smol-nocc, smol-nots, smol-nodelay

Pin the process to one core for the cpu section (taskset -c N).
";

fn parse_spec(s: &str) -> Spec {
    match s {
        "ours" => Spec::Ours,
        "ours64k" => Spec::Ours64k,
        "smol" => Spec::SMOL,
        "smol-reno" => Spec::SMOL_RENO,
        "smol-nocc" => Spec::Smol {
            cc: Cc::None,
            ts: true,
            nagle: true,
            buf: stacks::SMOL_BUF,
        },
        "smol-nots" => Spec::SMOL.with_ts(false),
        "smol-nodelay" => Spec::SMOL.with_nagle(false),
        _ => {
            eprintln!("unknown stack {s}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    let value = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    if flag("--help") || flag("-h") {
        print!("{HELP}");
        return;
    }
    if let Some(case) = value("--case") {
        let pair = value("--pair").unwrap_or_else(|| "ours,smol".into());
        let (c, s) = pair.split_once(',').unwrap_or((&pair, &pair));
        interop::diag(&case, parse_spec(c), parse_spec(s), flag("--trace"));
        return;
    }
    if let Some(p) = value("--probe") {
        let stack = value("--stack").unwrap_or_else(|| "ours".into());
        probes::run_one(&p, parse_spec(&stack));
        return;
    }
    if let Some(p) = value("--profile") {
        let pair = value("--pair").unwrap_or_else(|| "ours,ours".into());
        let (c, s) = pair.split_once(',').unwrap_or((&pair, &pair));
        let seed = value("--seed").and_then(|s| s.parse().ok()).unwrap_or(0);
        perf::diag(&p, parse_spec(c), parse_spec(s), seed, flag("--trace"));
        return;
    }
    let check = flag("--check");
    let quick = flag("--quick") || check;
    let only = value("--only");
    let on = |s: &str| match &only {
        Some(list) => list.split(',').any(|x| x == s),
        None => !check || matches!(s, "probes" | "interop" | "fuzz"),
    };

    let mut failures = Vec::new();
    if on("probes") {
        let t = std::time::Instant::now();
        let specs = [Spec::Ours, Spec::SMOL];
        println!("## RFC probes\n");
        let res = probes::run(&specs);
        probes::print(&res, &specs);
        for r in res.iter().filter(|r| r.regressed()) {
            failures.push(format!("probe {}: {:?}", r.id, r.verdict));
        }
        println!("_{:.1} s_\n", t.elapsed().as_secs_f64());
    }
    if on("interop") {
        let t = std::time::Instant::now();
        println!("## Interop matrix\n");
        let res = interop::run();
        interop::print(&res);
        for r in res.iter().filter(|r| !r.out.ok()) {
            if r.client.is_ours() || r.server.is_ours() {
                failures.push(format!(
                    "interop {} ({} → {})",
                    r.case,
                    r.client.label(),
                    r.server.label()
                ));
            }
        }
        println!("_{:.1} s_\n", t.elapsed().as_secs_f64());
    }
    if on("fuzz") {
        let t = std::time::Instant::now();
        let n = if quick { 100_000 } else { 1_000_000 };
        println!("## Robustness fuzzing\n");
        let res: Vec<_> = [Spec::Ours, Spec::SMOL]
            .into_iter()
            .map(|s| fuzz::run(s, n, 0xF022))
            .collect();
        fuzz::print(&res);
        for r in res.iter().filter(|r| r.spec.is_ours()) {
            if r.panics > 0 || r.invariant_breaks > 0 {
                failures.push(format!(
                    "fuzz: {} panics, {} invariant violations",
                    r.panics, r.invariant_breaks
                ));
            }
        }
        println!("_{:.1} s_\n", t.elapsed().as_secs_f64());
    }
    if on("sim") {
        let t = std::time::Instant::now();
        println!("## Goodput over the simulated link\n");
        let res = perf::run_sim(quick);
        perf::print_sim(&res);
        println!("_{:.1} s_\n", t.elapsed().as_secs_f64());
    }
    if on("cpu") {
        let t = std::time::Instant::now();
        println!("## CPU cost\n");
        perf::run_cpu(quick);
        println!("_{:.1} s_\n", t.elapsed().as_secs_f64());
    }
    if on("memory") {
        println!("## Memory per connection\n");
        perf::print_memory();
    }
    if check {
        if failures.is_empty() {
            println!("PASS: tcp-sans-io passed every probe, interop case and fuzz check.");
        } else {
            println!("FAIL:");
            for f in &failures {
                println!("  {f}");
            }
            std::process::exit(1);
        }
    }
}
