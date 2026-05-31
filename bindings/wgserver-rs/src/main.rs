//! Userspace TCP server harness over a UDP-encapsulated "WG-shaped"
//! transport, hosting many `tcp-sans-io` TCBs in parallel.
//!
//! Each inbound UDP datagram is treated as a raw IPv4+TCP packet; we
//! demultiplex by the destination TCP port to a per-port TCB and feed
//! it via `Tcb::inject_packet`. Outbound IPv4+TCP packets emitted by
//! the TCBs are wrapped (unchanged) in UDP datagrams and sent to the
//! configured peer.
//!
//! No kernel TUN, no root, no crypto. The transport stands in for a
//! WireGuard tunnel for stress and adversarial testing purposes —
//! deployment would slot a real WG endpoint in place of the UDP
//! socket.

mod server;

use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use server::{ServerConfig, ServerStats};

const DEFAULT_LISTEN: &str = "127.0.0.1:9001";
const DEFAULT_PEER: &str = "127.0.0.1:9002";
const DEFAULT_SERVER_IP: &str = "10.99.0.2";
const DEFAULT_BASE_PORT: u16 = 30000;
const DEFAULT_NUM_LISTENERS: u16 = 16;
const DEFAULT_MEMORY_CAP_MIB: usize = 4096;

fn main() -> ExitCode {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wgserver: {e}");
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
    };

    if let Err(e) = run(cfg) {
        eprintln!("wgserver: fatal: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cfg: ServerConfig) -> io::Result<()> {
    // Memory pre-flight: refuse to run if total TCB residency would
    // exceed the cap. The actual size_of::<Tcb>() is checked inside
    // server::Server::new and reported in the banner.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_stdin = stop.clone();

    // Watch stdin in a background thread for "shutdown\n". Cross-platform
    // alternative to signal handling (we don't pull in signal-hook).
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut line = String::new();
        loop {
            line.clear();
            match handle.read_line(&mut line) {
                Ok(0) => {
                    // EOF on stdin (parent closed it) → graceful shutdown.
                    stop_for_stdin.store(true, Ordering::SeqCst);
                    return;
                }
                Ok(_) => {
                    if line.trim_end() == "shutdown" {
                        stop_for_stdin.store(true, Ordering::SeqCst);
                        return;
                    }
                }
                Err(_) => {
                    stop_for_stdin.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }
    });

    let mut srv = server::Server::new(cfg)?;
    srv.print_banner();

    // Final stats printed on graceful exit so the driver can verify
    // counts via stdout parse.
    let final_stats = srv.run(stop)?;
    print_stats("final", &final_stats);
    Ok(())
}

fn print_stats(label: &str, s: &ServerStats) {
    println!(
        "wgserver: {label} stats: connections_accepted={} bytes_echoed={} udp_rx={} udp_tx={} parse_rejects={} cookie_validations={} active={}",
        s.connections_accepted,
        s.bytes_echoed,
        s.udp_rx,
        s.udp_tx,
        s.parse_rejects,
        s.cookie_validations,
        s.active_now,
    );
    let _ = io::stdout().flush();
}

// ---------------------------------------------------------------------------
// CLI parsing (no external dep — we keep this binary `std`-only)
// ---------------------------------------------------------------------------

fn print_usage() {
    eprintln!(
        "usage: wgserver [options]
options:
  --listen-udp <ip:port>       UDP bind address (default {DEFAULT_LISTEN})
  --peer-udp   <ip:port>       UDP peer address (default {DEFAULT_PEER})
  --server-ip  <a.b.c.d>       virtual TCP server IP (default {DEFAULT_SERVER_IP})
  --base-port  <p>             first listening TCP port (default {DEFAULT_BASE_PORT})
  --num-listeners <N>          listener count (default {DEFAULT_NUM_LISTENERS}, max 65535)
  --cookies <hex32|none>       enable SYN cookies with the given 16-byte secret (32 hex chars)
                               or generate a random one if `random` is passed; default off
  --memory-cap-mib <N>         refuse to run if total TCB RSS would exceed this (default {DEFAULT_MEMORY_CAP_MIB})
  --quiet                      suppress per-packet trace output
  -h, --help                   show this help
"
    );
}

fn parse_args() -> Result<ServerConfig, String> {
    let mut listen: SocketAddr = DEFAULT_LISTEN.parse().map_err(|e| format!("{e}"))?;
    let mut peer: SocketAddr = DEFAULT_PEER.parse().map_err(|e| format!("{e}"))?;
    let mut server_ip: [u8; 4] = parse_ip4(DEFAULT_SERVER_IP)?;
    let mut base_port: u16 = DEFAULT_BASE_PORT;
    let mut num_listeners: u32 = DEFAULT_NUM_LISTENERS as u32;
    let mut cookie_secret: Option<[u8; 16]> = None;
    let mut quiet = false;
    let mut memory_cap_mib: usize = DEFAULT_MEMORY_CAP_MIB;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--listen-udp" => {
                listen = args
                    .next()
                    .ok_or("--listen-udp requires <ip:port>")?
                    .parse()
                    .map_err(|e: std::net::AddrParseError| format!("--listen-udp: {e}"))?;
            }
            "--peer-udp" => {
                peer = args
                    .next()
                    .ok_or("--peer-udp requires <ip:port>")?
                    .parse()
                    .map_err(|e: std::net::AddrParseError| format!("--peer-udp: {e}"))?;
            }
            "--server-ip" => {
                let v = args.next().ok_or("--server-ip requires <a.b.c.d>")?;
                server_ip = parse_ip4(&v)?;
            }
            "--base-port" => {
                base_port = args
                    .next()
                    .ok_or("--base-port requires <port>")?
                    .parse()
                    .map_err(|e: std::num::ParseIntError| format!("--base-port: {e}"))?;
            }
            "--num-listeners" => {
                num_listeners = args
                    .next()
                    .ok_or("--num-listeners requires <N>")?
                    .parse()
                    .map_err(|e: std::num::ParseIntError| format!("--num-listeners: {e}"))?;
            }
            "--cookies" => {
                let v = args.next().ok_or("--cookies requires <hex32|random|none>")?;
                cookie_secret = match v.as_str() {
                    "none" => None,
                    "random" => {
                        // Use the seed-from-time hack — fine for tests.
                        let nanos = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos() as u64)
                            .unwrap_or(0xc0de_c0de_c0de_c0deu64);
                        let mut s = [0u8; 16];
                        let mut x = nanos.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        for chunk in s.chunks_mut(8) {
                            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                            let bytes = x.to_le_bytes();
                            chunk.copy_from_slice(&bytes[..chunk.len()]);
                        }
                        Some(s)
                    }
                    hex => {
                        let bytes = parse_hex32(hex).ok_or_else(|| {
                            "--cookies expects exactly 32 hex characters".to_string()
                        })?;
                        Some(bytes)
                    }
                };
            }
            "--memory-cap-mib" => {
                memory_cap_mib = args
                    .next()
                    .ok_or("--memory-cap-mib requires <N>")?
                    .parse()
                    .map_err(|e: std::num::ParseIntError| format!("--memory-cap-mib: {e}"))?;
            }
            "--quiet" => quiet = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    if num_listeners == 0 || num_listeners > u16::MAX as u32 {
        return Err(format!(
            "--num-listeners must be in 1..=65535 (got {num_listeners})"
        ));
    }
    let last_port = (base_port as u32).checked_add(num_listeners).ok_or_else(|| {
        format!("base_port + num_listeners overflows u16 ({base_port} + {num_listeners})")
    })?;
    if last_port > u16::MAX as u32 + 1 {
        return Err(format!(
            "base_port({base_port}) + num_listeners({num_listeners}) overflows u16"
        ));
    }

    Ok(ServerConfig {
        listen_udp: listen,
        peer_udp: peer,
        server_ip,
        base_port,
        num_listeners: num_listeners as u16,
        cookie_secret,
        memory_cap_mib,
        quiet,
        recv_timeout: Duration::from_millis(2),
    })
}

fn parse_ip4(s: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("invalid IPv4 {s:?}"));
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p
            .parse::<u8>()
            .map_err(|e| format!("invalid IPv4 octet {p:?}: {e}"))?;
    }
    Ok(out)
}

fn parse_hex32(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_digit(s.as_bytes().get(2 * i).copied()?)?;
        let lo = hex_digit(s.as_bytes().get(2 * i + 1).copied()?)?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
