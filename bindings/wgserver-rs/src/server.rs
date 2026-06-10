//! Pump loop and per-connection state machine for the userspace TCP
//! server harness. One `Server` owns:
//!   * a single non-blocking UDP socket (the WG-shaped outer transport)
//!   * an array of `N` `Tcb`s, one per `(server_ip, base_port + i)`
//!   * an active-set of indices whose pump work is non-trivial in the
//!     current iteration (avoids O(N) per-tick at idle)
//!   * a small per-connection scratch for the byte-echo app handler.

use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tcp_sans_io::tcb::events;
use tcp_sans_io::wire::{flags, IPV4_HDR_LEN, IPPROTO_TCP, TCP_HDR_LEN};
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError, BUF_CAP, MAX_PACKET};

const RECV_BUF: usize = 2048;
const APP_SCRATCH: usize = 4096;
const STATS_INTERVAL: Duration = Duration::from_secs(2);

/// Configuration passed in from the CLI.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_udp: SocketAddr,
    pub peer_udp: SocketAddr,
    pub server_ip: [u8; 4],
    pub base_port: u16,
    pub num_listeners: u16,
    pub cookie_secret: Option<[u8; 16]>,
    pub memory_cap_mib: usize,
    pub quiet: bool,
    pub recv_timeout: Duration,
}

#[derive(Debug, Default, Clone)]
pub struct ServerStats {
    pub connections_accepted: u64,
    pub bytes_echoed: u64,
    pub udp_rx: u64,
    pub udp_tx: u64,
    pub parse_rejects: u64,
    pub cookie_validations: u64,
    pub active_now: u64,
}

/// Per-connection scratch + lifecycle bookkeeping.
struct Conn {
    tcb: Tcb,
    /// `true` once the TCB has left LISTEN. Cleared on re-arm.
    active: bool,
    /// Echo handler pending output queue (sent in chunks as `tcp_send`
    /// returns `WouldBlock`).
    pending: Vec<u8>,
    /// `true` once we've sent the response and called `close()`.
    closing: bool,
    /// Connection count we've accepted on this TCB (across re-arms).
    served: u64,
    /// Latched peer 5-tuple last seen on this TCB (for debug).
    peer_seen: Option<([u8; 4], u16)>,
    /// Outer UDP source address of the last datagram this TCB *accepted*.
    /// Egress for this connection goes here. Without per-connection
    /// addressing, all egress chased the most recent UDP source seen on
    /// the socket — any datagram from anywhere (even one failing to
    /// parse) redirected every in-flight connection's replies.
    udp_peer: Option<SocketAddr>,
}

pub struct Server {
    cfg: ServerConfig,
    sock: UdpSocket,
    conns: Vec<Conn>,
    /// Indices in `conns` that need pump attention this iteration.
    active: Vec<u16>,
    /// Per-iteration scratch — reused across loops.
    recv_buf: Vec<u8>,
    extract_buf: Vec<u8>,
    app_buf: Vec<u8>,
    stats: ServerStats,
    last_stats_print: Instant,
    start_at: Instant,
}

impl Server {
    pub fn new(cfg: ServerConfig) -> io::Result<Self> {
        // Memory pre-flight.
        let tcb_size = std::mem::size_of::<Tcb>();
        let total_bytes = tcb_size.saturating_mul(cfg.num_listeners as usize);
        let total_mib = total_bytes / (1024 * 1024);
        if total_mib > cfg.memory_cap_mib {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!(
                    "memory_cap_mib={} exceeded: would need {} MiB ({} TCBs × {} B)",
                    cfg.memory_cap_mib, total_mib, cfg.num_listeners, tcb_size
                ),
            ));
        }

        let sock = UdpSocket::bind(cfg.listen_udp)?;
        sock.set_read_timeout(Some(cfg.recv_timeout))?;
        // Generous OS recv buffer — the 10K-handshake burst can be tens
        // of MiB on the wire.
        let _ = sock.set_nonblocking(false); // we use read_timeout for portability

        let mut conns: Vec<Conn> = Vec::with_capacity(cfg.num_listeners as usize);
        for i in 0..cfg.num_listeners {
            let port = cfg.base_port + i;
            let iss = fresh_iss();
            let tcb_cfg = TcbConfig {
                local: Endpoint {
                    ip: cfg.server_ip,
                    port,
                },
                // Wildcard; `listen()` zeroes it anyway.
                remote: Endpoint {
                    ip: [0, 0, 0, 0],
                    port: 0,
                },
                iss,
                initial_rto_ms: 1000,
            };
            let mut tcb = Tcb::new(tcb_cfg).map_err(map_tcp_err)?;
            tcb.set_now(0);
            tcb.listen().map_err(map_tcp_err)?;
            if let Some(ref secret) = cfg.cookie_secret {
                tcb.set_cookie_secret(secret);
            }
            conns.push(Conn {
                tcb,
                active: false,
                pending: Vec::new(),
                closing: false,
                served: 0,
                peer_seen: None,
                udp_peer: None,
            });
        }

        Ok(Self {
            cfg,
            sock,
            conns,
            active: Vec::with_capacity(256),
            recv_buf: vec![0u8; RECV_BUF],
            extract_buf: vec![0u8; MAX_PACKET],
            app_buf: vec![0u8; APP_SCRATCH],
            stats: ServerStats::default(),
            last_stats_print: Instant::now(),
            start_at: Instant::now(),
        })
    }

    pub fn print_banner(&self) {
        let tcb_size = std::mem::size_of::<Tcb>();
        let total_mib = (tcb_size * self.cfg.num_listeners as usize) / (1024 * 1024);
        println!(
            "wgserver: tcb_size={tcb_size} bytes, num_listeners={}, total_estimate={total_mib} MiB, buf_cap={} bytes, cookies={}",
            self.cfg.num_listeners,
            BUF_CAP,
            if self.cfg.cookie_secret.is_some() {
                "on"
            } else {
                "off"
            }
        );
        println!(
            "wgserver: listening on udp={} peer={} server_ip={}.{}.{}.{} ports={}..={}; ready",
            self.cfg.listen_udp,
            self.cfg.peer_udp,
            self.cfg.server_ip[0],
            self.cfg.server_ip[1],
            self.cfg.server_ip[2],
            self.cfg.server_ip[3],
            self.cfg.base_port,
            self.cfg.base_port + self.cfg.num_listeners - 1,
        );
        let _ = io::stdout().flush();
    }

    pub fn run(&mut self, stop: Arc<AtomicBool>) -> io::Result<ServerStats> {
        let mut peer = self.cfg.peer_udp;

        while !stop.load(Ordering::Relaxed) {
            let now_ms = self.now_ms();

            // 1. Drain UDP socket to WouldBlock / timeout. Each datagram
            //    is parsed for an inner IPv4+TCP packet; demuxed by
            //    inner TCP dest port to a Conn index; injected.
            loop {
                match self.sock.recv_from(&mut self.recv_buf) {
                    Ok((n, src)) => {
                        peer = src; // remember last UDP peer for adversary tests
                        self.stats.udp_rx += 1;
                        let pkt = &self.recv_buf[..n];
                        if let Some(idx) = parse_dest_index(
                            pkt,
                            self.cfg.server_ip,
                            self.cfg.base_port,
                            self.cfg.num_listeners,
                        ) {
                            let conn = &mut self.conns[idx];
                            conn.tcb.set_now(now_ms);
                            let was_listen = conn.tcb.state() == State::Listen;
                            match conn.tcb.inject_packet(pkt) {
                                Ok(()) => {
                                    // Pin this connection's egress to the
                                    // outer address of the datagram the TCB
                                    // accepted (the 5-tuple filter inside
                                    // inject_packet vouched for it).
                                    conn.udp_peer = Some(src);
                                    // Promote to active set if EITHER the TCB
                                    // left LISTEN OR the inject queued egress
                                    // bytes (stateless cookie SYN-ACK, RST
                                    // reply to a hostile SYN+ACK, etc.). The
                                    // active-set drains extract_packet on the
                                    // next iteration.
                                    let post = conn.tcb.state();
                                    let tx_pending =
                                        conn.tcb.poll() & events::TX_PENDING != 0;
                                    let needs_pump = post != State::Listen || tx_pending;
                                    if needs_pump && !conn.active {
                                        conn.active = true;
                                        self.active.push(idx as u16);
                                    }
                                    // Cookie validation: if we went
                                    // LISTEN -> ESTABLISHED in one
                                    // packet, that's the cookie path.
                                    if was_listen && post == State::Established {
                                        self.stats.cookie_validations += 1;
                                    }
                                }
                                Err(TcpError::MalformedPacket)
                                | Err(TcpError::NotForUs)
                                | Err(TcpError::InvalidState) => {
                                    self.stats.parse_rejects += 1;
                                }
                                Err(e) => {
                                    if !self.cfg.quiet {
                                        eprintln!(
                                            "wgserver: inject_packet idx={idx} err={e:?}"
                                        );
                                    }
                                    self.stats.parse_rejects += 1;
                                }
                            }
                        } else {
                            self.stats.parse_rejects += 1;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
                    Err(e) => return Err(e),
                }
            }

            // 2. Pump every active TCB.
            //    We swap the active vector with a scratch one so the
            //    inner loop can mutate `self.active` (when we drop a
            //    TCB out of the active set) without borrow conflicts.
            let mut iter_set: Vec<u16> = std::mem::take(&mut self.active);
            let mut next_active: Vec<u16> = Vec::with_capacity(iter_set.len());
            for idx in iter_set.drain(..) {
                let still_active = self.pump_one(idx as usize, now_ms, peer)?;
                if still_active {
                    next_active.push(idx);
                }
            }
            self.active = next_active;
            self.stats.active_now = self.active.len() as u64;

            // 3. Periodic stats line (so the driver can scrape progress
            //    from stdout).
            let now = Instant::now();
            if now.duration_since(self.last_stats_print) >= STATS_INTERVAL {
                self.last_stats_print = now;
                if !self.cfg.quiet {
                    println!(
                        "wgserver: stats t={:.1}s connections_accepted={} bytes_echoed={} udp_rx={} udp_tx={} parse_rejects={} cookie_validations={} active={}",
                        now.duration_since(self.start_at).as_secs_f64(),
                        self.stats.connections_accepted,
                        self.stats.bytes_echoed,
                        self.stats.udp_rx,
                        self.stats.udp_tx,
                        self.stats.parse_rejects,
                        self.stats.cookie_validations,
                        self.stats.active_now,
                    );
                    let _ = io::stdout().flush();
                }
            }

            // 4. If no UDP activity AND no active TCBs, sleep briefly so
            //    we don't spin at 100 % CPU when idle. The next UDP
            //    datagram arriving wakes us via read_timeout.
            if self.active.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        Ok(self.stats.clone())
    }

    /// Returns `true` if the TCB should remain in the active set, or
    /// `false` if it's back in LISTEN and idle.
    fn pump_one(
        &mut self,
        idx: usize,
        now_ms: u64,
        peer: SocketAddr,
    ) -> io::Result<bool> {
        let conn = &mut self.conns[idx];

        // Drive timers (RTO, RACK, TLP, TIME_WAIT, delayed-ACK).
        conn.tcb.set_now(now_ms);
        if let Err(e) = conn.tcb.tick() {
            if !self.cfg.quiet {
                eprintln!("wgserver: tick idx={idx} err={e:?}");
            }
        }

        // Drain any segments the TCB wants on the wire. Egress goes to the
        // UDP address this connection's traffic actually arrived from; the
        // global last-seen `peer` is only the bootstrap fallback for a TCB
        // that has never accepted a datagram.
        let egress = conn.udp_peer.unwrap_or(peer);
        loop {
            match conn.tcb.extract_packet(&mut self.extract_buf) {
                Ok(0) => break,
                Ok(n) => {
                    self.stats.udp_tx += 1;
                    if let Err(e) = self.sock.send_to(&self.extract_buf[..n], egress) {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        return Err(e);
                    }
                }
                Err(TcpError::BufferTooSmall) => {
                    // MAX_PACKET should always fit — bail loudly.
                    return Err(io::Error::other(
                        "extract_packet: buffer too small (bug in MAX_PACKET sizing)",
                    ));
                }
                Err(e) => {
                    if !self.cfg.quiet {
                        eprintln!("wgserver: extract idx={idx} err={e:?}");
                    }
                    break;
                }
            }
        }

        let state = conn.tcb.state();

        // Move into the app layer once we're ESTABLISHED.
        if state == State::Established && !conn.closing {
            // Drain peer bytes into our scratch, accumulate.
            loop {
                match conn.tcb.recv(&mut self.app_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.pending.extend_from_slice(&self.app_buf[..n]);
                    }
                    Err(TcpError::ConnectionClosed) | Err(TcpError::ConnectionReset) => {
                        break;
                    }
                    Err(e) => {
                        if !self.cfg.quiet {
                            eprintln!("wgserver: recv idx={idx} err={e:?}");
                        }
                        break;
                    }
                }
            }

            // Look for the echo "end-of-request" marker. We accept two
            // simple framings so the test driver has flexibility:
            //   * trailing newline ⇒ echo back the bytes through the
            //     newline inclusive (line-echo).
            //   * EOF from peer (we observe CloseWait) ⇒ echo whatever
            //     we have, then close.
            let mut should_close = false;
            if let Some(pos) = conn.pending.iter().position(|&b| b == b'\n') {
                // Echo through the newline, leave any bytes after for
                // a subsequent round (but our handler closes after the
                // first complete request).
                let echo = &conn.pending[..=pos].to_vec();
                send_all(&mut conn.tcb, echo, &mut self.stats.bytes_echoed);
                conn.pending.drain(..=pos);
                should_close = true;
            }

            if conn.tcb.state() == State::CloseWait && !conn.pending.is_empty() {
                let bytes = std::mem::take(&mut conn.pending);
                send_all(&mut conn.tcb, &bytes, &mut self.stats.bytes_echoed);
                should_close = true;
            } else if conn.tcb.state() == State::CloseWait && conn.pending.is_empty() {
                should_close = true;
            }

            if should_close {
                let _ = conn.tcb.close();
                conn.closing = true;
                conn.served += 1;
                self.stats.connections_accepted += 1;
            }
        } else if state == State::CloseWait && !conn.closing {
            // Peer closed before sending anything; still emit any
            // bytes we managed to recv (rare) and then close.
            if !conn.pending.is_empty() {
                let bytes = std::mem::take(&mut conn.pending);
                send_all(&mut conn.tcb, &bytes, &mut self.stats.bytes_echoed);
            }
            let _ = conn.tcb.close();
            conn.closing = true;
        }

        // Push any remaining pending response that the send-ring backpressure
        // forced us to defer earlier.
        if !conn.pending.is_empty() && conn.closing {
            let bytes = std::mem::take(&mut conn.pending);
            send_all(&mut conn.tcb, &bytes, &mut self.stats.bytes_echoed);
        }

        // Latch the peer's 5-tuple post-handshake (purely for debug).
        if state == State::Established && conn.peer_seen.is_none() {
            let snap = conn.tcb.debug_snapshot();
            // peer's port/ip is encoded in the Tcb internals; we read
            // it indirectly by sniffing the last successful inject.
            // For now we just stash the snapshot's state byte.
            let _ = snap;
            conn.peer_seen = Some(([0u8; 4], 0));
        }

        // Re-arm LISTEN when the TCB has drained back to Closed or TimeWait.
        let final_state = conn.tcb.state();
        if final_state == State::Closed || final_state == State::TimeWait {
            // Drop the active flag, re-arm with a *fresh* ISS — `listen()`
            // alone reuses the prior incarnation's `iss`, which would give
            // every connection on this port the same predictable ISN
            // (RFC 6528 wants per-connection randomness).
            conn.active = false;
            conn.closing = false;
            conn.pending.clear();
            conn.peer_seen = None;
            conn.udp_peer = None;
            conn.tcb.set_now(now_ms);
            let port = self.cfg.base_port + idx as u16;
            conn.tcb.reinit(TcbConfig {
                local: Endpoint {
                    ip: self.cfg.server_ip,
                    port,
                },
                remote: Endpoint {
                    ip: [0, 0, 0, 0],
                    port: 0,
                },
                iss: fresh_iss(),
                initial_rto_ms: 1000,
            });
            conn.tcb.set_now(now_ms);
            if let Err(e) = conn.tcb.listen() {
                if !self.cfg.quiet {
                    eprintln!("wgserver: re-listen idx={idx} err={e:?}");
                }
            }
            if let Some(ref secret) = self.cfg.cookie_secret {
                conn.tcb.set_cookie_secret(secret);
            }
            return Ok(false);
        }

        // Stay active while we're past LISTEN OR while there's tx
        // pending in the TCB egress ring.
        let events = conn.tcb.poll();
        let tx_pending = events & events::TX_PENDING != 0;
        let stays = final_state != State::Listen || tx_pending;
        if !stays {
            // Drop the active flag so a future inject can re-promote us.
            conn.active = false;
        }
        Ok(stays)
    }

    fn now_ms(&self) -> u64 {
        self.start_at.elapsed().as_millis() as u64
    }
}

/// Push `data` into `tcb.send` in a loop until either it's all
/// accepted or the send ring backpressures (`WouldBlock`). Any
/// remaining bytes are left for the next pump iteration via the
/// `Conn::pending` buffer (the caller is responsible for re-queuing).
fn send_all(tcb: &mut Tcb, data: &[u8], counter: &mut u64) {
    let mut off = 0;
    while off < data.len() {
        match tcb.send(&data[off..]) {
            Ok(0) => break,
            Ok(n) => {
                off += n;
                *counter += n as u64;
            }
            Err(TcpError::WouldBlock) => break,
            Err(_) => break,
        }
    }
}

/// Inspect a candidate IPv4+TCP datagram and return the index in the
/// `conns` array corresponding to its inner TCP destination port, if
/// the destination IP matches our `server_ip` and the port is within
/// `[base_port, base_port + num_listeners)`.
fn parse_dest_index(
    pkt: &[u8],
    server_ip: [u8; 4],
    base_port: u16,
    num_listeners: u16,
) -> Option<usize> {
    if pkt.len() < IPV4_HDR_LEN + TCP_HDR_LEN {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_HDR_LEN || pkt.len() < ihl + TCP_HDR_LEN {
        return None;
    }
    if pkt[9] != IPPROTO_TCP {
        return None;
    }
    // Destination IP at bytes [16..20).
    let dst_ip = [pkt[16], pkt[17], pkt[18], pkt[19]];
    if dst_ip != server_ip {
        return None;
    }
    // TCP dest port at IHL+2..IHL+4 (network byte order).
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    if dst_port < base_port {
        return None;
    }
    let idx = (dst_port - base_port) as usize;
    if idx >= num_listeners as usize {
        return None;
    }
    Some(idx)
}

/// Per-connection ISS from OS-seeded entropy. RFC 6528 (and the library's
/// host contract) require a CSPRNG-derived ISS per connection; the previous
/// fixed FNV of `(server_ip, port)` gave every incarnation on a port the
/// same predictable ISN. `RandomState` carries per-process SipHash keys
/// seeded from the OS CSPRNG plus a per-instance counter, so each call
/// yields an off-path-unpredictable value with no extra dependency. (The
/// Go driver learns the server ISS from the SYN-ACK, so nothing relies on
/// predictability.)
fn fresh_iss() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let h = RandomState::new().build_hasher().finish();
    (h ^ (h >> 32)) as u32
}

fn map_tcp_err(e: TcpError) -> io::Error {
    io::Error::other(format!("tcp-sans-io error: {e:?} (code {})", e.as_code()))
}

// Avoid unused-import warning when `flags` isn't referenced directly.
#[allow(dead_code)]
const _UNUSED_FLAGS: u8 = flags::ACK;
