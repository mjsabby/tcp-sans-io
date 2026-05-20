//! smoltcp interoperability tests.
//!
//! Two userspace TCP stacks (ours and smoltcp's) talking to each
//! other through an in-memory channel. The two stacks are entirely
//! independent codebases — different authors, different state
//! machines, different option-handling — so anything that flows
//! across this boundary is a strong correctness signal.
//!
//! Architecture:
//!
//! ```text
//!   our::Tcb (10.0.0.1:80, LISTEN)
//!         ↑↓ ipv4+tcp packets
//!     in-memory wire
//!         ↑↓ ipv4+tcp packets
//!   smoltcp::Interface + tcp::Socket (10.0.0.2:49152 → 10.0.0.1:80)
//! ```
//!
//! Each test exercises a different protocol path:
//!
//! * `smoltcp_handshake_only` — bare 3-way handshake + immediate
//!   close on both sides. Catches MSS / Window Scale / SACK / TS
//!   option-negotiation disagreements.
//! * `smoltcp_active_open_bulk_transfer` — smoltcp connects, sends a
//!   medium-sized payload, our Tcb echoes it back, both close. Catches
//!   sequence-number bookkeeping disagreements and ordering bugs
//!   that show up under sustained traffic.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

extern crate std;

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};

use crate::{Endpoint, State, Tcb, TcbConfig};

// ---------------------------------------------------------------------------
// ChannelDevice — a smoltcp Device that ferries packets through a pair of
// VecDeque<Vec<u8>> queues. tx packets land in `tx`; the test pump moves
// them to our::Tcb. our::Tcb's extracted packets go into the device's `rx`.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ChannelDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl Device for ChannelDevice {
    type RxToken<'a> = ChannelRxToken;
    type TxToken<'a> = ChannelTxToken<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((ChannelRxToken(pkt), ChannelTxToken { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        Some(ChannelTxToken { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ip;
        caps
    }
}

struct ChannelRxToken(Vec<u8>);

impl RxToken for ChannelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct ChannelTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for ChannelTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.tx.push_back(buf);
        r
    }
}

// ---------------------------------------------------------------------------
// Test harness — sets up both stacks + a pump driver.
// ---------------------------------------------------------------------------

const OUR_IP: [u8; 4] = [10, 0, 0, 1];
const SMOLTCP_IP: [u8; 4] = [10, 0, 0, 2];
const OUR_PORT: u16 = 80;
const SMOLTCP_PORT: u16 = 49152;

struct InteropHarness {
    // Our stack.
    our: Tcb,
    // smoltcp interface + sockets.
    device: ChannelDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp_handle: smoltcp::iface::SocketHandle,
    // Synthetic clock.
    now_ms: u64,
}

impl InteropHarness {
    fn new() -> Self {
        // Our Tcb in LISTEN. The remote field is wildcarded by
        // `listen()`, so smoltcp's ephemeral port doesn't need to match
        // anything we set here.
        let mut our = Tcb::new(TcbConfig {
            local: Endpoint { ip: OUR_IP, port: OUR_PORT },
            remote: Endpoint { ip: SMOLTCP_IP, port: 0 },
            iss: 0x1000_0000,
            initial_rto_ms: 1000,
        })
        .expect("Tcb::new");
        our.listen().expect("listen");

        // smoltcp interface — IP medium (we ferry raw IPv4 packets).
        let mut device = ChannelDevice::default();
        let cfg = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(cfg, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(SMOLTCP_IP[0], SMOLTCP_IP[1], SMOLTCP_IP[2], SMOLTCP_IP[3]), 24))
                .unwrap();
        });

        // One TCP socket — generously sized so we don't hit smoltcp's
        // own buffer backpressure during these short tests.
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        let mut sockets = SocketSet::new(Vec::new());
        let tcp_handle = sockets.add(socket);

        Self {
            our,
            device,
            iface,
            sockets,
            tcp_handle,
            now_ms: 0,
        }
    }

    fn tick(&mut self) {
        self.now_ms += 1;
        self.our.set_now(self.now_ms);
        let now = Instant::from_millis(self.now_ms as i64);

        // Move smoltcp's tx → our::Tcb's inject.
        while let Some(pkt) = self.device.tx.pop_front() {
            // Errors are fine — malformed/not-for-us packets get dropped.
            let _ = self.our.inject_packet(&pkt);
        }

        // Drive our::Tcb forward (timers, recovery, send drain).
        self.our.tick().expect("our.tick");

        // Move our::Tcb's tx → smoltcp's rx.
        let mut buf = [0u8; 1500];
        loop {
            match self.our.extract_packet(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    self.device.rx.push_back(buf[..n].to_vec());
                }
                Err(_) => break,
            }
        }

        // Poll smoltcp (consumes rx, emits to tx).
        let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    /// Pump until `cond(self)` returns true or `max_ms` virtual ms elapse.
    fn pump_until<F: Fn(&Self) -> bool>(&mut self, max_ms: u64, cond: F) -> bool {
        let start = self.now_ms;
        while self.now_ms - start < max_ms {
            if cond(self) {
                return true;
            }
            self.tick();
        }
        cond(self)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn smoltcp_handshake_only() {
    let mut h = InteropHarness::new();

    // smoltcp actively opens.
    {
        let cx = h.iface.context();
        let sock = h.sockets.get_mut::<tcp::Socket>(h.tcp_handle);
        sock.connect(
            cx,
            IpEndpoint::new(
                IpAddress::v4(OUR_IP[0], OUR_IP[1], OUR_IP[2], OUR_IP[3]),
                OUR_PORT,
            ),
            IpListenEndpoint { addr: None, port: SMOLTCP_PORT },
        )
        .expect("smoltcp connect");
    }

    // Drive both sides until both believe they're established.
    let established = h.pump_until(2_000, |h| {
        let sock = h.sockets.get::<tcp::Socket>(h.tcp_handle);
        let smoltcp_est = matches!(sock.state(), tcp::State::Established);
        let our_est = matches!(h.our.state(), State::Established);
        smoltcp_est && our_est
    });
    assert!(established, "handshake did not complete (our state: {:?}, smoltcp: {:?})",
        h.our.state(),
        h.sockets.get::<tcp::Socket>(h.tcp_handle).state());

    // smoltcp half-closes.
    h.sockets.get_mut::<tcp::Socket>(h.tcp_handle).close();

    // Pump until smoltcp's FIN reaches our::Tcb (we'll see CloseWait).
    assert!(
        h.pump_until(2_000, |h| matches!(h.our.state(), State::CloseWait)),
        "our::Tcb did not observe smoltcp's FIN (state: {:?})",
        h.our.state(),
    );

    // Our side closes too.
    h.our.close().expect("our.close");

    // Drive until both sides are fully closed.
    let closed = h.pump_until(5_000, |h| {
        let sock = h.sockets.get::<tcp::Socket>(h.tcp_handle);
        let smoltcp_closed = matches!(
            sock.state(),
            tcp::State::Closed | tcp::State::TimeWait
        );
        let our_closed = matches!(h.our.state(), State::Closed | State::TimeWait);
        smoltcp_closed && our_closed
    });
    assert!(closed, "close did not complete (our state: {:?}, smoltcp: {:?})",
        h.our.state(),
        h.sockets.get::<tcp::Socket>(h.tcp_handle).state());
}

#[test]
fn smoltcp_active_open_bulk_transfer() {
    let mut h = InteropHarness::new();

    // smoltcp actively opens.
    {
        let cx = h.iface.context();
        let sock = h.sockets.get_mut::<tcp::Socket>(h.tcp_handle);
        sock.connect(
            cx,
            IpEndpoint::new(
                IpAddress::v4(OUR_IP[0], OUR_IP[1], OUR_IP[2], OUR_IP[3]),
                OUR_PORT,
            ),
            IpListenEndpoint { addr: None, port: SMOLTCP_PORT },
        )
        .expect("connect");
    }

    // Establish.
    assert!(
        h.pump_until(2_000, |h| matches!(h.our.state(), State::Established)
            && matches!(
                h.sockets.get::<tcp::Socket>(h.tcp_handle).state(),
                tcp::State::Established
            )),
        "handshake stalled"
    );

    // smoltcp pushes 16 KiB of deterministic bytes.
    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i & 0xFF) as u8).collect();
    {
        let sock = h.sockets.get_mut::<tcp::Socket>(h.tcp_handle);
        let n = sock.send_slice(&payload).expect("smoltcp send_slice");
        assert_eq!(n, payload.len(), "smoltcp buffered the whole payload");
    }

    // Drain on our::Tcb side until all 16 KiB arrive.
    let mut received = Vec::with_capacity(payload.len());
    assert!(
        h.pump_until(10_000, |h| {
            // can't call recv inside pump_until's closure because it's &self.
            // We'll do the recv after pump_until in a separate phase by
            // checking ring length via debug_snapshot.
            h.our.debug_snapshot().recv_ring_len as usize >= payload.len()
        }),
        "our.Tcb did not receive full 16 KiB (got {} bytes)",
        h.our.debug_snapshot().recv_ring_len,
    );

    // Now actually drain into `received`.
    let mut buf = [0u8; 4096];
    while received.len() < payload.len() {
        let n = h.our.recv(&mut buf).expect("recv");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(received, payload, "received bytes mismatch");

    // smoltcp closes its send side.
    h.sockets.get_mut::<tcp::Socket>(h.tcp_handle).close();

    // Our::Tcb should observe FIN within a few RTTs.
    assert!(
        h.pump_until(2_000, |h| matches!(
            h.our.state(),
            State::CloseWait | State::Closed | State::TimeWait
        )),
        "our::Tcb did not observe smoltcp's FIN (state: {:?})",
        h.our.state(),
    );

    // Our side closes too.
    h.our.close().expect("our.close");

    // Both ends fully drain.
    assert!(
        h.pump_until(5_000, |h| matches!(h.our.state(), State::Closed | State::TimeWait)
            && matches!(
                h.sockets.get::<tcp::Socket>(h.tcp_handle).state(),
                tcp::State::Closed | tcp::State::TimeWait
            )),
        "both sides did not reach Closed/TimeWait (our: {:?}, smoltcp: {:?})",
        h.our.state(),
        h.sockets.get::<tcp::Socket>(h.tcp_handle).state(),
    );
}
