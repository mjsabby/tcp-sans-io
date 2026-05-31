# wgserver-rs — userspace TCP server harness over UDP

A standalone binary that hosts many `tcp-sans-io` TCBs in parallel on
a single UDP socket. UDP datagrams carry raw IPv4+TCP packets as
opaque payloads — a "WireGuard-shaped" outer transport without the
crypto. No kernel TUN, no root, runs on Linux / macOS / Windows.

Intended use:

* End-to-end stress and adversarial testing of the listen-side stack
  (driven by `bindings/wgserver/` from Go).
* Reference for Rust hosts that want to embed the stack in a real WG
  deployment — swap the `std::net::UdpSocket` for a WG endpoint and
  the rest of the loop is the same.

## Build

```sh
# Default (BUF_CAP = 1 MiB per Tcb) — small server / few listeners.
cargo build --release --manifest-path bindings/wgserver-rs/Cargo.toml

# Stress profile (BUF_CAP = 32 KiB per Tcb) — recommended for any
# `--num-listeners` ≥ ~100.
cargo build --release --manifest-path bindings/wgserver-rs/Cargo.toml \
            --features small-buffers
```

The `small-buffers` Cargo feature is forwarded to the parent crate
and shrinks the per-direction ring buffer from 1 MiB to 32 KiB. With
that, each `Tcb` is ~150 KiB; 10 000 of them fit in ~1.5 GiB.

## CLI

```
wgserver [options]

  --listen-udp <ip:port>     UDP bind address (default 127.0.0.1:9001)
  --peer-udp   <ip:port>     UDP peer to send replies to
  --server-ip  <a.b.c.d>     virtual TCP server IP advertised to clients
  --base-port  <p>           first listening TCP port (default 30000)
  --num-listeners <N>        listener count (default 16, max 65535)
  --cookies <hex32|random|none>
                             enable SYN cookies with a 16-byte secret
                             (32 hex chars), generate a random secret,
                             or leave them off (default)
  --memory-cap-mib <N>       refuse to run if total estimated RSS would
                             exceed this (default 4096)
  --quiet                    suppress per-iteration stats output
  -h, --help                 show this help
```

The binary prints a banner on stdout (`wgserver: tcb_size=… ready`)
once the listeners are armed; embedders / drivers can wait on that
line before sending packets.

## Memory footprint

| Build               | `BUF_CAP` | `size_of::<Tcb>()` | 10 000 listeners |
| ------------------- | --------: | ------------------: | ---------------: |
| Default             |    1 MiB |          ~2.15 MiB |          ~21 GiB |
| `--features small-buffers` |  32 KiB |           ~152 KiB |          ~1.5 GiB |

The exact `size_of::<Tcb>()` is reported in the startup banner.

## Pump architecture

Single-threaded event loop:

1. Drain the UDP socket to `WouldBlock` (one `recv_from` per call;
   per-iteration batching across all 10K TCBs).
2. Each datagram → parse IPv4 → demux on TCP destination port to the
   per-listener TCB index → `Tcb::inject_packet`.
3. TCBs that left LISTEN (or whose inject queued egress bytes — e.g.
   a stateless cookie SYN-ACK, or a RST in reply to a hostile SYN+ACK)
   join an **active set** keyed on listener index.
4. For each TCB in the active set: `tick`, drain `extract_packet` →
   `UdpSocket::send_to(peer)`, drain `recv` into a per-conn scratch,
   run the line-echo handler, push the response, call `close()` once
   the response is fully queued.
5. On `Closed` / `TimeWait`, the TCB re-arms (`listen()` + optional
   cookie secret) and leaves the active set.

This keeps per-iteration work O(|active set|) rather than O(N), which
matters at 10 000 listeners.

## Cross-platform shutdown

The pump reads stdin between iterations and exits cleanly on either
`"shutdown\n"` or EOF (parent closes stdin). No signal handlers,
works identically on every supported OS.

## Limitations

* The transport stands in for WireGuard's outer datagram framing only.
  No crypto, no replay protection, no allowed-IP filtering. Production
  deployments substitute a real WG endpoint at this layer.
* The line-echo app handler is intentionally tiny — frames a single
  request at the first `\n`, replies, and closes. Real applications
  would replace it.
* MSS clamping for cross-host runs is not configured; loopback only on
  the supplied tests.
