#!/usr/bin/env python3
"""Linux-kernel TCP endpoint for bench.sh.

Servers (run in the receiver namespace; they measure goodput the same way
for every stack under test, so results are directly comparable):
  sink   --listen IP:PORT                 accept one connection, read to EOF
  source --listen IP:PORT --bytes N [--cc] accept one connection, send N bytes,
                                           half-close, wait for the peer's FIN

Clients (the kernel stacks being compared with tcp-sans-io):
  send --connect IP:PORT --bytes N --cc CC  upload N bytes with congestion
                                            control CC, half-close, wait EOF
  recv --connect IP:PORT                    download to EOF, then close

Each prints one JSON line. Times start when the connection is established.
"""

import argparse
import json
import socket
import struct
import sys
import time

TCP_CONGESTION = getattr(socket, "TCP_CONGESTION", 13)
TCP_INFO = getattr(socket, "TCP_INFO", 11)
CHUNK = 256 * 1024


def tcp_info(sock):
    """Selected struct tcp_info fields (include/uapi/linux/tcp.h)."""
    raw = sock.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 256)
    u32 = lambda off: struct.unpack_from("I", raw, off)[0] if len(raw) >= off + 4 else None
    u64 = lambda off: struct.unpack_from("Q", raw, off)[0] if len(raw) >= off + 8 else None
    u16 = lambda off: struct.unpack_from("H", raw, off)[0] if len(raw) >= off + 2 else None
    info = {
        "snd_mss": u32(16),
        "snd_ssthresh": u32(76),
        "snd_cwnd": u32(80),
        "total_retrans": u32(100),
        "min_rtt_us": u32(148),
        "data_segs_out": u32(156),
        "bytes_retrans": u64(208),
        "dsack_dups": u32(216),
        "reord_seen": u32(220),
        "total_rto": u16(240),
        "total_rto_recoveries": u16(242),
    }
    return {k: v for k, v in info.items() if v is not None}


def addr(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def listener(where):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(addr(where))
    ls.listen(1)
    return ls


def read_to_eof(conn):
    total, last = 0, time.monotonic()
    buf = bytearray(CHUNK)
    while True:
        n = conn.recv_into(buf)
        if n == 0:
            return total, last
        total += n
        last = time.monotonic()


def send_all(conn, nbytes):
    payload = bytes(i * 7 & 0xFF for i in range(CHUNK))
    left = nbytes
    while left > 0:
        left -= conn.send(payload[: min(left, CHUNK)])


def main():
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["sink", "source", "send", "recv"])
    p.add_argument("--listen")
    p.add_argument("--connect")
    p.add_argument("--bytes", type=int, default=0)
    p.add_argument("--cc", default=None)
    p.add_argument("--ready", help="file to create once listening")
    a = p.parse_args()
    out = {"role": a.role}

    if a.role in ("sink", "source"):
        ls = listener(a.listen)
        if a.cc:
            ls.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, a.cc.encode())
        if a.ready:
            open(a.ready, "w").close()
        ls.settimeout(120)
        conn, peer = ls.accept()
        t0 = time.monotonic()
        if a.role == "sink":
            total, last = read_to_eof(conn)
            out.update(bytes=total, secs=last - t0)
        else:
            send_all(conn, a.bytes)
            conn.shutdown(socket.SHUT_WR)
            read_to_eof(conn)
            out.update(bytes=a.bytes, secs=time.monotonic() - t0, cc=a.cc)
            out["tcp_info"] = tcp_info(conn)
        conn.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if a.cc:
            s.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, a.cc.encode())
        s.settimeout(600)
        s.connect(addr(a.connect))
        t0 = time.monotonic()
        if a.role == "send":
            send_all(s, a.bytes)
            s.shutdown(socket.SHUT_WR)
            read_to_eof(s)
            out.update(bytes=a.bytes, secs=time.monotonic() - t0, cc=a.cc)
            out["tcp_info"] = tcp_info(s)
        else:
            total, last = read_to_eof(s)
            out.update(bytes=total, secs=last - t0)
        s.close()
    json.dump(out, sys.stdout)
    print()


if __name__ == "__main__":
    main()
