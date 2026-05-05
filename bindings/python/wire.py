"""Minimal IPv4 + TCP packet codec used by the integration test peer.

Mirrors src/wire.rs byte-for-byte. Only the two TCP options we negotiate
(MSS and Timestamps) are honoured on the parse side; everything else is
skipped. Built and parsed with checksums verified.

This file deliberately exists only to support the in-process integration
test peer — production callers do not need it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

IPPROTO_TCP = 6
IPV4_HDR_LEN = 20
TCP_HDR_LEN = 20

# Flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10


# ---------------------------------------------------------------------------
# Checksums (RFC 1071) — match the cdylib bit for bit.
# ---------------------------------------------------------------------------


def _ones_complement(data: bytes, seed: int = 0) -> int:
    s = seed
    n = len(data)
    i = 0
    while i + 1 < n:
        s += (data[i] << 8) | data[i + 1]
        i += 2
    if i < n:
        s += data[i] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_segment: bytes) -> int:
    pseudo = ((src_ip[0] << 8) | src_ip[1])
    pseudo += ((src_ip[2] << 8) | src_ip[3])
    pseudo += ((dst_ip[0] << 8) | dst_ip[1])
    pseudo += ((dst_ip[2] << 8) | dst_ip[3])
    pseudo += IPPROTO_TCP
    pseudo += len(tcp_segment) & 0xFFFF
    return _ones_complement(tcp_segment, pseudo)


# ---------------------------------------------------------------------------
# TCP options
# ---------------------------------------------------------------------------


@dataclass
class TcpOptions:
    mss: Optional[int] = None
    ts: Optional[tuple[int, int]] = None  # (TSval, TSecr)

    def encoded_len(self) -> int:
        if self.mss is None and self.ts is None:
            return 0
        if self.mss is not None and self.ts is None:
            return 4
        if self.mss is None and self.ts is not None:
            return 12
        return 16

    def encode(self) -> bytes:
        out = bytearray()
        if self.mss is not None:
            out.append(2)               # kind = MSS
            out.append(4)               # length
            out.extend(self.mss.to_bytes(2, "big"))
        if self.ts is not None:
            tsval, tsecr = self.ts
            if self.mss is None:
                out.extend(b"\x01\x01")  # NOP NOP
            out.append(8)                # kind = Timestamps
            out.append(10)               # length
            out.extend((tsval & 0xFFFF_FFFF).to_bytes(4, "big"))
            out.extend((tsecr & 0xFFFF_FFFF).to_bytes(4, "big"))
            if self.mss is not None:
                out.extend(b"\x01\x01")  # trailing NOPs to align to 4
        return bytes(out)

    @staticmethod
    def parse(opt_bytes: bytes) -> "TcpOptions":
        o = TcpOptions()
        i = 0
        n = len(opt_bytes)
        while i < n:
            kind = opt_bytes[i]
            if kind == 0:    # EOL
                break
            if kind == 1:    # NOP
                i += 1
                continue
            if i + 1 >= n:
                raise ValueError("truncated TCP option")
            length = opt_bytes[i + 1]
            if length < 2 or i + length > n:
                raise ValueError("bad TCP option length")
            if kind == 2 and length == 4:
                o.mss = int.from_bytes(opt_bytes[i + 2 : i + 4], "big")
            elif kind == 8 and length == 10:
                tsval = int.from_bytes(opt_bytes[i + 2 : i + 6], "big")
                tsecr = int.from_bytes(opt_bytes[i + 6 : i + 10], "big")
                o.ts = (tsval, tsecr)
            # other options: silently skip
            i += length
        return o


# ---------------------------------------------------------------------------
# Segment view
# ---------------------------------------------------------------------------


@dataclass
class Segment:
    src_ip: bytes
    dst_ip: bytes
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    window: int
    options: TcpOptions
    payload: bytes = field(default=b"")

    def has(self, f: int) -> bool:
        return (self.flags & f) == f


# ---------------------------------------------------------------------------
# Emit / parse
# ---------------------------------------------------------------------------


def emit(
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    window: int,
    options: TcpOptions,
    payload: bytes = b"",
    ip_id: int = 0,
) -> bytes:
    if len(src_ip) != 4 or len(dst_ip) != 4:
        raise ValueError("IPs must be 4 bytes")
    opt_bytes = options.encode()
    if len(opt_bytes) % 4 != 0:
        raise ValueError("options must be 4-byte aligned")
    tcp_hdr_len = TCP_HDR_LEN + len(opt_bytes)
    total = IPV4_HDR_LEN + tcp_hdr_len + len(payload)
    if total > 0xFFFF:
        raise ValueError("packet too large for IPv4")

    # IPv4 header
    ip = bytearray(IPV4_HDR_LEN)
    ip[0] = 0x45                        # version=4, IHL=5
    ip[1] = 0
    ip[2:4] = total.to_bytes(2, "big")
    ip[4:6] = (ip_id & 0xFFFF).to_bytes(2, "big")
    ip[6:8] = (0x4000).to_bytes(2, "big")  # DF set
    ip[8] = 64                          # TTL
    ip[9] = IPPROTO_TCP
    ip[10:12] = (0).to_bytes(2, "big")
    ip[12:16] = src_ip
    ip[16:20] = dst_ip
    ip_csum = _ones_complement(bytes(ip))
    ip[10:12] = ip_csum.to_bytes(2, "big")

    # TCP header
    tcp = bytearray(tcp_hdr_len + len(payload))
    tcp[0:2] = src_port.to_bytes(2, "big")
    tcp[2:4] = dst_port.to_bytes(2, "big")
    tcp[4:8] = (seq & 0xFFFF_FFFF).to_bytes(4, "big")
    tcp[8:12] = (ack & 0xFFFF_FFFF).to_bytes(4, "big")
    tcp[12] = (tcp_hdr_len // 4) << 4
    tcp[13] = flags & 0xFF
    tcp[14:16] = (window & 0xFFFF).to_bytes(2, "big")
    # csum (16-17), urg (18-19) start zeroed.
    if opt_bytes:
        tcp[TCP_HDR_LEN : TCP_HDR_LEN + len(opt_bytes)] = opt_bytes
    if payload:
        tcp[tcp_hdr_len : tcp_hdr_len + len(payload)] = payload

    csum = _tcp_checksum(src_ip, dst_ip, bytes(tcp))
    tcp[16:18] = csum.to_bytes(2, "big")

    return bytes(ip) + bytes(tcp)


def parse(packet: bytes) -> Segment:
    if len(packet) < IPV4_HDR_LEN + TCP_HDR_LEN:
        raise ValueError("packet too short")
    if packet[0] >> 4 != 4:
        raise ValueError("not IPv4")
    ihl = (packet[0] & 0x0F) * 4
    if ihl < IPV4_HDR_LEN:
        raise ValueError("bad IHL")
    total_len = int.from_bytes(packet[2:4], "big")
    if total_len > len(packet) or total_len < ihl + TCP_HDR_LEN:
        raise ValueError("bad total length")
    flags_frag = int.from_bytes(packet[6:8], "big")
    if (flags_frag & 0x2000) or (flags_frag & 0x1FFF):
        raise ValueError("fragmented packet")
    if packet[9] != IPPROTO_TCP:
        raise ValueError("not TCP")

    if _ones_complement(packet[:ihl]) != 0:
        raise ValueError("bad IPv4 checksum")

    src_ip = packet[12:16]
    dst_ip = packet[16:20]

    tcp = packet[ihl:total_len]
    if len(tcp) < TCP_HDR_LEN:
        raise ValueError("TCP too short")
    src_port = int.from_bytes(tcp[0:2], "big")
    dst_port = int.from_bytes(tcp[2:4], "big")
    seq = int.from_bytes(tcp[4:8], "big")
    ack = int.from_bytes(tcp[8:12], "big")
    data_off = (tcp[12] >> 4) * 4
    if data_off < TCP_HDR_LEN or data_off > len(tcp):
        raise ValueError("bad data offset")
    flags = tcp[13]
    window = int.from_bytes(tcp[14:16], "big")
    if _tcp_checksum(src_ip, dst_ip, tcp) != 0:
        raise ValueError("bad TCP checksum")

    options = TcpOptions.parse(tcp[TCP_HDR_LEN:data_off])
    payload = bytes(tcp[data_off:])
    return Segment(
        src_ip=bytes(src_ip),
        dst_ip=bytes(dst_ip),
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
        options=options,
        payload=payload,
    )
