"""End-to-end integration test for the tcp-sans-io cdylib via Python ctypes.

The cdylib is the *client*. A pure-Python ``TestPeer`` plays the server role
by hand-crafting IPv4+TCP packets through ``wire.py`` (with full checksums)
and feeding them to ``tcp_inject_packet``. No sockets, no privileges.

Run with:

    python -m unittest discover -s bindings/python -v
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tcp_sans_io  # noqa: E402
import wire         # noqa: E402

CLIENT_IP = bytes([10, 0, 0, 1])
SERVER_IP = bytes([10, 0, 0, 2])
CLIENT_PORT = 49152
SERVER_PORT = 80
SERVER_ISS = 0x9000_0000
CLIENT_ISS = 0x1000_0000


class TestPeer:
    """Tiny server-side peer that only does what we need for the tests."""

    def __init__(self) -> None:
        self.snd_nxt = SERVER_ISS
        self.snd_una = SERVER_ISS
        self.rcv_nxt = 0
        self.peer_mss = 536
        self.ts_enabled = False
        self.ts_recent = 0
        self.advertised_window = 65_535
        self.received = bytearray()

        self.handshake_done = False
        self.our_fin_sent = False
        self.our_fin_seq = 0
        self.our_fin_acked = False
        self.their_fin_received = False

        self.ip_id = 0
        self.now_ms = 0

    # ---- helpers ------------------------------------------------------

    def _opts(self) -> wire.TcpOptions:
        if self.ts_enabled:
            return wire.TcpOptions(ts=(self.now_ms & 0xFFFF_FFFF, self.ts_recent))
        return wire.TcpOptions()

    def _emit(
        self,
        flags: int,
        seq: int,
        ack: int,
        opts: wire.TcpOptions,
        payload: bytes = b"",
    ) -> bytes:
        pkt = wire.emit(
            SERVER_IP,
            CLIENT_IP,
            SERVER_PORT,
            CLIENT_PORT,
            seq,
            ack,
            flags,
            self.advertised_window,
            opts,
            payload,
            self.ip_id,
        )
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        return pkt

    # ---- public API ---------------------------------------------------

    def handle(self, packet: bytes) -> list[bytes]:
        try:
            seg = wire.parse(packet)
        except ValueError:
            return []
        if seg.options.ts is not None:
            self.ts_recent = seg.options.ts[0]

        out: list[bytes] = []

        if not self.handshake_done:
            if seg.has(wire.SYN) and not seg.has(wire.ACK):
                if seg.options.mss is not None:
                    self.peer_mss = seg.options.mss
                if seg.options.ts is not None:
                    self.ts_enabled = True
                self.rcv_nxt = (seg.seq + 1) & 0xFFFF_FFFF
                self.snd_una = self.snd_nxt
                opts = wire.TcpOptions(
                    mss=1460,
                    ts=(self.now_ms & 0xFFFF_FFFF, self.ts_recent) if self.ts_enabled else None,
                )
                out.append(self._emit(wire.SYN | wire.ACK, self.snd_nxt, self.rcv_nxt, opts))
                self.snd_nxt = (self.snd_nxt + 1) & 0xFFFF_FFFF
                self.handshake_done = True
            return out

        if self.our_fin_sent and self.our_fin_acked and self.their_fin_received:
            return out

        # ACK accounting
        if seg.has(wire.ACK):
            ack = seg.ack
            if not _seq_gt(ack, self.snd_nxt) and _seq_ge(ack, self.snd_una):
                self.snd_una = ack
            if (
                self.our_fin_sent
                and not self.our_fin_acked
                and _seq_gt(self.snd_una, self.our_fin_seq)
            ):
                self.our_fin_acked = True

        # Data
        if seg.payload and not self.their_fin_received:
            if seg.seq == self.rcv_nxt:
                self.received.extend(seg.payload)
                self.rcv_nxt = (self.rcv_nxt + len(seg.payload)) & 0xFFFF_FFFF
                out.append(self._emit(wire.ACK, self.snd_nxt, self.rcv_nxt, self._opts()))
            else:
                # OoO -> dup-ACK.
                out.append(self._emit(wire.ACK, self.snd_nxt, self.rcv_nxt, self._opts()))

        # FIN
        if seg.has(wire.FIN) and not self.their_fin_received:
            fin_seq = (seg.seq + len(seg.payload)) & 0xFFFF_FFFF
            if fin_seq == self.rcv_nxt:
                self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFF_FFFF
                self.their_fin_received = True
                out.append(self._emit(wire.ACK, self.snd_nxt, self.rcv_nxt, self._opts()))

        return out

    def send_data(self, data: bytes) -> bytes:
        seq = self.snd_nxt
        pkt = self._emit(wire.ACK | wire.PSH, seq, self.rcv_nxt, self._opts(), data)
        self.snd_nxt = (self.snd_nxt + len(data)) & 0xFFFF_FFFF
        return pkt

    def close(self) -> bytes:
        self.our_fin_seq = self.snd_nxt
        self.our_fin_sent = True
        pkt = self._emit(wire.FIN | wire.ACK, self.snd_nxt, self.rcv_nxt, self._opts())
        self.snd_nxt = (self.snd_nxt + 1) & 0xFFFF_FFFF
        return pkt

    @property
    def is_fully_closed(self) -> bool:
        return self.our_fin_sent and self.our_fin_acked and self.their_fin_received


def _seq_gt(a: int, b: int) -> bool:
    return ((a - b) & 0xFFFF_FFFF) != 0 and ((a - b) & 0xFFFF_FFFF) < 0x8000_0000


def _seq_ge(a: int, b: int) -> bool:
    d = (a - b) & 0xFFFF_FFFF
    return d == 0 or d < 0x8000_0000


# ---------------------------------------------------------------------------


def drain(client: tcp_sans_io.TcpStream, now_ms: int) -> list[bytes]:
    out: list[bytes] = []
    while True:
        client.tick(now_ms)
        pkt = client.extract_packet()
        if pkt is None:
            break
        out.append(pkt)
    return out


def make_client() -> tcp_sans_io.TcpStream:
    return tcp_sans_io.TcpStream(
        CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, CLIENT_ISS, 1000
    )


class IntegrationTests(unittest.TestCase):
    def test_abi_version(self) -> None:
        self.assertEqual(tcp_sans_io.abi_version(), 1)

    def test_handshake(self) -> None:
        client = make_client()
        peer = TestPeer()
        now = 1000
        try:
            client.connect(now)
            pkts = drain(client, now)
            self.assertEqual(len(pkts), 1, "expected one SYN")

            now += 5
            peer.now_ms = now
            replies = peer.handle(pkts[0])
            self.assertEqual(len(replies), 1, "expected SYN-ACK")

            now += 5
            client.inject_packet(replies[0], now)
            pkts = drain(client, now)
            self.assertEqual(len(pkts), 1, "expected ACK after SYN-ACK")
            peer.handle(pkts[0])

            self.assertEqual(client.state(), tcp_sans_io.State.ESTABLISHED)
            self.assertTrue(peer.ts_enabled, "peer should see Timestamps option")
            self.assertEqual(peer.peer_mss, 1460)
        finally:
            client.destroy()

    def test_request_response(self) -> None:
        client = make_client()
        peer = TestPeer()
        now = 1000
        try:
            self._handshake(client, peer, now)
            now += 50

            # Client → peer
            req = b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n"
            self.assertEqual(client.send(req), len(req))
            now += 1
            pkts = drain(client, now)
            self.assertEqual(len(pkts), 1)
            now += 1
            peer.now_ms = now
            replies = peer.handle(pkts[0])
            self.assertEqual(len(replies), 1)
            self.assertEqual(bytes(peer.received), req)

            now += 1
            client.inject_packet(replies[0], now)

            # Peer → client
            resp = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"
            now += 5
            peer.now_ms = now
            data = peer.send_data(resp)
            now += 1
            client.inject_packet(data, now)
            got = client.recv(4096)
            self.assertEqual(got, resp)
        finally:
            client.destroy()

    def test_active_close(self) -> None:
        client = make_client()
        peer = TestPeer()
        now = 1000
        try:
            self._handshake(client, peer, now)
            now += 50

            client.close(now)
            pkts = drain(client, now)
            self.assertEqual(len(pkts), 1)
            self.assertEqual(client.state(), tcp_sans_io.State.FIN_WAIT_1)

            now += 5
            peer.now_ms = now
            acks = peer.handle(pkts[0])
            self.assertEqual(len(acks), 1)
            now += 1
            client.inject_packet(acks[0], now)
            self.assertEqual(client.state(), tcp_sans_io.State.FIN_WAIT_2)

            now += 5
            peer.now_ms = now
            peer_fin = peer.close()
            now += 1
            client.inject_packet(peer_fin, now)
            self.assertEqual(client.state(), tcp_sans_io.State.TIME_WAIT)

            pkts = drain(client, now)
            self.assertEqual(len(pkts), 1)
            peer.handle(pkts[0])
            self.assertTrue(peer.is_fully_closed)

            # 2*MSL → CLOSED
            now += 60_001
            client.tick(now)
            self.assertEqual(client.state(), tcp_sans_io.State.CLOSED)
        finally:
            client.destroy()

    def test_rst_aborts(self) -> None:
        client = make_client()
        peer = TestPeer()
        now = 1000
        try:
            self._handshake(client, peer, now)
            now += 5

            peer.now_ms = now
            rst = peer._emit(
                wire.RST | wire.ACK, peer.snd_nxt, peer.rcv_nxt, peer._opts()
            )
            client.inject_packet(rst, now)

            self.assertEqual(client.state(), tcp_sans_io.State.CLOSED)
            self.assertTrue(client.poll() & tcp_sans_io.Events.ERROR)
            with self.assertRaises(tcp_sans_io.TcpError) as cm:
                client.recv(16)
            self.assertEqual(cm.exception.code, -7)  # ConnectionReset
        finally:
            client.destroy()

    # ---- helpers ------------------------------------------------------

    def _handshake(self, client: tcp_sans_io.TcpStream, peer: TestPeer, now: int) -> None:
        client.connect(now)
        pkts = drain(client, now)
        self.assertEqual(len(pkts), 1)
        peer.now_ms = now + 5
        replies = peer.handle(pkts[0])
        self.assertEqual(len(replies), 1)
        client.inject_packet(replies[0], now + 10)
        pkts = drain(client, now + 10)
        self.assertEqual(len(pkts), 1)
        peer.handle(pkts[0])
        self.assertEqual(client.state(), tcp_sans_io.State.ESTABLISHED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
