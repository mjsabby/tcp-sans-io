"""Python ctypes binding for the tcp-sans-io cdylib.

Loads ``tcp_sans_io.dll`` (Windows) / ``libtcp_sans_io.so`` (Linux) /
``libtcp_sans_io.dylib`` (macOS) from either this directory or the Cargo
``target/release`` output of the parent repo.

The ``TcpStream`` class wraps every FFI entry point in a Pythonic API that:

* allocates the connection's storage block as an aligned ``c_uint64`` array
  (caller-owned, exactly as the FFI contract requires),
* surfaces negative status codes as :class:`TcpError` exceptions,
* never holds a Python-side reference longer than the underlying handle.

This module is stdlib-only — no NumPy, no cffi, no pip install.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import (
    POINTER,
    c_int32,
    c_size_t,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
    c_void_p,
)
from typing import Optional

# ---------------------------------------------------------------------------
# Load the cdylib
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))


def _candidate_names() -> list[str]:
    if sys.platform.startswith("win"):
        return ["tcp_sans_io.dll"]
    if sys.platform == "darwin":
        return ["libtcp_sans_io.dylib"]
    return ["libtcp_sans_io.so"]


def _candidate_paths() -> list[str]:
    paths: list[str] = []
    for name in _candidate_names():
        paths.append(os.path.join(_HERE, name))
        paths.append(os.path.join(_HERE, "..", "..", "target", "release", name))
        paths.append(os.path.join(_HERE, "..", "..", "target", "debug", name))
    return paths


def _load() -> ctypes.CDLL:
    last_err: Optional[Exception] = None
    for path in _candidate_paths():
        if os.path.isfile(path):
            try:
                return ctypes.CDLL(path)
            except OSError as e:  # pragma: no cover
                last_err = e
    raise RuntimeError(
        "tcp-sans-io: could not locate the cdylib. Tried:\n  "
        + "\n  ".join(_candidate_paths())
        + (f"\nLast error: {last_err}" if last_err else "")
    )


_lib = _load()

# ---------------------------------------------------------------------------
# FFI signatures — matches src/ffi.rs
# ---------------------------------------------------------------------------

_lib.tcp_abi_version.restype = c_uint32
_lib.tcp_abi_version.argtypes = []

_lib.tcp_selftest.restype = c_int32
_lib.tcp_selftest.argtypes = []

_lib.tcp_handle_size.restype = c_size_t
_lib.tcp_handle_size.argtypes = []

_lib.tcp_handle_align.restype = c_size_t
_lib.tcp_handle_align.argtypes = []

_lib.tcp_init.restype = c_int32
_lib.tcp_init.argtypes = [
    c_void_p,         # storage
    c_void_p,         # local_ip (4 bytes)
    c_uint16,         # local_port
    c_void_p,         # remote_ip
    c_uint16,         # remote_port
    c_uint32,         # iss
    c_uint32,         # initial_rto_ms
]

_lib.tcp_destroy.restype = c_int32
_lib.tcp_destroy.argtypes = [c_void_p]

_lib.tcp_connect.restype = c_int32
_lib.tcp_connect.argtypes = [c_void_p, c_uint64]

_lib.tcp_listen.restype = c_int32
_lib.tcp_listen.argtypes = [c_void_p, c_uint64]

_lib.tcp_set_cookie_secret.restype = c_int32
_lib.tcp_set_cookie_secret.argtypes = [c_void_p, c_void_p]

_lib.tcp_close.restype = c_int32
_lib.tcp_close.argtypes = [c_void_p, c_uint64]

_lib.tcp_tick.restype = c_int32
_lib.tcp_tick.argtypes = [c_void_p, c_uint64]

_lib.tcp_state.restype = c_uint8
_lib.tcp_state.argtypes = [c_void_p]

_lib.tcp_poll.restype = c_uint32
_lib.tcp_poll.argtypes = [c_void_p]

_lib.tcp_send.restype = c_int32
_lib.tcp_send.argtypes = [c_void_p, c_void_p, c_size_t, POINTER(c_size_t)]

_lib.tcp_recv.restype = c_int32
_lib.tcp_recv.argtypes = [c_void_p, c_void_p, c_size_t, POINTER(c_size_t)]

_lib.tcp_inject_packet.restype = c_int32
_lib.tcp_inject_packet.argtypes = [c_void_p, c_void_p, c_size_t, c_uint64]

_lib.tcp_extract_packet.restype = c_int32
_lib.tcp_extract_packet.argtypes = [c_void_p, c_void_p, c_size_t, POINTER(c_size_t)]

# ---------------------------------------------------------------------------
# State / error / event constants — keep in sync with the Rust enum.
# ---------------------------------------------------------------------------


class State:
    CLOSED = 0
    SYN_SENT = 1
    ESTABLISHED = 2
    FIN_WAIT_1 = 3
    FIN_WAIT_2 = 4
    CLOSING = 5
    TIME_WAIT = 6
    CLOSE_WAIT = 7
    LAST_ACK = 8
    LISTEN = 9
    SYN_RCVD = 10
    INVALID = 0xFF

    _names = {
        0: "CLOSED",
        1: "SYN_SENT",
        2: "ESTABLISHED",
        3: "FIN_WAIT_1",
        4: "FIN_WAIT_2",
        5: "CLOSING",
        6: "TIME_WAIT",
        7: "CLOSE_WAIT",
        8: "LAST_ACK",
        9: "LISTEN",
        10: "SYN_RCVD",
        0xFF: "INVALID",
    }

    @classmethod
    def name(cls, code: int) -> str:
        return cls._names.get(code, f"UNKNOWN({code})")


class Events:
    READABLE = 1 << 0
    WRITABLE = 1 << 1
    ESTABLISHED = 1 << 2
    PEER_CLOSED = 1 << 3
    CLOSED = 1 << 4
    TX_PENDING = 1 << 5
    ERROR = 1 << 6
    LISTENING = 1 << 7
    HALF_OPEN = 1 << 8


_ERR_NAMES = {
    -1: "BufferTooSmall",
    -2: "NullPointer",
    -3: "InvalidState",
    -4: "MalformedPacket",
    -5: "NotForUs",
    -6: "WouldBlock",
    -7: "ConnectionReset",
    -8: "ConnectionClosed",
    -9: "Overflow",
}


class TcpError(Exception):
    def __init__(self, code: int) -> None:
        self.code = code
        self.kind = _ERR_NAMES.get(code, f"Unknown({code})")
        super().__init__(f"tcp-sans-io error: {self.kind} ({code})")


def abi_version() -> int:
    return int(_lib.tcp_abi_version())


def selftest() -> int:
    """Run the built-in self-conformance smoke test.

    Drives two in-process instances of the stack through a byte-exact
    bidirectional transfer and clean close. Returns 0 on success or a
    negative stage code. Call once after import to confirm the cdylib is
    correctly linked and healthy before opening a real connection.
    """
    return int(_lib.tcp_selftest())

# ---------------------------------------------------------------------------
# Pythonic wrapper
# ---------------------------------------------------------------------------


def _check(rc: int) -> None:
    if rc < 0:
        raise TcpError(rc)


class TcpStream:
    """Thin Pythonic wrapper around an opaque ``TcpStreamHandle``.

    Storage for the handle is allocated as an aligned ``c_uint64`` array so
    the FFI's ``tcp_handle_align()`` requirement is always satisfied.
    """

    __slots__ = ("_storage", "_handle", "_destroyed")

    def __init__(
        self,
        local_ip: bytes,
        local_port: int,
        remote_ip: bytes,
        remote_port: int,
        iss: int,
        initial_rto_ms: int = 1000,
    ) -> None:
        if len(local_ip) != 4 or len(remote_ip) != 4:
            raise ValueError("local_ip / remote_ip must be exactly 4 bytes")

        size = int(_lib.tcp_handle_size())
        align = int(_lib.tcp_handle_align())
        # c_uint64 array gives 8-byte alignment, sufficient for any field
        # the TCB currently uses (max alignment = u64).
        if align > 8:
            raise RuntimeError(
                f"FFI requires alignment {align}, ctypes can only guarantee 8"
            )
        n_words = (size + 7) // 8
        self._storage = (c_uint64 * n_words)()
        self._handle = ctypes.cast(self._storage, c_void_p)
        self._destroyed = False

        local_ip_buf = (c_uint8 * 4)(*local_ip)
        remote_ip_buf = (c_uint8 * 4)(*remote_ip)

        rc = _lib.tcp_init(
            self._handle,
            ctypes.cast(local_ip_buf, c_void_p),
            c_uint16(local_port),
            ctypes.cast(remote_ip_buf, c_void_p),
            c_uint16(remote_port),
            c_uint32(iss & 0xFFFF_FFFF),
            c_uint32(initial_rto_ms),
        )
        _check(rc)

    # ---- lifecycle -----------------------------------------------------

    def destroy(self) -> None:
        if not self._destroyed:
            _lib.tcp_destroy(self._handle)
            self._destroyed = True

    def __enter__(self) -> "TcpStream":
        return self

    def __exit__(self, *_: object) -> None:
        self.destroy()

    def __del__(self) -> None:  # pragma: no cover
        try:
            self.destroy()
        except Exception:
            pass

    # ---- connection control -------------------------------------------

    def connect(self, now_ms: int) -> None:
        _check(_lib.tcp_connect(self._handle, c_uint64(now_ms)))

    def listen(self, now_ms: int) -> None:
        """Transition CLOSED → LISTEN. Wildcard remote until SYN arrives."""
        _check(_lib.tcp_listen(self._handle, c_uint64(now_ms)))

    def set_cookie_secret(self, secret: bytes) -> None:
        """Enable RFC 4987 SYN cookies. ``secret`` must be exactly 16 bytes
        from a CSPRNG. Once set, the listener answers SYNs statelessly."""
        if len(secret) != 16:
            raise ValueError("cookie secret must be exactly 16 bytes")
        buf = (c_uint8 * 16)(*secret)
        _check(_lib.tcp_set_cookie_secret(self._handle, ctypes.cast(buf, c_void_p)))

    def close(self, now_ms: int) -> None:
        _check(_lib.tcp_close(self._handle, c_uint64(now_ms)))

    def tick(self, now_ms: int) -> None:
        _check(_lib.tcp_tick(self._handle, c_uint64(now_ms)))

    # ---- introspection -------------------------------------------------

    def state(self) -> int:
        return int(_lib.tcp_state(self._handle))

    def poll(self) -> int:
        return int(_lib.tcp_poll(self._handle))

    # ---- buffers -------------------------------------------------------

    def send(self, data: bytes) -> int:
        if not data:
            return 0
        buf = (c_uint8 * len(data))(*data)
        written = c_size_t(0)
        rc = _lib.tcp_send(
            self._handle,
            ctypes.cast(buf, c_void_p),
            c_size_t(len(data)),
            ctypes.byref(written),
        )
        _check(rc)
        return int(written.value)

    def recv(self, max_bytes: int = 4096) -> bytes:
        buf = (c_uint8 * max_bytes)()
        read = c_size_t(0)
        rc = _lib.tcp_recv(
            self._handle,
            ctypes.cast(buf, c_void_p),
            c_size_t(max_bytes),
            ctypes.byref(read),
        )
        _check(rc)
        n = int(read.value)
        return bytes(buf[:n])

    def inject_packet(self, packet: bytes, now_ms: int) -> None:
        if not packet:
            return
        buf = (c_uint8 * len(packet))(*packet)
        rc = _lib.tcp_inject_packet(
            self._handle,
            ctypes.cast(buf, c_void_p),
            c_size_t(len(packet)),
            c_uint64(now_ms),
        )
        _check(rc)

    def extract_packet(self) -> Optional[bytes]:
        # 1500 is the cdylib's MAX_PACKET (IPv4(20) + TCP(20) + MSS(1460)).
        cap = 1500
        buf = (c_uint8 * cap)()
        written = c_size_t(0)
        rc = _lib.tcp_extract_packet(
            self._handle,
            ctypes.cast(buf, c_void_p),
            c_size_t(cap),
            ctypes.byref(written),
        )
        _check(rc)
        n = int(written.value)
        if n == 0:
            return None
        return bytes(buf[:n])
