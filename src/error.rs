//! Error codes. Mapped 1:1 to negative `i32` values across the FFI boundary.

/// Errors returned by the stack. Every public TCB and FFI entry point uses
/// `Result<T, TcpError>` (or its FFI equivalent) — there is no implicit
/// failure mode.
#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpError {
    /// The supplied buffer was too small for the requested operation.
    BufferTooSmall = -1,
    /// A NULL pointer was passed across the FFI boundary.
    NullPointer = -2,
    /// The handle is in a state that cannot service the request
    /// (e.g. `tcp_send` while `CLOSED`).
    InvalidState = -3,
    /// Inbound packet is malformed (truncated header, bad checksum, …).
    MalformedPacket = -4,
    /// Inbound packet is well-formed but does not belong to this connection.
    NotForUs = -5,
    /// Local send ring is full and would block.
    WouldBlock = -6,
    /// Connection has been reset by the peer (RST received) or aborted locally.
    ConnectionReset = -7,
    /// Peer closed cleanly and all buffered data has been consumed.
    ConnectionClosed = -8,
    /// Numeric conversion / arithmetic boundary error (defensive).
    Overflow = -9,
}

impl TcpError {
    /// FFI: convert to the negative `i32` status code surfaced to host code.
    #[inline]
    pub const fn as_code(self) -> i32 {
        self as i32
    }
}
