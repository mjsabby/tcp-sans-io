// SPDX-License-Identifier: MIT OR Apache-2.0
//
// P/Invoke surface mirroring src/ffi.rs. The DLL is resolved at startup by
// Program.Main calling NativeLibrary.Load with an absolute path, so the
// DllImport names below need only match the exported symbols.

using System.Runtime.InteropServices;

namespace TcpSansIo;

internal static class Native
{
    public const string LibName = "tcp_sans_io";

    // ---- Sizing / ABI ------------------------------------------------------

    [DllImport(LibName)]
    public static extern uint tcp_abi_version();

    [DllImport(LibName)]
    public static extern UIntPtr tcp_handle_size();

    [DllImport(LibName)]
    public static extern UIntPtr tcp_handle_align();

    // ---- Lifecycle ---------------------------------------------------------

    [DllImport(LibName)]
    public static extern int tcp_init(
        IntPtr storage,
        IntPtr localIp,
        ushort localPort,
        IntPtr remoteIp,
        ushort remotePort,
        uint iss,
        uint initialRtoMs);

    [DllImport(LibName)]
    public static extern int tcp_destroy(IntPtr handle);

    // ---- Connection control -----------------------------------------------

    [DllImport(LibName)]
    public static extern int tcp_connect(IntPtr handle, ulong nowMs);

    [DllImport(LibName)]
    public static extern int tcp_listen(IntPtr handle, ulong nowMs);

    [DllImport(LibName)]
    public static extern int tcp_set_cookie_secret(IntPtr handle, IntPtr secret);

    [DllImport(LibName)]
    public static extern int tcp_close(IntPtr handle, ulong nowMs);

    [DllImport(LibName)]
    public static extern int tcp_tick(IntPtr handle, ulong nowMs);

    // ---- Introspection -----------------------------------------------------

    [DllImport(LibName)]
    public static extern byte tcp_state(IntPtr handle);

    [DllImport(LibName)]
    public static extern uint tcp_poll(IntPtr handle);

    // ---- Buffers -----------------------------------------------------------

    [DllImport(LibName)]
    public static extern int tcp_send(
        IntPtr handle,
        IntPtr data,
        UIntPtr len,
        out UIntPtr written);

    [DllImport(LibName)]
    public static extern int tcp_recv(
        IntPtr handle,
        IntPtr buf,
        UIntPtr cap,
        out UIntPtr read);

    [DllImport(LibName)]
    public static extern int tcp_inject_packet(
        IntPtr handle,
        IntPtr packet,
        UIntPtr len,
        ulong nowMs);

    [DllImport(LibName)]
    public static extern int tcp_extract_packet(
        IntPtr handle,
        IntPtr buf,
        UIntPtr cap,
        out UIntPtr written);
}

internal enum TcpState : byte
{
    Closed = 0,
    SynSent = 1,
    Established = 2,
    FinWait1 = 3,
    FinWait2 = 4,
    Closing = 5,
    TimeWait = 6,
    CloseWait = 7,
    LastAck = 8,
    Listen = 9,
    SynRcvd = 10,
    Invalid = 0xFF,
}

[Flags]
internal enum TcpEvents : uint
{
    None = 0,
    Readable = 1u << 0,
    Writable = 1u << 1,
    Established = 1u << 2,
    PeerClosed = 1u << 3,
    Closed = 1u << 4,
    TxPending = 1u << 5,
    Error = 1u << 6,
    Listening = 1u << 7,
    HalfOpen = 1u << 8,
}

internal enum TcpErrorCode
{
    BufferTooSmall = -1,
    NullPointer = -2,
    InvalidState = -3,
    MalformedPacket = -4,
    NotForUs = -5,
    WouldBlock = -6,
    ConnectionReset = -7,
    ConnectionClosed = -8,
    Overflow = -9,
}

internal sealed class TcpException : Exception
{
    public TcpErrorCode Code { get; }

    public TcpException(int code)
        : base($"tcp-sans-io error: {(TcpErrorCode)code} ({code})")
    {
        Code = (TcpErrorCode)code;
    }
}
