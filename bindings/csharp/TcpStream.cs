// SPDX-License-Identifier: MIT OR Apache-2.0
//
// High-level managed wrapper around the cdylib's placement-init handle.
//
// The native crate is no_std with no allocator. The host (us) is responsible
// for storage: we query tcp_handle_size / tcp_handle_align, allocate that
// block via Marshal.AllocHGlobal (which on .NET satisfies any reasonable
// alignment requirement up to pointer size), and free it after destroy.

using System.Runtime.InteropServices;

namespace TcpSansIo;

internal sealed class TcpStream : IDisposable
{
    // Sized from the cdylib (FFI contract: never hardcode 1500 — a future
    // MSS/options change would turn every extract into BufferTooSmall).
    private static readonly int MaxPacket = (int)(nuint)Native.tcp_max_packet();

    private IntPtr _storage;
    private bool _destroyed;

    public TcpStream(
        byte[] localIp, ushort localPort,
        byte[] remoteIp, ushort remotePort,
        uint iss, uint initialRtoMs)
    {
        if (localIp.Length != 4 || remoteIp.Length != 4)
        {
            throw new ArgumentException("IPs must be 4 bytes");
        }
        UIntPtr size = Native.tcp_handle_size();
        UIntPtr align = Native.tcp_handle_align();
        if (size == UIntPtr.Zero)
        {
            throw new InvalidOperationException("tcp_handle_size returned 0");
        }
        // AllocHGlobal (HeapAlloc / malloc) guarantees MEMORY_ALLOCATION_ALIGNMENT,
        // which is 8 even on 32-bit Windows — enough for the TCB's u64 fields.
        if ((nuint)align > (nuint)Math.Max(IntPtr.Size, 8))
        {
            throw new InvalidOperationException(
                $"native handle requires alignment {align}, host provides {Math.Max(IntPtr.Size, 8)}");
        }
        _storage = Marshal.AllocHGlobal((IntPtr)(nint)(nuint)size);

        unsafe
        {
            fixed (byte* lp = localIp)
            fixed (byte* rp = remoteIp)
            {
                int rc = Native.tcp_init(
                    _storage,
                    (IntPtr)lp, localPort,
                    (IntPtr)rp, remotePort,
                    iss, initialRtoMs);
                if (rc != 0)
                {
                    Marshal.FreeHGlobal(_storage);
                    _storage = IntPtr.Zero;
                    throw new TcpException(rc);
                }
            }
        }
    }

    public void Connect(ulong nowMs) => Check(Native.tcp_connect(_storage, nowMs));

    public void Listen(ulong nowMs) => Check(Native.tcp_listen(_storage, nowMs));

    /// <summary>
    /// Install a 16-byte secret enabling stateless SYN cookies (RFC 4987).
    /// Once set, an inbound SYN in LISTEN is answered statelessly.
    /// </summary>
    public void SetCookieSecret(ReadOnlySpan<byte> secret)
    {
        if (secret.Length != 16)
            throw new ArgumentException("cookie secret must be exactly 16 bytes", nameof(secret));
        unsafe
        {
            fixed (byte* p = secret)
            {
                Check(Native.tcp_set_cookie_secret(_storage, (IntPtr)p));
            }
        }
    }

    public void Close(ulong nowMs) => Check(Native.tcp_close(_storage, nowMs));

    /// <summary>
    /// Immediate teardown: queues a RST+ACK in the egress ring, drops all
    /// buffered data, transitions to CLOSED. Drain <see cref="ExtractPacket"/>
    /// once afterwards so the RST reaches the wire, then Dispose.
    /// </summary>
    public void Abort(ulong nowMs) => Check(Native.tcp_abort(_storage, nowMs));

    /// <summary>
    /// Reconfigure / disable TCP keepalive (RFC 9293 §3.8.4). On by default
    /// (10 min idle / 60 s interval / 4 probes); idleMs == 0 disables.
    /// </summary>
    public void SetKeepalive(ulong nowMs, uint idleMs, uint intvlMs, byte count) =>
        Check(Native.tcp_set_keepalive(_storage, nowMs, idleMs, intvlMs, count));

    /// <summary>
    /// RFC 9293 §3.8.3 USER TIMEOUT: max time without forward progress while
    /// send data is outstanding before the connection aborts. On by default
    /// (5 min); 0 disables.
    /// </summary>
    public void SetUserTimeout(ulong nowMs, uint userTimeoutMs) =>
        Check(Native.tcp_set_user_timeout(_storage, nowMs, userTimeoutMs));

    public void Tick(ulong nowMs) => Check(Native.tcp_tick(_storage, nowMs));

    public TcpState State() => (TcpState)Native.tcp_state(_storage);

    public TcpEvents Poll() => (TcpEvents)Native.tcp_poll(_storage);

    /// <summary>
    /// Buffer bytes into the send ring (the next Tick / inject flushes them).
    /// Returns the count accepted — possibly less than the input when the
    /// ring is nearly full, and 0 on the stack's WouldBlock backpressure
    /// (ring completely full; retry after a later turn drains it). Throws
    /// only for genuine failures (e.g. InvalidState).
    /// </summary>
    public int Send(ReadOnlySpan<byte> data)
    {
        unsafe
        {
            fixed (byte* p = data)
            {
                UIntPtr written;
                int rc = Native.tcp_send(_storage, (IntPtr)p, (UIntPtr)data.Length, out written);
                if (rc == (int)TcpErrorCode.WouldBlock) return 0; // backpressure, not an error
                if (rc != 0) throw new TcpException(rc);
                return (int)(nuint)written;
            }
        }
    }

    /// <summary>
    /// Drain bytes from the receive ring. An empty array means either "no
    /// data available right now" or clean EOF (peer FIN consumed) — check
    /// Poll() for PeerClosed/Readable to distinguish. Throws TcpException
    /// with ConnectionReset if the connection was reset/aborted.
    /// </summary>
    public byte[] Recv(int max)
    {
        if (max <= 0) return Array.Empty<byte>();
        var buf = new byte[max];
        unsafe
        {
            fixed (byte* p = buf)
            {
                UIntPtr read;
                int rc = Native.tcp_recv(_storage, (IntPtr)p, (UIntPtr)max, out read);
                if (rc == (int)TcpErrorCode.ConnectionClosed) return Array.Empty<byte>(); // EOF
                if (rc != 0) throw new TcpException(rc);
                int n = (int)(nuint)read;
                if (n == max) return buf;
                var trimmed = new byte[n];
                Array.Copy(buf, trimmed, n);
                return trimmed;
            }
        }
    }

    /// <summary>
    /// Feed one inbound IPv4+TCP datagram. Returns true if accepted; false
    /// for the contract's benign drop-and-continue rejections (NotForUs /
    /// MalformedPacket / InvalidState — normal under a hostile or mis-routed
    /// wire). Throws only for genuinely unexpected codes. Drain
    /// <see cref="ExtractPacket"/> until null after every call.
    /// </summary>
    public bool InjectPacket(ReadOnlySpan<byte> packet, ulong nowMs)
    {
        unsafe
        {
            fixed (byte* p = packet)
            {
                int rc = Native.tcp_inject_packet(
                    _storage, (IntPtr)p, (UIntPtr)packet.Length, nowMs);
                if (rc == (int)TcpErrorCode.NotForUs
                    || rc == (int)TcpErrorCode.MalformedPacket
                    || rc == (int)TcpErrorCode.InvalidState)
                {
                    return false;
                }
                if (rc != 0) throw new TcpException(rc);
                return true;
            }
        }
    }

    /// <summary>
    /// Drain at most one outbound packet. Returns null if nothing is staged.
    /// </summary>
    public byte[]? ExtractPacket()
    {
        var buf = new byte[MaxPacket];
        unsafe
        {
            fixed (byte* p = buf)
            {
                UIntPtr written;
                int rc = Native.tcp_extract_packet(
                    _storage, (IntPtr)p, (UIntPtr)MaxPacket, out written);
                if (rc != 0) throw new TcpException(rc);
                int n = (int)(nuint)written;
                if (n == 0) return null;
                var pkt = new byte[n];
                Array.Copy(buf, pkt, n);
                return pkt;
            }
        }
    }

    public void Dispose()
    {
        if (_destroyed) return;
        _destroyed = true;
        if (_storage != IntPtr.Zero)
        {
            Native.tcp_destroy(_storage);
            Marshal.FreeHGlobal(_storage);
            _storage = IntPtr.Zero;
        }
    }

    private static void Check(int rc)
    {
        if (rc != 0) throw new TcpException(rc);
    }
}
