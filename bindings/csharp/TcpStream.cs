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
    private const int MaxPacket = 1500;

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
        // AllocHGlobal returns memory aligned at least to the platform pointer
        // size (8 on x64). Our handle's alignment requirement comes from u64
        // fields inside the TCB, so 8-byte alignment is sufficient.
        if ((nuint)align > (nuint)IntPtr.Size)
        {
            throw new InvalidOperationException(
                $"native handle requires alignment {align}, host provides {IntPtr.Size}");
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

    public void Tick(ulong nowMs) => Check(Native.tcp_tick(_storage, nowMs));

    public TcpState State() => (TcpState)Native.tcp_state(_storage);

    public TcpEvents Poll() => (TcpEvents)Native.tcp_poll(_storage);

    public int Send(ReadOnlySpan<byte> data)
    {
        unsafe
        {
            fixed (byte* p = data)
            {
                UIntPtr written;
                int rc = Native.tcp_send(_storage, (IntPtr)p, (UIntPtr)data.Length, out written);
                if (rc != 0) throw new TcpException(rc);
                return (int)(nuint)written;
            }
        }
    }

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
                if (rc != 0) throw new TcpException(rc);
                int n = (int)(nuint)read;
                if (n == max) return buf;
                var trimmed = new byte[n];
                Array.Copy(buf, trimmed, n);
                return trimmed;
            }
        }
    }

    public void InjectPacket(ReadOnlySpan<byte> packet, ulong nowMs)
    {
        unsafe
        {
            fixed (byte* p = packet)
            {
                int rc = Native.tcp_inject_packet(
                    _storage, (IntPtr)p, (UIntPtr)packet.Length, nowMs);
                if (rc != 0) throw new TcpException(rc);
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
