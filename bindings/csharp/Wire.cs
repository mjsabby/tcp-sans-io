// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Minimal IPv4 + TCP packet codec used by the integration test peer.
// Mirrors src/wire.rs and bindings/python/wire.py byte-for-byte.

using System.Buffers.Binary;

namespace TcpSansIo;

internal static class Flags
{
    public const byte FIN = 0x01;
    public const byte SYN = 0x02;
    public const byte RST = 0x04;
    public const byte PSH = 0x08;
    public const byte ACK = 0x10;
}

internal sealed class TcpOptions
{
    public ushort? Mss { get; set; }
    public (uint TsVal, uint TsEcr)? Ts { get; set; }

    public int EncodedLen()
    {
        if (Mss is null && Ts is null) return 0;
        if (Mss is not null && Ts is null) return 4;
        if (Mss is null && Ts is not null) return 12;
        return 16;
    }

    public byte[] Encode()
    {
        int len = EncodedLen();
        if (len == 0) return Array.Empty<byte>();
        var buf = new byte[len];
        int i = 0;
        if (Mss is { } mss)
        {
            buf[i++] = 2; // kind = MSS
            buf[i++] = 4; // length
            BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(i, 2), mss);
            i += 2;
        }
        if (Ts is { } ts)
        {
            if (Mss is null)
            {
                buf[i++] = 1; buf[i++] = 1; // NOP NOP
            }
            buf[i++] = 8;  // kind = Timestamps
            buf[i++] = 10; // length
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(i, 4), ts.TsVal);
            i += 4;
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(i, 4), ts.TsEcr);
            i += 4;
            if (Mss is not null)
            {
                buf[i++] = 1; buf[i++] = 1; // trailing NOPs to align
            }
        }
        if (i != len)
        {
            throw new InvalidOperationException("option length mismatch");
        }
        return buf;
    }

    public static TcpOptions Parse(ReadOnlySpan<byte> bytes)
    {
        var o = new TcpOptions();
        int i = 0;
        while (i < bytes.Length)
        {
            byte kind = bytes[i];
            if (kind == 0) break;
            if (kind == 1) { i += 1; continue; }
            if (i + 1 >= bytes.Length)
            {
                throw new ArgumentException("truncated TCP option");
            }
            byte length = bytes[i + 1];
            if (length < 2 || i + length > bytes.Length)
            {
                throw new ArgumentException("bad TCP option length");
            }
            if (kind == 2 && length == 4)
            {
                o.Mss = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(i + 2, 2));
            }
            else if (kind == 8 && length == 10)
            {
                uint tsval = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(i + 2, 4));
                uint tsecr = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(i + 6, 4));
                o.Ts = (tsval, tsecr);
            }
            i += length;
        }
        return o;
    }
}

internal sealed class Segment
{
    public required byte[] SrcIp { get; init; }
    public required byte[] DstIp { get; init; }
    public required ushort SrcPort { get; init; }
    public required ushort DstPort { get; init; }
    public required uint Seq { get; init; }
    public required uint Ack { get; init; }
    public required byte Flags { get; init; }
    public required ushort Window { get; init; }
    public required TcpOptions Options { get; init; }
    public required byte[] Payload { get; init; }

    public bool Has(byte f) => (Flags & f) == f;
}

internal static class Wire
{
    public const byte IpProtoTcp = 6;
    public const int Ipv4HdrLen = 20;
    public const int TcpHdrLen = 20;

    private static ushort OnesComplement(ReadOnlySpan<byte> data, uint seed = 0)
    {
        uint s = seed;
        int n = data.Length;
        int i = 0;
        while (i + 1 < n)
        {
            s += (uint)((data[i] << 8) | data[i + 1]);
            i += 2;
        }
        if (i < n)
        {
            s += (uint)(data[i] << 8);
        }
        while ((s >> 16) != 0)
        {
            s = (s & 0xFFFF) + (s >> 16);
        }
        return (ushort)(~s & 0xFFFF);
    }

    private static ushort TcpChecksum(
        ReadOnlySpan<byte> srcIp,
        ReadOnlySpan<byte> dstIp,
        ReadOnlySpan<byte> tcpSegment)
    {
        uint pseudo = 0;
        pseudo += (uint)((srcIp[0] << 8) | srcIp[1]);
        pseudo += (uint)((srcIp[2] << 8) | srcIp[3]);
        pseudo += (uint)((dstIp[0] << 8) | dstIp[1]);
        pseudo += (uint)((dstIp[2] << 8) | dstIp[3]);
        pseudo += IpProtoTcp;
        pseudo += (uint)(tcpSegment.Length & 0xFFFF);
        return OnesComplement(tcpSegment, pseudo);
    }

    public static byte[] Emit(
        byte[] srcIp,
        byte[] dstIp,
        ushort srcPort,
        ushort dstPort,
        uint seq,
        uint ack,
        byte flags,
        ushort window,
        TcpOptions options,
        byte[]? payload,
        ushort ipId)
    {
        if (srcIp.Length != 4 || dstIp.Length != 4)
        {
            throw new ArgumentException("IPs must be 4 bytes");
        }
        payload ??= Array.Empty<byte>();
        byte[] optBytes = options.Encode();
        if (optBytes.Length % 4 != 0)
        {
            throw new ArgumentException("options must be 4-byte aligned");
        }
        int tcpHdrLen = TcpHdrLen + optBytes.Length;
        int total = Ipv4HdrLen + tcpHdrLen + payload.Length;
        if (total > 0xFFFF)
        {
            throw new ArgumentException("packet too large for IPv4");
        }

        var ip = new byte[Ipv4HdrLen];
        ip[0] = 0x45;
        ip[1] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2, 2), (ushort)total);
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(4, 2), ipId);
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(6, 2), 0x4000); // DF
        ip[8] = 64;
        ip[9] = IpProtoTcp;
        // checksum field stays zero before computation
        Array.Copy(srcIp, 0, ip, 12, 4);
        Array.Copy(dstIp, 0, ip, 16, 4);
        ushort ipCsum = OnesComplement(ip);
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(10, 2), ipCsum);

        var tcp = new byte[tcpHdrLen + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0, 2), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2, 2), dstPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(4, 4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(8, 4), ack);
        tcp[12] = (byte)((tcpHdrLen / 4) << 4);
        tcp[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(14, 2), window);
        // checksum (16..18) and urgent (18..20) start zero
        if (optBytes.Length > 0)
        {
            Array.Copy(optBytes, 0, tcp, TcpHdrLen, optBytes.Length);
        }
        if (payload.Length > 0)
        {
            Array.Copy(payload, 0, tcp, tcpHdrLen, payload.Length);
        }
        ushort csum = TcpChecksum(srcIp, dstIp, tcp);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(16, 2), csum);

        var pkt = new byte[ip.Length + tcp.Length];
        Array.Copy(ip, 0, pkt, 0, ip.Length);
        Array.Copy(tcp, 0, pkt, ip.Length, tcp.Length);
        return pkt;
    }

    public static Segment Parse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < Ipv4HdrLen + TcpHdrLen)
        {
            throw new ArgumentException("packet too short");
        }
        if ((packet[0] >> 4) != 4)
        {
            throw new ArgumentException("not IPv4");
        }
        int ihl = (packet[0] & 0x0F) * 4;
        if (ihl < Ipv4HdrLen)
        {
            throw new ArgumentException("bad IHL");
        }
        int totalLen = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        if (totalLen > packet.Length || totalLen < ihl + TcpHdrLen)
        {
            throw new ArgumentException("bad total length");
        }
        ushort flagsFrag = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
        if ((flagsFrag & 0x2000) != 0 || (flagsFrag & 0x1FFF) != 0)
        {
            throw new ArgumentException("fragmented packet");
        }
        if (packet[9] != IpProtoTcp)
        {
            throw new ArgumentException("not TCP");
        }
        if (OnesComplement(packet.Slice(0, ihl)) != 0)
        {
            throw new ArgumentException("bad IPv4 checksum");
        }

        var srcIp = packet.Slice(12, 4).ToArray();
        var dstIp = packet.Slice(16, 4).ToArray();

        var tcp = packet.Slice(ihl, totalLen - ihl);
        if (tcp.Length < TcpHdrLen)
        {
            throw new ArgumentException("TCP too short");
        }
        ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(tcp.Slice(0, 2));
        ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(tcp.Slice(2, 2));
        uint seq = BinaryPrimitives.ReadUInt32BigEndian(tcp.Slice(4, 4));
        uint ack = BinaryPrimitives.ReadUInt32BigEndian(tcp.Slice(8, 4));
        int dataOff = (tcp[12] >> 4) * 4;
        if (dataOff < TcpHdrLen || dataOff > tcp.Length)
        {
            throw new ArgumentException("bad data offset");
        }
        byte flags = tcp[13];
        ushort window = BinaryPrimitives.ReadUInt16BigEndian(tcp.Slice(14, 2));
        if (TcpChecksum(srcIp, dstIp, tcp) != 0)
        {
            throw new ArgumentException("bad TCP checksum");
        }

        var options = TcpOptions.Parse(tcp.Slice(TcpHdrLen, dataOff - TcpHdrLen));
        var payload = tcp.Slice(dataOff).ToArray();

        return new Segment
        {
            SrcIp = srcIp,
            DstIp = dstIp,
            SrcPort = srcPort,
            DstPort = dstPort,
            Seq = seq,
            Ack = ack,
            Flags = flags,
            Window = window,
            Options = options,
            Payload = payload,
        };
    }
}
