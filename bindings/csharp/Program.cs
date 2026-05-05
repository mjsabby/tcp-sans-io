// SPDX-License-Identifier: MIT OR Apache-2.0
//
// End-to-end integration test for the tcp-sans-io cdylib via P/Invoke.
//
// The cdylib is the *client*. A pure-managed TestPeer plays the server by
// hand-crafting IPv4+TCP packets through Wire.cs (with full checksums) and
// feeding them to tcp_inject_packet. No sockets, no privileges.

using System.Runtime.InteropServices;
using System.Text;
using TcpSansIo;

internal static class Program
{
    private static readonly byte[] ClientIp = { 10, 0, 0, 1 };
    private static readonly byte[] ServerIp = { 10, 0, 0, 2 };
    private const ushort ClientPort = 49152;
    private const ushort ServerPort = 80;
    private const uint ServerIss = 0x9000_0000;
    private const uint ClientIss = 0x1000_0000;

    private static int _failed;

    public static int Main()
    {
        PreloadNativeLibrary();

        Run("abi_version", TestAbiVersion);
        Run("handshake", TestHandshake);
        Run("request_response", TestRequestResponse);
        Run("active_close", TestActiveClose);
        Run("rst_aborts", TestRstAborts);

        Console.WriteLine();
        Console.WriteLine(_failed == 0
            ? "all tests passed"
            : $"{_failed} test(s) failed");
        return _failed == 0 ? 0 : 1;
    }

    // ---- Test runner -------------------------------------------------------

    private static void Run(string name, Action body)
    {
        try
        {
            body();
            Console.WriteLine($"  OK   {name}");
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine($"  FAIL {name}: {ex.GetType().Name}: {ex.Message}");
            if (ex.StackTrace is not null)
            {
                Console.WriteLine(ex.StackTrace);
            }
        }
    }

    private static void Assert(bool cond, string msg)
    {
        if (!cond) throw new InvalidOperationException("assertion failed: " + msg);
    }

    private static void AssertEqual<T>(T expected, T actual, string msg)
    {
        if (!Equals(expected, actual))
        {
            throw new InvalidOperationException(
                $"assertion failed: {msg} (expected {expected}, got {actual})");
        }
    }

    // ---- DLL pre-load ------------------------------------------------------

    private static void PreloadNativeLibrary()
    {
        // Resolve the cdylib relative to the assembly location. We expect the
        // standard cargo layout: <repo>/target/{release,debug}/<name>.{dll,so,dylib}.
        string baseDir = AppContext.BaseDirectory;
        string repoRoot = FindRepoRoot(baseDir);

        string fileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "tcp_sans_io.dll"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? "libtcp_sans_io.dylib"
                : "libtcp_sans_io.so";

        string[] candidates =
        {
            Path.Combine(repoRoot, "target", "release", fileName),
            Path.Combine(repoRoot, "target", "debug", fileName),
        };

        foreach (var path in candidates)
        {
            if (File.Exists(path))
            {
                NativeLibrary.SetDllImportResolver(
                    typeof(Native).Assembly,
                    (name, asm, search) =>
                        name == Native.LibName ? NativeLibrary.Load(path) : IntPtr.Zero);
                Console.WriteLine($"loaded {path}");
                return;
            }
        }

        throw new FileNotFoundException(
            $"could not find {fileName} under {repoRoot}/target/{{release,debug}}/. " +
            "Run `cargo build --release` first.");
    }

    private static string FindRepoRoot(string start)
    {
        // Walk up until we see a Cargo.toml — that's the repo root.
        var dir = new DirectoryInfo(start);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cargo.toml")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        throw new InvalidOperationException(
            $"could not find Cargo.toml above {start}");
    }

    // ---- Tests -------------------------------------------------------------

    private static void TestAbiVersion()
    {
        AssertEqual(1u, Native.tcp_abi_version(), "abi version");
    }

    private static void TestHandshake()
    {
        using var client = MakeClient();
        var peer = new TestPeer();
        ulong now = 1000;

        client.Connect(now);
        var pkts = Drain(client, now);
        AssertEqual(1, pkts.Count, "expected one SYN");

        now += 5;
        peer.NowMs = now;
        var replies = peer.Handle(pkts[0]);
        AssertEqual(1, replies.Count, "expected SYN-ACK");

        now += 5;
        client.InjectPacket(replies[0], now);
        pkts = Drain(client, now);
        AssertEqual(1, pkts.Count, "expected ACK after SYN-ACK");
        peer.Handle(pkts[0]);

        AssertEqual(TcpState.Established, client.State(), "ESTABLISHED");
        Assert(peer.TsEnabled, "peer should see Timestamps option");
        AssertEqual((ushort)1460, peer.PeerMss, "peer MSS");
    }

    private static void TestRequestResponse()
    {
        using var client = MakeClient();
        var peer = new TestPeer();
        ulong now = 1000;

        Handshake(client, peer, ref now);
        now += 50;

        var req = Encoding.ASCII.GetBytes(
            "GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n");
        AssertEqual(req.Length, client.Send(req), "client send");
        now += 1;
        var pkts = Drain(client, now);
        AssertEqual(1, pkts.Count, "request packet");
        now += 1;
        peer.NowMs = now;
        var replies = peer.Handle(pkts[0]);
        AssertEqual(1, replies.Count, "ack reply");
        AssertEqual(req.Length, peer.Received.Count, "received len");
        for (int i = 0; i < req.Length; i++)
        {
            if (req[i] != peer.Received[i])
            {
                throw new InvalidOperationException("payload mismatch");
            }
        }

        now += 1;
        client.InjectPacket(replies[0], now);

        var resp = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world");
        now += 5;
        peer.NowMs = now;
        var data = peer.SendData(resp);
        now += 1;
        client.InjectPacket(data, now);
        var got = client.Recv(4096);
        AssertEqual(resp.Length, got.Length, "recv len");
        for (int i = 0; i < resp.Length; i++)
        {
            if (resp[i] != got[i])
            {
                throw new InvalidOperationException("response mismatch");
            }
        }
    }

    private static void TestActiveClose()
    {
        using var client = MakeClient();
        var peer = new TestPeer();
        ulong now = 1000;

        Handshake(client, peer, ref now);
        now += 50;

        client.Close(now);
        var pkts = Drain(client, now);
        AssertEqual(1, pkts.Count, "FIN packet");
        AssertEqual(TcpState.FinWait1, client.State(), "FIN_WAIT_1");

        now += 5;
        peer.NowMs = now;
        var acks = peer.Handle(pkts[0]);
        AssertEqual(1, acks.Count, "peer ACKs FIN");
        now += 1;
        client.InjectPacket(acks[0], now);
        AssertEqual(TcpState.FinWait2, client.State(), "FIN_WAIT_2");

        now += 5;
        peer.NowMs = now;
        var peerFin = peer.Close();
        now += 1;
        client.InjectPacket(peerFin, now);
        AssertEqual(TcpState.TimeWait, client.State(), "TIME_WAIT");

        pkts = Drain(client, now);
        AssertEqual(1, pkts.Count, "final ACK");
        peer.Handle(pkts[0]);
        Assert(peer.IsFullyClosed, "peer fully closed");

        // 2*MSL → CLOSED
        now += 60_001;
        client.Tick(now);
        AssertEqual(TcpState.Closed, client.State(), "CLOSED after TIME_WAIT");
    }

    private static void TestRstAborts()
    {
        using var client = MakeClient();
        var peer = new TestPeer();
        ulong now = 1000;

        Handshake(client, peer, ref now);
        now += 5;
        peer.NowMs = now;

        var rst = peer.EmitRaw(Flags.RST | Flags.ACK, peer.SndNxt, peer.RcvNxt);
        client.InjectPacket(rst, now);

        AssertEqual(TcpState.Closed, client.State(), "CLOSED after RST");
        Assert((client.Poll() & TcpEvents.Error) != 0, "error event flagged");
        try
        {
            client.Recv(16);
            throw new InvalidOperationException("recv after RST should fail");
        }
        catch (TcpException ex)
        {
            AssertEqual(TcpErrorCode.ConnectionReset, ex.Code, "reset code");
        }
    }

    // ---- Helpers -----------------------------------------------------------

    private static TcpStream MakeClient() => new TcpStream(
        ClientIp, ClientPort, ServerIp, ServerPort, ClientIss, 1000);

    private static List<byte[]> Drain(TcpStream client, ulong now)
    {
        var packets = new List<byte[]>();
        while (true)
        {
            client.Tick(now);
            var pkt = client.ExtractPacket();
            if (pkt is null) break;
            packets.Add(pkt);
        }
        return packets;
    }

    private static void Handshake(TcpStream client, TestPeer peer, ref ulong now)
    {
        client.Connect(now);
        var pkts = Drain(client, now);
        AssertEqual(1, pkts.Count, "SYN");
        peer.NowMs = now + 5;
        var replies = peer.Handle(pkts[0]);
        AssertEqual(1, replies.Count, "SYN-ACK");
        client.InjectPacket(replies[0], now + 10);
        pkts = Drain(client, now + 10);
        AssertEqual(1, pkts.Count, "final ACK");
        peer.Handle(pkts[0]);
        AssertEqual(TcpState.Established, client.State(), "established");
        now += 10;
    }
}

// ---- TestPeer --------------------------------------------------------------

internal sealed class TestPeer
{
    public uint SndNxt = 0x9000_0000;
    public uint SndUna = 0x9000_0000;
    public uint RcvNxt;
    public ushort PeerMss = 536;
    public bool TsEnabled;
    public uint TsRecent;
    public ushort AdvertisedWindow = 65_535;
    public List<byte> Received = new();

    public bool HandshakeDone;
    public bool OurFinSent;
    public uint OurFinSeq;
    public bool OurFinAcked;
    public bool TheirFinReceived;

    public ushort IpId;
    public ulong NowMs;

    private static readonly byte[] ServerIp = { 10, 0, 0, 2 };
    private static readonly byte[] ClientIp = { 10, 0, 0, 1 };
    private const ushort ServerPort = 80;
    private const ushort ClientPort = 49152;

    private TcpOptions BuildOpts()
    {
        var o = new TcpOptions();
        if (TsEnabled)
        {
            o.Ts = ((uint)(NowMs & 0xFFFF_FFFF), TsRecent);
        }
        return o;
    }

    private byte[] EmitInternal(byte flags, uint seq, uint ack, TcpOptions opts, byte[]? payload = null)
    {
        var pkt = Wire.Emit(
            ServerIp, ClientIp, ServerPort, ClientPort,
            seq, ack, flags, AdvertisedWindow, opts, payload, IpId);
        IpId = (ushort)((IpId + 1) & 0xFFFF);
        return pkt;
    }

    /// <summary>For tests that need to inject specific packets (RST, etc.).</summary>
    public byte[] EmitRaw(byte flags, uint seq, uint ack)
        => EmitInternal(flags, seq, ack, BuildOpts());

    public List<byte[]> Handle(byte[] packet)
    {
        Segment seg;
        try { seg = Wire.Parse(packet); }
        catch (ArgumentException) { return new List<byte[]>(); }

        if (seg.Options.Ts is { } ts)
        {
            TsRecent = ts.TsVal;
        }

        var outPackets = new List<byte[]>();

        if (!HandshakeDone)
        {
            if (seg.Has(Flags.SYN) && !seg.Has(Flags.ACK))
            {
                if (seg.Options.Mss is { } mss) PeerMss = mss;
                if (seg.Options.Ts is not null) TsEnabled = true;
                RcvNxt = (seg.Seq + 1);
                SndUna = SndNxt;
                var opts = new TcpOptions
                {
                    Mss = 1460,
                    Ts = TsEnabled ? ((uint)(NowMs & 0xFFFF_FFFF), TsRecent) : null,
                };
                outPackets.Add(EmitInternal(
                    (byte)(Flags.SYN | Flags.ACK), SndNxt, RcvNxt, opts));
                SndNxt = SndNxt + 1;
                HandshakeDone = true;
            }
            return outPackets;
        }

        if (OurFinSent && OurFinAcked && TheirFinReceived)
        {
            return outPackets;
        }

        if (seg.Has(Flags.ACK))
        {
            uint ack = seg.Ack;
            if (!SeqGt(ack, SndNxt) && SeqGe(ack, SndUna))
            {
                SndUna = ack;
            }
            if (OurFinSent && !OurFinAcked && SeqGt(SndUna, OurFinSeq))
            {
                OurFinAcked = true;
            }
        }

        if (seg.Payload.Length > 0 && !TheirFinReceived)
        {
            if (seg.Seq == RcvNxt)
            {
                Received.AddRange(seg.Payload);
                RcvNxt = (uint)(RcvNxt + (uint)seg.Payload.Length);
                outPackets.Add(EmitInternal(Flags.ACK, SndNxt, RcvNxt, BuildOpts()));
            }
            else
            {
                outPackets.Add(EmitInternal(Flags.ACK, SndNxt, RcvNxt, BuildOpts()));
            }
        }

        if (seg.Has(Flags.FIN) && !TheirFinReceived)
        {
            uint finSeq = (uint)(seg.Seq + (uint)seg.Payload.Length);
            if (finSeq == RcvNxt)
            {
                RcvNxt = RcvNxt + 1;
                TheirFinReceived = true;
                outPackets.Add(EmitInternal(Flags.ACK, SndNxt, RcvNxt, BuildOpts()));
            }
        }

        return outPackets;
    }

    public byte[] SendData(byte[] data)
    {
        uint seq = SndNxt;
        var pkt = EmitInternal(
            (byte)(Flags.ACK | Flags.PSH), seq, RcvNxt, BuildOpts(), data);
        SndNxt = (uint)(SndNxt + (uint)data.Length);
        return pkt;
    }

    public byte[] Close()
    {
        OurFinSeq = SndNxt;
        OurFinSent = true;
        var pkt = EmitInternal(
            (byte)(Flags.FIN | Flags.ACK), SndNxt, RcvNxt, BuildOpts());
        SndNxt = SndNxt + 1;
        return pkt;
    }

    public bool IsFullyClosed => OurFinSent && OurFinAcked && TheirFinReceived;

    private static bool SeqGt(uint a, uint b)
    {
        uint d = a - b;
        return d != 0 && d < 0x8000_0000u;
    }

    private static bool SeqGe(uint a, uint b)
    {
        uint d = a - b;
        return d == 0 || d < 0x8000_0000u;
    }
}
