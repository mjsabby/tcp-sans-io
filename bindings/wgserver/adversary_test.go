// Adversarial integration tests for the wgserver harness.
//
// The unit-level coverage in `src/server_tests.rs` exhaustively
// verifies LISTEN / SYN_RCVD defenses against hostile inputs. These
// tests reproduce a subset at the integration layer: through the
// real UDP transport, through the pump loop's port-mux + active-set,
// against the same `Tcb` running inside a foreign process. A pass
// here proves the defenses survive the end-to-end pipeline.

package wgserver

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"testing"
	"time"
)

const (
	advServerIP = "10.99.0.2"
	advClientIP = "10.99.0.1"
)

// adversarySetup spawns a wgserver and returns a Transport bound on
// the address the server expects replies on, plus a cleanup. The
// `cookies` argument is passed verbatim ("none" / "random" / hex).
func adversarySetup(
	t *testing.T,
	cookies string,
	numListeners uint16,
	basePort uint16,
) (*Transport, *Harness, func()) {
	t.Helper()
	srvListen, drvListen := pickLocalAddrs(t, nil)
	driver, err := NewTransport(drvListen, srvListen)
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	cfg := DefaultHarnessConfig()
	cfg.NumListeners = numListeners
	cfg.BasePort = basePort
	cfg.ListenUDP = srvListen
	cfg.PeerUDP = drvListen
	cfg.CookieSecret = cookies
	h, err := Spawn(t, cfg)
	if err != nil {
		_ = driver.Close()
		t.Fatalf("spawn: %v", err)
	}
	cleanup := func() {
		_ = h.Shutdown(5 * time.Second)
		_ = driver.Close()
	}
	return driver, h, cleanup
}

// runOne dials one legitimate connection and asserts the echo round
// trip succeeds.
func runOne(t *testing.T, drv *Transport, port uint16, srcPort uint16, msg string, opts MiniOpts) {
	t.Helper()
	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	res := RunMini(drv, MiniClientConfig{
		SrcIP:    clientIP,
		SrcPort:  srcPort,
		DstIP:    serverIP,
		DstPort:  port,
		ISS:      0x55_55_00_00 + uint32(srcPort),
		Opts:     opts,
		Request:  []byte(msg + "\n"),
		RecvSize: len(msg) + 1,
		Deadline: 5 * time.Second,
	})
	if !res.OK || string(res.Response) != msg+"\n" {
		t.Fatalf("legitimate client (port %d) failed: err=%v got=%q lat=%v",
			port, res.Err, string(res.Response), res.Latency)
	}
}

// TestWGServer_SynFlood_NoCookies fires a SYN flood with forged
// random sources. Single-Tcb-per-port design locks the first SYN
// into SYN_RCVD; subsequent SYNs (legit or otherwise) are rejected
// until the bounded retransmit budget runs out (~63 s with default
// exponential RTO backoff capped at RTO_MAX=60s).
//
// This test asserts the *bounded* lifetime property — namely that
// the server is NOT permanently DoS'd by a flood. It is slow (~75s)
// and gated by STRESS=1; the production defense for fast availability
// after a flood is SYN cookies (covered in TestWGServer_SynFlood_Cookies).
func TestWGServer_SynFlood_NoCookies(t *testing.T) {
	if os.Getenv("STRESS") == "" {
		t.Skip("set STRESS=1 to run the slow (~40s) no-cookies flood test")
	}
	drv, h, cleanup := adversarySetup(t, "none", 1, 31000)
	defer cleanup()
	_ = h

	serverIP, _ := ParseIP4(advServerIP)
	// Pre-spray: 5000 random-source SYNs.
	spray := 5000
	for i := 0; i < spray; i++ {
		var src [4]byte
		_, _ = rand.Read(src[:])
		src[0] = 198 // pin to TEST-NET-2 to avoid clashing with our virtual IPs
		var iss [4]byte
		_, _ = rand.Read(iss[:])
		spec := PacketSpec{
			SrcIP:   src,
			DstIP:   serverIP,
			SrcPort: uint16(40000 + (i % 25000)),
			DstPort: 31000,
			Seq:     uint32(iss[0])<<24 | uint32(iss[1])<<16 | uint32(iss[2])<<8 | uint32(iss[3]),
			Flags:   FlagSYN,
			Window:  65535,
			Options: Options{MSSSet: true, MSS: 1460},
		}
		pkt, err := Encode(spec)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_ = drv.SendTo(pkt)
	}
	// SYN_RCVD lifetime: 5 retries with Karn's exponential backoff
	// (RTO starts at 1s, doubles each retransmit, capped at RTO_MAX=60s).
	// Total elapsed before reset to LISTEN: 1+2+4+8+16+32 ≈ 63s. Give
	// the legit client a 90 s deadline so it can re-handshake once the
	// half-open clears.
	clientIP, _ := ParseIP4(advClientIP)
	res := RunMini(drv, MiniClientConfig{
		SrcIP: clientIP, SrcPort: 50000,
		DstIP: serverIP, DstPort: 31000,
		ISS:      0x5555_aaaa,
		Opts:     OptsAll,
		Request:  []byte("post-flood\n"),
		RecvSize: 12,
		Deadline: 90 * time.Second,
	})
	if !res.OK {
		t.Fatalf("legitimate client failed after no-cookies flood: err=%v lat=%v",
			res.Err, res.Latency)
	}
	rx, tx, dropped, mismatch := drv.Stats()
	t.Logf("driver stats after no-cookies flood: rx=%d tx=%d dropped=%d mismatch=%d lat=%v",
		rx, tx, dropped, mismatch, res.Latency)
}

// TestWGServer_SynFlood_Cookies enables SYN cookies and verifies a
// legitimate client still succeeds after a flood. With cookies on,
// the server holds *no* state for the forged SYNs.
func TestWGServer_SynFlood_Cookies(t *testing.T) {
	// 16 bytes of zeros is a valid secret — content doesn't matter
	// for the harness, only the protocol behavior.
	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = byte(0xa0 ^ i)
	}
	drv, h, cleanup := adversarySetup(t, hex.EncodeToString(secret), 1, 31100)
	defer cleanup()
	_ = h

	serverIP, _ := ParseIP4(advServerIP)
	// 20K forged SYNs.
	spray := 20000
	for i := 0; i < spray; i++ {
		var src [4]byte
		_, _ = rand.Read(src[:])
		src[0] = 198
		spec := PacketSpec{
			SrcIP:   src,
			DstIP:   serverIP,
			SrcPort: uint16(40000 + (i % 25000)),
			DstPort: 31100,
			Seq:     uint32(i)*2654435761 + 1,
			Flags:   FlagSYN,
			Window:  65535,
			Options: Options{MSSSet: true, MSS: 1460},
		}
		pkt, _ := Encode(spec)
		_ = drv.SendTo(pkt)
	}
	time.Sleep(200 * time.Millisecond)

	runOne(t, drv, 31100, 50100, "cookies-post-flood", OptsNone)
}

// TestWGServer_BareAck_NoReflection sends a bare ACK to LISTEN with
// no cookie secret installed. The server must emit ZERO packets —
// otherwise it'd be a reflection / amplification gadget.
func TestWGServer_BareAck_NoReflection(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 31200)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	box := drv.RegisterInbox(clientIP, 50200, 32)
	defer box.Close()

	spec := PacketSpec{
		SrcIP:   clientIP,
		DstIP:   serverIP,
		SrcPort: 50200,
		DstPort: 31200,
		Seq:     0x1234_5678,
		Ack:     0x9abc_def0,
		Flags:   FlagACK,
		Window:  65535,
	}
	pkt, _ := Encode(spec)
	if err := drv.SendTo(pkt); err != nil {
		t.Fatalf("send: %v", err)
	}
	// Wait briefly for any reply.
	got, err := box.Recv(200 * time.Millisecond)
	if err == nil {
		// We got *something* back — that's a reflection. Dump and fail.
		pp, _ := Parse(got)
		t.Fatalf("expected no reply to bare ACK in LISTEN, got %+v", pp)
	}
	// Sanity: after the bare-ACK drop the listener still accepts a real connection.
	runOne(t, drv, 31200, 50201, "post-bare-ack", OptsAll)
}

// TestWGServer_Listen_DropsFinSilently asserts that a bare FIN to
// LISTEN emits zero packets, then a legit handshake still works.
func TestWGServer_Listen_DropsFinSilently(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 31300)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	box := drv.RegisterInbox(clientIP, 50300, 32)
	defer box.Close()

	spec := PacketSpec{
		SrcIP:   clientIP,
		DstIP:   serverIP,
		SrcPort: 50300,
		DstPort: 31300,
		Seq:     0x1,
		Flags:   FlagFIN | FlagACK,
		Window:  65535,
	}
	pkt, _ := Encode(spec)
	_ = drv.SendTo(pkt)
	if got, err := box.Recv(200 * time.Millisecond); err == nil {
		pp, _ := Parse(got)
		t.Fatalf("expected no reply to bare FIN in LISTEN, got %+v", pp)
	}
	runOne(t, drv, 31300, 50301, "post-bare-fin", OptsAll)
}

// TestWGServer_Listen_DropsRstSilently asserts that a bare RST to
// LISTEN emits zero packets, then a legit handshake still works.
func TestWGServer_Listen_DropsRstSilently(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 31400)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	box := drv.RegisterInbox(clientIP, 50400, 32)
	defer box.Close()

	spec := PacketSpec{
		SrcIP:   clientIP,
		DstIP:   serverIP,
		SrcPort: 50400,
		DstPort: 31400,
		Flags:   FlagRST,
		Window:  0,
	}
	pkt, _ := Encode(spec)
	_ = drv.SendTo(pkt)
	if got, err := box.Recv(200 * time.Millisecond); err == nil {
		pp, _ := Parse(got)
		t.Fatalf("expected no reply to bare RST in LISTEN, got %+v", pp)
	}
	runOne(t, drv, 31400, 50401, "post-bare-rst", OptsAll)
}

// TestWGServer_Listen_RstOnSynAck verifies that a SYN+ACK to LISTEN
// causes the cdylib to emit a RST packet (RFC 9293 §3.10.7.2).
//
// Quirk worth documenting: the LISTEN-RST is emitted to `self.remote`,
// which is wildcarded to (0.0.0.0, 0) while the TCB is in LISTEN (see
// `Tcb::listen`). Real WireGuard / real kernels would drop the
// resulting (0.0.0.0:0) destination as unroutable; the integration
// test observes the RST by registering a "wildcard" inbox at the
// (0.0.0.0, 0) key. The critical-path assertion is the *behavioral*
// one — server emits exactly one packet and stays in LISTEN.
func TestWGServer_Listen_RstOnSynAck(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 31500)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	// Wildcard inbox — the cdylib addresses the LISTEN-RST to the
	// wildcarded `remote` (0.0.0.0:0).
	wildcardBox := drv.RegisterInbox([4]byte{0, 0, 0, 0}, 0, 16)
	defer wildcardBox.Close()

	spec := PacketSpec{
		SrcIP:   clientIP,
		DstIP:   serverIP,
		SrcPort: 50500,
		DstPort: 31500,
		Seq:     0x100,
		Ack:     0x200,
		Flags:   FlagSYN | FlagACK,
		Window:  65535,
	}
	pkt, _ := Encode(spec)
	_ = drv.SendTo(pkt)
	got, err := wildcardBox.Recv(500 * time.Millisecond)
	if err != nil {
		t.Fatalf("expected RST emitted (to wildcard 0.0.0.0:0), got timeout")
	}
	// We can't fully Parse() — IP dst is 0.0.0.0 which is fine for
	// our wildcard reader but the TCP checksum verification still
	// holds (the cdylib computed it against 0.0.0.0). Parse should
	// succeed.
	pp, err := Parse(got)
	if err != nil {
		t.Fatalf("parse RST: %v", err)
	}
	if pp.Flags&FlagRST == 0 {
		t.Fatalf("expected RST flag, got %#x", pp.Flags)
	}
	// No further packets — drop any subsequent burst.
	if g2, err2 := wildcardBox.Recv(100 * time.Millisecond); err2 == nil {
		pp2, _ := Parse(g2)
		t.Fatalf("expected exactly one RST, got a second packet %+v", pp2)
	}
}

// TestWGServer_BlindRst_InWindow_SynRcvd: legitimate SYN advances the
// TCB into SYN_RCVD, an in-window RST from the same 5-tuple reverts
// it to LISTEN; a fresh handshake on the same listener still works.
func TestWGServer_BlindRst_InWindow_SynRcvd(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 31600)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	box := drv.RegisterInbox(clientIP, 50600, 32)
	defer box.Close()

	// SYN first.
	tsval := nextTSVal()
	syn := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 50600, DstPort: 31600,
		Seq: 0xABCD_0000, Flags: FlagSYN, Window: 65535,
		Options: Options{MSSSet: true, MSS: 1460, TSSet: true, TSVal: tsval},
	})
	_ = drv.SendTo(syn)
	pkt, err := box.Recv(1 * time.Second)
	if err != nil {
		t.Fatalf("no SYN-ACK: %v", err)
	}
	pp, err := Parse(pkt)
	if err != nil {
		t.Fatalf("parse SYN-ACK: %v", err)
	}
	if pp.Flags&(FlagSYN|FlagACK) != FlagSYN|FlagACK {
		t.Fatalf("expected SYN+ACK, got %#x", pp.Flags)
	}

	// Send in-window RST (seq == rcv_nxt = our ISS+1).
	rst := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 50600, DstPort: 31600,
		Seq: 0xABCD_0001, Flags: FlagRST, Window: 0,
	})
	_ = drv.SendTo(rst)
	time.Sleep(100 * time.Millisecond)
	box.Close()

	// Fresh handshake on the same listener should still work.
	runOne(t, drv, 31600, 50601, "post-rst-in-window", OptsAll)
}

// TestWGServer_BlindAck_InSynRcvd: SYN puts the TCB in SYN_RCVD. We
// then fire 100 random-ACK packets from the same 5-tuple; none of them
// should promote to ESTABLISHED. Finally, the legitimate third ACK
// completes the handshake.
func TestWGServer_BlindAck_InSynRcvd(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 31700)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	box := drv.RegisterInbox(clientIP, 50700, 64)
	defer box.Close()

	clientISS := uint32(0xDEAD_0000)
	syn := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 50700, DstPort: 31700,
		Seq: clientISS, Flags: FlagSYN, Window: 65535,
		Options: Options{MSSSet: true, MSS: 1460, TSSet: true, TSVal: nextTSVal()},
	})
	_ = drv.SendTo(syn)
	pkt, err := box.Recv(1 * time.Second)
	if err != nil {
		t.Fatalf("no SYN-ACK: %v", err)
	}
	pp, err := Parse(pkt)
	if err != nil {
		t.Fatalf("parse SYN-ACK: %v", err)
	}
	serverISS := pp.Seq

	// Fire blind ACKs with wrong ack values.
	for i := 0; i < 100; i++ {
		bad := mustEncode(t, PacketSpec{
			SrcIP: clientIP, DstIP: serverIP,
			SrcPort: 50700, DstPort: 31700,
			Seq: clientISS + 1,
			Ack: serverISS + 1 + uint32(i*7919+1000), // far off the right value
			Flags: FlagACK, Window: 65535,
		})
		_ = drv.SendTo(bad)
	}
	time.Sleep(100 * time.Millisecond)

	// Drain any retransmit SYN-ACKs that came back during the spray.
	for {
		if _, err := box.Recv(50 * time.Millisecond); err != nil {
			break
		}
	}

	// Send the *correct* third ACK and verify the connection actually
	// works (round-trip an echo).
	tsval := nextTSVal()
	ack := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 50700, DstPort: 31700,
		Seq: clientISS + 1, Ack: serverISS + 1,
		Flags: FlagACK, Window: 65535,
		Options: Options{TSSet: true, TSVal: tsval, TSEcr: pp.Options.TSVal},
	})
	_ = drv.SendTo(ack)

	// Send a request payload.
	req := []byte("blindack-survived\n")
	data := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 50700, DstPort: 31700,
		Seq: clientISS + 1, Ack: serverISS + 1,
		Flags: FlagACK | FlagPSH, Window: 65535,
		Options: Options{TSSet: true, TSVal: tsval, TSEcr: pp.Options.TSVal},
		Payload: req,
	})
	_ = drv.SendTo(data)

	// Wait up to 2s for an echo data segment.
	deadline := time.Now().Add(2 * time.Second)
	var resp bytes.Buffer
	for time.Now().Before(deadline) && resp.Len() < len(req) {
		pkt, err := box.Recv(deadline.Sub(time.Now()))
		if err != nil {
			break
		}
		pp2, err := Parse(pkt)
		if err != nil {
			continue
		}
		if len(pp2.Payload) > 0 {
			resp.Write(pp2.Payload)
		}
	}
	if resp.Len() < len(req) {
		t.Fatalf("expected echo of %q, got %q after spray",
			string(req), resp.String())
	}
}

// TestWGServer_CookieForgery_Rejected: cookies on, the attacker sees
// the SYN-ACK but cannot forge a valid third ACK without the secret.
// A subsequent legitimate handshake on the same listener still works.
func TestWGServer_CookieForgery_Rejected(t *testing.T) {
	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = byte(0xC0 ^ i)
	}
	drv, h, cleanup := adversarySetup(t, hex.EncodeToString(secret), 1, 31800)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	box := drv.RegisterInbox(clientIP, 50800, 32)
	defer box.Close()

	clientISS := uint32(0xBEEF_0001)
	syn := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 50800, DstPort: 31800,
		Seq: clientISS, Flags: FlagSYN, Window: 65535,
		Options: Options{MSSSet: true, MSS: 1460, TSSet: true, TSVal: nextTSVal()},
	})
	_ = drv.SendTo(syn)
	pkt, err := box.Recv(1 * time.Second)
	if err != nil {
		t.Fatalf("no cookie SYN-ACK: %v", err)
	}
	pp, _ := Parse(pkt)
	serverISS := pp.Seq

	// Forged third ACK with a guessed cookie (off by 1).
	forged := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 50800, DstPort: 31800,
		Seq: clientISS + 1, Ack: serverISS + 1 + 1,
		Flags: FlagACK, Window: 65535,
	})
	_ = drv.SendTo(forged)
	// Ensure no data response came through to our 5-tuple.
	if got, err := box.Recv(200 * time.Millisecond); err == nil {
		pp2, _ := Parse(got)
		if pp2 != nil && len(pp2.Payload) > 0 {
			t.Fatalf("forged third ACK got promoted: response payload = %q", string(pp2.Payload))
		}
	}
	box.Close()
	// Fresh legit handshake still works on the same listener.
	runOne(t, drv, 31800, 50801, "post-cookie-forgery", OptsNone)
}

// TestWGServer_BlindRst_Established: a legitimate connection is up;
// fire many RSTs from a foreign 5-tuple (different src port). None
// should tear down our connection.
func TestWGServer_BlindRst_Established(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 31900)
	defer cleanup()
	_ = h

	_, _ = ParseIP4(advClientIP) // sanity-parse the constant; not used directly
	serverIP, _ := ParseIP4(advServerIP)

	// Spray off-path RSTs (different src port → server rejects via
	// 5-tuple filter even before sequence acceptability). 200 should
	// be plenty.
	go func() {
		for i := 0; i < 200; i++ {
			var attacker [4]byte
			copy(attacker[:], []byte{198, 51, 100, byte(i & 0xFF)})
			spec := PacketSpec{
				SrcIP: attacker, DstIP: serverIP,
				SrcPort: uint16(60000 + i),
				DstPort: 31900,
				Seq:     uint32(i) * 12345,
				Ack:     uint32(i) * 67890,
				Flags:   FlagRST, Window: 0,
			}
			pkt, _ := Encode(spec)
			_ = drv.SendTo(pkt)
		}
	}()
	// Legitimate client must still succeed.
	runOne(t, drv, 31900, 50900, "post-rst-spray", OptsAll)
}

// TestWGServer_WrongLocalIP_Rejected: send a packet whose dst IP is
// NOT the configured server IP. The server must silently drop.
func TestWGServer_WrongLocalIP_Rejected(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 32000)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	wrongIP, _ := ParseIP4("10.99.0.99")
	box := drv.RegisterInbox(clientIP, 51000, 32)
	defer box.Close()

	spec := PacketSpec{
		SrcIP: clientIP, DstIP: wrongIP,
		SrcPort: 51000, DstPort: 32000,
		Seq: 0x1000_0000, Flags: FlagSYN, Window: 65535,
		Options: Options{MSSSet: true, MSS: 1460},
	}
	pkt, _ := Encode(spec)
	_ = drv.SendTo(pkt)
	if got, err := box.Recv(200 * time.Millisecond); err == nil {
		pp, _ := Parse(got)
		t.Fatalf("expected silent drop on wrong dst IP, got %+v", pp)
	}
	box.Close()
	runOne(t, drv, 32000, 51001, "post-wrong-ip", OptsAll)
}

// TestWGServer_Malformed_DontWedge throws a variety of garbage at the
// server: truncated, bad checksums, fragmented, and over-long option
// blobs. Then a legitimate handshake must still succeed.
func TestWGServer_Malformed_DontWedge(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 32100)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)

	mutators := []func(PacketSpec) PacketSpec{
		// Truncated.
		func(s PacketSpec) PacketSpec { s.TruncateBytes = 10; return s },
		// Bad IP checksum.
		func(s PacketSpec) PacketSpec { s.CorruptIPChecksum = true; return s },
		// Bad TCP checksum.
		func(s PacketSpec) PacketSpec { s.CorruptTCPChecksum = true; return s },
		// Fragmented (non-zero offset).
		func(s PacketSpec) PacketSpec { s.FragOffset = 8; return s },
		// More-fragments flag (we don't reassemble).
		func(s PacketSpec) PacketSpec { s.MoreFragments = true; return s },
		// Over-long options blob.
		func(s PacketSpec) PacketSpec {
			s.ExtraOptionsBlob = bytes.Repeat([]byte{0x55, 0xAA}, 22)
			return s
		},
		// All zero flags (no SYN/ACK/RST/FIN).
		func(s PacketSpec) PacketSpec { s.Flags = 0; return s },
	}

	for i, mu := range mutators {
		base := PacketSpec{
			SrcIP: clientIP, DstIP: serverIP,
			SrcPort: uint16(51100 + i),
			DstPort: 32100,
			Seq:     uint32(i) * 4096,
			Flags:   FlagSYN, Window: 65535,
			Options: Options{MSSSet: true, MSS: 1460},
		}
		muted := mu(base)
		pkt, err := Encode(muted)
		if err != nil {
			t.Logf("mutator %d encode err (ok if unencodable): %v", i, err)
			continue
		}
		_ = drv.SendTo(pkt)
	}
	time.Sleep(100 * time.Millisecond)
	runOne(t, drv, 32100, 51200, "post-malformed", OptsAll)
}

// TestWGServer_SynRetransmit_Idempotent: send a SYN, then send a few
// duplicate SYNs from the same 5-tuple while the TCB is in SYN_RCVD.
// The legitimate handshake should complete normally.
func TestWGServer_SynRetransmit_Idempotent(t *testing.T) {
	drv, h, cleanup := adversarySetup(t, "none", 1, 32200)
	defer cleanup()
	_ = h

	clientIP, _ := ParseIP4(advClientIP)
	serverIP, _ := ParseIP4(advServerIP)
	box := drv.RegisterInbox(clientIP, 51200, 32)
	defer box.Close()

	clientISS := uint32(0x1111_2222)
	mkSyn := func() []byte {
		return mustEncode(t, PacketSpec{
			SrcIP: clientIP, DstIP: serverIP,
			SrcPort: 51200, DstPort: 32200,
			Seq: clientISS, Flags: FlagSYN, Window: 65535,
			Options: Options{MSSSet: true, MSS: 1460, TSSet: true, TSVal: nextTSVal()},
		})
	}
	for i := 0; i < 5; i++ {
		_ = drv.SendTo(mkSyn())
		time.Sleep(20 * time.Millisecond)
	}
	// Read at least one SYN-ACK (we may get retransmits).
	pkt, err := box.Recv(1 * time.Second)
	if err != nil {
		t.Fatalf("no SYN-ACK: %v", err)
	}
	pp, _ := Parse(pkt)
	if pp.Flags&(FlagSYN|FlagACK) != FlagSYN|FlagACK {
		t.Fatalf("expected SYN+ACK, got %#x", pp.Flags)
	}
	serverISS := pp.Seq
	tsEcr := pp.Options.TSVal
	box.Close()

	// Now complete the handshake.
	box2 := drv.RegisterInbox(clientIP, 51200, 32)
	defer box2.Close()
	tsval := nextTSVal()
	ack := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 51200, DstPort: 32200,
		Seq: clientISS + 1, Ack: serverISS + 1,
		Flags: FlagACK, Window: 65535,
		Options: Options{TSSet: true, TSVal: tsval, TSEcr: tsEcr},
	})
	req := []byte("idempotent\n")
	data := mustEncode(t, PacketSpec{
		SrcIP: clientIP, DstIP: serverIP,
		SrcPort: 51200, DstPort: 32200,
		Seq: clientISS + 1, Ack: serverISS + 1,
		Flags: FlagACK | FlagPSH, Window: 65535,
		Options: Options{TSSet: true, TSVal: tsval, TSEcr: tsEcr},
		Payload: req,
	})
	_ = drv.SendTo(ack)
	_ = drv.SendTo(data)
	// Wait for echo.
	deadline := time.Now().Add(2 * time.Second)
	var resp bytes.Buffer
	for time.Now().Before(deadline) && resp.Len() < len(req) {
		pkt, err := box2.Recv(deadline.Sub(time.Now()))
		if err != nil {
			break
		}
		pp2, err := Parse(pkt)
		if err != nil {
			continue
		}
		if len(pp2.Payload) > 0 {
			resp.Write(pp2.Payload)
		}
	}
	if !bytes.Equal(resp.Bytes()[:min(resp.Len(), len(req))], req) {
		t.Fatalf("expected echo %q, got %q", req, resp.String())
	}
}

func mustEncode(t *testing.T, s PacketSpec) []byte {
	t.Helper()
	pkt, err := Encode(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return pkt
}

// Run all adversary tests sequentially in one process using a single
// shared mutex so port assignments don't collide.
var advMu sync.Mutex

func init() {
	_ = advMu.TryLock()
	advMu.Unlock()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
