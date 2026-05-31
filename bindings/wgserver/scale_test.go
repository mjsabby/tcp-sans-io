// Scale tests for the wgserver harness.
//
//   * TestWGServer_Smoke         — single mini-client; must succeed
//   * TestWGServer_1000_Connections — default-on, ~30s, smoke scale
//   * TestWGServer_10000_Connections — gated by STRESS=1
//
// The transport is loopback-only UDP carrying encapsulated IPv4+TCP
// packets. No kernel TUN, no root, no cgo.

package wgserver

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	smokeServerIP  = "10.99.0.2"
	smokeClientIP  = "10.99.0.1"
	smokeBasePort  = 30000
	smokeUDPListen = "127.0.0.1:0"
)

func TestWGServer_Smoke(t *testing.T) {
	// Pre-bind the driver's UDP socket so we know which port to give
	// the server as `--peer-udp`.
	driver, err := NewTransport(smokeUDPListen, "127.0.0.1:1") // peer placeholder
	if err != nil {
		t.Fatalf("driver transport: %v", err)
	}
	driverAddr := driver.LocalAddr()

	// Spawn the server, telling it to send replies to our bound port.
	cfg := DefaultHarnessConfig()
	cfg.NumListeners = 1
	cfg.ListenUDP = "127.0.0.1:0" // ephemeral
	// We can't know the server's listen port before launch; the
	// simpler arrangement is to pin both via fixed-port selection.
	cfg.ListenUDP, cfg.PeerUDP = pickLocalAddrs(t, driverAddr)
	_ = driver.Close()

	// Re-open the driver bound to the address we just promised the
	// server it would receive from.
	driver, err = NewTransport(extractPeerListen(cfg.PeerUDP), cfg.ListenUDP)
	if err != nil {
		t.Fatalf("re-open driver: %v", err)
	}
	defer func() { _ = driver.Close() }()

	h, err := Spawn(t, cfg)
	if err != nil {
		t.Fatalf("spawn wgserver: %v", err)
	}
	defer func() {
		if err := h.Shutdown(5 * time.Second); err != nil {
			t.Logf("shutdown: %v", err)
		}
	}()

	clientIP, err := ParseIP4(smokeClientIP)
	if err != nil {
		t.Fatal(err)
	}
	serverIP, _ := ParseIP4(smokeServerIP)

	res := RunMini(driver, MiniClientConfig{
		SrcIP:    clientIP,
		SrcPort:  40000,
		DstIP:    serverIP,
		DstPort:  smokeBasePort,
		ISS:      0x1000_0001,
		Opts:     OptsAll,
		Request:  []byte("hello-smoke\n"),
		RecvSize: 64,
		Deadline: 5 * time.Second,
	})
	if !res.OK {
		t.Fatalf("smoke client failed: err=%v lat=%v rx=%d tx=%d retx=%d",
			res.Err, res.Latency, res.RxPackets, res.TxPackets, res.Retransmits)
	}
	want := "hello-smoke\n"
	if string(res.Response) != want {
		t.Fatalf("echo mismatch: got %q want %q", string(res.Response), want)
	}
	t.Logf("smoke ok: lat=%v rx=%d tx=%d retx=%d", res.Latency, res.RxPackets, res.TxPackets, res.Retransmits)
}

func TestWGServer_1000_Connections(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short mode")
	}
	runScale(t, 1000, 256, 30*time.Second)
}

func TestWGServer_10000_Connections(t *testing.T) {
	if os.Getenv("STRESS") == "" {
		t.Skip("set STRESS=1 to run the 10000-connection stress test")
	}
	runScale(t, 10000, 256, 90*time.Second)
}

// runScale spawns the server with N listeners and drives N parallel
// mini-clients, bounded to `parallelism` in-flight at a time.
func runScale(t *testing.T, n, parallelism int, deadline time.Duration) {
	t.Helper()

	driverLocal := "127.0.0.1:0"
	peerLocal := "127.0.0.1:0"
	srvListen, drvPeer := pickLocalAddrs(t, nil)
	driverLocal = drvPeer
	peerLocal = srvListen
	_ = peerLocal

	driver, err := NewTransport(driverLocal, peerLocal)
	if err != nil {
		t.Fatalf("driver transport: %v", err)
	}
	defer func() { _ = driver.Close() }()

	cfg := DefaultHarnessConfig()
	cfg.NumListeners = uint16(n)
	cfg.BasePort = smokeBasePort
	cfg.ListenUDP = peerLocal
	cfg.PeerUDP = driverLocal
	cfg.MemoryCapMiB = 6 * 1024 // 6 GiB

	h, err := Spawn(t, cfg)
	if err != nil {
		t.Fatalf("spawn wgserver: %v", err)
	}
	defer func() { _ = h.Shutdown(15 * time.Second) }()

	serverIP, _ := ParseIP4(smokeServerIP)
	clientIP, _ := ParseIP4(smokeClientIP)

	t.Logf("scale: tcb_size=%d bytes, n=%d, est_rss=%d MiB",
		h.TcbSize(), n, (h.TcbSize()*uint64(n))/(1024*1024))

	type outcome struct {
		ok  bool
		lat time.Duration
		err error
	}
	results := make([]outcome, n)
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	var ok atomic.Int64
	start := time.Now()

	overallDeadline := start.Add(deadline)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if time.Now().After(overallDeadline) {
				results[i] = outcome{err: fmt.Errorf("deadline exceeded before start")}
				return
			}

			// Distribute the option matrix evenly.
			var opts MiniOpts
			switch i % 4 {
			case 0:
				opts = OptsNone
			case 1:
				opts = OptsTS
			case 2:
				opts = OptsWSTS
			case 3:
				opts = OptsAll
			}
			// Each client uses a unique src port so the driver-side
			// inbox demux is unambiguous.
			srcPort := uint16(40000 + i)
			dstPort := uint16(int(cfg.BasePort) + i)
			req := []byte(fmt.Sprintf("conn-%05d\n", i))

			res := RunMini(driver, MiniClientConfig{
				SrcIP:    clientIP,
				SrcPort:  srcPort,
				DstIP:    serverIP,
				DstPort:  dstPort,
				ISS:      0x10000000 + uint32(i),
				Opts:     opts,
				Request:  req,
				RecvSize: len(req),
				Deadline: 30 * time.Second,
			})
			if res.OK && string(res.Response) == string(req) {
				ok.Add(1)
				results[i] = outcome{ok: true, lat: res.Latency}
			} else {
				results[i] = outcome{ok: false, lat: res.Latency, err: res.Err}
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Latency percentiles over OK clients.
	lats := make([]time.Duration, 0, n)
	var firstErrs []error
	for _, r := range results {
		if r.ok {
			lats = append(lats, r.lat)
		} else if len(firstErrs) < 5 && r.err != nil {
			firstErrs = append(firstErrs, r.err)
		}
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	pct := func(p int) time.Duration {
		if len(lats) == 0 {
			return 0
		}
		idx := (len(lats) * p) / 100
		if idx >= len(lats) {
			idx = len(lats) - 1
		}
		return lats[idx]
	}

	okCount := int(ok.Load())
	successRate := float64(okCount) / float64(n) * 100.0
	rx, tx, dropped, mismatch := driver.Stats()
	t.Logf("scale: %d/%d ok (%.2f%%) in %v; p50=%v p95=%v p99=%v max=%v; rx=%d tx=%d dropped=%d mismatch=%d",
		okCount, n, successRate, elapsed.Round(time.Millisecond),
		pct(50).Round(time.Microsecond),
		pct(95).Round(time.Microsecond),
		pct(99).Round(time.Microsecond),
		pct(100).Round(time.Microsecond),
		rx, tx, dropped, mismatch)
	for i, e := range firstErrs {
		t.Logf("  failure[%d]: %v", i, e)
	}
	if successRate < 99.0 {
		t.Fatalf("success rate %.2f%% below threshold; %d/%d failed",
			successRate, n-okCount, n)
	}
}

// pickLocalAddrs reserves two free UDP ports on 127.0.0.1 and returns
// them as strings. Used so we can hand-coordinate the server's
// `--listen-udp` / `--peer-udp` and the driver's bind / peer addresses
// without an extra round-trip discovery step.
func pickLocalAddrs(t *testing.T, _ *net.UDPAddr) (server, driver string) {
	t.Helper()
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve A: %v", err)
	}
	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = a.Close()
		t.Fatalf("reserve B: %v", err)
	}
	server = a.LocalAddr().String()
	driver = b.LocalAddr().String()
	_ = a.Close()
	_ = b.Close()
	// Tiny sleep to let the OS release the bound port before the
	// real binders take it (TIME_WAIT-like effect on Windows).
	time.Sleep(20 * time.Millisecond)
	return server, driver
}

// extractPeerListen converts the address the driver was told the
// server runs at into a `:port`-style listen string for re-binding.
func extractPeerListen(addr string) string {
	return addr
}

// Compile-time sanity: ensure encoding/binary stays imported.
var _ = binary.BigEndian
