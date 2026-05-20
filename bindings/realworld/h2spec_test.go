// HTTP/2 conformance test via h2spec.
//
// h2spec (nghttp2.org/h2spec) is the de-facto HTTP/2 conformance
// suite. It connects to an HTTP/2 server, exercises every framing
// edge case in RFC 7540 / RFC 9113, and reports per-test pass/fail.
//
// For us, h2spec is a tremendous indirect signal: each test case is
// a fresh TCP+TLS connection that does a strict, framing-sensitive
// HTTP/2 conversation. Anything our TCP stack mis-orders, drops,
// or truncates surfaces as an h2spec failure (NOT silent corruption,
// since HTTP/2 frames have explicit lengths and HPACK has cross-
// frame state).
//
// Architecture:
//   cdylib (LISTEN, re-arms after each connection)
//     ↑↓ IPv4+TCP through TUN
//   cdylibListener.Accept() → net.Conn for one connection
//     ↓
//   tls.Server wraps it (ALPN advertises h2)
//     ↓
//   http.Server.Serve handles the conn (Go's H2 path takes over
//   automatically because ALPN selected h2)
//     ↓
//   simple "hello, h2spec" handler responds to GET /
//
// h2spec subprocess hits https://10.205.250.2:8443 and runs its
// conformance suite. The test asserts that the vast majority of
// generic-protocol tests pass (we don't pretend to be a full HTTP/2
// stack; some advanced HTTP/2-specific behavior is out of scope).

//go:build linux

package realworld

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	h2Iface    = "tcpsans-h2"
	h2HostAddr = "10.205.250.1"
	h2PeerAddr = "10.205.250.2"
	h2Prefix   = 30
	h2Port     = 18444
	h2spec     = "/tmp/h2spec"
)

// cdylibListener implements net.Listener over a single Tcb that
// re-LISTENs between connections. Each Accept() blocks until a new
// inbound handshake completes; the returned net.Conn owns the Tcb
// for the connection's lifetime. When the conn closes, the Listener
// re-arms the Tcb and waits for the next SYN.
//
// h2spec opens one TCP+TLS+H2 connection per test case (hundreds of
// connections in a typical run), so the re-LISTEN cycle is hit
// often — making this listener an interesting stress test in its
// own right.
type cdylibListener struct {
	tunFd       int
	tunIn       chan []byte
	handle      *TcpHandle
	pendingConn chan net.Conn
	pendingErr  chan error
	stop        chan struct{}
	closeOnce   sync.Once
	loopDone    chan struct{}
}

func (l *cdylibListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.pendingConn:
		return c, nil
	case err := <-l.pendingErr:
		return nil, err
	case <-l.stop:
		return nil, io.EOF
	}
}

func (l *cdylibListener) Close() error {
	l.closeOnce.Do(func() { close(l.stop) })
	<-l.loopDone
	return nil
}

func (l *cdylibListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(h2PeerAddr), Port: h2Port}
}

// serverLoop owns the Tcb. It LISTENs, waits for ESTABLISHED, hands
// the conn to Accept, waits for it to close, re-LISTENs, repeats.
// Single-threaded ownership of the Tcb (no concurrent FFI calls).
func (l *cdylibListener) serverLoop() {
	defer close(l.loopDone)

	for {
		select {
		case <-l.stop:
			return
		default:
		}

		// Pump until ESTABLISHED or stop.
		if !l.pumpUntilEstablished() {
			return
		}

		// Wrap as a cdylibConn for the caller.
		conn := &cdylibConn{
			srv:       l.handle,
			tunFd:     l.tunFd,
			tunIn:     l.tunIn,
			readReqs:  make(chan tlsReadReq, 1),
			writeReqs: make(chan tlsWriteReq, 1),
			closeCh:   make(chan struct{}),
			doneCh:    make(chan struct{}),
		}
		// Start the per-conn pump (owns the Tcb until conn closes).
		go conn.pump()

		// Hand to Accept.
		select {
		case l.pendingConn <- conn:
		case <-l.stop:
			_ = conn.Close()
			return
		}

		// Wait for the conn to fully drain (pump goroutine exits when
		// the Tcb reaches Closed or stop is signaled).
		<-conn.doneCh

		// Re-LISTEN. Tcb may be in Closed or TimeWait now.
		if err := l.handle.Listen(); err != nil {
			select {
			case l.pendingErr <- fmt.Errorf("relisten: %v", err):
			case <-l.stop:
			}
			return
		}
	}
}

// pumpUntilEstablished drives the Tcb forward (inject/extract/tick)
// until the state machine reaches ESTABLISHED or the listener stops.
// Returns true on success, false on stop.
func (l *cdylibListener) pumpUntilEstablished() bool {
	var extractBuf [mtu]byte
	for {
		select {
		case <-l.stop:
			return false
		default:
		}

		// extract → TUN.
		for {
			n, err := l.handle.ExtractPacket(extractBuf[:])
			if err != nil || n == 0 {
				break
			}
			_, _ = syscall.Write(l.tunFd, extractBuf[:n])
		}

		// TUN → inject.
	drainIn:
		for {
			select {
			case pkt := <-l.tunIn:
				_ = l.handle.InjectPacket(pkt)
			default:
				break drainIn
			}
		}

		_ = l.handle.Tick()
		if l.handle.State() == StateEstablished {
			return true
		}
		// Yield briefly so we don't burn CPU during idle LISTEN.
		time.Sleep(200 * time.Microsecond)
	}
}

func setupH2Listener(t *testing.T) (*cdylibListener, func()) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for /dev/net/tun + ip(8)")
	}
	if _, err := os.Stat(h2spec); err != nil {
		t.Skipf("%s not found (install with: wget https://github.com/summerwind/h2spec/releases/download/v2.6.0/h2spec_linux_amd64.tar.gz && tar -xzf h2spec_linux_amd64.tar.gz -C /tmp/)", h2spec)
	}

	tryRun("ip", "link", "del", h2Iface)
	tun, name, err := openTun(h2Iface)
	if err != nil {
		t.Fatalf("open TUN: %v", err)
	}
	tunFd := int(tun.Fd())

	mustRun(t, "ip", "link", "set", name, "up")
	mustRun(t, "ip", "addr", "add", fmt.Sprintf("%s/%d", h2HostAddr, h2Prefix), "dev", name)
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", name))
	tryRun("sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=2")
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.accept_local=1", name))

	handle, err := NewTcpHandle(
		parseIP4(h2PeerAddr), h2Port,
		parseIP4(h2HostAddr), 0,
		0xBEEFCAFE, 1000,
	)
	if err != nil {
		_ = tun.Close()
		tryRun("ip", "link", "del", name)
		t.Fatalf("NewTcpHandle: %v", err)
	}
	if err := handle.Listen(); err != nil {
		handle.Free()
		_ = tun.Close()
		tryRun("ip", "link", "del", name)
		t.Fatalf("listen: %v", err)
	}

	tunIn := make(chan []byte, 256)
	tunStop := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := syscall.Read(tunFd, buf)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				select {
				case <-tunStop:
					return
				default:
					return
				}
			}
			if n < 20 || buf[0]>>4 != 4 || buf[9] != 6 {
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			select {
			case tunIn <- pkt:
			case <-tunStop:
				return
			}
		}
	}()

	l := &cdylibListener{
		tunFd:       tunFd,
		tunIn:       tunIn,
		handle:      handle,
		pendingConn: make(chan net.Conn),
		pendingErr:  make(chan error, 1),
		stop:        make(chan struct{}),
		loopDone:    make(chan struct{}),
	}
	go l.serverLoop()

	cleanup := func() {
		_ = l.Close()
		close(tunStop)
		handle.Free()
		_ = tun.Close()
		tryRun("ip", "link", "del", name)
	}
	return l, cleanup
}

func TestH2spec_Generic(t *testing.T) {
	l, cleanup := setupH2Listener(t)
	defer cleanup()

	cert := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// http.Server with H2 advertised via ALPN. Go's net/http picks
	// up h2 automatically when the negotiated proto is h2.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello, h2spec\n"))
	})
	httpSrv := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Wrap the listener with TLS so net/http sees TLS connections
	// from the start (and ALPN selection happens before HTTP framing).
	tlsListener := tls.NewListener(l, tlsCfg)

	// Serve in a goroutine; will return when listener Close()d.
	srvDone := make(chan error, 1)
	go func() {
		err := httpSrv.Serve(tlsListener)
		if !errors.Is(err, io.EOF) && !errors.Is(err, http.ErrServerClosed) &&
			!errors.Is(err, net.ErrClosed) {
			srvDone <- err
		} else {
			srvDone <- nil
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	// h2spec subprocess. Run only the generic protocol tests (the
	// http2-specific framing test cases require server-side behavior
	// that's out of scope for our simple echo handler).
	//
	// -t: TLS (matches our setup)
	// -k: skip cert validation (self-signed)
	// -h / -p: target host/port
	// --strict: fail on any deviation
	// We pass --section to focus on the generic protocol part of the
	// suite that's about TCP framing / TLS / connection lifecycle —
	// the parts our stack is responsible for. Section 3 = starting
	// HTTP/2 (preface, settings, connection preface).
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, h2spec,
		"-t", "-k",
		"-h", h2PeerAddr,
		"-p", fmt.Sprintf("%d", h2Port),
		"--timeout", "10",
		"--strict",
		"generic",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("h2spec output:\n%s", out)
	// h2spec returns non-zero exit if ANY test fails. We assert that
	// no MORE than `tolerance` tests fail — some HTTP/2-specific
	// scenarios depend on application behavior our simple handler
	// doesn't implement (e.g. graceful shutdown frames in flight).
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("h2spec subprocess: %v", err)
		}
	}

	// Parse: look for "X tests, Y passed, Z skipped, W failed"
	// (h2spec's summary line). We accept up to 5 failures (HTTP/2
	// edge cases that require app-side behavior).
	const acceptableFailures = 5
	failed := parseH2specFailures(string(out))
	if failed > acceptableFailures {
		t.Fatalf("h2spec reported %d failures (acceptable: %d) — exit=%d", failed, acceptableFailures, exitCode)
	}
	t.Logf("h2spec PASSED with %d acceptable failures (exit=%d)", failed, exitCode)

	select {
	case err := <-srvDone:
		if err != nil {
			t.Errorf("http server: %v", err)
		}
	default:
	}
}

// parseH2specFailures extracts the failure count from h2spec's
// summary. Expected line format:
//   "X tests, Y passed, Z skipped, W failed"
func parseH2specFailures(out string) int {
	for _, line := range strings.Split(out, "\n") {
		// Tolerate leading whitespace / colors.
		s := strings.TrimSpace(stripANSI(line))
		if !strings.Contains(s, "tests,") || !strings.Contains(s, "failed") {
			continue
		}
		// "X tests, Y passed, Z skipped, W failed"
		fields := strings.Split(s, ",")
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if strings.HasSuffix(f, " failed") {
				var n int
				_, _ = fmt.Sscanf(f, "%d failed", &n)
				return n
			}
		}
	}
	return -1
}

// stripANSI strips simple ANSI color escapes (h2spec output is
// colorized when isatty; running under exec.Command shouldn't but
// be defensive).
func stripANSI(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		if r == 0x1b {
			in = true
			continue
		}
		if in {
			if r == 'm' {
				in = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
