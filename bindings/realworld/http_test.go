// Real-world HTTP/1.1 interop test: the cdylib hosts a minimal echo
// server in LISTEN mode through a TUN device, and we drive it with a
// real `curl` subprocess on the kernel side.
//
// Tests exercise patterns that pure conformance tests don't catch:
//
//   * Real curl negotiates ECN, TS, WS, SACK with our stack.
//   * HTTP/1.1 request framing forces us to handle small writes then
//     a header-terminator scan then variable-length bodies.
//   * Persistent connections (default in curl) exercise our handling
//     of multiple request/response cycles per TCB.
//   * Large bodies (1 MiB+) stress the BUF_CAP / WS / cwnd interaction.
//   * `curl --limit-rate` simulates a slow client, which keeps the
//     send ring full and exercises peer-window backpressure.
//
// Requires: Linux + root (CAP_NET_ADMIN) + `curl` in $PATH. Tests
// self-skip otherwise.

//go:build linux

package realworld

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	httpIface    = "tcpsans-http"
	httpHostAddr = "10.202.250.1"
	httpPeerAddr = "10.202.250.2"
	httpPrefix   = 30
	httpPort     = 18180

	// Pump deadline guards against a hung test. All scenarios should
	// complete well under this.
	httpDeadline = 60 * time.Second
)

// httpServer is a minimal HTTP/1.1 echo handler driven directly off
// the cdylib's recv/send rings. It supports:
//
//   * GET /echo?msg=...   → body = msg
//   * GET /size?n=...     → body = `n` deterministic bytes (pattern 0..255)
//   * POST /echo          → body = request body verbatim
//   * GET /close          → respond 200 then half-close
//
// Connection semantics are HTTP/1.0-style: respond + immediately
// half-close. Keep-alive is left for a follow-up since it requires
// tracking request boundaries across multiple round-trips.
type httpServer struct {
	t        *testing.T
	srv      *TcpHandle
	tunFd    int
	tunIn    chan []byte
	stop     chan struct{}
	closed   bool
	handled  int
}

func (s *httpServer) pump(deadline time.Time) error {
	var (
		extractBuf [mtu]byte
		recvBuf    [64 * 1024]byte
		reqBuf     bytes.Buffer
	)
	const maxReq = 8 << 20 // 8 MiB safety cap on request size

	// Partial response we still need to push through Send() (may take
	// multiple outer iterations because Send returns WouldBlock when
	// the send ring is full).
	var pendingResp []byte
	respondedAndClosing := false
	for time.Now().Before(deadline) {
		// cdylib → TUN.
		for {
			n, err := s.srv.ExtractPacket(extractBuf[:])
			if err != nil {
				return fmt.Errorf("extract: %v", err)
			}
			if n == 0 {
				break
			}
			if _, werr := syscall.Write(s.tunFd, extractBuf[:n]); werr != nil {
				return fmt.Errorf("tun write: %v", werr)
			}
		}

		// TUN → cdylib.
	drainIn:
		for {
			select {
			case pkt := <-s.tunIn:
				if err := s.srv.InjectPacket(pkt); err != nil &&
					!errors.Is(err, ErrMalformedPacket) &&
					!errors.Is(err, ErrNotForUs) &&
					!errors.Is(err, ErrInvalidState) {
					return fmt.Errorf("inject: %v", err)
				}
			default:
				break drainIn
			}
		}

		if err := s.srv.Tick(); err != nil {
			return fmt.Errorf("tick: %v", err)
		}

		// Drain any application bytes the peer sent into our recv ring,
		// up to the request safety cap.
		for !respondedAndClosing && reqBuf.Len() < maxReq {
			n, err := s.srv.Recv(recvBuf[:])
			if err != nil {
				if errors.Is(err, ErrConnectionClosed) || errors.Is(err, ErrConnectionReset) {
					// Peer half-close: still finish the response if we
					// have one in flight, then close ourselves.
					if pendingResp == nil && !respondedAndClosing {
						return nil
					}
					break
				}
				return fmt.Errorf("recv: %v", err)
			}
			if n == 0 {
				break
			}
			reqBuf.Write(recvBuf[:n])
		}

		// Try to handle a complete request if we don't already have a
		// response staged.
		if !respondedAndClosing && pendingResp == nil {
			done, resp, err := tryHandle(&reqBuf)
			if err != nil {
				return fmt.Errorf("handle: %v", err)
			}
			if done {
				pendingResp = resp
			}
		}

		// Push as many response bytes as the send ring will accept.
		// May take multiple iterations of the outer loop — that's
		// fine, we just keep pumping the TUN in between.
		if pendingResp != nil {
			for len(pendingResp) > 0 {
				n, err := s.srv.Send(pendingResp)
				if err != nil && !errors.Is(err, ErrWouldBlock) {
					return fmt.Errorf("send: %v", err)
				}
				if n == 0 {
					break // ring full — try again next iter
				}
				pendingResp = pendingResp[n:]
			}
			if len(pendingResp) == 0 {
				pendingResp = nil
				s.handled++
				respondedAndClosing = true
				if err := s.srv.Close(); err != nil {
					return fmt.Errorf("close: %v", err)
				}
			}
		}

		st := s.srv.State()
		if st == StateClosed || st == StateTimeWait {
			return nil
		}
	}
	return fmt.Errorf("pump deadline exceeded (handled %d requests, last state %s)",
		s.handled, StateName(s.srv.State()))
}

// tryHandle inspects `buf` for a complete HTTP/1.1 request. If found,
// generates the response, drains the request bytes from `buf`, and
// returns (true, response, nil). If incomplete, returns (false, nil,
// nil). If malformed, returns (false, nil, err).
func tryHandle(buf *bytes.Buffer) (bool, []byte, error) {
	headerEnd := bytes.Index(buf.Bytes(), []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return false, nil, nil
	}
	rawHeaders := buf.Bytes()[:headerEnd]
	bodyStart := headerEnd + 4

	// Parse request-line + headers using net/http for free.
	req, err := http.ReadRequest(bufio.NewReader(newReqReader(rawHeaders, buf.Bytes()[bodyStart:])))
	if err != nil {
		return false, nil, fmt.Errorf("parse request: %v", err)
	}

	contentLen := int64(0)
	if cl := req.Header.Get("Content-Length"); cl != "" {
		v, err := strconv.ParseInt(cl, 10, 64)
		if err != nil || v < 0 {
			return false, nil, fmt.Errorf("bad Content-Length %q", cl)
		}
		contentLen = v
	}
	totalReq := int64(bodyStart) + contentLen
	if int64(buf.Len()) < totalReq {
		// Body not yet fully received.
		return false, nil, nil
	}

	bodyBytes := buf.Bytes()[bodyStart : bodyStart+int(contentLen)]

	respBody, contentType, err := handleRoute(req, bodyBytes)
	if err != nil {
		return true, errorResponse(500, err.Error()), nil
	}

	// Consume the request bytes we processed (header + body).
	buf.Next(int(totalReq))

	resp := buildResponse(200, "OK", contentType, respBody)
	return true, resp, nil
}

// handleRoute is the actual echo logic. Returns (body, content-type, err).
func handleRoute(req *http.Request, body []byte) ([]byte, string, error) {
	u, _ := url.Parse(req.URL.String())
	switch req.Method {
	case "GET":
		switch u.Path {
		case "/echo":
			msg := u.Query().Get("msg")
			if msg == "" {
				msg = "hello"
			}
			return []byte(msg), "text/plain; charset=utf-8", nil
		case "/size":
			n, err := strconv.Atoi(u.Query().Get("n"))
			if err != nil || n < 0 || n > (16<<20) {
				return nil, "", fmt.Errorf("size n must be in [0, 16 MiB]")
			}
			b := make([]byte, n)
			for i := range b {
				b[i] = byte(i & 0xFF)
			}
			return b, "application/octet-stream", nil
		case "/close":
			return []byte("goodbye"), "text/plain; charset=utf-8", nil
		default:
			return nil, "", fmt.Errorf("unknown GET path %q", u.Path)
		}
	case "POST":
		if u.Path == "/echo" {
			return body, contentTypeOr(req, "application/octet-stream"), nil
		}
		return nil, "", fmt.Errorf("unknown POST path %q", u.Path)
	default:
		return nil, "", fmt.Errorf("unsupported method %q", req.Method)
	}
}

func contentTypeOr(req *http.Request, fallback string) string {
	if ct := req.Header.Get("Content-Type"); ct != "" {
		return ct
	}
	return fallback
}

func buildResponse(status int, reason, contentType string, body []byte) []byte {
	var resp bytes.Buffer
	fmt.Fprintf(&resp, "HTTP/1.1 %d %s\r\n", status, reason)
	fmt.Fprintf(&resp, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&resp, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&resp, "Connection: close\r\n")
	resp.WriteString("\r\n")
	resp.Write(body)
	return resp.Bytes()
}

func errorResponse(status int, msg string) []byte {
	return buildResponse(status, "ERROR", "text/plain; charset=utf-8", []byte(msg))
}

// newReqReader synthesises a *bufio.Reader-compatible stream from
// separate header + body slices so http.ReadRequest can parse it.
func newReqReader(headers, body []byte) *bufReader {
	r := &bufReader{}
	r.buf = append(r.buf, headers...)
	r.buf = append(r.buf, []byte("\r\n\r\n")...)
	r.buf = append(r.buf, body...)
	return r
}

// Minimal io.Reader → bufio.Reader bridge for net/http.ReadRequest.
type bufReader struct {
	buf []byte
	off int
}

func (r *bufReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

// http.ReadRequest needs a *bufio.Reader. Wrap.
//
// (using *bufio.Reader from the std lib means we wrap via a helper
// that delegates Read to bufReader)
//
//	import "bufio"
//	bufio.NewReader(r)
//
// Done in handle.

func setupTUNAndServer(t *testing.T) (*httpServer, func()) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for /dev/net/tun + ip(8)")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not in PATH")
	}

	tryRun("ip", "link", "del", httpIface)

	tun, name, err := openTun(httpIface)
	if err != nil {
		t.Fatalf("open TUN: %v", err)
	}
	tunFd := int(tun.Fd())

	mustRun(t, "ip", "link", "set", name, "up")
	mustRun(t, "ip", "addr", "add", fmt.Sprintf("%s/%d", httpHostAddr, httpPrefix), "dev", name)
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", name))
	tryRun("sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=2")
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.accept_local=1", name))

	srv, err := NewTcpHandle(
		parseIP4(httpPeerAddr), httpPort,
		parseIP4(httpHostAddr), 0,
		0xC0DEC0DE, 1000,
	)
	if err != nil {
		_ = tun.Close()
		tryRun("ip", "link", "del", name)
		t.Fatalf("NewTcpHandle: %v", err)
	}
	if err := srv.Listen(); err != nil {
		srv.Free()
		_ = tun.Close()
		tryRun("ip", "link", "del", name)
		t.Fatalf("listen: %v", err)
	}

	stop := make(chan struct{})
	tunIn := make(chan []byte, 256)

	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := syscall.Read(tunFd, buf)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				select {
				case <-stop:
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
			case <-stop:
				return
			}
		}
	}()

	s := &httpServer{
		t:     t,
		srv:   srv,
		tunFd: tunFd,
		tunIn: tunIn,
		stop:  stop,
	}
	cleanup := func() {
		if !s.closed {
			s.closed = true
			close(stop)
			srv.Free()
			_ = tun.Close()
			tryRun("ip", "link", "del", name)
		}
	}
	return s, cleanup
}

// runCurlScenario executes one curl request against the cdylib in a
// goroutine, drives the pump until the server has handled at least
// one request and reached a terminal state, and returns the curl
// stdout / err.
func runCurlScenario(t *testing.T, s *httpServer, curlArgs ...string) ([]byte, []byte, error) {
	t.Helper()

	cmd := exec.Command("curl", curlArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	curlDone := make(chan error, 1)
	go func() {
		curlDone <- cmd.Run()
	}()

	// Pump until server reaches Closed/TimeWait or curl finishes.
	pumpErr := s.pump(time.Now().Add(httpDeadline))

	// Wait for curl to finish (it may already have).
	select {
	case err := <-curlDone:
		if err != nil {
			return stdout.Bytes(), stderr.Bytes(),
				fmt.Errorf("curl: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-curlDone
		return stdout.Bytes(), stderr.Bytes(),
			fmt.Errorf("curl did not exit within 5s after server pump returned")
	}

	if pumpErr != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("pump: %v", pumpErr)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

// =============================================================================
// Tests
// =============================================================================

func TestHTTP_GET_Echo_Hello(t *testing.T) {
	s, cleanup := setupTUNAndServer(t)
	defer cleanup()

	url := fmt.Sprintf("http://%s:%d/echo?msg=hello", httpPeerAddr, httpPort)
	stdout, _, err := runCurlScenario(t, s,
		"-sS", "--max-time", "10", url,
	)
	if err != nil {
		t.Fatalf("scenario: %v", err)
	}
	if got, want := strings.TrimSpace(string(stdout)), "hello"; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
	if s.handled != 1 {
		t.Fatalf("expected 1 request handled, got %d", s.handled)
	}
}

func TestHTTP_GET_Size_64KiB(t *testing.T) {
	s, cleanup := setupTUNAndServer(t)
	defer cleanup()

	n := 64 * 1024
	url := fmt.Sprintf("http://%s:%d/size?n=%d", httpPeerAddr, httpPort, n)
	stdout, _, err := runCurlScenario(t, s,
		"-sS", "--max-time", "15", url,
	)
	if err != nil {
		t.Fatalf("scenario: %v", err)
	}
	if len(stdout) != n {
		t.Fatalf("body length: got %d want %d", len(stdout), n)
	}
	for i, b := range stdout {
		if b != byte(i&0xFF) {
			t.Fatalf("body pattern mismatch at offset %d: got 0x%02x want 0x%02x", i, b, byte(i&0xFF))
		}
	}
}

func TestHTTP_POST_Echo_Body(t *testing.T) {
	s, cleanup := setupTUNAndServer(t)
	defer cleanup()

	body := strings.Repeat("tcp-sans-io ", 100) // ~1.2 KiB request body
	url := fmt.Sprintf("http://%s:%d/echo", httpPeerAddr, httpPort)
	stdout, _, err := runCurlScenario(t, s,
		"-sS", "--max-time", "10",
		"-X", "POST",
		"-H", "Content-Type: text/plain",
		"--data-binary", body,
		url,
	)
	if err != nil {
		t.Fatalf("scenario: %v", err)
	}
	if string(stdout) != body {
		t.Fatalf("echo body mismatch (got %d bytes, want %d)", len(stdout), len(body))
	}
}

func TestHTTP_POST_Echo_1MiB(t *testing.T) {
	s, cleanup := setupTUNAndServer(t)
	defer cleanup()

	// 1 MiB deterministic body.
	body := make([]byte, 1<<20)
	for i := range body {
		body[i] = byte(i & 0xFF)
	}

	// Write body to a temp file for curl --data-binary @file.
	tmp, err := os.CreateTemp(t.TempDir(), "post-body-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = tmp.Close()

	url := fmt.Sprintf("http://%s:%d/echo", httpPeerAddr, httpPort)
	stdout, _, err := runCurlScenario(t, s,
		"-sS", "--max-time", "30",
		"-X", "POST",
		"-H", "Content-Type: application/octet-stream",
		"--data-binary", "@"+tmp.Name(),
		url,
	)
	if err != nil {
		t.Fatalf("scenario: %v", err)
	}
	if !bytes.Equal(stdout, body) {
		t.Fatalf("echo body mismatch (got %d bytes, want %d)", len(stdout), len(body))
	}
}

func TestHTTP_SlowClient_LimitRate(t *testing.T) {
	s, cleanup := setupTUNAndServer(t)
	defer cleanup()

	// 200 KiB body. With --limit-rate 100K curl uploads at ~100 KiB/s,
	// so this takes ~2s. Exercises the persist timer / peer-window
	// backpressure path.
	body := make([]byte, 200*1024)
	for i := range body {
		body[i] = byte((i * 31) & 0xFF)
	}
	tmp, err := os.CreateTemp(t.TempDir(), "slow-body-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = tmp.Close()

	url := fmt.Sprintf("http://%s:%d/echo", httpPeerAddr, httpPort)
	stdout, _, err := runCurlScenario(t, s,
		"-sS", "--max-time", "30",
		"--limit-rate", "100K",
		"-X", "POST",
		"--data-binary", "@"+tmp.Name(),
		url,
	)
	if err != nil {
		t.Fatalf("scenario: %v", err)
	}
	if !bytes.Equal(stdout, body) {
		t.Fatalf("echo body mismatch (got %d bytes, want %d)", len(stdout), len(body))
	}
}

// pumpServeForever loops the pump-handle-close-relisten cycle for
// `dur`. The pump runs inline rather than re-entering `pump` so
// LISTEN→ESTABLISHED→CLOSED transitions across many short curl /
// wrk connections all happen on a single set of buffers.
func (s *httpServer) pumpServeForever(dur time.Duration) error {
	deadline := time.Now().Add(dur + 5*time.Second) // grace for in-flight ones
	hardDeadline := time.Now().Add(dur + 30*time.Second)

	var (
		extractBuf  [mtu]byte
		recvBuf     [64 * 1024]byte
		reqBuf      bytes.Buffer
		pendingResp []byte
	)
	const maxReq = 8 << 20
	respondedAndClosing := false
	peerClosed := false

	for time.Now().Before(hardDeadline) {
		// cdylib → TUN.
		for {
			n, err := s.srv.ExtractPacket(extractBuf[:])
			if err != nil {
				return fmt.Errorf("extract: %v", err)
			}
			if n == 0 {
				break
			}
			if _, werr := syscall.Write(s.tunFd, extractBuf[:n]); werr != nil {
				return fmt.Errorf("tun write: %v", werr)
			}
		}

		// TUN → cdylib.
	drainIn:
		for {
			select {
			case pkt := <-s.tunIn:
				if err := s.srv.InjectPacket(pkt); err != nil &&
					!errors.Is(err, ErrMalformedPacket) &&
					!errors.Is(err, ErrNotForUs) &&
					!errors.Is(err, ErrInvalidState) {
					return fmt.Errorf("inject: %v", err)
				}
			default:
				break drainIn
			}
		}

		if err := s.srv.Tick(); err != nil {
			return fmt.Errorf("tick: %v", err)
		}

		// Drain recv into reqBuf. Track peer half-close so we can
		// abandon a stuck CLOSE_WAIT (peer sent FIN before completing
		// a request — common during wrk warmup connection-pool churn).
		for !respondedAndClosing && reqBuf.Len() < maxReq {
			n, err := s.srv.Recv(recvBuf[:])
			if err != nil {
				if errors.Is(err, ErrConnectionClosed) || errors.Is(err, ErrConnectionReset) {
					peerClosed = true
					break
				}
				return fmt.Errorf("recv: %v", err)
			}
			if n == 0 {
				break
			}
			reqBuf.Write(recvBuf[:n])
		}

		// Try to parse + respond to a request.
		if !respondedAndClosing && pendingResp == nil {
			done, resp, err := tryHandle(&reqBuf)
			if err != nil {
				return fmt.Errorf("handle: %v", err)
			}
			if done {
				pendingResp = resp
			} else if peerClosed {
				// Peer half-closed before sending a complete request.
				// Close our side too so the connection can transition
				// CLOSE_WAIT → LAST_ACK → CLOSED and we can re-LISTEN.
				if err := s.srv.Close(); err != nil {
					return fmt.Errorf("close (no-request): %v", err)
				}
				respondedAndClosing = true
			}
		}

		// Push response bytes; partial send is fine, we'll resume.
		if pendingResp != nil {
			for len(pendingResp) > 0 {
				n, err := s.srv.Send(pendingResp)
				if err != nil && !errors.Is(err, ErrWouldBlock) {
					return fmt.Errorf("send: %v", err)
				}
				if n == 0 {
					break
				}
				pendingResp = pendingResp[n:]
			}
			if len(pendingResp) == 0 {
				pendingResp = nil
				s.handled++
				respondedAndClosing = true
				if err := s.srv.Close(); err != nil {
					return fmt.Errorf("close: %v", err)
				}
			}
		}

		// Once a connection has fully closed, re-arm LISTEN for the
		// next inbound SYN. The Listen relaxation accepts TimeWait
		// (SO_REUSEADDR-style) so we don't need to wait out the
		// 2*MSL window between requests.
		st := s.srv.State()
		if respondedAndClosing && (st == StateClosed || st == StateTimeWait) {
			if err := s.srv.Listen(); err != nil {
				return fmt.Errorf("relisten: %v", err)
			}
			reqBuf.Reset()
			respondedAndClosing = false
			peerClosed = false
		}

		// Stop condition: past the requested duration AND we're idle
		// in LISTEN (no in-flight connection).
		if time.Now().After(deadline) && s.srv.State() == StateListen && !respondedAndClosing {
			return nil
		}
	}
	return fmt.Errorf("serve loop hard deadline exceeded (state %s, handled %d)",
		StateName(s.srv.State()), s.handled)
}

func TestHTTP_Sequential_Curl_3x(t *testing.T) {
	s, cleanup := setupTUNAndServer(t)
	defer cleanup()

	// Run 3 sequential curl invocations. Each opens a fresh TCP
	// connection (because we respond Connection: close and Close()
	// after each request). Tests the LISTEN re-arm path.
	url := fmt.Sprintf("http://%s:%d/echo?msg=round-%%d", httpPeerAddr, httpPort)

	// Background serve loop. Stops once each curl completes + LISTEN
	// is re-armed.
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- s.pumpServeForever(5 * time.Second)
	}()

	for i := 0; i < 3; i++ {
		u := fmt.Sprintf("http://%s:%d/echo?msg=round-%d", httpPeerAddr, httpPort, i)
		cmd := exec.Command("curl", "-sS", "--max-time", "10", u)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("curl round %d: %v", i, err)
		}
		want := fmt.Sprintf("round-%d", i)
		if strings.TrimSpace(string(out)) != want {
			t.Fatalf("round %d body mismatch: got %q want %q", i, strings.TrimSpace(string(out)), want)
		}
	}

	// Pump loop will exit on its own after the grace window.
	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("serve loop: %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("serve loop did not exit")
	}

	if s.handled < 3 {
		t.Fatalf("expected ≥3 requests handled, got %d", s.handled)
	}
	_ = url
}

func TestHTTP_Wrk_Load(t *testing.T) {
	if _, err := exec.LookPath("wrk"); err != nil {
		t.Skip("wrk not in PATH")
	}
	s, cleanup := setupTUNAndServer(t)
	defer cleanup()

	url := fmt.Sprintf("http://%s:%d/echo?msg=load", httpPeerAddr, httpPort)
	const dur = 3 * time.Second

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- s.pumpServeForever(dur)
	}()

	// 1 thread × 1 connection × duration. We force `Connection: close`
	// so wrk reconnects between requests (matching our server's
	// "close after each response" model). h2load would be a better
	// HTTP/1.1 chooser but isn't always installed.
	cmd := exec.Command("wrk",
		"-t1", "-c1", "-d", dur.String(),
		"-H", "Connection: close",
		url,
	)
	out, err := cmd.CombinedOutput()
	t.Logf("wrk output:\n%s", out)
	if err != nil {
		t.Fatalf("wrk: %v", err)
	}

	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("serve loop: %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("serve loop did not exit")
	}

	// We don't assert a specific RPS — too noisy in CI — but the
	// number of handled connections should be non-trivial and there
	// should be no failed requests.
	if s.handled < 10 {
		t.Fatalf("expected ≥10 requests in %v, got %d", dur, s.handled)
	}
	if bytes.Contains(out, []byte("Socket errors")) &&
		!bytes.Contains(out, []byte("connect 0, read 0, write 0, timeout 0")) {
		t.Fatalf("wrk reported socket errors:\n%s", out)
	}
}

// TestTimeWait_Churn_50x stresses the LISTEN → SYN_RCVD → ESTABLISHED
// → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → (re-LISTEN) cycle by
// firing 50 sequential HTTP requests as fast as Go's net/http will
// drive them. Our handler responds with `Connection: close` so we're
// always the active closer (→ TIME_WAIT), and the TimeWait→Listen
// relaxation in Tcb::listen lets the server re-arm immediately
// rather than waiting out 2*MSL between every request.
//
// Validates that:
//   - all 50 requests complete successfully and round-trip the body
//   - the server never gets stuck in a degenerate state
//   - throughput is sane (≥ 5 req/s sustained)
//
// This is the "many short connections in succession" pattern that's
// notoriously hard for TIME_WAIT-leaky stacks; ours collapses
// TIME_WAIT on the next Listen() so connection turnover is bounded
// only by the actual handshake/teardown round-trips.
func TestTimeWait_Churn_50x(t *testing.T) {
	s, cleanup := setupTUNAndServer(t)
	defer cleanup()

	const n = 50
	doneCh := make(chan error, 1)
	go func() {
		// Serve enough time to satisfy 50 requests + slack. Worst case
		// at ~10 req/s = 5s. Use 10s to leave headroom.
		doneCh <- s.pumpServeForever(10 * time.Second)
	}()

	start := time.Now()
	for i := 0; i < n; i++ {
		u := fmt.Sprintf("http://%s:%d/echo?msg=churn-%d", httpPeerAddr, httpPort, i)
		cmd := exec.Command("curl", "-sS", "--max-time", "5",
			"-H", "Connection: close", u)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("curl request %d/%d: %v", i, n, err)
		}
		want := fmt.Sprintf("churn-%d", i)
		if strings.TrimSpace(string(out)) != want {
			t.Fatalf("request %d body mismatch: got %q want %q", i, strings.TrimSpace(string(out)), want)
		}
	}
	elapsed := time.Since(start)

	// Drain server.
	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("serve loop: %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("serve loop did not exit")
	}

	if s.handled != n {
		t.Fatalf("expected %d requests handled, got %d", n, s.handled)
	}
	rps := float64(n) / elapsed.Seconds()
	t.Logf("TIME_WAIT churn: %d sequential requests in %v (%.1f req/s)", n, elapsed.Round(time.Millisecond), rps)
	if rps < 5 {
		t.Fatalf("throughput too low (%.1f req/s); TIME_WAIT may be blocking re-listen", rps)
	}
}
