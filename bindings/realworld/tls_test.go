// TLS-over-cdylib interop test. The cdylib hosts a TCP listener
// through a TUN; we wrap it with Go's crypto/tls.Server (talking
// the standard TLS 1.2/1.3 protocol); a real `curl` client on the
// kernel side dials it via HTTPS.
//
// Why this is interesting: TLS hammers a TCP stack in ways that
// pure HTTP doesn't. The handshake is a tightly choreographed
// sequence of small reads and writes that's sensitive to half-
// close timing, ordering, and small-packet handling. A bulk TLS
// transfer then exercises sustained data flow with continuous
// MAC validation on each record (so any bit-flip from the TCP
// layer surfaces as a TLS alert, not silent corruption).
//
// Go's crypto/tls is a fully-fledged TLS 1.3 implementation; if
// the connection succeeds, our TCP stack handed it a clean stream
// — a strong correctness signal that subsumes a lot of conformance
// scenarios.

//go:build linux

package realworld

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	tlsIface    = "tcpsans-tls"
	tlsHostAddr = "10.204.250.1"
	tlsPeerAddr = "10.204.250.2"
	tlsPrefix   = 30
	tlsPort     = 18443
)

// cdylibConn adapts our cdylib + TUN pair to Go's net.Conn interface
// so a tls.Server (which expects a blocking Read/Write byte stream)
// can drive it.
//
// Architecture: ONE pump goroutine owns the cdylib. Concurrent
// Read/Write from external goroutines (crypto/tls does this) post
// requests on channels; the pump serves them inline with its
// extract/inject/tick loop. The shared TUN fd is owned by the pump
// (no other goroutine touches it).
type cdylibConn struct {
	srv       *TcpHandle
	tunFd     int
	tunIn     chan []byte

	readReqs  chan tlsReadReq
	writeReqs chan tlsWriteReq

	closeCh   chan struct{}
	closeOnce sync.Once
	doneCh    chan struct{} // pump exited
}

type tlsReadReq struct {
	buf  []byte
	resp chan tlsReadResp
}

type tlsReadResp struct {
	n   int
	err error
}

type tlsWriteReq struct {
	buf  []byte
	resp chan tlsWriteResp
}

type tlsWriteResp struct {
	n   int
	err error
}

// Read blocks until at least 1 byte is available, EOF, or error.
func (c *cdylibConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	resp := make(chan tlsReadResp, 1)
	select {
	case c.readReqs <- tlsReadReq{buf: p, resp: resp}:
	case <-c.doneCh:
		return 0, io.EOF
	}
	select {
	case r := <-resp:
		return r.n, r.err
	case <-c.doneCh:
		return 0, io.EOF
	}
}

// Write blocks until all bytes are accepted by the cdylib's send
// ring, EOF, or error.
func (c *cdylibConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	resp := make(chan tlsWriteResp, 1)
	select {
	case c.writeReqs <- tlsWriteReq{buf: p, resp: resp}:
	case <-c.doneCh:
		return 0, io.ErrClosedPipe
	}
	select {
	case r := <-resp:
		return r.n, r.err
	case <-c.doneCh:
		return 0, io.ErrClosedPipe
	}
}

func (c *cdylibConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	<-c.doneCh
	return nil
}

func (c *cdylibConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *cdylibConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *cdylibConn) SetDeadline(_ time.Time) error      { return nil }
func (c *cdylibConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *cdylibConn) SetWriteDeadline(_ time.Time) error { return nil }

// pump runs in its own goroutine. It serves Read / Write requests
// inline with the cdylib's extract/inject/tick loop. Exits on
// closeCh OR when the cdylib reaches a terminal state.
func (c *cdylibConn) pump() {
	defer close(c.doneCh)

	var (
		extractBuf   [mtu]byte
		recvBuf      [16 * 1024]byte
		pendingRead  *tlsReadReq
		pendingWrite *tlsWriteReq
		writtenSoFar int
		closed       bool
	)

	for !closed {
		// extract → TUN
		for {
			n, err := c.srv.ExtractPacket(extractBuf[:])
			if err != nil || n == 0 {
				break
			}
			if _, werr := syscall.Write(c.tunFd, extractBuf[:n]); werr != nil {
				closed = true
				break
			}
		}

	drainIn:
		for {
			select {
			case pkt := <-c.tunIn:
				_ = c.srv.InjectPacket(pkt)
			default:
				break drainIn
			}
		}

		_ = c.srv.Tick()

		// Pick up new read/write requests if none pending.
		if pendingRead == nil {
			select {
			case r := <-c.readReqs:
				pendingRead = &r
			default:
			}
		}
		if pendingWrite == nil {
			select {
			case w := <-c.writeReqs:
				pendingWrite = &w
				writtenSoFar = 0
			default:
			}
		}

		// Serve pending Read.
		if pendingRead != nil {
			want := len(pendingRead.buf)
			if want > len(recvBuf) {
				want = len(recvBuf)
			}
			n, err := c.srv.Recv(recvBuf[:want])
			if err != nil {
				if errors.Is(err, ErrConnectionClosed) || errors.Is(err, ErrConnectionReset) {
					pendingRead.resp <- tlsReadResp{n: 0, err: io.EOF}
					pendingRead = nil
				}
			} else if n > 0 {
				copy(pendingRead.buf, recvBuf[:n])
				pendingRead.resp <- tlsReadResp{n: n, err: nil}
				pendingRead = nil
			}
		}

		// Serve pending Write.
		if pendingWrite != nil {
			remaining := pendingWrite.buf[writtenSoFar:]
			if len(remaining) > 0 {
				n, err := c.srv.Send(remaining)
				if err != nil && !errors.Is(err, ErrWouldBlock) {
					pendingWrite.resp <- tlsWriteResp{n: writtenSoFar, err: err}
					pendingWrite = nil
				} else {
					writtenSoFar += n
					if writtenSoFar == len(pendingWrite.buf) {
						pendingWrite.resp <- tlsWriteResp{n: writtenSoFar, err: nil}
						pendingWrite = nil
					}
				}
			} else {
				pendingWrite.resp <- tlsWriteResp{n: 0, err: nil}
				pendingWrite = nil
			}
		}

		st := c.srv.State()
		if st == StateClosed {
			closed = true
		}

		select {
		case <-c.closeCh:
			if !closed && st != StateClosed && st != StateLastAck {
				_ = c.srv.Close()
			}
			closed = true
		default:
		}

		// Brief yield when idle to avoid burning CPU.
		if pendingRead == nil && pendingWrite == nil {
			time.Sleep(200 * time.Microsecond)
		}
	}

	if pendingRead != nil {
		pendingRead.resp <- tlsReadResp{n: 0, err: io.EOF}
	}
	if pendingWrite != nil {
		pendingWrite.resp <- tlsWriteResp{n: writtenSoFar, err: io.ErrClosedPipe}
	}
}

// generateSelfSignedCert returns an ECDSA P-256 self-signed cert +
// key valid for `tlsPeerAddr` for 24 hours.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tcp-sans-io test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(tlsPeerAddr)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

func setupTLSServer(t *testing.T) (*cdylibConn, func()) {
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

	tryRun("ip", "link", "del", tlsIface)

	tun, name, err := openTun(tlsIface)
	if err != nil {
		t.Fatalf("open TUN: %v", err)
	}
	tunFd := int(tun.Fd())

	mustRun(t, "ip", "link", "set", name, "up")
	mustRun(t, "ip", "addr", "add", fmt.Sprintf("%s/%d", tlsHostAddr, tlsPrefix), "dev", name)
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", name))
	tryRun("sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=2")
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.accept_local=1", name))

	srv, err := NewTcpHandle(
		parseIP4(tlsPeerAddr), tlsPort,
		parseIP4(tlsHostAddr), 0,
		0xC0FFEEEE, 1000,
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

	tunIn := make(chan []byte, 256)
	readerStop := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := syscall.Read(tunFd, buf)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				select {
				case <-readerStop:
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
			case <-readerStop:
				return
			}
		}
	}()

	conn := &cdylibConn{
		srv:       srv,
		tunFd:     tunFd,
		tunIn:     tunIn,
		readReqs:  make(chan tlsReadReq, 1),
		writeReqs: make(chan tlsWriteReq, 1),
		closeCh:   make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
	go conn.pump()

	cleanup := func() {
		_ = conn.Close()
		close(readerStop)
		srv.Free()
		_ = tun.Close()
		tryRun("ip", "link", "del", name)
	}
	return conn, cleanup
}

func TestTLS_Handshake_And_Echo(t *testing.T) {
	conn, cleanup := setupTLSServer(t)
	defer cleanup()

	cert := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsConn := tls.Server(conn, tlsCfg)

	serverDone := make(chan error, 1)
	go func() {
		defer func() {
			_ = tlsConn.Close()
		}()
		if err := tlsConn.Handshake(); err != nil {
			serverDone <- fmt.Errorf("server handshake: %v", err)
			return
		}
		// Read the curl HTTP request (we expect the whole thing in a
		// short burst).
		buf := make([]byte, 4096)
		n, err := tlsConn.Read(buf)
		if err != nil {
			serverDone <- fmt.Errorf("server read: %v", err)
			return
		}
		req := string(buf[:n])
		resp := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(req), req,
		)
		if _, err := tlsConn.Write([]byte(resp)); err != nil {
			serverDone <- fmt.Errorf("server write: %v", err)
			return
		}
		if err := tlsConn.CloseWrite(); err != nil {
			serverDone <- fmt.Errorf("server close-write: %v", err)
			return
		}
		serverDone <- nil
	}()

	u := fmt.Sprintf("https://%s:%d/echo?msg=hello-tls", tlsPeerAddr, tlsPort)
	cmd := exec.Command("curl", "-sS", "-k", "--max-time", "15", u)
	out, err := cmd.Output()
	if err != nil {
		select {
		case serr := <-serverDone:
			if serr != nil {
				t.Fatalf("client curl: %v\nserver: %v", err, serr)
			}
		default:
		}
		t.Fatalf("client curl: %v", err)
	}

	select {
	case serr := <-serverDone:
		if serr != nil {
			t.Fatalf("server: %v", serr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server goroutine did not exit")
	}

	if !bytes.Contains(out, []byte("GET /echo?msg=hello-tls HTTP/1.1")) {
		t.Fatalf("unexpected echo body (got %d bytes):\n%s", len(out), out)
	}
	t.Logf("TLS echo round-trip OK; %d-byte response", len(out))
}
