// Server-mode TUN test: cdylib LISTENs on the peer side of a TUN /30
// link, the host's Linux kernel `net.Dial`s into it, and we hash-verify
// 1 GiB transferred in each direction.
//
// This is the highest-fidelity stress for the new LISTEN / SYN_RCVD
// states: the active opener is the actual production Linux TCP stack,
// with all of its retries, timestamps, SACK, and timing oddities.
//
// Requires: Linux + root (CAP_NET_ADMIN). The test self-skips otherwise.

//go:build linux

package gvisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	// Use a different port from TestAgainstLinuxKernelTUN so the two
	// don't interfere if the kernel is still draining state from the
	// previous run.
	tunServerPort = 18081

	// 1 GiB each direction. The TUN test uses larger amounts than the
	// in-memory test because the round-trip cost is essentially zero
	// (still no real wire), but we give it more wall time anyway.
	tunServerTransfer = int64(1 << 30)
	tunServerDeadline = 10 * time.Minute
)

// runBulkTransferClientN is a parametric, kernel-side analogue of
// runBulkClient (server_integration_test.go). Same shape, repeated here
// because tun_test.go and tun_server_test.go don't share a package-level
// generic helper for client-side bulk.
func runBulkTransferClientN(conn net.Conn, n int64) bulkClientResult {
	var (
		mu  sync.Mutex
		out bulkClientResult
		wg  sync.WaitGroup
	)
	setErr := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if out.err == nil {
			out.err = err
		}
	}
	wg.Add(2)

	// Reader: drain n bytes the cdylib sends (serverStreamX).
	go func() {
		defer wg.Done()
		h := sha256.New()
		buf := make([]byte, 64*1024)
		var total int64
		for total < n {
			r, err := conn.Read(buf)
			if r > 0 {
				h.Write(buf[:r])
				total += int64(r)
			}
			if err != nil {
				if errors.Is(err, io.EOF) && total == n {
					break
				}
				setErr(fmt.Errorf("kernel-client read after %d: %w", total, err))
				return
			}
		}
		mu.Lock()
		out.recvBytes = total
		out.recvHash = h.Sum(nil)
		mu.Unlock()
	}()

	// Writer: push n bytes (clientStreamX) to the cdylib.
	go func() {
		defer wg.Done()
		h := sha256.New()
		buf := make([]byte, 64*1024)
		var total int64
		for total < n {
			chunk := int64(len(buf))
			if rem := n - total; chunk > rem {
				chunk = rem
			}
			fillStream(buf[:chunk], uint64(total), clientStreamX)
			m, err := conn.Write(buf[:chunk])
			if err != nil {
				h.Write(buf[:m])
				total += int64(m)
				setErr(fmt.Errorf("kernel-client write after %d: %w", total, err))
				return
			}
			h.Write(buf[:m])
			total += int64(m)
		}
		mu.Lock()
		out.sentBytes = total
		out.sentHash = h.Sum(nil)
		mu.Unlock()
	}()

	wg.Wait()
	return out
}

func TestServerAgainstLinuxKernelTUN(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for /dev/net/tun + ip(8) + sysctl")
	}

	// Pre-clean any leftover device.
	tryRun("ip", "link", "del", tunIface)

	tun, name, err := openTun(tunIface)
	if err != nil {
		t.Fatalf("open TUN: %v", err)
	}
	defer tun.Close()
	defer tryRun("ip", "link", "del", name)

	tunFd := int(tun.Fd())

	mustRun(t, "ip", "link", "set", name, "up")
	mustRun(t, "ip", "addr", "add", fmt.Sprintf("%s/%d", tunHostAddr, tunPrefix), "dev", name)

	// Loose reverse-path / accept_local: same set as the client-side test.
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", name))
	tryRun("sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=2")
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.accept_local=1", name))

	t.Logf("TUN[%s]: %s/%d (kernel) ↔ %s (cdylib server); transfer=%d MiB",
		name, tunHostAddr, tunPrefix, tunPeerAddr, tunServerTransfer>>20)

	// --- TUN <-> cdylib pump ---
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
					if !errors.Is(err, syscall.EBADF) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.EOF) {
						t.Logf("tun read: %v", err)
					}
					return
				}
			}
			if n < 20 {
				continue
			}
			if buf[0]>>4 != 4 {
				continue
			}
			if buf[9] != 6 { // IPPROTO_TCP
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

	// cdylib server: bind tunPeerAddr:tunServerPort, LISTEN. The remote
	// is wildcarded — whichever ephemeral port the kernel chooses, the
	// listener will accept it on the first inbound SYN.
	srv, err := NewTcpHandle(parseIP4(tunPeerAddr), tunServerPort,
		parseIP4(tunHostAddr), 0,
		0xC0DEC0DE, 1000)
	if err != nil {
		t.Fatalf("init handle: %v", err)
	}
	defer srv.Free()
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Kernel-side dialer. Runs on a goroutine so the main loop can pump
	// the SYN-ACK out before the dial completes. We use a Dialer with a
	// reasonable connect timeout in case routing doesn't come up.
	cliCh := make(chan bulkClientResult, 1)
	go func() {
		dialer := net.Dialer{Timeout: 30 * time.Second}
		conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", tunPeerAddr, tunServerPort))
		if err != nil {
			cliCh <- bulkClientResult{err: fmt.Errorf("dial: %w", err)}
			return
		}
		defer conn.Close()
		cliCh <- runBulkTransferClientN(conn, tunServerTransfer)
	}()

	var (
		extractBuf [mtu]byte
		recvBuf    [32 * 1024]byte
		sendBuf    [32 * 1024]byte
		srvSentH   = sha256.New()
		srvRecvH   = sha256.New()
		srvSent    int64
		srvRecv    int64
		srvClose   bool
	)

	deadline := time.Now().Add(tunServerDeadline)
	start := time.Now()
	nextProgress := int64(64 << 20)

	for time.Now().Before(deadline) {
		progress := false

		// cdylib → TUN
		for {
			n, err := srv.ExtractPacket(extractBuf[:])
			if err != nil {
				close(stop)
				t.Fatalf("extract: %v", err)
			}
			if n == 0 {
				break
			}
			if _, werr := syscall.Write(tunFd, extractBuf[:n]); werr != nil {
				close(stop)
				t.Fatalf("tun write: %v", werr)
			}
			progress = true
		}

		// TUN → cdylib (drain non-blocking)
	drainIn:
		for {
			select {
			case pkt := <-tunIn:
				if err := srv.InjectPacket(pkt); err != nil {
					if !errors.Is(err, ErrMalformedPacket) && !errors.Is(err, ErrNotForUs) {
						close(stop)
						t.Fatalf("inject: %v", err)
					}
				}
				progress = true
			default:
				break drainIn
			}
		}

		if err := srv.Tick(); err != nil {
			close(stop)
			t.Fatalf("tick: %v", err)
		}
		st := srv.State()

		if st == StateEstablished && srvSent < tunServerTransfer {
			n := int64(len(sendBuf))
			if rem := tunServerTransfer - srvSent; n > rem {
				n = rem
			}
			fillStream(sendBuf[:n], uint64(srvSent), serverStreamX)
			written, err := srv.Send(sendBuf[:n])
			if err != nil && !errors.Is(err, ErrWouldBlock) {
				close(stop)
				t.Fatalf("send: %v", err)
			}
			if written > 0 {
				srvSentH.Write(sendBuf[:written])
				srvSent += int64(written)
				progress = true
			}
		}

		if srvRecv < tunServerTransfer {
			n, err := srv.Recv(recvBuf[:])
			if err != nil && !errors.Is(err, ErrConnectionClosed) {
				close(stop)
				t.Fatalf("recv: %v", err)
			}
			if n > 0 {
				srvRecvH.Write(recvBuf[:n])
				srvRecv += int64(n)
				progress = true
			}
		}

		if srvSent+srvRecv >= nextProgress {
			elapsed := time.Since(start).Seconds()
			t.Logf("tun-server progress: sent=%d recv=%d (%.1f MiB/s)",
				srvSent, srvRecv,
				float64(srvSent+srvRecv)/(1<<20)/elapsed)
			nextProgress = srvSent + srvRecv + (64 << 20)
		}

		if !srvClose && srvSent == tunServerTransfer && srvRecv == tunServerTransfer {
			if err := srv.Close(); err != nil {
				close(stop)
				t.Fatalf("close: %v", err)
			}
			srvClose = true
		}

		if srvClose && (st == StateTimeWait || st == StateClosed) {
			break
		}

		if !progress {
			runtime.Gosched()
		}
	}
	close(stop)

	if srvSent != tunServerTransfer {
		t.Fatalf("server sent %d/%d", srvSent, tunServerTransfer)
	}
	if srvRecv != tunServerTransfer {
		t.Fatalf("server recv %d/%d", srvRecv, tunServerTransfer)
	}
	if !srvClose {
		t.Fatal("server never closed")
	}

	srvSentSum := srvSentH.Sum(nil)
	srvRecvSum := srvRecvH.Sum(nil)

	select {
	case res := <-cliCh:
		if res.err != nil {
			t.Fatalf("kernel-client: %v", res.err)
		}
		if res.recvBytes != tunServerTransfer {
			t.Fatalf("kernel recv %d/%d", res.recvBytes, tunServerTransfer)
		}
		if res.sentBytes != tunServerTransfer {
			t.Fatalf("kernel sent %d/%d", res.sentBytes, tunServerTransfer)
		}
		if !bytes.Equal(srvSentSum, res.recvHash) {
			t.Fatalf("server→kernel hash mismatch:\n  cdylib sent: %s\n  kernel recv: %s",
				hex.EncodeToString(srvSentSum), hex.EncodeToString(res.recvHash))
		}
		if !bytes.Equal(srvRecvSum, res.sentHash) {
			t.Fatalf("kernel→server hash mismatch:\n  kernel sent: %s\n  cdylib recv: %s",
				hex.EncodeToString(res.sentHash), hex.EncodeToString(srvRecvSum))
		}
		t.Logf("LINUX KERNEL VERIFIED (cdylib=server): %d MiB each way, digests match (server=%s)",
			tunServerTransfer>>20, hex.EncodeToString(srvSentSum)[:16])
	case <-time.After(30 * time.Second):
		t.Fatal("kernel-client goroutine didn't finish")
	}

	if srvSent == 0 || srvRecv == 0 {
		t.Fatalf("no traffic flowed (sent=%d recv=%d)", srvSent, srvRecv)
	}
}
