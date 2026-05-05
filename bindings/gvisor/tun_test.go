// Real-Linux-kernel interop test.
//
// Creates a TUN device, configures it with a /30 between a "host" address
// (the Linux kernel side) and a "peer" address (the cdylib side), then runs
// a hash-verified bidirectional bulk transfer between:
//
//   - a vanilla Go net.Listener bound to <host>:port (driven by the Linux
//     kernel's production TCP stack)
//   - the tcp-sans-io cdylib, talking to the kernel over the TUN device
//
// This is the highest-fidelity interop the test suite has: gVisor netstack
// is its own implementation with its own bugs; this exercises the actual
// stack our users will encounter.
//
// Requires: Linux + root (CAP_NET_ADMIN). The test self-skips otherwise so
// developer machines without privileges still get a clean test pass.

//go:build linux

package gvisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	tunIface    = "tcpsans0"
	tunHostAddr = "10.200.250.1" // Linux-kernel side, where the listener binds
	tunPeerAddr = "10.200.250.2" // cdylib side
	tunPrefix   = 30             // /30 covers exactly these two
	tunPort     = 18080

	// 64 MiB per direction is enough to traverse cwnd ramp + several RTOs
	// while keeping the total CI cost bounded.
	tunTransfer = int64(64 << 20)
)

// --- TUN device plumbing ----------------------------------------------------

// /usr/include/linux/if_tun.h
const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunsetIff = 0x400454CA // _IOW('T', 202, int)

	ifreqNameSize = 16
)

// ifreq matches struct ifreq for TUNSETIFF (only the first union member used).
type ifreq struct {
	Name  [ifreqNameSize]byte
	Flags uint16
	_     [22]byte // pad to sizeof(struct ifreq) = 40
}

func openTun(name string) (*os.File, string, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNoPI
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(tunsetIff),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		_ = f.Close()
		return nil, "", fmt.Errorf("TUNSETIFF: %w", errno)
	}
	return f, string(bytes.TrimRight(req.Name[:], "\x00")), nil
}

func parseIP4(s string) []byte {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return nil
	}
	out := make([]byte, 4)
	copy(out, ip)
	return out
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func tryRun(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

// --- Test -------------------------------------------------------------------

func TestAgainstLinuxKernelTUN(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for /dev/net/tun + ip(8) + sysctl")
	}

	// Pre-clean any leftover device from a crashed previous run.
	tryRun("ip", "link", "del", tunIface)

	tun, name, err := openTun(tunIface)
	if err != nil {
		t.Fatalf("open TUN: %v", err)
	}
	defer tun.Close()
	defer tryRun("ip", "link", "del", name)

	// Go's netpoller refuses /dev/net/tun on some kernels with
	// `read /dev/net/tun: not pollable`, which then poisons every
	// subsequent tun.Read/tun.Write call. Drop the fd out of the poller
	// (Fd() also clears O_NONBLOCK) and do raw blocking syscalls instead.
	tunFd := int(tun.Fd())

	// Bring the interface up and assign it the kernel-side address. The /30
	// subnet auto-installs a directly-connected route, so packets to the
	// peer address get routed onto tun0 with no further config.
	mustRun(t, "ip", "link", "set", name, "up")
	mustRun(t, "ip", "addr", "add", fmt.Sprintf("%s/%d", tunHostAddr, tunPrefix), "dev", name)

	// Loose reverse-path; accept packets sourced from local addrs delivered
	// via TUN. Failure is non-fatal — newer kernels often work without these.
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", name))
	tryRun("sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=2")
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.accept_local=1", name))

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", tunHostAddr, tunPort))
	if err != nil {
		t.Fatalf("listen on %s:%d: %v", tunHostAddr, tunPort, err)
	}
	defer listener.Close()

	t.Logf("TUN[%s]: %s/%d ↔ peer %s; transfer=%d MiB",
		name, tunHostAddr, tunPrefix, tunPeerAddr, tunTransfer>>20)

	// --- TUN <-> cdylib pump --------------------------------------------------
	//
	// One goroutine reads frames from the TUN fd into a channel; the main
	// loop drains that channel into the cdylib. Writes to TUN happen
	// synchronously after each tcp_extract_packet.

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
					// EBADF on shutdown is expected once tun.Close() runs.
					if !errors.Is(err, syscall.EBADF) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.EOF) {
						t.Logf("tun read: %v", err)
					}
					return
				}
			}
			if n < 20 {
				continue // not even an IPv4 header
			}
			// Filter to IPv4 + TCP destined for our peer.
			if buf[0]>>4 != 4 {
				continue
			}
			proto := buf[9]
			if proto != 6 { // IPPROTO_TCP
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

	// Server: matches integration_test.go's bulk server, but on a real
	// net.Conn delivered by accept().
	srvCh := make(chan bulkServerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			srvCh <- bulkServerResult{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()
		srvCh <- runBulkTransferServerN(conn, tunTransfer)
	}()

	cli, err := NewTcpHandle(parseIP4(tunPeerAddr), 49152, parseIP4(tunHostAddr), tunPort,
		0x12345678, 1000)
	if err != nil {
		t.Fatalf("init handle: %v", err)
	}
	defer cli.Free()
	if err := cli.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}

	var (
		extractBuf [mtu]byte
		recvBuf    [32 * 1024]byte
		sendBuf    [32 * 1024]byte
		cliSentH   = sha256.New()
		cliRecvH   = sha256.New()
		cliSent    int64
		cliRecv    int64
		cliClose   bool
	)

	deadline := time.Now().Add(2 * time.Minute)
	start := time.Now()
	nextProgress := int64(8 << 20)

	for time.Now().Before(deadline) {
		progress := false

		// cdylib → TUN
		for {
			n, err := cli.ExtractPacket(extractBuf[:])
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
				if err := cli.InjectPacket(pkt); err != nil {
					// Stray non-TCP / ICMP-port-unreach / fragments; ignore.
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

		if err := cli.Tick(); err != nil {
			close(stop)
			t.Fatalf("tick: %v", err)
		}
		st := cli.State()

		if st == StateEstablished && cliSent < tunTransfer {
			n := int64(len(sendBuf))
			if rem := tunTransfer - cliSent; n > rem {
				n = rem
			}
			fillStream(sendBuf[:n], uint64(cliSent), clientStreamX)
			written, err := cli.Send(sendBuf[:n])
			if err != nil && !errors.Is(err, ErrWouldBlock) {
				close(stop)
				t.Fatalf("send: %v", err)
			}
			if written > 0 {
				cliSentH.Write(sendBuf[:written])
				cliSent += int64(written)
				progress = true
			}
		}

		if cliRecv < tunTransfer {
			n, err := cli.Recv(recvBuf[:])
			if err != nil && !errors.Is(err, ErrConnectionClosed) {
				close(stop)
				t.Fatalf("recv: %v", err)
			}
			if n > 0 {
				cliRecvH.Write(recvBuf[:n])
				cliRecv += int64(n)
				progress = true
			}
		}

		if cliSent+cliRecv >= nextProgress {
			elapsed := time.Since(start).Seconds()
			t.Logf("tun progress: sent=%d recv=%d (%.1f MiB/s)",
				cliSent, cliRecv,
				float64(cliSent+cliRecv)/(1<<20)/elapsed)
			nextProgress = cliSent + cliRecv + (8 << 20)
		}

		if !cliClose && cliSent == tunTransfer && cliRecv == tunTransfer {
			if err := cli.Close(); err != nil {
				close(stop)
				t.Fatalf("close: %v", err)
			}
			cliClose = true
		}

		if cliClose && (st == StateTimeWait || st == StateClosed) {
			break
		}

		if !progress {
			runtime.Gosched()
		}
	}
	close(stop)

	if cliSent != tunTransfer {
		t.Fatalf("client sent %d/%d", cliSent, tunTransfer)
	}
	if cliRecv != tunTransfer {
		t.Fatalf("client recv %d/%d", cliRecv, tunTransfer)
	}
	if !cliClose {
		t.Fatal("client never closed")
	}

	cliSentSum := cliSentH.Sum(nil)
	cliRecvSum := cliRecvH.Sum(nil)

	select {
	case res := <-srvCh:
		if res.err != nil {
			t.Fatalf("server: %v", res.err)
		}
		if !bytes.Equal(cliSentSum, res.recvHash) {
			t.Fatalf("client→kernel hash mismatch:\n  client sent: %s\n  kernel recv: %s",
				hex.EncodeToString(cliSentSum), hex.EncodeToString(res.recvHash))
		}
		if !bytes.Equal(cliRecvSum, res.sentHash) {
			t.Fatalf("kernel→client hash mismatch:\n  kernel sent: %s\n  client recv: %s",
				hex.EncodeToString(res.sentHash), hex.EncodeToString(cliRecvSum))
		}
		t.Logf("LINUX KERNEL VERIFIED: %d MiB each way, digests match (client=%s)",
			tunTransfer>>20, hex.EncodeToString(cliSentSum)[:16])
	case <-time.After(30 * time.Second):
		t.Fatal("server goroutine didn't finish")
	}

	// Sanity check that we actually saw IPv4 packets — guards against an
	// environment where /dev/net/tun silently swallowed everything.
	_ = binary.BigEndian
	if cliSent == 0 || cliRecv == 0 {
		t.Fatalf("no traffic flowed (sent=%d recv=%d)", cliSent, cliRecv)
	}
	_ = strconv.Itoa
}

// runBulkTransferServerN is a parametric variant of runBulkServer in
// integration_test.go. We keep the original (which uses a fixed
// `transferBytes`) intact and add this one because the TUN test runs at a
// smaller size to stay inside the CI time budget.
func runBulkTransferServerN(conn net.Conn, n int64) bulkServerResult {
	var (
		mu  sync.Mutex
		out bulkServerResult
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
				setErr(fmt.Errorf("server read after %d: %w", total, err))
				return
			}
		}
		mu.Lock()
		out.recvBytes = total
		out.recvHash = h.Sum(nil)
		mu.Unlock()
	}()

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
			fillStream(buf[:chunk], uint64(total), serverStreamX)
			m, err := conn.Write(buf[:chunk])
			if err != nil {
				h.Write(buf[:m])
				total += int64(m)
				setErr(fmt.Errorf("server write after %d: %w", total, err))
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
