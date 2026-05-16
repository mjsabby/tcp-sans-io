// Throughput benchmark: tcp-sans-io cdylib vs the real Linux TCP stack,
// with tc-netem injecting controlled loss / latency on the TUN device.
//
// Each TestNetem_<profile> test:
//   1. Creates a TUN device with a /30 between a host (kernel-side) and
//      peer (cdylib-side) address.
//   2. Applies a `tc qdisc add ... root netem` profile to the TUN device.
//   3. Runs a one-way bulk transfer (cdylib → kernel) over the resulting
//      lossy/laggy link.
//   4. Reports throughput in MiB/s.
//
// Requires: Linux + root (CAP_NET_ADMIN). Tests self-skip otherwise.
//
// Run all profiles with:
//   sudo -E env PATH=$PATH go test -v -timeout 300s ./bindings/netem/...
//
// Or a single profile, e.g.:
//   sudo -E env PATH=$PATH go test -v -run TestNetem_LAN_NoLoss -timeout 60s ./bindings/netem/...

//go:build linux

package netem

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	benchIface    = "tcpsans-bench"
	benchHostAddr = "10.201.250.1"
	benchPeerAddr = "10.201.250.2"
	benchPrefix   = 30
	benchPort     = 18181

	// Per-direction transfer size. 32 MiB is large enough that even at the
	// userspace cdylib's CPU-bound ~10 Mbit/s the network conditions (loss,
	// RTT) materially affect total runtime. Keeps individual runs under
	// the 90 s test timeout under healthy profiles.
	benchTransfer = int64(32 << 20)

	mtu = 1500
)

const (
	iffTUN        = 0x0001
	iffNoPI       = 0x1000
	tunsetIff     = 0x400454CA
	ifreqNameSize = 16
)

type ifreq struct {
	Name  [ifreqNameSize]byte
	Flags uint16
	_     [22]byte
}

func openTun(name string) (*os.File, string, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunsetIff), uintptr(unsafe.Pointer(&req)))
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

// netemProfile is a single tc netem configuration to apply.
type netemProfile struct {
	name string
	// args are passed verbatim after `tc qdisc add dev <iface> root netem`.
	// Empty slice means "no qdisc" (raw TUN, the baseline).
	args []string
}

// runBench drives a one-way cdylib→kernel bulk transfer of benchTransfer
// bytes over the TUN device with the given netem profile applied.
//
// Returns the wall-clock duration of the transfer and the achieved
// throughput in MiB/s.
func runBench(t *testing.T, profile netemProfile) (time.Duration, float64) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for /dev/net/tun + ip(8) + tc(8)")
	}

	tryRun("ip", "link", "del", benchIface)

	tun, name, err := openTun(benchIface)
	if err != nil {
		t.Fatalf("open TUN: %v", err)
	}
	defer tun.Close()
	defer tryRun("ip", "link", "del", name)

	tunFd := int(tun.Fd())

	mustRun(t, "ip", "link", "set", name, "up")
	mustRun(t, "ip", "addr", "add", fmt.Sprintf("%s/%d", benchHostAddr, benchPrefix), "dev", name)

	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", name))
	tryRun("sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=2")
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.accept_local=1", name))

	// Apply netem qdisc on the TUN device. netem affects packets the
	// kernel EGRESSES via this interface (i.e. server→cdylib direction).
	// To affect both directions we'd also need an ingress redirect (IFB);
	// for our one-way cdylib→kernel benchmark, single-direction is
	// sufficient because the data path runs that way and ACKs from the
	// kernel are also subject to the qdisc on their egress.
	if len(profile.args) > 0 {
		args := append([]string{"qdisc", "add", "dev", name, "root", "netem"}, profile.args...)
		mustRun(t, "tc", args...)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", benchHostAddr, benchPort))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	t.Logf("netem profile=%q: TUN[%s] %s/%d ↔ %s; transfer=%d MiB",
		profile.name, name, benchHostAddr, benchPrefix, benchPeerAddr, benchTransfer>>20)

	// Switch TUN fd to non-blocking so the main pump can poll it without
	// dedicating a goroutine and a channel — that pattern serialised
	// poorly under Go's scheduler and undersold the cdylib by ~50×.
	if err := syscall.SetNonblock(tunFd, true); err != nil {
		t.Fatalf("set nonblock: %v", err)
	}

	// Server: kernel-side sink that reads benchTransfer bytes and returns.
	srvDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			srvDone <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		var total int64
		buf := make([]byte, 32*1024)
		for total < benchTransfer {
			n, err := conn.Read(buf)
			if n > 0 {
				total += int64(n)
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				srvDone <- fmt.Errorf("read: %w (got %d)", err, total)
				return
			}
		}
		if total < benchTransfer {
			srvDone <- fmt.Errorf("short read: %d/%d", total, benchTransfer)
			return
		}
		srvDone <- nil
	}()

	cli, err := NewTcpHandle(parseIP4(benchPeerAddr), 49152, parseIP4(benchHostAddr), benchPort,
		0x12345678, 1000)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer cli.Free()
	if err := cli.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}

	var (
		extractBuf [mtu]byte
		readBuf    [mtu]byte
		sendBuf    [32 * 1024]byte
		cliSent    int64
		cliClose   bool
	)
	for i := range sendBuf {
		sendBuf[i] = byte(i & 0xFF)
	}

	deadline := time.Now().Add(120 * time.Second)
	start := time.Now()

	for time.Now().Before(deadline) {
		progress := false

		// cdylib → TUN
		for {
			n, err := cli.ExtractPacket(extractBuf[:])
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if n == 0 {
				break
			}
			if _, werr := syscall.Write(tunFd, extractBuf[:n]); werr != nil {
				t.Fatalf("tun write: %v", werr)
			}
			progress = true
		}

		// TUN → cdylib (non-blocking — drain everything that's ready)
		for {
			n, err := syscall.Read(tunFd, readBuf[:])
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					break
				}
				t.Fatalf("tun read: %v", err)
			}
			if n < 20 || readBuf[0]>>4 != 4 || readBuf[9] != 6 {
				continue // not IPv4/TCP
			}
			pkt := readBuf[:n]
			if err := cli.InjectPacket(pkt); err != nil {
				if !errors.Is(err, ErrMalformedPacket) && !errors.Is(err, ErrNotForUs) && !errors.Is(err, ErrInvalidState) {
					t.Fatalf("inject: %v", err)
				}
			}
			progress = true
		}

		if err := cli.Tick(); err != nil {
			t.Fatalf("tick: %v", err)
		}
		st := cli.State()

		if st == StateEstablished && cliSent < benchTransfer {
			n := int64(len(sendBuf))
			if rem := benchTransfer - cliSent; n > rem {
				n = rem
			}
			written, err := cli.Send(sendBuf[:n])
			if err != nil && !errors.Is(err, ErrWouldBlock) {
				t.Fatalf("send: %v", err)
			}
			if written > 0 {
				cliSent += int64(written)
				progress = true
			}
		}

		if !cliClose && cliSent == benchTransfer {
			if err := cli.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			cliClose = true
		}

		if cliClose && (st == StateTimeWait || st == StateClosed || st == StateFinWait2) {
			break
		}

		if !progress {
			runtime.Gosched()
		}
	}
	elapsed := time.Since(start)

	if cliSent != benchTransfer {
		t.Fatalf("client sent %d/%d in %v", cliSent, benchTransfer, elapsed)
	}

	select {
	case err := <-srvDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("server didn't finish")
	}

	throughputMiBs := float64(benchTransfer) / (1 << 20) / elapsed.Seconds()
	t.Logf("=== netem[%q]: %d MiB in %v → %.2f MiB/s (%.2f Mbit/s)",
		profile.name, benchTransfer>>20, elapsed.Round(time.Millisecond),
		throughputMiBs, throughputMiBs*8)
	return elapsed, throughputMiBs
}

// Suppress unused-import warning when binary.* isn't referenced (kept for
// future variants that decode IP headers).
var _ = binary.BigEndian

// --- Profiles ---------------------------------------------------------------

func TestNetem_Baseline_NoQdisc(t *testing.T) {
	runBench(t, netemProfile{name: "baseline", args: nil})
}

func TestNetem_LAN_NoLoss_1msDelay(t *testing.T) {
	// Trivial qdisc: 1 ms delay, no loss. Should be close to baseline.
	runBench(t, netemProfile{name: "1ms-no-loss", args: []string{"delay", "1ms"}})
}

func TestNetem_WAN_50msRtt_NoLoss(t *testing.T) {
	// 25 ms each way → 50 ms RTT. Exercises BUF_CAP × WS bandwidth-delay
	// product: at full window of 1 MiB and 50 ms RTT we should see ~20 MB/s
	// (160 Mbit/s) absent CPU/cgo overhead.
	runBench(t, netemProfile{name: "wan-50ms-rtt", args: []string{"delay", "25ms"}})
}

func TestNetem_Lossy_1pct(t *testing.T) {
	// 1% uniform random loss, 5 ms each way. PRR-class CC should sustain
	// meaningful throughput here; pure Tahoe would collapse to a small
	// fraction.
	runBench(t, netemProfile{name: "loss-1pct-5ms", args: []string{"loss", "1%", "delay", "5ms"}})
}

func TestNetem_HighRTT_100msEachWay(t *testing.T) {
	// 100 ms each way → effectively 100 ms perceived RTT (netem on TUN
	// root qdisc only delays kernel-egress = ACKs back to cdylib). With
	// BUF_CAP = 1 MiB the BDP ceiling is 1MiB/0.1s = 10 MiB/s = 80 Mbit/s,
	// or 4× that if the bottleneck is one-way ACK delay only.
	runBench(t, netemProfile{name: "hi-rtt-100ms", args: []string{"delay", "100ms"}})
}

func TestNetem_Lossy_5pct(t *testing.T) {
	// 5% loss is severe but representative of degraded wireless paths.
	runBench(t, netemProfile{name: "loss-5pct-5ms", args: []string{"loss", "5%", "delay", "5ms"}})
}
