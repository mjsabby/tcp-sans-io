//go:build linux

// tsbench: benchmark endpoint running tcp-sans-io behind a TUN device.
//
// bench.sh runs it inside the sender/receiver network namespace, so its
// traffic crosses exactly the same shaped veth (same qdiscs, same kernel
// peer) as the Linux TCP baselines it is compared with:
//
//	tsbench -mode upload   -remote 10.203.0.2:18181 -bytes N   # we send
//	tsbench -mode download -remote 10.203.0.2:18182            # we receive
//
// The host loop is event-driven (epoll on the TUN + tcp_next_deadline) and
// follows the library's host contract: the egress ring is drained after
// every call. One JSON result line is printed on stdout.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunSetIff = 0x400454CA
)

func openTun(name string) (int, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var req struct {
		Name  [16]byte
		Flags uint16
		_     [22]byte
	}
	copy(req.Name[:], name)
	req.Flags = iffTUN | iffNoPI
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&req))); e != 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", e)
	}
	return fd, syscall.SetNonblock(fd, true)
}

func run(args ...string) error {
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %v: %s", args, err, bytes.TrimSpace(out))
	}
	return nil
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "tsbench: "+format+"\n", a...)
	os.Exit(1)
}

func random32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

func main() {
	mode := flag.String("mode", "upload", "upload (send -bytes, then close) or download (receive until the peer closes)")
	tunName := flag.String("tun", "tsb0", "TUN device to create")
	tunAddr := flag.String("tun-addr", "10.203.1.1/30", "kernel-side TUN address")
	localStr := flag.String("local", "10.203.1.2", "address used by tcp-sans-io")
	remoteStr := flag.String("remote", "10.203.0.2:18181", "kernel peer ip:port")
	nbytes := flag.Int64("bytes", 64<<20, "bytes to send (upload)")
	timeout := flag.Duration("timeout", 300*time.Second, "abort after this long")
	mtu := flag.Int("mtu", 1500, "TUN MTU")
	flag.Parse()

	remote, err := netip.ParseAddrPort(*remoteStr)
	if err != nil {
		fatal("bad -remote: %v", err)
	}
	local, err := netip.ParseAddr(*localStr)
	if err != nil {
		fatal("bad -local: %v", err)
	}
	upload := *mode == "upload"
	if !upload && *mode != "download" {
		fatal("bad -mode %q", *mode)
	}

	fd, err := openTun(*tunName)
	if err != nil {
		fatal("open TUN: %v", err)
	}
	defer syscall.Close(fd)
	for _, cmd := range [][]string{
		{"sysctl", "-q", "-w", "net.ipv6.conf." + *tunName + ".disable_ipv6=1"},
		{"ip", "link", "set", "dev", *tunName, "mtu", fmt.Sprint(*mtu), "up"},
		{"ip", "addr", "add", *tunAddr, "dev", *tunName},
	} {
		if err := run(cmd...); err != nil {
			fatal("%v", err)
		}
	}

	t, err := newHandle(local.As4(), remote.Addr().As4(), uint16(32768+random32()%28000), remote.Port(), random32())
	if err != nil {
		fatal("%v", err)
	}
	defer t.free()
	var secret [16]byte
	_, _ = rand.Read(secret[:])
	if err := t.setSecret(secret); err != nil {
		fatal("%v", err)
	}

	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		fatal("epoll: %v", err)
	}
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd,
		&syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(fd)}); err != nil {
		fatal("epoll_ctl: %v", err)
	}

	var (
		rx       = make([]byte, 65536)
		tx       = make([]byte, 1500)
		app      = make([]byte, 256<<10)
		events   = make([]syscall.EpollEvent, 1)
		pktsIn   uint64
		pktsOut  uint64
		ignored  uint64
		sent     int64
		received int64
		closing  bool
		peerEOF  bool
		start    time.Time
		done     time.Time
	)
	for i := range app {
		app[i] = byte(i * 7)
	}
	flush := func() {
		for {
			n, err := t.extract(tx)
			if err != nil {
				fatal("%v", err)
			}
			if n == 0 {
				return
			}
			if _, err := syscall.Write(fd, tx[:n]); err != nil && !errors.Is(err, syscall.EAGAIN) {
				fatal("TUN write: %v", err)
			}
			pktsOut++
		}
	}

	if err := t.connect(); err != nil {
		fatal("%v", err)
	}
	flush()
	began := time.Now()
	for {
		if time.Since(began) > *timeout {
			fatal("timeout: state=%d sent=%d received=%d stats=%v", t.state(), sent, received, t.stats())
		}
		// Ingress: every datagram the kernel routed to us.
		for {
			n, err := syscall.Read(fd, rx)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) {
					break
				}
				fatal("TUN read: %v", err)
			}
			if n < 20 || rx[0]>>4 != 4 || rx[9] != syscall.IPPROTO_TCP {
				continue
			}
			pktsIn++
			ok, err := t.inject(rx[:n])
			if err != nil {
				fatal("%v", err)
			}
			if !ok {
				ignored++
			}
			flush()
		}
		st := t.state()
		if start.IsZero() && st == stateEstablished {
			start = time.Now()
		}
		// Application.
		progressed := false
		if upload {
			for sent < *nbytes {
				chunk := app[:min(int64(len(app)), *nbytes-sent)]
				n, err := t.send(chunk)
				if err != nil {
					if st == stateClosed {
						fatal("connection lost after %d bytes: stats=%v", sent, t.stats())
					}
					break
				}
				if n == 0 {
					break
				}
				sent += int64(n)
				progressed = true
			}
			if sent == *nbytes && !closing {
				if err := t.close(); err != nil {
					fatal("%v", err)
				}
				closing = true
			}
		} else if !peerEOF {
			for {
				n, err := t.recv(app)
				if errors.Is(err, errClosed) {
					peerEOF = true
					done = time.Now()
					if err := t.close(); err != nil {
						fatal("%v", err)
					}
					closing = true
					break
				}
				if err != nil {
					if st == stateClosed && received == 0 {
						fatal("connection failed: %v", err)
					}
					fatal("recv after %d bytes: %v", received, err)
				}
				if n == 0 {
					break
				}
				received += int64(n)
			}
		}
		if err := t.tick(); err != nil {
			fatal("%v", err)
		}
		flush()

		st = t.state()
		if closing && (st == stateTimeWait || st == stateClosed) {
			if upload {
				done = time.Now()
			}
			break
		}
		// Sleep until a packet arrives or the next timer is due.
		wait := 50
		if progressed {
			wait = 0
		} else if d, ok := t.nextDeadline(); ok {
			now := t.nowMs()
			if d <= now {
				wait = 0
			} else if d-now < uint64(wait) {
				wait = int(d - now)
			}
		}
		if _, err := syscall.EpollWait(epfd, events, wait); err != nil && !errors.Is(err, syscall.EINTR) {
			fatal("epoll_wait: %v", err)
		}
	}

	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	cpu := func(tv syscall.Timeval) float64 { return float64(tv.Sec) + float64(tv.Usec)/1e6 }
	moved := sent
	if !upload {
		moved = received
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"stack":    "tcp-sans-io",
		"mode":     *mode,
		"bytes":    moved,
		"secs":     done.Sub(start).Seconds(),
		"cpu_user": cpu(ru.Utime),
		"cpu_sys":  cpu(ru.Stime),
		"pkts_in":  pktsIn,
		"pkts_out": pktsOut,
		"ignored":  ignored,
		"stats":    t.stats(),
	})
}
