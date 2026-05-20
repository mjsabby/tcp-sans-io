// TUN device setup helpers for the real-world interop tests.
// Mirrors bindings/netem/bench_test.go's openTun + mustRun + tryRun
// helpers so the real-world tests can stand alone without importing
// the netem package (which has its own benchmark-specific test
// fixtures).

//go:build linux

package realworld

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

const (
	iffTUN        = 0x0001
	iffNoPI       = 0x1000
	tunsetIff     = 0x400454CA
	ifreqNameSize = 16

	mtu = 1500
)

type ifreq struct {
	Name  [ifreqNameSize]byte
	Flags uint16
	_     [22]byte
}

// openTun creates a TUN device with the given name. The returned file
// has /dev/net/tun open; the second return is the resolved interface
// name (the kernel may pick a different one if `name` is empty or
// already in use).
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
