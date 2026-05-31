// Subprocess harness for the Rust `wgserver` binary. Spawns it, waits
// for the "ready" banner on stdout, plumbs stdout/stderr to the test
// log, and shuts it down cleanly via "shutdown\n" on stdin.

package wgserver

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// HarnessConfig configures the wgserver subprocess.
type HarnessConfig struct {
	ListenUDP     string // e.g. "127.0.0.1:9001"
	PeerUDP       string // server sends replies here — must equal driver's bound UDP addr
	ServerIP      string // e.g. "10.99.0.2"
	BasePort      uint16
	NumListeners  uint16
	CookieSecret  string // "none" | "random" | 32 hex chars
	MemoryCapMiB  uint64
	Quiet         bool
	BuildFeatures string // pass "small-buffers" for the stress build
}

// DefaultHarnessConfig returns a config suitable for adversary tests
// (single listener, cookies off).
func DefaultHarnessConfig() HarnessConfig {
	return HarnessConfig{
		ListenUDP:     "127.0.0.1:0", // placeholder — caller picks
		PeerUDP:       "127.0.0.1:0",
		ServerIP:      "10.99.0.2",
		BasePort:      30000,
		NumListeners:  1,
		CookieSecret:  "none",
		MemoryCapMiB:  4096,
		Quiet:         true,
		BuildFeatures: "small-buffers",
	}
}

// Harness owns the running subprocess.
type Harness struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	stderr     io.ReadCloser
	stdoutBuf  *bufio.Reader
	tcbSize    uint64
	logMu      sync.Mutex
	t          *testing.T
	closed     bool
	exitWaitCh chan error
}

// Spawn builds (if missing) and launches `wgserver`. Returns the
// running Harness once the "ready" banner appears on stdout.
//
// The build step looks at `bindings/wgserver-rs/target/{debug,release}/wgserver`.
// If absent, it invokes `cargo build` with `--features <cfg.BuildFeatures>`.
func Spawn(t *testing.T, cfg HarnessConfig) (*Harness, error) {
	t.Helper()
	bin, err := wgserverBinary(t, cfg.BuildFeatures)
	if err != nil {
		return nil, err
	}

	args := []string{
		"--listen-udp", cfg.ListenUDP,
		"--peer-udp", cfg.PeerUDP,
		"--server-ip", cfg.ServerIP,
		"--base-port", fmt.Sprint(cfg.BasePort),
		"--num-listeners", fmt.Sprint(cfg.NumListeners),
		"--cookies", cfg.CookieSecret,
		"--memory-cap-mib", fmt.Sprint(cfg.MemoryCapMiB),
	}
	if cfg.Quiet {
		args = append(args, "--quiet")
	}

	cmd := exec.Command(bin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start wgserver: %w", err)
	}

	h := &Harness{
		cmd:        cmd,
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		stdoutBuf:  bufio.NewReaderSize(stdout, 64*1024),
		t:          t,
		exitWaitCh: make(chan error, 1),
	}

	// Drain stderr into the test log (background).
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			h.logMu.Lock()
			t.Logf("wgserver[stderr]: %s", sc.Text())
			h.logMu.Unlock()
		}
	}()

	// Watch process exit so the test can detect crashes.
	go func() {
		h.exitWaitCh <- cmd.Wait()
	}()

	// Wait for the "ready" banner.
	readyDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(readyDeadline) {
		line, err := h.stdoutBuf.ReadString('\n')
		if err != nil {
			_ = h.Kill()
			return nil, fmt.Errorf("reading banner: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		h.logMu.Lock()
		t.Logf("wgserver[stdout]: %s", line)
		h.logMu.Unlock()
		// Banner lines look like:
		//   wgserver: tcb_size=2253856 bytes, ...
		//   wgserver: listening on udp=... ready
		if strings.Contains(line, "tcb_size=") {
			// Parse "tcb_size=NNN bytes" for the cap-projection.
			if idx := strings.Index(line, "tcb_size="); idx >= 0 {
				rest := line[idx+len("tcb_size="):]
				var n uint64
				_, _ = fmt.Sscanf(rest, "%d", &n)
				h.tcbSize = n
			}
		}
		if strings.Contains(line, "ready") {
			// Drain remaining stdout to the test log in background.
			go h.drainStdout()
			return h, nil
		}
	}
	_ = h.Kill()
	return nil, fmt.Errorf("wgserver did not become ready within 10s")
}

// drainStdout copies stdout lines to the test log until EOF.
func (h *Harness) drainStdout() {
	for {
		line, err := h.stdoutBuf.ReadString('\n')
		if line != "" {
			h.logMu.Lock()
			h.t.Logf("wgserver[stdout]: %s", strings.TrimRight(line, "\r\n"))
			h.logMu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// TcbSize returns the size_of::<Tcb>() reported in the startup banner.
func (h *Harness) TcbSize() uint64 { return h.tcbSize }

// Shutdown asks the subprocess to drain and exit. Returns the
// subprocess's exit error (nil for status 0).
func (h *Harness) Shutdown(grace time.Duration) error {
	if h.closed {
		return nil
	}
	h.closed = true
	_, _ = h.stdin.Write([]byte("shutdown\n"))
	_ = h.stdin.Close()
	select {
	case err := <-h.exitWaitCh:
		return err
	case <-time.After(grace):
		_ = h.cmd.Process.Kill()
		<-h.exitWaitCh
		return fmt.Errorf("wgserver did not exit within %v; killed", grace)
	}
}

// Kill is a hard-stop fallback.
func (h *Harness) Kill() error {
	if h.closed {
		return nil
	}
	h.closed = true
	_ = h.cmd.Process.Kill()
	<-h.exitWaitCh
	return nil
}

// wgserverBinary returns an absolute path to a built wgserver binary.
// Builds with `cargo build --release --features <features>` if absent.
func wgserverBinary(t *testing.T, features string) (string, error) {
	t.Helper()
	repoRoot, err := findRepoRoot()
	if err != nil {
		return "", err
	}
	manifest := filepath.Join(repoRoot, "bindings", "wgserver-rs", "Cargo.toml")
	if _, err := os.Stat(manifest); err != nil {
		return "", fmt.Errorf("wgserver-rs manifest not found: %w", err)
	}
	exe := "wgserver"
	if isWindowsHost() {
		exe = "wgserver.exe"
	}
	candidate := filepath.Join(repoRoot, "bindings", "wgserver-rs", "target", "release", exe)
	// If the binary already exists AND the user explicitly opted out
	// of rebuild via env, skip cargo.
	if os.Getenv("WGSERVER_NO_BUILD") != "" {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	args := []string{"build", "--release", "--manifest-path", manifest}
	if features != "" {
		args = append(args, "--features", features)
	}
	cmd := exec.Command("cargo", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	t.Logf("building wgserver: cargo %v", args)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cargo build: %w", err)
	}
	if _, err := os.Stat(candidate); err != nil {
		return "", fmt.Errorf("wgserver binary missing after build: %w", err)
	}
	return candidate, nil
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
			// Must also have `src/` and `bindings/` to be the right root.
			if _, err := os.Stat(filepath.Join(dir, "bindings")); err == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate tcp-sans-io repo root")
		}
		dir = parent
	}
}

func isWindowsHost() bool {
	return os.PathSeparator == '\\'
}
