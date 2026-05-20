// Real `git clone https://...` through the cdylib.
//
// Reuses the same cdylibListener + TLS + http.Server stack as
// h2spec, but with a different application layer: an http handler
// that exposes a bare git repo via the "dumb HTTP" transport.
// We then spawn a real `git clone` subprocess that talks HTTPS
// to our listener and reconstructs the working tree.
//
// Why this matters: git over HTTPS is extremely chatty TCP. The
// clone protocol does many small writes (pkt-line framed),
// interleaves request and response, and reads variable-length
// packfile bodies. Subtle TCP ordering or framing bugs that pass
// h2spec / HTTP-echo may still surface here.

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
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

const (
	gitIface    = "tcpsans-git"
	gitHostAddr = "10.206.250.1"
	gitPeerAddr = "10.206.250.2"
	gitPrefix   = 30
	gitPort     = 18445
)

// setupGitListener mirrors setupH2Listener but with a distinct
// iface / IP / port so the tests don't clash with each other when
// run sequentially.
func setupGitListener(t *testing.T) (*cdylibListener, func()) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for /dev/net/tun + ip(8)")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not in PATH")
	}

	tryRun("ip", "link", "del", gitIface)
	tun, name, err := openTun(gitIface)
	if err != nil {
		t.Fatalf("open TUN: %v", err)
	}
	tunFd := int(tun.Fd())

	mustRun(t, "ip", "link", "set", name, "up")
	mustRun(t, "ip", "addr", "add", fmt.Sprintf("%s/%d", gitHostAddr, gitPrefix), "dev", name)
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", name))
	tryRun("sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=2")
	tryRun("sysctl", "-q", "-w", fmt.Sprintf("net.ipv4.conf.%s.accept_local=1", name))

	handle, err := NewTcpHandle(
		parseIP4(gitPeerAddr), gitPort,
		parseIP4(gitHostAddr), 0,
		0xFEEDD00D, 1000,
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

// createBareRepoWithSample builds a fresh bare git repo on disk
// with a few small commits, then runs `git update-server-info` so
// the repo is fetchable via dumb HTTP.
func createBareRepoWithSample(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	work := filepath.Join(tmp, "work")
	bare := filepath.Join(tmp, "repo.git")

	mustGit := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// Build a working repo + a couple of commits.
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	mustGit(work, "init", "-q", "-b", "main")
	mustGit(work, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(work, "README.md"),
		[]byte("# tcp-sans-io test repo\n\nMoved by HTTPS through our cdylib.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(work, "add", "README.md")
	mustGit(work, "commit", "-q", "-m", "initial commit")
	if err := os.WriteFile(filepath.Join(work, "hello.txt"),
		[]byte("Hello, git-over-HTTPS-over-cdylib!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(work, "add", "hello.txt")
	mustGit(work, "commit", "-q", "-m", "add hello.txt")

	// Clone as bare and prep for dumb-HTTP fetch.
	mustGit(tmp, "clone", "--bare", "-q", work, bare)
	mustGit(bare, "update-server-info")
	return bare
}

func TestGit_Clone_Over_HTTPS(t *testing.T) {
	l, cleanup := setupGitListener(t)
	defer cleanup()

	// Build a small bare repo to serve.
	bareRepo := createBareRepoWithSample(t)

	cert := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Force HTTP/1.1 to match the git "dumb HTTP" transport (no
		// HTTP/2 multiplexing for plain file fetches).
		NextProtos: []string{"http/1.1"},
	}

	// http.Handler: serve the bare repo as a static directory under
	// /repo.git. The dumb-HTTP protocol just does HTTP GETs on
	// /repo.git/info/refs, /repo.git/HEAD, /repo.git/objects/...,
	// etc., so a file server is sufficient.
	mux := http.NewServeMux()
	mux.Handle("/repo.git/", http.StripPrefix("/repo.git/", http.FileServer(http.Dir(bareRepo))))

	httpSrv := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 30 * time.Second,
	}
	// Disable keep-alive so each response closes the connection.
	// Our cdylibListener serves one connection at a time (single Tcb,
	// re-LISTEN between connections); keep-alive would hold a
	// connection open indefinitely while git tries to open another.
	httpSrv.SetKeepAlivesEnabled(false)

	tlsListener := tls.NewListener(l, tlsCfg)
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

	cloneDest := filepath.Join(t.TempDir(), "cloned")

	// git clone — disable cert verification (self-signed) and force
	// dumb HTTP (no smart pack-protocol), since our handler is a plain
	// file server.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git",
		"-c", "http.sslVerify=false",
		"-c", "http.version=HTTP/1.1",
		"clone",
		fmt.Sprintf("https://%s:%d/repo.git/", gitPeerAddr, gitPort),
		cloneDest,
	)
	cmd.Env = append(os.Environ(),
		"GIT_SMART_HTTP=0",
		"GIT_CURL_VERBOSE=0",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("git clone output:\n%s", out)
	if err != nil {
		t.Fatalf("git clone: %v", err)
	}

	// Verify the cloned content matches what we put in the source.
	got, err := os.ReadFile(filepath.Join(cloneDest, "hello.txt"))
	if err != nil {
		t.Fatalf("read cloned hello.txt: %v", err)
	}
	want := "Hello, git-over-HTTPS-over-cdylib!\n"
	if string(got) != want {
		t.Fatalf("hello.txt content mismatch:\ngot:  %q\nwant: %q", got, want)
	}

	// Verify git log shows our two commits in the clone.
	logCmd := exec.Command("git", "-C", cloneDest, "log", "--oneline", "--no-decorate")
	logOut, err := logCmd.Output()
	if err != nil {
		t.Fatalf("git log on clone: %v", err)
	}
	t.Logf("cloned git log:\n%s", logOut)
	// Two commits, each on a separate line — basic sanity.
	if n := bytesCount(logOut, '\n'); n != 2 {
		t.Fatalf("expected 2 commits in clone, got %d", n)
	}

	select {
	case err := <-srvDone:
		if err != nil {
			t.Errorf("http server: %v", err)
		}
	default:
	}
}

func bytesCount(b []byte, c byte) int {
	n := 0
	for _, x := range b {
		if x == c {
			n++
		}
	}
	return n
}
