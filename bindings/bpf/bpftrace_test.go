// Optional BPF trace test: runs the bpftrace uprobes against the
// tcp-sans-io cdylib while it drives a short netem benchmark, then
// asserts that the expected FFI functions were observed at non-zero
// rates. Skips unless run as root on Linux with bpftrace available.
//
// This is intentionally a coarse sanity check (not a strict perf
// assertion) — the goal is to:
//
//   1. Verify the cdylib exports the symbols bpftrace expects to
//      uprobe (catches accidental removal of #[no_mangle] etc).
//   2. Confirm the host driver is actually calling the FFI in a
//      reasonable pattern (e.g. many inject/extract calls, some
//      tick calls).
//   3. Produce a textual trace artifact that CI can upload for
//      offline inspection.
//
// Run locally with:
//   sudo -E env PATH=$PATH go test -v -tags bpftrace -run TestBpftraceUprobes ./bindings/bpf/

//go:build linux && bpftrace

package bpf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBpftraceUprobes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for bpftrace + TUN benchmark")
	}
	if _, err := exec.LookPath("bpftrace"); err != nil {
		t.Skip("bpftrace not installed")
	}

	// Resolve cdylib path. Test runs from bindings/bpf/.
	cdylib, err := filepath.Abs("../../target/release/libtcp_sans_io.so")
	if err != nil {
		t.Fatalf("resolve cdylib path: %v", err)
	}
	if _, err := os.Stat(cdylib); err != nil {
		t.Fatalf("cdylib not built (%s): %v — run `cargo build --release --lib` first", cdylib, err)
	}

	// Build the netem test binary (host of the cdylib).
	netemBin, err := filepath.Abs("../netem")
	if err != nil {
		t.Fatalf("resolve netem dir: %v", err)
	}
	binPath := filepath.Join(t.TempDir(), "netem.test")
	build := exec.Command("go", "test", "-c", "-o", binPath, "./...")
	build.Dir = netemBin
	build.Env = append(os.Environ(),
		"CGO_LDFLAGS=-L"+filepath.Dir(cdylib)+" -ltcp_sans_io -Wl,-rpath,"+filepath.Dir(cdylib),
	)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build netem.test: %v\n%s", err, out)
	}

	// Render the bpftrace template with the absolute cdylib path.
	tpl, err := os.ReadFile("scripts/trace_cdylib.bt")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	bt := strings.ReplaceAll(string(tpl), "LIBPATH", cdylib)
	btPath := filepath.Join(t.TempDir(), "trace.bt")
	if err := os.WriteFile(btPath, []byte(bt), 0o644); err != nil {
		t.Fatalf("write rendered bpftrace: %v", err)
	}

	// Run bpftrace as the parent, with the netem benchmark as the
	// traced child via `-c`. bpftrace attaches uprobes before exec,
	// runs the child to completion, then prints maps + exits.
	//
	// The benchmark profile is selectable via TCPSANSIO_BPF_PROFILE so
	// the CI workflow can keep the uprobe trace in sync with whichever
	// netem profile the perf-bench run is targeting.
	profile := os.Getenv("TCPSANSIO_BPF_PROFILE")
	if profile == "" {
		profile = "LAN_NoLoss_1msDelay"
	}
	runArg := fmt.Sprintf("^TestNetem_%s$", profile)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bpftrace", btPath,
		"-c", binPath+" -test.v -test.timeout=90s -test.run="+runArg,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bpftrace: %v\n%s", err, out)
	}

	// Persist the trace output as an artifact (relative to CWD so CI
	// can find it).
	artifact := "bpftrace_uprobes.txt"
	if err := os.WriteFile(artifact, out, 0o644); err != nil {
		t.Logf("warning: failed to write %s: %v", artifact, err)
	} else {
		t.Logf("wrote trace artifact: %s (%d bytes)", artifact, len(out))
	}

	// Sanity-check: the netem benchmark should have driven the cdylib
	// hard enough that each major FFI function was called many times.
	// We're not asserting exact numbers — just that the symbols
	// resolved and the host loop is exercising them.
	output := string(out)
	want := []string{
		`@count[inject]`,
		`@count[extract]`,
		`@count[tick]`,
	}
	for _, k := range want {
		if !strings.Contains(output, k) {
			t.Errorf("expected bpftrace output to contain %q, got:\n%s", k, output)
		}
	}
	// At least one bytes_in entry: the benchmark sends back and forth
	// at least the handshake worth of bytes.
	if !strings.Contains(output, "@bytes_in") && !strings.Contains(output, "@bytes_out") {
		t.Errorf("expected @bytes_in or @bytes_out counter, got:\n%s", output)
	}

	// First-line summary so the test log is readable.
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "@count[") || strings.HasPrefix(line, "@bytes_") {
			t.Log(line)
		}
	}
}
