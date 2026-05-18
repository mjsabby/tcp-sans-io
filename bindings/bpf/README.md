# BPF observability for tcp-sans-io

This directory provides eBPF-based tracing tools for the
tcp-sans-io cdylib. They're useful both as runtime diagnostics
(answer: "what is the host driver actually doing?") and as CI
artifacts (the GHA `perf-bench` workflow captures them on every
benchmark run).

Two distinct angles are supported:

## 1. cdylib FFI uprobes (`trace_cdylib.bt`)

Attaches `uprobe`/`uretprobe` to the public FFI entry points
exported by `libtcp_sans_io.so`:

- `tcp_inject_packet` — host→stack ingress
- `tcp_extract_packet` — stack→host egress
- `tcp_tick` — timer driver
- `tcp_send` — app→stack
- `tcp_recv` — stack→app

For each, it records:

- **Invocation count** (`@count[func]`).
- **Latency histogram** (`@ns[func]`) in nanoseconds, log2-binned.
- **Cumulative bytes** for ingress / egress (`@bytes_in`, `@bytes_out`).

The script is a template — `LIBPATH` must be replaced with the
absolute path of the cdylib before bpftrace can resolve the
uprobes. Use the bundled `trace.sh` runner which does this for
you:

```sh
sudo bindings/bpf/trace.sh target/release/libtcp_sans_io.so \
    -c "./bindings/netem/netem.test -test.run=^TestNetem_LAN_NoLoss"
```

Or attach to an already-running host program:

```sh
sudo bindings/bpf/trace.sh target/release/libtcp_sans_io.so --pid 12345
```

Press `Ctrl-C` (or wait for the child to exit) to print the
captured histograms and counters.

Requires `bpftrace` (apt: `bpftrace`) and root or `CAP_BPF`.

### Go test wrapper

`bpftrace_test.go` (build tag `bpftrace`) is a Linux-only Go test
that:

1. Builds the netem benchmark binary.
2. Wraps it in `bpftrace -c …` with the uprobes template rendered.
3. Persists the resulting trace as `bpftrace_uprobes.txt` for CI
   artifact upload.
4. Asserts the expected FFI symbols were observed (catches an
   accidental `#[no_mangle]` removal).

Run locally:

```sh
cargo build --release --lib
sudo -E env PATH=$PATH go test -v -tags bpftrace -run TestBpftraceUprobes ./bindings/bpf/
```

## 2. Kernel-side TCP comparison (`tcpretrans` etc.)

The companion piece — measuring how the **kernel's** TCP stack
behaves over the same netem profile — uses the `bpfcc-tools`
package (apt: `bpfcc-tools` or `bcc-tools` on older releases).
The `perf-bench` GHA workflow runs:

- **`tcpretrans`** during the kernel iperf3 baseline to count
  retransmits the kernel emits over each netem profile. These
  numbers serve as the apples-to-apples comparison point against
  our stack's retransmit behaviour (which the uprobe trace above
  surfaces via inject/extract counts).
- **`tcpconnlat`** for connection-establishment latency.

Both tools dump their output to text artifacts uploaded with the
workflow run.

## Interpreting the output

A healthy benchmark run looks something like:

```text
@bytes_in: 35840000
@bytes_out: 33554432

@count[extract]: 24000
@count[inject]: 23800
@count[recv]: 4
@count[send]: 4
@count[tick]: 96000

@ns[tick]:
[256, 512)         85120 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[512, 1K)           7800 |@@@@@                                               |
[1K, 2K)            2200 |@                                                   |
[2K, 4K)             450 |                                                    |
...
```

A few diagnostics:

- **`tick` count ≫ `inject`+`extract` counts**: host is over-driving
  the timer. Lower tick frequency or batch ticks.
- **`extract` latency p99 >> p50**: cache miss or hot lock somewhere
  in `maybe_send_data` — feed into a `perf record` flamegraph.
- **`bytes_out` ≪ `bytes_in`**: lots of pure-ACK egress with little
  data; expected for an unbalanced workload, surprising for bulk
  send.
- **`recv`/`send` counts low**: the host is doing few buffer-management
  calls; bytes are still flowing because the ring buffer absorbs
  bursts.
