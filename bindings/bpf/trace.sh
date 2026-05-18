#!/usr/bin/env bash
# trace.sh — wrap bpftrace, substituting the cdylib path into the
# trace_cdylib.bt template so uprobes resolve.
#
# Usage:
#   trace.sh <cdylib-path> -- <command-to-trace> [args...]
#   trace.sh <cdylib-path> --pid <pid>
#
# Example (one-shot):
#   sudo bindings/bpf/trace.sh target/release/libtcp_sans_io.so \
#       -- ./target/release/my_program
#
# Example (attach):
#   sudo bindings/bpf/trace.sh target/release/libtcp_sans_io.so \
#       --pid 12345
#
# Requires bpftrace (apt install bpftrace) and root / CAP_BPF.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <cdylib-path> [-- <command> [args...]] | [--pid <pid>]" >&2
    exit 2
fi

CDYLIB="$1"
shift

if [[ ! -f "$CDYLIB" ]]; then
    echo "error: cdylib not found: $CDYLIB" >&2
    exit 1
fi

# Resolve to absolute path so bpftrace can find it from any cwd.
CDYLIB=$(readlink -f "$CDYLIB")

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TEMPLATE="$SCRIPT_DIR/scripts/trace_cdylib.bt"
TMP_BT=$(mktemp --suffix=.bt)
trap 'rm -f "$TMP_BT"' EXIT

# Substitute LIBPATH → absolute cdylib path. Use | as delimiter since
# the path contains /.
sed "s|LIBPATH|$CDYLIB|g" "$TEMPLATE" > "$TMP_BT"

exec bpftrace "$TMP_BT" "$@"
