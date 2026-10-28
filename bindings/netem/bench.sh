#!/usr/bin/env bash
# Same-path throughput benchmark: tcp-sans-io vs Linux TCP (Reno, CUBIC, ...).
#
# Topology, rebuilt from scratch for every run (no cached TCP metrics):
#
#   tsb-tx                          tsb-mid (router)             tsb-rx
#   tcp-sans-io ⇄ TUN tsb0 ─┐                                    kernel_peer.py
#     (tsbench, 10.203.1.2) ├─ tx0 ══ mid0 ─[netem]─ mid1 ══ rx0  sink / source
#   Linux TCP (10.203.0.1) ─┘        ─[netem]─                   (10.203.2.2)
#
# The bottleneck lives on the router, as in a real network: no sender learns
# of a drop from its own qdisc (a local qdisc reports overflow to Linux TCP
# synchronously, which would flatter the kernel), and tcp-sans-io's packets,
# IP-forwarded from its TUN, cross exactly the same qdiscs as the kernel
# stacks' and reach the same kernel peer, which measures goodput the same
# way for all of them. Data direction: netem delay RTT/2 + random loss +
# rate-limited bottleneck with a tail-drop queue; ACK direction: delay RTT/2.
# Offloads are off and skbs carry one segment, so netem sees (and drops)
# real MTU-sized packets for every stack.
#
# Usage (root; re-execs itself under sudo):
#   bindings/netem/bench.sh [--profiles "wan wan-1"] [--runs 3] [--dir up|down|both]
#                           [--stacks "tcp-sans-io reno cubic"]
#                           [--baseline-lib DIR] [--out results.jsonl]
#
# --baseline-lib DIR adds a "tcp-sans-io@base" stack driven by an older build
# of the library in DIR (built with `go build -tags oldabi`).
#
# TSB_PCAP=DIR captures packet headers at the receiver's interface for every
# run into DIR/<profile>-<dir>-<stack>-<run>.pcap. TSB_CPU=N picks the CPU a
# sending tcp-sans-io endpoint is pinned to (default 2). TSB_NS=PREFIX names
# the run's network namespaces (default tsb<pid>, so concurrent runs from
# different checkouts never tear down each other's path); runs on one host
# are serialized by /run/lock/tcp-sans-io-bench.lock so they do not compete
# for the link or the pinned CPU.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

# name rtt_ms rate_mbit loss_pct queue_pkts MiB
PROFILES_ALL=$(cat <<'EOF'
lan        1    1000  0     200  512
wan        40   100   0     160  128
wan-0.1    40   100   0.1   160  32
wan-1      40   100   1     160  8
metro-0.1  10   200   0.1   80   64
lossy-5    20   50    5     80   4
shallow    20   100   0     16   128
EOF
)

profiles="lan wan wan-0.1 wan-1 metro-0.1 lossy-5 shallow"
runs=3
dir=both
stacks="tcp-sans-io reno cubic"
baseline_lib=""
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profiles) profiles=$2; shift 2 ;;
        --runs) runs=$2; shift 2 ;;
        --dir) dir=$2; shift 2 ;;
        --stacks) stacks=$2; shift 2 ;;
        --baseline-lib) baseline_lib=$(cd "$2" && pwd); shift 2 ;;
        --out) out=$2; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
out=${out:-$HERE/results-$(date +%Y%m%d-%H%M%S).jsonl}

# Build the endpoint(s) as the invoking user, then become root.
if [[ $EUID -ne 0 ]]; then
    (cd "$ROOT" && cargo build --release --lib -q)
    (cd "$HERE" && go build -o "$HERE/tsbench" .)
    if [[ -n "$baseline_lib" ]]; then
        (cd "$HERE" && CGO_LDFLAGS="-L$baseline_lib -Wl,-rpath,$baseline_lib" \
            go build -tags oldabi -o "$HERE/tsbench-base" .)
    fi
    args=(--profiles "$profiles" --runs "$runs" --dir "$dir" --stacks "$stacks" --out "$out")
    [[ -n "$baseline_lib" ]] && args+=(--baseline-lib "$baseline_lib")
    exec sudo env TSB_PCAP="${TSB_PCAP:-}" TSB_CPU="${TSB_CPU:-2}" TSB_NS="${TSB_NS:-}" \
        "$0" "${args[@]}"
fi
[[ -n "$baseline_lib" ]] && stacks="$stacks tcp-sans-io@base"
[[ -x "$HERE/tsbench" ]] || { echo "build $HERE/tsbench first" >&2; exit 1; }

# One benchmark at a time per host: concurrent runs would share the CPU and
# skew each other's numbers.
exec 9>/run/lock/tcp-sans-io-bench.lock
if ! flock -n 9; then
    echo "bench.sh: waiting for another run to finish (/run/lock/tcp-sans-io-bench.lock)" >&2
    flock 9
fi
# Per-run namespace names: fixed ones let one run's teardown destroy
# another's network path mid-transfer.
NS=${TSB_NS:-tsb$$}
TX=$NS-tx MID=$NS-mid RX=$NS-rx
# Namespaces of earlier runs that died without tearing down (named
# tsb<pid>-*, pid gone). Safe under the lock.
for ns in $(ip netns list | awk '{print $1}' | grep -E '^tsb[0-9]+-(tx|mid|rx)$' || true); do
    pid=${ns#tsb}
    pid=${pid%%-*}
    kill -0 "$pid" 2>/dev/null || ip netns del "$ns" 2>/dev/null || true
done
TX_IP=10.203.0.1 RX_IP=10.203.2.2 OUR_IP=10.203.1.2
PORT=18181
TMP=$(mktemp -d /tmp/tsb.XXXXXX)
pids=()

teardown() {
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
    pids=()
    for ns in $TX $MID $RX; do ip netns del $ns 2>/dev/null || true; done
}
trap 'teardown; rm -rf "$TMP"' EXIT

veth() { # ns_a dev_a ip_a ns_b dev_b ip_b
    ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2"
    ip -n "$4" addr add "$6" dev "$5"
    for end in "$1 $2" "$4 $5"; do
        set -- $end
        # Linux TCP always builds GSO skbs and segments them *after* the
        # qdisc, so netem would drop multi-segment bursts as one packet.
        ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null
        ip -n "$1" link set dev "$2" gso_max_segs 1 up
    done
}

setup() { # rtt rate loss queue direction
    local rtt=$1 rate=$2 loss=$3 queue=$4 direction=$5
    teardown
    for ns in $TX $MID $RX; do
        ip netns add $ns
        ip -n $ns link set lo up
        for k in tcp_rmem tcp_wmem tcp_sack tcp_timestamps tcp_window_scaling tcp_ecn tcp_dsack; do
            ip netns exec $ns sysctl -q -w "net.ipv4.$k=$(sysctl -n net.ipv4.$k)"
        done
        ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 \
            net.ipv6.conf.default.disable_ipv6=1 net.ipv4.conf.all.rp_filter=0 \
            net.ipv4.conf.default.rp_filter=0
    done
    ip netns exec $TX sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec $MID sysctl -q -w net.ipv4.ip_forward=1
    veth $TX tx0 $TX_IP/30 $MID mid0 10.203.0.2/30
    veth $MID mid1 10.203.2.1/30 $RX rx0 $RX_IP/30
    ip -n $TX route add default via 10.203.0.2
    ip -n $RX route add default via 10.203.2.1
    ip -n $MID route add 10.203.1.0/30 via $TX_IP

    local data_dev=mid1 ack_dev=mid0
    [[ $direction == down ]] && data_dev=mid0 ack_dev=mid1
    DATA_NS=$MID DATA_DEV=$data_dev
    # netem holds the delay line as well as the bottleneck queue.
    local half limit
    half=$(awk -v r="$rtt" 'BEGIN { printf "%g", r / 2 }')
    limit=$(awk -v r="$rate" -v h="$half" -v q="$queue" \
        'BEGIN { printf "%d", r * 1e6 / 8 * h / 1000 / 1514 + q + 1 }')
    local lossarg=()
    [[ $loss != 0 ]] && lossarg=(loss "$loss%")
    ip netns exec $MID tc qdisc add dev $data_dev root netem \
        delay "${half}ms" "${lossarg[@]}" rate "${rate}mbit" limit "$limit"
    ip netns exec $MID tc qdisc add dev $ack_dev root netem delay "${half}ms" limit 100000
}

nstat_json() { # ns
    NSTAT_HISTORY=$TMP/nstat.$1 ip netns exec "$1" nstat -az 2>/dev/null | awk '
        $1 ~ /^(TcpRetransSegs|TcpExtTCPTimeouts|TcpExtTCPLossProbes|TcpExtTCPSackRecovery|TcpExtTCPRenoRecovery|TcpExtTCPDSACKRecv|TcpExtTCPDSACKOldSent|TcpExtTCPDSACKOfoSent|TcpExtTCPSpuriousRTOs|TcpExtTCPOFOQueue|TcpExtTCPOFODrop|TcpExtTCPRcvQDrop|IpExtInNoRoutes|IpOutDiscards)$/ {
            printf "%s\"%s\":%s", sep, $1, $2; sep="," }
        BEGIN { printf "{" } END { printf "}" }'
}

qdisc_json() {
    local q v
    q=$(ip netns exec "$DATA_NS" tc -s qdisc show dev "$DATA_DEV" | awk '
        /Sent/ { sent=$4 } /dropped/ { gsub(",", "", $7); drop=$7 }
        END { printf "\"pkts\":%d,\"drops\":%d", sent, drop }')
    v=$(for ns in $TX $MID $RX; do ip -n $ns -s -j link show; done | python3 -c '
import json, sys
d = {}
for chunk in sys.stdin.read().replace("][", "]\n[").splitlines():
    for l in json.loads(chunk):
        if l["ifname"] != "lo":
            s = l["stats64"]
            d[l["ifname"]] = [s["tx"]["dropped"], s["rx"]["dropped"]]
print(json.dumps(d))')
    printf '{%s,"dev_tx_rx_dropped":%s}' "$q" "$v"
}

wait_ready() {
    for _ in $(seq 100); do [[ -e $1 ]] && return 0; sleep 0.05; done
    echo "server did not start" >&2; return 1
}

one_run() { # profile direction stack run rtt rate loss queue mib
    local profile=$1 direction=$2 stack=$3 run=$4 rtt=$5 rate=$6 loss=$7 queue=$8 mib=$9
    local bytes=$((mib * 1024 * 1024)) srv_out=$TMP/server.json cli_out=$TMP/client.json
    setup "$rtt" "$rate" "$loss" "$queue" "$direction"
    rm -f "$TMP/ready" "$srv_out" "$cli_out"
    if [[ $direction == up ]]; then
        ip netns exec $RX python3 "$HERE/kernel_peer.py" sink --listen $RX_IP:$PORT \
            --ready "$TMP/ready" >"$srv_out" &
    else
        ip netns exec $RX python3 "$HERE/kernel_peer.py" source --listen $RX_IP:$PORT \
            --bytes $bytes --cc cubic --ready "$TMP/ready" >"$srv_out" &
    fi
    local srv=$!
    pids=($srv)
    local cap=""
    if [[ -n "${TSB_PCAP:-}" ]]; then
        mkdir -p "$TSB_PCAP"
        ip netns exec $RX tcpdump -i rx0 -s 128 -U -w \
            "$TSB_PCAP/$profile-$direction-$stack-$run.pcap" tcp 2>/dev/null &
        cap=$!
        pids+=($cap)
        sleep 0.3
    fi
    wait_ready "$TMP/ready"
    local mode=upload; [[ $direction == down ]] && mode=download
    local ok=1
    case $stack in
        tcp-sans-io|tcp-sans-io@base)
            local bin=$HERE/tsbench; [[ $stack == *@base ]] && bin=$HERE/tsbench-base
            # When sending, pin to one CPU: TUN writes from a migrating thread
            # land on different CPUs' backlogs and can be forwarded out of
            # order (reordering no Linux sender would see).
            local pin=()
            [[ $mode == upload ]] && pin=(taskset -c "${TSB_CPU:-2}")
            ip netns exec $TX "${pin[@]}" "$bin" -mode $mode -tun tsb0 \
                -tun-addr 10.203.1.1/30 -local $OUR_IP -remote $RX_IP:$PORT -bytes $bytes \
                -timeout 600s >"$cli_out" || ok=0 ;;
        *)
            if [[ $direction == up ]]; then
                ip netns exec $TX python3 "$HERE/kernel_peer.py" send --connect $RX_IP:$PORT \
                    --bytes $bytes --cc "$stack" >"$cli_out" || ok=0
            else
                ip netns exec $TX python3 "$HERE/kernel_peer.py" recv --connect $RX_IP:$PORT \
                    >"$cli_out" || ok=0
            fi ;;
    esac
    wait $srv || ok=0
    if [[ -n "$cap" ]]; then
        sleep 0.2
        kill -INT "$cap" 2>/dev/null || true
        wait "$cap" 2>/dev/null || true
    fi
    pids=()
    local link tx_ns rx_ns
    link=$(qdisc_json); tx_ns=$(nstat_json $TX); rx_ns=$(nstat_json $RX)
    printf '{"profile":"%s","dir":"%s","stack":"%s","run":%d,"ok":%d,"rtt_ms":%s,"rate_mbit":%s,"loss_pct":%s,"queue_pkts":%s,"server":%s,"client":%s,"link":%s,"nstat_tx":%s,"nstat_rx":%s}\n' \
        "$profile" "$direction" "$stack" "$run" "$ok" "$rtt" "$rate" "$loss" "$queue" \
        "$(cat "$srv_out" 2>/dev/null || echo null)" "$(cat "$cli_out" 2>/dev/null || echo null)" \
        "$link" "$tx_ns" "$rx_ns" | tee -a "$out" | python3 "$HERE/summarize.py" --line
}

directions=()
case $dir in up) directions=(up) ;; down) directions=(down) ;; both) directions=(up down) ;; esac
: >"$out"
for profile in $profiles; do
    read -r name rtt rate loss queue mib < <(awk -v p="$profile" '$1 == p' <<<"$PROFILES_ALL")
    [[ -n "${name:-}" ]] || { echo "unknown profile $profile" >&2; exit 2; }
    for direction in "${directions[@]}"; do
        for run in $(seq "$runs"); do
            # Download compares receivers (the kernel sender is CUBIC):
            # tcp-sans-io builds against the Linux receiver.
            set -- $stacks
            [[ $direction == down ]] && set -- $(printf '%s\n' $stacks | grep '^tcp-sans-io') linux
            for stack in "$@"; do
                one_run "$name" "$direction" "$stack" "$run" "$rtt" "$rate" "$loss" "$queue" "$mib"
            done
        done
    done
done
python3 "$HERE/summarize.py" "$out"
echo "raw results: $out"
