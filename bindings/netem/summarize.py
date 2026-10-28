#!/usr/bin/env python3
"""Summarize bench.sh results (JSON lines) as Markdown tables.

  summarize.py results.jsonl   tables: median goodput (min–max) and loss-
                               recovery efficiency per profile and stack
  summarize.py --line          one progress line for a result on stdin
"""

import json
import statistics
import sys

MSS = 1448


def goodput(r):
    s = r.get("server") or {}
    return s["bytes"] / 2**20 / s["secs"] if s.get("secs") else 0.0


def ours(r):
    return r["stack"].startswith("tcp-sans-io")


def sender_counters(r):
    """(retransmitted segments, RTOs) of the data sender, or None if unknown."""
    if r["dir"] == "up":
        c = r.get("client") or {}
        if ours(r):
            st = c.get("stats")
            return (st["segs_retrans"], st["rto_count"]) if st else None
        ti = c.get("tcp_info", {})
        return ti.get("total_retrans"), r["nstat_tx"].get("TcpExtTCPTimeouts")
    ti = (r.get("server") or {}).get("tcp_info", {})
    return ti.get("total_retrans"), r["nstat_rx"].get("TcpExtTCPTimeouts")


def duplicates(r):
    """Duplicate segments seen by the receiver (spurious retransmissions)."""
    if r["dir"] == "up" or not ours(r):
        ns = r["nstat_rx" if r["dir"] == "up" else "nstat_tx"]
        return ns.get("TcpExtTCPDSACKOldSent", 0) + ns.get("TcpExtTCPDSACKOfoSent", 0)
    st = (r.get("client") or {}).get("stats")
    return round(st["dup_bytes_received"] / MSS) if st else None


def line():
    r = json.loads(sys.stdin.read())
    flag = "" if r["ok"] else "  FAILED"
    print(f"  {r['profile']:<10} {r['dir']:<4} {r['stack']:<17} run {r['run']}: "
          f"{goodput(r):8.2f} MiB/s  drops {r['link']['drops']}{flag}", file=sys.stderr)


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def fmt(x, nd=0):
    if x is None:
        return "–"
    return f"{x:.{nd}f}"


def table(rows, direction):
    who = "sender" if direction == "up" else "receiver"
    print(f"\n### {'Upload: compared stack sends' if direction == 'up' else 'Download: kernel CUBIC sends, compared stack receives'}\n")
    print(f"| profile | {who} | goodput MiB/s (median, min–max) | retransmits / link drops | RTOs | dup segs at receiver | runs |")
    print("|---|---|---|---|---|---|---|")
    groups = {}
    for r in rows:
        if r["dir"] == direction:
            groups.setdefault((r["profile"], r["stack"]), []).append(r)
    for (profile, stack), rs in groups.items():
        ok = [r for r in rs if r["ok"]]
        g = [goodput(r) for r in ok]
        counters = [sender_counters(r) for r in ok]
        retx = med([c[0] for c in counters if c])
        rto = med([c[1] for c in counters if c])
        drops = med([r["link"]["drops"] for r in ok])
        dups = med([duplicates(r) for r in ok])
        span = f"{statistics.median(g):.2f} ({min(g):.2f}–{max(g):.2f})" if g else "failed"
        failed = len(rs) - len(ok)
        print(f"| {profile} | {stack} | {span} | {fmt(retx)} / {fmt(drops)} | {fmt(rto)} | "
              f"{fmt(dups)} | {len(ok)}{f' ({failed} failed)' if failed else ''} |")


def main():
    if sys.argv[1:] == ["--line"]:
        return line()
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    print("## Same-path benchmark (medians across runs)")
    for d in ("up", "down"):
        if any(r["dir"] == d for r in rows):
            table(rows, d)


if __name__ == "__main__":
    main()
