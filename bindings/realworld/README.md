# Real-world interop tests

This package drives the `tcp-sans-io` cdylib through patterns that
real-world clients exercise — patterns that pure unit and
conformance tests don't naturally hit:

* Persistent / keep-alive *vs* connection-per-request lifecycles.
* Multiple sequential requests across LISTEN re-arm cycles.
* Real HTTP/1.1 request framing with arbitrary header sets and
  variable-length bodies.
* Slow uploaders that exercise peer-window backpressure.
* Load patterns from `wrk` (many short connections back-to-back).

The cdylib runs in LISTEN mode on the peer side of a TUN device. A
real `curl` or `wrk` on the host side dials the cdylib, exchanges
HTTP/1.1 with the in-test echo handler, and the test asserts wire
correctness on the response.

## Requirements

* Linux + root (CAP_NET_ADMIN for `/dev/net/tun` + `ip(8)`).
* `curl` in `$PATH` (always needed).
* `wrk` in `$PATH` (only `TestHTTP_Wrk_Load` skips without it).
* The cdylib built at `target/release/libtcp_sans_io.so`.

## Running

```sh
cargo build --release --lib
cd bindings/realworld
go test -c -o /tmp/http.test ./...
sudo /tmp/http.test -test.v -test.timeout=120s
```

The wrapped binary form is required because cgo + sudo don't preserve
`LD_LIBRARY_PATH` cleanly across `go test -exec sudo …`.

## Tests

| Test | What it exercises |
|---|---|
| `TestHTTP_GET_Echo_Hello` | Smallest possible round trip — GET, no body, ~50-byte response. |
| `TestHTTP_GET_Size_64KiB` | 64 KiB response body. Multi-segment send + ordered receive on real curl. |
| `TestHTTP_POST_Echo_Body` | Small POST body (~1.2 KiB). Tests request framing with `Content-Length`. |
| `TestHTTP_POST_Echo_1MiB` | 1 MiB POST body echoed back. Stresses `BUF_CAP` + multi-RTT send/recv overlap. |
| `TestHTTP_SlowClient_LimitRate` | `curl --limit-rate 100K` on a 200 KiB body. Exercises the persist-timer / peer-window backpressure path that's hard to reach in synthetic tests. |
| `TestHTTP_Sequential_Curl_3x` | Three sequential curl invocations against one TCB. Exercises the LISTEN re-arm path (`tcp_listen` from `Closed` / `TimeWait`). |
| `TestHTTP_Wrk_Load` | `wrk -c1 -d3s -H "Connection: close"`. Realistic short-connection churn: handshake, request, response, FIN exchange, re-listen, repeat. Asserts ≥10 requests handled with no socket errors. |

## Notes on the handler

The HTTP handler is intentionally minimal — `net/http.ReadRequest`
on a header buffer, then routing to a tiny set of paths:

* `GET /echo?msg=...` — body = `msg`
* `GET /size?n=...` — body = `n` deterministic bytes
* `POST /echo` — body = request body verbatim

Responses are always `Connection: close` so the test driver can
deterministically know when a connection ends (peer EOF). The serve
loop re-arms LISTEN immediately on `Closed` / `TimeWait` (relying on
the SO_REUSEADDR-style relaxation in `Tcb::listen`).
