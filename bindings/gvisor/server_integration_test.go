// Server-mode integration test: the cdylib plays the *server* (LISTEN)
// and gVisor's userspace netstack plays the active client. 1 GiB is
// transferred in each direction (2 GiB total), and the streams are
// hash-verified end-to-end — any byte change anywhere fails the test.
//
// Counterpart to TestAgainstGvisorNetstack (where the cdylib is the
// client). This direction is what stresses the new LISTEN / SYN_RCVD
// states and the bounded-half-open hardening.

package gvisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Different port from TestAgainstGvisorNetstack so `go test -count=2`
// doesn't collide with TIME_WAIT slots from the previous run.
const serverModePort = 82

// bulkClientResult mirrors bulkServerResult for the active side.
type bulkClientResult struct {
	sentHash  []byte
	recvHash  []byte
	sentBytes int64
	recvBytes int64
	err       error
}

// runBulkClient is the active-side analogue of runBulkServer. It writes
// `n` bytes (clientStreamX) and reads `n` bytes (serverStreamX) over
// `conn`, hashing both directions. The XOR mask choice keeps the
// per-direction digests identical to the client-mode test, so the same
// generator helpers (fillStream + expected{Client,Server}Digest in
// differential_test.go) are reusable.
func runBulkClient(conn net.Conn, n int64) bulkClientResult {
	var (
		mu  sync.Mutex
		out bulkClientResult
		wg  sync.WaitGroup
	)
	setErr := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if out.err == nil {
			out.err = err
		}
	}

	wg.Add(2)

	// Reader: drain n bytes the cdylib sends (serverStreamX).
	go func() {
		defer wg.Done()
		h := sha256.New()
		buf := make([]byte, serverChunk)
		var total int64
		for total < n {
			r, err := conn.Read(buf)
			if r > 0 {
				h.Write(buf[:r])
				total += int64(r)
			}
			if err != nil {
				if errors.Is(err, io.EOF) && total == n {
					break
				}
				setErr(fmt.Errorf("client read after %d bytes: %w", total, err))
				return
			}
		}
		mu.Lock()
		out.recvBytes = total
		out.recvHash = h.Sum(nil)
		mu.Unlock()
	}()

	// Writer: push n bytes (clientStreamX) to the cdylib.
	go func() {
		defer wg.Done()
		h := sha256.New()
		buf := make([]byte, serverChunk)
		var total int64
		for total < n {
			chunk := int64(len(buf))
			if rem := n - total; chunk > rem {
				chunk = rem
			}
			fillStream(buf[:chunk], uint64(total), clientStreamX)
			m, err := conn.Write(buf[:chunk])
			if err != nil {
				h.Write(buf[:m])
				total += int64(m)
				setErr(fmt.Errorf("client write after %d bytes: %w", total, err))
				return
			}
			h.Write(buf[:m])
			total += int64(m)
		}
		mu.Lock()
		out.sentBytes = total
		out.sentHash = h.Sum(nil)
		mu.Unlock()
	}()

	wg.Wait()
	return out
}

// runCdylibServerLoop drives the cdylib in LISTEN through the bulk
// transfer, returning sent/received hashes and byte counts. Mirrors the
// pump loop in TestAgainstGvisorNetstack with `Listen()` instead of
// `Connect()` and the per-direction streams swapped (cdylib now sends
// serverStreamX and reads clientStreamX).
func runCdylibServerLoop(
	t *testing.T,
	srv *TcpHandle,
	ep *channel.Endpoint,
	n int64,
) (sentHash, recvHash []byte, sentBytes, recvBytes int64) {
	t.Helper()

	var (
		extractBuf  [mtu]byte
		recvBuf     [clientRecvSize]byte
		sendBuf     [clientChunk]byte
		srvSentH    = sha256.New()
		srvRecvH    = sha256.New()
		srvSent     int64
		srvRecv     int64
		srvClose    bool
		nextProgIn  int64 = progressEvery
		nextProgOut int64 = progressEvery
	)

	start := time.Now()
	deadline := start.Add(bulkDeadline)
	logProgress := func(label string, sent, recv int64) {
		elapsed := time.Since(start).Seconds()
		mib := float64(sent+recv) / (1 << 20)
		t.Logf("%-7s sent=%d/%d (%.1f%%) recv=%d/%d (%.1f%%) total=%.1f MiB elapsed=%.1fs throughput=%.2f MiB/s",
			label,
			sent, n, 100*float64(sent)/float64(n),
			recv, n, 100*float64(recv)/float64(n),
			mib, elapsed, mib/elapsed)
	}

	for time.Now().Before(deadline) {
		progress := false

		// cdylib → netstack.
		for {
			r, err := srv.ExtractPacket(extractBuf[:])
			if err != nil {
				t.Fatalf("extract: %s", err)
			}
			if r == 0 {
				break
			}
			pkt := append([]byte(nil), extractBuf[:r]...)
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			ep.InjectInbound(ipv4.ProtocolNumber, pb)
			pb.DecRef()
			progress = true
		}

		// netstack → cdylib.
		for {
			pkt := ep.Read()
			if pkt == nil {
				break
			}
			view := pkt.ToView()
			err := srv.InjectPacket(view.AsSlice())
			view.Release()
			pkt.DecRef()
			if err != nil {
				// Listener tolerates the usual benign rejects (stray
				// non-TCP / fragments / packets for the previous slot
				// post-RST).
				if !errors.Is(err, ErrMalformedPacket) && !errors.Is(err, ErrNotForUs) {
					t.Fatalf("inject: %s", err)
				}
			}
			progress = true
		}

		if err := srv.Tick(); err != nil {
			t.Fatalf("tick: %s", err)
		}
		st := srv.State()

		if st == StateEstablished && srvSent < n {
			chunk := int64(len(sendBuf))
			if rem := n - srvSent; chunk > rem {
				chunk = rem
			}
			fillStream(sendBuf[:chunk], uint64(srvSent), serverStreamX)
			written, err := srv.Send(sendBuf[:chunk])
			if err != nil && !errors.Is(err, ErrWouldBlock) {
				t.Fatalf("send after %d bytes: %s", srvSent, err)
			}
			if written > 0 {
				srvSentH.Write(sendBuf[:written])
				srvSent += int64(written)
				progress = true
				if srvSent >= nextProgOut {
					logProgress("[send]", srvSent, srvRecv)
					nextProgOut = srvSent + progressEvery
				}
			}
		}

		if srvRecv < n {
			r, err := srv.Recv(recvBuf[:])
			if err != nil && !errors.Is(err, ErrConnectionClosed) {
				t.Fatalf("recv after %d bytes: %s", srvRecv, err)
			}
			if r > 0 {
				srvRecvH.Write(recvBuf[:r])
				srvRecv += int64(r)
				progress = true
				if srvRecv >= nextProgIn {
					logProgress("[recv]", srvSent, srvRecv)
					nextProgIn = srvRecv + progressEvery
				}
			}
		}

		if !srvClose && srvSent == n && srvRecv == n {
			logProgress("[done]", srvSent, srvRecv)
			if err := srv.Close(); err != nil {
				t.Fatalf("close: %s", err)
			}
			srvClose = true
		}

		if srvClose && (st == StateTimeWait || st == StateClosed) {
			break
		}

		if !progress {
			runtime.Gosched()
		}
	}

	return srvSentH.Sum(nil), srvRecvH.Sum(nil), srvSent, srvRecv
}

func TestServerAgainstGvisorNetstack(t *testing.T) {
	ns := newNetstackPeer(t)
	defer ns.stk.Close()

	t.Logf("starting %d-byte (%d MiB) bidirectional transfer (cdylib=server)",
		int64(transferBytes), int64(transferBytes)>>20)

	// In this test the cdylib is the *server* and gVisor's netstack is
	// the *client*. The shared NIC in newNetstackPeer is configured with
	// serverIP bound, so gVisor will source packets from serverIP. To
	// keep that NIC reuseable, we flip the cdylib's bind: it binds the
	// peer side of the link (clientIP:serverModePort), and gVisor
	// dial-targets clientIP:serverModePort from its bound serverIP.
	srv, err := NewTcpHandle(clientIP, serverModePort, serverIP, clientPort,
		0x90000000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Free()
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	// gVisor netstack does the active open. DialTCP blocks until the
	// SYN-ACK arrives, so it has to run on a goroutine while the main
	// loop pumps packets between the two sides.
	clientCh := make(chan bulkClientResult, 1)
	go func() {
		conn, err := gonet.DialTCP(ns.stk, tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.AddrFromSlice(clientIP),
			Port: serverModePort,
		}, ipv4.ProtocolNumber)
		if err != nil {
			clientCh <- bulkClientResult{err: fmt.Errorf("dial: %w", err)}
			return
		}
		defer conn.Close()
		clientCh <- runBulkClient(conn, int64(transferBytes))
	}()

	srvSent, srvRecv, srvSentBytes, srvRecvBytes := runCdylibServerLoop(
		t, srv, ns.ep, int64(transferBytes),
	)

	if srvSentBytes != transferBytes {
		t.Fatalf("cdylib server sent %d/%d", srvSentBytes, int64(transferBytes))
	}
	if srvRecvBytes != transferBytes {
		t.Fatalf("cdylib server recv %d/%d", srvRecvBytes, int64(transferBytes))
	}

	t.Logf("cdylib server sent %d MiB sha256=%s",
		srvSentBytes>>20, hex.EncodeToString(srvSent))
	t.Logf("cdylib server recv %d MiB sha256=%s",
		srvRecvBytes>>20, hex.EncodeToString(srvRecv))

	select {
	case res := <-clientCh:
		if res.err != nil {
			t.Fatalf("netstack client: %s", res.err)
		}
		if res.recvBytes != transferBytes {
			t.Fatalf("netstack recv %d/%d", res.recvBytes, int64(transferBytes))
		}
		if res.sentBytes != transferBytes {
			t.Fatalf("netstack sent %d/%d", res.sentBytes, int64(transferBytes))
		}
		if !bytes.Equal(srvSent, res.recvHash) {
			t.Fatalf("server→client hash mismatch:\n  cdylib sent : %s\n  netstack got: %s",
				hex.EncodeToString(srvSent), hex.EncodeToString(res.recvHash))
		}
		if !bytes.Equal(srvRecv, res.sentHash) {
			t.Fatalf("client→server hash mismatch:\n  netstack sent: %s\n  cdylib got   : %s",
				hex.EncodeToString(res.sentHash), hex.EncodeToString(srvRecv))
		}
		t.Logf("BIDIRECTIONAL VERIFIED (cdylib=server, gvisor=client): %d MiB each way",
			int64(transferBytes)>>20)
	case <-time.After(30 * time.Second):
		t.Fatal("netstack-client goroutine didn't finish")
	}
}
