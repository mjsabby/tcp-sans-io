// Differential test: run our cdylib client against a gVisor netstack
// server and assert SHA-256 digests match the analytic ground truth
// computed independently from the deterministic payload generator. Any
// divergence in our cdylib's wire output that the gVisor server can't
// reassemble — or that our cdylib reassembles differently — manifests
// as a hash mismatch or transfer failure here.
//
// We don't run a gvisor-vs-gvisor reference inline because two
// `channel.Endpoint`-backed stacks need link-layer resolution to dial
// each other (channel endpoints don't ship ARP), and the analytic
// digest already provides the differential ground truth.

package gvisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	diffTransferBytes = 4 << 20 // 4 MiB per direction; smaller than the bulk test
	diffServerPort    = 81
)

// expectedClientDigest hashes the deterministic stream the client sends,
// which is `fillStream(off, clientStreamX)` — the same generator the bulk
// and chaos tests use.
func expectedClientDigest(n int64) []byte {
	h := sha256.New()
	buf := make([]byte, 64*1024)
	var written int64
	for written < n {
		chunk := int64(len(buf))
		if rem := n - written; chunk > rem {
			chunk = rem
		}
		fillStream(buf[:chunk], uint64(written), clientStreamX)
		h.Write(buf[:chunk])
		written += chunk
	}
	return h.Sum(nil)
}

// expectedServerDigest hashes the deterministic stream the server sends.
func expectedServerDigest(n int64) []byte {
	h := sha256.New()
	buf := make([]byte, 64*1024)
	var written int64
	for written < n {
		chunk := int64(len(buf))
		if rem := n - written; chunk > rem {
			chunk = rem
		}
		fillStream(buf[:chunk], uint64(written), serverStreamX)
		h.Write(buf[:chunk])
		written += chunk
	}
	return h.Sum(nil)
}

// diffNetstack and pumpBetween used to live here for a gvisor-vs-gvisor
// reference run; both were removed because two channel-endpoint stacks
// can't trivially do link-layer resolution and the analytic digest
// already covers the differential ground truth.

func TestDifferentialClientBehaviour(t *testing.T) {
	if testing.Short() {
		t.Skip("differential test is slow under -short")
	}

	wantClientHash := expectedClientDigest(diffTransferBytes)
	wantServerHash := expectedServerDigest(diffTransferBytes)

	runDifferentialSubject(t, wantClientHash, wantServerHash)
}

// Subject run: our cdylib client connects to a gvisor server. Must produce
// the analytic-expected digests for both directions.
func runDifferentialSubject(t *testing.T, wantCli, wantSrv []byte) {
	ns := newNetstackPeer(t)
	defer ns.stk.Close()

	listener, err := gonet.ListenTCP(ns.stk, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(serverIP),
		Port: diffServerPort,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %s", err)
	}
	defer listener.Close()

	srvCh := make(chan bulkServerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			srvCh <- bulkServerResult{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()
		srvCh <- runBulkTransferServerN(conn, diffTransferBytes)
	}()

	cli, err := NewTcpHandle(clientIP, clientPort+1, serverIP, diffServerPort, 0xCAFE0000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Free()
	if err := cli.Connect(); err != nil {
		t.Fatal(err)
	}

	cliRecv, cliSent := runCdylibBulkTransfer(t, cli, ns, diffTransferBytes)

	srv := <-srvCh
	if srv.err != nil {
		t.Fatalf("server: %s", srv.err)
	}
	if !bytes.Equal(cliSent, wantCli) {
		t.Fatalf("[sub] client sent hash mismatch")
	}
	if !bytes.Equal(cliRecv, wantSrv) {
		t.Fatalf("[sub] client recv hash mismatch")
	}
	if !bytes.Equal(srv.recvHash, wantCli) {
		t.Fatalf("[sub] server recv hash mismatch (cdylib emitted bytes the\n"+
			"server interpreted differently from the reference run)\n want %s\n got  %s",
			hex.EncodeToString(wantCli), hex.EncodeToString(srv.recvHash))
	}
	if !bytes.Equal(srv.sentHash, wantSrv) {
		t.Fatalf("[sub] server sent hash mismatch")
	}
	t.Logf("[sub] cdylib↔gvisor OK  client=%s  server=%s — matches analytic digest",
		hex.EncodeToString(cliSent)[:16], hex.EncodeToString(srv.recvHash)[:16])
}

// runCdylibBulkTransfer runs the same pump loop as TestAgainstGvisorNetstack
// but parameterised on transfer size.
func runCdylibBulkTransfer(t *testing.T, cli *TcpHandle, ns *netstackPeer, n int64) ([]byte, []byte) {
	t.Helper()
	var (
		extractBuf [mtu]byte
		recvBuf    [32 * 1024]byte
		sendBuf    [32 * 1024]byte
		recvH      = sha256.New()
		sentH      = sha256.New()
		sent       int64
		recv       int64
		closed     bool
	)
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		progress := false

		for {
			m, err := cli.ExtractPacket(extractBuf[:])
			if err != nil {
				t.Fatalf("extract: %s", err)
			}
			if m == 0 {
				break
			}
			pkt := append([]byte(nil), extractBuf[:m]...)
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			ns.ep.InjectInbound(ipv4.ProtocolNumber, pb)
			pb.DecRef()
			progress = true
		}
		for {
			pkt := ns.ep.Read()
			if pkt == nil {
				break
			}
			view := pkt.ToView()
			if err := cli.InjectPacket(view.AsSlice()); err != nil {
				view.Release()
				pkt.DecRef()
				t.Fatalf("inject: %s", err)
			}
			view.Release()
			pkt.DecRef()
			progress = true
		}

		if err := cli.Tick(); err != nil {
			t.Fatalf("tick: %s", err)
		}
		st := cli.State()

		if st == StateEstablished && sent < n {
			c := int64(len(sendBuf))
			if rem := n - sent; c > rem {
				c = rem
			}
			fillStream(sendBuf[:c], uint64(sent), clientStreamX)
			w, err := cli.Send(sendBuf[:c])
			if err != nil && !errors.Is(err, ErrWouldBlock) {
				t.Fatalf("send: %s", err)
			}
			if w > 0 {
				sentH.Write(sendBuf[:w])
				sent += int64(w)
				progress = true
			}
		}

		if recv < n {
			r, err := cli.Recv(recvBuf[:])
			if err != nil && !errors.Is(err, ErrConnectionClosed) {
				t.Fatalf("recv: %s", err)
			}
			if r > 0 {
				recvH.Write(recvBuf[:r])
				recv += int64(r)
				progress = true
			}
		}

		if !closed && sent == n && recv == n {
			if err := cli.Close(); err != nil {
				t.Fatalf("close: %s", err)
			}
			closed = true
		}
		if closed && (st == StateTimeWait || st == StateClosed) {
			break
		}
		if !progress {
			runtime.Gosched()
		}
	}
	if sent != n || recv != n {
		t.Fatalf("incomplete: sent=%d recv=%d/%d", sent, recv, n)
	}
	return recvH.Sum(nil), sentH.Sum(nil)
}
