// Integration test: drive the tcp-sans-io cdylib (the client) against
// gVisor's userspace netstack (the server) over an in-memory channel link.
//
// Both sides live in the same process; packets are pumped between the
// netstack's channel.Endpoint and the cdylib's tcp_inject_packet /
// tcp_extract_packet by a small loop in the test goroutine. No sockets, no
// network namespace, no privileges.

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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	mtu        = 1500
	clientPort = 49152
	serverPort = 80
	nicID      = 1
)

var (
	clientIP = []byte{10, 0, 0, 1}
	serverIP = []byte{10, 0, 0, 2}
)

type netstackPeer struct {
	stk *stack.Stack
	ep  *channel.Endpoint
}

func newNetstackPeer(t *testing.T) *netstackPeer {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	ep := channel.New(256, mtu, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}

	addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(serverIP),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	return &netstackPeer{stk: s, ep: ep}
}

func TestAbiVersion(t *testing.T) {
	if v := AbiVersion(); v != 1 {
		t.Fatalf("ABI version = %d, want 1", v)
	}
}

// Transfer parameters for TestAgainstGvisorNetstack.
//
// Both directions move `transferBytes` of deterministic, but distinct, byte
// streams (client → server uses XOR mask 0x00, server → client uses 0xAA) so
// the resulting SHA-256 digests differ per direction and we can detect a
// crossed-streams bug immediately. The test fails unless every byte is
// transmitted in both directions and the digests on both ends agree.
const (
	transferBytes  = 1 << 30 // 1 GiB per direction (2 GiB total)
	progressEvery  = 64 << 20
	clientChunk    = 32 * 1024
	clientRecvSize = 32 * 1024
	serverChunk    = 64 * 1024
	clientStreamX  = byte(0x00)
	serverStreamX  = byte(0xAA)
	bulkDeadline   = 5 * time.Minute
)

func fillStream(buf []byte, off uint64, xor byte) {
	for i := range buf {
		buf[i] = byte(off+uint64(i)) ^ xor
	}
}

type bulkServerResult struct {
	sentHash  []byte
	recvHash  []byte
	sentBytes int64
	recvBytes int64
	err       error
}

func runBulkServer(conn net.Conn) bulkServerResult {
	var (
		mu  sync.Mutex
		out bulkServerResult
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

	// Reader: drain `transferBytes` bytes from the client, hashing as we go.
	go func() {
		defer wg.Done()
		h := sha256.New()
		buf := make([]byte, serverChunk)
		var total int64
		for total < transferBytes {
			n, err := conn.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				total += int64(n)
			}
			if err != nil {
				if errors.Is(err, io.EOF) && total == transferBytes {
					break
				}
				setErr(fmt.Errorf("server read after %d bytes: %w", total, err))
				return
			}
		}
		mu.Lock()
		out.recvBytes = total
		out.recvHash = h.Sum(nil)
		mu.Unlock()
	}()

	// Writer: push `transferBytes` bytes back to the client, hashing as we go.
	go func() {
		defer wg.Done()
		h := sha256.New()
		buf := make([]byte, serverChunk)
		var total int64
		for total < transferBytes {
			n := int64(len(buf))
			if remain := transferBytes - total; n > remain {
				n = remain
			}
			fillStream(buf[:n], uint64(total), serverStreamX)
			m, err := conn.Write(buf[:n])
			if err != nil {
				h.Write(buf[:m])
				total += int64(m)
				setErr(fmt.Errorf("server write after %d bytes: %w", total, err))
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

func TestAgainstGvisorNetstack(t *testing.T) {
	ns := newNetstackPeer(t)
	defer ns.stk.Close()

	listener, err := gonet.ListenTCP(ns.stk, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(serverIP),
		Port: serverPort,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %s", err)
	}
	defer listener.Close()

	t.Logf("starting %d-byte (%d MiB) bidirectional transfer",
		int64(transferBytes), int64(transferBytes)>>20)

	serverCh := make(chan bulkServerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverCh <- bulkServerResult{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()
		serverCh <- runBulkServer(conn)
	}()

	cli, err := NewTcpHandle(clientIP, clientPort, serverIP, serverPort, 0x10000000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Free()
	if err := cli.Connect(); err != nil {
		t.Fatal(err)
	}

	var (
		extractBuf  [mtu]byte
		recvBuf     [clientRecvSize]byte
		sendBuf     [clientChunk]byte
		cliSentH    = sha256.New()
		cliRecvH    = sha256.New()
		cliSent     int64
		cliRecv     int64
		cliClose    bool
		nextProgIn  int64 = progressEvery
		nextProgOut int64 = progressEvery
	)

	start := time.Now()
	deadline := start.Add(bulkDeadline)
	logProgress := func(label string, sent, recv int64) {
		elapsed := time.Since(start).Seconds()
		total := sent + recv
		mib := float64(total) / (1 << 20)
		t.Logf("%-7s sent=%d/%d (%.1f%%) recv=%d/%d (%.1f%%) total=%.1f MiB elapsed=%.1fs throughput=%.2f MiB/s",
			label,
			sent, int64(transferBytes), 100*float64(sent)/float64(transferBytes),
			recv, int64(transferBytes), 100*float64(recv)/float64(transferBytes),
			mib, elapsed, mib/elapsed)
	}

	for time.Now().Before(deadline) {
		progress := false

		// Drain cdylib → netstack.
		for {
			n, err := cli.ExtractPacket(extractBuf[:])
			if err != nil {
				t.Fatalf("extract: %s", err)
			}
			if n == 0 {
				break
			}
			pkt := append([]byte(nil), extractBuf[:n]...)
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			ns.ep.InjectInbound(ipv4.ProtocolNumber, pb)
			pb.DecRef()
			progress = true
		}

		// Drain netstack → cdylib.
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

		// Push as many bytes as the send ring will accept this turn.
		if st == StateEstablished && cliSent < transferBytes {
			n := int64(len(sendBuf))
			if remain := transferBytes - cliSent; n > remain {
				n = remain
			}
			fillStream(sendBuf[:n], uint64(cliSent), clientStreamX)
			written, err := cli.Send(sendBuf[:n])
			if err != nil && !errors.Is(err, ErrWouldBlock) {
				t.Fatalf("send after %d bytes: %s", cliSent, err)
			}
			if written > 0 {
				cliSentH.Write(sendBuf[:written])
				cliSent += int64(written)
				progress = true
				if cliSent >= nextProgOut {
					logProgress("[send]", cliSent, cliRecv)
					nextProgOut = cliSent + progressEvery
				}
			}
		}

		// Drain whatever has been delivered to the recv ring this turn.
		if cliRecv < transferBytes {
			n, err := cli.Recv(recvBuf[:])
			if err != nil && !errors.Is(err, ErrConnectionClosed) {
				t.Fatalf("recv after %d bytes: %s", cliRecv, err)
			}
			if n > 0 {
				cliRecvH.Write(recvBuf[:n])
				cliRecv += int64(n)
				progress = true
				if cliRecv >= nextProgIn {
					logProgress("[recv]", cliSent, cliRecv)
					nextProgIn = cliRecv + progressEvery
				}
			}
		}

		// Both directions complete → graceful close from our side.
		if !cliClose && cliSent == transferBytes && cliRecv == transferBytes {
			logProgress("[done]", cliSent, cliRecv)
			if err := cli.Close(); err != nil {
				t.Fatalf("close: %s", err)
			}
			cliClose = true
		}

		if cliClose && (st == StateTimeWait || st == StateClosed) {
			break
		}

		if !progress {
			runtime.Gosched()
		}
	}

	if cliSent != transferBytes {
		t.Fatalf("client sent %d/%d bytes", cliSent, int64(transferBytes))
	}
	if cliRecv != transferBytes {
		t.Fatalf("client recv %d/%d bytes", cliRecv, int64(transferBytes))
	}
	if !cliClose {
		t.Fatal("client never reached close handshake")
	}
	if st := cli.State(); st != StateTimeWait && st != StateClosed {
		t.Fatalf("client end state = %d, want TIME_WAIT or CLOSED", st)
	}

	cliSentSum := cliSentH.Sum(nil)
	cliRecvSum := cliRecvH.Sum(nil)

	t.Logf("client sent  %d bytes (%d MiB)  sha256=%s",
		cliSent, cliSent>>20, hex.EncodeToString(cliSentSum))
	t.Logf("client recv  %d bytes (%d MiB)  sha256=%s",
		cliRecv, cliRecv>>20, hex.EncodeToString(cliRecvSum))

	select {
	case res := <-serverCh:
		if res.err != nil {
			t.Fatalf("server: %s", res.err)
		}
		t.Logf("server recv  %d bytes (%d MiB)  sha256=%s",
			res.recvBytes, res.recvBytes>>20, hex.EncodeToString(res.recvHash))
		t.Logf("server sent  %d bytes (%d MiB)  sha256=%s",
			res.sentBytes, res.sentBytes>>20, hex.EncodeToString(res.sentHash))

		if res.recvBytes != transferBytes {
			t.Fatalf("server recv %d/%d bytes", res.recvBytes, int64(transferBytes))
		}
		if res.sentBytes != transferBytes {
			t.Fatalf("server sent %d/%d bytes", res.sentBytes, int64(transferBytes))
		}
		if !bytes.Equal(cliSentSum, res.recvHash) {
			t.Fatalf("client→server hash mismatch:\n  client sent: %s\n  server recv: %s",
				hex.EncodeToString(cliSentSum), hex.EncodeToString(res.recvHash))
		}
		if !bytes.Equal(cliRecvSum, res.sentHash) {
			t.Fatalf("server→client hash mismatch:\n  server sent: %s\n  client recv: %s",
				hex.EncodeToString(res.sentHash), hex.EncodeToString(cliRecvSum))
		}

		t.Logf("BIDIRECTIONAL VERIFIED: %d MiB each way, both digests match",
			int64(transferBytes)>>20)
	case <-time.After(30 * time.Second):
		t.Fatal("server goroutine didn't finish")
	}
}
