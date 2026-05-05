// Adversarial-channel test: hash-verified bidirectional bulk transfer
// (same payload generators as integration_test.go) with a deterministic
// chaos layer — loss, reorder, duplication, latency jitter, single-bit
// corruption — inserted on BOTH directions of the cdylib ⇄ gVisor
// channel. Each profile runs the transfer end-to-end and asserts SHA-256
// digests match — any byte change anywhere is a fatal protocol error.
//
// Both directions are exercised: gVisor's full TCP reassembler absorbs
// outbound chaos, and the cdylib's single-hole reassembly buffer absorbs
// inbound chaos. Pathological loss patterns that overflow the single
// hole fall back to per-RTO retransmission — slow but correct.
//
// All randomness is seeded from the profile's name so failures reproduce
// byte-for-byte.

package gvisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Chaos profile: probabilities are 0.0 .. 1.0; latency parameters are millis.
type chaosProfile struct {
	name string
	// Per-direction independent hazards.
	dropProb     float64 // outright drop
	dupProb      float64 // emit twice (after a small delay)
	reorderProb  float64 // hold this packet, release it after the next one
	corruptProb  float64 // flip a single bit in the payload (must trigger checksum reject)
	jitterMaxMs  int     // uniform 0..jitterMaxMs delay added to every packet
	transferSize int64
}

// Defaults are deliberately small. With initial RTO clamped to 200 ms
// by the cdylib's RTO_MIN_MS, every drop that doesn't fast-retransmit
// costs >=200 ms with exponential backoff. 1 MiB at MSS=1460 is ~720
// segments, which gives every profile enough events to exercise
// recovery without risking a CI timeout.
const chaosTransferDefault int64 = 1 << 20 // 1 MiB

func bulkSizeFor(p chaosProfile) int64 {
	if p.transferSize > 0 {
		return p.transferSize
	}
	return chaosTransferDefault
}

var chaosProfiles = []chaosProfile{
	{name: "loss-1pct", dropProb: 0.01},
	{name: "loss-5pct", dropProb: 0.05},
	{name: "reorder-2pct", reorderProb: 0.02},
	{name: "dup-1pct", dupProb: 0.01},
	{name: "jitter-20ms", jitterMaxMs: 20},
	{name: "corrupt-0p5pct", corruptProb: 0.005},
	{
		name: "kitchen-sink",
		// Light combination of every hazard. Aggressive enough that the
		// transfer takes real recovery work, gentle enough to finish.
		dropProb:    0.005,
		dupProb:     0.005,
		reorderProb: 0.005,
		corruptProb: 0.002,
		jitterMaxMs: 10,
	},
}

// timed packet: emitted at or after `releaseAt`.
type timedPacket struct {
	releaseAt time.Time
	data      []byte
}

// chaosQueue is a min-heap keyed by releaseAt. We hand-roll the heap rather
// than use container/heap so the inline call-site stays readable; in either
// case we want O(log n) push/pop, not the O(n log n) of sort.Slice — which
// matters once `jitter-Nms` profiles park ~50 items at once.
type chaosQueue struct {
	items []timedPacket
}

func (q *chaosQueue) Len() int { return len(q.items) }

func (q *chaosQueue) push(t time.Time, b []byte) {
	q.items = append(q.items, timedPacket{releaseAt: t, data: b})
	// sift up
	i := len(q.items) - 1
	for i > 0 {
		parent := (i - 1) / 2
		if !q.items[i].releaseAt.Before(q.items[parent].releaseAt) {
			break
		}
		q.items[i], q.items[parent] = q.items[parent], q.items[i]
		i = parent
	}
}

func (q *chaosQueue) popMin() timedPacket {
	out := q.items[0]
	last := len(q.items) - 1
	q.items[0] = q.items[last]
	q.items = q.items[:last]
	// sift down
	i, n := 0, len(q.items)
	for {
		l, r := 2*i+1, 2*i+2
		smallest := i
		if l < n && q.items[l].releaseAt.Before(q.items[smallest].releaseAt) {
			smallest = l
		}
		if r < n && q.items[r].releaseAt.Before(q.items[smallest].releaseAt) {
			smallest = r
		}
		if smallest == i {
			break
		}
		q.items[i], q.items[smallest] = q.items[smallest], q.items[i]
		i = smallest
	}
	return out
}

// drainReady pops everything whose releaseAt <= now (in priority order).
func (q *chaosQueue) drainReady(now time.Time) [][]byte {
	var out [][]byte
	for len(q.items) > 0 && !q.items[0].releaseAt.After(now) {
		out = append(out, q.popMin().data)
	}
	return out
}

// chaos applies the profile's hazards to a single packet and pushes 0..2
// resulting packets into `q` with appropriate release times.
//
// Returns the number of "successful sends" (i.e. non-dropped) for stats.
func chaos(rng *rand.Rand, p chaosProfile, q *chaosQueue, pkt []byte, now time.Time) int {
	if rng.Float64() < p.dropProb {
		return 0
	}

	jitter := time.Duration(0)
	if p.jitterMaxMs > 0 {
		jitter = time.Duration(rng.IntN(p.jitterMaxMs+1)) * time.Millisecond
	}
	release := now.Add(jitter)

	if rng.Float64() < p.reorderProb {
		// Reorder by delaying this packet beyond the max possible jitter
		// of subsequent packets so they overtake it. The held-slot design
		// (stash, release on next packet) deadlocks if the reordered
		// packet happens to be the *last* one in this direction (e.g.
		// gvisor's tail segment, or the cdylib's final ACK after gvisor
		// backs off): no follow-up ever arrives to drain the slot. Queue
		// it now with a generous pad so it is guaranteed to drain.
		pad := time.Duration(p.jitterMaxMs+5+rng.IntN(10)) * time.Millisecond
		q.push(now.Add(pad), append([]byte(nil), pkt...))
		return 1
	}

	if rng.Float64() < p.corruptProb {
		// Flip one bit in the IP/TCP region. Checksum validation in the
		// cdylib (or gVisor) MUST drop this — corruption that survives is a
		// fatal protocol error.
		mut := append([]byte(nil), pkt...)
		idx := rng.IntN(len(mut))
		mut[idx] ^= 1 << uint(rng.IntN(8))
		q.push(release, mut)
		return 1
	}

	cp := append([]byte(nil), pkt...)
	q.push(release, cp)

	if rng.Float64() < p.dupProb {
		dupRelease := release.Add(time.Duration(rng.IntN(p.jitterMaxMs+1)+1) * time.Millisecond)
		q.push(dupRelease, append([]byte(nil), pkt...))
		return 1
	}
	return 1
}

func seedFor(name string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(name))
	return h.Sum64()
}

func TestAgainstGvisorWithChaos(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos matrix is slow; skipped under -short")
	}
	for _, p := range chaosProfiles {
		p := p
		t.Run(p.name, func(t *testing.T) { runChaosTransfer(t, p) })
	}
}

func runChaosTransfer(t *testing.T, p chaosProfile) {
	t.Helper()
	transfer := bulkSizeFor(p)

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

	t.Logf("chaos[%s]: transfer=%d KiB drop=%.3f dup=%.3f reorder=%.3f corrupt=%.3f jitter=%dms",
		p.name, transfer>>10, p.dropProb, p.dupProb, p.reorderProb, p.corruptProb, p.jitterMaxMs)

	type srvRes struct {
		recvHash, sentHash []byte
		recvN, sentN       int64
		err                error
	}
	srvCh := make(chan srvRes, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			srvCh <- srvRes{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()

		var (
			res srvRes
			mu  sync.Mutex
			wg  sync.WaitGroup
		)
		setErr := func(err error) {
			mu.Lock()
			if res.err == nil {
				res.err = err
			}
			mu.Unlock()
		}
		wg.Add(2)

		// Reader.
		go func() {
			defer wg.Done()
			h := sha256.New()
			buf := make([]byte, 64*1024)
			var total int64
			for total < transfer {
				n, err := conn.Read(buf)
				if n > 0 {
					h.Write(buf[:n])
					total += int64(n)
				}
				if err != nil {
					setErr(fmt.Errorf("server read after %d: %w", total, err))
					return
				}
			}
			res.recvN = total
			res.recvHash = h.Sum(nil)
		}()

		// Writer.
		go func() {
			defer wg.Done()
			h := sha256.New()
			buf := make([]byte, 64*1024)
			var total int64
			for total < transfer {
				n := int64(len(buf))
				if rem := transfer - total; n > rem {
					n = rem
				}
				fillStream(buf[:n], uint64(total), serverStreamX)
				m, err := conn.Write(buf[:n])
				if err != nil {
					setErr(fmt.Errorf("server write after %d: %w", total+int64(m), err))
					return
				}
				h.Write(buf[:m])
				total += int64(m)
			}
			res.sentN = total
			res.sentHash = h.Sum(nil)
		}()

		wg.Wait()
		srvCh <- res
	}()

	cli, err := NewTcpHandle(clientIP, clientPort, serverIP, serverPort, 0x10000000, 200)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Free()
	if err := cli.Connect(); err != nil {
		t.Fatal(err)
	}

	// Two independent chaos rngs (one per direction) keyed off the
	// profile name so failures are deterministic per profile.
	seed := seedFor(p.name)
	outRng := rand.New(rand.NewPCG(seed, 0xC1A05))
	inRng := rand.New(rand.NewPCG(seed, 0x10AD))
	var outQ, inQ chaosQueue

	var (
		extractBuf [mtu]byte
		recvBuf    [32 * 1024]byte
		sendBuf    [32 * 1024]byte
		cliSentH   = sha256.New()
		cliRecvH   = sha256.New()
		cliSent    int64
		cliRecv    int64
		cliClose   bool
	)

	// 90 s per profile is much more than any of these configured
	// profiles need at 1 MiB unidirectional chaos. Realistic per-profile
	// runtime is 5–30 s; the budget is generous so a slow CI runner can
	// still pass without flake.
	start := time.Now()
	deadline := start.Add(90 * time.Second)
	nextLog := start.Add(15 * time.Second)

	for time.Now().Before(deadline) {
		now := time.Now()
		progress := false

		if now.After(nextLog) {
			snap := cli.DebugSnapshot()
			t.Logf("chaos[%s] progress: sent=%d/%d recv=%d/%d state=%d outQ=%d inQ=%d\n  cdylib: snd_una=%d snd_nxt=%d snd_wnd=%d rcv_nxt=%d cwnd=%d ssthresh=%d rto_ms=%d rto_dl=%d now=%d send_ring=%d recv_ring=%d oo_start=%d oo_len=%d tx_len=%d pending_ack=%t dup_acks=%d",
				p.name, cliSent, transfer, cliRecv, transfer, cli.State(),
				outQ.Len(), inQ.Len(),
				snap.SndUna, snap.SndNxt, snap.SndWnd, snap.RcvNxt,
				snap.Cwnd, snap.Ssthresh, snap.RtoMs, snap.RtoDeadline, snap.NowMs,
				snap.SendRingLen, snap.RecvRingLen, snap.OoStart, snap.OoLen,
				snap.TxLen, snap.PendingAck, snap.DupAckCount)
			nextLog = now.Add(15 * time.Second)
		}

		// Drain cdylib → chaos out queue. We loop tick+extract so the
		// cdylib's single-slot tx_buf doesn't starve us — each extract
		// frees the slot for the next staged segment.
		for {
			if err := cli.Tick(); err != nil {
				t.Fatalf("tick: %s", err)
			}
			n, err := cli.ExtractPacket(extractBuf[:])
			if err != nil {
				t.Fatalf("extract: %s", err)
			}
			if n == 0 {
				break
			}
			pkt := append([]byte(nil), extractBuf[:n]...)
			chaos(outRng, p, &outQ, pkt, now)
			progress = true
		}
		// Release outbound packets whose time has come into netstack.
		for _, pkt := range outQ.drainReady(now) {
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			ns.ep.InjectInbound(ipv4.ProtocolNumber, pb)
			pb.DecRef()
			progress = true
		}

		// Drain netstack → chaos in queue.
		for {
			pkt := ns.ep.Read()
			if pkt == nil {
				break
			}
			view := pkt.ToView()
			data := append([]byte(nil), view.AsSlice()...)
			view.Release()
			pkt.DecRef()
			chaos(inRng, p, &inQ, data, now)
			progress = true
		}
		// Release inbound packets whose time has come into the cdylib.
		// After each inject we immediately drain any staged response so
		// subsequent injects can also stage their own ACK / data segments.
		for _, pkt := range inQ.drainReady(now) {
			if err := cli.InjectPacket(pkt); err != nil {
				// Expected on corrupted/non-TCP frames (recovered via
				// retransmission) or on packets arriving after the cdylib
				// has reached CLOSED — late chaos packets following a
				// post-FIN RST are physically realistic and benign.
				if errors.Is(err, ErrMalformedPacket) ||
					errors.Is(err, ErrNotForUs) ||
					errors.Is(err, ErrInvalidState) {
					continue
				}
				t.Fatalf("inject: %s", err)
			}
			progress = true
			// Per-inject extract: pull the response immediately so the
			// next inject's emit_segment isn't blocked by tx_len > 0.
			for {
				n, err := cli.ExtractPacket(extractBuf[:])
				if err != nil {
					t.Fatalf("extract: %s", err)
				}
				if n == 0 {
					break
				}
				out := append([]byte(nil), extractBuf[:n]...)
				chaos(outRng, p, &outQ, out, now)
			}
		}

		st := cli.State()

		if st == StateEstablished && cliSent < transfer {
			n := int64(len(sendBuf))
			if rem := transfer - cliSent; n > rem {
				n = rem
			}
			fillStream(sendBuf[:n], uint64(cliSent), clientStreamX)
			written, err := cli.Send(sendBuf[:n])
			if err != nil && !errors.Is(err, ErrWouldBlock) {
				t.Fatalf("send after %d: %s", cliSent, err)
			}
			if written > 0 {
				cliSentH.Write(sendBuf[:written])
				cliSent += int64(written)
				progress = true
			}
		}

		if cliRecv < transfer {
			n, err := cli.Recv(recvBuf[:])
			if err != nil && !errors.Is(err, ErrConnectionClosed) {
				t.Fatalf("recv after %d: %s", cliRecv, err)
			}
			if n > 0 {
				cliRecvH.Write(recvBuf[:n])
				cliRecv += int64(n)
				progress = true
			}
		}

		if !cliClose && cliSent == transfer && cliRecv == transfer {
			if err := cli.Close(); err != nil {
				t.Fatalf("close: %s", err)
			}
			cliClose = true
		}

		if cliClose && (st == StateTimeWait || st == StateClosed) && outQ.Len() == 0 && inQ.Len() == 0 {
			break
		}

		if !progress {
			runtime.Gosched()
		}
	}

	if cliSent != transfer {
		t.Fatalf("chaos[%s] timed out: client sent %d/%d (state=%d outQ=%d inQ=%d elapsed=%s)",
			p.name, cliSent, transfer, cli.State(), outQ.Len(), inQ.Len(), time.Since(start))
	}
	if cliRecv != transfer {
		t.Fatalf("chaos[%s] timed out: client recv %d/%d (state=%d outQ=%d inQ=%d elapsed=%s)",
			p.name, cliRecv, transfer, cli.State(), outQ.Len(), inQ.Len(), time.Since(start))
	}
	if !cliClose {
		t.Fatal("client never closed")
	}

	cliSentSum := cliSentH.Sum(nil)
	cliRecvSum := cliRecvH.Sum(nil)

	select {
	case res := <-srvCh:
		if res.err != nil {
			t.Fatalf("server: %s", res.err)
		}
		if res.recvN != transfer {
			t.Fatalf("server recv %d/%d", res.recvN, transfer)
		}
		if res.sentN != transfer {
			t.Fatalf("server sent %d/%d", res.sentN, transfer)
		}
		if !bytes.Equal(cliSentSum, res.recvHash) {
			t.Fatalf("client→server hash mismatch:\n  client sent: %s\n  server recv: %s",
				hex.EncodeToString(cliSentSum), hex.EncodeToString(res.recvHash))
		}
		if !bytes.Equal(cliRecvSum, res.sentHash) {
			t.Fatalf("server→client hash mismatch:\n  server sent: %s\n  client recv: %s",
				hex.EncodeToString(res.sentHash), hex.EncodeToString(cliRecvSum))
		}
		t.Logf("chaos[%s] OK  client=%s  server=%s",
			p.name,
			hex.EncodeToString(cliSentSum)[:16],
			hex.EncodeToString(res.recvHash)[:16])
	case <-time.After(60 * time.Second):
		t.Fatal("server goroutine didn't finish")
	}
}
