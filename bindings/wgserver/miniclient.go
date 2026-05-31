// MiniClient: a minimal stateful TCP client used by the scale test.
//
// Does just enough to drive a request/response exchange:
//   SYN  →  SYN-ACK ← ACK  →  data ← echo  →  FIN ↔ ACK ↔ FIN ↔ ACK.
// Sliding-window / retransmit / SACK / congestion control are
// intentionally absent — the harness is loopback-only and serves
// small payloads, so a simple "send + wait + retransmit on RTO"
// suffices.

package wgserver

import (
	"bytes"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// MiniOpts picks the option set the client offers in its SYN.
type MiniOpts int

const (
	// OptsNone: no TCP options (plain RFC 793).
	OptsNone MiniOpts = iota
	// OptsTS: Timestamps only.
	OptsTS
	// OptsWSTS: WScale + Timestamps.
	OptsWSTS
	// OptsAll: SACK_PERMITTED + WScale + Timestamps.
	OptsAll
)

// MiniClientConfig describes one connection attempt.
type MiniClientConfig struct {
	SrcIP    [4]byte
	SrcPort  uint16
	DstIP    [4]byte
	DstPort  uint16
	ISS      uint32
	Opts     MiniOpts
	WScale   uint8
	MSS      uint16
	Request  []byte
	RecvSize int
	// Total deadline for the entire connection attempt.
	Deadline    time.Duration
	RetransmitT time.Duration
}

// MiniClientResult reports a single connection's outcome.
type MiniClientResult struct {
	OK        bool
	Response  []byte
	Latency   time.Duration
	Err       error
	// Counters for diagnostics.
	Retransmits int
	RxPackets   int
	TxPackets   int
}

// monoTSVal is a global monotonic counter used as the TSval for all
// mini-clients. Each invocation increments it so the server's PAWS
// check sees fresh, monotonic timestamps.
var monoTSVal uint64

func nextTSVal() uint32 {
	return uint32(atomic.AddUint64(&monoTSVal, 1))
}

// RunMini executes one connection. Safe to call concurrently — each
// invocation creates its own Inbox.
func RunMini(t *Transport, cfg MiniClientConfig) MiniClientResult {
	if cfg.Deadline == 0 {
		cfg.Deadline = 5 * time.Second
	}
	if cfg.RetransmitT == 0 {
		cfg.RetransmitT = 250 * time.Millisecond
	}
	if cfg.MSS == 0 {
		cfg.MSS = 1460
	}
	if cfg.RecvSize == 0 {
		cfg.RecvSize = 16384
	}
	if cfg.WScale == 0 {
		cfg.WScale = 7
	}

	box := t.RegisterInbox(cfg.SrcIP, cfg.SrcPort, 64)
	defer box.Close()

	start := time.Now()
	overallDeadline := start.Add(cfg.Deadline)

	res := MiniClientResult{}

	// 1. Send SYN.
	tsval := nextTSVal()
	sndNxt := cfg.ISS
	rcvNxt := uint32(0)
	mss := cfg.MSS
	tsEnabled := cfg.Opts == OptsTS || cfg.Opts == OptsWSTS || cfg.Opts == OptsAll
	wsEnabled := cfg.Opts == OptsWSTS || cfg.Opts == OptsAll
	sackPerm := cfg.Opts == OptsAll

	mkOpts := func(includeMSS, includeWS, includeSACK, includeTS bool) Options {
		o := Options{}
		if includeMSS {
			o.MSSSet = true
			o.MSS = mss
		}
		if includeWS && wsEnabled {
			o.WSSet = true
			o.WS = cfg.WScale
		}
		if includeSACK && sackPerm {
			o.SACKPermitted = true
		}
		if includeTS && tsEnabled {
			o.TSSet = true
			o.TSVal = tsval
			o.TSEcr = 0
		}
		return o
	}

	send := func(flags uint8, seq, ack uint32, opts Options, payload []byte) error {
		spec := PacketSpec{
			SrcIP:   cfg.SrcIP,
			DstIP:   cfg.DstIP,
			SrcPort: cfg.SrcPort,
			DstPort: cfg.DstPort,
			Seq:     seq,
			Ack:     ack,
			Flags:   flags,
			Window:  65535,
			Options: opts,
			Payload: payload,
			IPID:    uint16(seq & 0xFFFF),
		}
		pkt, err := Encode(spec)
		if err != nil {
			return err
		}
		res.TxPackets++
		return t.SendTo(pkt)
	}

	// SYN.
	synOpts := mkOpts(true, true, true, true)
	if err := send(FlagSYN, sndNxt, 0, synOpts, nil); err != nil {
		res.Err = fmt.Errorf("send SYN: %w", err)
		return res
	}

	// 2. Wait for SYN-ACK, retransmitting SYN on RTO.
	var peerISS uint32
	var peerTsVal uint32
	gotSynAck := false
	for time.Now().Before(overallDeadline) && !gotSynAck {
		recvD := cfg.RetransmitT
		if remaining := time.Until(overallDeadline); remaining < recvD {
			recvD = remaining
		}
		pkt, err := box.Recv(recvD)
		if errors.Is(err, ErrTimeout) {
			res.Retransmits++
			tsval = nextTSVal()
			synOpts = mkOpts(true, true, true, true)
			if err := send(FlagSYN, sndNxt, 0, synOpts, nil); err != nil {
				res.Err = fmt.Errorf("retx SYN: %w", err)
				return res
			}
			continue
		}
		if err != nil {
			res.Err = fmt.Errorf("recv SYN-ACK: %w", err)
			return res
		}
		res.RxPackets++
		pp, err := Parse(pkt)
		if err != nil {
			// drop bad checksum / unrelated.
			continue
		}
		if pp.Flags&FlagRST != 0 {
			res.Err = fmt.Errorf("peer RST during handshake")
			return res
		}
		if pp.Flags&FlagSYN == 0 || pp.Flags&FlagACK == 0 {
			continue
		}
		if pp.Ack != sndNxt+1 {
			continue
		}
		peerISS = pp.Seq
		if pp.Options.TSSet {
			peerTsVal = pp.Options.TSVal
		}
		if pp.Options.MSSSet && pp.Options.MSS > 0 && pp.Options.MSS < mss {
			mss = pp.Options.MSS
		}
		gotSynAck = true
	}
	if !gotSynAck {
		res.Err = fmt.Errorf("timed out waiting for SYN-ACK after %v", time.Since(start))
		return res
	}

	// 3. Send ACK (third leg).
	sndNxt = cfg.ISS + 1
	rcvNxt = peerISS + 1
	tsval = nextTSVal()
	ackOpts := mkOpts(false, false, false, true)
	ackOpts.TSEcr = peerTsVal
	if err := send(FlagACK, sndNxt, rcvNxt, ackOpts, nil); err != nil {
		res.Err = fmt.Errorf("send 3rd ACK: %w", err)
		return res
	}

	// 4. Send request payload (single PSH/ACK segment). For our small
	//    echo requests this is always one MSS.
	if len(cfg.Request) > 0 {
		tsval = nextTSVal()
		dataOpts := mkOpts(false, false, false, true)
		dataOpts.TSEcr = peerTsVal
		segLen := uint32(len(cfg.Request))
		if err := send(FlagACK|FlagPSH, sndNxt, rcvNxt, dataOpts, cfg.Request); err != nil {
			res.Err = fmt.Errorf("send data: %w", err)
			return res
		}
		sndNxt += segLen
	}

	// 5. Drain response until peer FIN or full RecvSize gathered.
	var resp bytes.Buffer
	peerFinSeen := false
	dataDeadlineHit := false
	lastSendT := time.Now()
	for !peerFinSeen && resp.Len() < cfg.RecvSize && time.Now().Before(overallDeadline) {
		recvD := cfg.RetransmitT
		if remaining := time.Until(overallDeadline); remaining < recvD {
			recvD = remaining
		}
		pkt, err := box.Recv(recvD)
		if errors.Is(err, ErrTimeout) {
			// Retransmit the data segment if we haven't seen any ACK
			// for our request bytes in a while.
			if len(cfg.Request) > 0 && time.Since(lastSendT) > cfg.RetransmitT {
				res.Retransmits++
				tsval = nextTSVal()
				dataOpts := mkOpts(false, false, false, true)
				dataOpts.TSEcr = peerTsVal
				if err := send(FlagACK|FlagPSH, cfg.ISS+1, rcvNxt, dataOpts, cfg.Request); err != nil {
					res.Err = fmt.Errorf("retx data: %w", err)
					return res
				}
				lastSendT = time.Now()
			} else {
				// Plain keepalive ACK with no payload — nudges PAWS.
				tsval = nextTSVal()
				kOpts := mkOpts(false, false, false, true)
				kOpts.TSEcr = peerTsVal
				_ = send(FlagACK, sndNxt, rcvNxt, kOpts, nil)
			}
			continue
		}
		if err != nil {
			res.Err = fmt.Errorf("recv data: %w", err)
			return res
		}
		res.RxPackets++
		pp, err := Parse(pkt)
		if err != nil {
			continue
		}
		if pp.Flags&FlagRST != 0 {
			res.Err = fmt.Errorf("peer RST during data phase (resp_so_far=%d)", resp.Len())
			return res
		}
		if pp.Options.TSSet {
			peerTsVal = pp.Options.TSVal
		}
		// Accept in-order data (seq == rcvNxt) only. Reordering is
		// extremely rare on loopback.
		if len(pp.Payload) > 0 {
			if pp.Seq == rcvNxt {
				resp.Write(pp.Payload)
				rcvNxt += uint32(len(pp.Payload))
				// Ack the data immediately.
				tsval = nextTSVal()
				ack2 := mkOpts(false, false, false, true)
				ack2.TSEcr = peerTsVal
				_ = send(FlagACK, sndNxt, rcvNxt, ack2, nil)
			} else if seqLess(pp.Seq, rcvNxt) {
				// Stale duplicate. Re-ACK to nudge sender.
				tsval = nextTSVal()
				ack2 := mkOpts(false, false, false, true)
				ack2.TSEcr = peerTsVal
				_ = send(FlagACK, sndNxt, rcvNxt, ack2, nil)
			}
		}
		if pp.Flags&FlagFIN != 0 {
			// Acknowledge the FIN's sequence-number consumption.
			if pp.Seq+uint32(len(pp.Payload)) == rcvNxt {
				rcvNxt++
				peerFinSeen = true
				tsval = nextTSVal()
				ack2 := mkOpts(false, false, false, true)
				ack2.TSEcr = peerTsVal
				_ = send(FlagACK, sndNxt, rcvNxt, ack2, nil)
			}
		}
	}

	if !peerFinSeen && resp.Len() < cfg.RecvSize {
		dataDeadlineHit = true
		_ = dataDeadlineHit
	}

	// 6. Send our FIN to complete the close.
	tsval = nextTSVal()
	finOpts := mkOpts(false, false, false, true)
	finOpts.TSEcr = peerTsVal
	_ = send(FlagACK|FlagFIN, sndNxt, rcvNxt, finOpts, nil)
	sndNxt++ // our FIN consumes a sequence number

	// 7. Wait briefly for the server's ACK of our FIN (best-effort —
	//    the server has plenty more work to do).
	waitFinAck := 100 * time.Millisecond
	if remaining := time.Until(overallDeadline); remaining < waitFinAck {
		waitFinAck = remaining
	}
	deadline := time.Now().Add(waitFinAck)
	for time.Now().Before(deadline) {
		pkt, err := box.Recv(deadline.Sub(time.Now()))
		if err != nil {
			break
		}
		res.RxPackets++
		pp, perr := Parse(pkt)
		if perr != nil {
			continue
		}
		if pp.Flags&FlagACK != 0 && pp.Ack == sndNxt {
			break
		}
	}

	res.OK = (resp.Len() > 0) || len(cfg.Request) == 0
	res.Response = resp.Bytes()
	res.Latency = time.Since(start)
	return res
}

// seqLess returns true if a < b in 32-bit sequence-number arithmetic.
func seqLess(a, b uint32) bool {
	return int32(a-b) < 0
}
