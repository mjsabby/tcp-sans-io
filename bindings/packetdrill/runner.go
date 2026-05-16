// Packetdrill script runner: walks Script.Steps, advancing the cdylib's
// synthetic clock, injecting / extracting packets, dispatching directives.
//
// Pump semantics (per rubber-duck review):
//   * Drain any expected `>` packets at the current time BEFORE injecting.
//   * After inject, call tick(now) then extract iteratively (with tick
//     between extracts) until tx_len == 0 or all expects satisfied.
//   * After --send, call tick(now) so the stack stages any newly-eligible
//     segments.

package packetdrill

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	defaultOurISS  uint32 = 0x12345678
	defaultPeerISS uint32 = 0x87654321
	defaultRtoMs   uint32 = 1000
)

// RunScript executes one parsed script end-to-end. Returns nil on full
// pass or a wrapped error pointing at the failing step.
func RunScript(s *Script) error {
	r := &runner{
		script: s,
		nowMs:  0,
		sym:    NewSymTab(defaultOurISS, defaultPeerISS),
		ipID:   1,
	}
	for stepIdx, step := range s.Steps {
		r.advanceClock(step.AtMs())
		if err := r.runStep(step); err != nil {
			return fmt.Errorf("%s:%d step %d (%s): %v",
				s.Path, step.LineNo(), stepIdx, step.stepKind(), err)
		}
	}
	return nil
}

type runner struct {
	script *Script
	handle *Handle
	nowMs  uint64
	sym    *SymTab

	// Cdylib 4-tuple (filled by --connect or --listen).
	localIP, remoteIP   [4]byte
	localPort, peerPort uint16
	established         bool // any handshake happened
	isListener          bool

	// Pending bytes to be received from the cdylib (synthetic data
	// generator). Each --send pushes; --recv pops + verifies.
	recvCursor uint64 // bytes already verified on recv side

	ipID uint16
}

func (r *runner) advanceClock(targetMs int64) {
	if targetMs < 0 {
		targetMs = 0
	}
	if uint64(targetMs) > r.nowMs {
		r.nowMs = uint64(targetMs)
	}
	if r.handle != nil {
		_ = r.handle.Tick(r.nowMs)
	}
}

func (r *runner) runStep(step Step) error {
	switch st := step.(type) {
	case DirectiveStep:
		return r.runDirective(st)
	case InjectStep:
		return r.runInject(st)
	case ExpectStep:
		return r.runExpect(st)
	}
	return fmt.Errorf("unknown step type %T", step)
}

func (r *runner) runDirective(d DirectiveStep) error {
	switch d.Verb {
	case "connect":
		// --connect LOCAL_IP:PORT REMOTE_IP:PORT [iss N] [peer_iss N]
		if len(d.Args) < 2 {
			return fmt.Errorf("--connect requires LOCAL_IP:PORT REMOTE_IP:PORT")
		}
		lip, lport, err := parseHostPort(d.Args[0])
		if err != nil {
			return err
		}
		rip, rport, err := parseHostPort(d.Args[1])
		if err != nil {
			return err
		}
		ourISS, peerISS, err := parseISSArgs(d.Args[2:])
		if err != nil {
			return err
		}
		r.sym.OurISS = ourISS
		r.sym.PeerISS = peerISS
		r.localIP, r.localPort = lip, lport
		r.remoteIP, r.peerPort = rip, rport
		h, err := NewHandle(r.localIP[:], r.localPort, r.remoteIP[:], r.peerPort,
			ourISS, defaultRtoMs)
		if err != nil {
			return err
		}
		r.handle = h
		return h.Connect(r.nowMs)

	case "listen":
		if len(d.Args) < 1 {
			return fmt.Errorf("--listen requires LOCAL_IP:PORT")
		}
		lip, lport, err := parseHostPort(d.Args[0])
		if err != nil {
			return err
		}
		ourISS, peerISS, err := parseISSArgs(d.Args[1:])
		if err != nil {
			return err
		}
		r.sym.OurISS = ourISS
		r.sym.PeerISS = peerISS
		r.localIP, r.localPort = lip, lport
		// Remote will be pinned by the first inbound SYN.
		var dummy [4]byte
		h, err := NewHandle(r.localIP[:], r.localPort, dummy[:], 0,
			ourISS, defaultRtoMs)
		if err != nil {
			return err
		}
		r.handle = h
		r.isListener = true
		return h.Listen(r.nowMs)

	case "send":
		if len(d.Args) != 1 {
			return fmt.Errorf("--send requires byte count")
		}
		n, err := strconv.Atoi(d.Args[0])
		if err != nil {
			return fmt.Errorf("--send: %v", err)
		}
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(i & 0xFF)
		}
		written, err := r.handle.Send(buf)
		if err != nil && !errors.Is(err, ErrWouldBlock) {
			return err
		}
		if written != n {
			return fmt.Errorf("--send wrote only %d/%d bytes", written, n)
		}
		// Stage any newly-eligible segments.
		return r.handle.Tick(r.nowMs)

	case "recv":
		if len(d.Args) != 1 {
			return fmt.Errorf("--recv requires byte count")
		}
		want, err := strconv.Atoi(d.Args[0])
		if err != nil {
			return fmt.Errorf("--recv: %v", err)
		}
		buf := make([]byte, want)
		n, err := r.handle.Recv(buf)
		if err != nil && !errors.Is(err, ErrConnectionClosed) {
			return err
		}
		if n != want {
			return fmt.Errorf("--recv got %d/%d bytes", n, want)
		}
		// Verify the deterministic pattern.
		for i := 0; i < n; i++ {
			expected := byte((int(r.recvCursor) + i) & 0xFF)
			if buf[i] != expected {
				return fmt.Errorf("--recv byte %d: expected 0x%02x, got 0x%02x",
					int(r.recvCursor)+i, expected, buf[i])
			}
		}
		r.recvCursor += uint64(n)
		return nil

	case "close":
		return r.handle.Close(r.nowMs)

	case "expect_state":
		if len(d.Args) != 1 {
			return fmt.Errorf("--expect_state requires STATE")
		}
		want := ParseStateName(d.Args[0])
		got := r.handle.State()
		if want != got {
			return fmt.Errorf("state: expected %s, got %s",
				d.Args[0], StateName(got))
		}
		return nil

	default:
		return fmt.Errorf("unknown directive --%s", d.Verb)
	}
}

func (r *runner) runInject(st InjectStep) error {
	if r.handle == nil {
		return fmt.Errorf("inject before --connect or --listen")
	}
	// For listener: if no remote pinned yet, use the script's expected
	// peer as src/dst. We always treat the scripted peer as src.
	pkt, err := BuildPacket(st.Pkt,
		r.remoteIP, r.localIP, // src = peer, dst = us
		r.peerPort, r.localPort,
		r.sym, SidePeer,
		r.ipID,
	)
	if err != nil {
		return fmt.Errorf("build: %v", err)
	}
	r.ipID++
	if err := r.handle.InjectPacket(pkt, r.nowMs); err != nil {
		return fmt.Errorf("inject: %v", err)
	}
	return r.handle.Tick(r.nowMs)
}

func (r *runner) runExpect(st ExpectStep) error {
	if r.handle == nil {
		return fmt.Errorf("expect before --connect or --listen")
	}
	buf := make([]byte, MaxPacket)
	// Tick first in case staging is pending.
	if err := r.handle.Tick(r.nowMs); err != nil {
		return err
	}
	n, err := r.handle.ExtractPacket(buf)
	if err != nil {
		return fmt.Errorf("extract: %v", err)
	}
	if n == 0 {
		return fmt.Errorf("expected a packet, none staged (snapshot: state=%s)",
			StateName(r.handle.State()))
	}
	observed, err := ParsePacket(buf[:n])
	if err != nil {
		return fmt.Errorf("parse own emission: %v (%d bytes)", err, n)
	}

	// For listener path: pin the peer's port/IP on the first packet we
	// receive that has a remote not yet set. Actually we *send* to the
	// peer, so the dst is the peer — we pin remoteIP/peerPort from the
	// first injected packet, not from outbound. So this is already
	// handled.

	if err := MatchPacket(observed, st.Pkt, r.sym, SideOur); err != nil {
		return fmt.Errorf("match: %v\n  observed: %s\n  expected: %s",
			err, describePacket(observed, r.sym, SideOur), describeDesc(st.Pkt))
	}
	return nil
}

func describePacket(p *ParsedPacket, sym *SymTab, emitterSide Side) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s seq=%d (rel %+d)",
		flagString(p.Flags), p.Seq, sym.ScriptRelative(p.Seq, emitterSide))
	if p.Flags&flagACK != 0 {
		other := SidePeer
		if emitterSide == SidePeer {
			other = SideOur
		}
		fmt.Fprintf(&b, " ack=%d (rel %+d)", p.Ack, sym.ScriptRelative(p.Ack, other))
	}
	fmt.Fprintf(&b, " win=%d len=%d opts=%s", p.Window, len(p.Payload), optsSummary(p.Options))
	if p.ECN != 0 {
		fmt.Fprintf(&b, " ecn=%s", ecnName(p.ECN))
	}
	return b.String()
}

func describeDesc(d PacketDesc) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s seq=%s", flagString(d.Flags), d.Seq)
	if d.Ack != nil {
		fmt.Fprintf(&b, " ack=%s", *d.Ack)
	}
	if d.Win != nil {
		fmt.Fprintf(&b, " win=%d", *d.Win)
	}
	fmt.Fprintf(&b, " len=%d opts=%s", d.PayloadLen, optsSummary(d.Options))
	if d.ECN != nil {
		fmt.Fprintf(&b, " ecn=%s", ecnName(*d.ECN))
	}
	return b.String()
}

func parseHostPort(s string) ([4]byte, uint16, error) {
	colon := strings.LastIndex(s, ":")
	if colon < 0 {
		return [4]byte{}, 0, fmt.Errorf("expected IP:PORT, got %q", s)
	}
	ip := s[:colon]
	port, err := strconv.ParseUint(s[colon+1:], 10, 16)
	if err != nil {
		return [4]byte{}, 0, fmt.Errorf("bad port %q: %v", s[colon+1:], err)
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return [4]byte{}, 0, fmt.Errorf("bad IP %q", ip)
	}
	var out [4]byte
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return [4]byte{}, 0, fmt.Errorf("bad IP octet %q: %v", p, err)
		}
		out[i] = byte(v)
	}
	return out, uint16(port), nil
}

func parseISSArgs(args []string) (ourISS, peerISS uint32, err error) {
	ourISS = defaultOurISS
	peerISS = defaultPeerISS
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "iss":
			if i+1 >= len(args) {
				return 0, 0, fmt.Errorf("iss without value")
			}
			v, perr := parseUint32Maybe(args[i+1])
			if perr != nil {
				return 0, 0, fmt.Errorf("iss: %v", perr)
			}
			ourISS = v
			i++
		case "peer_iss":
			if i+1 >= len(args) {
				return 0, 0, fmt.Errorf("peer_iss without value")
			}
			v, perr := parseUint32Maybe(args[i+1])
			if perr != nil {
				return 0, 0, fmt.Errorf("peer_iss: %v", perr)
			}
			peerISS = v
			i++
		default:
			return 0, 0, fmt.Errorf("unknown arg %q", args[i])
		}
	}
	return
}

func parseUint32Maybe(s string) (uint32, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 32)
		return uint32(v), err
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err
}

// Free releases the cdylib handle. Tests should defer this.
func (r *runner) Free() {
	if r.handle != nil {
		r.handle.Free()
		r.handle = nil
	}
}
