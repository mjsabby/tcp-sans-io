// Wire codec for the packetdrill runner: build IPv4+TCP packets from
// PacketDesc, and match cdylib-emitted packets against PacketDesc.
//
// We implement IPv4+TCP serialisation natively in Go (no FFI to wire.rs)
// so the runner has a second implementation that can catch bugs in the
// stack's own codec. Checksum logic is the same 1's-complement-sum that
// wire.rs uses; if the two diverged we'd see test failures.

package packetdrill

import (
	"encoding/binary"
	"fmt"
)

const (
	ipv4HdrLen = 20
	tcpHdrLen  = 20
	protoTCP   = 6
)

// BuildPacket renders an inject-side PacketDesc into a full IPv4+TCP
// datagram. `srcIP`/`dstIP` and ports are passed by the caller (the
// runner derives them from the cdylib's 4-tuple). `pkt`'s seq/ack/opts
// are resolved through the symbol table.
//
// The payload is synthesised as a deterministic 0..255 repeating pattern
// starting at offset `Seq - peer_iss` (so the receiving cdylib gets data
// it can verify against the same generator).
func BuildPacket(
	pkt PacketDesc,
	srcIP, dstIP [4]byte,
	srcPort, dstPort uint16,
	sym *SymTab,
	emitterSide Side,
	ipID uint16,
) ([]byte, error) {
	// Resolve seq/ack through the symbol table.
	seq, ok, err := sym.Resolve(pkt.Seq, emitterSide)
	if err != nil {
		return nil, fmt.Errorf("inject seq: %v", err)
	}
	if !ok {
		return nil, fmt.Errorf("inject seq cannot be wildcard")
	}
	var ack uint32
	if pkt.Ack != nil {
		// Ack is on the OTHER side's seq space.
		other := SidePeer
		if emitterSide == SidePeer {
			other = SideOur
		}
		ack, ok, err = sym.Resolve(*pkt.Ack, other)
		if err != nil {
			return nil, fmt.Errorf("inject ack: %v", err)
		}
		if !ok {
			return nil, fmt.Errorf("inject ack cannot be wildcard")
		}
	}

	// Resolve options.
	optBytes, err := encodeOptions(pkt.Options, sym, emitterSide)
	if err != nil {
		return nil, err
	}
	// Pad options to a 4-byte boundary with NOPs (kind=1).
	for len(optBytes)%4 != 0 {
		optBytes = append(optBytes, 1)
	}
	if len(optBytes) > 40 {
		return nil, fmt.Errorf("options exceed 40-byte TCP cap")
	}

	// Synthesise payload from the deterministic pattern, if requested.
	// The pattern's user-data offset = script-relative seq minus 1 (the
	// SYN consumes seq 0 but carries no user data). This matches the
	// runner's --recv verifier which starts its cursor at user-byte 0.
	var payload []byte
	if pkt.PayloadLen > 0 {
		base := sym.OurISS
		if emitterSide == SidePeer {
			base = sym.PeerISS
		}
		relSeq := int32(seq) - int32(base) // script-relative seq
		userOff := int64(relSeq) - 1       // subtract SYN
		if userOff < 0 {
			userOff = 0 // tolerate SYN-with-data scripts (TFO-like)
		}
		payload = make([]byte, pkt.PayloadLen)
		for i := range payload {
			payload[i] = byte((userOff + int64(i)) & 0xFF)
		}
	}

	tcpHdr := tcpHdrLen + len(optBytes)
	total := ipv4HdrLen + tcpHdr + len(payload)
	if total > 65535 {
		return nil, fmt.Errorf("packet too large")
	}
	buf := make([]byte, total)

	// --- IPv4 header ---
	buf[0] = 0x45 // version=4, IHL=5
	if pkt.ECN != nil {
		buf[1] = *pkt.ECN & 0x03
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	binary.BigEndian.PutUint16(buf[4:6], ipID)
	binary.BigEndian.PutUint16(buf[6:8], 0x4000) // DF
	buf[8] = 64                                  // TTL
	buf[9] = protoTCP
	// checksum (10..12) zero for computation
	copy(buf[12:16], srcIP[:])
	copy(buf[16:20], dstIP[:])
	ipCsum := checksum16(buf[:ipv4HdrLen], 0)
	binary.BigEndian.PutUint16(buf[10:12], ipCsum)

	// --- TCP header ---
	tcp := buf[ipv4HdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte((tcpHdr / 4) << 4)
	tcp[13] = pkt.Flags
	if pkt.Win != nil {
		binary.BigEndian.PutUint16(tcp[14:16], *pkt.Win)
	} else {
		binary.BigEndian.PutUint16(tcp[14:16], 65535)
	}
	// urgent (18:20) zeroed
	copy(tcp[tcpHdrLen:tcpHdrLen+len(optBytes)], optBytes)
	copy(tcp[tcpHdrLen+len(optBytes):], payload)
	tcpCsum := tcpChecksum(srcIP, dstIP, tcp[:tcpHdr+len(payload)])
	binary.BigEndian.PutUint16(tcp[16:18], tcpCsum)

	return buf, nil
}

// encodeOptions serialises the option list using the same wire format as
// src/wire.rs (matching kind/length conventions).
func encodeOptions(opts []OptionDesc, sym *SymTab, side Side) ([]byte, error) {
	var out []byte
	for _, o := range opts {
		switch v := o.(type) {
		case MSSOpt:
			out = append(out, 2, 4)
			out = binary.BigEndian.AppendUint16(out, v.Val)
		case WScaleOpt:
			out = append(out, 3, 3, v.Shift)
		case SackPermittedOpt:
			out = append(out, 4, 2)
		case SackOpt:
			length := byte(2 + 8*len(v.Blocks))
			out = append(out, 5, length)
			for _, b := range v.Blocks {
				l, ok, err := sym.Resolve(b.Left, side)
				if err != nil || !ok {
					return nil, fmt.Errorf("sack left unresolved: %v", err)
				}
				r, ok, err := sym.Resolve(b.Right, side)
				if err != nil || !ok {
					return nil, fmt.Errorf("sack right unresolved: %v", err)
				}
				out = binary.BigEndian.AppendUint32(out, l)
				out = binary.BigEndian.AppendUint32(out, r)
			}
		case TSOpt:
			// TS values are NOT sequence numbers; they pass through
			// verbatim. Resolve only handles literal/wildcard/symbolic
			// without applying any ISS base. Symbolic TS values use a
			// separate __ts_<name> namespace so they don't collide with
			// sequence captures.
			val, err := resolveTSVal(v.Val, sym)
			if err != nil {
				return nil, fmt.Errorf("TS val: %v", err)
			}
			ecr, err := resolveTSVal(v.Ecr, sym)
			if err != nil {
				return nil, fmt.Errorf("TS ecr: %v", err)
			}
			out = append(out, 8, 10)
			out = binary.BigEndian.AppendUint32(out, val)
			out = binary.BigEndian.AppendUint32(out, ecr)
		case NopOpt:
			out = append(out, 1)
		default:
			return nil, fmt.Errorf("unknown option type %T", o)
		}
	}
	return out, nil
}

// resolveTSVal handles a TS-value SeqRef without applying any ISS
// translation (TS values aren't sequence numbers). Wildcards on inject
// are encoded as 0 (peer is expected to ignore them anyway since the
// inject side determined the value). Symbolics use the `__ts_<name>`
// namespace shared with the matcher.
func resolveTSVal(ref SeqRef, sym *SymTab) (uint32, error) {
	switch ref.Mode {
	case SeqLiteral:
		return uint32(ref.Value), nil
	case SeqWildcard:
		return 0, nil
	case SeqSymbolic:
		v, ok := sym.Names["__ts_"+ref.Name]
		if !ok {
			return 0, fmt.Errorf("symbolic TS $%s not bound", ref.Name)
		}
		return v, nil
	default:
		return 0, fmt.Errorf("unknown SeqMode %d", ref.Mode)
	}
}
// ParsedPacket is the runner-facing form of a parsed inbound/outbound
// IPv4+TCP datagram. Mostly mirrors what wire.rs's Segment exposes.
type ParsedPacket struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   byte
	Window  uint16
	ECN     uint8
	Payload []byte
	Options []OptionDesc // decoded (NOPs stripped)
}

// ParsePacket pulls out the fields we care about from a raw IPv4+TCP
// datagram. Validates lengths + checksums; rejects fragments and non-TCP.
func ParsePacket(buf []byte) (*ParsedPacket, error) {
	if len(buf) < ipv4HdrLen+tcpHdrLen {
		return nil, fmt.Errorf("short packet")
	}
	if buf[0]>>4 != 4 {
		return nil, fmt.Errorf("not IPv4")
	}
	ihl := int(buf[0]&0x0F) * 4
	if ihl < ipv4HdrLen {
		return nil, fmt.Errorf("bad IHL")
	}
	totalLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if totalLen > len(buf) {
		return nil, fmt.Errorf("truncated")
	}
	flagsFrag := binary.BigEndian.Uint16(buf[6:8])
	if flagsFrag&0x2000 != 0 || flagsFrag&0x1FFF != 0 {
		return nil, fmt.Errorf("fragment")
	}
	if buf[9] != protoTCP {
		return nil, fmt.Errorf("not TCP")
	}
	if checksum16(buf[:ihl], 0) != 0 {
		return nil, fmt.Errorf("IP checksum")
	}

	p := &ParsedPacket{}
	copy(p.SrcIP[:], buf[12:16])
	copy(p.DstIP[:], buf[16:20])
	p.ECN = buf[1] & 0x03

	tcp := buf[ihl:totalLen]
	if len(tcp) < tcpHdrLen {
		return nil, fmt.Errorf("short TCP")
	}
	p.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
	p.DstPort = binary.BigEndian.Uint16(tcp[2:4])
	p.Seq = binary.BigEndian.Uint32(tcp[4:8])
	p.Ack = binary.BigEndian.Uint32(tcp[8:12])
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < tcpHdrLen || dataOff > len(tcp) {
		return nil, fmt.Errorf("bad data offset")
	}
	p.Flags = tcp[13]
	p.Window = binary.BigEndian.Uint16(tcp[14:16])

	if tcpChecksum(p.SrcIP, p.DstIP, tcp) != 0 {
		return nil, fmt.Errorf("TCP checksum")
	}

	if dataOff > tcpHdrLen {
		opts, err := decodeOptions(tcp[tcpHdrLen:dataOff])
		if err != nil {
			return nil, fmt.Errorf("options: %v", err)
		}
		p.Options = opts
	}
	p.Payload = append([]byte(nil), tcp[dataOff:]...)
	return p, nil
}

// decodeOptions parses the option bytes, dropping NOP padding (which is
// alignment, not signal). Returns options in wire order.
func decodeOptions(b []byte) ([]OptionDesc, error) {
	var out []OptionDesc
	i := 0
	for i < len(b) {
		kind := b[i]
		switch kind {
		case 0:
			// EOL
			return out, nil
		case 1:
			// NOP — skip (don't surface, it's padding).
			i++
		case 2:
			if i+4 > len(b) || b[i+1] != 4 {
				return nil, fmt.Errorf("bad MSS")
			}
			out = append(out, MSSOpt{Val: binary.BigEndian.Uint16(b[i+2 : i+4])})
			i += 4
		case 3:
			if i+3 > len(b) || b[i+1] != 3 {
				return nil, fmt.Errorf("bad WS")
			}
			out = append(out, WScaleOpt{Shift: b[i+2]})
			i += 3
		case 4:
			if i+2 > len(b) || b[i+1] != 2 {
				return nil, fmt.Errorf("bad SackOK")
			}
			out = append(out, SackPermittedOpt{})
			i += 2
		case 5:
			if i+2 > len(b) {
				return nil, fmt.Errorf("bad SACK")
			}
			length := int(b[i+1])
			if length < 10 || (length-2)%8 != 0 || i+length > len(b) {
				return nil, fmt.Errorf("bad SACK length")
			}
			nblocks := (length - 2) / 8
			blocks := make([]SackBlockDesc, nblocks)
			for k := 0; k < nblocks; k++ {
				off := i + 2 + k*8
				l := binary.BigEndian.Uint32(b[off : off+4])
				r := binary.BigEndian.Uint32(b[off+4 : off+8])
				blocks[k] = SackBlockDesc{
					Left:  SeqRef{Mode: SeqLiteral, Value: int64(int32(l))},
					Right: SeqRef{Mode: SeqLiteral, Value: int64(int32(r))},
				}
			}
			out = append(out, SackOpt{Blocks: blocks})
			i += length
		case 8:
			if i+10 > len(b) || b[i+1] != 10 {
				return nil, fmt.Errorf("bad TS")
			}
			val := binary.BigEndian.Uint32(b[i+2 : i+6])
			ecr := binary.BigEndian.Uint32(b[i+6 : i+10])
			out = append(out, TSOpt{
				Val: SeqRef{Mode: SeqLiteral, Value: int64(int32(val))},
				Ecr: SeqRef{Mode: SeqLiteral, Value: int64(int32(ecr))},
			})
			i += 10
		default:
			// Unknown length-prefixed option; skip.
			if i+2 > len(b) {
				return nil, fmt.Errorf("truncated unknown option")
			}
			length := int(b[i+1])
			if length < 2 || i+length > len(b) {
				return nil, fmt.Errorf("bad unknown option length")
			}
			i += length
		}
	}
	return out, nil
}

func checksum16(data []byte, seed uint32) uint16 {
	sum := seed
	i := 0
	for ; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if i < len(data) {
		sum += uint32(data[i]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP [4]byte, tcp []byte) uint16 {
	length := uint32(len(tcp))
	pseudo := uint32(srcIP[0])<<8 | uint32(srcIP[1])
	pseudo += uint32(srcIP[2])<<8 | uint32(srcIP[3])
	pseudo += uint32(dstIP[0])<<8 | uint32(dstIP[1])
	pseudo += uint32(dstIP[2])<<8 | uint32(dstIP[3])
	pseudo += uint32(protoTCP)
	pseudo += length & 0xFFFF
	return checksum16(tcp, pseudo)
}
