// Package wgserver provides Go test drivers + adversarial harnesses
// for the tcp-sans-io userspace TCP server (`bindings/wgserver-rs/`).
//
// This file implements a pure-Go IPv4 + TCP encoder/decoder, including
// option encoding (MSS, WScale, Timestamps, SACK_PERMITTED) and
// Internet checksums. It is intentionally independent of the cdylib —
// the wire it produces must interop with the Rust server through a
// real (encapsulated) packet path.
package wgserver

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// IPv4 + TCP constants (mirror of `src/wire.rs`).
const (
	IPV4HdrLen = 20
	TCPHdrLen  = 20
	IPProtoTCP = 6

	// Sub-set of options we encode/decode.
	tcpOptEnd   = 0
	tcpOptNop   = 1
	tcpOptMSS   = 2
	tcpOptWS    = 3
	tcpOptSACKP = 4
	tcpOptSACK  = 5
	tcpOptTS    = 8
)

// TCP flag bits.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
	FlagURG = 0x20
	FlagECE = 0x40
	FlagCWR = 0x80
)

// Options carries the small set of TCP options used by the harness.
// All fields are optional; `Some=true` means encode the option.
type Options struct {
	// MSS option (RFC 9293).
	MSSSet bool
	MSS    uint16

	// Window Scale option (RFC 7323).
	WSSet bool
	WS    uint8

	// SACK Permitted option (RFC 2018).
	SACKPermitted bool

	// Timestamps option (RFC 7323).
	TSSet bool
	TSVal uint32
	TSEcr uint32
}

// encodedLen returns the on-wire option block length in bytes, padded
// to a 4-byte boundary with NOPs/EOL as `encode` does.
func (o Options) encodedLen() int {
	n := 0
	if o.MSSSet {
		n += 4
	}
	if o.WSSet {
		n += 3
	}
	if o.SACKPermitted {
		n += 2
	}
	if o.TSSet {
		n += 10
	}
	// Pad to multiple of 4.
	if rem := n % 4; rem != 0 {
		n += 4 - rem
	}
	return n
}

// encode writes the options into `buf`; returns bytes written.
func (o Options) encode(buf []byte) (int, error) {
	off := 0
	put := func(b ...byte) error {
		if off+len(b) > len(buf) {
			return errors.New("options buffer too small")
		}
		copy(buf[off:], b)
		off += len(b)
		return nil
	}
	if o.MSSSet {
		var b [4]byte
		b[0] = tcpOptMSS
		b[1] = 4
		binary.BigEndian.PutUint16(b[2:], o.MSS)
		if err := put(b[:]...); err != nil {
			return 0, err
		}
	}
	if o.SACKPermitted {
		if err := put(tcpOptSACKP, 2); err != nil {
			return 0, err
		}
	}
	if o.WSSet {
		if err := put(tcpOptWS, 3, o.WS); err != nil {
			return 0, err
		}
	}
	if o.TSSet {
		var b [10]byte
		b[0] = tcpOptTS
		b[1] = 10
		binary.BigEndian.PutUint32(b[2:], o.TSVal)
		binary.BigEndian.PutUint32(b[6:], o.TSEcr)
		if err := put(b[:]...); err != nil {
			return 0, err
		}
	}
	// Pad to multiple of 4 with EOL (`end-of-options` is 0). RFC 9293
	// allows NOP padding for alignment; we use EOL for simplicity.
	for off%4 != 0 {
		if err := put(tcpOptEnd); err != nil {
			return 0, err
		}
	}
	return off, nil
}

// PacketSpec describes a full IPv4+TCP packet for emission.
type PacketSpec struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Window  uint16
	Options Options
	Payload []byte
	IPID    uint16

	// Adversarial mutators (zero values are no-ops).
	CorruptIPChecksum  bool
	CorruptTCPChecksum bool
	FragOffset         uint16 // 13-bit offset; non-zero produces a fragmented packet
	MoreFragments      bool
	// ExtraOptionsBlob lets adversary tests inject arbitrary bytes
	// after the standard options. Used for malformed-option fuzzing.
	ExtraOptionsBlob []byte
	// TruncateBytes drops the last N bytes from the emitted packet
	// (for truncated-header tests). Applied last.
	TruncateBytes int
}

// Encode emits an IPv4+TCP packet for `s` and returns the bytes.
func Encode(s PacketSpec) ([]byte, error) {
	optLen := s.Options.encodedLen() + len(s.ExtraOptionsBlob)
	if optLen%4 != 0 {
		// Pad ExtraOptionsBlob region so the TCP data offset stays
		// 4-byte aligned. We pad with EOL bytes; the resulting blob
		// is intentionally non-canonical for adversary tests.
		pad := 4 - (optLen % 4)
		s.ExtraOptionsBlob = append(append([]byte{}, s.ExtraOptionsBlob...), make([]byte, pad)...)
		optLen += pad
	}
	if optLen > 40 {
		return nil, fmt.Errorf("TCP options too large: %d > 40", optLen)
	}
	tcpHdrLen := TCPHdrLen + optLen
	total := IPV4HdrLen + tcpHdrLen + len(s.Payload)
	if total > 65535 {
		return nil, fmt.Errorf("total length %d exceeds u16", total)
	}
	out := make([]byte, total)

	// IPv4 header.
	out[0] = 0x45
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:], uint16(total))
	binary.BigEndian.PutUint16(out[4:], s.IPID)
	// Flags + Fragment Offset: DF=0x4000 unless caller asked for frag.
	var fo uint16
	if s.MoreFragments {
		fo |= 0x2000
	}
	fo |= s.FragOffset & 0x1FFF
	if !s.MoreFragments && s.FragOffset == 0 {
		fo |= 0x4000 // Don't Fragment
	}
	binary.BigEndian.PutUint16(out[6:], fo)
	out[8] = 64 // TTL
	out[9] = IPProtoTCP
	binary.BigEndian.PutUint16(out[10:], 0) // checksum placeholder
	copy(out[12:16], s.SrcIP[:])
	copy(out[16:20], s.DstIP[:])
	ipCsum := inetChecksum(out[:IPV4HdrLen], 0)
	binary.BigEndian.PutUint16(out[10:], ipCsum)
	if s.CorruptIPChecksum {
		binary.BigEndian.PutUint16(out[10:], ipCsum^0xFFFF)
	}

	// TCP header.
	t := out[IPV4HdrLen:]
	binary.BigEndian.PutUint16(t[0:], s.SrcPort)
	binary.BigEndian.PutUint16(t[2:], s.DstPort)
	binary.BigEndian.PutUint32(t[4:], s.Seq)
	binary.BigEndian.PutUint32(t[8:], s.Ack)
	t[12] = byte((tcpHdrLen / 4) << 4)
	t[13] = s.Flags
	binary.BigEndian.PutUint16(t[14:], s.Window)
	// checksum (16:18) + urgent (18:20) start zero.

	// Options.
	if s.Options.encodedLen() > 0 {
		if _, err := s.Options.encode(t[TCPHdrLen:]); err != nil {
			return nil, err
		}
	}
	if len(s.ExtraOptionsBlob) > 0 {
		copy(t[TCPHdrLen+s.Options.encodedLen():], s.ExtraOptionsBlob)
	}

	// Payload.
	copy(t[tcpHdrLen:], s.Payload)

	// TCP checksum.
	csum := tcpChecksum(s.SrcIP, s.DstIP, t[:tcpHdrLen+len(s.Payload)])
	binary.BigEndian.PutUint16(t[16:], csum)
	if s.CorruptTCPChecksum {
		binary.BigEndian.PutUint16(t[16:], csum^0xFFFF)
	}

	if s.TruncateBytes > 0 {
		n := len(out) - s.TruncateBytes
		if n < 0 {
			n = 0
		}
		out = out[:n]
	}
	return out, nil
}

// ParsedPacket is the subset of fields decoded by Parse.
type ParsedPacket struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Window  uint16
	Payload []byte
	Options Options
}

// Parse decodes an IPv4+TCP packet into a `ParsedPacket`. Returns an
// error on truncation, version mismatch, non-TCP protocol, or bad
// checksums.
func Parse(pkt []byte) (*ParsedPacket, error) {
	if len(pkt) < IPV4HdrLen+TCPHdrLen {
		return nil, fmt.Errorf("packet too short: %d", len(pkt))
	}
	if pkt[0]>>4 != 4 {
		return nil, fmt.Errorf("not IPv4: version=%d", pkt[0]>>4)
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < IPV4HdrLen || len(pkt) < ihl+TCPHdrLen {
		return nil, fmt.Errorf("IHL invalid: %d", ihl)
	}
	if pkt[9] != IPProtoTCP {
		return nil, fmt.Errorf("not TCP: proto=%d", pkt[9])
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
	if totalLen > len(pkt) {
		return nil, fmt.Errorf("IP total %d > buf %d", totalLen, len(pkt))
	}
	if inetChecksum(pkt[:ihl], 0) != 0 {
		// Many adversary inputs have bad IP csum on purpose — return
		// a typed error so callers can distinguish.
		return nil, fmt.Errorf("IP checksum bad")
	}
	pp := &ParsedPacket{}
	copy(pp.SrcIP[:], pkt[12:16])
	copy(pp.DstIP[:], pkt[16:20])

	t := pkt[ihl:totalLen]
	pp.SrcPort = binary.BigEndian.Uint16(t[0:])
	pp.DstPort = binary.BigEndian.Uint16(t[2:])
	pp.Seq = binary.BigEndian.Uint32(t[4:])
	pp.Ack = binary.BigEndian.Uint32(t[8:])
	doff := int(t[12]>>4) * 4
	if doff < TCPHdrLen || doff > len(t) {
		return nil, fmt.Errorf("TCP data offset invalid: %d", doff)
	}
	pp.Flags = t[13]
	pp.Window = binary.BigEndian.Uint16(t[14:])

	// Verify TCP checksum (pseudo-header includes IPs).
	if !verifyTCPChecksum(pp.SrcIP, pp.DstIP, t) {
		return nil, fmt.Errorf("TCP checksum bad")
	}

	// Parse options.
	opts := t[TCPHdrLen:doff]
	if err := decodeOptions(opts, &pp.Options); err != nil {
		return nil, err
	}

	pp.Payload = append([]byte(nil), t[doff:]...)
	return pp, nil
}

func decodeOptions(b []byte, o *Options) error {
	for i := 0; i < len(b); {
		kind := b[i]
		switch kind {
		case tcpOptEnd:
			return nil
		case tcpOptNop:
			i++
			continue
		}
		if i+1 >= len(b) {
			return fmt.Errorf("option kind=%d truncated", kind)
		}
		ln := int(b[i+1])
		if ln < 2 || i+ln > len(b) {
			return fmt.Errorf("option kind=%d bad len=%d", kind, ln)
		}
		switch kind {
		case tcpOptMSS:
			if ln != 4 {
				return fmt.Errorf("MSS option bad len=%d", ln)
			}
			o.MSSSet = true
			o.MSS = binary.BigEndian.Uint16(b[i+2:])
		case tcpOptWS:
			if ln != 3 {
				return fmt.Errorf("WS option bad len=%d", ln)
			}
			o.WSSet = true
			o.WS = b[i+2]
		case tcpOptSACKP:
			if ln != 2 {
				return fmt.Errorf("SACKP bad len=%d", ln)
			}
			o.SACKPermitted = true
		case tcpOptTS:
			if ln != 10 {
				return fmt.Errorf("TS option bad len=%d", ln)
			}
			o.TSSet = true
			o.TSVal = binary.BigEndian.Uint32(b[i+2:])
			o.TSEcr = binary.BigEndian.Uint32(b[i+6:])
		}
		i += ln
	}
	return nil
}

// ----------------------------------------------------------------------------
// Checksums
// ----------------------------------------------------------------------------

func inetChecksum(b []byte, seed uint32) uint16 {
	sum := seed
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP [4]byte, tcp []byte) uint16 {
	// Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcpLen(2).
	var ph [12]byte
	copy(ph[0:4], srcIP[:])
	copy(ph[4:8], dstIP[:])
	ph[9] = IPProtoTCP
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcp)))
	var sum uint32
	for i := 0; i < 12; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ph[i:]))
	}
	// Zero the existing checksum field for compute.
	saved := uint16(0)
	if len(tcp) >= 18 {
		saved = binary.BigEndian.Uint16(tcp[16:])
		binary.BigEndian.PutUint16(tcp[16:], 0)
	}
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	if len(tcp) >= 18 {
		binary.BigEndian.PutUint16(tcp[16:], saved)
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func verifyTCPChecksum(srcIP, dstIP [4]byte, tcp []byte) bool {
	// Sum pseudo-header + entire TCP segment (including the carried
	// checksum). Should fold to zero.
	var ph [12]byte
	copy(ph[0:4], srcIP[:])
	copy(ph[4:8], dstIP[:])
	ph[9] = IPProtoTCP
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(tcp)))
	var sum uint32
	for i := 0; i < 12; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ph[i:]))
	}
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum) == 0xFFFF
}

// ParseIP4 turns "a.b.c.d" into a [4]byte.
func ParseIP4(s string) ([4]byte, error) {
	var out [4]byte
	var a, b, c, d int
	_, err := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)
	if err != nil {
		return out, err
	}
	for i, v := range []int{a, b, c, d} {
		if v < 0 || v > 255 {
			return out, fmt.Errorf("bad octet %d in %q", v, s)
		}
		out[i] = byte(v)
	}
	return out, nil
}
