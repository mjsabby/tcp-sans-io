// Symbol table for translating between script-relative sequence numbers
// and real cdylib sequence numbers.
//
// In packetdrill scripts both sides use `0` as the relative origin for
// their own sequence numbers. The runner maintains two ISN values:
//
//   our_iss  — the cdylib's initial send sequence (script value `N` for
//              our seq / peer ack maps to `our_iss + N`).
//   peer_iss — the scripted peer's initial send sequence (script value
//              `N` for peer seq / our ack maps to `peer_iss + N`).
//
// Both are 32-bit and translation uses wrapping arithmetic, so scripts
// can run past sequence rollover (though comparisons across more than
// 2³¹ bytes of distance are inherently ambiguous and should be avoided).
//
// Named captures (`$name`) are also stored here: in an ExpectStep they
// record what the runner saw, in an InjectStep they substitute the
// previously captured value.

package packetdrill

import "fmt"

type SymTab struct {
	OurISS  uint32
	PeerISS uint32
	Names   map[string]uint32
}

func NewSymTab(ourISS, peerISS uint32) *SymTab {
	return &SymTab{
		OurISS:  ourISS,
		PeerISS: peerISS,
		Names:   make(map[string]uint32),
	}
}

// Side identifies whether a sequence number is on the cdylib's side
// (Our) or the scripted peer's side (Peer). The same script-relative
// number translates to different real seqs on each side.
type Side uint8

const (
	SideOur Side = iota
	SidePeer
)

// Resolve turns a script-relative SeqRef into a real 32-bit sequence
// number, using `side` to pick the right base ISS.
//
// For a wildcard SeqRef, Resolve returns 0 and a `false` ok value —
// the caller (matcher) should treat the field as "any".
func (s *SymTab) Resolve(ref SeqRef, side Side) (uint32, bool, error) {
	base := s.OurISS
	if side == SidePeer {
		base = s.PeerISS
	}
	switch ref.Mode {
	case SeqLiteral:
		return base + uint32(int32(ref.Value)), true, nil
	case SeqWildcard:
		return 0, false, nil
	case SeqSymbolic:
		v, ok := s.Names[ref.Name]
		if !ok {
			return 0, false, fmt.Errorf("symbolic reference $%s not bound", ref.Name)
		}
		return v, true, nil
	default:
		return 0, false, fmt.Errorf("unknown SeqMode %d", ref.Mode)
	}
}

// CapturePeerAbs records an observed peer-side absolute seq (whatever
// the cdylib received or sent on the peer side) into the symbol table
// under `name`.
func (s *SymTab) Capture(name string, abs uint32) {
	s.Names[name] = abs
}

// ScriptRelative is the inverse of Resolve: given a real wire seq number
// and which side it belongs to, return the script-relative offset.
// Useful for failure diffs.
func (s *SymTab) ScriptRelative(abs uint32, side Side) int32 {
	base := s.OurISS
	if side == SidePeer {
		base = s.PeerISS
	}
	return int32(abs - base)
}
