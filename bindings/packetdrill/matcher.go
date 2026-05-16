// Matcher: compare a cdylib-emitted ParsedPacket against an expected
// PacketDesc. On mismatch, produce a diff that shows both real and
// script-relative seq numbers.

package packetdrill

import (
	"fmt"
	"strings"
)

// MatchPacket compares observed (parsed from cdylib emission) against
// expected (from the script). Returns nil on match or a descriptive
// error on mismatch.
//
// `emitterSide` is the side that produced `observed` — for `> ...`
// expects, the cdylib emitted, so emitterSide = SideOur. The expected
// seq lives in emitterSide's space, and the expected ack in the other
// side's space.
//
// On match, any `$name` capture SeqRefs in `expected` are bound in
// `sym` to the real values observed.
func MatchPacket(observed *ParsedPacket, expected PacketDesc, sym *SymTab, emitterSide Side) error {
	if observed.Flags != expected.Flags {
		return fmt.Errorf("flags mismatch: expected %s, got %s",
			flagString(expected.Flags), flagString(observed.Flags))
	}

	// Seq.
	if err := matchSeqRef("seq", expected.Seq, observed.Seq, sym, emitterSide); err != nil {
		return err
	}

	// Ack (if expected mentions it).
	if expected.Ack != nil {
		otherSide := SidePeer
		if emitterSide == SidePeer {
			otherSide = SideOur
		}
		if err := matchSeqRef("ack", *expected.Ack, observed.Ack, sym, otherSide); err != nil {
			return err
		}
	}

	// Payload length: expected describes payload via SEQ:END(LEN).
	if expected.PayloadLen != len(observed.Payload) {
		return fmt.Errorf("payload length: expected %d, got %d",
			expected.PayloadLen, len(observed.Payload))
	}

	// Window.
	if expected.Win != nil && *expected.Win != observed.Window {
		return fmt.Errorf("window: expected %d, got %d", *expected.Win, observed.Window)
	}

	// ECN codepoint (only if explicitly asserted; otherwise we don't care).
	if expected.ECN != nil && *expected.ECN != observed.ECN {
		return fmt.Errorf("ECN: expected %s, got %s",
			ecnName(*expected.ECN), ecnName(observed.ECN))
	}

	// Options: order-strict, NOPs already stripped in decodeOptions.
	if err := matchOptions(expected.Options, observed.Options, sym, emitterSide); err != nil {
		return err
	}
	return nil
}

func matchSeqRef(label string, ref SeqRef, observed uint32, sym *SymTab, side Side) error {
	switch ref.Mode {
	case SeqWildcard:
		return nil
	case SeqLiteral:
		exp, _, err := sym.Resolve(ref, side)
		if err != nil {
			return err
		}
		if exp != observed {
			expRel := sym.ScriptRelative(exp, side)
			obsRel := sym.ScriptRelative(observed, side)
			return fmt.Errorf("%s mismatch: expected %d (rel %+d), got %d (rel %+d)",
				label, exp, expRel, observed, obsRel)
		}
		return nil
	case SeqSymbolic:
		if prior, ok := sym.Names[ref.Name]; ok {
			if prior != observed {
				return fmt.Errorf("%s symbolic $%s: expected %d (previously bound), got %d",
					label, ref.Name, prior, observed)
			}
			return nil
		}
		// First binding — capture.
		sym.Capture(ref.Name, observed)
		return nil
	}
	return fmt.Errorf("unhandled SeqRef mode %d", ref.Mode)
}

func matchOptions(expected, observed []OptionDesc, sym *SymTab, side Side) error {
	if len(expected) != len(observed) {
		return fmt.Errorf("options count: expected %d (%s), got %d (%s)",
			len(expected), optsSummary(expected),
			len(observed), optsSummary(observed))
	}
	for i := range expected {
		if err := matchOneOption(expected[i], observed[i], sym, side); err != nil {
			return fmt.Errorf("option %d: %v", i, err)
		}
	}
	return nil
}

func matchOneOption(expected, observed OptionDesc, sym *SymTab, side Side) error {
	if expected.optName() != observed.optName() {
		return fmt.Errorf("kind: expected %s, got %s",
			expected.optName(), observed.optName())
	}
	switch exp := expected.(type) {
	case MSSOpt:
		obs := observed.(MSSOpt)
		if exp.Val != obs.Val {
			return fmt.Errorf("mss: expected %d, got %d", exp.Val, obs.Val)
		}
	case WScaleOpt:
		obs := observed.(WScaleOpt)
		if exp.Shift != obs.Shift {
			return fmt.Errorf("wscale: expected %d, got %d", exp.Shift, obs.Shift)
		}
	case SackPermittedOpt:
		// kind already matched
	case SackOpt:
		obs := observed.(SackOpt)
		if len(exp.Blocks) != len(obs.Blocks) {
			return fmt.Errorf("sack blocks: expected %d, got %d",
				len(exp.Blocks), len(obs.Blocks))
		}
		for j := range exp.Blocks {
			// Observed SACK blocks were decoded as absolute u32 wrapped
			// into int64 — translate observed back to absolute and
			// compare with resolved expected.
			el, _, err := sym.Resolve(exp.Blocks[j].Left, SideOur)
			if err != nil {
				return err
			}
			er, _, err := sym.Resolve(exp.Blocks[j].Right, SideOur)
			if err != nil {
				return err
			}
			ol := uint32(obs.Blocks[j].Left.Value)
			or := uint32(obs.Blocks[j].Right.Value)
			if el != ol || er != or {
				return fmt.Errorf("sack block %d: expected %d:%d, got %d:%d",
					j, el, er, ol, or)
			}
		}
	case TSOpt:
		obs := observed.(TSOpt)
		obsVal := uint32(obs.Val.Value)
		obsEcr := uint32(obs.Ecr.Value)
		switch exp.Val.Mode {
		case SeqWildcard:
			// match anything
		case SeqLiteral:
			if uint32(exp.Val.Value) != obsVal {
				return fmt.Errorf("TS val: expected %d, got %d", uint32(exp.Val.Value), obsVal)
			}
		case SeqSymbolic:
			if prior, ok := sym.Names["__ts_"+exp.Val.Name]; ok {
				if prior != obsVal {
					return fmt.Errorf("TS val $%s: expected %d (prior), got %d",
						exp.Val.Name, prior, obsVal)
				}
			} else {
				sym.Names["__ts_"+exp.Val.Name] = obsVal
			}
		}
		switch exp.Ecr.Mode {
		case SeqWildcard:
		case SeqLiteral:
			if uint32(exp.Ecr.Value) != obsEcr {
				return fmt.Errorf("TS ecr: expected %d, got %d", uint32(exp.Ecr.Value), obsEcr)
			}
		case SeqSymbolic:
			if prior, ok := sym.Names["__ts_"+exp.Ecr.Name]; ok {
				if prior != obsEcr {
					return fmt.Errorf("TS ecr $%s: expected %d (prior), got %d",
						exp.Ecr.Name, prior, obsEcr)
				}
			} else {
				sym.Names["__ts_"+exp.Ecr.Name] = obsEcr
			}
		}
	}
	return nil
}

func optsSummary(opts []OptionDesc) string {
	var parts []string
	for _, o := range opts {
		parts = append(parts, o.optName())
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func flagString(b byte) string {
	var s []string
	if b&flagSYN != 0 {
		s = append(s, "S")
	}
	if b&flagACK != 0 {
		s = append(s, ".")
	}
	if b&flagFIN != 0 {
		s = append(s, "F")
	}
	if b&flagRST != 0 {
		s = append(s, "R")
	}
	if b&flagPSH != 0 {
		s = append(s, "P")
	}
	if b&flagECE != 0 {
		s = append(s, "E")
	}
	if b&flagCWR != 0 {
		s = append(s, "W")
	}
	if len(s) == 0 {
		return "[none]"
	}
	return strings.Join(s, "")
}

func ecnName(c uint8) string {
	switch c & 0x03 {
	case ecnNotECT:
		return "NotECT"
	case ecnECT0:
		return "ECT0"
	case ecnECT1:
		return "ECT1"
	case ecnCE:
		return "CE"
	}
	return "?"
}
