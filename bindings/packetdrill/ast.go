// Packetdrill DSL AST.
//
// One Script per .pkt file, made up of Steps that the runner executes in
// order. Time directives (`+N`) are folded into the step they precede —
// each non-time step has an `At` offset (absolute ms from script start).

package packetdrill

import "fmt"

// Script is a parsed .pkt file.
type Script struct {
	Path  string
	Steps []Step
}

// Step is one executable action in the script.
type Step interface {
	stepKind() string
	// LineNo is the 1-based source line for diagnostics.
	LineNo() int
	// AtMs is the absolute time (in ms since script start) the step
	// executes at. Folded in by the parser from `+N` directives.
	AtMs() int64
}

type baseStep struct {
	line int
	atMs int64
}

func (b baseStep) LineNo() int { return b.line }
func (b baseStep) AtMs() int64 { return b.atMs }

// InjectStep: `< FLAGS SEQ:END(LEN) [ack N] [win N] [<OPTS>]`
type InjectStep struct {
	baseStep
	Pkt PacketDesc
}

func (InjectStep) stepKind() string { return "inject" }

// ExpectStep: `> FLAGS SEQ:END(LEN) [ack N] [win N] [<OPTS>]`
type ExpectStep struct {
	baseStep
	Pkt PacketDesc
}

func (ExpectStep) stepKind() string { return "expect" }

// DirectiveStep: `--VERB ARG1 ARG2 ...`
type DirectiveStep struct {
	baseStep
	Verb string
	Args []string
}

func (DirectiveStep) stepKind() string { return "directive" }

// PacketDesc is the parsed form of a `<` or `>` line.
//
// Flags is the TCP flags byte (SYN/ACK/...). Seq, EndSeq, Ack are seqs
// in *script-relative* form — the runner translates them through the
// symbol table to/from real wire seq numbers.
type PacketDesc struct {
	Flags      byte
	Seq        SeqRef
	EndSeq     *SeqRef // nil if not specified (implied = Seq+PayloadLen)
	PayloadLen int
	Ack        *SeqRef
	Win        *uint16 // raw wire window (not WS-scaled)
	ECN        *uint8  // IP TOS ECN codepoint (NotECT/ECT0/ECT1/CE). nil = NotECT
	Options    []OptionDesc
	// HasPayload is true if the script explicitly described a payload
	// length > 0; the actual bytes are synthesized from a known pattern
	// so the runner can verify recv on the cdylib side.
}

// SeqRef is a sequence number in script-relative form. The owning side
// is determined by where it appears in the PacketDesc (Seq belongs to
// the emitter, Ack belongs to the recipient i.e. the other side).
type SeqRef struct {
	Mode  SeqMode
	Value int64  // for Literal
	Name  string // for Symbolic
}

type SeqMode uint8

const (
	// SeqLiteral: an explicit relative number, e.g. `5`.
	SeqLiteral SeqMode = iota
	// SeqWildcard: `*` — matches anything (only valid in ExpectStep).
	SeqWildcard
	// SeqSymbolic: `$name` — captures (in ExpectStep) or substitutes (in
	// InjectStep) a named value from the symbol table.
	SeqSymbolic
)

func (s SeqRef) String() string {
	switch s.Mode {
	case SeqLiteral:
		return fmt.Sprintf("%d", s.Value)
	case SeqWildcard:
		return "*"
	case SeqSymbolic:
		return "$" + s.Name
	default:
		return "?"
	}
}

// OptionDesc is a TCP option entry, parameterised the same way as wire-side
// options. The runner constructs / compares them via the wire codec.
type OptionDesc interface {
	optName() string
}

type MSSOpt struct{ Val uint16 }

func (MSSOpt) optName() string { return "mss" }

type WScaleOpt struct{ Shift uint8 }

func (WScaleOpt) optName() string { return "wscale" }

type SackPermittedOpt struct{}

func (SackPermittedOpt) optName() string { return "sackOK" }

type SackBlockDesc struct{ Left, Right SeqRef }

type SackOpt struct{ Blocks []SackBlockDesc }

func (SackOpt) optName() string { return "sack" }

// TSOpt: Timestamps. Either Val/Ecr can be wildcards or symbolics.
type TSOpt struct{ Val, Ecr SeqRef }

func (TSOpt) optName() string { return "TS" }

type NopOpt struct{}

func (NopOpt) optName() string { return "nop" }
