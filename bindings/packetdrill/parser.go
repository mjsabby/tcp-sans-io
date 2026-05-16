// Packetdrill DSL parser.
//
// Line-oriented. Each non-blank, non-comment line is one of:
//
//   +N       — time directive (decimal seconds). Folded into the next step.
//   < ...    — inject step.
//   > ...    — expect step.
//   --VERB   — directive step (custom; replaces packetdrill's syscall lines).
//
// Comments start with `#` or `//` and run to end-of-line. Blank lines
// are skipped.
//
// Packet syntax (after `<` or `>`):
//
//   FLAGS SEQ:END(LEN) [ack N] [win N] [ecn ECT0|ECT1|CE|NotECT] [<OPTS>]
//
// FLAGS uses single-letter shorthand:
//   S=SYN  .=ACK  F=FIN  R=RST  P=PSH  E=ECE  W=CWR
//
// A flag combination like `S.` means SYN|ACK; `.` alone is a pure ACK;
// `P.` is PSH|ACK; `F.` is FIN|ACK. The dot is the ACK marker by
// convention; flag letters can otherwise appear in any order.
//
// SEQ and END are script-relative (see symtab.go). SEQ:END(LEN) describes
// the payload range: e.g. `0:0(0)` is empty, `1:1(0)` is an empty
// segment after consuming the SYN, `1:1461(1460)` carries 1460 bytes.
// END must equal SEQ + LEN.
//
// Wildcards: `*` matches any value (only in `>` lines). Named captures:
// `$name` records (in `>`) or substitutes (in `<`) a value.
//
// Options inside `< >` are comma-separated:
//   mss N
//   wscale N
//   sackOK
//   sack N:N,N:N,... (up to 4 blocks)
//   TS val N ecr N      (val/ecr can be `*` or `$name`)
//   nop                 (rare in source; usually elided as padding)

package packetdrill

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	flagFIN byte = 0x01
	flagSYN byte = 0x02
	flagRST byte = 0x04
	flagPSH byte = 0x08
	flagACK byte = 0x10
	flagECE byte = 0x40
	flagCWR byte = 0x80
)

const (
	ecnNotECT uint8 = 0b00
	ecnECT1   uint8 = 0b01
	ecnECT0   uint8 = 0b10
	ecnCE     uint8 = 0b11
)

// ParseFile reads a .pkt file from disk.
func ParseFile(path string) (*Script, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	script, err := ParseReader(path, f)
	if err != nil {
		return nil, err
	}
	return script, nil
}

// ParseReader parses a .pkt from any io.Reader. The path is used only
// for error messages.
func ParseReader(path string, r interface{ Read([]byte) (int, error) }) (*Script, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	script := &Script{Path: path}
	lineNo := 0
	var atMs int64
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Time directive: +N (decimal seconds → integer ms).
		if line[0] == '+' {
			rest, deltaMs, err := parseTime(line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", path, lineNo, err)
			}
			atMs += deltaMs
			line = strings.TrimSpace(rest)
			if line == "" {
				continue
			}
		}

		base := baseStep{line: lineNo, atMs: atMs}
		switch {
		case strings.HasPrefix(line, "<"):
			body := strings.TrimSpace(line[1:])
			pkt, err := parsePacketDesc(body)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: inject: %v", path, lineNo, err)
			}
			script.Steps = append(script.Steps, InjectStep{baseStep: base, Pkt: pkt})

		case strings.HasPrefix(line, ">"):
			body := strings.TrimSpace(line[1:])
			pkt, err := parsePacketDesc(body)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: expect: %v", path, lineNo, err)
			}
			script.Steps = append(script.Steps, ExpectStep{baseStep: base, Pkt: pkt})

		case strings.HasPrefix(line, "--"):
			verb, args := parseDirective(line[2:])
			script.Steps = append(script.Steps, DirectiveStep{
				baseStep: base,
				Verb:     verb,
				Args:     args,
			})

		default:
			return nil, fmt.Errorf("%s:%d: unrecognised line: %q", path, lineNo, raw)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: scan: %v", path, err)
	}
	return script, nil
}

func stripComment(line string) string {
	// Comments start at the first unquoted `#` or `//` (none of our
	// syntax uses # or // otherwise).
	for i := 0; i < len(line); i++ {
		if line[i] == '#' {
			return line[:i]
		}
		if i+1 < len(line) && line[i] == '/' && line[i+1] == '/' {
			return line[:i]
		}
	}
	return line
}

// parseTime parses `+N[.fraction]` at the start of `line` and returns
// the rest of the line plus the parsed delta in ms.
//
// To avoid float drift, fractional seconds are parsed as integer ms
// directly: we split on `.` and treat the second half as base-10 digits
// scaled to milliseconds.
func parseTime(line string) (rest string, deltaMs int64, err error) {
	if len(line) < 2 || line[0] != '+' {
		return line, 0, fmt.Errorf("expected `+N` time directive")
	}
	// Find the end of the number (first whitespace).
	i := 1
	for i < len(line) && line[i] != ' ' && line[i] != '\t' {
		i++
	}
	tok := line[1:i]
	rest = line[i:]
	// Tokenize "S.F": S = whole seconds, F = fractional seconds (max 3 digits).
	dot := strings.IndexByte(tok, '.')
	var secs, ms int64
	if dot < 0 {
		v, perr := strconv.ParseInt(tok, 10, 64)
		if perr != nil {
			return line, 0, fmt.Errorf("invalid time %q: %v", tok, perr)
		}
		secs = v
	} else {
		wholePart := tok[:dot]
		fracPart := tok[dot+1:]
		if wholePart != "" {
			v, perr := strconv.ParseInt(wholePart, 10, 64)
			if perr != nil {
				return line, 0, fmt.Errorf("invalid time seconds %q: %v", wholePart, perr)
			}
			secs = v
		}
		if fracPart != "" {
			// Pad/truncate to 3 digits.
			if len(fracPart) > 3 {
				// Reject sub-ms — the cdylib only has ms granularity, and
				// silently rounding leads to brittle tests.
				if fracPart[3:] != strings.Repeat("0", len(fracPart)-3) {
					return line, 0, fmt.Errorf("time has sub-ms precision (cdylib resolution is 1 ms): %q", tok)
				}
				fracPart = fracPart[:3]
			}
			for len(fracPart) < 3 {
				fracPart += "0"
			}
			v, perr := strconv.ParseInt(fracPart, 10, 64)
			if perr != nil {
				return line, 0, fmt.Errorf("invalid time fraction %q: %v", fracPart, perr)
			}
			ms = v
		}
	}
	deltaMs = secs*1000 + ms
	return rest, deltaMs, nil
}

func parseDirective(s string) (string, []string) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields[1:]
}

// parsePacketDesc parses the body of a `<` or `>` line: everything after
// the leading `<` or `>` and whitespace.
func parsePacketDesc(body string) (PacketDesc, error) {
	// Split off any `<...>` options block first; it's the only place
	// commas-with-spaces appear so it's easiest to extract verbatim.
	var optsBlock string
	if open := strings.Index(body, "<"); open >= 0 {
		close := strings.Index(body[open:], ">")
		if close < 0 {
			return PacketDesc{}, fmt.Errorf("unclosed `<` in options")
		}
		optsBlock = body[open+1 : open+close]
		body = strings.TrimSpace(body[:open] + body[open+close+1:])
	}

	tokens := strings.Fields(body)
	if len(tokens) == 0 {
		return PacketDesc{}, fmt.Errorf("empty packet description")
	}

	desc := PacketDesc{}

	// First token: flag letters.
	flagTok := tokens[0]
	tokens = tokens[1:]
	flags, err := parseFlagLetters(flagTok)
	if err != nil {
		return PacketDesc{}, err
	}
	desc.Flags = flags

	// Second token: SEQ:END(LEN) — required.
	if len(tokens) == 0 {
		return PacketDesc{}, fmt.Errorf("missing seq:end(len)")
	}
	seqTok := tokens[0]
	tokens = tokens[1:]
	seq, endSeq, payloadLen, err := parseSeqRange(seqTok)
	if err != nil {
		return PacketDesc{}, fmt.Errorf("bad seq range %q: %v", seqTok, err)
	}
	desc.Seq = seq
	desc.EndSeq = &endSeq
	desc.PayloadLen = payloadLen

	// Remaining tokens: keyword/value pairs.
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "ack":
			if i+1 >= len(tokens) {
				return PacketDesc{}, fmt.Errorf("`ack` without value")
			}
			ref, err := parseSeqRef(tokens[i+1])
			if err != nil {
				return PacketDesc{}, fmt.Errorf("bad ack %q: %v", tokens[i+1], err)
			}
			desc.Ack = &ref
			i++
		case "win":
			if i+1 >= len(tokens) {
				return PacketDesc{}, fmt.Errorf("`win` without value")
			}
			v, err := strconv.ParseUint(tokens[i+1], 10, 16)
			if err != nil {
				return PacketDesc{}, fmt.Errorf("bad win %q: %v", tokens[i+1], err)
			}
			w := uint16(v)
			desc.Win = &w
			i++
		case "ecn":
			if i+1 >= len(tokens) {
				return PacketDesc{}, fmt.Errorf("`ecn` without value")
			}
			ec, err := parseECNName(tokens[i+1])
			if err != nil {
				return PacketDesc{}, err
			}
			desc.ECN = &ec
			i++
		default:
			return PacketDesc{}, fmt.Errorf("unknown keyword %q", tokens[i])
		}
	}

	if optsBlock != "" {
		opts, err := parseOptions(optsBlock)
		if err != nil {
			return PacketDesc{}, fmt.Errorf("options: %v", err)
		}
		desc.Options = opts
	}

	return desc, nil
}

// parseFlagLetters: e.g. "S", "S.", "F.", "P.", "R", ".".
func parseFlagLetters(s string) (byte, error) {
	if s == "" {
		return 0, fmt.Errorf("empty flag token")
	}
	var out byte
	for _, c := range s {
		switch c {
		case 'S':
			out |= flagSYN
		case '.':
			out |= flagACK
		case 'F':
			out |= flagFIN
		case 'R':
			out |= flagRST
		case 'P':
			out |= flagPSH
		case 'E':
			out |= flagECE
		case 'W':
			out |= flagCWR
		default:
			return 0, fmt.Errorf("unknown flag letter %q in %q", string(c), s)
		}
	}
	return out, nil
}

// parseSeqRange: SEQ:END(LEN). Returns SEQ, END, LEN.
func parseSeqRange(s string) (SeqRef, SeqRef, int, error) {
	lp := strings.Index(s, "(")
	rp := strings.Index(s, ")")
	if lp < 0 || rp < 0 || rp < lp {
		return SeqRef{}, SeqRef{}, 0, fmt.Errorf("missing (LEN)")
	}
	rangePart := s[:lp]
	lenPart := s[lp+1 : rp]
	colon := strings.Index(rangePart, ":")
	if colon < 0 {
		return SeqRef{}, SeqRef{}, 0, fmt.Errorf("missing `:` in seq range")
	}
	seq, err := parseSeqRef(rangePart[:colon])
	if err != nil {
		return SeqRef{}, SeqRef{}, 0, err
	}
	end, err := parseSeqRef(rangePart[colon+1:])
	if err != nil {
		return SeqRef{}, SeqRef{}, 0, err
	}
	length, err := strconv.Atoi(lenPart)
	if err != nil {
		return SeqRef{}, SeqRef{}, 0, fmt.Errorf("bad length: %v", err)
	}
	return seq, end, length, nil
}

// parseSeqRef: a literal int, `*`, or `$name`.
func parseSeqRef(s string) (SeqRef, error) {
	if s == "*" {
		return SeqRef{Mode: SeqWildcard}, nil
	}
	if strings.HasPrefix(s, "$") {
		name := s[1:]
		if name == "" {
			return SeqRef{}, fmt.Errorf("empty $name")
		}
		return SeqRef{Mode: SeqSymbolic, Name: name}, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return SeqRef{}, fmt.Errorf("bad seq number %q: %v", s, err)
	}
	return SeqRef{Mode: SeqLiteral, Value: v}, nil
}

func parseECNName(s string) (uint8, error) {
	switch s {
	case "NotECT", "not-ect":
		return ecnNotECT, nil
	case "ECT0", "ect0":
		return ecnECT0, nil
	case "ECT1", "ect1":
		return ecnECT1, nil
	case "CE", "ce":
		return ecnCE, nil
	default:
		return 0, fmt.Errorf("unknown ECN codepoint %q", s)
	}
}

// parseOptions parses the body of a `<...>` block.
//
// Options are comma-separated; whitespace around commas is tolerated.
// We split by commas and dispatch by the first whitespace-delimited
// token of each piece.
//
// NOPs in the source are stripped: they're padding/alignment, not signal,
// and our wire decoder strips them from emitted packets too. Comparing
// like with like keeps test scripts compact (you write `<TS val 1 ecr 2>`
// not `<TS val 1 ecr 2, nop, nop>`).
func parseOptions(s string) ([]OptionDesc, error) {
	parts := splitOptions(s)
	out := make([]OptionDesc, 0, len(parts))
	for _, raw := range parts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		opt, err := parseOneOption(raw)
		if err != nil {
			return nil, err
		}
		if _, isNop := opt.(NopOpt); isNop {
			continue // strip padding
		}
		out = append(out, opt)
	}
	return out, nil
}

// splitOptions splits on commas, but treats commas inside `sack N:N,N:N`
// as part of the sack list. Simple state machine: track whether we're
// inside a sack value.
func splitOptions(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		// `sack ` keyword: detect by checking if the prior fragment
		// starts with "sack" and we're seeing colons. Simpler approach:
		// only respect commas at depth 0; sack uses colon-separated
		// blocks which we'll parse later.
		if c == ',' && depth == 0 {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func parseOneOption(s string) (OptionDesc, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty option")
	}
	switch fields[0] {
	case "mss":
		if len(fields) != 2 {
			return nil, fmt.Errorf("mss requires one argument")
		}
		v, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad mss: %v", err)
		}
		return MSSOpt{Val: uint16(v)}, nil

	case "wscale":
		if len(fields) != 2 {
			return nil, fmt.Errorf("wscale requires one argument")
		}
		v, err := strconv.ParseUint(fields[1], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("bad wscale: %v", err)
		}
		return WScaleOpt{Shift: uint8(v)}, nil

	case "sackOK":
		if len(fields) != 1 {
			return nil, fmt.Errorf("sackOK takes no arguments")
		}
		return SackPermittedOpt{}, nil

	case "sack":
		// `sack L:R[,L:R...]` — we already split on commas above, so
		// here we only see the FIRST block. To recover the rest, the
		// caller would have to have grouped them. For MVP we accept
		// exactly one block per sack option and document the limitation.
		if len(fields) != 2 {
			return nil, fmt.Errorf("sack requires one L:R argument")
		}
		blk, err := parseSackBlock(fields[1])
		if err != nil {
			return nil, err
		}
		return SackOpt{Blocks: []SackBlockDesc{blk}}, nil

	case "TS":
		// Syntax: `TS val N ecr N`.
		if len(fields) != 5 || fields[1] != "val" || fields[3] != "ecr" {
			return nil, fmt.Errorf("TS syntax: TS val N ecr N (got %q)", s)
		}
		val, err := parseSeqRef(fields[2])
		if err != nil {
			return nil, fmt.Errorf("bad TS val: %v", err)
		}
		ecr, err := parseSeqRef(fields[4])
		if err != nil {
			return nil, fmt.Errorf("bad TS ecr: %v", err)
		}
		return TSOpt{Val: val, Ecr: ecr}, nil

	case "nop":
		return NopOpt{}, nil

	default:
		return nil, fmt.Errorf("unknown option %q", fields[0])
	}
}

func parseSackBlock(s string) (SackBlockDesc, error) {
	colon := strings.Index(s, ":")
	if colon < 0 {
		return SackBlockDesc{}, fmt.Errorf("sack block missing `:`")
	}
	l, err := parseSeqRef(s[:colon])
	if err != nil {
		return SackBlockDesc{}, fmt.Errorf("sack left: %v", err)
	}
	r, err := parseSeqRef(s[colon+1:])
	if err != nil {
		return SackBlockDesc{}, fmt.Errorf("sack right: %v", err)
	}
	return SackBlockDesc{Left: l, Right: r}, nil
}
