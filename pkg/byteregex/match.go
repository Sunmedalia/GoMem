package byteregex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrBudget = errors.New("byte regex execution budget exhausted")

// Limits bound one Search or FindIter invocation, including all candidate
// starts and backtracking. Zero fields select finite defaults.
type Limits struct {
	Steps   uint64
	Timeout time.Duration
}
type Match struct{ Start, End int }
type capture struct {
	start, end int
	set        bool
}
type state struct {
	pos      int
	captures []capture
}
type execution struct {
	ctx             context.Context
	data            []byte
	steps, maxSteps uint64
	deadline        time.Time
	err             error
	depth           int
}
type continuation func(state) bool

func newExecution(ctx context.Context, data []byte, limits Limits) (*execution, error) {
	if ctx == nil {
		return nil, fmt.Errorf("byte regex needs a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limits.Steps == 0 {
		limits.Steps = 100000000
	}
	if limits.Timeout == 0 {
		limits.Timeout = time.Second
	}
	if limits.Timeout < 0 {
		return nil, fmt.Errorf("byte regex timeout must be positive")
	}
	if len(data) > 32<<20 {
		return nil, fmt.Errorf("byte regex input exceeds 32 MiB")
	}
	return &execution{ctx: ctx, data: data, maxSteps: limits.Steps, deadline: time.Now().Add(limits.Timeout)}, nil
}
func (e *execution) step() bool {
	if e.err != nil {
		return false
	}
	e.steps++
	if e.steps > e.maxSteps {
		e.err = ErrBudget
		return false
	}
	if e.steps == 1 || e.steps&1023 == 0 {
		if err := e.ctx.Err(); err != nil {
			e.err = err
			return false
		}
		if time.Now().After(e.deadline) {
			e.err = fmt.Errorf("%w: timeout", ErrBudget)
			return false
		}
	}
	return true
}
func clone(s state) state { s.captures = append([]capture(nil), s.captures...); return s }
func word(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}

func (e *execution) eval(n *node, s state, k continuation) bool {
	if !e.step() {
		return false
	}
	e.depth++
	defer func() { e.depth-- }()
	if e.depth > 4096 {
		e.err = fmt.Errorf("%w: evaluation depth", ErrBudget)
		return false
	}
	switch n.kind {
	case "set":
		if s.pos < len(e.data) && n.set[e.data[s.pos]] {
			s.pos++
			return k(s)
		}
	case "seq":
		return e.sequence(n.children, 0, s, k)
	case "seqwrap":
		return e.eval(n.children[0], s, k)
	case "alt":
		for _, c := range n.children {
			if e.eval(c, s, k) {
				return true
			}
			if e.err != nil {
				return false
			}
		}
	case "group":
		start := s.pos
		return e.eval(n.children[0], s, func(out state) bool {
			out = clone(out)
			out.captures[n.id] = capture{start, out.pos, true}
			return k(out)
		})
	case "ref":
		c := s.captures[n.id]
		if !c.set {
			return false
		}
		length := c.end - c.start
		if length > len(e.data)-s.pos {
			return false
		}
		for i := 0; i < length; i++ {
			if !e.step() {
				return false
			}
			a, b := e.data[c.start+i], e.data[s.pos+i]
			if n.flags&fold != 0 {
				a, b = asciiLower(a), asciiLower(b)
			}
			if a != b {
				return false
			}
		}
		s.pos += length
		return k(s)
	case "condition":
		i := 1
		if s.captures[n.id].set {
			i = 0
		}
		return e.eval(n.children[i], s, k)
	case "^":
		if s.pos == 0 || n.flags&multiline != 0 && s.pos > 0 && e.data[s.pos-1] == '\n' {
			return k(s)
		}
	case "$":
		if s.pos == len(e.data) || s.pos < len(e.data) && e.data[s.pos] == '\n' && (n.flags&multiline != 0 || s.pos == len(e.data)-1) {
			return k(s)
		}
	case "A":
		if s.pos == 0 {
			return k(s)
		}
	case "Z":
		if s.pos == len(e.data) {
			return k(s)
		}
	case "boundary", "nonboundary":
		left := s.pos > 0 && word(e.data[s.pos-1])
		right := s.pos < len(e.data) && word(e.data[s.pos])
		ok := left != right
		if n.kind == "nonboundary" {
			ok = !ok && len(e.data) > 0
		}
		if ok {
			return k(s)
		}
	case "ahead", "notahead", "behind", "notbehind":
		at := s.pos
		start := at
		behind := n.kind == "behind" || n.kind == "notbehind"
		if behind {
			start -= n.children[0].w.min
		}
		found := false
		result := s
		if start >= 0 {
			probe := s
			probe.pos = start
			e.eval(n.children[0], probe, func(out state) bool {
				if behind && out.pos != at {
					return false
				}
				found = true
				result = out
				return true
			})
		}
		if e.err != nil {
			return false
		}
		negative := n.kind == "notahead" || n.kind == "notbehind"
		if negative {
			if !found {
				return k(s)
			}
		} else if found {
			result.pos = at
			return k(result)
		}
	case "atomic":
		found := false
		result := s
		e.eval(n.children[0], s, func(out state) bool { found = true; result = out; return true })
		if found && e.err == nil {
			return k(result)
		}
	case "repeat":
		if n.possessive {
			found := false
			result := s
			e.repeat(n, 0, s, func(out state) bool { found = true; result = out; return true })
			if found && e.err == nil {
				return k(result)
			}
			return false
		}
		return e.repeat(n, 0, s, k)
	default:
		e.err = fmt.Errorf("invalid byte regex instruction %q", n.kind)
	}
	return false
}
func (e *execution) sequence(nodes []*node, i int, s state, k continuation) bool {
	if !e.step() {
		return false
	}
	for i < len(nodes) && nodes[i].kind == "set" {
		if !e.step() || s.pos == len(e.data) || !nodes[i].set[e.data[s.pos]] {
			return false
		}
		i++
		s.pos++
	}
	if i == len(nodes) {
		return k(s)
	}
	return e.eval(nodes[i], s, func(out state) bool { return e.sequence(nodes, i+1, out, k) })
}
func (e *execution) repeat(n *node, count int, s state, k continuation) bool {
	if !e.step() {
		return false
	}
	if count == 0 && n.linear != nil {
		return e.repeatLinear(n, s, k)
	}
	// An iteration must consume bytes after the minimum has been satisfied.
	// The first empty iteration still records its captures, matching Python.
	if n.lazy && count >= n.low {
		if k(s) {
			return true
		}
	}
	if n.high < 0 || count < n.high {
		if e.eval(n.children[0], s, func(out state) bool {
			if out.pos == s.pos && count+1 >= n.low {
				return k(out)
			}
			return e.repeat(n, count+1, out, k)
		}) {
			return true
		}
	}
	if !n.lazy && count >= n.low {
		return k(s)
	}
	return false
}

// repeatLinear handles unambiguous fixed-width bytes and their captures without
// growing the Go stack for every input byte. Continuations still run in the
// original greedy/lazy order, and each choice receives its own capture state.
func (e *execution) repeatLinear(n *node, s state, k continuation) bool {
	plan := n.linear
	width := len(plan.sets)
	units := 0
	advance := func() bool {
		if n.high >= 0 && units >= n.high || width > len(e.data)-s.pos-units*width {
			return false
		}
		base := s.pos + units*width
		for i, part := range plan.sets {
			if !e.step() {
				return false
			}
			if !part.set[e.data[base+i]] {
				return false
			}
		}
		units++
		return true
	}
	attempt := func(count int) bool {
		if !e.step() {
			return false
		}
		out := s
		out.pos = s.pos + count*width
		if count > 0 && len(plan.captures) > 0 {
			out = clone(out)
			base := out.pos - width
			for _, c := range plan.captures {
				out.captures[c.id] = capture{base + c.start, base + c.end, true}
			}
		}
		return k(out)
	}
	if n.lazy {
		for units < n.low {
			if !advance() {
				return false
			}
		}
		for {
			if attempt(units) {
				return true
			}
			if e.err != nil || !advance() {
				return false
			}
		}
	} else {
		for advance() {
		}
		if e.err != nil || units < n.low {
			return false
		}
		for count := units; count >= n.low; count-- {
			if attempt(count) {
				return true
			}
			if e.err != nil {
				return false
			}
		}
	}
	return false
}

func (r *Regexp) find(e *execution, start int, anchored bool, skipEmptyAt int) *Match {
	for at := start; at <= len(e.data); at++ {
		if !e.step() {
			return nil
		}
		if r.prefilter {
			if at == len(e.data) {
				return nil
			}
			if !r.first[e.data[at]] {
				if anchored {
					return nil
				}
				if r.singleByte >= 0 {
					skip := bytes.IndexByte(e.data[at:], byte(r.singleByte))
					if skip < 0 {
						return nil
					}
					at += skip
				} else {
					for at < len(e.data) && !r.first[e.data[at]] {
						if !e.step() {
							return nil
						}
						at++
					}
					if at == len(e.data) {
						return nil
					}
				}
			}
		}
		var found *Match
		s := state{pos: at}
		if r.groups > 0 {
			s.captures = make([]capture, r.groups+1)
		}
		e.eval(r.root, s, func(out state) bool {
			if out.pos == at && at == skipEmptyAt {
				return false
			}
			found = &Match{at, out.pos}
			return true
		})
		if e.err != nil {
			return nil
		}
		if found != nil {
			return found
		}
		if anchored {
			return nil
		}
	}
	return nil
}

// Search returns the first match at/after start. anchored requires its start to
// equal start; lookbehind still sees the preceding original input bytes.
func (r *Regexp) Search(ctx context.Context, data []byte, start int, anchored bool, limits Limits) (*Match, error) {
	if r == nil || r.root == nil || start < 0 || start > len(data) {
		return nil, fmt.Errorf("invalid byte regex search")
	}
	e, err := newExecution(ctx, data, limits)
	if err != nil {
		return nil, err
	}
	m := r.find(e, start, anchored, -1)
	if err = e.ctx.Err(); err != nil {
		return nil, err
	}
	return m, e.err
}

// FindIter reproduces Python 3.12 byte finditer progression. An empty match can
// be followed by a nonempty alternative at the same start. maxStart is an
// exclusive scanner overlap bound, not an input length or match-end bound.
func (r *Regexp) FindIter(ctx context.Context, data []byte, maxStart int, limits Limits, emit func(Match) error) error {
	if r == nil || r.root == nil || emit == nil || maxStart < 0 {
		return fmt.Errorf("invalid byte regex iteration")
	}
	e, err := newExecution(ctx, data, limits)
	if err != nil {
		return err
	}
	pos, skip := 0, -1
	for pos <= len(data) {
		m := r.find(e, pos, false, skip)
		if e.err != nil {
			return e.err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if m == nil || m.Start >= maxStart {
			return nil
		}
		if err := emit(*m); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		pos = m.End
		skip = -1
		if m.Start == m.End {
			skip = m.Start
		}
	}
	return nil
}
