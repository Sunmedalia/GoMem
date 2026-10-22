// Package byteregex implements bounded Python-style byte regular expressions.
// Patterns are UTF-8 encoded bytes; input is never converted into Unicode runes.
package byteregex

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type flags uint8

const (
	fold flags = 1 << iota
	multiline
	dotall
	verbose
)

type charset [256]bool
type width struct{ min, max int }
type node struct {
	kind             string
	set              charset
	children         []*node
	id, low, high    int
	lazy, possessive bool
	flags            flags
	w                width
	linear           *linearPlan
}
type captureSpan struct{ id, start, end int }
type linearPlan struct {
	sets     []*node
	captures []captureSpan
}

func fixedPlan(n *node, plan *linearPlan) bool {
	switch n.kind {
	case "set":
		plan.sets = append(plan.sets, n)
		return true
	case "seq", "seqwrap", "atomic", "group":
		start := len(plan.sets)
		for _, c := range n.children {
			if !fixedPlan(c, plan) {
				return false
			}
		}
		if n.kind == "group" {
			plan.captures = append(plan.captures, captureSpan{n.id, start, len(plan.sets)})
		}
		return true
	}
	return false
}

type parser struct {
	pattern                   []byte
	pos, depth, count, groups int
	names                     map[string]int
	closed                    map[int]width
	open                      map[int]bool
	behindBases               []int
	rootStarted               bool
}

// Regexp is immutable and can be shared by concurrent tasks.
type Regexp struct {
	root       *node
	groups     int
	first      charset
	prefilter  bool
	singleByte int
}

// Compile takes the original text parameter. dotAll is the scanner default,
// not the default used by the upstream result-extraction expressions.
func Compile(pattern string, dotAll bool) (*Regexp, error) {
	if !utf8.ValidString(pattern) {
		return nil, fmt.Errorf("byte regex parameter must be valid UTF-8; use hex escapes for arbitrary bytes")
	}
	if len(pattern) > 65536 {
		return nil, fmt.Errorf("byte regex pattern exceeds 65536 bytes")
	}
	p := &parser{pattern: []byte(pattern), names: map[string]int{}, closed: map[int]width{}, open: map[int]bool{}}
	f := flags(0)
	if dotAll {
		f |= dotall
	}
	n, err := p.expression(&f, true)
	if err == nil && p.pos != len(p.pattern) {
		err = p.error("unbalanced parenthesis")
	}
	if err != nil {
		return nil, err
	}
	var validate func(*node) error
	validate = func(n *node) error {
		if n.kind == "condition" && n.id > p.groups {
			return p.error("invalid conditional group reference")
		}
		for _, c := range n.children {
			if err := validate(c); err != nil {
				return err
			}
		}
		if n.kind == "repeat" {
			plan := &linearPlan{}
			if fixedPlan(n.children[0], plan) && len(plan.sets) > 0 {
				n.linear = plan
			}
		}
		return nil
	}
	if err := validate(n); err != nil {
		return nil, err
	}
	first, nullable, known := firstBytes(n)
	single, count := -1, 0
	for i, ok := range first {
		if ok {
			single = i
			count++
		}
	}
	if count != 1 {
		single = -1
	}
	return &Regexp{root: n, groups: p.groups, first: first, prefilter: known && !nullable, singleByte: single}, nil
}

func firstBytes(n *node) (s charset, nullable, known bool) {
	known = true
	switch n.kind {
	case "set":
		return n.set, false, true
	case "group", "seqwrap", "atomic":
		return firstBytes(n.children[0])
	case "repeat":
		s, nullable, known = firstBytes(n.children[0])
		return s, n.low == 0 || nullable, known
	case "seq":
		nullable = true
		for _, c := range n.children {
			part, empty, ok := firstBytes(c)
			for i := range s {
				s[i] = s[i] || part[i]
			}
			known = known && ok
			if !empty {
				nullable = false
				break
			}
		}
	case "alt", "condition":
		for _, c := range n.children {
			part, empty, ok := firstBytes(c)
			for i := range s {
				s[i] = s[i] || part[i]
			}
			nullable = nullable || empty
			known = known && ok
		}
	case "ref":
		return s, true, false
	default:
		nullable = true
	}
	return
}

func (p *parser) error(message string) error {
	return fmt.Errorf("byte regex at byte %d: %s", p.pos, message)
}
func (p *parser) make(kind string, f flags) (*node, error) {
	p.count++
	if p.count > 32768 {
		return nil, p.error("node limit exceeded")
	}
	return &node{kind: kind, flags: f}, nil
}
func (p *parser) skip(f flags) {
	for p.pos < len(p.pattern) {
		if len(p.pattern)-p.pos >= 3 && p.pattern[p.pos] == '(' && p.pattern[p.pos+1] == '?' && p.pattern[p.pos+2] == '#' {
			start := p.pos
			p.pos += 3
			if err := p.comment(); err == nil {
				continue
			}
			p.pos = start
			return
		}
		if f&verbose == 0 {
			return
		}
		if strings.ContainsRune(" \t\n\r\v\f", rune(p.pattern[p.pos])) {
			p.pos++
			continue
		}
		if p.pattern[p.pos] == '#' {
			for p.pos < len(p.pattern) && p.pattern[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		break
	}
}
func (p *parser) comment() error {
	for p.pos < len(p.pattern) {
		b := p.pattern[p.pos]
		p.pos++
		if b == ')' {
			return nil
		}
		if b == '\\' && p.pos < len(p.pattern) {
			p.pos++
		}
	}
	return p.error("unterminated comment")
}
func (p *parser) expression(f *flags, root bool) (*node, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		return nil, p.error("nesting limit exceeded")
	}
	var alternatives []*node
	for {
		var sequence []*node
		for {
			p.skip(*f)
			if p.pos == len(p.pattern) || p.pattern[p.pos] == '|' || p.pattern[p.pos] == ')' {
				break
			}
			n, err := p.atom(f, root)
			if err != nil {
				return nil, err
			}
			if n == nil {
				continue
			}
			if root {
				p.rootStarted = true
			}
			p.skip(*f)
			n, err = p.quantify(n, *f)
			if err != nil {
				return nil, err
			}
			sequence = append(sequence, n)
		}
		n, err := p.make("seq", *f)
		if err != nil {
			return nil, err
		}
		n.children = sequence
		for _, c := range sequence {
			n.w.min = addWidth(n.w.min, c.w.min)
			n.w.max = addWidth(n.w.max, c.w.max)
		}
		alternatives = append(alternatives, n)
		if p.pos == len(p.pattern) || p.pattern[p.pos] != '|' {
			break
		}
		if root {
			p.rootStarted = true
		}
		p.pos++
	}
	if len(alternatives) == 1 {
		return alternatives[0], nil
	}
	n, err := p.make("alt", *f)
	if err != nil {
		return nil, err
	}
	n.children = alternatives
	n.w = alternatives[0].w
	for _, c := range alternatives[1:] {
		n.w.min = min(n.w.min, c.w.min)
		if n.w.max < 0 || c.w.max < 0 {
			n.w.max = -1
		} else {
			n.w.max = max(n.w.max, c.w.max)
		}
	}
	return n, nil
}
func addWidth(a, b int) int {
	if a < 0 || b < 0 || a > 1<<30-b {
		return -1
	}
	return a + b
}
func multiplyWidth(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a < 0 || b < 0 || a > 1<<30/b {
		return -1
	}
	return a * b
}
func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
func (s *charset) folding() {
	for b := byte('A'); b <= 'Z'; b++ {
		if s[b] || s[b+32] {
			s[b] = true
			s[b+32] = true
		}
	}
}
func classEscape(c byte) (charset, bool) {
	var s charset
	neg := c == 'D' || c == 'S' || c == 'W'
	for i := 0; i < 256; i++ {
		b := byte(i)
		switch c | 32 {
		case 'd':
			s[i] = b >= '0' && b <= '9'
		case 'w':
			s[i] = b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
		case 's':
			s[i] = strings.ContainsRune(" \t\n\r\v\f", rune(b))
		default:
			return s, false
		}
		if neg {
			s[i] = !s[i]
		}
	}
	return s, true
}
func (p *parser) literal(b byte, f flags) (*node, error) {
	n, err := p.make("set", f)
	if err != nil {
		return nil, err
	}
	n.set[b] = true
	if f&fold != 0 {
		n.set.folding()
	}
	n.w = width{1, 1}
	return n, nil
}
func (p *parser) atom(f *flags, root bool) (*node, error) {
	b := p.pattern[p.pos]
	p.pos++
	switch b {
	case '*', '+', '?':
		return nil, p.error("nothing to repeat")
	case '{':
		p.pos--
		empty := &node{kind: "seq"}
		q, err := p.quantify(empty, *f)
		if err != nil {
			return nil, err
		}
		if q != empty {
			return nil, p.error("nothing to repeat")
		}
		p.pos++
		return p.literal(b, *f)
	case '(':
		return p.group(f, root)
	case '[':
		return p.characterClass(*f)
	case '\\':
		return p.escape(*f, false)
	case '.':
		n, err := p.make("set", *f)
		if err != nil {
			return nil, err
		}
		for i := range n.set {
			n.set[i] = byte(i) != '\n' || *f&dotall != 0
		}
		n.w = width{1, 1}
		return n, nil
	case '^', '$':
		return p.make(string(b), *f)
	default:
		return p.literal(b, *f)
	}
}
func (p *parser) escape(f flags, inClass bool) (*node, error) {
	if p.pos == len(p.pattern) {
		return nil, p.error("trailing backslash")
	}
	c := p.pattern[p.pos]
	p.pos++
	if s, ok := classEscape(c); ok {
		n, err := p.make("set", f)
		if err != nil {
			return nil, err
		}
		n.set = s
		n.w = width{1, 1}
		return n, nil
	}
	switch c {
	case 'a':
		return p.literal(7, f)
	case 'b':
		if inClass {
			return p.literal(8, f)
		}
		return p.make("boundary", f)
	case 'B':
		if inClass {
			return nil, p.error("bad class escape")
		}
		return p.make("nonboundary", f)
	case 'f':
		return p.literal(12, f)
	case 'n':
		return p.literal(10, f)
	case 'r':
		return p.literal(13, f)
	case 't':
		return p.literal(9, f)
	case 'v':
		return p.literal(11, f)
	case 'A', 'Z':
		if inClass {
			return nil, p.error("bad class escape")
		}
		return p.make(string(c), f)
	case 'x':
		if len(p.pattern)-p.pos < 2 {
			return nil, p.error("incomplete hex escape")
		}
		n, err := strconv.ParseUint(string(p.pattern[p.pos:p.pos+2]), 16, 8)
		if err != nil {
			return nil, p.error("bad hex escape")
		}
		p.pos += 2
		return p.literal(byte(n), f)
	}
	if c >= '0' && c <= '9' {
		start := p.pos - 1
		if c == '0' || inClass || len(p.pattern)-start >= 3 && octal(p.pattern[start]) && octal(p.pattern[start+1]) && octal(p.pattern[start+2]) {
			if !octal(c) {
				return nil, p.error("bad octal escape")
			}
			for p.pos < len(p.pattern) && p.pos-start < 3 && octal(p.pattern[p.pos]) {
				p.pos++
			}
			v, err := strconv.ParseUint(string(p.pattern[start:p.pos]), 8, 8)
			if err != nil {
				return nil, p.error("octal escape out of range")
			}
			return p.literal(byte(v), f)
		}
		if p.pos < len(p.pattern) && p.pattern[p.pos] >= '0' && p.pattern[p.pos] <= '9' {
			p.pos++
		}
		id, _ := strconv.Atoi(string(p.pattern[start:p.pos]))
		return p.reference(id, f)
	}
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return nil, p.error("unknown byte escape")
	}
	return p.literal(c, f)
}
func octal(b byte) bool { return b >= '0' && b <= '7' }
func (p *parser) reference(id int, f flags) (*node, error) {
	w, ok := p.closed[id]
	if !ok || p.open[id] {
		return nil, p.error("invalid or open group reference")
	}
	for _, base := range p.behindBases {
		if id > base {
			return nil, p.error("reference to group defined in the same lookbehind")
		}
	}
	n, err := p.make("ref", f)
	if err != nil {
		return nil, err
	}
	n.id = id
	n.w = w
	return n, nil
}
func (p *parser) characterClass(f flags) (*node, error) {
	neg := false
	if p.pos < len(p.pattern) && p.pattern[p.pos] == '^' {
		neg = true
		p.pos++
	}
	var set charset
	first := true
	for p.pos < len(p.pattern) {
		if p.pattern[p.pos] == ']' && !first {
			p.pos++
			if f&fold != 0 {
				set.folding()
			}
			if neg {
				for i := range set {
					set[i] = !set[i]
				}
			}
			n, err := p.make("set", f)
			if err != nil {
				return nil, err
			}
			n.set = set
			n.w = width{1, 1}
			return n, nil
		}
		first = false
		s, single, b, err := p.classAtom()
		if err != nil {
			return nil, err
		}
		if p.pos+1 < len(p.pattern) && p.pattern[p.pos] == '-' && p.pattern[p.pos+1] != ']' {
			p.pos++
			_, other, end, err := p.classAtom()
			if err != nil {
				return nil, err
			}
			if !single || !other || end < b {
				return nil, p.error("bad class range")
			}
			for i := int(b); i <= int(end); i++ {
				set[i] = true
			}
		} else {
			for i := range set {
				set[i] = set[i] || s[i]
			}
		}
	}
	return nil, p.error("unterminated character class")
}
func (p *parser) classAtom() (s charset, single bool, b byte, err error) {
	if p.pos == len(p.pattern) {
		err = p.error("unterminated class")
		return
	}
	var n *node
	c := p.pattern[p.pos]
	p.pos++
	if c == '\\' {
		n, err = p.escape(0, true)
	} else {
		n, err = p.literal(c, 0)
	}
	if err != nil {
		return
	}
	s = n.set
	count := 0
	for i, ok := range s {
		if ok {
			count++
			b = byte(i)
		}
	}
	single = count == 1
	return
}
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range []byte(s) {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (p *parser) until(end byte) (string, error) {
	start := p.pos
	for p.pos < len(p.pattern) && p.pattern[p.pos] != end {
		p.pos++
	}
	if p.pos == len(p.pattern) {
		return "", p.error("unterminated group header")
	}
	s := string(p.pattern[start:p.pos])
	p.pos++
	return s, nil
}
func (p *parser) group(f *flags, root bool) (*node, error) {
	kind := "group"
	id := 0
	local := *f
	if p.pos < len(p.pattern) && p.pattern[p.pos] == '?' {
		p.pos++
		if p.pos == len(p.pattern) {
			return nil, p.error("incomplete group")
		}
		switch p.pattern[p.pos] {
		case '#':
			p.pos++
			err := p.comment()
			return nil, err
		case ':':
			kind = "seqwrap"
			p.pos++
		case '>':
			kind = "atomic"
			p.pos++
		case '=':
			kind = "ahead"
			p.pos++
		case '!':
			kind = "notahead"
			p.pos++
		case '<':
			p.pos++
			if p.pos == len(p.pattern) || (p.pattern[p.pos] != '=' && p.pattern[p.pos] != '!') {
				return nil, p.error("unknown group extension")
			}
			kind = "behind"
			if p.pattern[p.pos] == '!' {
				kind = "notbehind"
			}
			p.pos++
		case 'P':
			p.pos++
			if p.pos == len(p.pattern) {
				return nil, p.error("incomplete named group")
			}
			b := p.pattern[p.pos]
			p.pos++
			if b == '=' {
				name, err := p.until(')')
				if err != nil {
					return nil, err
				}
				id, ok := p.names[name]
				if !ok {
					return nil, p.error("unknown group name")
				}
				return p.reference(id, *f)
			}
			if b != '<' {
				return nil, p.error("unknown named group extension")
			}
			name, err := p.until('>')
			if err != nil {
				return nil, err
			}
			if !validName(name) {
				return nil, p.error("invalid group name")
			}
			if _, ok := p.names[name]; ok {
				return nil, p.error("duplicate group name")
			}
			p.groups++
			id = p.groups
			p.names[name] = id
		case '(':
			p.pos++
			condition, err := p.until(')')
			if err != nil {
				return nil, err
			}
			var ok bool
			digits := condition != ""
			for _, b := range []byte(condition) {
				digits = digits && b >= '0' && b <= '9'
			}
			id, err = strconv.Atoi(condition)
			if !digits {
				err = fmt.Errorf("not a decimal group number")
			}
			if err != nil {
				id, ok = p.names[condition]
				if !ok {
					return nil, p.error("unknown conditional group")
				}
			} else if id < 1 || id > 1024 {
				return nil, p.error("invalid conditional group")
			}
			for _, base := range p.behindBases {
				if id > base {
					return nil, p.error("conditional refers to group defined in the same lookbehind")
				}
			}
			n, err := p.make("condition", *f)
			if err != nil {
				return nil, err
			}
			n.id = id
			child, err := p.expression(&local, false)
			if err != nil {
				return nil, err
			}
			if p.pos == len(p.pattern) || p.pattern[p.pos] != ')' {
				return nil, p.error("unterminated conditional")
			}
			p.pos++
			if child.kind == "alt" {
				if len(child.children) != 2 {
					return nil, p.error("conditional has more than two branches")
				}
				n.children = child.children
			} else {
				empty, _ := p.make("seq", local)
				n.children = []*node{child, empty}
			}
			n.w = width{min(n.children[0].w.min, n.children[1].w.min), max(n.children[0].w.max, n.children[1].w.max)}
			if n.children[0].w.max < 0 || n.children[1].w.max < 0 {
				n.w.max = -1
			}
			return n, nil
		default:
			var err error
			var global bool
			local, global, err = p.flagGroup(local)
			if err != nil {
				return nil, err
			}
			if global {
				if !root || p.rootStarted {
					return nil, p.error("global flags must precede the expression")
				}
				*f = local
				return nil, nil
			}
			kind = "seqwrap"
		}
	} else {
		p.groups++
		id = p.groups
	}
	if p.groups > 1024 {
		return nil, p.error("capture group limit exceeded")
	}
	if id > 0 {
		p.open[id] = true
	}
	if kind == "behind" || kind == "notbehind" {
		p.behindBases = append(p.behindBases, p.groups)
	}
	child, err := p.expression(&local, false)
	if err != nil {
		return nil, err
	}
	if p.pos == len(p.pattern) || p.pattern[p.pos] != ')' {
		return nil, p.error("unterminated group")
	}
	p.pos++
	if kind == "behind" || kind == "notbehind" {
		p.behindBases = p.behindBases[:len(p.behindBases)-1]
		if child.w.max < 0 || child.w.min != child.w.max {
			return nil, p.error("lookbehind requires fixed width")
		}
	}
	n, err := p.make(kind, *f)
	if err != nil {
		return nil, err
	}
	n.id = id
	n.children = []*node{child}
	n.w = child.w
	if id > 0 {
		p.open[id] = false
		p.closed[id] = child.w
	}
	if kind == "ahead" || kind == "notahead" || kind == "behind" || kind == "notbehind" {
		n.w = width{}
	}
	return n, nil
}
func (p *parser) flagGroup(f flags) (flags, bool, error) {
	minus := false
	removed := false
	added := flags(0)
	removedBits := flags(0)
	seen := false
	for p.pos < len(p.pattern) {
		c := p.pattern[p.pos]
		p.pos++
		if c == ')' || c == ':' {
			if !seen || minus && !removed {
				return f, false, p.error("empty flag group")
			}
			if c == ')' && minus {
				return f, false, p.error("global flag removal is invalid")
			}
			return f, c == ')', nil
		}
		if c == '-' && !minus {
			minus = true
			continue
		}
		seen = true
		var bit flags
		switch c {
		case 'i':
			bit = fold
		case 'm':
			bit = multiline
		case 's':
			bit = dotall
		case 'x':
			bit = verbose
		case 'a':
			if minus {
				return f, false, p.error("invalid ASCII flag")
			}
			continue
		case 'L':
			return f, false, p.error("locale-sensitive byte regex requires an explicit locale adapter")
		default:
			return f, false, p.error("unknown byte regex flag")
		}
		if minus {
			removed = true
			removedBits |= bit
			f &^= bit
		} else {
			added |= bit
			f |= bit
		}
		if added&removedBits != 0 {
			return f, false, p.error("flag is both enabled and disabled")
		}
	}
	return f, false, p.error("unterminated flag group")
}
func (p *parser) quantify(child *node, f flags) (*node, error) {
	if p.pos == len(p.pattern) {
		return child, nil
	}
	start := p.pos
	low, high := 0, 0
	switch p.pattern[p.pos] {
	case '*':
		high = -1
		p.pos++
	case '+':
		low = 1
		high = -1
		p.pos++
	case '?':
		high = 1
		p.pos++
	case '{':
		p.pos++
		a := p.pos
		for p.pos < len(p.pattern) && p.pattern[p.pos] >= '0' && p.pattern[p.pos] <= '9' {
			p.pos++
		}
		left := string(p.pattern[a:p.pos])
		right := left
		if p.pos < len(p.pattern) && p.pattern[p.pos] == ',' {
			p.pos++
			a = p.pos
			for p.pos < len(p.pattern) && p.pattern[p.pos] >= '0' && p.pattern[p.pos] <= '9' {
				p.pos++
			}
			right = string(p.pattern[a:p.pos])
			if right == "" {
				high = -1
			}
		}
		if p.pos == len(p.pattern) || p.pattern[p.pos] != '}' || (left == "" && right == "" && high != -1) {
			p.pos = start
			return child, nil
		}
		p.pos++
		var err error
		if left != "" {
			low, err = strconv.Atoi(left)
			if err != nil {
				return nil, p.error("repeat bound overflow")
			}
		}
		if high != -1 && right != "" {
			high, err = strconv.Atoi(right)
			if err != nil {
				return nil, p.error("repeat bound overflow")
			}
		}
		if low > 1000000 || high > 1000000 {
			return nil, p.error("repeat resource bound exceeds 1000000")
		}
		if high >= 0 && high < low {
			return nil, p.error("minimum repeat exceeds maximum")
		}
	default:
		return child, nil
	}
	if child.kind == "^" || child.kind == "$" || child.kind == "A" || child.kind == "Z" || child.kind == "boundary" || child.kind == "nonboundary" {
		return nil, p.error("assertion cannot be repeated")
	}
	n, err := p.make("repeat", f)
	if err != nil {
		return nil, err
	}
	n.low = low
	n.high = high
	n.children = []*node{child}
	n.w = width{multiplyWidth(child.w.min, low), multiplyWidth(child.w.max, high)}
	if p.pos < len(p.pattern) {
		if p.pattern[p.pos] == '?' {
			n.lazy = true
			p.pos++
		} else if p.pattern[p.pos] == '+' {
			n.possessive = true
			p.pos++
		}
	}
	if p.pos < len(p.pattern) && strings.ContainsRune("*+?", rune(p.pattern[p.pos])) {
		return nil, p.error("multiple repeat")
	}
	return n, nil
}
