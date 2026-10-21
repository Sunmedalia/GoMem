package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxKmsgPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.kmsg", Upstream: "linux.kmsg.Kmsg", Platform: "linux", NeedsKernel: true,
		Description: "Read typed Linux printk rings with original-byte evidence and explicit completion",
		Parameters:  []plugin.Parameter{{Name: "max-records", Kind: "uint", Default: "1000000", Description: "Ring record traversal bound, 1..1000000"}, {Name: "max-lines", Kind: "uint", Default: "1000000", Description: "Output log-line bound, 1..1000000"}, {Name: "max-bytes", Kind: "uint", Default: "67108864", Description: "Cumulative acquired-byte budget, 1..1073741824"}},
		Columns:     []evidence.Column{{Name: "facility", Kind: "string"}, {Name: "level", Kind: "string"}, {Name: "timestamp", Kind: "string"}, {Name: "caller", Kind: "string"}, {Name: "line", Kind: "string"}, {Name: "Offset", Kind: "address"}, {Name: "Descriptor", Kind: "address"}, {Name: "RecordID", Kind: "uint64"}, {Name: "State", Kind: "uint64"}, {Name: "StoredID", Kind: "uint64"}, {Name: "IDMatches", Kind: "bool"}, {Name: "Layout", Kind: "string"}, {Name: "RecordType", Kind: "string"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "Coverage", Kind: "structure"}, {Name: "Error", Kind: "missing"}}}, linuxKmsg}}
}

var kmsgLevels = []string{"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}
var kmsgFacilities = []string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp"}

func kmsgLabel(n uint64, labels []string) string {
	if n < uint64(len(labels)) {
		return labels[n]
	}
	return strconv.FormatUint(n, 10)
}

// Python str.splitlines treats CRLF as one boundary and recognizes these
// Unicode separators. Keep blank interior lines, but omit a trailing boundary.
func kmsgLines(s string) []string {
	var lines []string
	start := 0
	cr := false
	for i, r := range s {
		if cr && r == '\n' {
			start = i + 1
			cr = false
			continue
		}
		cr = false
		if r == '\n' || r == '\r' || r == '\v' || r == '\f' || r == 0x1c || r == 0x1d || r == 0x1e || r == 0x85 || r == 0x2028 || r == 0x2029 {
			lines = append(lines, s[start:i])
			start = i + len(string(r))
			cr = r == '\r'
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// Match the ASCII priority and time produced by printk. Unicode whitespace is
// handled explicitly instead of assuming Go's ASCII-only regexp \s semantics.
var kmsgLegacyLine = regexp.MustCompile(`^<([^>]+)>\[([^]]*)\](.*)$`)

func kmsgDigits(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	var result strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			result.WriteRune(r)
			continue
		}
		digit := -1
		for _, span := range unicode.Digit.R16 {
			if uint32(r) >= uint32(span.Lo) && uint32(r) <= uint32(span.Hi) && (uint32(r)-uint32(span.Lo))%uint32(span.Stride) == 0 {
				digit = int((uint32(r) - uint32(span.Lo)) / uint32(span.Stride) % 10)
				break
			}
		}
		if digit < 0 {
			for _, span := range unicode.Digit.R32 {
				if uint32(r) >= span.Lo && uint32(r) <= span.Hi && (uint32(r)-span.Lo)%span.Stride == 0 {
					digit = int((uint32(r) - span.Lo) / span.Stride % 10)
					break
				}
			}
		}
		if digit < 0 {
			return "", false
		}
		result.WriteByte(byte('0' + digit))
	}
	return result.String(), true
}
func kmsgSpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

type kmsgPrefix struct {
	facility, level, timestamp string
	caller                     evidence.Value
}
type kmsgBudgetLayer struct {
	memory.MemoryLayer
	reader *kmsgReader
}

func (l *kmsgBudgetLayer) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if uint64(len(p)) > l.reader.maxBytes-l.reader.acquired {
		return 0, fmt.Errorf("kmsg byte budget exhausted")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

type kmsgReader struct {
	ctx                             context.Context
	e                               plugin.Environment
	send                            plugin.Emit
	maxRecords, maxLines, maxBytes  uint64
	records, lines, reads, acquired uint64
	layout                          string
	currentID                       *uint64
	descriptor                      uint64
}

func (k *kmsgReader) row(kind string, at uint64) evidence.Row {
	return evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Offset": evidence.Address(at), "Layout": evidence.Text(k.layout), "Error": evidence.Missing("not_applicable", nil)}, Provenance: evidence.Provenance{Layer: k.e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", at)}}
}
func (k *kmsgReader) pointer(name string) (uint64, error) {
	s, err := k.e.Symbols.Lookup(name)
	if err != nil {
		return 0, err
	}
	if s.Type == nil || s.Type.Kind != "pointer" {
		return 0, fmt.Errorf("%s requires a declared pointer", name)
	}
	return k.scalar(name)
}
func (k *kmsgReader) scalar(name string) (uint64, error) {
	s, err := k.e.Symbols.Lookup(name)
	if err != nil {
		return 0, err
	}
	if s.Type == nil {
		return 0, fmt.Errorf("%s has no declared type", name)
	}
	at, err := k.e.Symbol(name)
	if err != nil {
		return 0, err
	}
	return k.e.Objects.Scalar(k.ctx, at, *s.Type)
}
func (k *kmsgReader) uint(at uint64, typ, path string) (uint64, error) {
	return k.e.Objects.Uint(k.ctx, at, typ, path)
}
func (k *kmsgReader) read(at, size uint64) ([]byte, error) {
	if size > k.maxBytes-k.acquired {
		return nil, fmt.Errorf("kmsg byte budget exhausted")
	}
	if _, err := memory.Add(at, size); err != nil {
		return nil, err
	}
	var result []byte
	for done := uint64(0); done < size; {
		n := min(size-done, uint64(memory.MaxRead))
		raw, err := memory.Read(k.ctx, k.e.Kernel, at+done, int(n))
		result = append(result, raw...)
		if err != nil {
			return result, err
		}
		done += n
	}
	return result, nil
}
func (k *kmsgReader) record() error {
	if err := k.ctx.Err(); err != nil {
		return err
	}
	if k.records >= k.maxRecords {
		return fmt.Errorf("kmsg record bound exhausted")
	}
	k.records++
	return nil
}
func (k *kmsgReader) line(at uint64, p kmsgPrefix, text string) error {
	if k.lines >= k.maxLines {
		return fmt.Errorf("kmsg line bound exhausted")
	}
	k.lines++
	row := k.row("log", at)
	if k.currentID != nil {
		row.Cells["RecordID"] = evidence.Number(*k.currentID)
		row.Cells["Descriptor"] = evidence.Address(k.descriptor)
	}
	row.Cells["facility"] = evidence.Text(p.facility)
	row.Cells["level"] = evidence.Text(p.level)
	row.Cells["timestamp"] = evidence.Text(p.timestamp)
	row.Cells["caller"] = p.caller
	row.Cells["line"] = evidence.Text(text)
	return k.send(row)
}
func (k *kmsgReader) prefix(at uint64, typ string) (kmsgPrefix, error) {
	p := kmsgPrefix{caller: evidence.Missing("field_not_available", nil)}
	facility, err := k.uint(at, typ, "facility")
	if err != nil {
		return p, err
	}
	level, err := k.uint(at, typ, "level")
	if err != nil {
		return p, err
	}
	ns, err := k.uint(at, typ, "ts_nsec")
	if err != nil {
		return p, err
	}
	p.facility, p.level = kmsgLabel(facility, kmsgFacilities), kmsgLabel(level, kmsgLevels)
	p.timestamp = fmt.Sprintf("%d.%06d", ns/1000000000, ns%1000000000/1000)
	if _, err := k.e.Objects.Field(typ, "caller_id"); err == nil {
		id, err := k.uint(at, typ, "caller_id")
		if err != nil {
			return p, err
		}
		name := "Task"
		if id&0x80000000 != 0 {
			name = "CPU"
		}
		p.caller = evidence.Text(fmt.Sprintf("%s(%d)", name, id&^uint64(0x80000000)))
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		return p, err
	}
	return p, nil
}
func (k *kmsgReader) emitText(at uint64, p kmsgPrefix, raw []byte) error {
	decoded, _ := replaceInvalidUTF8(raw)
	for _, line := range kmsgLines(decoded) {
		if err := k.line(at, p, line); err != nil {
			return err
		}
	}
	return nil
}
func (k *kmsgReader) legacy() error {
	ptr, err := k.pointer("log_buf")
	if err != nil {
		return err
	}
	size, err := k.scalar("log_buf_len")
	if err != nil {
		return err
	}
	if size == 0 {
		return fmt.Errorf("empty log buffer extent")
	}
	raw, err := k.read(ptr, size)
	if err != nil {
		return err
	}
	end, err := k.scalar("log_end")
	if err != nil {
		return err
	}
	// The pinned pointer-to-string conversion stops at the first NUL before
	// rotating. Its log_end-len slice is deliberately not reduced modulo size.
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	decoded, _ := replaceInvalidUTF8(raw)
	decoded, _, _ = strings.Cut(decoded, "\uFFFD")
	if end > size {
		runes := []rune(decoded)
		start := end - size
		if start > uint64(len(runes)) {
			start = uint64(len(runes))
		}
		decoded = string(runes[start:]) + string(runes[:start])
	}
	for _, line := range kmsgLines(decoded) {
		if err := k.record(); err != nil {
			return err
		}
		m := kmsgLegacyLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		stamp := strings.TrimLeftFunc(m[2], kmsgSpace)
		parts := strings.Split(stamp, ".")
		if len(parts) != 2 {
			continue
		}
		_, whole := kmsgDigits(parts[0])
		_, fraction := kmsgDigits(parts[1])
		if !whole || !fraction {
			continue
		}
		rest := []rune(m[3])
		if len(rest) == 0 || !kmsgSpace(rest[0]) {
			continue
		}
		digits, ok := kmsgDigits(m[1])
		if !ok {
			continue
		}
		if len(digits) > 4300 {
			return fmt.Errorf("excessive legacy printk priority digits")
		}
		priority, ok := new(big.Int).SetString(digits, 10)
		if !ok {
			continue
		}
		level := new(big.Int).And(new(big.Int).Set(priority), big.NewInt(7)).Uint64()
		facility := new(big.Int).Rsh(priority, 3)
		label := facility.String()
		if facility.IsUint64() {
			label = kmsgLabel(facility.Uint64(), kmsgFacilities)
		}
		if err := k.line(ptr, kmsgPrefix{label, kmsgLabel(level, kmsgLevels), stamp, evidence.Missing("not_applicable", nil)}, string(rest[1:])); err != nil {
			return err
		}
	}
	return nil
}
func (k *kmsgReader) structured(typ string) error {
	ptr, err := k.pointer("log_buf")
	if err != nil {
		return err
	}
	size, err := k.scalar("log_buf_len")
	if err != nil {
		return err
	}
	first, err := k.scalar("log_first_idx")
	if err != nil {
		return err
	}
	next, err := k.scalar("log_next_idx")
	if err != nil {
		return err
	}
	t, err := k.e.Symbols.Type(typ)
	if err != nil {
		return err
	}
	if size == 0 || size > k.maxBytes || first >= size || next >= size || t.Size == 0 || t.Size > size {
		return fmt.Errorf("invalid structured log extent/index")
	}
	end := size
	if first < next {
		end = next
	}
	seen := map[uint64]bool{}
	for cur := first; cur < end; {
		if err := k.record(); err != nil {
			return err
		}
		if seen[cur] {
			return fmt.Errorf("repeated kmsg record offset %#x", cur)
		}
		seen[cur] = true
		at, err := memory.Add(ptr, cur)
		if err != nil {
			return err
		}
		length, err := k.uint(at, typ, "len")
		if err != nil {
			return err
		}
		if length == 0 {
			cur, end = 0, next
			continue
		}
		if length < t.Size || length > size-cur {
			return fmt.Errorf("invalid kmsg record length %d at %#x", length, at)
		}
		textLen, err := k.uint(at, typ, "text_len")
		if err != nil {
			return err
		}
		dictLen, err := k.uint(at, typ, "dict_len")
		if err != nil {
			return err
		}
		if textLen > length-t.Size || dictLen > length-t.Size-textLen {
			return fmt.Errorf("kmsg text/dict exceeds record")
		}
		p, err := k.prefix(at, typ)
		if err != nil {
			return err
		}
		payload, err := memory.Add(at, t.Size)
		if err != nil {
			return err
		}
		if textLen > 0 {
			raw, err := k.read(payload, textLen)
			if err != nil {
				return err
			}
			if err = k.emitText(at, p, raw); err != nil {
				return err
			}
		}
		if dictLen > 0 {
			dictAt, err := memory.Add(payload, textLen)
			if err != nil {
				return err
			}
			raw, err := k.read(dictAt, dictLen)
			if err != nil {
				return err
			}
			for _, chunk := range bytes.Split(raw, []byte{0}) {
				decoded, _ := replaceInvalidUTF8(chunk)
				if err = k.line(at, p, " "+decoded); err != nil {
					return err
				}
			}
		}
		cur += length
	}
	return nil
}
func (k *kmsgReader) modern() error {
	root, err := k.pointer("prb")
	if err != nil {
		return err
	}
	if root == 0 {
		return fmt.Errorf("null printk ring")
	}
	u := func(path string) (uint64, error) { return k.uint(root, "printk_ringbuffer", path) }
	bits, err := u("desc_ring.count_bits")
	if err != nil {
		return err
	}
	if bits > 20 {
		return fmt.Errorf("excessive printk descriptor count")
	}
	count := uint64(1) << bits
	textBits, err := u("text_data_ring.size_bits")
	if err != nil {
		return err
	}
	if textBits > 30 {
		return fmt.Errorf("excessive printk text extent")
	}
	textSize := uint64(1) << textBits
	if textSize > k.maxBytes {
		return fmt.Errorf("printk text ring exceeds byte bound")
	}
	data, err := u("text_data_ring.data")
	if err != nil {
		return err
	}
	descs, err := u("desc_ring.descs")
	if err != nil {
		return err
	}
	infos, err := u("desc_ring.infos")
	if err != nil {
		return err
	}
	dt, err := k.e.Symbols.Type("prb_desc")
	if err != nil {
		return err
	}
	it, err := k.e.Symbols.Type("printk_info")
	if err != nil {
		return err
	}
	width := k.e.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return fmt.Errorf("invalid printk pointer width")
	}
	if dt.Size == 0 || dt.Size > 1<<20 || it.Size == 0 || it.Size > 1<<20 {
		return fmt.Errorf("invalid printk record extents")
	}
	flagShift := uint(width*8 - 2)
	mask := uint64(1)<<flagShift - 1
	cur, err := u("desc_ring.tail_id.counter")
	if err != nil {
		return err
	}
	var previousHead uint64
	first := true
	for first || cur != previousHead {
		first = false
		if err := k.record(); err != nil {
			return err
		}
		head, err := u("desc_ring.head_id.counter")
		if err != nil {
			return err
		}
		previousHead = head
		if cur > mask || head > mask {
			return fmt.Errorf("printk IDs exceed state mask")
		}
		desc, err := memory.Add(descs, (cur%count)*dt.Size)
		if err != nil {
			return err
		}
		info, err := memory.Add(infos, (cur%count)*it.Size)
		if err != nil {
			return err
		}
		recordID := cur
		k.currentID = &recordID
		k.descriptor = desc
		state, err := k.uint(desc, "prb_desc", "state_var.counter")
		if err != nil {
			return err
		}
		flags := (state >> flagShift) & 3
		row := k.row("descriptor", desc)
		row.Cells["RecordID"], row.Cells["State"] = evidence.Number(cur), evidence.Number(flags)
		row.Cells["StoredID"], row.Cells["IDMatches"] = evidence.Number(state&mask), evidence.Bool(state&mask == cur)
		if err = k.send(row); err != nil {
			return err
		}
		if flags == 1 || flags == 2 {
			p, err := k.prefix(info, "printk_info")
			if err != nil {
				return err
			}
			begin, err := k.uint(desc, "prb_desc", "text_blk_lpos.begin")
			if err != nil {
				return err
			}
			end, err := k.uint(desc, "prb_desc", "text_blk_lpos.next")
			if err != nil {
				return err
			}
			begin, end = begin%textSize, end%textSize
			if begin&1 == 0 {
				if begin > end {
					begin = 0
				}
				length, err := k.uint(info, "printk_info", "text_len")
				if err != nil {
					return err
				}
				if length > end-begin {
					length = end - begin
				}
				// The pinned reader caps text_len with end-begin before skipping the ID
				// word. Preserve that coordinate, including its possible over-read.
				textAt, err := memory.Add(data, begin+uint64(width))
				if err != nil {
					return err
				}
				raw, err := k.read(textAt, length)
				if err != nil {
					return err
				}
				if err = k.emitText(info, p, raw); err != nil {
					return err
				}
			}
			for _, field := range []struct{ name, prefix string }{{"subsystem", " SUBSYSTEM="}, {"device", " DEVICE="}} {
				value, err := k.e.Objects.String(k.ctx, info, "printk_info", "dev_info."+field.name, 256)
				if err != nil {
					return err
				}
				decoded, _ := replaceInvalidUTF8([]byte(value))
				decoded, _, _ = strings.Cut(decoded, "\uFFFD")
				if decoded != "" {
					if err = k.line(info, p, field.prefix+decoded); err != nil {
						return err
					}
				}
			}
		}
		cur = (cur + 1) & mask
	}
	return nil
}

// Match the pinned producer gate for the selected kernel table. Other
// producers and absent/non-numeric versions are not rejected by this gate.
func kmsgCheckProducer(e plugin.Environment) error {
	raw := e.Symbols.Metadata()["producer"]
	if len(raw) == 0 {
		return nil
	}
	var producer struct{ Name, Version string }
	if err := json.Unmarshal(raw, &producer); err != nil {
		return err
	}
	if producer.Name != "dwarf2json" || producer.Version == "" {
		return nil
	}
	for _, r := range producer.Version {
		if r != '.' && (r < '0' || r > '9') {
			return nil
		}
	}
	parts := strings.Split(producer.Version, ".")
	version := make([]int, len(parts))
	for i, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("invalid dwarf2json version: %w", err)
		}
		version[i] = n
	}
	minimum := []int{0, 4, 1}
	comparison := 0
	for i := 0; i < min(len(version), len(minimum)); i++ {
		if version[i] < minimum[i] {
			comparison = -1
			break
		}
		if version[i] > minimum[i] {
			comparison = 1
			break
		}
	}
	if comparison == 0 {
		if len(version) > len(minimum) {
			comparison = 1
		} else {
			comparison = -1
		}
	}
	if comparison <= 0 {
		return fmt.Errorf("linux.kmsg requires dwarf2json newer than 0.4.1 (found %s)", producer.Version)
	}
	return nil
}

func linuxKmsg(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if err := kmsgCheckProducer(e); err != nil {
		return err
	}
	if e.Architecture != "x64" && e.Architecture != "x86" && e.Architecture != "pae" {
		return fmt.Errorf("linux.kmsg requires an Intel kernel layer")
	}
	bound := func(name string, max uint64) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 64)
		if err != nil || n == 0 || n > max {
			return 0, fmt.Errorf("%s must be 1..%d", name, max)
		}
		return n, nil
	}
	records, err := bound("max-records", 1000000)
	if err != nil {
		return err
	}
	lines, err := bound("max-lines", 1000000)
	if err != nil {
		return err
	}
	budget, err := bound("max-bytes", 1<<30)
	if err != nil {
		return err
	}
	var outputErr error
	send := func(row evidence.Row) error {
		if outputErr != nil {
			return outputErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		outputErr = out(row)
		return outputErr
	}
	k := &kmsgReader{ctx: ctx, e: e, send: send, maxRecords: records, maxLines: lines, maxBytes: budget}
	hasSymbol := func(name string) bool { _, err := e.Symbols.Lookup(name); return err == nil }
	hasType := func(name string) bool { _, err := e.Symbols.Type(name); return err == nil }
	hasField := func(typ, field string) bool { _, err := e.Objects.Field(typ, field); return err == nil }
	var run func() error
	switch {
	case hasSymbol("log_end") && hasSymbol("log_buf_len") && !hasSymbol("log_first_idx") && !hasField("log", "ts_nsec"):
		k.layout = "text"
		run = k.legacy
	case hasField("log", "ts_nsec") && hasSymbol("log_first_idx"):
		k.layout = "log"
		run = func() error { return k.structured("log") }
	case !hasType("printk_ringbuffer") && hasField("printk_log", "ts_nsec") && hasSymbol("log_first_idx"):
		k.layout = "printk_log"
		run = func() error { return k.structured("printk_log") }
	case hasSymbol("prb") && hasType("printk_ringbuffer"):
		k.layout = "printk_ringbuffer"
		run = k.modern
	default:
		return fmt.Errorf("unsupported kernel log ring layout")
	}
	trace := &linuxIDRLayer{MemoryLayer: &kmsgBudgetLayer{MemoryLayer: e.Kernel, reader: k}}
	trace.observe = func(at uint64, raw []byte, want int, readErr error) error {
		k.acquired += uint64(len(raw))
		k.reads++
		row := k.row("ring_read", at)
		proof := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(readErr == nil)}
		if readErr != nil {
			proof["Error"] = evidence.Missing("read_failed", readErr)
			row.Cells["Error"] = proof["Error"]
		}
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
		return send(row)
	}
	k.e.Kernel = trace
	k.e.Objects = &object.Reader{Layer: trace, Symbols: e.Symbols}
	runErr := run()
	if outputErr != nil {
		return outputErr
	}
	if trace.outputErr != nil {
		return trace.outputErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	summary := k.row("ring_summary", 0)
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Reads": evidence.Number(k.reads), "AcquiredBytes": evidence.Number(k.acquired), "Records": evidence.Number(k.records), "Lines": evidence.Number(k.lines), "Completed": evidence.Bool(runErr == nil)}}
	if runErr != nil {
		summary.Cells["Error"] = evidence.Missing("ring_incomplete", runErr)
	}
	return errors.Join(runErr, send(summary))
}
