package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxBashPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "linux.bash", Upstream: "linux.bash.Bash", Platform: "linux", NeedsKernel: true,
		Description: "Recover bash history entries from process heaps using the pinned hist_entry layout",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated task.pid filter"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task traversal bound, 1..1000000"},
			{Name: "max-heap-bytes", Kind: "uint", Default: "1073741824", Description: "Maximum selected heap VMA bytes per task, 1..17179869184"},
			{Name: "max-entries", Kind: "uint", Default: "100000", Description: "History entries retained per task, 1..1000000"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"},
			{Name: "CommandTime", Kind: "string"}, {Name: "Command", Kind: "string"},
			{Name: "ProcessIdentity", Kind: "string"}, {Name: "Task", Kind: "address"}, {Name: "Entry", Kind: "address"},
			{Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"},
			{Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"},
		},
	}, linuxBash}}
}

func linuxBash(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Physical == nil || e.Symbols == nil {
		return fmt.Errorf("linux.bash requires kernel memory, symbols and physical memory")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	maxEntries, err := strconv.ParseUint(p["max-entries"], 0, 32)
	if err != nil || maxEntries < 1 || maxEntries > 1000000 {
		return fmt.Errorf("max-entries must be 1..1000000")
	}
	width := e.Symbols.PointerSize()
	if width != 4 && width != 8 {
		return fmt.Errorf("unsupported bash pointer width %d", width)
	}
	heapLimit, err := strconv.ParseUint(p["max-heap-bytes"], 0, 64)
	if err != nil || heapLimit == 0 || heapLimit > 16<<30 {
		return fmt.Errorf("max-heap-bytes must be 1..17179869184")
	}
	var outputErr error
	emit := func(row evidence.Row) error {
		outputErr = out(row)
		return outputErr
	}
	var failures pluginFailures
	var shells, entries uint64
	err = visitLinuxProcesses(ctx, e, max, pids, func(task, pid uint64, name string, created evidence.Value) error {
		if name != "bash" && name != "sh" && name != "dash" {
			return nil
		}
		shells++
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, pid, stamp)
		found, err := linuxBashTask(ctx, e, task, pid, name, identity, int(maxEntries), max, width, heapLimit, emit)
		entries += uint64(found)
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			failures.add(err)
			row := evidence.Row{Cells: map[string]evidence.Value{
				"PID": evidence.Number(pid), "Process": evidence.Text(name), "Task": evidence.Address(task),
				"RecordType": evidence.Text("diagnostic"), "Error": evidence.Missing("bash_history_incomplete", err),
			}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", task)}}
			if err := out(row); err != nil {
				return err
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return err
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{
		"RecordType": evidence.Text("summary"),
		"Coverage":   poolCoverage(map[string]string{"shells": formatCount(shells), "entries": formatCount(entries), "read_layout_errors": strconv.Itoa(failures.count), "scope": "heap hist_entry candidates; invalid entries are not history"}),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: "bash"}}
	if err = out(summary); err != nil {
		return err
	}
	return failures.err("Linux bash history")
}

type bashHistory struct {
	entry   uint64
	seconds *big.Int
	command string
	stamp   evidence.Value
	fields  map[string]evidence.Value
}

func linuxBashTask(ctx context.Context, e plugin.Environment, task, pid uint64, name, identity string, maxEntries, maxRegions, width int, heapLimit uint64, out plugin.Emit) (int, error) {
	mm, err := e.Objects.Uint(ctx, task, "task_struct", "mm")
	if err != nil || mm == 0 {
		if err == nil {
			err = fmt.Errorf("shell has no mm")
		}
		return 0, err
	}
	start, err := e.Objects.Uint(ctx, mm, "mm_struct", "start_brk")
	if err != nil {
		return 0, err
	}
	end, err := e.Objects.Uint(ctx, mm, "mm_struct", "brk")
	if err != nil {
		return 0, err
	}
	if start > end {
		return 0, fmt.Errorf("inverted heap break interval")
	}
	regions, _, err := linuxELFRegions(ctx, e, mm, maxRegions)
	if err != nil {
		return 0, err
	}
	layer, err := processMemory(ctx, e, task, mm, identity)
	if err != nil {
		return 0, err
	}
	virtual, ok := layer.(*memory.Virtual)
	if !ok {
		return 0, fmt.Errorf("process memory is not virtual")
	}
	mapped, err := linuxBashMappings(ctx, virtual.Translator, regions, start, end, heapLimit)
	if err != nil {
		return 0, err
	}
	ranges, heapBytes, mappedBytes, err := linuxBashRanges(regions, mapped, start, end, heapLimit)
	if err != nil {
		return 0, err
	}
	coverage := poolCoverage(map[string]string{
		"heap_bytes": formatCount(heapBytes), "mapped_bytes": formatCount(mappedBytes),
		"unmapped_bytes": formatCount(heapBytes - mappedBytes),
		"scope":          "whole VMAs overlapping [start_brk, brk]; resident mappings only; no swap recovery",
	})
	base := func(kind string) evidence.Row {
		return evidence.Row{Cells: map[string]evidence.Value{
			"PID": evidence.Number(pid), "Process": evidence.Text(name), "Task": evidence.Address(task),
			"ProcessIdentity": evidence.Text(identity), "RecordType": evidence.Text(kind), "Coverage": coverage,
		}, Provenance: evidence.Provenance{Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", task)}}
	}
	if err := out(base("coverage")); err != nil {
		return 0, err
	}
	var failures pluginFailures
	if heapBytes != mappedBytes {
		failures.add(fmt.Errorf("heap scan omits %d unmapped bytes", heapBytes-mappedBytes))
	}
	if len(ranges) == 0 {
		return 0, failures.err("bash heap coverage")
	}
	scanner := &rangeLayer{virtual: virtual, ranges: ranges}
	found, err := linuxBashScan(ctx, scanner, layer, width, maxEntries, func(history bashHistory, err error) error {
		failures.add(err)
		row := base("diagnostic")
		row.Cells["Entry"] = evidence.Address(history.entry)
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: history.fields}
		row.Cells["Error"] = evidence.Missing("candidate_unreadable", err)
		row.Provenance.Offset = fmt.Sprintf("0x%x", history.entry)
		return out(row)
	})
	if err != nil {
		return 0, err
	}

	for _, history := range found {
		row := evidence.Row{Cells: map[string]evidence.Value{
			"PID": evidence.Number(pid), "Process": evidence.Text(name),
			"CommandTime": history.stamp, "Command": evidence.Text(history.command),
			"Task": evidence.Address(task), "Entry": evidence.Address(history.entry), "ProcessIdentity": evidence.Text(identity),
			"FieldEvidence": evidence.Value{Kind: "structure", Data: history.fields},
			"RecordType":    evidence.Text("history"),
		}, Provenance: evidence.Provenance{Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", history.entry)}}
		if err := out(row); err != nil {
			return len(found), err
		}
	}
	return len(found), failures.err("bash history scan")
}

type rangeLayer struct {
	virtual *memory.Virtual
	ranges  []memory.Range
}

func (l *rangeLayer) Name() string           { return l.virtual.Name() }
func (l *rangeLayer) Ranges() []memory.Range { return append([]memory.Range(nil), l.ranges...) }
func (l *rangeLayer) ReadAt(ctx context.Context, p []byte, address uint64) (int, error) {
	return l.virtual.ReadAt(ctx, p, address)
}

// linuxBashMappings preserves the pinned Intel enumeration and walks only
// bounded heap VMAs for ARM64. Invalid descriptors are holes; read failures
// and unsupported descriptors remain errors.
func linuxBashMappings(ctx context.Context, tr memory.Translator, regions []linuxELFRegion, start, end, limit uint64) ([]memory.Range, error) {
	if intel, ok := tr.(*memory.Intel); ok {
		return intel.MappedRanges(ctx)
	}
	if _, ok := tr.(*memory.ARM64); !ok {
		return nil, fmt.Errorf("unsupported bash process translator %T", tr)
	}
	_, _, _, err := linuxBashRanges(regions, nil, start, end, limit)
	if err != nil {
		return nil, err
	}
	var mapped []memory.Range
	for _, vma := range regions {
		if vma.start > end || vma.end < start {
			continue
		}
		for at := vma.start; at < vma.end; {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			n := min(uint64(4096)-at%4096, vma.end-at)
			translation, err := tr.Translate(ctx, at)
			if err != nil {
				var readError *memory.ReadError
				if errors.As(err, &readError) || !errors.Is(err, memory.ErrUnmapped) {
					return nil, err
				}
			} else {
				n = min(translation.Available, vma.end-at)
				if n == 0 {
					return nil, fmt.Errorf("empty bash heap translation at %#x", at)
				}
				last := len(mapped) - 1
				if last >= 0 && mapped[last].Start+mapped[last].Length == at {
					mapped[last].Length += n
				} else {
					mapped = append(mapped, memory.Range{Start: at, Length: n})
				}
			}
			at += n
		}
	}
	return mapped, nil
}

// linuxBashRanges intersects verified whole heap VMAs with resident page runs.
// A merged page-table run may span unrelated VMAs and must never select them.
func linuxBashRanges(regions []linuxELFRegion, mapped []memory.Range, start, end, limit uint64) ([]memory.Range, uint64, uint64, error) {
	var ranges []memory.Range
	var selected, resident uint64
	firstRun := 0
	for _, vma := range regions {
		if vma.start > end || vma.end < start {
			continue
		}
		length := vma.end - vma.start
		if length > limit-selected {
			return nil, selected, resident, fmt.Errorf("heap VMAs exceed max-heap-bytes")
		}
		selected += length
		for index := firstRun; index < len(mapped); index++ {
			run := mapped[index]
			if run.Start >= vma.end {
				break
			}
			runEnd, err := memory.Add(run.Start, run.Length)
			if err != nil {
				return nil, selected, resident, err
			}
			if runEnd <= vma.start {
				firstRun = index + 1
				continue
			}
			lo, hi := max(vma.start, run.Start), min(vma.end, runEnd)
			if lo < hi {
				ranges = append(ranges, memory.Range{Start: lo, Length: hi - lo})
				resident += hi - lo
			}
		}
	}
	return ranges, selected, resident, nil
}

// Scan in batches of 4096 markers, rather than rereading the heap per marker.
// Candidate sorting restores upstream address order across batches before its
// stable time sort; unaligned timestamp pointers are valid on both layouts.
func linuxBashScan(ctx context.Context, scanner, layer memory.MemoryLayer, width, maxEntries int, diagnostic func(bashHistory, error) error) ([]bashHistory, error) {
	var markers []uint64
	if err := memory.Scan(ctx, scanner, []byte{'#'}, func(address uint64) error {
		markers = append(markers, address)
		if len(markers) > 1000000 {
			return fmt.Errorf("hash markers exceed 1000000")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var found []bashHistory
	seen := map[uint64]bool{}
	for offset := 0; offset < len(markers); offset += 4096 {
		if err := memory.ScanPointers(ctx, scanner, markers[offset:min(offset+4096, len(markers))], width, func(address, _ uint64) error {
			if address < uint64(width) {
				return nil
			}
			entry := address - uint64(width)
			if seen[entry] {
				return nil
			}
			if len(seen) >= 1000000 {
				return fmt.Errorf("hist_entry candidates exceed 1000000")
			}
			seen[entry] = true
			history, valid, err := linuxBashEntry(ctx, layer, entry, width)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return diagnostic(history, err)
			}
			if !valid {
				return nil
			}
			if len(found) >= maxEntries {
				return fmt.Errorf("bash history exceeds max-entries")
			}
			found = append(found, history)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].entry < found[j].entry })
	sort.SliceStable(found, func(i, j int) bool { return found[i].seconds.Cmp(found[j].seconds) < 0 })
	return found, nil
}

func linuxBashEntry(ctx context.Context, layer memory.MemoryLayer, entry uint64, width int) (bashHistory, bool, error) {
	h := bashHistory{entry: entry, fields: map[string]evidence.Value{}}
	if width != 4 && width != 8 {
		return h, false, fmt.Errorf("invalid hist_entry pointer width")
	}
	raw, capture, err := linuxCaptureRange(ctx, layer, entry, width*2)
	h.fields["EntryPointers"] = capture
	if err != nil {
		return h, false, err
	}
	var line, stampAddr uint64
	if width == 8 {
		line = binary.LittleEndian.Uint64(raw[:8])
		stampAddr = binary.LittleEndian.Uint64(raw[8:])
	} else {
		line = uint64(binary.LittleEndian.Uint32(raw[:4]))
		stampAddr = uint64(binary.LittleEndian.Uint32(raw[4:8]))
	}
	// Validate the marker first so arbitrary hash references do not demand a
	// command dereference unless they have the timestamp shape.
	stamp, capture, err := linuxBashString(ctx, layer, stampAddr, 1024)
	h.fields["Timestamp"] = capture
	if err != nil {
		return h, false, err
	}
	seconds, valid := linuxBashSeconds(stamp)
	if !valid {
		return h, false, nil
	}
	command, capture, err := linuxBashString(ctx, layer, line, 1024)
	h.fields["Line"] = capture
	if err != nil {
		return h, false, err
	}
	if command == "" {
		return h, false, nil
	}
	h.command, h.seconds = command, seconds
	h.stamp = evidence.Missing("unparsable_timestamp", nil)
	if seconds.Sign() > 0 && seconds.IsInt64() && seconds.Int64() <= 253402300799 {
		h.stamp = evidence.Text(time.Unix(seconds.Int64(), 0).UTC().Format(time.RFC3339))
	}
	return h, true, nil
}

// Python int accepts signs, whitespace, digit separators and arbitrary size.
// Unicode decimal digits remain a documented compatibility gap.
func linuxBashSeconds(stamp string) (*big.Int, bool) {
	if len([]rune(stamp)) < 10 || !strings.HasPrefix(stamp, "#") {
		return nil, false
	}
	s := strings.TrimSpace(stamp[1:])
	if len(s) == 0 {
		return nil, false
	}
	start := 0
	if s[0] == '+' || s[0] == '-' {
		start = 1
	}
	if start == len(s) {
		return nil, false
	}
	for i := start; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			continue
		}
		if s[i] != '_' || i == start || i+1 == len(s) || s[i-1] < '0' || s[i-1] > '9' || s[i+1] < '0' || s[i+1] > '9' {
			return nil, false
		}
	}
	return new(big.Int).SetString(strings.ReplaceAll(s, "_", ""), 10)
}

func linuxBashString(ctx context.Context, layer memory.MemoryLayer, address uint64, limit int) (string, evidence.Value, error) {
	var raw []byte
	requested := 0
	var readErr error
	for len(raw) < limit {
		at, err := memory.Add(address, uint64(len(raw)))
		if err != nil {
			readErr = err
			break
		}
		// Stop at the current page boundary: a terminated string does not need
		// the next page, which may legitimately be absent from the image.
		size := min(limit-len(raw), 4096-int(at&4095))
		chunk := make([]byte, size)
		requested += size
		got, err := layer.ReadAt(ctx, chunk, at)
		if got < 0 || got > size {
			got, err = 0, fmt.Errorf("invalid bash string capture count")
		}
		if err == nil && got != size {
			err = fmt.Errorf("short bash string read: %d/%d", got, size)
		}
		raw = append(raw, chunk[:got]...)
		if err != nil {
			readErr = err
			break
		}
		if bytes.IndexByte(chunk[:got], 0) >= 0 {
			break
		}
	}
	fields := map[string]evidence.Value{"Address": evidence.Address(address), "Raw": evidence.Bytes(raw),
		"RequestedBytes": evidence.Number(uint64(requested)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(readErr == nil)}
	if readErr != nil {
		fields["Error"] = evidence.Missing("string_unreadable", readErr)
	}
	text := raw
	if i := bytes.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	value := strings.ToValidUTF8(string(text), "\uFFFD")
	if i := strings.IndexRune(value, '\uFFFD'); i >= 0 {
		value = value[:i]
	}
	return value, evidence.Value{Kind: "structure", Data: fields}, readErr
}
