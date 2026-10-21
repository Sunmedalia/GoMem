package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
			{Name: "max-entries", Kind: "uint", Default: "100000", Description: "History entries retained per task, 1..1000000"},
		},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"},
			{Name: "CommandTime", Kind: "string"}, {Name: "Command", Kind: "string"},
			{Name: "Task", Kind: "address"}, {Name: "Entry", Kind: "address"},
			{Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"},
			{Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"},
		},
	}, linuxBash}}
}

func linuxBash(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Physical == nil {
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
	var failures pluginFailures
	var shells, entries uint64
	err = visitLinuxProcesses(ctx, e, max, pids, func(task, pid uint64, name string, _ evidence.Value) error {
		if name != "bash" && name != "sh" && name != "dash" {
			return nil
		}
		shells++
		found, err := linuxBashTask(ctx, e, task, pid, name, int(maxEntries), width, out)
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
		entries += uint64(found)
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
	entry, seconds uint64
	command, stamp string
	fields         map[string]evidence.Value
}

func linuxBashTask(ctx context.Context, e plugin.Environment, task, pid uint64, name string, maxEntries, width int, out plugin.Emit) (int, error) {
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
	layer, err := processMemory(ctx, e, task, mm, fmt.Sprintf("%x", task))
	if err != nil {
		return 0, err
	}
	virtual, ok := layer.(*memory.Virtual)
	if !ok {
		return 0, fmt.Errorf("process memory is not virtual")
	}
	intel, ok := virtual.Translator.(*memory.Intel)
	if !ok {
		return 0, fmt.Errorf("process translator is not an Intel page table")
	}
	mapped, err := intel.MappedRanges(ctx)
	if err != nil {
		return 0, err
	}
	var ranges []memory.Range
	// The pinned heap filter keeps each whole VMA that overlaps [start_brk, brk].
	// Page mappings are the readable parts of those VMAs.
	for _, mapping := range mapped {
		if mapping.Length == 0 || mapping.Start > end || mapping.Start+mapping.Length < start {
			continue
		}
		ranges = append(ranges, mapping)
	}
	if len(ranges) == 0 {
		return 0, nil
	}
	scanner := &rangeLayer{virtual: virtual, ranges: ranges}
	var hashes []uint64
	err = memory.Scan(ctx, scanner, []byte{'#'}, func(address uint64) error {
		hashes = append(hashes, address)
		if len(hashes) > 1000000 {
			return fmt.Errorf("hash markers exceed 1000000")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	needles := map[string]uint64{}
	var patterns [][]byte
	for _, address := range hashes {
		raw := make([]byte, width)
		if width == 8 {
			binary.LittleEndian.PutUint64(raw, address)
		} else {
			binary.LittleEndian.PutUint32(raw, uint32(address))
		}
		key := string(raw)
		if _, ok := needles[key]; ok {
			continue
		}
		needles[key] = address
		patterns = append(patterns, raw)
	}
	var found []bashHistory
	seen := map[uint64]bool{}
	for _, pattern := range patterns {
		err = memory.Scan(ctx, scanner, pattern, func(address uint64) error {
			if address < 8 {
				return nil
			}
			entry := address - 8
			if seen[entry] {
				return nil
			}
			seen[entry] = true
			history, ok, err := linuxBashEntry(ctx, layer, entry, width)
			if err != nil || !ok {
				return err
			}
			found = append(found, history)
			if len(found) > maxEntries {
				return fmt.Errorf("bash history exceeds max-entries")
			}
			return nil
		})
		if err != nil {
			return len(found), err
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		return found[i].seconds < found[j].seconds || found[i].seconds == found[j].seconds && found[i].entry < found[j].entry
	})
	for _, history := range found {
		row := evidence.Row{Cells: map[string]evidence.Value{
			"PID": evidence.Number(pid), "Process": evidence.Text(name),
			"CommandTime": evidence.Text(history.stamp), "Command": evidence.Text(history.command),
			"Task": evidence.Address(task), "Entry": evidence.Address(history.entry),
			"FieldEvidence": evidence.Value{Kind: "structure", Data: history.fields},
			"RecordType":    evidence.Text("history"),
		}, Provenance: evidence.Provenance{Layer: layer.Name(), Offset: fmt.Sprintf("0x%x", history.entry)}}
		if err := out(row); err != nil {
			return len(found), err
		}
	}
	return len(found), nil
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

func linuxBashEntry(ctx context.Context, layer memory.MemoryLayer, entry uint64, width int) (bashHistory, bool, error) {
	raw := make([]byte, width*2)
	got, err := layer.ReadAt(ctx, raw, entry)
	if err != nil || got != len(raw) {
		return bashHistory{}, false, nil
	}
	var line, stampAddr uint64
	if width == 8 {
		line = binary.LittleEndian.Uint64(raw[:8])
		stampAddr = binary.LittleEndian.Uint64(raw[8:])
	} else {
		line = uint64(binary.LittleEndian.Uint32(raw[:4]))
		stampAddr = uint64(binary.LittleEndian.Uint32(raw[4:8]))
	}
	command, commandRaw, err := linuxBashString(ctx, layer, line, 1024)
	if err != nil || command == "" {
		return bashHistory{}, false, nil
	}
	stamp, stampRaw, err := linuxBashString(ctx, layer, stampAddr, 1024)
	if err != nil || len(stamp) < 10 || stamp[0] != '#' {
		return bashHistory{}, false, nil
	}
	seconds, err := strconv.ParseUint(stamp[1:], 10, 64)
	if err != nil || seconds > uint64(1<<63-1) {
		return bashHistory{}, false, nil
	}
	when := time.Unix(int64(seconds), 0).UTC()
	return bashHistory{entry: entry, seconds: seconds, command: command, stamp: when.Format(time.RFC3339),
		fields: map[string]evidence.Value{
			"Line":      evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Address": evidence.Address(line), "Raw": evidence.Bytes(commandRaw), "ReadComplete": evidence.Bool(true)}},
			"Timestamp": evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Address": evidence.Address(stampAddr), "Raw": evidence.Bytes(stampRaw), "ReadComplete": evidence.Bool(true)}},
		}}, true, nil
}

func linuxBashString(ctx context.Context, layer memory.MemoryLayer, address uint64, max int) (string, []byte, error) {
	raw := make([]byte, max)
	got, err := layer.ReadAt(ctx, raw, address)
	if got <= 0 {
		return "", nil, err
	}
	raw = raw[:got]
	text := string(raw)
	if !utf8.Valid(raw) {
		text = strings.ToValidUTF8(text, "\uFFFD")
	}
	if i := strings.IndexAny(text, "\x00\uFFFD"); i >= 0 {
		text = text[:i]
	}
	return text, raw, nil
}
