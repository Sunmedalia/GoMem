package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/registry"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

const windowsHiveSignature = 0xBEE0BEE0

var errHiveDirectionStopped = errors.New("hive list direction stopped")

func windowsHivePlugins() []builtin {
	columns := []evidence.Column{}
	for _, group := range []struct{ kind, names string }{
		{"address", "Offset"},
		{"uint64", "Signature"},
		{"string", "Name NameSource FileFullPath FileUserName HiveRootPath FileOutput RecordType Error"},
		{"structure", "Coverage"},
	} {
		for _, name := range strings.Fields(group.names) {
			columns = append(columns, evidence.Column{Name: name, Kind: group.kind})
		}
	}
	return []builtin{{plugin.Spec{Name: "windows.hivelist", Upstream: "windows.registry.hivelist.HiveList", Platform: "windows", NeedsKernel: true,
		Description: "Walk CmpHiveListHead and retain hive signatures, path fields and list breaks",
		Parameters: []plugin.Parameter{
			{Name: "filter", Kind: "string", Description: "Case-insensitive substring of the selected hive name"},
			{Name: "max-nodes", Kind: "uint", Default: "1024", Description: "Hive list bound, 1..1000000"},
			{Name: "dump", Kind: "bool", Default: "false", Description: "Reconstruct each listed stable hive into the case; missing pages are logged and fail the task"},
			{Name: "max-hive", Kind: "uint", Default: "268435456", Description: "Maximum reconstructed hive bytes, including the 4096-byte base block"},
		}, Columns: columns}, windowsHiveList}}
}

func windowsHiveList(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	dump, err := strconv.ParseBool(p["dump"])
	if err != nil {
		return err
	}
	maxHive := uint64(268435456)
	if dump || p["max-hive"] != "" {
		text := p["max-hive"]
		if text == "" {
			text = "268435456"
		}
		maxHive, err = strconv.ParseUint(text, 0, 64)
		if err != nil || maxHive < registry.HiveBaseBlockSize || maxHive > 1<<32 {
			return fmt.Errorf("max-hive must be 4096..4294967296")
		}
	}
	var layout registry.Offsets
	var proc memory.MemoryLayer
	if dump {
		layout, err = windowsHiveLayout(e)
		if err != nil {
			return err
		}
		proc, _, err = windowsRegistryLayer(ctx, e)
		if err != nil {
			return err
		}
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	head, err := e.Symbol("CmpHiveListHead")
	if err != nil {
		return err
	}
	link, err := e.Objects.Field("_CMHIVE", "HiveList")
	if err != nil {
		return err
	}
	filter := strings.ToLower(p["filter"])
	seen := map[uint64]bool{}
	var failures, dumpFailures pluginFailures
	var hives, diagnostics int
	emit := func(address uint64) error {
		if seen[address] {
			return nil
		}
		seen[address] = true
		row := hiveRow(e, address)
		signature, sigErr := e.Objects.Uint(ctx, address, "_CMHIVE", "Hive.Signature")
		if sigErr != nil {
			row.Cells["RecordType"] = evidence.Text("diagnostic")
			row.Cells["Error"] = evidence.Missing("hive_signature_unreadable", sigErr)
			diagnostics++
			failures.add(sigErr)
			if err := out(row); err != nil {
				return err
			}
			return errHiveDirectionStopped
		}
		row.Cells["Signature"] = evidence.Number(signature)
		if signature != windowsHiveSignature {
			cause := fmt.Errorf("hive %#x signature %#x is not %#x", address, signature, windowsHiveSignature)
			row.Cells["RecordType"] = evidence.Text("diagnostic")
			row.Cells["Error"] = evidence.Missing("hive_signature_invalid", cause)
			diagnostics++
			failures.add(cause)
			if err := out(row); err != nil {
				return err
			}
			return errHiveDirectionStopped
		}
		name, source, fields, nameErr := readHiveNames(ctx, e, address)
		for key, value := range fields {
			row.Cells[key] = value
		}
		row.Cells["Name"] = evidence.Text(name)
		row.Cells["NameSource"] = evidence.Text(source)
		if nameErr != nil {
			row.Cells["Name"] = evidence.Missing("hive_name_unreadable", nameErr)
			row.Cells["NameSource"] = evidence.Missing("hive_name_unreadable", nameErr)
			row.Cells["Error"] = evidence.Missing("hive_name_unreadable", nameErr)
			failures.add(nameErr)
		} else if filter != "" && !strings.Contains(strings.ToLower(name), filter) {
			return nil
		}
		if dump {
			value, dumpErr := reconstructWindowsHive(ctx, e, address, name, maxHive, layout, proc)
			row.Cells["FileOutput"] = value
			if dumpErr != nil {
				dumpFailures.add(dumpErr)
				if row.Cells["Error"].Reason == "not_applicable" {
					row.Cells["Error"] = evidence.Missing("hive_reconstruction_incomplete", dumpErr)
				}
			}
		}
		row.Cells["RecordType"] = evidence.Text("hive")
		hives++
		return out(row)
	}
	forwardErr := e.Objects.WalkList(ctx, head, link.Offset, max, emit)
	if forwardErr != nil && !errors.Is(forwardErr, errHiveDirectionStopped) {
		failures.add(forwardErr)
		diagnostic := hiveRow(e, head)
		diagnostic.Cells["RecordType"] = evidence.Text("diagnostic")
		diagnostic.Cells["Error"] = evidence.Missing("hive_list_forward_failed", forwardErr)
		diagnostics++
		if err := out(diagnostic); err != nil {
			return err
		}
	}
	if forwardErr != nil {
		if backErr := walkHiveListBackward(ctx, e, head, link.Offset, max, emit); backErr != nil && !errors.Is(backErr, errHiveDirectionStopped) {
			failures.add(backErr)
			diagnostic := hiveRow(e, head)
			diagnostic.Cells["RecordType"] = evidence.Text("diagnostic")
			diagnostic.Cells["Error"] = evidence.Missing("hive_list_backward_failed", backErr)
			diagnostics++
			if err := out(diagnostic); err != nil {
				return err
			}
		}
	}
	summary := hiveRow(e, head)
	summary.Cells["RecordType"] = evidence.Text("summary")
	coverage := map[string]any{
		"hives":       strconv.Itoa(hives),
		"diagnostics": strconv.Itoa(diagnostics),
	}
	if dump {
		coverage["dump_failures"] = strconv.Itoa(dumpFailures.count)
	}
	summary.Cells["Coverage"] = evidence.Value{Kind: "structure", Data: coverage}
	cause := failures.err("Windows registry hives")
	dumpCause := dumpFailures.err("Windows registry hive reconstruction")
	if cause != nil {
		summary.Cells["Error"] = evidence.Missing("hive_list_incomplete", cause)
	} else if dumpCause != nil {
		summary.Cells["Error"] = evidence.Missing("hive_reconstruction_incomplete", dumpCause)
	}
	if err := out(summary); err != nil {
		return err
	}
	return errors.Join(cause, dumpCause)
}

func hiveRow(e plugin.Environment, address uint64) evidence.Row {
	row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)}}
	for _, column := range windowsHivePlugins()[0].spec.Columns {
		row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
	}
	row.Cells["Offset"] = evidence.Address(address)
	row.Cells["FileOutput"] = evidence.Text("disabled")
	return row
}

func readHiveNames(ctx context.Context, e plugin.Environment, address uint64) (string, string, map[string]evidence.Value, error) {
	fields := map[string]evidence.Value{}
	var selected, source string
	var failures pluginFailures
	for _, name := range []string{"FileFullPath", "FileUserName", "HiveRootPath"} {
		text, err := hiveUnicodeString(ctx, e, address, name)
		if err != nil {
			fields[name] = evidence.Missing("hive_name_unreadable", err)
			failures.add(err)
			continue
		}
		fields[name] = evidence.Text(text)
		if selected == "" && text != "" {
			selected, source = text, name
		}
	}
	if source == "" {
		source = "none"
	}
	if selected == "" {
		return "", source, fields, failures.err("hive name")
	}
	return selected, source, fields, nil
}

func hiveUnicodeString(ctx context.Context, e plugin.Environment, address uint64, field string) (string, error) {
	descriptor, err := e.Objects.Field("_CMHIVE", field)
	if err != nil {
		return "", err
	}
	base, err := memory.Add(address, descriptor.Offset)
	if err != nil {
		return "", err
	}
	length, err := e.Objects.Uint(ctx, base, "_UNICODE_STRING", "Length")
	if err != nil {
		return "", err
	}
	// A zero length is an empty name. Windows does not require a readable buffer.
	if length == 0 {
		return "", nil
	}
	return unicodeString(ctx, e, address, "_CMHIVE", field)
}

func walkHiveListBackward(ctx context.Context, e plugin.Environment, head, offset uint64, max int, emit func(uint64) error) error {
	size := e.Objects.Symbols.PointerSize()
	if size <= 0 {
		return fmt.Errorf("invalid pointer size")
	}
	pointer := symbols.TypeRef{Kind: "pointer"}
	blink, err := memory.Add(head, uint64(size))
	if err != nil {
		return err
	}
	next, err := e.Objects.Scalar(ctx, blink, pointer)
	if err != nil {
		return err
	}
	prev := head
	seen := map[uint64]bool{}
	for next != head {
		if err := ctx.Err(); err != nil {
			return err
		}
		if next == 0 || next < offset {
			return fmt.Errorf("invalid linked-list pointer %#x", next)
		}
		if seen[next] || len(seen) >= max {
			if len(seen) >= max {
				return fmt.Errorf("linked list exceeded %d nodes", max)
			}
			return fmt.Errorf("cycle in linked list at %#x", next)
		}
		seen[next] = true
		flink, err := e.Objects.Scalar(ctx, next, pointer)
		if err != nil {
			return err
		}
		if flink != prev {
			return fmt.Errorf("inconsistent forward link at %#x: have %#x want %#x", next, flink, prev)
		}
		if err := emit(next - offset); err != nil {
			return err
		}
		prev = next
		blink, err = memory.Add(next, uint64(size))
		if err != nil {
			return err
		}
		next, err = e.Objects.Scalar(ctx, blink, pointer)
		if err != nil {
			return err
		}
	}
	return nil
}

func reconstructWindowsHive(ctx context.Context, e plugin.Environment, address uint64, name string, max uint64, layout registry.Offsets, proc memory.MemoryLayer) (evidence.Value, error) {
	h, err := registry.Open(ctx, e.Kernel, proc, address, name, layout)
	if err != nil {
		return evidence.Missing("hive_unreadable", err), err
	}
	size, err := h.StableFileSize(max)
	if err != nil {
		reason := "hive_too_large"
		if strings.Contains(err.Error(), "unreadable") {
			reason = "hive_length_unreadable"
		}
		return evidence.Missing(reason, err), err
	}
	if e.Artifacts == nil {
		err = fmt.Errorf("case artifact sink required for hive dump")
		return evidence.Missing("extraction_unavailable", err), err
	}
	w, err := e.Artifacts.Create(ctx, evidence.ArtifactRequest{Name: hiveFileName(h.Name, address), Size: size, Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", address)})
	if err != nil {
		return evidence.Missing("extraction_unavailable", err), err
	}
	var gaps int
	err = h.VisitStable(ctx, func(span registry.StableSpan) error {
		if span.Err != nil {
			gaps++
			return w.PadZero(ctx, span.Length, span.Address, span.Layer, span.Err)
		}
		n, werr := w.Write(span.Data)
		if werr == nil && n != len(span.Data) {
			werr = io.ErrShortWrite
		}
		return werr
	})
	artifact, finishErr := w.Finish(ctx, err)
	if gaps > 0 {
		err = errors.Join(err, fmt.Errorf("hive %s reconstruction left %d unreadable ranges", h.Name, gaps))
	}
	return evidence.Value{Kind: "artifact", Data: artifact}, errors.Join(err, finishErr)
}

func hiveFileName(name string, address uint64) string {
	base := name
	if i := strings.LastIndex(base, `\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '.', '[', ']', '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			if r == '.' || r == '[' || r == ']' {
				return -1
			}
			return '_'
		}
		if r < 32 {
			return -1
		}
		return r
	}, base)
	base = strings.Trim(base, " _.")
	if base == "" {
		base = "NONAME"
	}
	file := fmt.Sprintf("registry.%s.%x.hive", base, address)
	if len(file) > 160 {
		file = fmt.Sprintf("registry.%x.hive", address)
	}
	return file
}
