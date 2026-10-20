package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func cmdlinePlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.cmdline", Upstream: "windows.cmdline.CmdLine", Platform: "windows", NeedsKernel: true,
		Description: "Read native PEB command lines with raw UTF-16, capture lengths and process identities",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process traversal bound"}},
		Columns:     []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Args", Kind: "string"}, {Name: "ArgsFull", Kind: "string"}, {Name: "ArgsRaw", Kind: "bytes"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "PEB", Kind: "address"}, {Name: "Parameters", Kind: "address"}, {Name: "CommandLineOffset", Kind: "address"}, {Name: "Buffer", Kind: "address"}, {Name: "Length", Kind: "uint64"}, {Name: "MaximumLength", Kind: "uint64"}, {Name: "CapturedBytes", Kind: "uint64"}, {Name: "ReadComplete", Kind: "bool"}, {Name: "Validation", Kind: "structure"}}}, windowsCmdline}}
}

func windowsCmdline(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	var failures pluginFailures
	err = visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		row := evidence.Row{Cells: map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(name), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", process)}}
		for _, field := range []string{"Args", "ArgsFull", "ArgsRaw", "PEB", "Parameters", "CommandLineOffset", "Buffer", "Length", "MaximumLength", "CapturedBytes", "ReadComplete", "Validation"} {
			row.Cells[field] = evidence.Missing("not_reached", nil)
		}
		failures.add(readProcessCommandLine(ctx, e, process, identity, &row))
		if err := ctx.Err(); err != nil {
			return err
		}
		return out(row)
	})
	if err != nil {
		return err
	}
	return failures.err("process command lines")
}

func readProcessCommandLine(ctx context.Context, e plugin.Environment, process uint64, identity string, row *evidence.Row) error {
	fail := func(stage string, err error) error {
		row.Cells["Args"], row.Cells["ArgsFull"] = evidence.Missing(stage, err), evidence.Missing(stage, err)
		// Preserve metadata and any captured prefix, even after a later failure.
		for field, value := range row.Cells {
			if value.Kind == "missing" && value.Reason == "not_reached" {
				row.Cells[field] = evidence.Missing(stage, err)
			}
		}
		return err
	}
	peb, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
	if err != nil {
		return fail("peb_pointer_unreadable", err)
	}
	row.Cells["PEB"] = evidence.Address(peb)
	if peb == 0 {
		return fail("no_process_peb", nil)
	}
	layer, err := processMemory(ctx, e, process, 0, identity)
	if err != nil {
		return fail("process_address_space_unavailable", err)
	}
	reader := &object.Reader{Layer: layer, Symbols: e.Symbols}
	row.Provenance.Layer, row.Provenance.Offset = layer.Name(), fmt.Sprintf("0x%x", peb)
	parameters, err := reader.Uint(ctx, peb, "_PEB", "ProcessParameters")
	if err != nil {
		return fail("process_parameters_pointer_unreadable", err)
	}
	row.Cells["Parameters"] = evidence.Address(parameters)
	if parameters == 0 {
		return fail("process_parameters_not_set", nil)
	}
	field, err := reader.Field("_RTL_USER_PROCESS_PARAMETERS", "CommandLine")
	if err != nil {
		return fail("command_line_layout_unavailable", err)
	}
	if field.Type.Kind != "struct" || field.Type.Name != "_UNICODE_STRING" {
		return fail("command_line_layout_unavailable", fmt.Errorf("CommandLine must be an embedded _UNICODE_STRING"))
	}
	descriptor, err := memory.Add(parameters, field.Offset)
	if err != nil {
		return fail("command_line_descriptor_overflow", err)
	}
	row.Cells["CommandLineOffset"] = evidence.Address(descriptor)
	row.Provenance.Offset = fmt.Sprintf("0x%x", descriptor)
	values := make(map[string]uint64, 3)
	for _, name := range []string{"Length", "MaximumLength", "Buffer"} {
		value, err := reader.Uint(ctx, descriptor, "_UNICODE_STRING", name)
		if err != nil {
			return fail("command_line_descriptor_unreadable", err)
		}
		values[name] = value
		row.Cells[name] = evidence.Number(value)
		if name == "Buffer" {
			row.Cells[name] = evidence.Address(value)
		}
	}
	length, capacity, buffer := values["Length"], values["MaximumLength"], values["Buffer"]
	if length > 65535 || capacity > 65535 || length != 0 && buffer == 0 {
		return fail("invalid_command_line_descriptor", fmt.Errorf("invalid UNICODE_STRING length/capacity/buffer"))
	}
	if _, err := memory.Add(buffer, length); err != nil {
		return fail("invalid_command_line_descriptor", err)
	}
	warnings := make([]string, 0)
	if length > capacity {
		warnings = append(warnings, "length_exceeds_maximum")
	}
	if capacity%2 != 0 {
		warnings = append(warnings, "odd_maximum_length")
	}
	row.Cells["Validation"] = evidence.Value{Kind: "structure", Data: warnings}
	row.Provenance.Offset = fmt.Sprintf("0x%x", buffer)
	raw := make([]byte, int(length))
	got := 0
	if length != 0 {
		got, err = layer.ReadAt(ctx, raw, buffer)
	}
	if got < 0 || got > len(raw) {
		return fail("invalid_command_line_read", fmt.Errorf("source returned an invalid byte count"))
	}
	row.Cells["ArgsRaw"] = evidence.Value{Kind: "bytes", Data: raw[:got]}
	row.Cells["CapturedBytes"] = evidence.Number(uint64(got))
	complete := err == nil && got == len(raw)
	row.Cells["ReadComplete"] = evidence.Value{Kind: "bool", Data: complete}
	if !complete {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fail("command_line_buffer_unreadable", err)
	}
	full, decoding := decodeWindowsUTF16(raw)
	warnings = append(warnings, decoding...)
	args := full
	if index := strings.IndexByte(args, 0); index >= 0 {
		warnings = append(warnings, "embedded_nul")
		args = args[:index]
	}
	row.Cells["Args"], row.Cells["ArgsFull"] = evidence.Text(args), evidence.Text(full)
	row.Cells["Validation"] = evidence.Value{Kind: "structure", Data: warnings}
	return nil
}

// Windows UNICODE_STRING is UTF-16LE. Keep all declared bytes separately;
// replacement characters are a display decision, never a change to evidence.
func decodeWindowsUTF16(raw []byte) (string, []string) {
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	warnings := make([]string, 0)
	if len(raw)%2 != 0 {
		warnings = append(warnings, "odd_byte_length")
	}
	for i := 0; i < len(units); i++ {
		v := units[i]
		if v >= 0xd800 && v <= 0xdbff && i+1 < len(units) && units[i+1] >= 0xdc00 && units[i+1] <= 0xdfff {
			i++
		} else if v >= 0xd800 && v <= 0xdfff {
			warnings = append(warnings, "unpaired_surrogate")
			break
		}
	}
	if len(units) > 0 && (units[0] == 0xfeff || units[0] == 0xfffe) {
		warnings = append(warnings, "leading_bom")
	}
	decoded := string(utf16.Decode(units))
	if len(raw)%2 != 0 {
		decoded += "\ufffd"
	}
	return decoded, warnings
}
