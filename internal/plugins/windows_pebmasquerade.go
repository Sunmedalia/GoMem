package plugins

import (
	"context"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsPebMasqueradePlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "windows.pebmasquerade", Upstream: "windows.malware.pebmasquerade.PebMasquerade", Platform: "windows", NeedsKernel: true,
		Description: "Inspect native PEB string lengths and kernel audit names, retaining raw strings and read failures",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process traversal bound; native parameter"}},
		Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "EPROCESS_ImageFileName", Kind: "string"}, {Name: "EPROCESS_SeAudit_ImageFileName", Kind: "string"}, {Name: "PEB_ImageFilePath", Kind: "string"},
			{Name: "PEB_ImageFilePath_Spoofed", Kind: "bool"}, {Name: "PEB_CommandLine_Spoofed", Kind: "bool"}, {Name: "PEB_CommandLine", Kind: "string"},
			{Name: "ImagePathLengthMismatch", Kind: "bool"}, {Name: "CommandLineLengthMismatch", Kind: "bool"},
			{Name: "ImagePathEvidence", Kind: "structure"}, {Name: "CommandLineEvidence", Kind: "structure"}, {Name: "AuditEvidence", Kind: "structure"},
			{Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "ProcessLayer", Kind: "string"}, {Name: "PEB", Kind: "address"}, {Name: "Parameters", Kind: "address"},
			{Name: "RecordType", Kind: "string"}, {Name: "Coverage", Kind: "structure"}, {Name: "Error", Kind: "structure"},
		},
	}, windowsPebMasquerade}}
}

// Python len counts Unicode codepoints, including replacement characters, not
// UTF-16 code units. MaximumLength is compared after integer division by two.
func pebLengthMismatch(text string, length, maximum uint64) bool {
	n := int64(utf8.RuneCountInString(text))
	return int64(length/2) != n || int64(maximum/2)-1 != n
}

type pebString struct {
	text     evidence.Value
	mismatch evidence.Value
	details  map[string]evidence.Value
}

// Read each string independently. A bad MaximumLength prevents the length check
// but does not erase readable text. Partial captures remain raw evidence only.
func readPebString(ctx context.Context, layer memory.MemoryLayer, reader *object.Reader, base uint64, typ, field string, check bool, issue func(string, error)) pebString {
	result := pebString{evidence.Missing("not_available", nil), evidence.Missing("not_checked", nil), map[string]evidence.Value{}}
	d := result.details
	fail := func(stage string, err error) pebString {
		d["Error"] = evidence.Missing(stage, err)
		issue(stage, err)
		return result
	}
	member, err := reader.Field(typ, field)
	if err != nil {
		return fail("descriptor_unavailable", err)
	}
	descriptor, err := memory.Add(base, member.Offset)
	if err != nil {
		return fail("descriptor_unavailable", err)
	}
	d["Descriptor"] = evidence.Address(descriptor)
	d["Layer"] = evidence.Text(layer.Name())
	length, err := reader.Uint(ctx, descriptor, "_UNICODE_STRING", "Length")
	if err != nil {
		return fail("length_unreadable", err)
	}
	d["Length"] = evidence.Number(length)
	buffer, err := reader.Uint(ctx, descriptor, "_UNICODE_STRING", "Buffer")
	if err != nil {
		return fail("buffer_pointer_unreadable", err)
	}
	d["Buffer"] = evidence.Address(buffer)
	if length > 65535 {
		return fail("invalid_string_length", fmt.Errorf("UNICODE_STRING length exceeds USHORT: %d", length))
	}
	raw := make([]byte, int(length))
	got := 0
	if length != 0 {
		got, err = layer.ReadAt(ctx, raw, buffer)
	}
	if got < 0 || got > len(raw) {
		return fail("invalid_string_read", fmt.Errorf("invalid byte count %d", got))
	}
	d["Raw"] = evidence.Bytes(raw[:got])
	d["CapturedBytes"] = evidence.Number(uint64(got))
	complete := err == nil && got == len(raw)
	d["ReadComplete"] = evidence.Bool(complete)
	if !complete {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fail("string_buffer_unreadable", err)
	}
	text := poolUTF16(raw)
	d["Decoded"] = evidence.Text(text)
	if text == "" {
		return result
	}
	result.text = evidence.Text(text)
	if !check {
		return result
	}
	maximum, err := reader.Uint(ctx, descriptor, "_UNICODE_STRING", "MaximumLength")
	if err != nil {
		return fail("maximum_length_unreadable", err)
	}
	d["MaximumLength"] = evidence.Number(maximum)
	d["Codepoints"] = evidence.Number(uint64(utf8.RuneCountInString(text)))
	result.mismatch = evidence.Bool(pebLengthMismatch(text, length, maximum))
	return result
}

func pebMasqueradeRow(layer string, process uint64) evidence.Row {
	r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: layer, Offset: fmt.Sprintf("0x%x", process)}}
	for _, c := range windowsPebMasqueradePlugins()[0].spec.Columns {
		r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
	}
	return r
}

func windowsPebMasquerade(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Objects == nil || e.Symbols == nil {
		return fmt.Errorf("windows.pebmasquerade requires kernel memory and symbols")
	}
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	head, err := e.Symbol("PsActiveProcessHead")
	if err != nil {
		return err
	}
	links, err := e.Objects.Field("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return err
	}
	var processes, pathChecked, cmdChecked, pathMismatch, cmdMismatch, diagnostics uint64
	err = e.Objects.WalkList(ctx, head, links.Offset, max, func(process uint64) error {
		pid, err := e.Objects.Uint(ctx, process, "_EPROCESS", "UniqueProcessId")
		if err != nil {
			return err
		}
		if pids != nil && !pids[pid] {
			return nil
		}
		processes++
		r := pebMasqueradeRow(e.Kernel.Name(), process)
		r.Cells["PID"], r.Cells["ProcessOffset"], r.Cells["RecordType"] = evidence.Number(pid), evidence.Address(process), evidence.Text("process")
		issues := map[string]evidence.Value{}
		issue := func(stage string, cause error) { diagnostics++; issues[stage] = evidence.Missing(stage, cause) }
		created, _ := windowsTime(ctx, e, process, "_EPROCESS", "CreateTime")
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		r.Cells["ProcessIdentity"] = evidence.Text(identity)
		for _, name := range []string{"EPROCESS_ImageFileName", "EPROCESS_SeAudit_ImageFileName", "PEB_ImageFilePath", "PEB_CommandLine"} {
			r.Cells[name] = evidence.Missing("not_available", nil)
		}
		for _, name := range []string{"ImagePathLengthMismatch", "CommandLineLengthMismatch"} {
			r.Cells[name] = evidence.Missing("not_checked", nil)
		}
		// The baseline yields these booleans even if it could not perform the checks.
		r.Cells["PEB_ImageFilePath_Spoofed"], r.Cells["PEB_CommandLine_Spoofed"] = evidence.Bool(false), evidence.Bool(false)
		name, err := e.Objects.String(ctx, process, "_EPROCESS", "ImageFileName", 64)
		if err != nil {
			issue("process_name_unreadable", err)
		} else {
			r.Cells["EPROCESS_ImageFileName"] = evidence.Text(name)
		}
		audit, err := e.Objects.Uint(ctx, process, "_EPROCESS", "SeAuditProcessCreationInfo.ImageFileName")
		if err != nil {
			issue("audit_pointer_unreadable", err)
		} else {
			s := readPebString(ctx, e.Kernel, e.Objects, audit, "_OBJECT_NAME_INFORMATION", "Name", false, func(stage string, err error) { issue("audit_"+stage, err) })
			s.details["Object"] = evidence.Address(audit)
			r.Cells["EPROCESS_SeAudit_ImageFileName"], r.Cells["AuditEvidence"] = s.text, evidence.Value{Kind: "structure", Data: s.details}
		}
		// Fresh per-process state: never reuse another process's PEB on a failed read.
		readPEB := func() {
			layer, err := processMemory(ctx, e, process, 0, identity)
			if err != nil {
				issue("process_layer_unavailable", err)
				return
			}
			r.Cells["ProcessLayer"] = evidence.Text(layer.Name())
			peb, err := e.Objects.Uint(ctx, process, "_EPROCESS", "Peb")
			if err != nil {
				issue("peb_pointer_unreadable", err)
				return
			}
			r.Cells["PEB"] = evidence.Address(peb)
			if _, err = memory.Read(ctx, layer, peb, 1); err != nil {
				issue("peb_unreadable", err)
				return
			}
			reader := &object.Reader{Layer: layer, Symbols: e.Symbols}
			parameters, err := reader.Uint(ctx, peb, "_PEB", "ProcessParameters")
			if err != nil {
				issue("parameters_pointer_unreadable", err)
				return
			}
			r.Cells["Parameters"] = evidence.Address(parameters)
			if parameters == 0 {
				return
			}
			for _, f := range []struct {
				field, text, detail, mismatch, upstream string
				checked, mismatches                     *uint64
			}{
				{"ImagePathName", "PEB_ImageFilePath", "ImagePathEvidence", "ImagePathLengthMismatch", "PEB_CommandLine_Spoofed", &pathChecked, &pathMismatch},
				{"CommandLine", "PEB_CommandLine", "CommandLineEvidence", "CommandLineLengthMismatch", "PEB_ImageFilePath_Spoofed", &cmdChecked, &cmdMismatch},
			} {
				s := readPebString(ctx, layer, reader, parameters, "_RTL_USER_PROCESS_PARAMETERS", f.field, true, func(stage string, err error) { issue(f.field+"_"+stage, err) })
				r.Cells[f.text], r.Cells[f.detail], r.Cells[f.mismatch] = s.text, evidence.Value{Kind: "structure", Data: s.details}, s.mismatch
				if s.mismatch.Kind == "bool" {
					(*f.checked)++
					r.Cells[f.upstream] = s.mismatch
					if s.mismatch.Data == true {
						(*f.mismatches)++
					}
				}
			}
		}
		readPEB()
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(issues) > 0 {
			r.Cells["Error"] = evidence.Value{Kind: "structure", Data: issues}
		}
		return out(r)
	})
	if err != nil {
		return err
	}
	r := pebMasqueradeRow(e.Kernel.Name(), 0)
	r.Provenance.Offset = ""
	r.Cells["RecordType"] = evidence.Text("summary")
	r.Cells["Coverage"] = poolCoverage(map[string]string{"processes": formatCount(processes), "image_path_checked": formatCount(pathChecked), "command_line_checked": formatCount(cmdChecked), "image_path_mismatches": formatCount(pathMismatch), "command_line_mismatches": formatCount(cmdMismatch), "diagnostics": formatCount(diagnostics)})
	return out(r)
}
