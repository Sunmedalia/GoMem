package plugins

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxPsauxPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "linux.psaux", Upstream: "linux.psaux.PsAux", Platform: "linux", NeedsKernel: true,
		Description: "Read process argument ranges with raw bytes, independent page tables and explicit missing data",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated task PID filter"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task traversal bound"}, {Name: "max-args", Kind: "uint", Default: "4096", Description: "Argument byte limit (1..16777216); default matches the pinned reference"}},
		Columns:     []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "PPID", Kind: "uint64"}, {Name: "COMM", Kind: "string"}, {Name: "ARGS", Kind: "string"}, {Name: "Arguments", Kind: "structure"}, {Name: "ArgsRaw", Kind: "bytes"}, {Name: "ArgsSource", Kind: "string"}, {Name: "MM", Kind: "address"}, {Name: "ArgStart", Kind: "address"}, {Name: "ArgEnd", Kind: "address"}, {Name: "Length", Kind: "uint64"}, {Name: "CapturedBytes", Kind: "uint64"}, {Name: "ReadComplete", Kind: "bool"}, {Name: "Validation", Kind: "structure"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}}}, linuxPsaux}}
}

const maxLinuxArgumentVector = 65536

func linuxPsaux(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	maxArgs, err := strconv.ParseUint(p["max-args"], 0, 32)
	if err != nil || maxArgs == 0 || maxArgs > memory.MaxRead {
		return fmt.Errorf("max-args must be 1..%d", memory.MaxRead)
	}
	var failures pluginFailures
	err = visitLinuxProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		row := evidence.Row{Cells: map[string]evidence.Value{"PID": evidence.Number(pid), "COMM": evidence.Text(name), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", process)}}
		parent, err := e.Objects.Uint(ctx, process, "task_struct", "real_parent")
		row.Cells["PPID"] = evidence.Number(0)
		if err != nil {
			row.Cells["PPID"] = evidence.Missing("parent_pointer_unreadable", err)
		} else if parent != 0 {
			// getppid uses the parent's thread-group PID, not its individual TID.
			row.Cells["PPID"] = optionalUint(ctx, e, parent, "task_struct", "tgid", false)
		}
		for _, key := range []string{"ARGS", "Arguments", "ArgsRaw", "ArgsSource", "MM", "ArgStart", "ArgEnd", "Length", "CapturedBytes", "ReadComplete", "Validation"} {
			row.Cells[key] = evidence.Missing("not_reached", nil)
		}
		failures.add(readLinuxArguments(ctx, e, process, identity, name, maxArgs, &row))
		if err := ctx.Err(); err != nil {
			return err
		}
		return out(row)
	})
	if err != nil {
		return err
	}
	return failures.err("Linux process arguments")
}

func readLinuxArguments(ctx context.Context, e plugin.Environment, process uint64, identity, name string, maxArgs uint64, row *evidence.Row) error {
	fail := func(stage string, err error) error {
		row.Cells["ARGS"], row.Cells["Arguments"] = evidence.Missing(stage, err), evidence.Missing(stage, err)
		for key, value := range row.Cells {
			if value.Kind == "missing" && value.Reason == "not_reached" {
				row.Cells[key] = evidence.Missing(stage, err)
			}
		}
		return err
	}
	mm, err := e.Objects.Uint(ctx, process, "task_struct", "mm")
	if err != nil {
		return fail("mm_pointer_unreadable", err)
	}
	row.Cells["MM"] = evidence.Address(mm)
	if mm == 0 {
		fail("no_user_mm", nil)
		row.Cells["ARGS"] = evidence.Text("[" + name + "]")
		row.Cells["ArgsSource"] = evidence.Text("comm_without_mm")
		// Null mm also occurs on exiting user tasks; bracket display alone is
		// not evidence that a task was originally a kernel thread.
		return nil
	}
	row.Cells["ArgsSource"] = evidence.Text("user_argument_bytes")
	for _, name := range []string{"arg_start", "arg_end"} {
		value, err := e.Objects.Uint(ctx, mm, "mm_struct", name)
		if err != nil {
			return fail("argument_range_unreadable", err)
		}
		key := "ArgStart"
		if name == "arg_end" {
			key = "ArgEnd"
		}
		row.Cells[key] = evidence.Address(value)
	}
	start, _ := row.Cells["ArgStart"].Uint()
	end, _ := row.Cells["ArgEnd"].Uint()
	if end < start {
		return fail("invalid_argument_range", fmt.Errorf("argument end %#x precedes start %#x", end, start))
	}
	size := end - start
	row.Cells["Length"] = evidence.Number(size)
	if size == 0 {
		return fail("empty_argument_range", nil)
	}
	if size > maxArgs {
		return fail("argument_size_limit", fmt.Errorf("argument range %d exceeds max-args=%d", size, maxArgs))
	}
	layer, err := processMemory(ctx, e, process, mm, identity)
	if err != nil {
		return fail("process_address_space_unavailable", err)
	}
	row.Provenance.Layer, row.Provenance.Offset = layer.Name(), fmt.Sprintf("0x%x", start)
	raw := make([]byte, int(size))
	got, err := layer.ReadAt(ctx, raw, start)
	if got < 0 || got > len(raw) {
		return fail("invalid_argument_read", fmt.Errorf("source returned an invalid byte count"))
	}
	row.Cells["ArgsRaw"] = evidence.Value{Kind: "bytes", Data: raw[:got]}
	row.Cells["CapturedBytes"] = evidence.Number(uint64(got))
	complete := err == nil && got == len(raw)
	row.Cells["ReadComplete"] = evidence.Value{Kind: "bool", Data: complete}
	if !complete {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fail("argument_buffer_unreadable", err)
	}
	args, vector, warnings := linuxArgumentDisplay(raw)
	row.Cells["ARGS"] = evidence.Text(args)
	row.Cells["Arguments"] = evidence.Value{Kind: "structure", Data: vector}
	row.Cells["Validation"] = evidence.Value{Kind: "structure", Data: warnings}
	if vector == nil {
		err := fmt.Errorf("argument vector exceeds %d entries; complete raw bytes and display retained", maxLinuxArgumentVector)
		row.Cells["Arguments"] = evidence.Missing("argument_count_limit", err)
		return err
	}
	return nil
}

func linuxArgumentDisplay(raw []byte) (string, []string, []string) {
	decoded, valid := replaceInvalidUTF8(raw)
	warnings := make([]string, 0)
	if !valid {
		warnings = append(warnings, "invalid_utf8")
	}
	terminated := len(raw) > 0 && raw[len(raw)-1] == 0
	count := strings.Count(decoded, "\x00") + 1
	if terminated {
		count--
	} else {
		warnings = append(warnings, "missing_terminal_nul")
	}
	var vector []string
	if count > maxLinuxArgumentVector {
		warnings = append(warnings, "argument_count_limit")
	} else {
		vector = strings.Split(decoded, "\x00")
		if terminated {
			vector = vector[:len(vector)-1]
		}
	}
	// The pinned renderer replaces every NUL, then removes exactly one final
	// space only when the resulting display has more than one character.
	args := strings.ReplaceAll(decoded, "\x00", " ")
	if len(args) > 1 && strings.HasSuffix(args, " ") {
		args = args[:len(args)-1]
	}
	return args, vector, warnings
}

// Match Unicode replacement decoding: a valid prefix of an incomplete sequence
// becomes one U+FFFD; invalid leading/continuation bytes remain separate errors.
func replaceInvalidUTF8(raw []byte) (string, bool) {
	var out strings.Builder
	valid := true
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		if r == utf8.RuneError && size == 1 {
			valid = false
			want := 1
			switch b := raw[0]; {
			case b >= 0xc2 && b <= 0xdf:
				want = 2
			case b >= 0xe0 && b <= 0xef:
				want = 3
			case b >= 0xf0 && b <= 0xf4:
				want = 4
			}
			for size < want && size < len(raw) {
				b := raw[size]
				if b < 0x80 || b > 0xbf || size == 1 && (raw[0] == 0xe0 && b < 0xa0 || raw[0] == 0xed && b >= 0xa0 || raw[0] == 0xf0 && b < 0x90 || raw[0] == 0xf4 && b >= 0x90) {
					break
				}
				size++
			}
		}
		out.WriteRune(r)
		raw = raw[size:]
	}
	return out.String(), valid
}
