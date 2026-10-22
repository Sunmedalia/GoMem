package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/Sunmedalia/GoMem/pkg/winconsole"
)

func windowsConsolesPlugins() []builtin {
	s := windowsCmdScanPlugins()[0].spec
	s.Name, s.Upstream, s.Description = "windows.consoles", "windows.consoles.Consoles", "Recover conhost console metadata, attached processes, aliases, active histories and screen buffers"
	s.Parameters = append(append([]plugin.Parameter{}, s.Parameters...),
		plugin.Parameter{Name: "max-buffers", Kind: "string", Default: "4", Description: "Comma-separated console validity buffer bounds in 0..65535"},
		plugin.Parameter{Name: "max-screens", Kind: "uint", Default: "1024", Description: "Per-console screen traversal limit, 1..1000000"},
		plugin.Parameter{Name: "max-screen-rows", Kind: "uint", Default: "32767", Description: "Per-screen row limit, 1..32767"},
		plugin.Parameter{Name: "max-screen-cells", Kind: "uint", Default: "32767", Description: "Per-row cell limit, 1..32767"},
		plugin.Parameter{Name: "max-screen-bytes", Kind: "uint", Default: "16777216", Description: "Per-screen cell-byte limit, 1..16777216"})
	return []builtin{{s, windowsConsoles}}
}

type consoleScanOptions struct {
	buffers    []uint64
	maxScreens uint64
	screen     winconsole.ScreenLimits
}

func windowsConsoles(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	opts := &consoleScanOptions{}
	var err error
	opts.buffers, err = parseCmdHistory(p["max-buffers"])
	if err != nil {
		return fmt.Errorf("max-buffers: %w", err)
	}
	for _, bound := range []struct {
		name  string
		value *uint64
		limit uint64
	}{
		{"max-screens", &opts.maxScreens, 1000000},
		{"max-screen-rows", &opts.screen.MaxRows, 32767},
		{"max-screen-cells", &opts.screen.MaxCells, 32767},
		{"max-screen-bytes", &opts.screen.MaxTextBytes, memory.MaxRead},
	} {
		n, err := strconv.ParseUint(p[bound.name], 0, 64)
		if err != nil || n == 0 || n > bound.limit {
			return fmt.Errorf("%s must be 1..%d", bound.name, bound.limit)
		}
		*bound.value = n
	}
	return windowsConhostRun(ctx, e, p, out, opts)
}

func (s *cmdScan) consoleProcess(ctx context.Context, process uint64, identity string, histories []uint64) error {
	acquired, err := s.acquireConhost(ctx, process, identity, conhostExecutableVAD)
	if err != nil || acquired == nil {
		return err
	}
	layout, err := winconsole.ParseConsoleLayout(s.catalog.Data)
	if err != nil {
		return err
	}
	screen, err := winconsole.ParseScreenLayout(s.catalog.Data)
	if err != nil {
		return err
	}
	kernel, ok := s.env.Symbols.(*symbols.ISF)
	if !ok {
		return fmt.Errorf("console lists require native ISF kernel types")
	}
	reader := winconsole.ConsoleReader{Layer: acquired.Layer, Layout: layout, KernelSymbols: kernel}
	field, err := layout.Field("_CONSOLE_INFORMATION.CommandHistorySize")
	if err != nil || field.Offset < 0 {
		return fmt.Errorf("invalid console signature offset: %v", err)
	}
	found := false
	var last uint64
	if acquired.Scan != nil {
		for _, maximum := range histories {
			err = memory.Scan(ctx, acquired.Scan, []byte{byte(maximum), byte(maximum >> 8)}, func(match uint64) error {
				if s.candidates >= s.maxCandidates {
					return fmt.Errorf("max-candidates exhausted")
				}
				s.candidates++
				if match < uint64(field.Offset) {
					return s.diagnostic("candidate_underflow", match, fmt.Errorf("console signature before structure start"))
				}
				last = match - uint64(field.Offset)
				valid := false
				// The pinned list comprehension evaluates every max-buffer validity test.
				for _, buffers := range s.console.buffers {
					ok, readErr := reader.Valid(ctx, last, buffers)
					if readErr != nil {
						if err := s.diagnostic("candidate_unreadable", last, readErr); err != nil {
							return err
						}
					}
					valid = valid || ok
				}
				if !valid {
					return nil
				}
				found = true
				s.histories++
				tree := &consoleTree{s: s, reader: reader, screen: screen, at: last, root: fmt.Sprintf("consoles:%s:%x:%d", identity, last, maximum)}
				return tree.attempt(ctx, "console_incomplete", last, func() error { return tree.properties(ctx) })
			})
			if err != nil {
				return err
			}
		}
	}
	if found {
		return nil
	}
	at := evidence.Missing("not_applicable", nil)
	if last != 0 {
		at = evidence.Address(last)
	}
	return s.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("console_not_found"), "ConsoleInfo": at, "Property": evidence.Text("_CONSOLE_INFORMATION"), "Address": evidence.Missing("not_applicable", nil), "Data": evidence.Text("Console Information Not Found"), "Depth": evidence.Number(0)}, Provenance: evidence.Provenance{Layer: acquired.Layer.Name()}})
}

// Depth follows the original TreeGrid stream, including same-depth metadata
// siblings. Do not infer different parents from property-name punctuation.
type consoleTree struct {
	s        *cmdScan
	reader   winconsole.ConsoleReader
	screen   *winconsole.ScreenLayout
	at       uint64
	root     string
	parents  [4]string
	sequence uint64
}

func (t *consoleTree) property(name string, depth uint64, address, typed evidence.Value, text string, raw []byte) error {
	if depth >= uint64(len(t.parents)) {
		return fmt.Errorf("invalid console property depth")
	}
	id := fmt.Sprintf("%s:%d", t.root, t.sequence)
	t.sequence++
	parent := ""
	if depth > 0 {
		parent = t.parents[depth-1]
		if parent == "" {
			return fmt.Errorf("console tree missing parent")
		}
	}
	t.parents[depth] = id
	for i := depth + 1; i < uint64(len(t.parents)); i++ {
		t.parents[i] = ""
	}
	data := evidence.Text(text)
	if text == "" {
		data = evidence.Missing("not_available", nil)
	}
	row := evidence.Row{ID: id, ParentID: parent, Cells: map[string]evidence.Value{"RecordType": evidence.Text("console_property"), "ConsoleInfo": evidence.Address(t.at), "Property": evidence.Text("_CONSOLE_INFORMATION" + name), "Address": address, "Data": data, "TypedData": {Kind: "structure", Data: typed}, "Depth": evidence.Number(depth)}, Provenance: evidence.Provenance{Layer: t.reader.Layer.Name(), Offset: fmt.Sprintf("0x%x", t.at)}}
	if raw != nil {
		row.Cells["Raw"] = evidence.Bytes(raw)
	}
	return t.s.emit(row)
}
func (t *consoleTree) attempt(ctx context.Context, kind string, at uint64, call func() error) error {
	err := call()
	if err == nil {
		return nil
	}
	if t.s.a.stop != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	return t.s.diagnostic(kind, at, err)
}
func (t *consoleTree) empty(name string, depth uint64, at uint64) error {
	return t.property(name, depth, evidence.Address(at), evidence.Text(""), "", nil)
}
func (t *consoleTree) scalar(ctx context.Context, owner uint64, field, name string, depth uint64, hex bool) error {
	v, err := t.reader.Scalar(ctx, owner, field)
	if err != nil {
		return err
	}
	typed, text := evidence.Number(v.Value), strconv.FormatUint(v.Value, 10)
	if v.Signed {
		typed, text = evidence.Integer(int64(v.Value)), strconv.FormatInt(int64(v.Value), 10)
	}
	if hex {
		text = fmt.Sprintf("0x%x", v.Value)
	} else if v.Value == 0 {
		text = ""
	}
	return t.property(name, depth, evidence.Address(v.Address), typed, text, v.Raw)
}
func (t *consoleTree) properties(ctx context.Context) error {
	if err := t.empty("", 0, t.at); err != nil {
		return err
	}
	for _, name := range []string{"ScreenX", "ScreenY", "CommandHistorySize", "HistoryBufferCount", "HistoryBufferMax"} {
		if err := t.scalar(ctx, t.at, "_CONSOLE_INFORMATION."+name, "."+name, 1, false); err != nil {
			return err
		}
	}
	for _, original := range []bool{false, true} {
		name := "Title"
		if original {
			name = "OriginalTitle"
		}
		v, err := t.reader.Title(ctx, t.at, original)
		if err != nil {
			return err
		}
		at, err := t.reader.Layout.Address(t.at, "_CONSOLE_INFORMATION."+name)
		if err != nil {
			return err
		}
		if err = t.property("."+name, 1, evidence.Address(at), evidence.Text(v.Text), v.Text, v.Raw); err != nil {
			return err
		}
	}
	if err := t.scalar(ctx, t.at, "_CONSOLE_INFORMATION.ProcessCount", ".ProcessCount", 1, false); err != nil {
		return err
	}
	for _, list := range []struct {
		name, kind string
		read       func(context.Context) error
	}{
		{"ConsoleProcessList", "console_processes_incomplete", t.processes},
		{"ExeAliasList", "console_aliases_incomplete", t.aliases},
		{"HistoryList", "console_histories_incomplete", t.histories},
		{"CurrentScreenBuffer", "console_screens_incomplete", t.screens},
	} {
		at, err := t.reader.Layout.Address(t.at, "_CONSOLE_INFORMATION."+list.name)
		if err != nil {
			return err
		}
		if err = t.empty("."+list.name, 1, at); err != nil {
			return err
		}
		if err = t.attempt(ctx, list.kind, at, func() error { return list.read(ctx) }); err != nil {
			return err
		}
	}
	return nil
}
func (t *consoleTree) processes(ctx context.Context) error {
	index := 0
	return t.reader.WalkList(ctx, t.at, "_CONSOLE_INFORMATION.ConsoleProcessList", "_CONSOLE_PROCESS_LIST", t.s.maxNodes, func(node uint64) error {
		name := fmt.Sprintf(".ConsoleProcessList.ConsoleProcess_%d", index)
		index++
		v, err := t.reader.Scalar(ctx, node, "_CONSOLE_PROCESS_LIST.ConsoleProcess")
		if err != nil {
			return err
		}
		if err = t.empty(name, 2, v.Value); err != nil {
			return err
		}
		if err = t.scalar(ctx, v.Value, "_CONSOLE_PROCESS.ProcessId", name+"_ProcessId", 2, false); err != nil {
			return err
		}
		return t.scalar(ctx, v.Value, "_CONSOLE_PROCESS.ProcessHandle", name+"_ProcessHandle", 2, true)
	})
}
func (t *consoleTree) aliases(ctx context.Context) error {
	index := 0
	return t.reader.WalkList(ctx, t.at, "_CONSOLE_INFORMATION.ExeAliasList", "_EXE_ALIAS_LIST", t.s.maxNodes, func(node uint64) error {
		name := fmt.Sprintf(".ExeAliasList.AliasList_%d", index)
		index++
		return t.attempt(ctx, "console_alias_incomplete", node, func() error {
			if err := t.empty(name, 2, node); err != nil {
				return err
			}
			at, text, raw, err := t.reader.ExeName(ctx, node)
			if err != nil {
				return err
			}
			if err = t.text(name+".ExeName", 2, at, text, raw); err != nil {
				return err
			}
			aliases := 0
			return t.reader.WalkList(ctx, node, "_EXE_ALIAS_LIST.AliasList", "_ALIAS", t.s.maxNodes, func(alias uint64) error {
				prefix := fmt.Sprintf("%s.Alias_%d", name, aliases)
				aliases++
				for _, field := range []string{"Source", "Target"} {
					at, text, raw, err := t.reader.CommandText(ctx, alias, "_ALIAS."+field)
					if err != nil {
						return err
					}
					if err = t.text(prefix+"."+field, 3, at, text, raw); err != nil {
						return err
					}
				}
				return nil
			})
		})
	})
}
func (t *consoleTree) text(name string, depth, at uint64, text *string, raw []byte) error {
	typed, display := evidence.Missing("baseline_none", nil), ""
	if text != nil {
		typed, display = evidence.Text(*text), *text
	}
	return t.property(name, depth, evidence.Address(at), typed, display, raw)
}
func (t *consoleTree) histories(ctx context.Context) error {
	index := 0
	r := winconsole.Reader{Objects: &object.Reader{Layer: t.reader.Layer, Symbols: t.reader.Layout.History}}
	return t.reader.WalkList(ctx, t.at, "_CONSOLE_INFORMATION.HistoryList", "_COMMAND_HISTORY", t.s.maxNodes, func(node uint64) error {
		name := fmt.Sprintf(".HistoryList.CommandHistory_%d", index)
		index++
		return t.attempt(ctx, "console_history_incomplete", node, func() error {
			if err := t.empty(name, 2, node); err != nil {
				return err
			}
			at, err := t.reader.Layout.Address(node, "_COMMAND_HISTORY.Application")
			if err != nil {
				return err
			}
			text, raw, err := r.Application(ctx, node)
			if err != nil {
				return err
			}
			if err = t.text(name+"_Application", 2, at, text, raw); err != nil {
				return err
			}
			ptr, err := r.Objects.Uint(ctx, node, "_COMMAND_HISTORY", "ConsoleProcessHandle")
			if err != nil {
				return err
			}
			f, err := r.Objects.Field("_CONSOLE_PROCESS_HANDLE", "ProcessHandle")
			if err != nil {
				return err
			}
			at, err = memory.Add(ptr, f.Offset)
			if err != nil {
				return err
			}
			handle, err := r.ProcessHandle(ctx, node)
			if err != nil {
				return err
			}
			if err = t.property(name+"_ProcessHandle", 2, evidence.Address(at), evidence.Number(handle), fmt.Sprintf("0x%x", handle), nil); err != nil {
				return err
			}
			count, err := r.CommandCount(ctx, node)
			if err != nil {
				return err
			}
			display := strconv.FormatInt(count, 10)
			if count == 0 {
				display = ""
			}
			if err = t.property(name+"_CommandCount", 2, evidence.Missing("not_applicable", nil), evidence.Integer(count), display, nil); err != nil {
				return err
			}
			if err = t.scalar(ctx, node, "_COMMAND_HISTORY.LastDisplayed", name+"_LastDisplayed", 2, false); err != nil {
				return err
			}
			begin, err := r.Objects.Uint(ctx, node, "_COMMAND_HISTORY", "CommandBucket.Begin")
			if err != nil {
				return err
			}
			end, err := r.Objects.Uint(ctx, node, "_COMMAND_HISTORY", "CommandBucket.End")
			if err != nil {
				return err
			}
			return r.WalkBucket(ctx, winconsole.History{Begin: begin}, &end, t.s.maxSlots, func(index uint64, c winconsole.Command) error {
				return t.attempt(ctx, "console_command_incomplete", c.Address, func() error {
					text, raw, err := r.Text(ctx, c.Address)
					if err != nil {
						return err
					}
					return t.text(fmt.Sprintf("%s_Command_%d", name, index), 3, c.Address, text, raw)
				})
			})
		})
	})
}
func (t *consoleTree) screens(ctx context.Context) error {
	index := 0
	r := winconsole.ScreenReader{Layer: t.reader.Layer, Layout: t.screen}
	return t.reader.WalkScreens(ctx, t.at, t.screen, t.s.console.maxScreens, func(link winconsole.ScreenLink) error {
		name := fmt.Sprintf(".ScreenBuffer_%d", index)
		index++
		return t.attempt(ctx, "console_screen_incomplete", link.Target, func() error {
			if err := t.empty(name, 2, link.Target); err != nil {
				return err
			}
			x, y, err := r.Dimensions(ctx, link.Target)
			if err != nil {
				return err
			}
			for _, dimension := range []struct {
				name string
				n    int64
			}{{"ScreenX", x}, {"ScreenY", y}} {
				display := strconv.FormatInt(dimension.n, 10)
				if dimension.n == 0 {
					display = ""
				}
				if err = t.property(name+"."+dimension.name, 2, evidence.Missing("not_applicable", nil), evidence.Integer(dimension.n), display, nil); err != nil {
					return err
				}
			}
			buffer, readErr := r.Buffer(ctx, link.Target, t.s.console.screen, true, true)
			lines := make([]string, len(buffer.Rows))
			for i, row := range buffer.Rows {
				lines[i] = row.Text
			}
			text := strings.Join(lines, "\n")
			if err = t.property(name+".Dump", 2, evidence.Missing("not_applicable", nil), evidence.Text(text), text, nil); err != nil {
				return err
			}
			return readErr
		})
	})
}
