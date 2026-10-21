package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxTracepointsPlugins() []builtin {
	columns := []evidence.Column{}
	for _, n := range []string{"tracepoint", "Probe", "Module", "ArrayLayout"} {
		columns = append(columns, evidence.Column{Name: n, Kind: "string"})
	}
	for _, n := range []string{"tracepoint address", "Probe address", "Module address", "Entry", "Slot", "Data", "TracepointObject"} {
		columns = append(columns, evidence.Column{Name: n, Kind: "address"})
	}
	columns = append(columns, evidence.Column{Name: "Probe priority", Kind: "int64"}, evidence.Column{Name: "RawPriority", Kind: "int64"}, evidence.Column{Name: "NameReadComplete", Kind: "bool"}, evidence.Column{Name: "Matches", Kind: "structure"})
	columns = append(columns, linuxModxviewPlugins()[0].spec.Columns...)
	return []builtin{{plugin.Spec{Name: "linux.check_tracepoints", Upstream: "linux.tracing.tracepoints.CheckTracepoints", Platform: "linux", NeedsKernel: true, Description: "Inspect tracepoint probes from absolute or PREL32 arrays with native attribution and acquisition evidence", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Module-source traversal bound, 1..1000000"}, {Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Maximum module allocation span, 1..8589934592"}, {Name: "max-tracepoints", Kind: "uint", Default: "1000000", Description: "Tracepoint array entry bound, 1..1000000"}, {Name: "max-probes", Kind: "uint", Default: "1000000", Description: "Global non-null probe bound, 1..1000000"}, {Name: "max-bytes", Kind: "uint", Default: "536870912", Description: "Cumulative actual acquisition bound, 1..1073741824"}}, Columns: columns}, linuxTracepoints}}
}

type tracepointReadBudget struct {
	memory.MemoryLayer
	remaining func() uint64
}

func (l *tracepointReadBudget) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if uint64(len(p)) > l.remaining() {
		return 0, fmt.Errorf("tracepoint acquisition byte budget exhausted")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}
func tracepointRelative32(slot, encoded uint64) (uint64, error) {
	delta := int64(int32(uint32(encoded)))
	if delta >= 0 {
		return memory.Add(slot, uint64(delta))
	}
	n := uint64(-delta)
	if n > slot {
		return 0, fmt.Errorf("PREL32 address underflow")
	}
	return slot - n, nil
}

func linuxTracepoints(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("tracepoints require kernel memory and symbols")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	if _, _, err := limits(p); err != nil {
		return err
	}
	bound := func(name string, max uint64) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 64)
		if err != nil || n == 0 || n > max {
			return 0, fmt.Errorf("%s must be 1..%d", name, max)
		}
		return n, nil
	}
	maxPoints, err := bound("max-tracepoints", 1000000)
	if err != nil {
		return err
	}
	maxProbes, err := bound("max-probes", 1000000)
	if err != nil {
		return err
	}
	maxBytes, err := bound("max-bytes", 1<<30)
	if err != nil {
		return err
	}
	start, err := e.Symbol("__start___tracepoints_ptrs")
	if err != nil {
		return fmt.Errorf("unsupported tracepoints: %w", err)
	}
	end, err := e.Symbol("__stop___tracepoints_ptrs")
	if err != nil {
		return err
	}
	if end < start {
		return fmt.Errorf("inverted tracepoint array bounds")
	}
	root, err := e.Symbols.Lookup("__start___tracepoints_ptrs")
	if err != nil {
		return err
	}
	if root.Type == nil || root.Type.Subtype == nil || (root.Type.Kind != "array" && root.Type.Kind != "pointer") {
		return fmt.Errorf("tracepoint array symbol lacks array/pointer subtype metadata")
	}
	relative := root.Type.Subtype.Kind == "base" && root.Type.Subtype.Name == "int"
	stride := uint64(e.Symbols.PointerSize())
	layout := "absolute"
	slotType := symbols.TypeRef{Kind: "pointer"}
	if relative {
		typ, err := e.Symbols.Type("int")
		if err != nil {
			return err
		}
		if typ.Size != 4 || !typ.Signed {
			return fmt.Errorf("PREL32 requires a signed four-byte int type")
		}
		stride = 4
		layout = "prel32"
		slotType = symbols.TypeRef{Kind: "base", Name: "int"}
	}
	if stride != 4 && stride != 8 {
		return fmt.Errorf("unsupported tracepoint pointer width")
	}
	count := (end - start) / stride
	trailing := (end - start) % stride
	if count > maxPoints {
		return fmt.Errorf("tracepoint array count %d exceeds max-tracepoints %d", count, maxPoints)
	}
	var outputErr error
	send := func(r evidence.Row) error {
		if outputErr != nil {
			return outputErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		outputErr = out(r)
		if outputErr == nil {
			outputErr = ctx.Err()
		}
		return outputErr
	}
	var reads, acquired, probes, selected, points uint64
	trace := &linuxIDRLayer{MemoryLayer: &tracepointReadBudget{MemoryLayer: e.Kernel, remaining: func() uint64 { return maxBytes - acquired }}}
	trace.observe = func(at uint64, raw []byte, want int, cause error) error {
		reads++
		acquired += uint64(len(raw))
		r := linuxModuleRow(e, at, "tracepoint_read", "")
		proof := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(cause == nil)}
		if cause != nil {
			proof["Error"] = evidence.Missing("read_failed", cause)
			r.Cells["Error"] = proof["Error"]
		}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: proof}
		return send(r)
	}
	e.Kernel = trace
	e.Objects = &object.Reader{Layer: trace, Symbols: e.Symbols}
	s, err := linuxGatherModuleSources(ctx, e, p, send)
	if err != nil {
		return err
	}
	if err = s.kernel(); err != nil {
		if err = s.issue(0, "kernel", "kernel_bounds_unavailable", err); err != nil {
			return err
		}
	}
	modules := linuxFlattenModuleSources(s.results, mask)
	kernelIndex, err := linuxKernelSymbolIndex(ctx, e, mask)
	if err != nil {
		return err
	}
	pointer := func(at uint64, typ, path string) (uint64, error) {
		f, err := e.Objects.Field(typ, path)
		if err != nil {
			return 0, err
		}
		if f.Type.Kind != "pointer" {
			return 0, fmt.Errorf("%s.%s is not a pointer", typ, path)
		}
		return e.Objects.Uint(ctx, at, typ, path)
	}
	for i := uint64(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if outputErr != nil {
			return outputErr
		}
		slot, err := memory.Add(start, i*stride)
		if err != nil {
			return err
		}
		encoded, err := e.Objects.Scalar(ctx, slot, slotType)
		if err != nil {
			return err
		}
		at := encoded
		if relative {
			at, err = tracepointRelative32(slot, encoded)
			if err != nil {
				return err
			}
		}
		if e.Symbols.PointerSize() == 4 && at > 0xffffffff {
			return fmt.Errorf("tracepoint address exceeds 32-bit address space")
		}
		points++
		row := linuxModuleRow(e, at, "tracepoint_observation", "")
		// Absolute-array iteration yields Pointer objects whose vol.offset is the slot;
		// PREL32 iteration constructs tracepoint objects at the decoded target.
		display := slot
		if relative {
			display = at
		}
		row.Cells["tracepoint address"] = evidence.Address(display)
		row.Cells["TracepointObject"] = evidence.Address(at)
		row.Cells["Slot"] = evidence.Address(slot)
		row.Cells["ArrayLayout"] = evidence.Text(layout)
		before := s.failures.count
		inspect := func() error {
			if at == 0 {
				return fmt.Errorf("null tracepoint array entry")
			}
			if _, err := memory.Read(ctx, trace, at, 1); err != nil {
				return err
			}
			funcs, err := pointer(at, "tracepoint", "funcs")
			if err != nil {
				return err
			}
			row.Cells["Entry"] = evidence.Address(funcs)
			if funcs == 0 {
				row.Cells["Status"] = evidence.Text("no_probes")
				return nil
			}
			typ, err := e.Symbols.Type("tracepoint_func")
			if err != nil {
				return err
			}
			if typ.Size == 0 || typ.Size > 1<<20 {
				return fmt.Errorf("invalid tracepoint_func extent")
			}
			// The first funcs pointer is checked against the declared complete subtype.
			if _, err := memory.Read(ctx, trace, funcs, int(typ.Size)); err != nil {
				return err
			}
			funcField, err := e.Objects.Field("tracepoint_func", "func")
			if err != nil {
				return err
			}
			if funcField.Type.Kind != "pointer" || funcField.Type.Subtype == nil {
				return fmt.Errorf("tracepoint_func.func must declare a pointer target")
			}
			targetSize := uint64(1)
			if funcField.Type.Subtype.Kind != "function" {
				targetSize, err = e.Objects.Size(*funcField.Type.Subtype)
				if err != nil {
					return err
				}
				if targetSize == 0 {
					targetSize = 1
				}
				if targetSize > 1<<20 {
					return fmt.Errorf("probe target extent exceeds bound")
				}
			}
			current := funcs
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				if outputErr != nil {
					return outputErr
				}
				if _, err := memory.Read(ctx, trace, current, 1); err != nil {
					return err
				}
				fn, err := pointer(current, "tracepoint_func", "func")
				if err != nil {
					return err
				}
				if fn == 0 {
					row.Cells["Status"] = evidence.Text("null_probe_terminator")
					break
				}
				if probes >= maxProbes {
					return fmt.Errorf("tracepoint probes exceed max-probes %d", maxProbes)
				}
				probes++
				probe := row
				probe.Cells = map[string]evidence.Value{}
				for k, v := range row.Cells {
					probe.Cells[k] = v
				}
				probe.Cells["Entry"] = evidence.Address(current)
				probe.Cells["Probe address"] = evidence.Address(fn)
				probe.Cells["RecordType"] = evidence.Text("probe_observation")
				fields := map[string]evidence.Value{}
				probe.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
				n := s.reader(fields)
				probeBefore := s.failures.count
				parse := func() error {
					if _, err := memory.Read(ctx, trace, fn, int(targetSize)); err != nil {
						return err
					}
					namePtr, err := pointer(at, "tracepoint", "name")
					if err != nil {
						return err
					}
					raw := make([]byte, 512)
					got, cause := trace.ReadAt(ctx, raw, namePtr)
					if got < 0 || got > len(raw) {
						return fmt.Errorf("invalid tracepoint name read count")
					}
					if cause == nil && got != len(raw) {
						cause = io.ErrUnexpectedEOF
					}
					probe.Cells["NameReadComplete"] = evidence.Bool(cause == nil)
					if cause != nil {
						s.failures.add(cause)
						probe.Cells["NameError"] = evidence.Missing("name_prefix_only", cause)
					}
					if got == 0 {
						return fmt.Errorf("tracepoint name unavailable: %w", cause)
					}
					probe.Cells["tracepoint"] = evidence.Text(spoofDecoded(raw[:got]))
					probe.Cells["Probe priority"] = evidence.Missing("not_available", nil)
					probe.Cells["RawPriority"] = evidence.Missing("not_available", nil)
					if _, err := e.Objects.Field("tracepoint_func", "prio"); err == nil {
						prio, err := e.Objects.Int(ctx, current, "tracepoint_func", "prio")
						if err != nil {
							return err
						}
						probe.Cells["RawPriority"] = evidence.Integer(prio)
						if prio != 0 {
							probe.Cells["Probe priority"] = evidence.Integer(prio)
						}
					} else if !errors.Is(err, object.ErrFieldAbsent) {
						return err
					}
					probe.Cells["Data"] = evidence.Missing("not_available", nil)
					if _, err := e.Objects.Field("tracepoint_func", "data"); err == nil {
						data, err := pointer(current, "tracepoint_func", "data")
						if err != nil {
							return err
						}
						probe.Cells["Data"] = evidence.Address(data)
					} else if !errors.Is(err, object.ErrFieldAbsent) {
						return err
					}
					match, symbol, matches, cause := linuxModuleLookup(n, modules, kernelIndex, fn)
					s.failures.add(cause)
					for _, key := range []string{"Probe", "Module", "Module address"} {
						probe.Cells[key] = evidence.Missing("not_available", nil)
					}
					if match != nil {
						probe.Cells["Module"] = evidence.Text(match.name)
						probe.Cells["Module address"] = evidence.Address(match.offset)
						if symbol != "" {
							probe.Cells["Probe"] = evidence.Text(symbol)
						}
					}
					ranges := []map[string]evidence.Value{}
					for _, m := range matches {
						ranges = append(ranges, map[string]evidence.Value{"Module": evidence.Text(m.name), "Offset": evidence.Address(m.offset), "Base": evidence.Address(m.base), "Size": evidence.Number(m.size), "Source": evidence.Text(m.source)})
					}
					probe.Cells["Matches"] = evidence.Value{Kind: "structure", Data: map[string]any{"ranges": ranges, "overlap": len(matches) > 1}}
					probe.Cells["RecordType"] = evidence.Text("tracepoint_probe")
					return nil
				}
				cause := parse()
				if outputErr != nil {
					return outputErr
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				s.failures.add(cause)
				probe.Cells["Status"] = evidence.Text("selected")
				if cause != nil {
					probe.Cells["Status"] = evidence.Text("unavailable")
				}
				if s.failures.count > probeBefore {
					probe.Cells["Error"] = evidence.Missing("probe_inspection_incomplete", cause)
				}
				if err := send(probe); err != nil {
					return err
				}
				if probe.Cells["RecordType"].String() == "tracepoint_probe" {
					selected++
				}
				// An unreadable non-null handler ends this array as in the fixed parser,
				// while name failures continue to the next independently bounded entry.
				if cause != nil && probe.Cells["NameReadComplete"].Kind == "" {
					return cause
				}
				current, err = memory.Add(current, typ.Size)
				if err != nil {
					return err
				}
			}
			return nil
		}
		cause := inspect()
		if outputErr != nil {
			return outputErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.failures.add(cause)
		if s.failures.count > before {
			row.Cells["Error"] = evidence.Missing("tracepoint_inspection_incomplete", cause)
			row.Cells["Status"] = evidence.Text("incomplete")
		}
		if err := send(row); err != nil {
			return err
		}
	}
	summary := linuxModuleRow(e, start, "tracepoints_summary", "")
	summary.Cells["ArrayLayout"] = evidence.Text(layout)
	summary.Cells["Coverage"] = poolCoverage(map[string]string{"array_entries": formatCount(count), "tracepoints": formatCount(points), "probes": formatCount(probes), "selected": formatCount(selected), "trailing_array_bytes": formatCount(trailing), "reads": formatCount(reads), "acquired_bytes": formatCount(acquired), "module_ranges": strconv.Itoa(len(modules)), "read_layout_errors": strconv.Itoa(s.failures.count), "scope": "typed Intel tracepoints; callback ownership is not a maliciousness verdict"})
	failure := s.failures.err("Linux tracepoint inspection")
	if failure != nil {
		summary.Cells["Error"] = evidence.Missing("tracepoints_inspection_incomplete", failure)
	}
	if err := send(summary); err != nil {
		return err
	}
	return failure
}
