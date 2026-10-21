package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

var ftraceFlagNames = []string{"ENABLED", "DYNAMIC", "SAVE_REGS", "SAVE_REGS_IF_SUPPORTED", "RECURSION", "STUB", "INITIALIZED", "DELETED", "ADDING", "REMOVING", "MODIFYING", "ALLOC_TRAMP", "IPMODIFY", "PID", "RCU", "TRACE_ARRAY", "PERMANENT", "DIRECT", "SUBOP"}

func ftraceFlags(flags uint64) string {
	var names []string
	for i, name := range ftraceFlagNames {
		if flags&(1<<i) != 0 {
			names = append(names, "FTRACE_OPS_FL_"+name)
		}
	}
	return strings.Join(names, ",")
}
func linuxFtracePlugins() []builtin {
	columns := []evidence.Column{}
	for _, n := range []string{"ftrace_ops address", "Callback address", "Module address", "Hook address", "Entry"} {
		columns = append(columns, evidence.Column{Name: n, Kind: "address"})
	}
	for _, n := range []string{"Callback", "Hooked symbols", "Module", "Flags"} {
		columns = append(columns, evidence.Column{Name: n, Kind: "string"})
	}
	columns = append(columns, evidence.Column{Name: "RawFlags", Kind: "uint64"}, evidence.Column{Name: "Matches", Kind: "structure"})
	columns = append(columns, linuxModxviewPlugins()[0].spec.Columns...)
	return []builtin{{plugin.Spec{Name: "linux.check_ftrace", Upstream: "linux.tracing.ftrace.CheckFtrace", Platform: "linux", NeedsKernel: true, Description: "Inspect ftrace callbacks and first-bucket filters with module attribution and raw evidence", Parameters: []plugin.Parameter{{Name: "show-ftrace-flags", Kind: "bool", Default: "false", Description: "Show named ftrace_ops flags"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Source and per-list traversal bound, 1..1000000"}, {Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Maximum module allocation span, 1..8589934592"}, {Name: "max-entries", Kind: "uint", Default: "1000000", Description: "Global ftrace filter entry bound, 1..1000000"}, {Name: "max-bytes", Kind: "uint", Default: "536870912", Description: "Cumulative actual acquisition bound, 1..1073741824"}}, Columns: columns}, linuxFtrace}}
}

type ftraceReadBudget struct {
	memory.MemoryLayer
	remaining func() uint64
}

func (l *ftraceReadBudget) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if uint64(len(p)) > l.remaining() {
		return 0, fmt.Errorf("ftrace acquisition byte budget exhausted")
	}
	return l.MemoryLayer.ReadAt(ctx, p, at)
}

func linuxFtrace(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("ftrace requires kernel memory and symbols")
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	show, err := strconv.ParseBool(p["show-ftrace-flags"])
	if err != nil {
		return err
	}
	maxNodes, _, err := limits(p)
	if err != nil {
		return err
	}
	bound := func(name string, max uint64) (uint64, error) {
		n, err := strconv.ParseUint(p[name], 0, 64)
		if err != nil || n == 0 || n > max {
			return 0, fmt.Errorf("%s must be 1..%d", name, max)
		}
		return n, nil
	}
	maxEntries, err := bound("max-entries", 1000000)
	if err != nil {
		return err
	}
	maxBytes, err := bound("max-bytes", 1<<30)
	if err != nil {
		return err
	}
	root, err := e.Symbol("ftrace_ops_list")
	if err != nil {
		return fmt.Errorf("unsupported ftrace: %w", err)
	}
	rootSymbol, err := e.Symbols.Lookup("ftrace_ops_list")
	if err != nil {
		return err
	}
	if rootSymbol.Type == nil || rootSymbol.Type.Kind != "pointer" {
		return fmt.Errorf("ftrace_ops_list must declare a pointer type")
	}
	end, err := e.Symbol("ftrace_list_end")
	if err != nil {
		return err
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
	var reads, acquired uint64
	trace := &linuxIDRLayer{MemoryLayer: &ftraceReadBudget{MemoryLayer: e.Kernel, remaining: func() uint64 { return maxBytes - acquired }}}
	trace.observe = func(at uint64, raw []byte, want int, cause error) error {
		reads++
		acquired += uint64(len(raw))
		r := linuxModuleRow(e, at, "ftrace_read", "")
		fields := map[string]evidence.Value{"Address": evidence.Address(at), "Raw": evidence.Bytes(append([]byte(nil), raw...)), "RequestedBytes": evidence.Number(uint64(want)), "CapturedBytes": evidence.Number(uint64(len(raw))), "ReadComplete": evidence.Bool(cause == nil)}
		if cause != nil {
			fields["Error"] = evidence.Missing("read_failed", cause)
			r.Cells["Error"] = fields["Error"]
		}
		r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
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
	// Preserve every exact alias for hook symbols; callback lookup uses the
	// existing pinned first-alias policy and selected matching module owner.
	aliases := map[uint64][]string{}
	for _, name := range e.Symbols.Names() {
		if err := ctx.Err(); err != nil {
			return err
		}
		address, err := e.Symbol(name)
		if err != nil {
			return err
		}
		aliases[address&mask] = append(aliases[address&mask], name)
	}
	for at := range aliases {
		sort.Strings(aliases[at])
		for i, name := range aliases[at] {
			parts := strings.Split(name, "!")
			aliases[at][i] = parts[len(parts)-1]
		}
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
	// Dereference pointer fields explicitly; Reader.Field only walks embedded types.
	member := func(at uint64, typ, path, want string) (uint64, error) {
		f, err := e.Objects.Field(typ, path)
		if err != nil {
			return 0, err
		}
		address, err := memory.Add(at, f.Offset)
		if err != nil {
			return 0, err
		}
		if f.Type.Kind == "struct" && f.Type.Name == want {
			return address, nil
		}
		if f.Type.Kind != "pointer" || f.Type.Subtype == nil || f.Type.Subtype.Kind != "struct" || f.Type.Subtype.Name != want {
			return 0, fmt.Errorf("unsupported %s.%s %s layout", typ, path, want)
		}
		return e.Objects.Uint(ctx, at, typ, path)
	}
	probe := func(at uint64, typ string) error {
		t, err := e.Symbols.Type(typ)
		if err != nil {
			return err
		}
		if t.Size == 0 || t.Size > 1<<20 {
			return fmt.Errorf("invalid %s extent", typ)
		}
		_, err = memory.Read(ctx, trace, at, int(t.Size))
		return err
	}
	current, err := e.Objects.Scalar(ctx, root, *rootSymbol.Type)
	if err != nil {
		return err
	}
	var ops, entries, selected uint64
	seenOps := map[uint64]bool{}
	for current != end {
		if err := ctx.Err(); err != nil {
			return err
		}
		if outputErr != nil {
			return outputErr
		}
		if current == 0 {
			s.failures.add(fmt.Errorf("ftrace list terminated at null instead of sentinel"))
			break
		}
		if seenOps[current] || ops >= uint64(maxNodes) {
			s.failures.add(fmt.Errorf("ftrace ops cycle or traversal bound at %#x", current))
			break
		}
		seenOps[current] = true
		ops++
		row := linuxModuleRow(e, current, "ftrace_ops", "")
		row.Cells["ftrace_ops address"] = evidence.Address(current)
		fields := map[string]evidence.Value{}
		row.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
		n := s.reader(fields)
		before := s.failures.count
		parse := func() error {
			if err := probe(current, "ftrace_ops"); err != nil {
				return err
			}
			callback, err := pointer(current, "ftrace_ops", "func")
			if err != nil {
				return err
			}
			row.Cells["Callback address"] = evidence.Address(callback)
			flags, err := e.Objects.Uint(ctx, current, "ftrace_ops", "flags")
			if err != nil {
				return err
			}
			row.Cells["RawFlags"] = evidence.Number(flags)
			if show {
				row.Cells["Flags"] = evidence.Text(ftraceFlags(flags))
			}
			match, symbol, matches, cause := linuxModuleLookup(n, modules, kernelIndex, callback)
			s.failures.add(cause)
			for _, key := range []string{"Callback", "Module", "Module address"} {
				row.Cells[key] = evidence.Missing("not_available", nil)
			}
			if match != nil {
				row.Cells["Module"] = evidence.Text(match.name)
				row.Cells["Module address"] = evidence.Address(match.base)
				if symbol != "" {
					row.Cells["Callback"] = evidence.Text(symbol)
				}
			}
			ranges := []map[string]evidence.Value{}
			for _, m := range matches {
				ranges = append(ranges, map[string]evidence.Value{"Module": evidence.Text(m.name), "Offset": evidence.Address(m.offset), "Base": evidence.Address(m.base), "Size": evidence.Number(m.size), "Source": evidence.Text(m.source)})
			}
			row.Cells["Matches"] = evidence.Value{Kind: "structure", Data: map[string]any{"ranges": ranges, "overlap": len(matches) > 1}}
			hashBase, hashType := current, "ftrace_ops"
			if _, err := e.Objects.Field("ftrace_ops", "func_hash"); err == nil {
				hashBase, err = member(current, "ftrace_ops", "func_hash", "ftrace_ops_hash")
				if err != nil {
					return err
				}
				hashType = "ftrace_ops_hash"
			} else if !errors.Is(err, object.ErrFieldAbsent) {
				return err
			}
			hash, err := member(hashBase, hashType, "filter_hash", "ftrace_hash")
			if err != nil {
				return err
			}
			buckets, err := member(hash, "ftrace_hash", "buckets", "hlist_head")
			if err != nil {
				return err
			}
			node, err := pointer(buckets, "hlist_head", "first")
			if err != nil {
				return err
			}
			seen := map[uint64]bool{}
			for node != 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
				if outputErr != nil {
					return outputErr
				}
				if seen[node] || len(seen) >= maxNodes || entries >= maxEntries {
					return fmt.Errorf("ftrace filter cycle or traversal bound at %#x", node)
				}
				seen[node] = true
				entries++
				if err := probe(node, "hlist_node"); err != nil {
					return err
				}
				// Pinned cast uses the hlist node coordinate directly as ftrace_func_entry.
				ip, err := e.Objects.Uint(ctx, node, "ftrace_func_entry", "ip")
				if err != nil {
					return err
				}
				hook := row
				hook.Cells = map[string]evidence.Value{}
				for k, v := range row.Cells {
					hook.Cells[k] = v
				}
				hook.Cells["RecordType"] = evidence.Text("ftrace_hook")
				hook.Cells["Entry"] = evidence.Address(node)
				hook.Cells["Hook address"] = evidence.Address(ip)
				hook.Cells["Hooked symbols"] = evidence.Missing("not_available", nil)
				if names := aliases[ip&mask]; len(names) > 0 {
					hook.Cells["Hooked symbols"] = evidence.Text(strings.Join(names, ","))
					fields[fmt.Sprintf("hook_symbols@%x", node)] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Address": evidence.Address(ip), "SymbolDigest": evidence.Text(e.Symbols.Digest())}}
				}
				if s.failures.count > before {
					hook.Cells["Error"] = evidence.Missing("callback_resolution_incomplete", cause)
				}
				snapshot := map[string]evidence.Value{}
				for k, v := range fields {
					snapshot[k] = v
				}
				hook.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: snapshot}
				if err := send(hook); err != nil {
					return err
				}
				selected++
				node, err = pointer(node, "hlist_node", "next")
				if err != nil {
					return err
				}
			}
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
		row.Cells["Status"] = evidence.Text("first_bucket_inspected")
		if s.failures.count > before {
			row.Cells["Error"] = evidence.Missing("ftrace_ops_incomplete", cause)
			row.Cells["Status"] = evidence.Text("incomplete")
		}
		if err := send(row); err != nil {
			return err
		}
		next, err := pointer(current, "ftrace_ops", "next")
		if err != nil {
			s.failures.add(err)
			break
		}
		current = next
	}
	summary := linuxModuleRow(e, root, "ftrace_summary", "")
	summary.Cells["Coverage"] = poolCoverage(map[string]string{"ops": formatCount(ops), "entries": formatCount(entries), "selected": formatCount(selected), "reads": formatCount(reads), "acquired_bytes": formatCount(acquired), "module_ranges": strconv.Itoa(len(modules)), "read_layout_errors": strconv.Itoa(s.failures.count), "scope": "first hash bucket only, pinned selection; callback ownership is not a maliciousness verdict"})
	failure := s.failures.err("Linux ftrace inspection")
	if failure != nil {
		summary.Cells["Error"] = evidence.Missing("ftrace_inspection_incomplete", failure)
	}
	if err := send(summary); err != nil {
		return err
	}
	return failure
}
