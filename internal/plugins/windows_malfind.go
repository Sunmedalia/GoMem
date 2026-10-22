package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/pe"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsMalfindPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.malfind", Upstream: "windows.malware.malfind.Malfind", Platform: "windows", NeedsKernel: true,
		Description: "Inspect executable VAD injection candidates using protection, dirty-page and nonzero-page evidence",
		Parameters: []plugin.Parameter{
			{Name: "pid", Kind: "string", Description: "Optional comma-separated active process PID filter"},
			{Name: "dump", Kind: "bool", Default: "false", Description: "Extract selected VADs into the case with missing-page logs"},
			{Name: "maxsize", Kind: "uint", Default: "1073741824", Description: "Maximum extraction bytes per VAD; zero disables this limit"},
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process/per-VAD traversal bound, 1..1000000"},
			{Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Task VAD bound, 1..1000000"},
			{Name: "max-pages", Kind: "uint", Default: "16777216", Description: "Task dirty and nonzero page probes, 1..1073741824"},
			{Name: "max-read-bytes", Kind: "uint", Default: "536870912", Description: "Task captured metadata, page-table, data and extraction bytes, 1..4294967296"},
		}, Columns: []evidence.Column{
			{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Start", Kind: "address"}, {Name: "End", Kind: "address"}, {Name: "Tag", Kind: "string"}, {Name: "Protection", Kind: "string"}, {Name: "CommitCharge", Kind: "uint64"}, {Name: "PrivateMemory", Kind: "uint64"}, {Name: "FileOutput", Kind: "artifact"}, {Name: "Notes", Kind: "string"}, {Name: "Hexdump", Kind: "bytes"}, {Name: "Disasm", Kind: "string"},
			{Name: "Disassembly", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "VADOffset", Kind: "address"}, {Name: "DirtyPage", Kind: "address"}, {Name: "DirtyLeaf", Kind: "structure"}, {Name: "NonzeroPage", Kind: "address"}, {Name: "Offset", Kind: "address"}, {Name: "Requested", Kind: "uint64"}, {Name: "Captured", Kind: "uint64"}, {Name: "Raw", Kind: "bytes"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"}, {Name: "Resolution", Kind: "structure"},
		}}, windowsMalfind}}
}

type windowsMalfindRead struct {
	memory.MemoryLayer
	a     *windowsSymbolAnalysis
	scope string
}

func (l windowsMalfindRead) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	if l.a.stop != nil {
		return 0, l.a.stop
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(p)) > l.a.maxBytes-l.a.coverage.Bytes {
		l.a.stop = fmt.Errorf("Windows malfind byte limit exhausted")
		return 0, l.a.stop
	}
	n, err := (windowsSymbolLayer{MemoryLayer: l.MemoryLayer, analysis: l.a}).ReadAt(ctx, p, at)
	if cause := l.a.capture(l.Name(), l.scope, pe.ExportRead{Address: at, Requested: len(p), Raw: append([]byte(nil), p[:n]...), Err: err}); cause != nil {
		return n, cause
	}
	return n, err
}

// Artifact extraction treats genuine missing pages as explicit gaps. An output
// or byte-budget stop must instead cancel its loop immediately.
type windowsMalfindDump struct {
	windowsMalfindRead
	cancel context.CancelFunc
}

func (l windowsMalfindDump) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	n, err := l.windowsMalfindRead.ReadAt(ctx, p, at)
	if l.a.stop != nil {
		l.cancel()
	}
	return n, err
}

func windowsMalfind(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) (err error) {
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	budget := map[string]uint64{}
	for key, limit := range map[string]uint64{"max-regions": 1000000, "max-pages": 1 << 30, "max-read-bytes": 1 << 32} {
		n, cause := strconv.ParseUint(p[key], 0, 64)
		if cause != nil || n == 0 || n > limit {
			return fmt.Errorf("%s must be 1..%d", key, limit)
		}
		budget[key] = n
	}
	dump, maxsize, err := extractionOptions(p)
	if err != nil {
		return err
	}
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil || e.Physical == nil {
		return fmt.Errorf("windows.malfind requires kernel memory, physical memory and symbols")
	}
	if e.Architecture != "x64" && e.Architecture != "x86" && e.Architecture != "pae" {
		return fmt.Errorf("windows.malfind requires Intel translation")
	}
	a := &windowsSymbolAnalysis{ctx: ctx, env: e, out: out, maxNodes: max, maxBytes: budget["max-read-bytes"]}
	a.env.Kernel = windowsMalfindRead{e.Kernel, a, "metadata"}
	a.env.Objects = &object.Reader{Layer: a.env.Kernel, Symbols: e.Symbols}
	protect := vadProtectionCache{env: a.env}
	var processes, regions, pages, dirtyProbes, emptyProbes, findings, missingPages uint64
	defer func() {
		err = errors.Join(err, errors.Join(a.failures...))
		if a.stop != nil || ctx.Err() != nil {
			err = errors.Join(err, a.stop, ctx.Err())
			return
		}
		a.coverage.Complete = err == nil
		err = errors.Join(err, a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("summary"), "Coverage": {Kind: "structure", Data: map[string]any{"acquisition": a.coverage, "processes": processes, "regions": regions, "pages": pages, "dirty_probes": dirtyProbes, "empty_probes": emptyProbes, "findings": findings, "missing_pages": missingPages}}}}))
	}()
	probe := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if a.stop != nil {
			return a.stop
		}
		if pages >= budget["max-pages"] {
			return fmt.Errorf("max-pages exhausted")
		}
		pages++
		return nil
	}
	return visitWindowsProcesses(ctx, a.env, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		processes++
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, identityTime(created))
		baseCells := func(kind string, region windowsVADPath) map[string]evidence.Value {
			return map[string]evidence.Value{"RecordType": evidence.Text(kind), "PID": evidence.Number(pid), "Process": evidence.Text(name), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity), "VADOffset": evidence.Address(region.address), "Start": evidence.Address(region.start), "End": evidence.Address(region.end), "Tag": evidence.Text(region.tag)}
		}
		diagnostic := func(region windowsVADPath, reason string, cause error) error {
			a.failure(cause)
			cells := baseCells("diagnostic", region)
			cells["Error"] = evidence.Missing(reason, cause)
			return a.emit(evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", region.address)}})
		}
		space, cause := processMemory(ctx, a.env, process, 0, identity)
		if cause != nil {
			return diagnostic(windowsVADPath{}, "process_space_unavailable", cause)
		}
		_, ok := space.(*memory.Virtual)
		if !ok {
			return fmt.Errorf("native process translator unavailable")
		}
		// A separate translator captures the actual physical page-table acquisitions
		// made for dirty probes; cache hits do not invent additional source reads.
		dirtyEnv := a.env
		dirtyEnv.Physical = windowsMalfindRead{e.Physical, a, "page_table"}
		dirtySpace, cause := processMemory(ctx, dirtyEnv, process, 0, identity)
		if cause != nil {
			return diagnostic(windowsVADPath{}, "dirty_translator_unavailable", cause)
		}
		dirtyVirtual := dirtySpace.(*memory.Virtual)
		if regions >= budget["max-regions"] {
			return fmt.Errorf("max-regions exhausted")
		}
		vads, cause := windowsVADRegions(ctx, a.env, process, int(min(uint64(max), budget["max-regions"]-regions)), false)
		if cause != nil {
			return diagnostic(windowsVADPath{}, "vad_index_incomplete", cause)
		}
		regions += uint64(len(vads))
		mode := e.Architecture
		if e.Architecture == "x64" {
			for _, path := range []string{"Wow64Process", "WoW64Process"} {
				if _, cause := a.env.Objects.Field("_EPROCESS", path); cause == nil {
					value, cause := a.env.Objects.Uint(ctx, process, "_EPROCESS", path)
					if cause != nil {
						return diagnostic(windowsVADPath{}, "wow64_state_unreadable", cause)
					}
					if value != 0 {
						mode = "x86"
					}
					break
				} else if !errors.Is(cause, object.ErrFieldAbsent) {
					return cause
				}
			}
		}
		for _, region := range vads {
			if cause := ctx.Err(); cause != nil {
				return cause
			}
			if a.stop != nil {
				return a.stop
			}
			protection, cause := protect.read(ctx, region)
			if cause != nil {
				if cause = diagnostic(region, "protection_unreadable", cause); cause != nil {
					return cause
				}
				continue
			}
			writeExec := strings.Contains(protection, "EXECUTE") && strings.Contains(protection, "WRITE")
			dirty := evidence.Missing("not_required", nil)
			leaf := evidence.Missing("not_required", nil)
			if !writeExec {
				if !strings.Contains(protection, "EXECUTE") {
					continue
				}
				for at := region.start; at < region.end; {
					if cause := probe(); cause != nil {
						return cause
					}
					dirtyProbes++
					tr, cause := dirtyVirtual.Translator.Translate(ctx, at)
					if cause != nil {
						missingPages++
						if cause = diagnostic(region, "dirty_page_unavailable", fmt.Errorf("page %#x: %w", at, cause)); cause != nil {
							return cause
						}
						break
					}
					if !tr.DirtyKnown {
						if cause = diagnostic(region, "dirty_state_unavailable", fmt.Errorf("hardware dirty state unavailable at %#x", at)); cause != nil {
							return cause
						}
						break
					}
					if tr.Dirty {
						dirty = evidence.Address(at)
						leaf = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Virtual": evidence.Address(at), "PhysicalEntry": evidence.Address(tr.EntryAddress), "Entry": evidence.Address(tr.Entry), "EntryWidth": evidence.Number(uint64(tr.EntryWidth)), "PageSize": evidence.Number(tr.PageSize), "Dirty": evidence.Bool(tr.Dirty)}}
						break
					}
					if region.end-at <= 4096 {
						break
					}
					at += 4096
				}
				if dirty.Kind == "missing" {
					continue
				}
			}
			typ := "_MMVAD"
			if region.tag == "VadS" || region.tag == "VadF" {
				typ = "_MMVAD_SHORT"
			}
			field := func(paths []string) (uint64, error) {
				path, _, cause := windowsVADField(a.env, typ, paths)
				if cause != nil {
					return 0, cause
				}
				return a.env.Objects.Uint(ctx, region.address, typ, path)
			}
			private, cause := field([]string{"u1.VadFlags1.PrivateMemory", "u.VadFlags.PrivateMemory", "Core.u1.VadFlags1.PrivateMemory", "Core.u.VadFlags.PrivateMemory"})
			if cause != nil {
				if cause = diagnostic(region, "private_memory_unreadable", cause); cause != nil {
					return cause
				}
				continue
			}
			if !(private == 1 && region.tag == "VadS" || private == 0 && protection != "PAGE_EXECUTE_WRITECOPY") {
				continue
			}
			nonzero := evidence.Missing("no_readable_nonzero_page", nil)
			layer := windowsMalfindRead{space, a, "nonzero_page"}
			for at := region.start; ; {
				if cause := probe(); cause != nil {
					return cause
				}
				emptyProbes++
				raw := make([]byte, 4096)
				n, readErr := layer.ReadAt(ctx, raw, at)
				if a.stop != nil || ctx.Err() != nil {
					return errors.Join(a.stop, ctx.Err())
				}
				if readErr != nil || n != 4096 {
					missingPages++
				} else if !bytes.Equal(raw, make([]byte, 4096)) {
					nonzero = evidence.Address(at)
					break
				}
				if region.end-at < 4096 {
					break
				}
				at += 4096
			}
			if nonzero.Kind == "missing" {
				continue
			}
			commit, cause := field([]string{"CommitCharge", "u1.VadFlags1.CommitCharge", "u.VadFlags.CommitCharge", "Core.CommitCharge", "Core.u1.VadFlags1.CommitCharge"})
			if cause != nil {
				if cause = diagnostic(region, "commit_charge_unreadable", cause); cause != nil {
					return cause
				}
				continue
			}
			raw := make([]byte, 64)
			n, readErr := (windowsMalfindRead{space, a, "hexdump"}).ReadAt(ctx, raw, region.start)
			if a.stop != nil || ctx.Err() != nil {
				return errors.Join(a.stop, ctx.Err())
			}
			cells := baseCells("finding", region)
			cells["Protection"] = evidence.Text(protection)
			cells["CommitCharge"] = evidence.Number(commit)
			cells["PrivateMemory"] = evidence.Number(private)
			cells["DirtyPage"] = dirty
			cells["DirtyLeaf"] = leaf
			cells["NonzeroPage"] = nonzero
			cells["Notes"] = evidence.Missing("not_applicable", nil)
			if readErr == nil && n == 64 {
				cells["Hexdump"] = evidence.Bytes(raw)
				cells["Disasm"], cells["Disassembly"] = linuxMalfindDisassembly(raw, region.start, mode)
				notes := map[string]string{"MZ": "MZ header", "\x55\x8b": "PE header", "\x55\x48": "Function prologue", "\x55\x89": "Function prologue"}
				if note, ok := notes[string(raw[:2])]; ok {
					cells["Notes"] = evidence.Text(note)
				}
			} else {
				cells["Hexdump"] = evidence.Missing("first_bytes_unavailable", readErr)
				cells["Disasm"] = evidence.Missing("first_bytes_unavailable", readErr)
				cells["Disassembly"] = evidence.Missing("first_bytes_unavailable", readErr)
				cells["Notes"] = evidence.Missing("first_bytes_unavailable", readErr)
			}
			cells["FileOutput"] = evidence.Missing("not_requested", nil)
			if dump {
				size := region.end - region.start + 1
				if maxsize != 0 && size > maxsize {
					cells["FileOutput"] = evidence.Missing("maxsize_exceeded", nil)
				} else {
					dumpCtx, cancelDump := context.WithCancel(ctx)
					output, cause := extractRegion(dumpCtx, e, windowsMalfindDump{windowsMalfindRead{space, a, "dump"}, cancelDump}, fmt.Sprintf("pid.%d.vad.%#x-%#x.dmp", pid, region.start, region.end), region.start, size)
					cancelDump()
					cells["FileOutput"] = output
					if cause != nil {
						a.failure(cause)
					}
				}
			}
			if a.stop != nil || ctx.Err() != nil {
				return errors.Join(a.stop, ctx.Err())
			}
			if cause := a.emit(evidence.Row{Cells: cells, Provenance: evidence.Provenance{Layer: space.Name(), Offset: fmt.Sprintf("0x%x", region.start)}}); cause != nil {
				return cause
			}
			findings++
		}
		return nil
	})
}
