package plugins

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/byteregex"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/memoryscan"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsVADRegexPlugins() []builtin {
	spec := regexPlugins()[0].spec
	spec.Name = "windows.vadregexscan"
	spec.Upstream = "windows.vadregexscan.VadRegExScan"
	spec.Platform = "windows"
	spec.NeedsKernel = true
	spec.Description = "Scan Windows process VADs with native byte regex and explicit original-source coverage"
	spec.Parameters = append(append([]plugin.Parameter{}, spec.Parameters...),
		plugin.Parameter{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"},
		plugin.Parameter{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process and per-process VAD traversal bound, 1..1000000"},
		plugin.Parameter{Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Task total VAD traversal bound, 1..1000000"})
	spec.Columns = append([]evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "Created", Kind: "string"}}, spec.Columns...)
	return []builtin{{spec, windowsVADRegex}}
}

func windowsVADRegex(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	o, err := parseRegexOptions(p)
	if err != nil {
		return err
	}
	// The pinned Windows generator also ignores its advertised maxsize.
	o.context = 128
	max, pids, err := limits(p)
	if err != nil {
		return err
	}
	maxRegions, err := strconv.ParseUint(p["max-regions"], 0, 32)
	if err != nil || maxRegions == 0 || maxRegions > 1000000 {
		return fmt.Errorf("max-regions must be 1..1000000")
	}
	if e.Physical == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("windows.vadregexscan requires physical memory and Windows symbols")
	}
	kernel, ok := e.Kernel.(*memory.Virtual)
	if !ok {
		return fmt.Errorf("windows.vadregexscan requires native Intel kernel translation")
	}
	original, ok := kernel.Translator.(*memory.Intel)
	if !ok {
		return fmt.Errorf("windows.vadregexscan supports x86, PAE and x64 Intel translation")
	}
	a := &regexAnalysis{ctx: ctx, env: e, o: o, out: out, layer: e.Kernel.Name()}
	traced, err := a.intel(original.Root(), "metadata_page_table")
	if err != nil {
		return err
	}
	native := &memory.Virtual{Physical: a.physical(), Translator: traced, ID: e.Kernel.Name()}
	env := e
	// VAD tags use direct kernel reads, so trace the layer as well as objects.
	env.Kernel = regexRead{MemoryLayer: native, a: a, scope: "metadata", raw: true}
	env.Objects = &object.Reader{Layer: env.Kernel, Symbols: e.Symbols}
	var scan, extract *byteregex.Regexp
	var regions uint64
	err = visitWindowsProcesses(ctx, env, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, identityTime(created))
		a.owner = map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(memoryscan.DisplayUTF8([]byte(name))), "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity), "Created": created}
		defer func() { a.owner = nil; a.layer = e.Kernel.Name() }()
		space, err := processMemory(ctx, env, process, 0, identity)
		if err != nil {
			return a.diagnostic("process_unavailable", process, err)
		}
		root, ok := space.(*memory.Virtual).Translator.(*memory.Intel)
		if !ok {
			return fmt.Errorf("process translator is not Intel")
		}
		if regions >= maxRegions {
			return a.diagnostic("vma_unavailable", process, fmt.Errorf("max-regions exhausted"))
		}
		vads, err := windowsVADRegions(ctx, env, process, int(min(uint64(max), maxRegions-regions)), false)
		if err != nil {
			return a.diagnostic("vma_unavailable", process, err)
		}
		regions += uint64(len(vads))
		sort.Slice(vads, func(i, j int) bool { return vads[i].start < vads[j].start })
		sections := []memory.Range{}
		for i, vad := range vads {
			if i > 0 && vad.start <= vads[i-1].end {
				return a.diagnostic("vma_unavailable", vad.address, fmt.Errorf("overlapping VAD ranges"))
			}
			length := vad.end - vad.start + 1
			if length == 0 {
				return a.diagnostic("vma_unavailable", vad.address, fmt.Errorf("VAD size overflow"))
			}
			if err := a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("vma_section"), "Offset": evidence.Address(vad.address), "Mapping": {Kind: "structure", Data: map[string]evidence.Value{"Start": evidence.Address(vad.start), "Length": evidence.Number(length)}}}}); err != nil {
				return err
			}
			if len(sections) > 0 && sections[len(sections)-1].Start+sections[len(sections)-1].Length == vad.start {
				sections[len(sections)-1].Length += length
			} else {
				sections = append(sections, memory.Range{Start: vad.start, Length: length})
			}
		}
		// Windows compiles even with an empty VAD selection, but only after
		// reaching a process layer. PID filters can therefore avoid compilation.
		if scan == nil {
			scan, err = byteregex.Compile(p["pattern"], true)
			if err != nil {
				return err
			}
			extract, err = byteregex.Compile(p["pattern"], false)
			if err != nil {
				return err
			}
		}
		a.layer = space.Name()
		return a.scan(root.Root(), sections, scan, extract, true)
	})
	return a.finish(err)
}
