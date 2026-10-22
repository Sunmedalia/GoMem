package plugins

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/byteregex"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/memoryscan"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxVMARegexPlugins() []builtin {
	spec := regexPlugins()[0].spec
	spec.Name = "linux.vmaregexscan"
	spec.Upstream = "linux.vmaregexscan.VmaRegExScan"
	spec.Platform = "linux"
	spec.NeedsKernel = true
	spec.Description = "Scan Linux process VMAs using native byte regex with explicit coverage and original source evidence"
	spec.Parameters = append(append([]plugin.Parameter{}, spec.Parameters...), plugin.Parameter{Name: "pid", Kind: "string", Description: "Optional comma-separated task PID filter"}, plugin.Parameter{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Process and per-mm VMA traversal bound, 1..1000000"}, plugin.Parameter{Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Task total VMA traversal bound, 1..1000000"})
	spec.Columns = append([]evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "TID", Kind: "uint64"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}, {Name: "Created", Kind: "uint64"}}, spec.Columns...)
	return []builtin{{spec, linuxVMARegex}}
}

func linuxVMARegex(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	o, err := parseRegexOptions(p)
	if err != nil {
		return err
	}
	// The pinned VMA generator advertises maxsize but always reads 128 bytes.
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
		return fmt.Errorf("linux.vmaregexscan requires physical memory and Linux symbols")
	}
	kernel, ok := e.Kernel.(*memory.Virtual)
	if !ok {
		return fmt.Errorf("linux.vmaregexscan requires native Intel kernel translation")
	}
	original, ok := kernel.Translator.(*memory.Intel)
	if !ok {
		return fmt.Errorf("linux.vmaregexscan supports x86, PAE and x64 Intel translation")
	}
	a := &regexAnalysis{ctx: ctx, env: e, o: o, out: out, layer: e.Kernel.Name()}
	traced, err := a.intel(original.Root(), "metadata_page_table")
	if err != nil {
		return err
	}
	nativeKernel := &memory.Virtual{Physical: a.physical(), Translator: traced, ID: e.Kernel.Name()}
	env := e
	env.Kernel = nativeKernel
	env.Objects = &object.Reader{Layer: regexRead{MemoryLayer: nativeKernel, a: a, scope: "metadata", raw: true}, Symbols: e.Symbols}
	var scan, extract *byteregex.Regexp
	var regions uint64
	err = visitLinuxProcesses(ctx, env, max, pids, func(task, tid uint64, name string, created evidence.Value) error {
		name, _, _ = strings.Cut(memoryscan.DisplayUTF8([]byte(name)), "\uFFFD")
		a.owner = map[string]evidence.Value{"TID": evidence.Number(tid), "ProcessOffset": evidence.Address(task), "Process": evidence.Text(name), "Created": created}
		defer func() { a.owner = nil; a.layer = e.Kernel.Name() }()
		tgid, err := env.Objects.Uint(ctx, task, "task_struct", "tgid")
		if err != nil {
			return a.diagnostic("process_unavailable", task, err)
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), task, tgid, identityTime(created))
		a.owner["PID"] = evidence.Number(tgid)
		a.owner["ProcessIdentity"] = evidence.Text(identity)
		mm, err := env.Objects.Uint(ctx, task, "task_struct", "mm")
		if err != nil {
			return a.diagnostic("process_unavailable", task, err)
		}
		if mm == 0 {
			return a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("process_skipped"), "Offset": evidence.Address(task), "Error": evidence.Missing("no_userspace_mm", nil)}})
		}
		space, err := processMemory(ctx, env, task, mm, identity)
		if err != nil {
			return a.diagnostic("process_unavailable", task, err)
		}
		process := space.(*memory.Virtual)
		root, ok := process.Translator.(*memory.Intel)
		if !ok {
			return fmt.Errorf("process translator is not Intel")
		}
		if regions >= maxRegions {
			return a.diagnostic("vma_unavailable", task, fmt.Errorf("max-regions exhausted"))
		}
		vmas, visited, err := linuxELFRegions(ctx, env, mm, int(min(uint64(max), maxRegions-regions)))
		regions += visited
		if err != nil {
			return a.diagnostic("vma_unavailable", task, err)
		}
		sections := []memory.Range{}
		for _, vma := range vmas {
			if err = a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("vma_section"), "Offset": evidence.Address(vma.object), "Mapping": {Kind: "structure", Data: map[string]evidence.Value{"Start": evidence.Address(vma.start), "Length": evidence.Number(vma.end - vma.start)}}}}); err != nil {
				return err
			}
			if len(sections) > 0 && sections[len(sections)-1].Start+sections[len(sections)-1].Length == vma.start {
				sections[len(sections)-1].Length += vma.end - vma.start
			} else {
				sections = append(sections, memory.Range{Start: vma.start, Length: vma.end - vma.start})
			}
		}
		// Compile only after a usable mm/process layer, preserving null-mm behavior.
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
