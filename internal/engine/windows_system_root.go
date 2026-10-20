package engine

import (
	"bytes"
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

// A crash header may hold a captured process CR3 whose kernel mappings are less
// complete than the System process page table. Replace only an automatically
// chosen header root, and only after validating System's identity, PE and list
// anchors under the replacement. Explicit user roots are never replaced.
func (e *Engine) preferWindowsSystemRoot(ctx context.Context) error {
	table, ok := e.Env.Symbols.(*symbols.ISF)
	if !ok {
		return fmt.Errorf("System root requires an ISF-compatible table")
	}
	head, err := e.Env.Symbol("PsActiveProcessHead")
	if err != nil {
		return err
	}
	link, err := e.Env.Objects.Field("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return err
	}
	var system, root uint64
	err = e.Env.Objects.WalkList(ctx, head, link.Offset, 131072, func(address uint64) error {
		pid, err := e.Env.Objects.Uint(ctx, address, "_EPROCESS", "UniqueProcessId")
		if err != nil {
			return err
		}
		if pid != 4 {
			return nil
		}
		if system != 0 {
			return fmt.Errorf("multiple System PID objects prevent unambiguous root selection")
		}
		field, err := e.Env.Objects.Field("_EPROCESS", "Pcb.DirectoryTableBase")
		if err != nil {
			return err
		}
		location, err := memory.Add(address, field.Offset)
		if err != nil {
			return err
		}
		ref := field.Type
		if ref.Kind == "array" {
			if ref.Subtype == nil || ref.Count == 0 {
				return fmt.Errorf("empty process page-table-root array")
			}
			ref = *ref.Subtype
		}
		root, err = e.Env.Objects.Scalar(ctx, location, ref)
		if err != nil {
			return err
		}
		system = address
		return nil
	})
	if err != nil {
		return err
	}
	if system == 0 || root == 0 {
		return fmt.Errorf("no usable System process page-table root")
	}
	tr, err := memory.NewIntelForOS(e.Env.Physical, root, e.Config.Arch, "windows", 1024)
	if err != nil {
		return err
	}
	root = tr.Root()
	current, err := strconv.ParseUint(e.Config.DTB, 0, 64)
	if err != nil {
		return err
	}
	if root == current {
		return nil
	}
	layer := &memory.Virtual{Physical: e.Env.Physical, Translator: tr, ID: fmt.Sprintf("kernel:%s:dtb=%#x", e.Config.Arch, root)}
	if err = verifyPE(ctx, layer, e.Config.KernelBase, table); err != nil {
		return fmt.Errorf("verify System root PE: %w", err)
	}
	r := &object.Reader{Layer: layer, Symbols: table}
	pid, err := r.Uint(ctx, system, "_EPROCESS", "UniqueProcessId")
	if err != nil || pid != 4 {
		return fmt.Errorf("System object is not stable in proposed address space: PID=%d error=%v", pid, err)
	}
	for _, name := range []string{"PsLoadedModuleList", "PsActiveProcessHead"} {
		address, err := e.Env.Symbol(name)
		if err != nil {
			return err
		}
		before, err := memory.Read(ctx, e.Env.Kernel, address, table.PointerSize()*2)
		if err != nil {
			return err
		}
		after, err := memory.Read(ctx, layer, address, table.PointerSize()*2)
		if err != nil {
			return fmt.Errorf("verify System root %s: %w", name, err)
		}
		if !bytes.Equal(before, after) {
			return fmt.Errorf("System root changes %s list anchors", name)
		}
	}
	proof := e.WindowsDiscovery
	if e.WindowsDiscovery == nil {
		id, err := table.PDBIdentity()
		if err != nil {
			return err
		}
		proof = &WindowsDiscovery{Method: "crash-header-explicit-base", Architecture: e.Config.Arch, KernelBase: fmt.Sprintf("0x%x", e.Config.KernelBase), Identity: id, Verified: true}
	}
	old := e.Config.DTB
	e.Config.DTB = fmt.Sprintf("0x%x", root)
	e.Env.Kernel, e.Env.Objects, e.WindowsDiscovery = layer, r, proof
	e.WindowsDiscovery.Method += "+system-process-root"
	e.WindowsDiscovery.InitialDTB, e.WindowsDiscovery.DTB, e.WindowsDiscovery.SystemProcess = old, e.Config.DTB, fmt.Sprintf("0x%x", system)
	return nil
}
