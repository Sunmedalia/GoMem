package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func windowsOrphanKernelThreadPlugins() []builtin {
	columns := append([]evidence.Column{}, windowsThrdScanPlugins()[0].spec.Columns...)
	return []builtin{{plugin.Spec{
		Name: "windows.orphan_kernel_threads", Upstream: "windows.orphan_kernel_threads.Threads", Platform: "windows", NeedsKernel: true,
		Description: "List kernel threads whose start address is outside every loaded module",
		Parameters: []plugin.Parameter{
			{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "VAD node limit for one owning process"},
		},
		Columns: columns,
	}, windowsOrphanKernelThreads}}
}

type orphanStats struct {
	examined, ownerUnreadable, notKernel, exited, userStart, inModule, orphans, gatherSkipped uint64
}

func (s orphanStats) fill(extra map[string]string) {
	extra["examined"] = formatCount(s.examined)
	extra["owner_unreadable"] = formatCount(s.ownerUnreadable)
	extra["not_kernel"] = formatCount(s.notKernel)
	extra["exited"] = formatCount(s.exited)
	extra["user_start"] = formatCount(s.userStart)
	extra["in_module"] = formatCount(s.inModule)
	extra["orphans"] = formatCount(s.orphans)
	extra["gather_skipped"] = formatCount(s.gatherSkipped)
}

func windowsOrphanKernelThreads(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if p == nil {
		p = map[string]string{}
	}
	if p["max-nodes"] == "" {
		p["max-nodes"] = "131072"
	}
	maxNodes, err := strconv.ParseUint(p["max-nodes"], 0, 32)
	if err != nil || maxNodes == 0 || maxNodes > 1000000 {
		return fmt.Errorf("max-nodes must be 1..1000000")
	}
	if err = requireThreadFields(e); err != nil {
		return err
	}
	for _, check := range []struct{ typ, field string }{
		{"_ETHREAD", "ExitTime.QuadPart"},
		{"_ETHREAD", "Tcb.State"},
		{"_EPROCESS", "UniqueProcessId"},
		{"_EPROCESS", "InheritedFromUniqueProcessId"},
	} {
		if _, err = e.Objects.Field(check.typ, check.field); err != nil {
			return fmt.Errorf("%s.%s: %w", check.typ, check.field, err)
		}
	}
	pointer := e.Symbols.PointerSize()
	if pointer != 4 && pointer != 8 {
		return fmt.Errorf("windows.orphan_kernel_threads needs a 4- or 8-byte pointer")
	}
	kernelStart, err := kernelSpaceStart(ctx, e)
	if err != nil {
		return err
	}
	kernelStart = maskKernelStart(kernelStart, pointer)
	modules, err := windowsKernelModules(ctx, e)
	if err != nil {
		return err
	}
	for i := range modules {
		modules[i].base = canonicalPointer(modules[i].base, pointer)
	}
	constraints, err := builtinPoolConstraints("Thr\xe5", "Thre")
	if err != nil {
		return err
	}
	owners := map[uint64]*threadOwner{}
	extra := map[string]string{}
	stats := orphanStats{}
	stats.fill(extra)
	return scanPoolObjectsExtra(ctx, e, constraints, "orphans", thrdScanRow, out, func(ctx context.Context, found poolHit) (evidence.Row, bool, error) {
		stats.examined++
		defer func() { stats.fill(extra) }()
		keep, err := orphanKernelCandidate(ctx, found, kernelStart, pointer, modules, &stats)
		if err != nil || !keep {
			return evidence.Row{}, false, err
		}
		row, ok, err := thrdScanHit(ctx, e, found, int(maxNodes), owners)
		if err != nil || !ok {
			stats.gatherSkipped++
			return row, false, err
		}
		stats.orphans++
		return row, true, nil
	}, extra)
}

func orphanKernelCandidate(ctx context.Context, found poolHit, kernelStart uint64, pointer int, modules []kernelModule, stats *orphanStats) (bool, error) {
	owner, err := threadOwnerAddress(ctx, found.scan, found.object)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		stats.ownerUnreadable++
		return false, nil
	}
	pid, err := found.scan.Uint(ctx, owner, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		stats.ownerUnreadable++
		return false, nil
	}
	ppid, err := found.scan.Uint(ctx, owner, "_EPROCESS", "InheritedFromUniqueProcessId")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		stats.ownerUnreadable++
		return false, nil
	}
	start, err := found.scan.Uint(ctx, found.object, "_ETHREAD", "StartAddress")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		stats.ownerUnreadable++
		return false, nil
	}
	pid = pointerIdentity(pid, pointer)
	ppid = pointerIdentity(ppid, pointer)
	if pid != 4 && ppid != 4 {
		stats.notKernel++
		return false, nil
	}
	exit, err := found.scan.Int(ctx, found.object, "_ETHREAD", "ExitTime.QuadPart")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, poolFatalError{fmt.Errorf("thread exit time at %#x: %w", found.object, err)}
	}
	state, err := found.scan.Uint(ctx, found.object, "_ETHREAD", "Tcb.State")
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, poolFatalError{fmt.Errorf("thread state at %#x: %w", found.object, err)}
	}
	if exit > 0 || state == 4 {
		stats.exited++
		return false, nil
	}
	if pointerIdentity(start, pointer) < kernelStart {
		stats.userStart++
		return false, nil
	}
	canon := canonicalPointer(start, pointer)
	for _, module := range modules {
		if addressInModule(module.base, module.size, canon) {
			stats.inModule++
			return false, nil
		}
	}
	return true, nil
}
