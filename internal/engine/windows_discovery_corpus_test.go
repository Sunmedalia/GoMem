package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

type hiddenKDBG struct {
	memory.MemoryLayer
	address uint64
}

func (l hiddenKDBG) ReadAt(ctx context.Context, p []byte, address uint64) (int, error) {
	n, err := l.MemoryLayer.ReadAt(ctx, p, address)
	for i := 0; i < n; i++ {
		if a := address + uint64(i); a >= l.address && a < l.address+4 {
			p[i] = 0
		}
	}
	return n, err
}

// The optional public corpus is kept outside git. Hide only the KDBG tag in a
// read-layer wrapper to exercise the real module-list fallback without changing
// or making another multi-gigabyte copy of the acquired image.
func TestOfficialWindowsDiscoveryFallback(t *testing.T) {
	dir := os.Getenv("GOMEM_CORPUS_DIR")
	if dir == "" {
		t.Skip("set GOMEM_CORPUS_DIR for public-image fault injection; not full acceptance")
	}
	e, err := Open(context.Background(), Config{Image: filepath.Join(dir, "win-10_19041-2025_03.dmp"), Symbols: filepath.Join(dir, "symbols_win-10_19041-2025_03.zip#167FE94B5641C005AC3036212A01F8DC-1.json"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.WindowsDiscoveryError != nil || e.WindowsDiscovery == nil {
		t.Fatal(e.WindowsDiscoveryError)
	}
	h := *e.CrashHeader
	e.Env.Kernel = hiddenKDBG{MemoryLayer: e.Env.Kernel, address: h.DebuggerData + 16}
	e.Config.KernelBase, e.Env.KernelBase = 0, 0
	e.WindowsDiscovery = nil
	if err = e.discoverWindows(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if e.WindowsDiscovery == nil || e.WindowsDiscovery.Method != "crash-header-module-list-pe" || e.Config.KernelBase != 0xfffff8043601f000 {
		t.Fatal(e.WindowsDiscovery)
	}
	for _, kind := range []struct {
		name  string
		count int64
	}{{"windows.pslist", 120}, {"windows.modules", 176}} {
		result, err := e.Run(context.Background(), kind.name, nil, RunOptions{})
		if err != nil || result.Task.Rows != kind.count {
			t.Fatal(kind.name, result, err)
		}
	}
	t.Log(fmt.Sprintf("fallback root=%s base=%#x module=%s field=%s", e.Config.DTB, e.Config.KernelBase, e.WindowsDiscovery.ModuleEntry, e.WindowsDiscovery.BaseField))
}
