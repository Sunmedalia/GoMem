package engine_test

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type dwarfProbe struct{}

func (dwarfProbe) Spec() plugin.Spec {
	return plugin.Spec{Name: "native.dwarf.probe", Platform: "linux", NeedsKernel: true}
}
func (dwarfProbe) Run(ctx context.Context, e plugin.Environment, _ map[string]string, emit plugin.Emit) error {
	address, err := e.Symbol("init_task")
	if err != nil {
		return err
	}
	pid, err := e.Objects.Int(ctx, address, "task_struct", "pid")
	if err != nil {
		return err
	}
	if pid != -123 {
		return os.ErrInvalid
	}
	return emit(evidence.Row{Cells: map[string]evidence.Value{"Name": evidence.Text("DWARF native object")}})
}
func TestNativeDWARFEngineAndISFUseIdenticalCache(t *testing.T) {
	ctx := context.Background()
	debugPath := "../../pkg/symbols/testdata/dwarf-x86_64-v4.elf"
	f, err := elf.Open(debugPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	image := make([]byte, 2<<20)
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Type != elf.SHT_PROGBITS {
			continue
		}
		if s.Addr+s.Size > uint64(len(image)) {
			t.Fatal("unexpected corpus address")
		}
		b, err := s.Data()
		if err != nil {
			t.Fatal(err)
		}
		copy(image[s.Addr:], b)
	}
	binary.LittleEndian.PutUint64(image[0x1000:], 0x2003)
	binary.LittleEndian.PutUint64(image[0x2000:], 0x3003)
	binary.LittleEndian.PutUint64(image[0x3000:], 0x83)
	dir := t.TempDir()
	path := filepath.Join(dir, "native.raw")
	if err = os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := engine.Config{Image: path, Symbols: debugPath, DTB: "0x1000", Arch: "x64", CaseDir: filepath.Join(dir, "case")}
	e, err := engine.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.Registry.Register(dwarfProbe{})
	first, err := e.Run(ctx, "native.dwarf.probe", nil, engine.RunOptions{})
	if err != nil {
		e.Close()
		t.Fatal(err)
	}
	native := e.Env.Symbols.(*symbols.ISF)
	data, err := native.Encode()
	if err != nil {
		e.Close()
		t.Fatal(err)
	}
	e.Close()
	converted := filepath.Join(dir, "native.json")
	if err = os.WriteFile(converted, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Symbols = converted
	e, err = engine.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Registry.Register(dwarfProbe{})
	second, err := e.Run(ctx, "native.dwarf.probe", nil, engine.RunOptions{})
	if err != nil || !second.Reused || second.Task.ID != first.Task.ID {
		t.Fatal("native and converted ISF differ", second, err)
	}
}
