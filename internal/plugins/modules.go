package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func modulePlugins() []builtin {
	var out []builtin
	for _, os := range []string{"windows", "linux"} {
		name, up := os+".modules", os+".modules.Modules"
		fn := windowsModules
		if os == "linux" {
			name, up = "linux.lsmod", "linux.lsmod.Lsmod"
			fn = linuxModules
		}
		out = append(out, builtin{plugin.Spec{Name: name, Upstream: up, Platform: os, NeedsKernel: true, Description: "Enumerate loaded kernel modules from the kernel list", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "65536", Description: "Traversal safety limit"}}, Columns: []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "Name", Kind: "string"}, {Name: "Base", Kind: "address"}, {Name: "Size", Kind: "uint64"}}}, fn})
	}
	return out
}
func linuxModules(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	head, err := e.Symbol("modules")
	if err != nil {
		return err
	}
	f, err := e.Objects.Field("module", "list")
	if err != nil {
		return err
	}
	return e.Objects.WalkList(ctx, head, f.Offset, max, func(a uint64) error {
		name, err := e.Objects.String(ctx, a, "module", "name", 256)
		if err != nil {
			return err
		}
		baseField, sizeField := "core_layout.base", "core_layout.size"
		if _, err := e.Objects.Field("module", "core_layout"); err != nil {
			baseField, sizeField = "module_core", "core_size"
		}
		return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Name": evidence.Text(name), "Base": optionalUint(ctx, e, a, "module", baseField, true), "Size": optionalUint(ctx, e, a, "module", sizeField, false)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", a)}})
	})
}
func unicodeString(ctx context.Context, e plugin.Environment, a uint64, t, field string) (string, error) {
	f, err := e.Objects.Field(t, field)
	if err != nil {
		return "", err
	}
	base, err := memory.Add(a, f.Offset)
	if err != nil {
		return "", err
	}
	n, err := e.Objects.Uint(ctx, base, "_UNICODE_STRING", "Length")
	if err != nil {
		return "", err
	}
	if n > 65534 || n%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16 length")
	}
	ptr, err := e.Objects.Uint(ctx, base, "_UNICODE_STRING", "Buffer")
	if err != nil {
		return "", err
	}
	b, err := memory.Read(ctx, e.Kernel, ptr, int(n))
	if err != nil {
		return "", err
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u)), nil
}
func windowsModules(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	head, err := e.Symbol("PsLoadedModuleList")
	if err != nil {
		return err
	}
	typ := "_KLDR_DATA_TABLE_ENTRY"
	f, err := e.Objects.Field(typ, "InLoadOrderLinks")
	if err != nil {
		typ = "_LDR_DATA_TABLE_ENTRY"
		f, err = e.Objects.Field(typ, "InLoadOrderLinks")
	}
	if err != nil {
		return err
	}
	return e.Objects.WalkList(ctx, head, f.Offset, max, func(a uint64) error {
		name, err := unicodeString(ctx, e, a, typ, "BaseDllName")
		if err != nil {
			return err
		}
		return out(evidence.Row{Cells: map[string]evidence.Value{"Offset": evidence.Address(a), "Name": evidence.Text(name), "Base": optionalUint(ctx, e, a, typ, "DllBase", true), "Size": optionalUint(ctx, e, a, typ, "SizeOfImage", false)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", a)}})
	})
}
