package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func vadPlugins() []builtin {
	return []builtin{{plugin.Spec{Name: "windows.vadinfo", Upstream: "windows.vadinfo.VadInfo", Platform: "windows", NeedsKernel: true,
		Description: "Enumerate modern process VAD ranges, native protection values and mapped files",
		Parameters:  []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Optional comma-separated process IDs"}, {Name: "address", Kind: "string", Description: "Optional inclusive process virtual address filter"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Per-process VAD and process traversal limit"}, {Name: "max-regions", Kind: "uint", Default: "1000000", Description: "Total VAD traversal limit"}},
		Columns:     []evidence.Column{{Name: "PID", Kind: "uint64"}, {Name: "Process", Kind: "string"}, {Name: "Offset", Kind: "address"}, {Name: "Start", Kind: "address"}, {Name: "End", Kind: "address"}, {Name: "Tag", Kind: "string"}, {Name: "Protection", Kind: "string"}, {Name: "ProtectionIndex", Kind: "uint64"}, {Name: "ProtectionValue", Kind: "uint64"}, {Name: "CommitCharge", Kind: "uint64"}, {Name: "CommitChargeHigh", Kind: "uint64"}, {Name: "PrivateMemory", Kind: "uint64"}, {Name: "Parent", Kind: "address"}, {Name: "Path", Kind: "string"}, {Name: "ProcessOffset", Kind: "address"}, {Name: "ProcessIdentity", Kind: "string"}}}, windowsVADInfo}}
}

// Try declared alternatives only when a field is absent; a read failure must
// not silently select a different union layout.
func windowsVADUint(ctx context.Context, e plugin.Environment, address uint64, paths ...string) evidence.Value {
	for _, path := range paths {
		if _, err := e.Objects.Field("_MMVAD_SHORT", path); err != nil {
			if errors.Is(err, object.ErrFieldAbsent) {
				continue
			}
			return evidence.Missing("unreadable_or_unavailable", err)
		}
		return optionalUint(ctx, e, address, "_MMVAD_SHORT", path, false)
	}
	return evidence.Missing("unsupported_vad_field", fmt.Errorf("no declared VAD member among %s", strings.Join(paths, ", ")))
}

func windowsProtectionNames(value uint64) (string, error) {
	flags := []struct {
		mask uint64
		name string
	}{{1, "PAGE_NOACCESS"}, {2, "PAGE_READONLY"}, {4, "PAGE_READWRITE"}, {8, "PAGE_WRITECOPY"}, {16, "PAGE_EXECUTE"}, {32, "PAGE_EXECUTE_READ"}, {64, "PAGE_EXECUTE_READWRITE"}, {128, "PAGE_EXECUTE_WRITECOPY"}, {256, "PAGE_GUARD"}, {512, "PAGE_NOCACHE"}, {1024, "PAGE_WRITECOMBINE"}, {0x40000000, "PAGE_TARGETS_INVALID"}}
	var names []string
	var known uint64
	for _, flag := range flags {
		known |= flag.mask
		if value&flag.mask != 0 {
			names = append(names, flag.name)
		}
	}
	if value & ^known != 0 {
		return "", fmt.Errorf("unknown protection bits %#x", value & ^known)
	}
	return strings.Join(names, "|"), nil
}

func windowsVADInfo(ctx context.Context, e plugin.Environment, parameters map[string]string, emit plugin.Emit) error {
	max, pids, err := limits(parameters)
	if err != nil {
		return err
	}
	limit, err := strconv.ParseUint(parameters["max-regions"], 0, 32)
	if err != nil || limit == 0 || limit > 1000000 {
		return fmt.Errorf("max-regions must be 1..1000000")
	}
	var address uint64
	filter := parameters["address"] != ""
	if filter {
		address, err = strconv.ParseUint(parameters["address"], 0, 64)
		if err != nil {
			return fmt.Errorf("address: %w", err)
		}
	}
	var protect []byte
	var protectErr error
	loaded := false
	var count uint64
	return visitWindowsProcesses(ctx, e, max, pids, func(process, pid uint64, name string, created evidence.Value) error {
		// Bound work even for address-filtered queries, counting visited regions.
		regions, err := windowsVADPaths(ctx, e, process, int(min(uint64(max), limit-count)))
		if err != nil {
			return fmt.Errorf("process %#x PID %d VAD index: %w", process, pid, err)
		}
		count += uint64(len(regions))
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(e.ImageHash, e.Kernel.Name(), process, pid, stamp)
		for _, region := range regions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if filter && (address < region.start || address > region.end) {
				continue
			}
			if !loaded {
				loaded = true
				base, err := e.Symbol("MmProtectToValue")
				protectErr = err
				if err == nil {
					protect, protectErr = memory.Read(ctx, e.Kernel, base, 32*4)
				}
			}
			index := windowsVADUint(ctx, e, region.address, "u.VadFlags.Protection")
			protection, value := index, index
			if index.Kind != "missing" {
				n, err := index.Uint()
				if err == nil && n >= 32 {
					err = fmt.Errorf("VAD protection index %d exceeds native 32-entry table", n)
				}
				if err == nil {
					err = protectErr
				}
				if err != nil {
					protection, value = evidence.Missing("unreadable_or_unavailable", err), evidence.Missing("unreadable_or_unavailable", err)
				} else {
					numeric := uint64(binary.LittleEndian.Uint32(protect[n*4:]))
					value = evidence.Number(numeric)
					names, err := windowsProtectionNames(numeric)
					if err != nil {
						protection = evidence.Missing("unknown_protection", err)
					} else {
						protection = evidence.Text(names)
					}
				}
			}
			row := evidence.Row{Cells: map[string]evidence.Value{"PID": evidence.Number(pid), "Process": evidence.Text(name), "Offset": evidence.Address(region.address), "Start": evidence.Address(region.start), "End": evidence.Address(region.end), "Tag": evidence.Text(region.tag), "Protection": protection, "ProtectionIndex": index, "ProtectionValue": value, "CommitCharge": windowsVADUint(ctx, e, region.address, "CommitCharge", "u1.VadFlags1.CommitCharge", "u.VadFlags.CommitCharge"), "CommitChargeHigh": windowsVADUint(ctx, e, region.address, "CommitChargeHigh"), "PrivateMemory": windowsVADUint(ctx, e, region.address, "u1.VadFlags1.PrivateMemory", "u.VadFlags.PrivateMemory"), "Parent": evidence.Address(region.parent), "Path": region.file, "ProcessOffset": evidence.Address(process), "ProcessIdentity": evidence.Text(identity)}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", region.address)}}
			if err := emit(row); err != nil {
				return err
			}
		}
		return nil
	})
}
