package plugins

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/pesymbols"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/winnet"
)

func windowsNetStatPlugins() []builtin {
	spec := windowsNetScanPlugins()[0].spec
	spec.Name, spec.Upstream = "windows.netstat", "windows.netstat.NetStat"
	spec.Description = "Walk TCP/IP partition and port-pool indexes with matching driver PDB and original-source evidence"
	spec.ExternalSymbols = true
	spec.Parameters = append(append([]plugin.Parameter(nil), spec.Parameters...), plugin.Parameter{Name: "max-nodes", Kind: "uint", Default: "1000000", Description: "All partition, hash, bitmap and port-chain steps, 1..16777216"})
	for _, name := range []string{"IndexRoute", "TCPIPSymbolSHA256", "TCPIPSourceSHA256"} {
		spec.Columns = append(spec.Columns, evidence.Column{Name: name, Kind: "string"})
	}
	spec.Columns = append(spec.Columns, evidence.Column{Name: "TCPIPBase", Kind: "address"}, evidence.Column{Name: "IndexPort", Kind: "uint64"})
	return []builtin{{spec, windowsNetStat}}
}

func networkTCPIPModule(ctx context.Context, e plugin.Environment) (pesymbols.Module, error) {
	head, err := e.Symbol("PsLoadedModuleList")
	if err != nil {
		return pesymbols.Module{}, err
	}
	typ := "_KLDR_DATA_TABLE_ENTRY"
	link, err := e.Objects.Field(typ, "InLoadOrderLinks")
	if err != nil {
		typ = "_LDR_DATA_TABLE_ENTRY"
		link, err = e.Objects.Field(typ, "InLoadOrderLinks")
	}
	if err != nil {
		return pesymbols.Module{}, err
	}
	var found pesymbols.Module
	err = e.Objects.WalkList(ctx, head, link.Offset, 65536, func(at uint64) error {
		name, err := unicodeString(ctx, e, at, typ, "BaseDllName")
		if err != nil {
			return err
		}
		if name != "tcpip.sys" {
			return nil
		}
		if found.Layer != nil {
			return fmt.Errorf("ambiguous loaded tcpip.sys module")
		}
		base, err := e.Objects.Uint(ctx, at, typ, "DllBase")
		if err != nil {
			return err
		}
		size, err := e.Objects.Uint(ctx, at, typ, "SizeOfImage")
		if err != nil {
			return err
		}
		found = pesymbols.Module{Layer: e.Kernel, Base: base, Size: size, PDBNames: []string{"tcpip.pdb"}}
		return nil
	})
	if err != nil {
		return found, err
	}
	if found.Layer == nil {
		return found, fmt.Errorf("loaded tcpip.sys module is unavailable")
	}
	return found, nil
}

func windowsNetStat(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	a := &poolScannerAnalysis{ctx: ctx, out: out}
	for name, target := range map[string]*uint64{"max-read-bytes": &a.maxBytes, "max-reads": &a.maxReads, "max-rows": &a.maxRows} {
		limit := uint64(1 << 40)
		if name == "max-reads" {
			limit = 1 << 24
		}
		if name == "max-rows" {
			limit = 10000000
		}
		n, err := strconv.ParseUint(p[name], 0, 64)
		if err != nil || n == 0 || n > limit {
			return fmt.Errorf("%s must be 1..%d", name, limit)
		}
		*target = n
	}
	nodes, err := strconv.ParseUint(p["max-nodes"], 0, 64)
	if err != nil || nodes == 0 || nodes > 1<<24 {
		return fmt.Errorf("max-nodes must be 1..16777216")
	}
	corrupt, err := strconv.ParseBool(p["include-corrupt"])
	if err != nil {
		return err
	}
	if e.ModulePDB == nil {
		return fmt.Errorf("NetStat requires matching tcpip.pdb acquisition")
	}
	env, err := poolScannerEnvironment(ctx, e, a)
	if err != nil {
		return err
	}
	if err := networkOwnerSchema(env); err != nil {
		return err
	}
	version, err := networkVersion(ctx, env)
	if err != nil {
		return errors.Join(err, a.stop, a.failures.err("NetStat version reads"))
	}
	selected, err := winnet.Select(version)
	if err != nil {
		return err
	}
	cache := e.SymbolCache
	if cache != "" {
		cache = filepath.Join(cache, "network-symbols")
	}
	catalog, err := winnet.Load(ctx, cache, selected.Name, e.Offline)
	if err != nil {
		return err
	}
	if err := a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("network_symbols"), "NetworkSymbols": evidence.Text(catalog.Name), "NetworkSymbolSHA256": evidence.Text(catalog.SHA256), "Raw": evidence.Bytes(catalog.Data), "Source": evidence.Text(catalog.URL), "Coverage": {Kind: "structure", Data: map[string]any{"version": version, "selection": selected}}}}); err != nil {
		return err
	}
	module, err := networkTCPIPModule(ctx, env)
	if err != nil {
		return errors.Join(err, a.stop, a.failures.err("NetStat module reads"))
	}
	pdb, err := env.ModulePDB(ctx, module)
	if err != nil && pdb.Table == nil {
		return errors.Join(err, a.stop, a.failures.err("NetStat driver reads"))
	}
	if err != nil {
		a.failures.add(err)
		if emitErr := a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("diagnostic"), "Error": evidence.Missing("tcpip_acquisition_partial", err)}}); emitErr != nil {
			return emitErr
		}
	}
	if pdb.Table == nil || pdb.Table.PointerSize() != env.Symbols.PointerSize() {
		return fmt.Errorf("invalid TCP/IP symbol table pointer width")
	}
	if err := a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("tcpip_symbols"), "TCPIPBase": evidence.Address(module.Base), "TCPIPSymbolSHA256": evidence.Text(pdb.Table.Digest()), "TCPIPSourceSHA256": evidence.Text(pdb.SourceSHA256), "Coverage": {Kind: "structure", Data: pdb.Identity}}}); err != nil {
		return err
	}
	index := &winnet.Index{Layout: catalog.Layout, Layer: env.Kernel, Kernel: env.Symbols, TCPIP: pdb.Table, ModuleBase: module.Base, MaxNodes: nodes}
	var candidates, rejected, networks uint64
	err = index.Walk(ctx, func(entry winnet.IndexEntry) error {
		if a.stop != nil {
			return a.stop
		}
		candidates++
		o := winnet.Object{Layout: catalog.Layout, Layer: env.Kernel, Native: env.Kernel, Address: entry.Address, Type: entry.Type}
		validity := "not_checked_include_corrupt"
		if !corrupt {
			valid, err := networkObjectValid(ctx, env, o)
			a.failures.add(err)
			if !valid {
				rejected++
				row := poolScannerRow(env.Kernel.Name(), entry.Address)
				row.Cells["RecordType"], row.Cells["Type"], row.Cells["Validity"], row.Cells["IndexRoute"] = evidence.Text("network_candidate"), evidence.Text(entry.Type), evidence.Text("rejected"), evidence.Text(entry.Route)
				if err != nil {
					row.Cells["Error"] = evidence.Missing("network_validation_failed", err)
				}
				return a.emit(row)
			}
			validity = "valid"
		}
		rows, err := networkRows(ctx, env, o, validity)
		a.failures.add(err)
		for _, row := range rows {
			row.Cells["IndexRoute"], row.Cells["IndexPort"] = evidence.Text(entry.Route), evidence.Number(entry.Port)
			row.Cells["TCPIPBase"], row.Cells["TCPIPSymbolSHA256"], row.Cells["TCPIPSourceSHA256"] = evidence.Address(module.Base), evidence.Text(pdb.Table.Digest()), evidence.Text(pdb.SourceSHA256)
			row.Cells["NetworkSymbols"], row.Cells["NetworkSymbolSHA256"] = evidence.Text(catalog.Name), evidence.Text(catalog.SHA256)
			if err != nil {
				row.Cells["Error"] = evidence.Missing("network_fields_incomplete", err)
			}
			if err := a.emit(row); err != nil {
				return err
			}
			networks++
		}
		return nil
	})
	cause := errors.Join(err, a.stop, a.failures.err("NetStat captured reads"))
	if a.stop != nil || ctx.Err() != nil {
		return errors.Join(cause, ctx.Err())
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("task_summary"), "Coverage": {Kind: "structure", Data: map[string]evidence.Value{"Candidates": evidence.Number(candidates), "Rejected": evidence.Number(rejected), "Networks": evidence.Number(networks), "Reads": evidence.Number(a.reads), "RequestedBytes": evidence.Number(a.requested), "EvidenceRows": evidence.Number(a.rows), "ReadFailures": evidence.Number(uint64(a.failures.count)), "Completed": evidence.Bool(cause == nil)}}}}
	if cause != nil {
		summary.Cells["Error"] = evidence.Missing("network_index_incomplete", cause)
	}
	return errors.Join(cause, a.emit(summary))
}
