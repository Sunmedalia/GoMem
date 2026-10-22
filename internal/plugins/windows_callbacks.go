package plugins

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/wincallbacks"
)

func windowsCallbackPlugins() []builtin {
	parameters := append([]plugin.Parameter(nil), windowsPoolScannerPlugins()[0].spec.Parameters...)
	parameters = append(parameters, plugin.Parameter{Name: "max-nodes", Kind: "uint", Default: "1000000", Description: "Callback index steps and pool candidates, each bounded at 1..1000000"})
	columns := append([]evidence.Column(nil), windowsPoolScannerPlugins()[0].spec.Columns...)
	for _, c := range []evidence.Column{{Name: "PoolHeader", Kind: "address"}, {Name: "Callback", Kind: "address"}, {Name: "Module", Kind: "string"}, {Name: "Symbol", Kind: "string"}, {Name: "Detail", Kind: "string"}, {Name: "Route", Kind: "string"}, {Name: "Validity", Kind: "string"}, {Name: "Structure", Kind: "string"}, {Name: "LayoutSHA256", Kind: "string"}, {Name: "Source", Kind: "string"}} {
		columns = append(columns, c)
	}
	return []builtin{{plugin.Spec{Name: "windows.callbacks", Upstream: "windows.callbacks.Callbacks", Platform: "windows", NeedsKernel: true, Description: "Enumerate callback indexes and pool objects with module attribution, fixed layouts and original-source evidence", Parameters: parameters, Columns: columns}, windowsCallbacks}}
}

type callbackAnalysis struct {
	trace           *poolScannerAnalysis
	modules         []kernelModule
	symbols         map[uint64][]string
	layout          string
	callbacks, rows uint64
}

func (a *callbackAnalysis) emit(source uint64, layer, route string, typ evidence.Value, address uint64, detail evidence.Value, extra map[string]evidence.Value) error {
	a.callbacks++
	row := poolScannerRow(layer, source)
	row.Cells["RecordType"], row.Cells["Type"], row.Cells["Callback"], row.Cells["Detail"] = evidence.Text("callback"), typ, evidence.Address(address), detail
	row.Cells["Route"], row.Cells["LayoutSHA256"] = evidence.Text(route), evidence.Text(a.layout)
	for key, value := range extra {
		row.Cells[key] = value
	}
	send := func(module, symbol evidence.Value) error {
		projected := row
		projected.Cells = make(map[string]evidence.Value, len(row.Cells)+2)
		for key, value := range row.Cells {
			projected.Cells[key] = value
		}
		projected.Cells["Module"], projected.Cells["Symbol"] = module, symbol
		a.rows++
		return a.trace.emit(projected)
	}
	matched := false
	for _, module := range a.modules {
		if !addressInModule(module.base, module.size, address) {
			continue
		}
		matched = true
		names := a.symbols[address-module.base]
		if len(names) == 0 {
			if err := send(evidence.Text(module.stem), evidence.Missing("not_available", nil)); err != nil {
				return err
			}
			continue
		}
		for _, name := range names {
			if err := send(evidence.Text(module.stem), evidence.Text(name)); err != nil {
				return err
			}
		}
	}
	if !matched {
		return send(evidence.Missing("not_available", nil), evidence.Missing("not_available", nil))
	}
	return nil
}

func windowsCallbacks(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	trace := &poolScannerAnalysis{ctx: ctx, out: out}
	for name, target := range map[string]*uint64{"max-read-bytes": &trace.maxBytes, "max-reads": &trace.maxReads, "max-rows": &trace.maxRows} {
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
	if err != nil || nodes == 0 || nodes > 1000000 {
		return fmt.Errorf("max-nodes must be 1..1000000")
	}
	env, err := poolScannerEnvironment(ctx, e, trace)
	if err != nil {
		return err
	}
	cache := e.SymbolCache
	if cache != "" {
		cache = filepath.Join(cache, "callback-symbols")
	}
	catalog, err := wincallbacks.Load(ctx, cache, e.Symbols, e.Offline)
	if err != nil {
		return err
	}
	if err := trace.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("callback_symbols"), "LayoutSHA256": evidence.Text(catalog.SHA256), "Name": evidence.Text(catalog.Name), "Source": evidence.Text(catalog.URL), "Raw": evidence.Bytes(catalog.Data)}}); err != nil {
		return err
	}
	a := &callbackAnalysis{trace: trace, layout: catalog.SHA256, symbols: ssdtSymbols(e.Symbols)}
	a.modules, err = windowsKernelModules(ctx, env)
	trace.failures.add(err)
	if err != nil {
		if err := trace.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("diagnostic"), "Error": evidence.Missing("callback_module_collection_incomplete", err)}}); err != nil {
			return err
		}
	}
	index := &wincallbacks.Index{Table: catalog.Layout, Layer: env.Kernel, KernelBase: e.KernelBase, Vista: windowsVistaOrLater(e.Symbols), MaxNodes: nodes}
	indexErr := index.Walk(ctx, func(entry wincallbacks.Entry) error {
		return a.emit(entry.Source, env.Kernel.Name(), entry.Route, evidence.Text(entry.Type), entry.Callback, entry.Detail, nil)
	})
	trace.failures.add(indexErr)
	if trace.stop != nil || ctx.Err() != nil {
		return errors.Join(indexErr, trace.stop, ctx.Err())
	}
	constraints, err := callbackPoolConstraints(e.Symbols.PointerSize(), windowsVistaOrLater(e.Symbols))
	if err != nil {
		return errors.Join(indexErr, err)
	}
	types, typeErr := windowsObjectTypes(ctx, env)
	var candidates, rejected uint64
	var poolErr error
	if typeErr != nil {
		poolErr = typeErr
	} else {
		poolErr = scanPoolObjects(ctx, env, constraints, "callback_pool_candidates", poolScannerRow, trace.emit, func(ctx context.Context, hit poolHit) (evidence.Row, bool, error) {
			candidates++
			if candidates > nodes {
				return evidence.Row{}, false, poolFatalError{fmt.Errorf("callback pool candidate bound exhausted")}
			}
			decoded, err := callbackPoolObject(ctx, env, catalog.Layout, hit, types)
			trace.failures.add(callbackObjectError(decoded, err))
			extra := map[string]evidence.Value{"PoolHeader": evidence.Address(hit.header), "Tag": evidence.Bytes(hit.tag), "Structure": evidence.Text(hit.typ)}
			if err != nil {
				extra["Error"] = evidence.Missing("callback_pool_object_incomplete", err)
			}
			if !decoded.valid {
				rejected++
				row := poolScannerRow(hit.layer, hit.object)
				row.Cells["RecordType"], row.Cells["Type"], row.Cells["Validity"] = evidence.Text("callback_candidate"), decoded.typ, evidence.Text("rejected")
				for key, value := range extra {
					row.Cells[key] = value
				}
				return row, true, nil
			}
			if err := a.emit(hit.object, hit.layer, "pool", decoded.typ, decoded.address, decoded.detail, extra); err != nil {
				return evidence.Row{}, false, poolFatalError{err}
			}
			return evidence.Row{}, false, nil
		})
	}
	cause := errors.Join(indexErr, poolErr, trace.stop, trace.failures.err("callback captured reads and decoding"))
	if trace.stop != nil || ctx.Err() != nil {
		return errors.Join(cause, ctx.Err())
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("task_summary"), "Coverage": {Kind: "structure", Data: map[string]evidence.Value{"Callbacks": evidence.Number(a.callbacks), "Rows": evidence.Number(a.rows), "PoolCandidates": evidence.Number(candidates), "Rejected": evidence.Number(rejected), "Reads": evidence.Number(trace.reads), "RequestedBytes": evidence.Number(trace.requested), "EvidenceRows": evidence.Number(trace.rows), "ReadFailures": evidence.Number(uint64(trace.failures.count)), "Completed": evidence.Bool(cause == nil)}}}}
	if cause != nil {
		summary.Cells["Error"] = evidence.Missing("callback_analysis_incomplete", cause)
	}
	return errors.Join(cause, trace.emit(summary))
}
