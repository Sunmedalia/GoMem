package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type linuxNetfilterProto struct {
	name  string
	hooks []string
}

func linuxNetfilterPlugins() []builtin {
	return []builtin{{plugin.Spec{
		Name: "linux.netfilter", Upstream: "linux.malware.netfilter.Netfilter", Platform: "linux", NeedsKernel: true,
		Description: "Enumerate global, namespace and device Netfilter hooks",
		Parameters:  []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Module source and per-hook list bound, 1..1000000"}, {Name: "max-scan-bytes", Kind: "uint", Default: "268435456", Description: "Module allocation scan bound, 1..8589934592"}},
		Columns: []evidence.Column{
			{Name: "Net NS", Kind: "uint64"}, {Name: "Namespace", Kind: "address"}, {Name: "Device", Kind: "address"}, {Name: "Layout", Kind: "string"}, {Name: "Slot", Kind: "address"}, {Name: "Proto", Kind: "string"}, {Name: "Hook", Kind: "string"},
			{Name: "Priority", Kind: "int64"}, {Name: "Handler", Kind: "address"}, {Name: "Module", Kind: "string"},
			{Name: "Symbol", Kind: "string"}, {Name: "Is Hooked", Kind: "string"},
			{Name: "Offset", Kind: "address"}, {Name: "FieldEvidence", Kind: "structure"},
			{Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "missing"},
		},
	}, linuxNetfilter}}
}

func linuxNetfilterProtocols() []linuxNetfilterProto {
	inet := []string{"PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING"}
	return []linuxNetfilterProto{
		{name: "UNSPEC"},
		{name: "INET", hooks: inet},
		{name: "IPV4", hooks: inet},
		{name: "ARP", hooks: []string{"IN", "OUT", "FORWARD"}},
		{name: "UNSPEC"},
		{name: "NETDEV", hooks: []string{"INGRESS", "EGRESS"}},
		{name: "UNSPEC"},
		{name: "BRIDGE", hooks: inet},
		{name: "UNSPEC"},
		{name: "UNSPEC"},
		{name: "IPV6", hooks: inet},
		{name: "UNSPEC"},
		{name: "DECNET", hooks: []string{"PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING", "HELLO", "ROUTE"}},
	}
}

func linuxNetfilter(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("linux.netfilter requires kernel memory and symbols")
	}
	switch e.Architecture {
	case "x64", "x86", "pae":
	default:
		return fmt.Errorf("linux.netfilter requires an Intel kernel layer")
	}
	maxNodes, _, err := limits(p)
	if err != nil {
		return err
	}
	layouts, err := linuxNetfilterLayouts(e)
	if err != nil {
		return err
	}
	var failures pluginFailures
	var emitErr error
	emit := func(row evidence.Row) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if emitErr != nil {
			return emitErr
		}
		emitErr = out(row)
		return emitErr
	}
	sources, err := linuxGatherModuleSources(ctx, e, p, emit)
	if err != nil {
		return err
	}
	mask, err := linuxModuleAddressMask(e)
	if err != nil {
		return err
	}
	if err = sources.kernel(); err != nil {
		if err = sources.issue(0, "kernel", "kernel_bounds_unavailable", err); err != nil {
			return err
		}
	}
	attributionErr := sources.failures.err("Netfilter module attribution")
	failures.add(attributionErr)
	modules := linuxFlattenModuleSources(sources.results, mask)
	kernel, err := linuxKernelSymbolIndex(ctx, e, mask)
	if err != nil {
		return err
	}
	runner := &linuxNFReader{ctx: ctx, e: e, max: maxNodes, failures: &failures, emit: emit}
	runner.hook = func(scope linuxNFScope, fields map[string]evidence.Value, ops uint64) error {
		return linuxNetfilterRow(ctx, e, &failures, modules, kernel, attributionErr, scope.proto, scope.hook, ops, func(row evidence.Row) error {
			scope.decorate(&row)
			proof := row.Cells["FieldEvidence"].Data.(map[string]evidence.Value)
			proof["Route"] = evidence.Value{Kind: "structure", Data: fields}
			return emit(row)
		})
	}
	if err = runner.run(layouts); err != nil {
		return err
	}

	return errors.Join(failures.err("Linux Netfilter hooks"), ctx.Err())
}

func linuxNetfilterRow(ctx context.Context, e plugin.Environment, failures *pluginFailures, modules []linuxModuleInfo, kernel map[uint64]string, attributionErr error, proto, hook string, ops uint64, out plugin.Emit) error {
	fields := map[string]evidence.Value{}
	row := evidence.Row{Cells: map[string]evidence.Value{
		"Net NS": evidence.Missing("global_table", nil), "Proto": evidence.Text(proto), "Hook": evidence.Text(hook),
		"Priority": evidence.Missing("not_read", nil), "Handler": evidence.Missing("not_read", nil),
		"Module": evidence.Missing("not_available", nil), "Symbol": evidence.Missing("not_available", nil),
		"Is Hooked": evidence.Missing("handler_not_resolved", nil), "Offset": evidence.Address(ops),
		"FieldEvidence": evidence.Value{Kind: "structure", Data: fields}, "RecordType": evidence.Text("netfilter_hook"),
		"Error": evidence.Missing("not_applicable", nil),
	}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", ops)}}
	_, capture, err := linuxCaptureField(ctx, e, ops, "nf_hook_ops", "")
	fields["nf_hook_ops"] = capture
	if err != nil {
		failures.add(err)
		row.Cells["Error"] = evidence.Missing("hook_ops_unreadable", err)
		return out(row)
	}
	priority, _, priorityErr := linuxSignedField(ctx, e, ops, "nf_hook_ops", "priority", fields, "priority")
	if priorityErr != nil {
		failures.add(priorityErr)
		row.Cells["Priority"] = evidence.Missing("priority_unreadable", priorityErr)
	} else {
		row.Cells["Priority"] = evidence.Integer(priority)
	}
	handler, _, handlerErr := linuxUnsignedField(ctx, e, ops, "nf_hook_ops", "hook", fields, "hook")
	if handlerErr != nil {
		failures.add(handlerErr)
		row.Cells["Handler"] = evidence.Missing("handler_unreadable", handlerErr)
	} else {
		row.Cells["Handler"] = evidence.Address(handler)
		module, symbol, lookupErr := linuxNetfilterHandler(ctx, e, fields, modules, kernel, handler)
		failures.add(lookupErr)
		if lookupErr != nil {
			row.Cells["Error"] = evidence.Missing("handler_lookup_incomplete", lookupErr)
		}
		if module == "" && lookupErr != nil {
			row.Cells["Is Hooked"] = evidence.Missing("handler_lookup_incomplete", lookupErr)
		} else if module == "" {
			if attributionErr != nil {
				row.Cells["Is Hooked"] = evidence.Missing("module_sources_incomplete", attributionErr)
				row.Cells["Error"] = evidence.Missing("module_sources_incomplete", attributionErr)
			} else {
				row.Cells["Is Hooked"] = evidence.Text("True")
			}
		} else {
			row.Cells["Module"] = evidence.Text(module)
			if symbol != "" {
				row.Cells["Symbol"] = evidence.Text(symbol)
			}
			row.Cells["Is Hooked"] = evidence.Text("False")
		}
	}
	return out(row)
}

func linuxNetfilterHandler(ctx context.Context, e plugin.Environment, fields map[string]evidence.Value, modules []linuxModuleInfo, kernel map[uint64]string, handler uint64) (string, string, error) {
	n := &linuxModuleRead{ctx: ctx, e: e, fields: fields, failures: &pluginFailures{}}
	match, symbol, _, err := linuxModuleLookup(n, modules, kernel, handler)
	if match == nil {
		return "", symbol, err
	}
	fields["ModuleOwner"] = evidence.Value{Kind: "structure", Data: map[string]evidence.Value{"Object": evidence.Address(match.offset), "Base": evidence.Address(match.base), "Size": evidence.Number(match.size), "Name": evidence.Text(match.name)}}
	return match.name, symbol, errors.Join(err, n.failures.err("module symbol lookup"))
}
