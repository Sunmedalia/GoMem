package plugins

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

type linuxNFLayout struct {
	name, kind            string
	global, split, device bool
}

func linuxNFContainerKind(t symbols.TypeRef) string {
	if t.Kind == "struct" && t.Name == "list_head" {
		return "list"
	}
	if t.Kind == "pointer" && t.Underlying() != nil && t.Underlying().Kind == "struct" {
		switch t.Underlying().Name {
		case "nf_hook_entry":
			return "entry"
		case "nf_hook_entries":
			return "entries"
		}
	}
	return ""
}

func linuxNFMatrixKind(t symbols.TypeRef) string {
	if t.Kind != "array" || t.Underlying() == nil || t.Underlying().Kind != "array" || t.Underlying().Underlying() == nil {
		return ""
	}
	return linuxNFContainerKind(*t.Underlying().Underlying())
}

// Match every applicable pinned implementation, including device hooks in a
// kernel with global hooks. Selection follows symbols and types, not a banner.
func linuxNetfilterLayouts(e plugin.Environment) ([]linuxNFLayout, error) {
	var layouts []linuxNFLayout
	if symbol, err := e.Symbols.Lookup("nf_hooks"); err == nil {
		if symbol.Type == nil || linuxNFMatrixKind(*symbol.Type) != "list" {
			return nil, fmt.Errorf("nf_hooks lacks a typed list_head matrix")
		}
		layouts = append(layouts, linuxNFLayout{name: "global-list", kind: "list", global: true})
	}
	if _, err := e.Symbols.Lookup("net_namespace_list"); err == nil {
		if nf, err := e.Symbols.Type("netns_nf"); err == nil {
			if field, ok := nf.Fields["hooks"]; ok {
				kind := linuxNFMatrixKind(field.Type)
				if kind != "" {
					layouts = append(layouts, linuxNFLayout{name: "namespace-" + kind, kind: kind})
				}
			}
			if _, ok := nf.Fields["hooks_ipv4"]; ok {
				layouts = append(layouts, linuxNFLayout{name: "namespace-split", kind: "entries", split: true})
			}
		}
		if dev, err := e.Symbols.Type("net_device"); err == nil {
			if field, ok := dev.Fields["nf_hooks_ingress"]; ok {
				if kind := linuxNFContainerKind(field.Type); kind != "" {
					layouts = append(layouts, linuxNFLayout{name: "device-" + kind, kind: kind, device: true})
				}
			}
		}
	}
	if len(layouts) == 0 {
		return nil, fmt.Errorf("unsupported Netfilter symbol layout")
	}
	return layouts, nil
}

type linuxNFScope struct {
	layout, proto, hook string
	ns, device, slot    uint64
	id                  evidence.Value
	route               map[string]evidence.Value
}

func (s linuxNFScope) decorate(row *evidence.Row) {
	row.Cells["Net NS"] = s.id
	row.Cells["Layout"] = evidence.Text(s.layout)
	row.Cells["Slot"] = evidence.Address(s.slot)
	if s.ns != 0 {
		row.Cells["Namespace"] = evidence.Address(s.ns)
	}
	if s.device != 0 {
		row.Cells["Device"] = evidence.Address(s.device)
	}
}

type linuxNFReader struct {
	ctx      context.Context
	e        plugin.Environment
	max      int
	failures *pluginFailures
	emit     plugin.Emit
	emitErr  error
	hook     func(linuxNFScope, map[string]evidence.Value, uint64) error
}

func (r *linuxNFReader) out(row evidence.Row) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if r.emitErr != nil {
		return r.emitErr
	}
	r.emitErr = r.emit(row)
	return r.emitErr
}

type linuxNFReadError struct {
	error
	fields map[string]evidence.Value
}

func (e *linuxNFReadError) Unwrap() error { return e.error }

func (r *linuxNFReader) diagnostic(scope linuxNFScope, err error) error {
	if r.emitErr != nil {
		return r.emitErr
	}
	if r.ctx.Err() != nil {
		return r.ctx.Err()
	}
	r.failures.add(err)
	fields := scope.route
	var readErr *linuxNFReadError
	if errors.As(err, &readErr) {
		fields = readErr.fields
	}
	row := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("netfilter_error"), "Proto": evidence.Text(scope.proto), "Hook": evidence.Text(scope.hook), "Offset": evidence.Address(scope.slot), "Error": evidence.Missing("netfilter_container_incomplete", err), "FieldEvidence": {Kind: "structure", Data: maps.Clone(fields)}}, Provenance: evidence.Provenance{Layer: r.e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", scope.slot)}}
	scope.decorate(&row)
	return r.out(row)
}
func (r *linuxNFReader) run(layouts []linuxNFLayout) error {
	for _, layout := range layouts {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		scope := linuxNFScope{layout: layout.name, id: evidence.Missing("global_table", nil)}
		if layout.global {
			symbol, err := r.e.Symbols.Lookup("nf_hooks")
			if err != nil {
				return err
			}
			base, err := r.e.Symbol("nf_hooks")
			if err != nil {
				return err
			}
			if err = r.matrix(layout, scope, base, *symbol.Type); err != nil {
				return err
			}
			continue
		}
		scope.id = evidence.Missing("namespace_not_read", nil)
		head, err := r.e.Symbol("net_namespace_list")
		if err != nil {
			return err
		}
		_, rootProof, rootErr := linuxCaptureField(r.ctx, r.e, head, "list_head", "")
		scope.slot = head
		scope.route = map[string]evidence.Value{"NamespaceHead": rootProof}
		if err = r.listObservation(scope, "netfilter_namespace_list"); err != nil {
			return err
		}
		if rootErr != nil {
			if err = r.diagnostic(scope, rootErr); err != nil {
				return err
			}
			continue
		}
		link, err := r.e.Objects.Field("net", "list")
		if err != nil {
			return err
		}
		err = r.e.Objects.WalkList(r.ctx, head, link.Offset, r.max, func(ns uint64) error {
			fields := maps.Clone(scope.route)
			_, linkProof, linkErr := linuxCaptureField(r.ctx, r.e, ns, "net", "list")
			fields["NamespaceLink"] = linkProof
			if linkErr != nil {
				return linkErr
			}
			id, _, err := linuxUnsignedField(r.ctx, r.e, ns, "net", "ns.inum", fields, "NamespaceID")
			current := scope
			current.route = fields
			current.ns = ns
			current.slot = ns
			current.id = evidence.Number(id)
			if err != nil {
				current.id = evidence.Missing("namespace_id_unreadable", err)
				return r.diagnostic(current, err)
			}
			row := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("netfilter_namespace"), "FieldEvidence": {Kind: "structure", Data: fields}}, Provenance: evidence.Provenance{Layer: r.e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", ns)}}
			current.decorate(&row)
			if err = r.out(row); err != nil {
				return err
			}
			if layout.device {
				return r.devices(layout, current)
			}
			if layout.split {
				return r.split(layout, current)
			}
			field, err := r.e.Objects.Field("net", "nf.hooks")
			if err != nil {
				return err
			}
			base, err := memory.Add(ns, field.Offset)
			if err != nil {
				return err
			}
			return r.matrix(layout, current, base, field.Type)
		})
		if err != nil {
			scope.slot = head
			if err = r.diagnostic(scope, err); err != nil {
				return err
			}
		}
	}
	return r.ctx.Err()
}

func (r *linuxNFReader) matrix(layout linuxNFLayout, scope linuxNFScope, base uint64, t symbols.TypeRef) error {
	if linuxNFMatrixKind(t) != layout.kind || t.Count < 13 || t.Count > 256 || t.Underlying().Count < 8 || t.Underlying().Count > 256 {
		return fmt.Errorf("invalid Netfilter matrix dimensions or element type")
	}
	inner := *t.Underlying()
	leaf := *inner.Underlying()
	rowSize, err := r.e.Objects.Size(inner)
	if err != nil {
		return err
	}
	stride, err := r.e.Objects.Size(leaf)
	if err != nil || stride == 0 || stride > 64 {
		return fmt.Errorf("invalid Netfilter matrix stride: %v", err)
	}
	for proto, protocol := range linuxNetfilterProtocols() {
		if protocol.name == "INET" || protocol.name == "NETDEV" {
			continue
		}
		for hook, name := range protocol.hooks {
			at, err := memory.Add(base, uint64(proto)*rowSize+uint64(hook)*stride)
			if err != nil {
				return err
			}
			current := scope
			current.proto = protocol.name
			current.hook = name
			current.slot = at
			if err = r.container(layout, current); err != nil {
				if err = r.diagnostic(current, err); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *linuxNFReader) split(layout linuxNFLayout, scope linuxNFScope) error {
	for _, protocol := range linuxNetfilterProtocols() {
		if len(protocol.hooks) == 0 || protocol.name == "INET" || protocol.name == "NETDEV" {
			continue
		}
		name := "nf.hooks_" + strings.ToLower(protocol.name)
		// Missing protocol members represent kernel configuration exclusions.
		nf, err := r.e.Symbols.Type("netns_nf")
		if err != nil {
			return err
		}
		if _, ok := nf.Fields["hooks_"+strings.ToLower(protocol.name)]; !ok {
			continue
		}
		field, err := r.e.Objects.Field("net", name)
		if err != nil {
			return err
		}
		if field.Type.Kind != "array" || field.Type.Underlying() == nil || linuxNFContainerKind(*field.Type.Underlying()) != "entries" || field.Type.Count < uint64(len(protocol.hooks)) {
			return fmt.Errorf("invalid %s hook array", name)
		}
		base, err := memory.Add(scope.ns, field.Offset)
		if err != nil {
			return err
		}
		stride, err := r.e.Objects.Size(*field.Type.Underlying())
		if err != nil || stride == 0 {
			return fmt.Errorf("invalid hook pointer stride: %v", err)
		}
		for index, hook := range protocol.hooks {
			current := scope
			current.proto = protocol.name
			current.hook = hook
			current.slot, err = memory.Add(base, uint64(index)*stride)
			if err != nil {
				return err
			}
			if err = r.container(layout, current); err != nil {
				if err = r.diagnostic(current, err); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *linuxNFReader) devices(layout linuxNFLayout, scope linuxNFScope) error {
	headField, err := r.e.Objects.Field("net", "dev_base_head")
	if err != nil {
		return err
	}
	head, err := memory.Add(scope.ns, headField.Offset)
	if err != nil {
		return err
	}
	link, err := r.e.Objects.Field("net_device", "dev_list")
	if err != nil {
		return err
	}
	_, headProof, headErr := linuxCaptureField(r.ctx, r.e, head, "list_head", "")
	scope.route = maps.Clone(scope.route)
	scope.route["DeviceHead"] = headProof
	scope.slot = head
	if err = r.listObservation(scope, "netfilter_device_list"); err != nil {
		return err
	}
	if headErr != nil {
		return headErr
	}
	devType, err := r.e.Symbols.Type("net_device")
	if err != nil {
		return err
	}
	for _, hook := range []string{"INGRESS", "EGRESS"} {
		field, ok := devType.Fields["nf_hooks_"+strings.ToLower(hook)]
		if !ok {
			continue
		}
		if linuxNFContainerKind(field.Type) != layout.kind {
			return fmt.Errorf("device %s container type differs from ingress", hook)
		}
		err = r.e.Objects.WalkList(r.ctx, head, link.Offset, r.max, func(device uint64) error {
			current := scope
			current.device = device
			current.route = maps.Clone(scope.route)
			_, linkProof, linkErr := linuxCaptureField(r.ctx, r.e, device, "net_device", "dev_list")
			current.route["DeviceLink"] = linkProof
			if linkErr != nil {
				return linkErr
			}
			current.proto = "NETDEV"
			current.hook = hook
			var err error
			current.slot, err = memory.Add(device, field.Offset)
			if err != nil {
				return err
			}
			if err = r.container(layout, current); err != nil {
				return r.diagnostic(current, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *linuxNFReader) ptr(at uint64, fields map[string]evidence.Value, key string) (uint64, error) {
	_, proof, err := linuxCaptureRange(r.ctx, r.e.Kernel, at, r.e.Symbols.PointerSize())
	fields[key] = proof
	if err != nil {
		return 0, err
	}
	return r.e.Objects.Scalar(r.ctx, at, symbols.TypeRef{Kind: "pointer"})
}
func (r *linuxNFReader) listObservation(scope linuxNFScope, kind string) error {
	row := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Offset": evidence.Address(scope.slot), "FieldEvidence": {Kind: "structure", Data: maps.Clone(scope.route)}}, Provenance: evidence.Provenance{Layer: r.e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", scope.slot)}}
	scope.decorate(&row)
	return r.out(row)
}

func (r *linuxNFReader) slotProof(scope linuxNFScope, fields map[string]evidence.Value) error {
	kind := "netfilter_slot"
	if scope.layout == "global-list" || strings.HasSuffix(scope.layout, "-list") {
		kind = "netfilter_list"
	}
	row := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text(kind), "Proto": evidence.Text(scope.proto), "Hook": evidence.Text(scope.hook), "Offset": evidence.Address(scope.slot), "FieldEvidence": {Kind: "structure", Data: maps.Clone(fields)}}, Provenance: evidence.Provenance{Layer: r.e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", scope.slot)}}
	scope.decorate(&row)
	return r.out(row)
}
func (r *linuxNFReader) emitHook(scope linuxNFScope, fields map[string]evidence.Value, ops uint64) error {
	if r.ctx.Err() != nil {
		return r.ctx.Err()
	}
	if err := r.hook(scope, fields, ops); err != nil {
		r.emitErr = err
		return err
	}
	return r.ctx.Err()
}
func (r *linuxNFReader) container(layout linuxNFLayout, scope linuxNFScope) (err error) {
	fields := maps.Clone(scope.route)
	if fields == nil {
		fields = map[string]evidence.Value{}
	}
	failureProof := fields
	defer func() {
		if err != nil && r.emitErr == nil && r.ctx.Err() == nil {
			err = &linuxNFReadError{err, maps.Clone(failureProof)}
		}
	}()
	if layout.kind == "list" {
		list, listErr := r.e.Symbols.Type("list_head")
		if listErr != nil || list.Size < uint64(2*r.e.Symbols.PointerSize()) || list.Size > 64 {
			return fmt.Errorf("invalid list_head size: %v", listErr)
		}
		_, proof, readErr := linuxCaptureField(r.ctx, r.e, scope.slot, "list_head", "")
		fields["Head"] = proof
		if err := r.slotProof(scope, fields); err != nil {
			return err
		}
		if readErr != nil {
			return readErr
		}
		link, err := r.e.Objects.Field("nf_hook_ops", "list")
		if err != nil {
			return err
		}
		return r.e.Objects.WalkList(r.ctx, scope.slot, link.Offset, r.max, func(ops uint64) error { return r.emitHook(scope, fields, ops) })
	}
	pointer, err := r.ptr(scope.slot, fields, "ContainerPointer")
	if layout.kind == "entry" || pointer == 0 || err != nil {
		if emitErr := r.slotProof(scope, fields); emitErr != nil {
			return emitErr
		}
	}
	if err != nil {
		return err
	}
	if pointer == 0 {
		return nil
	}
	if layout.kind == "entry" {
		seen := map[uint64]bool{}
		for pointer != 0 {
			if r.ctx.Err() != nil {
				return r.ctx.Err()
			}
			if seen[pointer] {
				return fmt.Errorf("cycle in nf_hook_entry at %#x", pointer)
			}
			if len(seen) >= r.max {
				return fmt.Errorf("nf_hook_entry exceeds max-nodes %d", r.max)
			}
			seen[pointer] = true
			proof := maps.Clone(fields)
			failureProof = proof
			ops, _, err := linuxUnsignedField(r.ctx, r.e, pointer, "nf_hook_entry", "orig_ops", proof, "OriginalOps")
			if err != nil {
				return err
			}
			next, _, nextErr := linuxUnsignedField(r.ctx, r.e, pointer, "nf_hook_entry", "next", proof, "Next")
			if ops == 0 {
				return fmt.Errorf("null original nf_hook_ops pointer")
			}
			if err = r.emitHook(scope, proof, ops); err != nil {
				return err
			}
			if nextErr != nil {
				return nextErr
			}
			pointer = next
		}
		return nil
	}
	count, _, err := linuxUnsignedField(r.ctx, r.e, pointer, "nf_hook_entries", "num_hook_entries", fields, "Count")
	if emitErr := r.slotProof(scope, fields); emitErr != nil {
		return emitErr
	}
	if err != nil {
		return err
	}
	if count > uint64(r.max) {
		return fmt.Errorf("nf_hook_entries count %d exceeds max-nodes %d", count, r.max)
	}
	array, err := r.e.Objects.Field("nf_hook_entries", "hooks")
	if err != nil {
		return err
	}
	if array.Type.Kind != "array" || array.Type.Underlying() == nil || array.Type.Underlying().Name != "nf_hook_entry" {
		return fmt.Errorf("nf_hook_entries.hooks is not an entry array")
	}
	stride, err := r.e.Objects.Size(*array.Type.Underlying())
	if err != nil || stride == 0 || stride > 4096 {
		return fmt.Errorf("invalid nf_hook_entry stride: %v", err)
	}
	end, err := memory.Add(pointer, array.Offset)
	if err != nil {
		return err
	}
	if count > (^uint64(0)-end)/stride {
		return fmt.Errorf("nf_hook_entries pointer arithmetic overflow")
	}
	original := end + count*stride
	for index := uint64(0); index < count; index++ {
		at, err := memory.Add(original, index*uint64(r.e.Symbols.PointerSize()))
		if err != nil {
			return err
		}
		proof := maps.Clone(fields)
		failureProof = proof
		proof["OriginalArray"] = evidence.Address(original)
		ops, err := r.ptr(at, proof, "OriginalOps")
		if err != nil {
			return err
		}
		if ops == 0 {
			return fmt.Errorf("null original nf_hook_ops pointer")
		}
		if err = r.emitHook(scope, proof, ops); err != nil {
			return err
		}
	}
	return nil
}
