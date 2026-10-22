package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/memoryscan"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/winnet"
)

func windowsNetScanPlugins() []builtin {
	parameters := append([]plugin.Parameter{{Name: "include-corrupt", Kind: "bool", Default: "false", Description: "Bypass network validity checks; preserve unreadable fields and errors"}}, windowsPoolScannerPlugins()[0].spec.Parameters...)
	columns := []evidence.Column{}
	for _, name := range []string{"Offset", "OwnerOffset"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "address"})
	}
	for _, name := range []string{"Proto", "LocalAddr", "ForeignAddr", "State", "Owner", "ProcessIdentity", "Layer", "Type", "RecordType", "Validity", "NetworkSymbols", "NetworkSymbolSHA256"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "string"})
	}
	for _, name := range []string{"LocalPort", "ForeignPort", "PID", "CreateTimeRaw"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "uint64"})
	}
	columns = append(columns, evidence.Column{Name: "Created", Kind: "timestamp"}, evidence.Column{Name: "Error", Kind: "missing"}, evidence.Column{Name: "Coverage", Kind: "structure"})
	for _, field := range []evidence.Column{{Name: "Raw", Kind: "bytes"}, {Name: "SHA256", Kind: "string"}, {Name: "Source", Kind: "string"}, {Name: "Requested", Kind: "uint64"}, {Name: "Captured", Kind: "uint64"}, {Name: "ReadComplete", Kind: "bool"}, {Name: "Tag", Kind: "bytes"}, {Name: "PoolHeader", Kind: "address"}} {
		columns = append(columns, field)
	}
	return []builtin{{plugin.Spec{Name: "windows.netscan", Upstream: "windows.netscan.NetScan", Platform: "windows", NeedsKernel: true, Description: "Scan Windows TCP/IP pools using pinned native layouts, with read evidence and explicit incomplete results", Parameters: parameters, Columns: columns}, windowsNetScan}}
}

// networkVersion reads the same kernel/debug inputs as the fixed baseline.
// Metadata is a symbol dependency, not an inference from the image filename.
func networkVersion(ctx context.Context, e plugin.Environment) (winnet.Version, error) {
	v := winnet.Version{Width: e.Symbols.PointerSize()}
	debug, err := e.Symbol("KdVersionBlock")
	if err != nil {
		return v, err
	}
	v.Build, err = e.Objects.Uint(ctx, debug, "_DBGKD_GET_VERSION64", "MinorVersion")
	if err != nil {
		return v, err
	}
	kuser := uint64(0xffdf0000)
	if v.Width == 8 {
		kuser = 0xfffff78000000000
	}
	v.Major, err = e.Objects.Uint(ctx, kuser, "_KUSER_SHARED_DATA", "NtMajorVersion")
	if err != nil {
		return v, err
	}
	v.Minor, err = e.Objects.Uint(ctx, kuser, "_KUSER_SHARED_DATA", "NtMinorVersion")
	if err != nil {
		return v, err
	}
	var metadata struct {
		PE *struct{ Major, Minor, Revision, Build *uint64 }
	}
	if json.Unmarshal(e.Symbols.Metadata()["windows"], &metadata) == nil && metadata.PE != nil && metadata.PE.Major != nil && metadata.PE.Minor != nil && metadata.PE.Revision != nil && metadata.PE.Build != nil {
		pe := metadata.PE
		v.Is18363 = *pe.Major > 10 || *pe.Major == 10 && (*pe.Minor > 0 || *pe.Revision >= 18363)
	} else {
		_, symbolErr := e.Symbols.Lookup("_KQOS_GROUPING_SETS")
		_, typeErr := e.Symbols.Type("_KQOS_GROUPING_SETS")
		v.Is18363 = symbolErr == nil || typeErr == nil
	}
	if v.NeedsTCPIPRevision() {
		version, found, err := findExtensiveVersion(ctx, e.Physical, "tcpip.sys")
		if err != nil {
			return v, err
		}
		if found {
			v.TCPIPRevision = version.build
		}
	}
	return v, nil
}

func networkConstraints(layout *winnet.Layout, selected winnet.Selection) ([]poolConstraint, error) {
	tags := []struct{ tag, typ string }{{"TcpL", "_TCP_LISTENER"}, {"TcpE", "_TCP_ENDPOINT"}, {"UdpA", "_UDP_ENDPOINT"}}
	if selected.AdditionalTCPTag {
		tags = append(tags, struct{ tag, typ string }{"TTcb", "_TCP_ENDPOINT"})
	}
	var result []poolConstraint
	for _, entry := range tags {
		size, err := layout.DeclaredSize(entry.typ)
		if err != nil || size == 0 {
			return nil, fmt.Errorf("network pool type %s: invalid declared size %d: %v", entry.typ, size, err)
		}
		result = append(result, poolConstraint{tag: []byte(entry.tag), typeName: entry.typ, minSize: size, hasMin: true, pageType: poolNonPaged | poolFree})
	}
	return result, nil
}

// The endpoint validity check uses raw owner PID only when the local address
// cannot be obtained. Process validity is a separate attribution decision.
func networkObjectValid(ctx context.Context, e plugin.Environment, o winnet.Object) (bool, error) {
	if o.Type == "_TCP_ENDPOINT" {
		if _, err := o.State(ctx); err != nil {
			if errors.Is(err, winnet.ErrInvalidState) {
				return false, nil
			}
			return false, err
		}
	}
	family, err := o.Family(ctx)
	if err != nil || family != 2 && family != 23 {
		return false, err
	}
	if o.Type != "_TCP_ENDPOINT" {
		return true, nil
	}
	local, localErr := o.TCPAddress(ctx, false)
	if local != "" {
		return true, localErr
	}
	owner, err := o.Scalar(ctx, "Owner")
	if err != nil {
		return false, errors.Join(localErr, err)
	}
	pid, err := e.Objects.Uint(ctx, owner, "_EPROCESS", "UniqueProcessId")
	return err == nil && pid > 0 && pid <= 65535, errors.Join(localErr, err)
}

func networkTime(raw uint64) evidence.Value {
	ticks := int64(raw)
	if floorDivInt64(ticks, 10000000) == 0 {
		return evidence.Missing("not_applicable_filetime", nil)
	}
	stamp, ok := volatilityFiletime(ticks)
	if !ok {
		return evidence.Missing("unparsable_filetime", nil)
	}
	if stamp.Year() <= 1950 || stamp.Year() >= 2200 {
		return evidence.Missing("unreadable_network_time", nil)
	}
	return evidence.Value{Kind: "timestamp", Data: stamp.Format(time.RFC3339)}
}

// processObjectValid deliberately treats unreadable candidate objects as
// invalid. Validate its schema first so missing/wrong symbols cannot masquerade
// as cleanly rejected owners without ever issuing a traceable memory read.
func networkOwnerSchema(e plugin.Environment) error {
	for _, path := range []string{"UniqueProcessId", "Pcb.DirectoryTableBase", "ThreadListHead.Flink", "ThreadListHead.Blink", "CreateTime", "ExitTime"} {
		field, err := e.Objects.Field("_EPROCESS", path)
		if err != nil {
			return err
		}
		if path == "CreateTime" || path == "ExitTime" {
			if field.Type.Kind == "struct" || field.Type.Kind == "union" {
				field, err = e.Objects.Field("_EPROCESS", path+".QuadPart")
				if err != nil {
					return err
				}
			}
		}
		ref := field.Type
		if path == "Pcb.DirectoryTableBase" && ref.Kind == "array" {
			if ref.Subtype == nil || ref.Count == 0 {
				return fmt.Errorf("invalid network owner CR3 array")
			}
			ref = *ref.Subtype
		}
		if _, err := e.Objects.ScalarType(ref); err != nil {
			return fmt.Errorf("network owner %s: %w", path, err)
		}
	}
	field, err := e.Objects.Field("_EPROCESS", "ImageFileName")
	if err != nil {
		return err
	}
	if field.Type.Kind != "array" || field.Type.Subtype == nil || field.Type.Count == 0 || field.Type.Count > 256 {
		return fmt.Errorf("network owner name must be a bounded byte array")
	}
	size, err := e.Objects.Size(*field.Type.Subtype)
	if err != nil || size != 1 {
		return fmt.Errorf("network owner name has invalid byte element")
	}
	return nil
}

type networkOwnerReads struct {
	memory.MemoryLayer
	failure error
}

func (l *networkOwnerReads) ReadAt(ctx context.Context, p []byte, at uint64) (int, error) {
	n, err := l.MemoryLayer.ReadAt(ctx, p, at)
	if err != nil && l.failure == nil {
		l.failure = err
	}
	return n, err
}

func networkOwner(ctx context.Context, e plugin.Environment, o winnet.Object, row *evidence.Row) error {
	for _, key := range []string{"PID", "Owner", "OwnerOffset", "ProcessIdentity"} {
		row.Cells[key] = evidence.Missing("unreadable_network_owner", nil)
	}
	owner, err := o.Scalar(ctx, "Owner")
	if err != nil {
		return err
	}
	row.Cells["OwnerOffset"] = evidence.Address(owner)
	reads := &networkOwnerReads{MemoryLayer: e.Kernel}
	reader := &object.Reader{Layer: reads, Symbols: e.Symbols}
	valid, err := processObjectValid(ctx, reader, owner)
	if reads.failure != nil {
		for _, key := range []string{"PID", "Owner", "ProcessIdentity"} {
			row.Cells[key] = evidence.Missing("network_owner_read_failed", reads.failure)
		}
		return errors.Join(err, reads.failure)
	}
	if err != nil || !valid {
		return err
	}
	pid, err := e.Objects.Uint(ctx, owner, "_EPROCESS", "UniqueProcessId")
	if err != nil {
		return err
	}
	field, err := e.Objects.Field("_EPROCESS", "ImageFileName")
	if err != nil {
		return err
	}
	if field.Type.Kind != "array" || field.Type.Subtype == nil || field.Type.Count == 0 || field.Type.Count > 256 {
		return fmt.Errorf("network owner name must be a bounded byte array")
	}
	element, err := e.Objects.Size(*field.Type.Subtype)
	if err != nil || element != 1 {
		return fmt.Errorf("network owner name has non-byte elements")
	}
	nameAt, err := memory.Add(owner, field.Offset)
	if err != nil {
		return err
	}
	name, err := memory.Read(ctx, e.Kernel, nameAt, int(field.Type.Count))
	if err != nil {
		return err
	}
	if end := bytes.IndexByte(name, 0); end >= 0 {
		name = name[:end]
	}
	row.Cells["PID"] = evidence.Number(pid)
	if len(name) != 0 {
		row.Cells["Owner"] = evidence.Text(memoryscan.DisplayUTF8(name))
	}
	raw, err := windowsRawTime(ctx, e, owner, "_EPROCESS", "CreateTime")
	if err != nil {
		return err
	}
	row.Cells["ProcessIdentity"] = evidence.Text(evidence.ProcessID(e.ImageHash, e.Kernel.Name(), owner, pid, strconv.FormatUint(raw, 10)))
	return nil
}

func networkRows(ctx context.Context, e plugin.Environment, o winnet.Object, validity string) ([]evidence.Row, error) {
	base := poolScannerRow(o.Layer.Name(), o.Address)
	base.Cells["RecordType"], base.Cells["Type"], base.Cells["Validity"] = evidence.Text("network"), evidence.Text(o.Type), evidence.Text(validity)
	var failures []error
	failures = append(failures, networkOwner(ctx, e, o, &base))
	raw, err := o.Scalar(ctx, "CreateTime.QuadPart")
	if err != nil {
		base.Cells["Created"] = evidence.Missing("read_failed", err)
		base.Cells["CreateTimeRaw"] = evidence.Missing("read_failed", err)
		failures = append(failures, err)
	} else {
		base.Cells["Created"], base.Cells["CreateTimeRaw"] = networkTime(raw), evidence.Number(raw)
	}
	getPort := func(path string) evidence.Value {
		n, err := o.Scalar(ctx, path)
		if err != nil {
			failures = append(failures, err)
			return evidence.Missing("read_failed", err)
		}
		return evidence.Number(n)
	}
	if o.Type == "_TCP_ENDPOINT" {
		family, err := o.Family(ctx)
		failures = append(failures, err)
		proto := "TCPv?"
		if family == 2 {
			proto = "TCPv4"
		} else if family == 23 {
			proto = "TCPv6"
		}
		base.Cells["Proto"] = evidence.Text(proto)
		base.Cells["LocalPort"], base.Cells["ForeignPort"] = getPort("LocalPort"), getPort("RemotePort")
		for _, endpoint := range []struct {
			name   string
			remote bool
		}{{"LocalAddr", false}, {"ForeignAddr", true}} {
			name, remote := endpoint.name, endpoint.remote
			address, err := o.TCPAddress(ctx, remote)
			failures = append(failures, err)
			base.Cells[name] = evidence.Text(address)
			if address == "" {
				base.Cells[name] = evidence.Missing("unreadable_network_address", err)
			}
		}
		state, err := o.State(ctx)
		base.Cells["State"] = evidence.Text(state)
		if err != nil {
			base.Cells["State"] = evidence.Missing("invalid_network_state", err)
		}
		// Unknown state is expected with include-corrupt; no source read failure.
		if !errors.Is(err, winnet.ErrInvalidState) {
			failures = append(failures, err)
		}
		return []evidence.Row{base}, errors.Join(failures...)
	}
	base.Cells["LocalPort"], base.Cells["ForeignPort"] = getPort("Port"), evidence.Number(0)
	sockets, err := o.ListenerSockets(ctx)
	failures = append(failures, err)
	var rows []evidence.Row
	for _, socket := range sockets {
		row := base
		row.Cells = make(map[string]evidence.Value, len(base.Cells)+4)
		for key, value := range base.Cells {
			row.Cells[key] = value
		}
		proto, state, remote := "TCP", "LISTENING", socket.Remote
		if o.Type == "_UDP_ENDPOINT" {
			proto, state, remote = "UDP", "", "*"
		}
		row.Cells["Proto"], row.Cells["State"] = evidence.Text(proto+socket.Version), evidence.Text(state)
		row.Cells["LocalAddr"], row.Cells["ForeignAddr"] = evidence.Text(socket.Local), evidence.Text(remote)
		rows = append(rows, row)
	}
	return rows, errors.Join(failures...)
}

func windowsNetScan(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
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
	corrupt, err := strconv.ParseBool(p["include-corrupt"])
	if err != nil {
		return err
	}
	env, err := poolScannerEnvironment(ctx, e, a)
	if err != nil {
		return err
	}
	if err := networkOwnerSchema(env); err != nil {
		return fmt.Errorf("network owner schema: %w", err)
	}
	v, err := networkVersion(ctx, env)
	if err != nil {
		return errors.Join(err, a.stop, a.failures.err("network version reads"))
	}
	selected, err := winnet.Select(v)
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
	if err := a.emit(evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("network_symbols"), "NetworkSymbols": evidence.Text(catalog.Name), "NetworkSymbolSHA256": evidence.Text(catalog.SHA256), "Raw": evidence.Bytes(catalog.Data), "Source": evidence.Text(catalog.URL), "Coverage": {Kind: "structure", Data: map[string]any{"version": v, "selection": selected}}}}); err != nil {
		return err
	}
	constraints, err := networkConstraints(catalog.Layout, selected)
	if err != nil {
		return err
	}
	var candidates, rejected, networks uint64
	err = scanPoolObjects(ctx, env, constraints, "network_objects", poolScannerRow, a.emit, func(ctx context.Context, hit poolHit) (evidence.Row, bool, error) {
		candidates++
		o := winnet.Object{Layout: catalog.Layout, Layer: hit.scan.Layer, Native: env.Kernel, Address: hit.object, Type: hit.typ}
		validity := "not_checked_include_corrupt"
		if !corrupt {
			valid, err := networkObjectValid(ctx, env, o)
			if err != nil {
				a.failures.add(err)
			}
			if !valid {
				rejected++
				row := poolScannerRow(hit.layer, hit.object)
				row.Cells["RecordType"], row.Cells["Type"], row.Cells["Validity"] = evidence.Text("network_candidate"), evidence.Text(hit.typ), evidence.Text("rejected")
				if err != nil {
					row.Cells["Error"] = evidence.Missing("network_validation_failed", err)
				}
				return row, true, nil
			}
			validity = "valid"
		}
		rows, err := networkRows(ctx, env, o, validity)
		if err != nil {
			a.failures.add(err)
		}
		for _, row := range rows {
			row.Cells["NetworkSymbols"], row.Cells["NetworkSymbolSHA256"] = evidence.Text(catalog.Name), evidence.Text(catalog.SHA256)
			row.Cells["PoolHeader"], row.Cells["Tag"] = evidence.Address(hit.header), evidence.Bytes(hit.tag)
			if err != nil {
				row.Cells["Error"] = evidence.Missing("network_fields_incomplete", err)
			}
			if err := a.emit(row); err != nil {
				return row, false, poolFatalError{err}
			}
			networks++
		}
		if len(rows) == 0 && err != nil {
			return evidence.Row{}, false, err
		}
		return evidence.Row{}, false, nil
	})
	cause := errors.Join(err, a.stop, a.failures.err("network captured reads"))
	if a.stop != nil || ctx.Err() != nil {
		return errors.Join(cause, ctx.Err())
	}
	summary := evidence.Row{Cells: map[string]evidence.Value{"RecordType": evidence.Text("task_summary"), "Coverage": {Kind: "structure", Data: map[string]evidence.Value{"Candidates": evidence.Number(candidates), "Rejected": evidence.Number(rejected), "Networks": evidence.Number(networks), "Reads": evidence.Number(a.reads), "RequestedBytes": evidence.Number(a.requested), "EvidenceRows": evidence.Number(a.rows), "ReadFailures": evidence.Number(uint64(a.failures.count)), "Completed": evidence.Bool(cause == nil)}}}}
	if cause != nil {
		summary.Cells["Error"] = evidence.Missing("network_scan_incomplete", cause)
	}
	return errors.Join(cause, a.emit(summary))
}
