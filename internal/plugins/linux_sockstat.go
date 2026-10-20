package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxSocketPlugins() []builtin {
	parameters := []plugin.Parameter{{Name: "pid", Kind: "string", Description: "Task-list PID set; expands selected groups' threads"}, {Name: "netns", Kind: "string", Description: "Task network namespace inode filter; empty or zero selects all"}, {Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Task, group and interface traversal bound"}, {Name: "max-tasks", Kind: "uint", Default: "1000000", Description: "Total task/thread bound"}, {Name: "max-fds", Kind: "uint", Default: "500000", Description: "Per-task descriptor slot bound"}, {Name: "max-slots", Kind: "uint", Default: "10000000", Description: "Total descriptor slot bound"}}
	columns := []evidence.Column{}
	for _, pair := range [][2]string{{"PID", "uint64"}, {"Process", "string"}, {"FD", "uint64"}, {"Family", "string"}, {"TID", "uint64"}, {"NetNS", "uint64"}, {"Type", "string"}, {"Proto", "string"}, {"Source", "string"}, {"SourcePort", "string"}, {"Destination", "string"}, {"DestinationPort", "string"}, {"State", "string"}, {"Filter", "string"}, {"Offset", "address"}, {"FileOffset", "address"}, {"Dentry", "address"}, {"InodeOffset", "address"}, {"Socket", "address"}, {"Peer", "address"}, {"Inode", "uint64"}, {"FamilyRaw", "uint64"}, {"TypeRaw", "uint64"}, {"ProtocolRaw", "uint64"}, {"StateRaw", "uint64"}, {"SocketStateRaw", "uint64"}, {"SourceRaw", "bytes"}, {"DestinationRaw", "bytes"}, {"SourcePortRaw", "bytes"}, {"DestinationPortRaw", "bytes"}, {"SourceEncoding", "string"}, {"DestinationEncoding", "string"}, {"EndpointKind", "string"}, {"TaskNet", "address"}, {"SocketNet", "address"}, {"TaskOffset", "address"}, {"ProcessOffset", "address"}, {"ProcessIdentity", "string"}, {"TaskIdentity", "string"}, {"Files", "address"}, {"FDTable", "address"}, {"Slot", "address"}, {"SkippedSlots", "uint64"}, {"Filters", "structure"}, {"ReadProof", "structure"}, {"RecordType", "string"}, {"Error", "string"}} {
		columns = append(columns, evidence.Column{Name: pair[0], Kind: pair[1]})
	}
	for _, name := range []string{"SocketBacklink", "NSProxy", "SourceIPv6Info", "DestinationIPv6Info", "SourceUnixAddress", "DestinationUnixAddress", "SourcePortSocket", "DestinationPortSocket", "NetlinkGroups", "NetlinkModule", "DeviceNamespace", "HCIDevice", "BluetoothChannel", "XDPDevice", "XDPProgram", "XDPProgramAux"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "address"})
	}
	for _, name := range []string{"SourceUnixLength", "DestinationUnixLength", "SourcePortInode", "DestinationPortInode", "DestinationGroupRaw", "SourcePortValue", "DestinationPortValue", "SourceValue", "DestinationValue", "EtherProtocolRaw", "XDPStateRaw", "XDPProgramID"} {
		columns = append(columns, evidence.Column{Name: name, Kind: "uint64"})
	}
	columns = append(columns, evidence.Column{Name: "InterfaceIndex", Kind: "int64"})
	for _, prefix := range []string{"sk_filter", "sk_reuseport_cb"} {
		for _, suffix := range []string{"Pointer", "Program", "ProgramAux"} {
			columns = append(columns, evidence.Column{Name: prefix + suffix, Kind: "address"})
		}
		columns = append(columns, evidence.Column{Name: prefix + "HeaderRaw", Kind: "bytes"}, evidence.Column{Name: prefix + "ProgramNameRaw", Kind: "bytes"})
		for _, suffix := range []string{"ProgramType", "ProgramID"} {
			columns = append(columns, evidence.Column{Name: prefix + suffix, Kind: "uint64"})
		}
	}
	return []builtin{{plugin.Spec{Name: "linux.sockstat", Upstream: "linux.sockstat.Sockstat", Platform: "linux", NeedsKernel: true, Description: "Enumerate descriptor-backed Linux sockets with typed endpoints, namespace provenance and raw bytes", Parameters: parameters, Columns: columns}, linuxSockstat}}
}

type linuxNetReader struct {
	ctx      context.Context
	e        plugin.Environment
	cells    map[string]evidence.Value
	failures pluginFailures
	proof    map[string]any
	maxNodes int
}

func (n *linuxNetReader) fail(key, reason string, err error) {
	n.cells[key] = evidence.Missing(reason, err)
	n.failures.add(err)
}
func (n *linuxNetReader) uint(key string, address uint64, typ, path string) (uint64, bool) {
	v, err := n.e.Objects.Uint(n.ctx, address, typ, path)
	if err != nil {
		n.fail(key, "socket_field_unreadable", err)
		return 0, false
	}
	n.cells[key] = evidence.Number(v)
	return v, true
}
func (n *linuxNetReader) pointer(key string, address uint64, typ, path string) (uint64, bool) {
	v, ok := n.uint(key, address, typ, path)
	if ok {
		n.cells[key] = evidence.Address(v)
	}
	return v, ok
}
func (n *linuxNetReader) choose(typ string, paths ...string) (string, error) {
	for _, path := range paths {
		if _, err := n.e.Objects.Field(typ, path); err == nil {
			return path, nil
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return "", err
		}
	}
	return "", fmt.Errorf("%w: no supported %s fields: %v", object.ErrFieldAbsent, typ, paths)
}
func (n *linuxNetReader) raw(key string, address uint64, size int) ([]byte, error) {
	if size < 0 || size > 4096 || size > 0 && uint64(size)-1 > ^uint64(0)-address {
		return nil, fmt.Errorf("invalid socket field read range")
	}
	b := make([]byte, size)
	got, err := n.e.Kernel.ReadAt(n.ctx, b, address)
	if got < 0 || got > len(b) {
		return nil, fmt.Errorf("invalid socket source read length")
	}
	n.cells[key] = evidence.Bytes(b[:got])
	if got < len(b) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	n.proof[key] = map[string]any{"address": fmt.Sprintf("0x%x", address), "length": strconv.Itoa(size), "captured": strconv.Itoa(got), "complete": got == len(b) && err == nil}
	if err != nil {
		if proof, ok := n.proof[key].(map[string]any); ok {
			proof["error"] = err.Error()
		}
	}
	return b[:got], err
}
func (n *linuxNetReader) fieldBytes(key string, base uint64, typ, path string, size int) ([]byte, error) {
	field, err := n.e.Objects.Field(typ, path)
	if err != nil {
		return nil, err
	}
	length, err := n.e.Objects.Size(field.Type)
	if err != nil || uint64(size) > length {
		return nil, fmt.Errorf("socket field %s.%s is smaller than %d bytes", typ, path, size)
	}
	address, err := memory.Add(base, field.Offset)
	if err != nil {
		return nil, err
	}
	data, err := n.raw(key, address, size)
	if proof, ok := n.proof[key].(map[string]any); ok {
		proof["type"], proof["field"] = typ, path
	}
	return data, err
}
func (n *linuxNetReader) container(address uint64, typ string) (uint64, error) {
	path, err := n.choose(typ, "sk", "bt.sk")
	if err != nil {
		return 0, err
	}
	field, err := n.e.Objects.Field(typ, path)
	if err != nil {
		return 0, err
	}
	if field.Type.Kind != "struct" || field.Type.Name != "sock" || address < field.Offset {
		return 0, fmt.Errorf("invalid %s sock container", typ)
	}
	return address - field.Offset, nil
}
func linuxNetLabel(value uint64, labels []string, reason string) evidence.Value {
	if value >= uint64(len(labels)) {
		return evidence.Missing(reason, nil)
	}
	return evidence.Text(labels[value])
}

func linuxSockstat(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit) error {
	maxNodes, _, validationErr := limits(p)
	if validationErr != nil {
		return validationErr
	}
	filter := uint64(0)
	var err error
	if p["netns"] != "" {
		filter, err = strconv.ParseUint(p["netns"], 0, 64)
		if err != nil {
			return fmt.Errorf("netns: %w", err)
		}
	}
	targets := map[uint64]bool{}
	for _, name := range []string{"socket_file_ops", "sockfs_dentry_operations"} {
		if address, err := e.Symbol(name); err == nil && address != 0 {
			targets[address] = true
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("socket operation symbols are unavailable")
	}
	inodeMember, err := e.Objects.Field("socket_alloc", "vfs_inode")
	if err != nil {
		return err
	}
	socketMember, err := e.Objects.Field("socket_alloc", "socket")
	if err != nil {
		return err
	}
	var failures pluginFailures
	var outputErr error
	columns := linuxSocketPlugins()[0].spec.Columns
	emit := func(row evidence.Row) error { outputErr = out(row); return outputErr }
	err = visitLinuxDescriptors(ctx, e, p, func(fd evidence.Row) error {
		row := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: fd.Provenance}
		for _, column := range columns {
			row.Cells[column.Name] = evidence.Missing("not_applicable", nil)
		}
		for _, key := range []string{"PID", "TID", "Process", "FD", "TaskOffset", "ProcessOffset", "ProcessIdentity", "TaskIdentity", "Files", "FDTable", "Slot", "SkippedSlots"} {
			row.Cells[key] = fd.Cells[key]
		}
		row.Cells["RecordType"], row.Cells["Error"] = evidence.Text("socket"), evidence.Missing("not_applicable", nil)
		if fd.Cells["RecordType"].String() != "file" {
			row.Cells["RecordType"], row.Cells["Error"] = fd.Cells["RecordType"], fd.Cells["Error"]
			return emit(row)
		}
		file, _ := fd.Cells["Offset"].Uint()
		task, _ := fd.Cells["TaskOffset"].Uint()
		row.Cells["FileOffset"] = evidence.Address(file)
		n := linuxNetReader{ctx: ctx, e: e, cells: row.Cells, proof: map[string]any{}, maxNodes: maxNodes}
		finish := func() error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if er := n.failures.err("socket decoding"); er != nil {
				row.Cells["Error"] = evidence.Missing("socket_decoding_incomplete", er)
				failures.add(er)
			}
			row.Cells["ReadProof"] = evidence.Value{Kind: "structure", Data: n.proof}
			return emit(row)
		}
		operation, er := e.Objects.Uint(ctx, file, "file", "f_op")
		if er != nil {
			row.Cells["RecordType"] = evidence.Text("diagnostic")
			n.fail("Error", "file_classification_unreadable", er)
			return finish()
		}
		if !targets[operation] {
			return nil
		}
		dentry, er := linuxMember(ctx, e, file, "file", "f_path.dentry", "f_dentry")
		if er != nil {
			n.fail("Dentry", "socket_dentry_unreadable", er)
			return finish()
		}
		row.Cells["Dentry"] = evidence.Address(dentry)
		if dentry == 0 {
			n.fail("Dentry", "socket_dentry_null", fmt.Errorf("socket file has no dentry"))
			return finish()
		}
		inode, ok := n.pointer("InodeOffset", dentry, "dentry", "d_inode")
		if !ok {
			return finish()
		}
		if inode == 0 || inode < inodeMember.Offset {
			n.fail("InodeOffset", "socket_container_invalid", fmt.Errorf("socket inode container underflow"))
			return finish()
		}
		socket, er := memory.Add(inode-inodeMember.Offset, socketMember.Offset)
		if er != nil {
			n.fail("Socket", "socket_container_invalid", er)
			return finish()
		}
		row.Cells["Socket"] = evidence.Address(socket)
		sock, ok := n.pointer("Offset", socket, "socket", "sk")
		if !ok {
			return finish()
		}
		if sock == 0 {
			n.fail("Offset", "socket_sk_null", fmt.Errorf("socket sk pointer is null"))
			return finish()
		}
		row.Provenance.Offset = fmt.Sprintf("0x%x", sock)
		if back, ok := n.pointer("SocketBacklink", sock, "sock", "sk_socket"); ok && back != socket {
			n.fail("SocketBacklink", "socket_owner_mismatch", fmt.Errorf("sock.sk_socket %#x differs from inode socket %#x", back, socket))
			return finish()
		}
		n.uint("Inode", inode, "inode", "i_ino")
		linuxTaskNetworkNamespace(&n, task)
		if filter != 0 {
			ns, er := row.Cells["NetNS"].Uint()
			if er != nil {
				row.Cells["RecordType"] = evidence.Text("diagnostic")
				n.fail("NetNS", "namespace_filter_unavailable", er)
				return finish()
			}
			if ns != filter {
				return nil
			}
		}
		if field, er := e.Objects.Field("sock", "__sk_common.skc_net"); er == nil {
			path := "__sk_common.skc_net"
			if field.Type.Kind == "struct" {
				path += ".net"
			}
			n.pointer("SocketNet", sock, "sock", path)
		}
		family, fok := n.uint("FamilyRaw", sock, "sock", "__sk_common.skc_family")
		kind, kok := n.uint("TypeRaw", sock, "sock", "sk_type")
		if fok {
			row.Cells["Family"] = linuxNetLabel(family, linuxSocketFamilies, "unknown_socket_family")
		}
		if kok {
			if text, ok := linuxSocketTypes[kind]; ok {
				row.Cells["Type"] = evidence.Text(text)
			} else {
				row.Cells["Type"] = evidence.Missing("unknown_socket_type", nil)
			}
		}
		n.uint("ProtocolRaw", sock, "sock", "sk_protocol")
		n.uint("StateRaw", sock, "sock", "__sk_common.skc_state")
		if value, ok := n.uint("SocketStateRaw", socket, "socket", "state"); ok {
			row.Cells["State"] = linuxNetLabel(value, linuxSocketStates, "unknown_socket_state")
		}
		if !fok || !kok {
			return finish()
		}
		switch family {
		case 1:
			linuxUnixEndpoints(&n, sock, kind)
		case 2, 10:
			linuxInetEndpoints(&n, sock, family, kind)
		case 16:
			linuxNetlinkEndpoints(&n, sock)
		case 17:
			linuxPacketEndpoints(&n, sock)
		case 40:
			linuxVsockEndpoints(&n, sock)
		case 31:
			linuxBluetoothEndpoints(&n, sock)
		case 44:
			linuxXDPEndpoints(&n, sock)
		default:
			n.fail("EndpointKind", "unsupported_socket_family", fmt.Errorf("socket family %d has no native endpoint handler", family))
		}
		linuxSocketFilters(&n, sock)
		return finish()
	})
	if outputErr != nil {
		return outputErr
	}
	return errors.Join(err, failures.err("Linux socket enumeration"))
}

func linuxTaskNetworkNamespace(n *linuxNetReader, task uint64) {
	nsproxy, ok := n.pointer("NSProxy", task, "task_struct", "nsproxy")
	if !ok {
		return
	}
	if nsproxy == 0 {
		n.fail("TaskNet", "namespace_proxy_null", fmt.Errorf("task nsproxy pointer is null"))
		return
	}
	net, ok := n.pointer("TaskNet", nsproxy, "nsproxy", "net_ns")
	if !ok {
		return
	}
	if net == 0 {
		n.fail("TaskNet", "network_namespace_null", fmt.Errorf("task network namespace pointer is null"))
		return
	}
	path, err := n.choose("net", "proc_inum", "ns.inum")
	if err != nil {
		if errors.Is(err, object.ErrFieldAbsent) {
			n.cells["NetNS"] = evidence.Missing("namespace_inode_not_in_layout", nil)
		} else {
			n.fail("NetNS", "namespace_inode_unreadable", err)
		}
		return
	}
	n.uint("NetNS", net, "net", path)
}

// Helpers use these explicit absent values rather than interpreting zero as a
// missing endpoint. A zero address/port can be a captured unbound INET endpoint.
func (n *linuxNetReader) streamState(kind uint64) {
	if kind == 1 {
		if state, err := n.cells["StateRaw"].Uint(); err == nil {
			n.cells["State"] = linuxNetLabel(state, linuxTCPStates, "unknown_stream_state")
		}
	}
}
func (n *linuxNetReader) optional(typ, path string) bool {
	_, err := n.e.Objects.Field(typ, path)
	return err == nil
}
