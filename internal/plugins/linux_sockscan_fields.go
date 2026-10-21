package plugins

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

func socketScanLabel(raw uint64, labels []string, unknown string) string {
	if raw < uint64(len(labels)) {
		return labels[raw]
	}
	return unknown
}
func (s *linuxSocketScan) optional(v object.View, path string) bool {
	_, err := v.Field(path)
	if err != nil && !errors.Is(err, object.ErrFieldAbsent) {
		s.failures.add(err)
		r := s.row(v.Address(), "socket_layout_error")
		r.Provenance.Layer = v.Layer().Name()
		r.Cells["Error"] = evidence.Missing("socket_layout_invalid", err)
		_ = s.emit(r)
	}
	return err == nil
}
func (s *linuxSocketScan) choose(v object.View, paths ...string) (string, error) {
	for _, path := range paths {
		if _, err := v.Field(path); err == nil {
			return path, nil
		} else if !errors.Is(err, object.ErrFieldAbsent) {
			return "", err
		}
	}
	return "", fmt.Errorf("%w: %s paths %v", object.ErrFieldAbsent, v.Type(), paths)
}
func socketScanString(raw []byte) string {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	text := strings.ToValidUTF8(string(raw), "\ufffd")
	if i := strings.IndexRune(text, '\ufffd'); i >= 0 {
		text = text[:i]
	}
	return text
}
func (s *linuxSocketScan) text(v object.View, path string, maximum uint64) (string, error) {
	f, err := v.Field(path)
	if err != nil {
		return "", err
	}
	if f.Type.Kind != "array" || f.Type.Subtype == nil {
		return "", fmt.Errorf("%s.%s is not a character array", v.Type(), path)
	}
	r := object.Reader{Layer: v.Layer(), Symbols: s.e.Symbols}
	size, err := r.Size(f.Type)
	if err != nil || size > maximum {
		return "", fmt.Errorf("invalid socket string bound: %v", err)
	}
	element, err := r.Size(*f.Type.Subtype)
	if err != nil || element != 1 {
		return "", fmt.Errorf("socket string element is not one byte")
	}
	raw, err := v.Bytes(s.ctx, path, int(size))
	if err != nil {
		return "", err
	}
	return socketScanString(raw), nil
}
func (s *linuxSocketScan) genericState(root object.View) (evidence.Value, error) {
	socket, err := root.Dereference(s.ctx, "sk_socket")
	if errors.Is(err, object.ErrNullPointer) {
		return evidence.Value{}, err
	}
	if err != nil {
		return evidence.Value{}, err
	}
	state, err := socket.Uint(s.ctx, "state")
	if err != nil {
		return evidence.Value{}, err
	}
	return evidence.Text(socketScanLabel(state, linuxSocketStates, "Unknown socket state")), nil
}
func (s *linuxSocketScan) extract(root object.View, r *evidence.Row) error {
	cells := r.Cells
	for _, key := range []string{"Family", "Type", "Proto", "Source", "SourcePort", "Destination", "DestinationPort", "State", "Filter"} {
		cells[key] = evidence.Missing("not_available", nil)
	}
	family, err := root.Uint(s.ctx, "__sk_common.skc_family")
	if err != nil {
		return err
	}
	kind, err := root.Uint(s.ctx, "sk_type")
	if err != nil {
		return err
	}
	cells["FamilyRaw"], cells["TypeRaw"] = evidence.Number(family), evidence.Number(kind)
	cells["Family"] = evidence.Text(socketScanLabel(family, linuxSocketFamilies, "Unknown socket family"))
	cells["Type"] = evidence.Text(linuxSocketTypes[kind])
	cells["CandidateAssessment"] = evidence.Text("structural_fields_only")
	if family >= uint64(len(linuxSocketFamilies)) || linuxSocketTypes[kind] == "" {
		cells["CandidateAssessment"] = evidence.Text("unknown_family_or_type")
	}
	state, err := root.Uint(s.ctx, "__sk_common.skc_state")
	if err != nil {
		return err
	}
	cells["StateRaw"] = evidence.Number(state)
	typ := map[uint64]string{1: "unix_sock", 2: "inet_sock", 10: "inet_sock", 16: "netlink_sock", 17: "packet_sock", 40: "vsock_sock", 31: "bt_sock", 44: "xdp_sock"}[family]
	subtype := root
	if typ != "" {
		if _, er := s.e.Symbols.Type(typ); er == nil {
			subtype, err = root.Cast(typ)
			if err != nil {
				return err
			}
		} else {
			typ = ""
			cells["CandidateAssessment"] = evidence.Text("family_layout_unavailable")
		}
	}
	r.Cells["FieldEvidence"].Data.(map[string]evidence.Value)["DecodedType"] = evidence.Text(subtype.Type())
	if (family == 1 || family == 2 || family == 10) && typ != "" && kind == 1 {
		cells["State"] = evidence.Text(socketScanLabel(state, linuxTCPStates, "Unknown "+typ+" stream state"))
	} else {
		cells["State"], err = s.genericState(root)
		if err != nil {
			return err
		}
	}
	if typ != "" {
		protocol, er := root.Uint(s.ctx, "sk_protocol")
		if er != nil {
			return er
		}
		cells["ProtocolRaw"] = evidence.Number(protocol)
		switch family {
		case 1:
			err = s.unixEndpoints(subtype, cells)
		case 2, 10:
			err = s.inetEndpoints(subtype, family, protocol, cells)
		case 16:
			err = s.netlinkEndpoints(subtype, protocol, cells)
		case 17:
			err = s.packetEndpoints(subtype, cells)
		case 40:
			err = s.vsockEndpoints(subtype, cells)
		case 31:
			err = s.bluetoothEndpoints(subtype, protocol, state, cells)
		case 44:
			err = s.xdpEndpoints(subtype, cells)
		}
		if err != nil {
			return err
		}
		if err = s.socketFilters(root, cells); err != nil {
			return err
		}
	}
	// Preserve the fixed baseline's source-availability check in both halves.
	src, dst := cells["Source"], cells["Destination"]
	if (src.Kind == "missing" || src.String() == "0.0.0.0") && (src.Kind == "missing" || dst.String() == "0.0.0.0") && (cells["State"].String() == "UNCONNECTED" || cells["SourcePort"].String() == "0" && cells["DestinationPort"].String() == "0") {
		cells["RecordType"] = evidence.Text("socket_candidate")
		cells["CandidateAssessment"] = evidence.Text("baseline_empty_endpoint_filter")
		return nil
	}
	cells["RecordType"] = evidence.Text("socket")
	return nil
}
func (s *linuxSocketScan) unixName(root object.View) (evidence.Value, error) {
	address, err := root.Dereference(s.ctx, "addr")
	if errors.Is(err, object.ErrNullPointer) {
		return evidence.Missing("not_bound", nil), nil
	}
	if err != nil {
		return evidence.Value{}, err
	}
	name, err := address.Field("name")
	if err != nil {
		return evidence.Value{}, err
	}
	at, err := memory.Add(address.Address(), name.Offset)
	if err != nil {
		return evidence.Value{}, err
	}
	v, err := s.view(address.Layer(), at, "sockaddr_un")
	if err != nil {
		return evidence.Value{}, err
	}
	text, err := s.text(v, "sun_path", 4096)
	return evidence.Text(text), err
}
func (s *linuxSocketScan) inode(root object.View) (string, error) {
	socket, err := root.Dereference(s.ctx, "sk_socket")
	if errors.Is(err, object.ErrNullPointer) {
		return "0", nil
	}
	if err != nil {
		return "", err
	}
	allocation, err := socket.Container("socket_alloc", "socket")
	if err != nil {
		return "", err
	}
	value, err := allocation.Uint(s.ctx, "vfs_inode.i_ino")
	return strconv.FormatUint(value, 10), err
}
func (s *linuxSocketScan) unixEndpoints(v object.View, c map[string]evidence.Value) error {
	name, err := s.unixName(v)
	if err != nil {
		return err
	}
	c["Source"] = name
	sk, err := v.Embedded("sk")
	if err != nil {
		return err
	}
	ino, err := s.inode(sk)
	if err != nil {
		return err
	}
	c["SourcePort"] = evidence.Text(ino)
	peer, err := v.Dereference(s.ctx, "peer")
	if errors.Is(err, object.ErrNullPointer) {
		return nil
	}
	if err != nil {
		return err
	}
	peer, err = peer.Cast("unix_sock")
	if err != nil {
		return err
	}
	name, err = s.unixName(peer)
	if err != nil {
		return err
	}
	c["Destination"] = name
	sk, err = peer.Embedded("sk")
	if err != nil {
		return err
	}
	ino, err = s.inode(sk)
	if err != nil {
		return err
	}
	c["DestinationPort"] = evidence.Text(ino)
	return nil
}
func (s *linuxSocketScan) inetEndpoints(v object.View, family, proto uint64, c map[string]evidence.Value) error {
	label, known := linuxIPProtocols[proto]
	if family == 10 {
		if p, ok := linuxIPv6Protocols[proto]; ok {
			label, known = p, true
		}
	}
	if known {
		c["Proto"] = evidence.Text(label)
	}
	for _, p := range []struct {
		key   string
		paths []string
	}{{"SourcePort", []string{"sport", "inet_sport"}}, {"DestinationPort", []string{"sk.__sk_common.skc_portpair", "dport", "inet_dport", "sk.__sk_common.skc_dport"}}} {
		path, err := s.choose(v, p.paths...)
		if errors.Is(err, object.ErrFieldAbsent) {
			continue
		}
		if err != nil {
			return err
		}
		raw, err := v.Bytes(s.ctx, path, 2)
		if err != nil {
			return err
		}
		c[p.key] = evidence.Text(strconv.FormatUint(uint64(binary.BigEndian.Uint16(raw)), 10))
	}
	for _, key := range []string{"Source", "Destination"} {
		data := v
		fromPointer := false
		path := ""
		size := 4
		if family == 2 {
			paths := []string{"rcv_saddr", "inet_rcv_saddr", "sk.__sk_common.skc_rcv_saddr"}
			if key == "Destination" {
				paths = []string{"daddr", "inet_daddr", "sk.__sk_common.skc_daddr"}
			}
			for _, p := range paths {
				if s.optional(v, p) {
					if key == "Destination" && p != "sk.__sk_common.skc_daddr" {
						value, err := v.Uint(s.ctx, p)
						if err != nil {
							return err
						}
						if value == 0 {
							continue
						}
					}
					path = p
					break
				}
			}
			if path == "" {
				continue
			}
		} else {
			size = 16
			common := "sk.__sk_common.skc_v6_rcv_saddr"
			path = "saddr"
			if key == "Destination" {
				common = "sk.__sk_common.skc_v6_daddr"
				path = "daddr"
			}
			if s.optional(v, "pinet6") {
				info, err := v.Dereference(s.ctx, "pinet6")
				if err != nil {
					return err
				}
				if s.optional(info, path) {
					data = info
					fromPointer = true
				} else {
					path = common
				}
			} else {
				path = common
			}
			// A pointer-derived address belongs to the native layer. Pinned
			// get_src_addr/get_dst_addr instead read it in the physical root
			// layer; retain this intentional difference with acquisition proof.
		}
		var raw []byte
		var err error
		if fromPointer && s.baselineIPv6 {
			field, er := data.Field(path)
			if er != nil {
				return er
			}
			at, er := memory.Add(data.Address(), field.Offset)
			if er != nil {
				return er
			}
			raw, err = memory.Read(s.ctx, s.physical, at, size)
			if err != nil {
				if s.outputErr != nil || s.ctx.Err() != nil || errors.Is(err, errSocketReadBudget) {
					return err
				}
				c[key] = evidence.Missing("baseline_ipv6_address_unreadable", err)
				continue
			}
		} else {
			raw, err = data.Bytes(s.ctx, path, size)
		}
		if err != nil {
			return err
		}
		var address netip.Addr
		if size == 4 {
			address = netip.AddrFrom4([4]byte(raw))
		} else {
			address = netip.AddrFrom16([16]byte(raw))
		}
		c[key] = evidence.Text(address.String())
	}
	return nil
}
func (s *linuxSocketScan) netlinkEndpoints(v object.View, proto uint64, c map[string]evidence.Value) error {
	c["Proto"] = evidence.Text(socketScanLabel(proto, linuxNetlinkProtocols, "Unknown netlink_sock protocol"))
	if at, err := v.Uint(s.ctx, "groups"); err != nil {
		return err
	} else if at != 0 {
		f, err := v.Field("groups")
		if err != nil {
			return err
		}
		if f.Type.Kind != "pointer" || f.Type.Subtype == nil {
			return fmt.Errorf("netlink groups lacks a pointer target")
		}
		r := object.Reader{Layer: s.native, Symbols: s.e.Symbols}
		value, err := r.Scalar(s.ctx, at, *f.Type.Subtype)
		if err != nil {
			return err
		}
		c["Source"] = evidence.Text(fmt.Sprintf("groups:0x%08x", value))
	}
	group, err := v.Uint(s.ctx, "dst_group")
	if err != nil {
		return err
	}
	destination := fmt.Sprintf("group:0x%08x", group)
	module, err := v.Dereference(s.ctx, "module")
	if err != nil && !errors.Is(err, object.ErrNullPointer) {
		return err
	}
	if err == nil {
		name, er := s.text(module, "name", 4096)
		if er != nil {
			return er
		}
		if name != "" {
			destination += ",lkm:" + name
		}
	}
	c["Destination"] = evidence.Text(destination)
	for _, p := range []struct {
		key   string
		paths []string
	}{{"SourcePort", []string{"pid", "portid"}}, {"DestinationPort", []string{"dst_pid", "dst_portid"}}} {
		path, err := s.choose(v, p.paths...)
		if errors.Is(err, object.ErrFieldAbsent) {
			continue
		}
		if err != nil {
			return err
		}
		value, err := v.Uint(s.ctx, path)
		if err != nil {
			return err
		}
		c[p.key] = evidence.Text(strconv.FormatUint(value, 10))
	}
	return nil
}
