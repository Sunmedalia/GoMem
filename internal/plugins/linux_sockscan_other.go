package plugins

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
)

func (s *linuxSocketScan) loadDevices() error {
	if s.devicesLoaded {
		return s.devicesErr
	}
	s.devicesLoaded = true
	s.devicesErr = s.buildDevices()
	return s.devicesErr
}
func (s *linuxSocketScan) buildDevices() error {
	init, err := s.e.Symbol("init_task")
	if err != nil {
		return err
	}
	task, err := s.view(s.native, init, "task_struct")
	if err != nil {
		return err
	}
	nsproxy, err := task.Dereference(s.ctx, "nsproxy")
	if err != nil {
		return err
	}
	net, err := nsproxy.Dereference(s.ctx, "net_ns")
	if err != nil {
		return err
	}
	inodePath, err := s.choose(net, "proc_inum", "ns.inum")
	if errors.Is(err, object.ErrFieldAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	inode, err := net.Uint(s.ctx, inodePath)
	if err != nil {
		return err
	}
	head, err := s.e.Symbol("net_namespace_list")
	if err != nil {
		return err
	}
	r := object.Reader{Layer: s.native, Symbols: s.e.Symbols}
	link, err := r.Field("net", "list")
	if err != nil {
		return err
	}
	deviceLink, err := r.Field("net_device", "dev_list")
	if err != nil {
		return err
	}
	return r.WalkList(s.ctx, head, link.Offset, s.maxNodes, func(at uint64) error {
		net, err := s.view(s.native, at, "net")
		if err != nil {
			return err
		}
		n, err := net.Uint(s.ctx, inodePath)
		if err != nil {
			return err
		}
		if n != inode {
			return nil
		}
		f, err := net.Field("dev_base_head")
		if err != nil {
			return err
		}
		head, err := memory.Add(at, f.Offset)
		if err != nil {
			return err
		}
		return r.WalkList(s.ctx, head, deviceLink.Offset, s.maxNodes, func(at uint64) error {
			v, err := s.view(s.native, at, "net_device")
			if err != nil {
				return err
			}
			index, err := v.Int(s.ctx, "ifindex")
			if err != nil {
				return err
			}
			name, err := s.text(v, "name", 4096)
			if err != nil {
				return err
			}
			s.devices[index] = name
			return nil
		})
	})
}
func (s *linuxSocketScan) packetEndpoints(v object.View, c map[string]evidence.Value) error {
	index, err := v.Int(s.ctx, "ifindex")
	if err != nil {
		return err
	}
	if index <= 0 {
		c["Source"] = evidence.Text("ANY")
	} else {
		if err = s.loadDevices(); err != nil {
			return err
		}
		if name, ok := s.devices[index]; ok {
			c["Source"] = evidence.Text(name)
		}
	}
	proto, err := v.Uint(s.ctx, "num")
	if err != nil {
		return err
	}
	if proto > 65535 {
		return fmt.Errorf("packet protocol exceeds uint16")
	}
	proto = (proto&255)<<8 | proto>>8
	if proto != 0 {
		label, ok := linuxEtherProtocols[proto]
		if !ok {
			label = fmt.Sprintf("0x%x", proto)
		}
		c["Proto"] = evidence.Text(label)
	}
	return nil
}
func (s *linuxSocketScan) vsockEndpoints(v object.View, c map[string]evidence.Value) error {
	for _, p := range []struct{ key, path string }{{"Source", "local_addr.svm_cid"}, {"SourcePort", "local_addr.svm_port"}, {"Destination", "remote_addr.svm_cid"}, {"DestinationPort", "remote_addr.svm_port"}} {
		value, err := v.Uint(s.ctx, p.path)
		if err != nil {
			return err
		}
		c[p.key] = evidence.Text(strconv.FormatUint(value, 10))
	}
	return nil
}
func (s *linuxSocketScan) bluetoothEndpoints(v object.View, proto, state uint64, c map[string]evidence.Value) error {
	if proto < uint64(len(linuxBluetoothProtocols)) {
		c["Proto"] = evidence.Text(linuxBluetoothProtocols[proto])
	}
	c["State"] = evidence.Missing("unknown_bluetooth_state", nil)
	if state < uint64(len(linuxBluetoothStates)) {
		c["State"] = evidence.Text(linuxBluetoothStates[state])
	}
	typ := ""
	switch proto {
	case 0:
		typ = "l2cap_pinfo"
	case 1:
		typ = "hci_pinfo"
	case 2:
		typ = "sco_pinfo"
	case 3:
		typ = "rfcomm_pinfo"
	default:
		return nil
	}
	if _, err := s.e.Symbols.Type(typ); err != nil {
		return nil
	}
	p, err := v.Cast(typ)
	if err != nil {
		return err
	}
	if proto == 1 {
		if !s.optional(p, "hdev") {
			return nil
		}
		device, err := p.Dereference(s.ctx, "hdev")
		if errors.Is(err, object.ErrNullPointer) {
			return nil
		}
		if err != nil {
			return err
		}
		if s.optional(device, "dev_name") {
			name, err := s.text(device, "dev_name", 4096)
			if err != nil {
				return err
			}
			c["Source"] = evidence.Text(name)
		}
		return nil
	}
	source, destination := "src.b", "dst.b"
	if proto == 0 {
		f, err := p.Field("chan")
		if err != nil {
			return err
		}
		if f.Type.Kind == "pointer" {
			p, err = p.Dereference(s.ctx, "chan")
			if err != nil {
				return err
			}
		} else {
			p, err = p.Embedded("chan")
			if err != nil {
				return err
			}
		}
	}
	for _, endpoint := range []struct{ key, path string }{{"Source", source}, {"Destination", destination}} {
		raw, err := p.Bytes(s.ctx, endpoint.path, 6)
		if err != nil {
			return err
		}
		parts := make([]string, 6)
		for i := range parts {
			parts[i] = fmt.Sprintf("%02x", raw[5-i])
		}
		c[endpoint.key] = evidence.Text(strings.Join(parts, ":"))
	}
	ports := []struct{ key, path string }{}
	if proto == 0 {
		ports = append(ports, struct{ key, path string }{"SourcePort", "sport"}, struct{ key, path string }{"DestinationPort", "psm"})
	} else if proto == 3 {
		ports = append(ports, struct{ key, path string }{"SourcePort", "channel"})
	}
	for _, port := range ports {
		value, err := p.Uint(s.ctx, port.path)
		if err != nil {
			return err
		}
		c[port.key] = evidence.Text(strconv.FormatUint(value, 10))
	}
	return nil
}
func (s *linuxSocketScan) xdpEndpoints(v object.View, c map[string]evidence.Value) error {
	device, err := v.Dereference(s.ctx, "dev")
	if err != nil {
		return err
	}
	name, err := s.text(device, "name", 4096)
	if err != nil {
		return err
	}
	c["Source"] = evidence.Text(name)
	prog, err := device.Dereference(s.ctx, "xdp_prog")
	if err != nil {
		return err
	}
	if !s.optional(prog, "aux") {
		return fmt.Errorf("XDP program has no aux layout")
	}
	aux, err := prog.Dereference(s.ctx, "aux")
	if err != nil {
		return err
	}
	if s.optional(aux, "id") {
		id, err := aux.Uint(s.ctx, "id")
		if err != nil {
			return err
		}
		c["DestinationPort"] = evidence.Text("ebpf_prog_id:" + strconv.FormatUint(id, 10))
	}
	if s.optional(aux, "name") {
		name, err := s.text(aux, "name", 4096)
		if err != nil {
			return err
		}
		if name != "" {
			c["Destination"] = evidence.Text("ebpf_prog_name:" + name)
		}
	}
	_, names, err := v.Enum(s.ctx, "state")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("unrecognized XDP state")
	}
	c["State"] = evidence.Text(strings.ReplaceAll(names[0], "XSK_", ""))
	return nil
}
func (s *linuxSocketScan) socketFilters(root object.View, c map[string]evidence.Value) error {
	info := map[string]string{}
	keys := []string{}
	put := func(key, value string) {
		if _, ok := info[key]; !ok {
			keys = append(keys, key)
		}
		info[key] = value
	}
	for _, candidate := range []struct{ field, kind string }{{"sk_filter", "socket_filter"}, {"sk_reuseport_cb", "reuseport_filter"}} {
		if !s.optional(root, candidate.field) {
			continue
		}
		filter, err := root.Dereference(s.ctx, candidate.field)
		if errors.Is(err, object.ErrNullPointer) {
			continue
		}
		if err != nil {
			return err
		}
		put("filter_type", candidate.kind)
		put("bpf_filter_type", "cBPF")
		if !s.optional(filter, "prog") {
			continue
		}
		prog, err := filter.Dereference(s.ctx, "prog")
		if errors.Is(err, object.ErrNullPointer) {
			continue
		}
		if err != nil {
			return err
		}
		typeObject := prog
		path := "type"
		var aux object.View
		haveAux := false
		if s.optional(prog, "aux") {
			aux, err = prog.Dereference(s.ctx, "aux")
			if err != nil && !errors.Is(err, object.ErrNullPointer) {
				return err
			}
			haveAux = err == nil
		}
		if !s.optional(prog, path) {
			if !haveAux || !s.optional(aux, "prog_type") {
				continue
			}
			typeObject, path = aux, "prog_type"
		}
		value, names, err := typeObject.Enum(s.ctx, path)
		if err != nil {
			return err
		}
		if value == 0 {
			continue
		}
		if value != 1 {
			label := strconv.FormatUint(value, 10)
			if len(names) > 0 {
				label = names[0]
			}
			put("bpf_filter_type", "UNK("+label+")")
			continue
		}
		put("bpf_filter_type", "eBPF")
		if !haveAux {
			continue
		}
		if s.optional(aux, "id") {
			id, err := aux.Uint(s.ctx, "id")
			if err != nil {
				return err
			}
			put("bpf_filter_id", strconv.FormatUint(id, 10))
		}
		if s.optional(aux, "name") {
			name, err := s.text(aux, "name", 4096)
			if err != nil {
				return err
			}
			if name != "" {
				put("bpf_filter_name", name)
			}
		}
	}
	if len(keys) > 0 {
		parts := []string{}
		for _, key := range keys {
			parts = append(parts, key+"="+info[key])
		}
		c["Filter"] = evidence.Text(strings.Join(parts, ","))
	}
	return nil
}
