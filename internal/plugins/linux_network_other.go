package plugins

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func linuxVsockEndpoints(n *linuxNetReader, sock uint64) {
	n.cells["EndpointKind"] = evidence.Text("vsock_cid_port")
	base, err := n.container(sock, "vsock_sock")
	if err != nil {
		n.fail("Source", "vsock_layout_unavailable", err)
		return
	}
	for _, field := range []struct{ key, path string }{{"Source", "local_addr.svm_cid"}, {"SourcePort", "local_addr.svm_port"}, {"Destination", "remote_addr.svm_cid"}, {"DestinationPort", "remote_addr.svm_port"}} {
		if v, ok := n.uint(field.key+"Value", base, "vsock_sock", field.path); ok {
			n.cells[field.key] = evidence.Text(strconv.FormatUint(v, 10))
		}
	}
}
func linuxDeviceName(n *linuxNetReader, index int64) (evidence.Value, error) {
	if index <= 0 {
		return evidence.Text("ANY"), nil
	}
	net, err := n.cells["SocketNet"].Uint()
	if err != nil || net == 0 {
		net, err = n.cells["TaskNet"].Uint()
	}
	n.cells["DeviceNamespace"] = evidence.Address(net)
	if err != nil {
		return evidence.Missing("namespace_unavailable", err), err
	}
	head, err := n.e.Objects.Field("net", "dev_base_head")
	if err != nil {
		return evidence.Missing("interface_layout_unavailable", err), err
	}
	at, err := memory.Add(net, head.Offset)
	if err != nil {
		return evidence.Missing("interface_layout_unavailable", err), err
	}
	link, err := n.e.Objects.Field("net_device", "dev_list")
	if err != nil {
		return evidence.Missing("interface_layout_unavailable", err), err
	}
	name := evidence.Missing("interface_not_found", nil)
	err = n.e.Objects.WalkList(n.ctx, at, link.Offset, n.maxNodes, func(device uint64) error {
		id, err := n.e.Objects.Int(n.ctx, device, "net_device", "ifindex")
		if err != nil {
			return err
		}
		if id == index {
			value, err := n.e.Objects.String(n.ctx, device, "net_device", "name", 256)
			if err != nil {
				return err
			}
			name = evidence.Text(value)
		}
		return nil
	})
	if err != nil {
		name = evidence.Missing("interface_list_incomplete", err)
	}
	return name, err
}
func linuxPacketEndpoints(n *linuxNetReader, sock uint64) {
	n.cells["EndpointKind"] = evidence.Text("packet_interface")
	base, err := n.container(sock, "packet_sock")
	if err != nil {
		n.fail("Source", "packet_layout_unavailable", err)
		return
	}
	index, err := n.e.Objects.Int(n.ctx, base, "packet_sock", "ifindex")
	if err != nil {
		n.fail("Source", "interface_index_unreadable", err)
	} else {
		n.cells["InterfaceIndex"] = evidence.Integer(index)
		value, err := linuxDeviceName(n, index)
		n.cells["Source"] = value
		n.failures.add(err)
	}
	if raw, ok := n.uint("EtherProtocolRaw", base, "packet_sock", "num"); ok {
		if raw > 0xffff {
			n.fail("Proto", "invalid_ether_protocol", fmt.Errorf("packet num exceeds uint16"))
			return
		}
		value := ((raw & 255) << 8) | (raw >> 8)
		if value != 0 {
			label, ok := linuxEtherProtocols[value]
			if !ok {
				label = fmt.Sprintf("0x%x", value)
			}
			n.cells["Proto"] = evidence.Text(label)
		}
	}
}
func linuxBluetoothEndpoints(n *linuxNetReader, sock uint64) {
	n.cells["EndpointKind"] = evidence.Text("bluetooth_address_channel")
	base, err := n.container(sock, "bt_sock")
	if err != nil {
		n.fail("Source", "bluetooth_layout_unavailable", err)
		return
	}
	protocol, err := n.cells["ProtocolRaw"].Uint()
	if err != nil {
		return
	}
	n.cells["Proto"] = linuxNetLabel(protocol, linuxBluetoothProtocols, "unknown_bluetooth_protocol")
	if state, err := n.cells["StateRaw"].Uint(); err == nil {
		n.cells["State"] = linuxNetLabel(state, linuxBluetoothStates, "unknown_bluetooth_state")
	}
	typ := ""
	source, destination := "src.b", "dst.b"
	switch protocol {
	case 0:
		typ, source, destination = "l2cap_pinfo", "chan.src.b", "chan.dst.b"
	case 1:
		typ = "hci_pinfo"
		hci, er := n.container(sock, typ)
		if er != nil {
			n.fail("Source", "hci_layout_unavailable", er)
			return
		}
		dev, ok := n.pointer("HCIDevice", hci, typ, "hdev")
		if !ok {
			return
		}
		if dev == 0 {
			return
		}
		name, er := n.e.Objects.String(n.ctx, dev, "hci_dev", "dev_name", 256)
		if er != nil {
			n.fail("Source", "hci_device_unreadable", er)
		} else {
			n.cells["Source"] = evidence.Text(name)
		}
		return
	case 2:
		typ = "sco_pinfo"
	case 3:
		typ = "rfcomm_pinfo"
	default:
		n.fail("Source", "bluetooth_protocol_unsupported", fmt.Errorf("Bluetooth protocol %d has no endpoint layout", protocol))
		return
	}
	base, err = n.container(sock, typ)
	if err != nil {
		n.fail("Source", "bluetooth_endpoint_layout_unavailable", err)
		return
	}
	if protocol == 0 {
		field, er := n.e.Objects.Field(typ, "chan")
		if er != nil {
			n.fail("Source", "l2cap_channel_layout_unavailable", er)
			return
		}
		if field.Type.Kind == "pointer" {
			channel, ok := n.pointer("BluetoothChannel", base, typ, "chan")
			if !ok {
				return
			}
			if channel == 0 {
				n.fail("Source", "l2cap_channel_null", fmt.Errorf("L2CAP channel pointer is null"))
				return
			}
			if field.Type.Subtype == nil || field.Type.Subtype.Name == "" {
				n.fail("Source", "l2cap_channel_layout_unavailable", fmt.Errorf("channel pointer has no declared pointee"))
				return
			}
			typ, base, source, destination = field.Type.Subtype.Name, channel, "src.b", "dst.b"
		}
	}
	for _, endpoint := range []struct{ key, path string }{{"Source", source}, {"Destination", destination}} {
		raw, err := n.fieldBytes(endpoint.key+"Raw", base, typ, endpoint.path, 6)
		if err != nil {
			n.fail(endpoint.key, "bluetooth_address_unreadable", err)
			continue
		}
		pieces := make([]string, 6)
		for i := range pieces {
			pieces[i] = fmt.Sprintf("%02x", raw[5-i])
		}
		n.cells[endpoint.key] = evidence.Text(strings.Join(pieces, ":"))
		n.cells[endpoint.key+"Encoding"] = evidence.Text("bluetooth-little-endian")
	}
	ports := map[string]string{}
	if protocol == 0 {
		prefix := "chan."
		if source == "src.b" {
			prefix = ""
		}
		ports = map[string]string{"SourcePort": prefix + "sport", "DestinationPort": prefix + "psm"}
	} else if protocol == 3 {
		ports = map[string]string{"SourcePort": "channel"}
	}
	for key, path := range ports {
		if value, ok := n.uint(key+"Value", base, typ, path); ok {
			n.cells[key] = evidence.Text(strconv.FormatUint(value, 10))
		}
	}
}
func linuxXDPEndpoints(n *linuxNetReader, sock uint64) {
	n.cells["EndpointKind"] = evidence.Text("xdp_device_program")
	base, err := n.container(sock, "xdp_sock")
	if err != nil {
		n.fail("Source", "xdp_layout_unavailable", err)
		return
	}
	device, ok := n.pointer("XDPDevice", base, "xdp_sock", "dev")
	if !ok {
		return
	}
	if device == 0 {
		n.fail("Source", "xdp_device_null", fmt.Errorf("XDP device pointer is null"))
		return
	}
	name, err := n.e.Objects.String(n.ctx, device, "net_device", "name", 256)
	if err != nil {
		n.fail("Source", "xdp_device_unreadable", err)
	} else {
		n.cells["Source"] = evidence.Text(name)
	}
	value, labels, err := n.e.Objects.Enum(n.ctx, base, "xdp_sock", "state")
	if err != nil {
		n.fail("State", "xdp_state_unreadable", err)
	} else {
		n.cells["XDPStateRaw"] = evidence.Number(value)
		if len(labels) > 0 {
			n.cells["State"] = evidence.Text(strings.TrimPrefix(labels[0], "XSK_"))
		} else {
			n.cells["State"] = evidence.Missing("unknown_xdp_state", nil)
		}
	}
	// Device xdp_prog is a legacy single-program layout; do not guess modern
	// bpf_prog_array contents when the field is not declared.
	program, ok := n.pointer("XDPProgram", device, "net_device", "xdp_prog")
	if !ok || program == 0 {
		return
	}
	aux, ok := n.pointer("XDPProgramAux", program, "bpf_prog", "aux")
	if !ok || aux == 0 {
		return
	}
	if n.optional("bpf_prog_aux", "id") {
		if id, ok := n.uint("XDPProgramID", aux, "bpf_prog_aux", "id"); ok {
			n.cells["DestinationPort"] = evidence.Text("ebpf_prog_id:" + strconv.FormatUint(id, 10))
		}
	}
	if n.optional("bpf_prog_aux", "name") {
		name, err := n.e.Objects.String(n.ctx, aux, "bpf_prog_aux", "name", 256)
		if err != nil {
			n.fail("Destination", "xdp_program_name_unreadable", err)
		} else if name != "" {
			n.cells["Destination"] = evidence.Text("ebpf_prog_name:" + name)
		}
	}
}
