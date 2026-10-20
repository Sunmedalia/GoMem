package plugins

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxInetEndpoints(n *linuxNetReader, sock, family, kind uint64) {
	n.cells["EndpointKind"] = evidence.Text("ip_port")
	base, err := n.container(sock, "inet_sock")
	if err != nil {
		n.fail("Source", "inet_layout_unavailable", err)
		return
	}
	protocol, _ := n.cells["ProtocolRaw"].Uint()
	label, found := linuxIPProtocols[protocol]
	if family == 10 {
		if value, ok := linuxIPv6Protocols[protocol]; ok {
			label, found = value, true
		}
	}
	if found {
		n.cells["Proto"] = evidence.Text(label)
	} else {
		n.cells["Proto"] = evidence.Missing("unknown_ip_protocol", nil)
	}
	n.streamState(kind)
	for _, endpoint := range []struct {
		key   string
		paths []string
	}{{"SourcePort", []string{"sport", "inet_sport"}}, {"DestinationPort", []string{"sk.__sk_common.skc_portpair", "dport", "inet_dport", "sk.__sk_common.skc_dport"}}} {
		path, err := n.choose("inet_sock", endpoint.paths...)
		if err != nil {
			n.fail(endpoint.key, "port_layout_unavailable", err)
			continue
		}
		data, err := n.fieldBytes(endpoint.key+"Raw", base, "inet_sock", path, 2)
		if err != nil {
			n.fail(endpoint.key, "port_unreadable", err)
			continue
		}
		n.cells[endpoint.key] = evidence.Text(strconv.FormatUint(uint64(binary.BigEndian.Uint16(data)), 10))
	}
	for _, endpoint := range []string{"Source", "Destination"} {
		err = nil
		typ, address, path, size := "inet_sock", base, "", 4
		if family == 2 {
			fields := []string{"rcv_saddr", "inet_rcv_saddr", "sk.__sk_common.skc_rcv_saddr"}
			if endpoint == "Destination" {
				fields = []string{"daddr", "inet_daddr", "sk.__sk_common.skc_daddr"}
			}
			path, err = n.choose(typ, fields...)
			if err == nil && endpoint == "Destination" && path != "sk.__sk_common.skc_daddr" {
				value, readErr := n.e.Objects.Uint(n.ctx, base, typ, path)
				if readErr != nil {
					err = readErr
				} else if value == 0 {
					if fallback, er := n.choose(typ, "sk.__sk_common.skc_daddr"); er == nil {
						path = fallback
					}
				}
			}
		} else {
			size = 16
			common := "sk.__sk_common.skc_v6_rcv_saddr"
			if endpoint == "Destination" {
				common = "sk.__sk_common.skc_v6_daddr"
			}
			if n.optional("inet_sock", "pinet6") {
				pinfo, ok := n.pointer(endpoint+"IPv6Info", base, "inet_sock", "pinet6")
				if !ok {
					n.cells[endpoint] = n.cells[endpoint+"IPv6Info"]
					continue
				}
				if pinfo == 0 {
					n.fail(endpoint, "ipv6_info_null", fmt.Errorf("inet_sock.pinet6 is null"))
					continue
				}
				typ, address = "ipv6_pinfo", pinfo
				path = "saddr"
				if endpoint == "Destination" {
					path = "daddr"
				}
				if endpoint == "Destination" && !n.optional(typ, path) {
					typ, address, path = "inet_sock", base, common
				}
			} else {
				path, err = n.choose(typ, common)
			}
		}
		if err != nil {
			n.fail(endpoint, "address_layout_unavailable", err)
			continue
		}
		data, er := n.fieldBytes(endpoint+"Raw", address, typ, path, size)
		if er != nil {
			n.fail(endpoint, "address_unreadable", er)
			continue
		}
		var value netip.Addr
		if size == 4 {
			value = netip.AddrFrom4([4]byte(data))
		} else {
			value = netip.AddrFrom16([16]byte(data))
		}
		// Go's netip displays mapped IPv6 as dotted IPv4, matching inet_ntop.
		n.cells[endpoint] = evidence.Text(value.String())
		n.cells[endpoint+"Encoding"] = evidence.Text(fmt.Sprintf("network-order-ipv%d", map[bool]int{true: 4, false: 6}[size == 4]))
	}
}

// UNIX names are length-delimited. Abstract names may contain embedded/trailing
// NUL bytes; the escaped display is for navigation, original bytes are evidence.
func linuxUnixDisplay(raw []byte) (string, string) {
	if len(raw) > 0 && raw[0] == 0 {
		var b strings.Builder
		b.WriteByte('@')
		for _, c := range raw[1:] {
			if c >= 0x21 && c <= 0x7e && c != '\\' {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "\\x%02x", c)
			}
		}
		return b.String(), "abstract"
	}
	name := raw
	if end := bytes.IndexByte(name, 0); end >= 0 {
		name = name[:end]
	}
	return strings.ToValidUTF8(string(name), "\ufffd"), "pathname"
}
func linuxUnixName(n *linuxNetReader, sock uint64, key string) {
	base, err := n.container(sock, "unix_sock")
	if err != nil {
		n.fail(key, "unix_layout_unavailable", err)
		return
	}
	address, ok := n.pointer(key+"UnixAddress", base, "unix_sock", "addr")
	if !ok {
		n.cells[key] = n.cells[key+"UnixAddress"]
		return
	}
	if address == 0 {
		n.cells[key], n.cells[key+"Raw"] = evidence.Missing("not_bound", nil), evidence.Missing("not_bound", nil)
		return
	}
	length, ok := n.uint(key+"UnixLength", address, "unix_address", "len")
	if !ok {
		n.cells[key] = n.cells[key+"UnixLength"]
		return
	}
	name, err := n.e.Objects.Field("unix_address", "name")
	if err != nil {
		n.fail(key, "unix_name_layout_unavailable", err)
		return
	}
	path, err := n.e.Objects.Field("sockaddr_un", "sun_path")
	if err != nil {
		n.fail(key, "unix_name_layout_unavailable", err)
		return
	}
	maximum, err := n.e.Objects.Size(path.Type)
	if err != nil || length < path.Offset || length-path.Offset > maximum || maximum > 4096 {
		n.fail(key, "invalid_unix_name_length", fmt.Errorf("unix sockaddr length %d is outside declared path bounds", length))
		return
	}
	location, err := memory.Add(address, name.Offset)
	if err == nil {
		location, err = memory.Add(location, path.Offset)
	}
	if err != nil {
		n.fail(key, "unix_name_overflow", err)
		return
	}
	raw, err := n.raw(key+"Raw", location, int(length-path.Offset))
	if err != nil {
		n.fail(key, "unix_name_unreadable", err)
		return
	}
	display, encoding := linuxUnixDisplay(raw)
	n.cells[key], n.cells[key+"Encoding"] = evidence.Text(display), evidence.Text(encoding)
}
func linuxSockInode(n *linuxNetReader, sock uint64, key string) {
	socket, ok := n.pointer(key+"Socket", sock, "sock", "sk_socket")
	if !ok {
		return
	}
	if socket == 0 {
		n.cells[key] = evidence.Text("0")
		return
	}
	sf, err := n.e.Objects.Field("socket_alloc", "socket")
	if err != nil {
		n.fail(key, "socket_inode_layout_unavailable", err)
		return
	}
	inf, err := n.e.Objects.Field("socket_alloc", "vfs_inode")
	if err != nil || socket < sf.Offset {
		n.fail(key, "socket_inode_layout_unavailable", fmt.Errorf("invalid socket_alloc layout/container: %v", err))
		return
	}
	inode, err := memory.Add(socket-sf.Offset, inf.Offset)
	if err != nil {
		n.fail(key, "socket_inode_overflow", err)
		return
	}
	value, ok := n.uint(key+"Inode", inode, "inode", "i_ino")
	if ok {
		n.cells[key] = evidence.Text(strconv.FormatUint(value, 10))
	}
}
func linuxUnixEndpoints(n *linuxNetReader, sock, kind uint64) {
	n.cells["EndpointKind"], n.cells["Proto"] = evidence.Text("unix_name_inode"), evidence.Missing("not_applicable", nil)
	n.streamState(kind)
	linuxUnixName(n, sock, "Source")
	linuxSockInode(n, sock, "SourcePort")
	base, err := n.container(sock, "unix_sock")
	if err != nil {
		n.fail("Destination", "unix_layout_unavailable", err)
		return
	}
	peer, ok := n.pointer("Peer", base, "unix_sock", "peer")
	if !ok {
		n.cells["Destination"], n.cells["DestinationPort"] = n.cells["Peer"], n.cells["Peer"]
		return
	}
	if peer == 0 {
		n.cells["Destination"], n.cells["DestinationPort"] = evidence.Missing("no_peer", nil), evidence.Missing("no_peer", nil)
		return
	}
	linuxUnixName(n, peer, "Destination")
	linuxSockInode(n, peer, "DestinationPort")
}

func linuxNetlinkEndpoints(n *linuxNetReader, sock uint64) {
	n.cells["EndpointKind"] = evidence.Text("netlink_group_portid")
	base, err := n.container(sock, "netlink_sock")
	if err != nil {
		n.fail("Source", "netlink_layout_unavailable", err)
		return
	}
	protocol, _ := n.cells["ProtocolRaw"].Uint()
	n.cells["Proto"] = linuxNetLabel(protocol, linuxNetlinkProtocols, "unknown_netlink_protocol")
	if pointer, ok := n.pointer("NetlinkGroups", base, "netlink_sock", "groups"); ok && pointer != 0 {
		v, err := n.e.Objects.Scalar(n.ctx, pointer, symbols.TypeRef{Kind: "pointer"})
		if err != nil {
			n.fail("Source", "netlink_groups_unreadable", err)
		} else {
			n.cells["Source"] = evidence.Text(fmt.Sprintf("groups:0x%08x", v))
		}
	}
	if group, ok := n.uint("DestinationGroupRaw", base, "netlink_sock", "dst_group"); ok {
		destination := fmt.Sprintf("group:0x%08x", group)
		if module, ok := n.pointer("NetlinkModule", base, "netlink_sock", "module"); ok && module != 0 {
			name, err := n.e.Objects.String(n.ctx, module, "module", "name", 256)
			if err != nil {
				n.fail("Destination", "netlink_module_unreadable", err)
			} else if name != "" {
				destination += ",lkm:" + name
			}
		}
		if n.cells["Destination"].Error == "" {
			n.cells["Destination"] = evidence.Text(destination)
		}
	}
	for _, port := range []struct {
		key   string
		paths []string
	}{{"SourcePort", []string{"pid", "portid"}}, {"DestinationPort", []string{"dst_pid", "dst_portid"}}} {
		path, err := n.choose("netlink_sock", port.paths...)
		if err != nil {
			n.fail(port.key, "netlink_portid_layout_unavailable", err)
			continue
		}
		if value, ok := n.uint(port.key+"Value", base, "netlink_sock", path); ok {
			n.cells[port.key] = evidence.Text(strconv.FormatUint(value, 10))
		}
	}
}
