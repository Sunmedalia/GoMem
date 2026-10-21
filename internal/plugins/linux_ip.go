package plugins

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

func linuxIPPlugins() []builtin {
	common := []evidence.Column{{Name: "Offset", Kind: "address"}, {Name: "NamespaceOffset", Kind: "address"}, {Name: "AddressOffset", Kind: "address"}, {Name: "Family", Kind: "string"}, {Name: "FieldEvidence", Kind: "structure"}, {Name: "RecordType", Kind: "string"}, {Name: "Error", Kind: "string"}, {Name: "Coverage", Kind: "structure"}}
	columns := func(names, kinds []string) []evidence.Column {
		out := []evidence.Column{}
		for i, n := range names {
			out = append(out, evidence.Column{Name: n, Kind: kinds[i]})
		}
		return append(out, common...)
	}
	spec := func(name, upstream string, cols []evidence.Column) plugin.Spec {
		return plugin.Spec{Name: name, Upstream: upstream, Platform: "linux", NeedsKernel: true, Description: "Enumerate network namespaces and interfaces with bounded traversal and raw field evidence", Parameters: []plugin.Parameter{{Name: "max-nodes", Kind: "uint", Default: "131072", Description: "Total namespace, device and address visit bound, 1..1000000"}}, Columns: cols}
	}
	return []builtin{
		{spec("linux.ip.link", "linux.ip.Link", columns([]string{"NS", "Interface", "MAC", "State", "MTU", "Qdisc", "Qlen", "Flags"}, []string{"uint64", "string", "string", "string", "uint64", "string", "uint64", "string"})), func(c context.Context, e plugin.Environment, p map[string]string, o plugin.Emit) error {
			return linuxIP(c, e, p, o, false)
		}},
		{spec("linux.ip.addr", "linux.ip.Addr", columns([]string{"NetNS", "Index", "Interface", "MAC", "Promiscuous", "IP", "Prefix", "Scope Type", "State"}, []string{"uint64", "int64", "string", "string", "bool", "string", "int64", "string", "string"})), func(c context.Context, e plugin.Environment, p map[string]string, o plugin.Emit) error {
			return linuxIP(c, e, p, o, true)
		}},
	}
}

var linuxIPFlagDefaults = map[string]uint64{"IFF_UP": 1, "IFF_BROADCAST": 2, "IFF_DEBUG": 4, "IFF_LOOPBACK": 8, "IFF_POINTOPOINT": 16, "IFF_NOTRAILERS": 32, "IFF_RUNNING": 64, "IFF_NOARP": 128, "IFF_PROMISC": 256, "IFF_ALLMULTI": 512, "IFF_MASTER": 1024, "IFF_SLAVE": 2048, "IFF_MULTICAST": 4096, "IFF_PORTSEL": 8192, "IFF_AUTOMEDIA": 16384, "IFF_DYNAMIC": 32768, "IFF_LOWER_UP": 65536, "IFF_DORMANT": 131072, "IFF_ECHO": 262144}
var linuxIPStates = []string{"UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN", "TESTING", "DORMANT", "UP"}

// Preserve the pinned gflags spelling and Flags' any-bit mask semantics.
func linuxIPFlags(flags, gflags, state, oper uint64, choices, bits map[string]uint64) (string, error) {
	for _, key := range []string{"__LINK_STATE_START", "__LINK_STATE_NOCARRIER", "__LINK_STATE_DORMANT"} {
		v, ok := bits[key]
		if !ok || v > 63 {
			return "", fmt.Errorf("missing or invalid netdev_state_t.%s", key)
		}
	}
	clear := choices["IFF_PROMISC"] | choices["IFF_ALLMULTI"] | choices["IFF_RUNNING"] | choices["IFF_LOWER_UP"] | choices["IFF_DORMANT"]
	value := (flags &^ clear) | (gflags &^ (choices["IFF_PROMISC"] | choices["IFF_ALLMULTI)"]))
	if state&(uint64(1)<<bits["__LINK_STATE_START"]) != 0 {
		if oper == 0 || oper == 6 {
			value |= choices["IFF_RUNNING"]
		}
		if state&(uint64(1)<<bits["__LINK_STATE_NOCARRIER"]) == 0 {
			value |= choices["IFF_LOWER_UP"]
		}
		if state&(uint64(1)<<bits["__LINK_STATE_DORMANT"]) != 0 {
			value |= choices["IFF_DORMANT"]
		}
	}
	names := []string{}
	for k, v := range choices {
		if value&v != 0 && k != "IFF_RUNNING" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for i := range names {
		names[i] = strings.ReplaceAll(names[i], "IFF_", "")
	}
	return strings.Join(names, ","), nil
}

type linuxIPRead struct {
	ctx      context.Context
	e        plugin.Environment
	fields   map[string]evidence.Value
	failures *pluginFailures
}

func (n *linuxIPRead) capture(base uint64, typ, field string) ([]byte, error) {
	raw, v, err := linuxCaptureField(n.ctx, n.e, base, typ, field)
	n.fields[fmt.Sprintf("%s@%x.%s", typ, base, field)] = v
	n.failures.add(err)
	return raw, err
}
func (n *linuxIPRead) uint(base uint64, typ, field string) (uint64, error) {
	if _, err := n.capture(base, typ, field); err != nil {
		return 0, err
	}
	v, err := n.e.Objects.Uint(n.ctx, base, typ, field)
	n.failures.add(err)
	return v, err
}
func (n *linuxIPRead) number(base uint64, typ, field string) evidence.Value {
	v, err := n.uint(base, typ, field)
	if err != nil {
		return evidence.Missing("field_unreadable", err)
	}
	return evidence.Number(v)
}
func (n *linuxIPRead) integer(base uint64, typ, field string) evidence.Value {
	if _, err := n.capture(base, typ, field); err != nil {
		return evidence.Missing("field_unreadable", err)
	}
	v, err := n.e.Objects.Int(n.ctx, base, typ, field)
	n.failures.add(err)
	if err != nil {
		return evidence.Missing("field_unreadable", err)
	}
	return evidence.Integer(v)
}
func (n *linuxIPRead) text(base uint64, typ, field string) evidence.Value {
	raw, err := n.capture(base, typ, field)
	if err != nil {
		return evidence.Missing("field_unreadable", err)
	}
	return evidence.Text(spoofDecoded(raw))
}
func (n *linuxIPRead) bytes(address, size uint64) ([]byte, error) {
	if size > 4096 {
		err := fmt.Errorf("byte extent %d exceeds bound", size)
		n.failures.add(err)
		return nil, err
	}
	raw := make([]byte, int(size))
	got, err := n.e.Kernel.ReadAt(n.ctx, raw, address)
	if got < 0 || got > len(raw) {
		err = fmt.Errorf("invalid byte read count %d", got)
		got = 0
	}
	if err == nil && got != len(raw) {
		err = io.ErrUnexpectedEOF
	}
	fields := map[string]evidence.Value{"Address": evidence.Address(address), "Raw": evidence.Bytes(raw[:got]), "RequestedBytes": evidence.Number(size), "CapturedBytes": evidence.Number(uint64(got)), "ReadComplete": evidence.Bool(err == nil)}
	if err != nil {
		fields["Error"] = evidence.Missing("byte_read_incomplete", err)
	}
	n.fields[fmt.Sprintf("bytes@%x:%d", address, size)] = evidence.Value{Kind: "structure", Data: fields}
	n.failures.add(err)
	return raw[:got], err
}
func (n *linuxIPRead) mac(device uint64) evidence.Value {
	length, err := n.uint(device, "net_device", "addr_len")
	if err != nil {
		return evidence.Missing("mac_length_unreadable", err)
	}
	if length > 4096 {
		err = fmt.Errorf("MAC extent %d exceeds bound", length)
		n.failures.add(err)
		return evidence.Missing("mac_extent_invalid", err)
	}
	format := func(raw []byte) evidence.Value {
		parts := make([]string, len(raw))
		for i, v := range raw {
			parts[i] = fmt.Sprintf("%02x", v)
		}
		return evidence.Text(strings.Join(parts, ":"))
	}
	if _, err := n.e.Objects.Field("net_device", "perm_addr"); err == nil {
		raw, err := n.capture(device, "net_device", "perm_addr")
		if err != nil {
			return evidence.Missing("mac_unreadable", err)
		}
		if uint64(len(raw)) > length {
			raw = raw[:length]
		}
		nonzero := false
		for _, v := range raw {
			nonzero = nonzero || v != 0
		}
		// Upstream compares formatted strings, including truncated permanent arrays.
		if nonzero || uint64(len(raw)) != length {
			return format(raw)
		}
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		n.failures.add(err)
		return evidence.Missing("mac_layout_invalid", err)
	}
	address, err := n.uint(device, "net_device", "dev_addr")
	if err != nil {
		return evidence.Missing("mac_pointer_unreadable", err)
	}
	raw, err := n.bytes(address, length)
	if err != nil {
		return evidence.Missing("mac_unreadable", err)
	}
	return format(raw)
}
func (n *linuxIPRead) namespace(device uint64) evidence.Value {
	path := "nd_net"
	f, err := n.e.Objects.Field("net_device", path)
	if err != nil {
		n.failures.add(err)
		return evidence.Missing("namespace_layout_unavailable", err)
	}
	if f.Type.Kind == "struct" || f.Type.Kind == "union" {
		path = "nd_net.net"
	}
	address, err := n.uint(device, "net_device", path)
	if err != nil {
		return evidence.Missing("namespace_pointer_unreadable", err)
	}
	// A missing inode layout is a normal pinned-kernel applicability condition.
	inode := "proc_inum"
	if _, err := n.e.Objects.Field("net", inode); err != nil {
		if !errors.Is(err, object.ErrFieldAbsent) {
			n.failures.add(err)
			return evidence.Missing("namespace_layout_invalid", err)
		}
		inode = "ns.inum"
		if _, err := n.e.Objects.Field("net", inode); err != nil {
			if !errors.Is(err, object.ErrFieldAbsent) {
				n.failures.add(err)
				return evidence.Missing("namespace_layout_invalid", err)
			}
			return evidence.Missing("namespace_inode_layout_unavailable", nil)
		}
	}
	value, err := n.uint(address, "net", inode)
	if err != nil {
		return evidence.Missing("namespace_inode_unreadable", err)
	}
	if value == 0 {
		return evidence.Missing("namespace_inode_zero", nil)
	}
	return evidence.Number(value)
}
func (n *linuxIPRead) qdisc(device uint64) evidence.Value {
	q, err := n.uint(device, "net_device", "qdisc")
	if err != nil {
		return evidence.Missing("qdisc_pointer_unreadable", err)
	}
	ops, err := n.uint(q, "Qdisc", "ops")
	if err != nil {
		return evidence.Missing("qdisc_ops_unreadable", err)
	}
	value := n.text(ops, "Qdisc_ops", "id")
	if value.Kind == "string" && value.String() == "" {
		return evidence.Missing("qdisc_empty", nil)
	}
	return value
}

func linuxIP(ctx context.Context, e plugin.Environment, p map[string]string, out plugin.Emit, addresses bool) error {
	if e.Kernel == nil || e.Symbols == nil || e.Objects == nil {
		return fmt.Errorf("network interfaces require kernel memory and symbols")
	}
	max, _, err := limits(p)
	if err != nil {
		return err
	}
	root, err := e.Symbol("net_namespace_list")
	if err != nil {
		return err
	}
	netLink, err := e.Objects.Field("net", "list")
	if err != nil {
		return err
	}
	devHead, err := e.Objects.Field("net", "dev_base_head")
	if err != nil {
		return err
	}
	devLink, err := e.Objects.Field("net_device", "dev_list")
	if err != nil {
		return err
	}
	choices, choicesErr := linuxEnumChoices(e, "net_device_flags", linuxIPFlagDefaults)
	bits, bitsErr := linuxEnumChoices(e, "netdev_state_t", nil)
	var failures pluginFailures
	var visits, devices, rows, diagnostics uint64
	var emitErr error
	emit := func(r evidence.Row) error {
		if emitErr != nil {
			return emitErr
		}
		emitErr = out(r)
		return emitErr
	}
	base := func(device, namespace uint64, kind string) evidence.Row {
		r := evidence.Row{Cells: map[string]evidence.Value{}, Provenance: evidence.Provenance{Layer: e.Kernel.Name(), Offset: fmt.Sprintf("0x%x", device)}}
		index := 0
		if addresses {
			index = 1
		}
		for _, c := range linuxIPPlugins()[index].spec.Columns {
			r.Cells[c.Name] = evidence.Missing("not_applicable", nil)
		}
		r.Cells["Offset"], r.Cells["NamespaceOffset"], r.Cells["RecordType"] = evidence.Address(device), evidence.Address(namespace), evidence.Text(kind)
		return r
	}
	diagnostic := func(address, namespace uint64, cause error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if emitErr != nil {
			return emitErr
		}
		failures.add(cause)
		diagnostics++
		r := base(address, namespace, "diagnostic")
		r.Cells["Error"] = evidence.Missing("enumeration_incomplete", cause)
		return emit(r)
	}
	visit := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visits >= uint64(max) {
			return fmt.Errorf("network visits exceed max-nodes %d", max)
		}
		visits++
		return nil
	}
	err = e.Objects.WalkList(ctx, root, netLink.Offset, max, func(namespace uint64) error {
		if err := visit(); err != nil {
			return err
		}
		head, err := memory.Add(namespace, devHead.Offset)
		if err != nil {
			return diagnostic(namespace, namespace, err)
		}
		err = e.Objects.WalkList(ctx, head, devLink.Offset, max, func(device uint64) error {
			if err := visit(); err != nil {
				return err
			}
			devices++
			r := base(device, namespace, "interface")
			fields := map[string]evidence.Value{}
			r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
			n := &linuxIPRead{ctx, e, fields, &failures}
			before := failures.count
			n.capture(root, "list_head", "")
			n.capture(namespace, "net", "list")
			n.capture(namespace, "net", "dev_base_head")
			n.capture(device, "net_device", "dev_list")
			r.Cells["Interface"] = n.text(device, "net_device", "name")
			r.Cells["MAC"] = n.mac(device)
			oper, operErr := n.uint(device, "net_device", "operstate")
			if operErr != nil {
				r.Cells["State"] = evidence.Missing("state_unreadable", operErr)
			} else if oper >= uint64(len(linuxIPStates)) {
				r.Cells["State"] = evidence.Missing("state_unparsable", nil)
			} else {
				r.Cells["State"] = evidence.Text(linuxIPStates[oper])
			}
			ns := n.namespace(device)
			if !addresses {
				r.Cells["NS"] = ns
				r.Cells["MTU"] = n.number(device, "net_device", "mtu")
				r.Cells["Qlen"] = n.number(device, "net_device", "tx_queue_len")
				r.Cells["Qdisc"] = n.qdisc(device)
				flags, ferr := n.uint(device, "net_device", "flags")
				gflags, gerr := n.uint(device, "net_device", "gflags")
				state, serr := n.uint(device, "net_device", "state")
				var err error
				switch {
				case choicesErr != nil:
					err = choicesErr
				case bitsErr != nil:
					err = bitsErr
				case ferr != nil:
					err = ferr
				case gerr != nil:
					err = gerr
				case serr != nil:
					err = serr
				case operErr != nil:
					err = operErr
				default:
					var value string
					value, err = linuxIPFlags(flags, gflags, state, oper, choices, bits)
					if err == nil {
						r.Cells["Flags"] = evidence.Text(value)
					}
				}
				if err != nil {
					failures.add(err)
					r.Cells["Flags"] = evidence.Missing("flags_unavailable", err)
				}
				if failures.count > before {
					r.Cells["Error"] = evidence.Missing("interface_fields_incomplete", fmt.Errorf("%d interface read/layout errors", failures.count-before))
				}
				rows++
				return emit(r)
			}
			r.Cells["RecordType"] = evidence.Text("device_observation")
			r.Cells["NetNS"] = ns
			if _, err := n.capture(device, "net_device", "ifindex"); err == nil {
				value, err := e.Objects.Int(ctx, device, "net_device", "ifindex")
				failures.add(err)
				if err == nil {
					r.Cells["Index"] = evidence.Integer(value)
				} else {
					r.Cells["Index"] = evidence.Missing("index_unreadable", err)
				}
			} else {
				r.Cells["Index"] = evidence.Missing("index_unreadable", err)
			}
			flags, ferr := n.uint(device, "net_device", "flags")
			mask, hasMask := choices["IFF_PROMISC"]
			if choicesErr != nil || !hasMask {
				r.Cells["Promiscuous"] = evidence.Missing("promisc_mask_unavailable", choicesErr)
				failures.add(fmt.Errorf("IFF_PROMISC unavailable: %v", choicesErr))
			} else if ferr != nil {
				r.Cells["Promiscuous"] = evidence.Missing("flags_unreadable", ferr)
			} else {
				r.Cells["Promiscuous"] = evidence.Bool(flags&mask != 0)
			}
			// Capture traversal roots before sealing the device observation.
			ip4, ip4err := n.uint(device, "net_device", "ip_ptr")
			ip6, ip6err := n.uint(device, "net_device", "ip6_ptr")
			if failures.count > before {
				r.Cells["Error"] = evidence.Missing("interface_fields_incomplete", fmt.Errorf("%d interface read/layout errors", failures.count-before))
			}
			if err := emit(r); err != nil {
				return err
			}
			if ip4err == nil && ip4 != 0 {
				err = linuxIP4(n, r, ip4, visit, func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "address" {
						rows++
					}
					return emit(row)
				})
				if err != nil {
					if err := diagnostic(ip4, namespace, err); err != nil {
						return err
					}
				}
			}
			if ip6err == nil && ip6 != 0 {
				err = linuxIP6(n, r, ip6, max, visit, func(row evidence.Row) error {
					if row.Cells["RecordType"].String() == "address" {
						rows++
					}
					return emit(row)
				})
				if err != nil {
					if err := diagnostic(ip6, namespace, err); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return diagnostic(head, namespace, err)
		}
		return nil
	})
	if err != nil {
		if err := diagnostic(root, 0, err); err != nil {
			return err
		}
	}
	if emitErr != nil {
		return emitErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	summary := base(root, 0, "summary")
	summary.Cells["Coverage"] = poolCoverage(map[string]string{"visits": strconv.FormatUint(visits, 10), "devices": strconv.FormatUint(devices, 10), "rows": strconv.FormatUint(rows, 10), "diagnostics": strconv.FormatUint(diagnostics, 10), "read_layout_errors": strconv.Itoa(failures.count), "list_policy": "bounded_forward_with_backlinks", "ipv4_address_bound": "129_per_device", "scope": "symbol-described Intel Linux; no cross-kernel release acceptance"})
	if err := emit(summary); err != nil {
		return err
	}
	return failures.err("Linux network interface enumeration")
}

func linuxIPAddressRow(parent evidence.Row, address uint64, family string) (evidence.Row, map[string]evidence.Value) {
	r := parent
	r.ID = ""
	r.Cells = copyEvidenceCells(parent.Cells)
	fields := map[string]evidence.Value{}
	r.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: fields}
	r.Cells["AddressOffset"] = evidence.Address(address)
	r.Cells["Family"] = evidence.Text(family)
	r.Cells["RecordType"] = evidence.Text("address")
	return r, fields
}
func linuxIP4(n *linuxIPRead, parent evidence.Row, device uint64, visit func() error, emit plugin.Emit) error {
	rootFields := map[string]evidence.Value{}
	root := *n
	root.fields = rootFields
	current, err := root.uint(device, "in_device", "ifa_list")
	observation, _ := linuxIPAddressRow(parent, device, "IPv4")
	observation.Cells["RecordType"] = evidence.Text("address_list_observation")
	observation.Cells["FieldEvidence"] = evidence.Value{Kind: "structure", Data: rootFields}
	if err != nil {
		observation.Cells["Error"] = evidence.Missing("address_list_unreadable", err)
	}
	if emitErr := emit(observation); emitErr != nil {
		return emitErr
	}
	if err != nil {
		return err
	}
	seen := map[uint64]bool{}
	for current != 0 {
		if len(seen) >= 129 {
			return fmt.Errorf("IPv4 address chain exceeds pinned 129-address bound")
		}
		if seen[current] {
			return fmt.Errorf("IPv4 address chain cycle at %#x", current)
		}
		seen[current] = true
		if err := visit(); err != nil {
			return err
		}
		r, fields := linuxIPAddressRow(parent, current, "IPv4")
		for k, v := range rootFields {
			fields[k] = v
		}
		reader := *n
		reader.fields = fields
		before := n.failures.count
		value, err := reader.uint(current, "in_ifaddr", "ifa_address")
		if err != nil {
			r.Cells["IP"] = evidence.Missing("address_unreadable", err)
		} else if value > 0xffffffff {
			err = fmt.Errorf("IPv4 integer exceeds 32 bits")
			n.failures.add(err)
			r.Cells["IP"] = evidence.Missing("address_invalid", err)
		} else {
			r.Cells["IP"] = evidence.Text(linuxIP4Text(uint32(value)))
		}
		r.Cells["Prefix"] = reader.integer(current, "in_ifaddr", "ifa_prefixlen")
		scope, err := reader.uint(current, "in_ifaddr", "ifa_scope")
		if err != nil {
			r.Cells["Scope Type"] = evidence.Missing("scope_unreadable", err)
		} else {
			enum, err := n.e.Symbols.Enumeration("rt_scope_t")
			if err != nil {
				n.failures.add(err)
				r.Cells["Scope Type"] = evidence.Missing("scope_enum_unavailable", err)
			} else {
				label := "unknown"
				names := enum.Names(scope)
				ambiguous := false
				for i, name := range names {
					mapped := map[string]string{"RT_SCOPE_UNIVERSE": "global", "RT_SCOPE_NOWHERE": "nowhere", "RT_SCOPE_HOST": "host", "RT_SCOPE_LINK": "link", "RT_SCOPE_SITE": "site"}[name]
					if mapped == "" {
						mapped = "unknown"
					}
					if i > 0 && label != mapped {
						ambiguous = true
					}
					label = mapped
				}
				if ambiguous {
					err := fmt.Errorf("rt_scope_t value %d has ambiguous aliases %v", scope, names)
					n.failures.add(err)
					r.Cells["Scope Type"] = evidence.Missing("scope_enum_ambiguous", err)
				} else {
					r.Cells["Scope Type"] = evidence.Text(label)
				}
			}
		}
		next, nextErr := reader.uint(current, "in_ifaddr", "ifa_next")
		if n.failures.count > before {
			r.Cells["Error"] = evidence.Missing("address_fields_incomplete", fmt.Errorf("%d address errors", n.failures.count-before))
		}
		if err := emit(r); err != nil {
			return err
		}
		if nextErr != nil {
			return nextErr
		}
		current = next
	}
	return nil
}
func linuxIP6(n *linuxIPRead, parent evidence.Row, device uint64, max int, visit func() error, emit plugin.Emit) error {
	observation, fields := linuxIPAddressRow(parent, device, "IPv6")
	observation.Cells["RecordType"] = evidence.Text("address_list_observation")
	reader := *n
	reader.fields = fields
	_, captureErr := reader.capture(device, "inet6_dev", "addr_list")
	if captureErr != nil {
		observation.Cells["Error"] = evidence.Missing("address_list_unreadable", captureErr)
	}
	if err := emit(observation); err != nil {
		return err
	}
	if captureErr != nil {
		return captureErr
	}
	head, err := n.e.Objects.Field("inet6_dev", "addr_list")
	if err != nil {
		return err
	}
	if head.Type.Kind != "struct" || head.Type.Name != "list_head" {
		return fmt.Errorf("unsupported pre-3.0 IPv6 address-list layout")
	}
	link, err := n.e.Objects.Field("inet6_ifaddr", "if_list")
	if err != nil {
		return err
	}
	at, err := memory.Add(device, head.Offset)
	if err != nil {
		return err
	}
	return n.e.Objects.WalkList(n.ctx, at, link.Offset, max, func(address uint64) error {
		if err := visit(); err != nil {
			return err
		}
		r, fields := linuxIPAddressRow(parent, address, "IPv6")
		reader := *n
		reader.fields = fields
		before := n.failures.count
		reader.capture(device, "inet6_dev", "addr_list")
		reader.capture(address, "inet6_ifaddr", "if_list")
		raw, err := reader.capture(address, "inet6_ifaddr", "addr.in6_u.u6_addr32")
		if err != nil {
			r.Cells["IP"] = evidence.Missing("address_unreadable", err)
		} else {
			var bytes [16]byte
			f, layoutErr := n.e.Objects.Field("inet6_ifaddr", "addr.in6_u.u6_addr32")
			if layoutErr != nil {
				err = layoutErr
			} else if len(raw) != 16 || f.Type.Kind != "array" || f.Type.Count != 4 || f.Type.Underlying() == nil {
				err = fmt.Errorf("IPv6 field must be four 32-bit scalars, got %s/%d bytes", f.Type.Kind, len(raw))
			} else if size, sizeErr := n.e.Objects.Size(*f.Type.Underlying()); sizeErr != nil || size != 4 {
				err = fmt.Errorf("IPv6 element extent %d: %v", size, sizeErr)
			} else {
				start, addErr := memory.Add(address, f.Offset)
				err = addErr
				for i := uint64(0); i < 4 && err == nil; i++ {
					var at, value uint64
					at, err = memory.Add(start, i*4)
					if err != nil {
						break
					}
					value, err = n.e.Objects.Scalar(n.ctx, at, *f.Type.Underlying())
					if err != nil {
						break
					}
					binary.LittleEndian.PutUint32(bytes[i*4:], uint32(value))
				}
			}
			if err != nil {
				n.failures.add(err)
				r.Cells["IP"] = evidence.Missing("address_invalid", err)
			} else {
				r.Cells["IP"] = evidence.Text(linuxIP6Text(bytes))
			}
		}
		r.Cells["Prefix"] = reader.integer(address, "inet6_ifaddr", "prefix_len")
		scope, err := reader.uint(address, "inet6_ifaddr", "scope")
		if err != nil {
			r.Cells["Scope Type"] = evidence.Missing("scope_unreadable", err)
		} else {
			r.Cells["Scope Type"] = evidence.Text(linuxIP6Scope(scope))
		}
		if n.failures.count > before {
			r.Cells["Error"] = evidence.Missing("address_fields_incomplete", fmt.Errorf("%d address errors", n.failures.count-before))
		}
		return emit(r)
	})
}

// Mapped tails use dotted IPv4; older Python renderers can normalize by address.
func linuxIP6Text(raw [16]byte) string { return netip.AddrFrom16(raw).String() }

func linuxIP4Text(value uint32) string {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	return netip.AddrFrom4(raw).String()
}
func linuxIP6Scope(scope uint64) string {
	switch {
	case scope&0x10 != 0:
		return "host"
	case scope&0x20 != 0:
		return "link"
	case scope&0x40 != 0:
		return "site"
	default:
		return "global"
	}
}
