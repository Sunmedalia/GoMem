package engine_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/testfixture"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func linuxSocketFixture(t *testing.T, scenario string) testfixture.Fixture {
	t.Helper()
	f := linuxLsofFixture(t, "normal")
	table, err := symbols.Load(f.Symbols)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Image)
	if err != nil {
		t.Fatal(err)
	}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(data[a:], v) }
	put16 := func(a uint64, v uint16) { binary.LittleEndian.PutUint16(data[a:], v) }
	ptr := symbols.TypeRef{Kind: "pointer"}
	ref := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "struct", Name: n} }
	base := func(n string) symbols.TypeRef { return symbols.TypeRef{Kind: "base", Name: n} }
	field := func(a uint64, r symbols.TypeRef) symbols.Field { return symbols.Field{Offset: a, Type: r} }
	array := func(n uint64) symbols.TypeRef {
		b := base("char")
		return symbols.TypeRef{Kind: "array", Count: n, Subtype: &b}
	}
	add := func(name string, size uint64, fields map[string]symbols.Field) {
		table.Types[name] = symbols.Type{Kind: "struct", Size: size, Fields: fields}
	}
	table.Symbols["socket_file_ops"] = symbols.Symbol{Address: 0x8400}
	table.Symbols["sockfs_dentry_operations"] = symbols.Symbol{Address: 0x8500}
	file := table.Types["file"]
	file.Size = 32
	file.Fields["f_op"] = field(24, ptr)
	table.Types["file"] = file
	put(0x13118, 0x8400)
	task := table.Types["task_struct"]
	task.Size = 160
	task.Fields["nsproxy"] = field(152, ptr)
	table.Types["task_struct"] = task
	put(0xa098, 0x1c000)
	add("nsproxy", 8, map[string]symbols.Field{"net_ns": field(0, ptr)})
	put(0x1c000, 0x1c100)
	add("net", 32, map[string]symbols.Field{"proc_inum": field(0, base("u64")), "dev_base_head": field(8, ref("list_head"))})
	put(0x1c100, 4026531993)
	put(0x1c108, 0x1c108)
	put(0x1c110, 0x1c108)
	add("possible_net_t", 8, map[string]symbols.Field{"net": field(0, ptr)})
	add("sock_common", 64, map[string]symbols.Field{"skc_family": field(0, base("u16")), "skc_state": field(2, base("char")), "skc_rcv_saddr": field(4, base("u32")), "skc_daddr": field(8, base("u32")), "skc_portpair": field(12, base("u32")), "skc_v6_rcv_saddr": field(16, array(16)), "skc_v6_daddr": field(32, array(16)), "skc_net": field(48, ref("possible_net_t"))})
	add("sock", 96, map[string]symbols.Field{"__sk_common": field(0, ref("sock_common")), "sk_socket": field(64, ptr), "sk_protocol": field(72, base("u16")), "sk_type": field(74, base("u16")), "sk_filter": field(80, ptr), "sk_reuseport_cb": field(88, ptr)})
	add("socket", 32, map[string]symbols.Field{"sk": field(0, ptr), "state": field(8, base("u32"))})
	inode := table.Types["inode"]
	add("socket_alloc", 32+inode.Size, map[string]symbols.Field{"socket": field(0, ref("socket")), "vfs_inode": field(32, ref("inode"))})
	// The FD's dentry inode is 0x18100; the containing socket is 32 bytes before it.
	put(0x180e0, 0x1d000)
	put(0x180e8, 3)
	put(0x1d040, 0x180e0)
	put16(0x1d000, 2)
	data[0x1d002] = 10
	put16(0x1d048, 6)
	put16(0x1d04a, 1)
	put(0x1d030, 0x1c100)
	copy(data[0x1d004:], []byte{1, 2, 3, 4})
	copy(data[0x1d008:], []byte{127, 0, 0, 1})
	binary.BigEndian.PutUint16(data[0x1d00c:], 8080)
	add("inet_sock", 112, map[string]symbols.Field{"sk": field(0, ref("sock")), "inet_sport": field(96, base("u16"))})
	binary.BigEndian.PutUint16(data[0x1d060:], 443)
	add("unix_sock", 112, map[string]symbols.Field{"sk": field(0, ref("sock")), "addr": field(96, ptr), "peer": field(104, ptr)})
	add("sockaddr_un", 110, map[string]symbols.Field{"sun_family": field(0, base("u16")), "sun_path": field(2, array(108))})
	subtype := ref("sockaddr_un")
	add("unix_address", 8, map[string]symbols.Field{"len": field(0, base("u32")), "name": field(8, symbols.TypeRef{Kind: "array", Count: 0, Subtype: &subtype})})
	add("sk_filter", 8, map[string]symbols.Field{"len": field(0, base("u32"))})
	switch scenario {
	case "unix", "abstract", "unix-peer", "bad-unix-length":
		put16(0x1d000, 1)
		put16(0x1d048, 0)
		put(0x1d060, 0x1d500)
		payload := []byte("/tmp/socket\x00")
		if scenario == "abstract" {
			payload = []byte{0, 'a', 0, 'b', 0, 0xff}
		}
		put(0x1d500, uint64(2+len(payload)))
		put16(0x1d508, 1)
		copy(data[0x1d50a:], payload)
		if scenario == "unix-peer" {
			put(0x1d068, 0x1d800)
			put(0x1d860, 0x1da00)
			put(0x1da00, 8)
			put16(0x1da08, 1)
			copy(data[0x1da0a:], "/peer\x00")
		}
		if scenario == "bad-unix-length" {
			put(0x1d500, 1000)
		}
	case "ipv6", "ipv6-pinfo", "truncated-ipv6":
		put16(0x1d000, 10)
		clear(data[0x1d010:0x1d030])
		copy(data[0x1d010:], []byte{0x20, 1, 0x0d, 0xb8})
		data[0x1d01f] = 1
		data[0x1d02f] = 2
		if scenario == "ipv6-pinfo" || scenario == "truncated-ipv6" {
			inet := table.Types["inet_sock"]
			inet.Fields["pinet6"] = field(104, ptr)
			table.Types["inet_sock"] = inet
			add("ipv6_pinfo", 32, map[string]symbols.Field{"saddr": field(0, array(16)), "daddr": field(16, array(16))})
			put(0x1d068, 0x1d700)
			copy(data[0x1d700:0x1d720], data[0x1d010:0x1d030])
			if scenario == "truncated-ipv6" {
				put(0x1d068, 0x1fff8)
			}
		}
	case "udp":
		put16(0x1d048, 17)
		put16(0x1d04a, 2)
	case "netlink":
		put16(0x1d000, 16)
		put16(0x1d048, 15)
		put16(0x1d04a, 3)
		add("netlink_sock", 128, map[string]symbols.Field{"sk": field(0, ref("sock")), "groups": field(96, ptr), "dst_group": field(104, base("u32")), "module": field(112, ptr), "pid": field(120, base("u32")), "dst_pid": field(124, base("u32"))})
		put(0x1d060, 0x1d500)
		put(0x1d500, 3)
		put(0x1d068, 4)
		binary.LittleEndian.PutUint32(data[0x1d078:], 11)
		binary.LittleEndian.PutUint32(data[0x1d07c:], 22)
	case "vsock":
		put16(0x1d000, 40)
		add("sockaddr_vm", 8, map[string]symbols.Field{"svm_cid": field(0, base("u32")), "svm_port": field(4, base("u32"))})
		add("vsock_sock", 112, map[string]symbols.Field{"sk": field(0, ref("sock")), "local_addr": field(96, ref("sockaddr_vm")), "remote_addr": field(104, ref("sockaddr_vm"))})
		binary.LittleEndian.PutUint32(data[0x1d060:], 2)
		binary.LittleEndian.PutUint32(data[0x1d064:], 1000)
		binary.LittleEndian.PutUint32(data[0x1d068:], 3)
		binary.LittleEndian.PutUint32(data[0x1d06c:], 2000)
	case "packet":
		put16(0x1d000, 17)
		add("packet_sock", 104, map[string]symbols.Field{"sk": field(0, ref("sock")), "ifindex": field(96, base("u32")), "num": field(100, base("u16"))})
		put(0x1d060, 0)
		put16(0x1d064, 0x300)
	case "bluetooth-sco", "bluetooth-rfcomm", "bluetooth-l2cap", "bluetooth-hci":
		put16(0x1d000, 31)
		data[0x1d002] = 1
		add("bt_sock", 96, map[string]symbols.Field{"sk": field(0, ref("sock"))})
		add("bdaddr_t", 6, map[string]symbols.Field{"b": field(0, array(6))})
		typ := "sco_pinfo"
		protocol := uint16(2)
		fields := map[string]symbols.Field{"bt": field(0, ref("bt_sock")), "src": field(96, ref("bdaddr_t")), "dst": field(102, ref("bdaddr_t"))}
		if scenario == "bluetooth-rfcomm" {
			typ, protocol = "rfcomm_pinfo", 3
			fields["channel"] = field(108, base("u16"))
			put16(0x1d06c, 7)
		}
		if scenario == "bluetooth-l2cap" {
			typ, protocol = "l2cap_pinfo", 0
			pointee := ref("l2cap_chan")
			channel := ptr
			channel.Subtype = &pointee
			fields = map[string]symbols.Field{"bt": field(0, ref("bt_sock")), "chan": field(96, channel)}
			add("l2cap_chan", 16, map[string]symbols.Field{"src": field(0, ref("bdaddr_t")), "dst": field(6, ref("bdaddr_t")), "sport": field(12, base("u16")), "psm": field(14, base("u16"))})
			put(0x1d060, 0x1d700)
			copy(data[0x1d700:], []byte{1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1})
			put16(0x1d70c, 11)
			put16(0x1d70e, 12)
		} else {
			copy(data[0x1d060:], []byte{1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1})
		}
		if scenario == "bluetooth-hci" {
			typ, protocol = "hci_pinfo", 1
			fields = map[string]symbols.Field{"sk": field(0, ref("sock")), "hdev": field(96, ptr)}
			put(0x1d060, 0x1d700)
			add("hci_dev", 16, map[string]symbols.Field{"dev_name": field(0, array(16))})
			copy(data[0x1d700:], "hci0\x00")
		}
		add(typ, 112, fields)
		put16(0x1d048, protocol)
	case "xdp":
		put16(0x1d000, 44)
		add("xdp_sock", 112, map[string]symbols.Field{"sk": field(0, ref("sock")), "dev": field(96, ptr), "state": field(104, symbols.TypeRef{Kind: "enum", Name: "xdp_sock_state"})})
		table.Enums = map[string]symbols.Enumeration{"xdp_sock_state": {Base: "u32", Size: 4, Constants: map[string]json.Number{"XSK_READY": "2"}}}
		put(0x1d060, 0x1c300)
		put(0x1d068, 2)
		add("net_device", 24, map[string]symbols.Field{"name": field(0, array(16)), "xdp_prog": field(16, ptr)})
		copy(data[0x1c300:], "eth0\x00")
		put(0x1c310, 0x1d600)
		add("bpf_prog", 16, map[string]symbols.Field{"aux": field(8, ptr)})
		put(0x1d608, 0x1d680)
		add("bpf_prog_aux", 24, map[string]symbols.Field{"id": field(0, base("u32")), "name": field(8, array(16))})
		put(0x1d680, 33)
		copy(data[0x1d688:], "socket_xdp\x00")
	case "packet-device":
		put16(0x1d000, 17)
		add("packet_sock", 104, map[string]symbols.Field{"sk": field(0, ref("sock")), "ifindex": field(96, base("u32")), "num": field(100, base("u16"))})
		put(0x1d060, 2)
		put16(0x1d064, 0x300)
		add("net_device", 40, map[string]symbols.Field{"dev_list": field(0, ref("list_head")), "name": field(16, array(16)), "ifindex": field(32, base("u32"))})
		put(0x1c108, 0x1c300)
		put(0x1c110, 0x1c300)
		put(0x1c300, 0x1c108)
		put(0x1c308, 0x1c108)
		copy(data[0x1c310:], "eth0\x00")
		put(0x1c320, 2)

	case "bad-filter":
		put(0x1d050, 0x300000)
	case "cbpf":
		put(0x1d050, 0x1d600)
	case "ebpf", "old-ebpf", "reuseport":
		put(0x1d050, 0x1d600)
		add("sk_filter", 8, map[string]symbols.Field{"prog": field(0, ptr)})
		put(0x1d600, 0x1d680)
		add("bpf_prog", 16, map[string]symbols.Field{"type": field(0, base("u32")), "aux": field(8, ptr)})
		put(0x1d680, 1)
		put(0x1d688, 0x1d700)
		add("bpf_prog_aux", 24, map[string]symbols.Field{"id": field(0, base("u32")), "name": field(8, array(16))})
		put(0x1d700, 19)
		copy(data[0x1d708:], "capture\x00")
		if scenario == "old-ebpf" {
			delete(table.Types["bpf_prog"].Fields, "type")
			aux := table.Types["bpf_prog_aux"]
			aux.Fields["prog_type"] = field(4, base("u32"))
			table.Types["bpf_prog_aux"] = aux
			binary.LittleEndian.PutUint32(data[0x1d704:], 1)
		}
		if scenario == "reuseport" {
			put(0x1d058, 0x1d600)
			delete(table.Types["sk_filter"].Fields, "len")
			sock := table.Types["sock"]
			pointee := ref("sk_filter")
			pointer := ptr
			pointer.Subtype = &pointee
			sock.Fields["sk_reuseport_cb"] = field(88, pointer)
			table.Types["sock"] = sock
		}

	case "other-ns":
		put(0x1d030, 0x1c180)
	case "new-ns":
		delete(table.Types["net"].Fields, "proc_inum")
		add("ns_common", 8, map[string]symbols.Field{"inum": field(0, base("u64"))})
		net := table.Types["net"]
		net.Fields["ns"] = field(0, ref("ns_common"))
		table.Types["net"] = net
	case "old-ns":
		delete(table.Types["net"].Fields, "proc_inum")
	case "missing-bt":
		put16(0x1d000, 31)
	case "bad-backlink":
		put(0x1d040, 0)
	case "null-sk":
		put(0x180e0, 0)
	case "unreadable-sk":
		put(0x180e0, 0x300000)
	case "unknown-family":
		put16(0x1d000, 60)
	case "unknown-type":
		put16(0x1d04a, 99)
	}
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.Image, data, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLinuxSocketEndpointsAndRawEvidence(t *testing.T) {
	for _, scenario := range []string{"inet", "udp", "ipv6", "ipv6-pinfo", "unix", "abstract", "unix-peer", "netlink", "vsock", "packet", "cbpf", "ebpf", "old-ebpf", "reuseport", "other-ns", "new-ns", "old-ns", "unknown-type", "bluetooth-sco", "bluetooth-rfcomm", "bluetooth-l2cap", "bluetooth-hci", "xdp", "packet-device"} {
		t.Run(scenario, func(t *testing.T) {
			e := openLinuxELF(t, linuxSocketFixture(t, scenario), true)
			var row evidence.Row
			result, err := e.Run(context.Background(), "linux.sockstat", map[string]string{"pid": "100"}, engine.RunOptions{Emit: func(v evidence.Row) error { row = v; return nil }})
			if err != nil || result.Task.Rows != 1 || row.Cells["Offset"].String() != "0x000000000001d000" || row.Cells["FileOffset"].String() != "0x0000000000013100" {
				t.Fatal(result, row, err)
			}
			c := row.Cells
			switch scenario {
			case "ipv6", "ipv6-pinfo":
				if c["Source"].String() != "2001:db8::1" || c["Destination"].String() != "::2" {
					t.Fatal(c)
				}
			case "unix", "unix-peer":
				if c["Source"].String() != "/tmp/socket" || c["SourcePort"].String() != "124" {
					t.Fatal(c)
				}
				if scenario == "unix-peer" && (c["Destination"].String() != "/peer" || c["DestinationPort"].String() != "0") {
					t.Fatal(c)
				}
			case "abstract":
				if c["Source"].String() != `@a\x00b\x00\xff` || c["SourceEncoding"].String() != "abstract" || len(c["SourceRaw"].Data.([]byte)) != 6 {
					t.Fatal(c)
				}
			case "netlink":
				if c["Source"].String() != "groups:0x00000003" || c["Destination"].String() != "group:0x00000004" || c["SourcePort"].String() != "11" || c["DestinationPort"].String() != "22" {
					t.Fatal(c)
				}
			case "vsock":
				if c["Source"].String() != "2" || c["SourcePort"].String() != "1000" || c["Destination"].String() != "3" || c["DestinationPort"].String() != "2000" {
					t.Fatal(c)
				}
			case "packet":
				if c["Source"].String() != "ANY" || c["Proto"].String() != "ETH_P_ALL" {
					t.Fatal(c)
				}
			case "bluetooth-sco", "bluetooth-rfcomm", "bluetooth-l2cap":
				if c["Source"].String() != "06:05:04:03:02:01" || c["Destination"].String() != "01:02:03:04:05:06" {
					t.Fatal(c)
				}
			case "bluetooth-hci":
				if c["Source"].String() != "hci0" {
					t.Fatal(c)
				}
			case "xdp":
				if c["Source"].String() != "eth0" || c["State"].String() != "READY" || c["DestinationPort"].String() != "ebpf_prog_id:33" {
					t.Fatal(c)
				}
			case "packet-device":
				if c["Source"].String() != "eth0" {
					t.Fatal(c)
				}

			case "cbpf":
				if c["Filter"].String() != "filter_type=socket_filter,bpf_filter_type=cBPF" {
					t.Fatal(c)
				}
			case "ebpf", "old-ebpf", "reuseport":
				if !strings.Contains(c["Filter"].String(), "bpf_filter_id=19,bpf_filter_name=capture") {
					t.Fatal(c)
				}
			case "old-ns":
				if c["NetNS"].Reason != "namespace_inode_not_in_layout" {
					t.Fatal(c)
				}
			case "unknown-type":
				if c["Type"].Reason != "unknown_socket_type" {
					t.Fatal(c)
				}
			default:
				if c["Source"].String() != "1.2.3.4" || c["Destination"].String() != "127.0.0.1" || c["SourcePort"].String() != "443" || c["DestinationPort"].String() != "8080" {
					t.Fatal(c)
				}
			}
			if scenario == "other-ns" && c["TaskNet"].String() == c["SocketNet"].String() {
				t.Fatal("task/socket namespace distinction collapsed")
			}
		})
	}
}

func TestLinuxSocketFailuresFilteringAndCancel(t *testing.T) {
	for _, scenario := range []string{"bad-unix-length", "missing-bt", "bad-backlink", "null-sk", "unreadable-sk", "unknown-family", "truncated-ipv6", "bad-filter"} {
		t.Run(scenario, func(t *testing.T) {
			e := openLinuxELF(t, linuxSocketFixture(t, scenario), true)
			var row evidence.Row
			result, err := e.Run(context.Background(), "linux.sockstat", nil, engine.RunOptions{Emit: func(v evidence.Row) error { row = v; return nil }})
			if err == nil || result.Task.Rows != 1 || result.Task.State != "failed" || row.Cells["Error"].Error == "" {
				t.Fatal(result, row, err)
			}
			if scenario == "truncated-ipv6" {
				if row.Cells["Source"].Kind != "missing" || len(row.Cells["SourceRaw"].Data.([]byte)) != 8 {
					t.Fatal(row)
				}
			}
		})
	}
	e := openLinuxELF(t, linuxSocketFixture(t, "inet"), true)
	for _, params := range []map[string]string{{"netns": "4026531993"}, {"netns": "0"}} {
		r, err := e.Run(context.Background(), "linux.sockstat", params, engine.RunOptions{})
		if err != nil || r.Task.Rows != 1 {
			t.Fatal(r, err)
		}
	}
	for _, params := range []map[string]string{{"netns": "1"}, {"pid": "999"}} {
		r, err := e.Run(context.Background(), "linux.sockstat", params, engine.RunOptions{})
		if err != nil || r.Task.Rows != 0 {
			t.Fatal(r, err)
		}
	}
	if _, err := e.Run(context.Background(), "linux.sockstat", map[string]string{"netns": "bad"}, engine.RunOptions{}); err == nil {
		t.Fatal("invalid namespace filter accepted")
	}
	old := openLinuxELF(t, linuxSocketFixture(t, "old-ns"), true)
	r, err := old.Run(context.Background(), "linux.sockstat", map[string]string{"netns": "1"}, engine.RunOptions{})
	if err == nil || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	sentinel := errors.New("output stop")
	r, err = e.Run(context.Background(), "linux.sockstat", nil, engine.RunOptions{Emit: func(evidence.Row) error { return sentinel }})
	if !errors.Is(err, sentinel) || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err = e.Run(ctx, "linux.sockstat", nil, engine.RunOptions{Emit: func(evidence.Row) error { cancel(); return nil }})
	if !errors.Is(err, context.Canceled) || r.Task.Rows != 1 {
		t.Fatal(r, err)
	}
}

func TestLinuxSocket32BitDescriptorAndObjectPointers(t *testing.T) {
	for _, mode := range []string{"x86", "pae"} {
		t.Run(mode, func(t *testing.T) {
			f := linuxSocketFixture(t, "inet")
			table, err := symbols.Load(f.Symbols)
			if err != nil {
				t.Fatal(err)
			}
			pointer := table.Bases["pointer"]
			pointer.Size = 4
			table.Bases["pointer"] = pointer
			list := table.Types["list_head"]
			prev := list.Fields["prev"]
			prev.Offset = 4
			list.Fields["prev"] = prev
			table.Types["list_head"] = list
			data, err := os.ReadFile(f.Image)
			if err != nil {
				t.Fatal(err)
			}
			clear(data[0x1000:0x4000])
			if mode == "x86" {
				binary.LittleEndian.PutUint32(data[0x1000:], 0x83)
			} else {
				binary.LittleEndian.PutUint64(data[0x1000:], 0x2001)
				binary.LittleEndian.PutUint64(data[0x2000:], 0x83)
			}
			for _, v := range []struct{ at, next, prev uint32 }{{0x9000, 0xa000, 0xb000}, {0xa000, 0xb000, 0x9000}, {0xb000, 0x9000, 0xa000}, {0xa060, 0xa060, 0xa060}, {0xb060, 0xb060, 0xb060}} {
				binary.LittleEndian.PutUint32(data[v.at:], v.next)
				binary.LittleEndian.PutUint32(data[v.at+4:], v.prev)
			}
			clear(data[0x1f000:0x1f020])
			binary.LittleEndian.PutUint32(data[0x1f000:], 0x13000)
			binary.LittleEndian.PutUint32(data[0x1f008:], 0x13100)
			encoded, err := table.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.Symbols, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.Image, data, 0600); err != nil {
				t.Fatal(err)
			}
			e, err := engine.Open(context.Background(), engine.Config{Image: f.Image, Symbols: f.Symbols, DTB: f.DTB, Arch: mode, OS: "linux", Offline: true})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			var row evidence.Row
			r, err := e.Run(context.Background(), "linux.sockstat", nil, engine.RunOptions{Emit: func(v evidence.Row) error { row = v; return nil }})
			if err != nil || r.Task.Rows != 1 || row.Cells["SourcePort"].String() != "443" {
				t.Fatal(r, row, err)
			}
		})
	}
}
