#!/usr/bin/env python3
"""Execute pinned Sockscan and SockHandlers over physically distinct paged objects."""
import argparse
import base64
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-sockscan-oracle.json"

def fixture(width=8, scenario='normal'):
    base = lambda n: dict(kind='base', name=n)
    obj = lambda n: dict(kind='struct', name=n)
    ptr = lambda n: dict(kind='pointer', subtype=obj(n))
    field = lambda off, t: dict(offset=off, type=t)
    rec = lambda sz, fs: dict(kind='struct', size=sz, fields=fs)
    arr = lambda n, t: dict(kind='array', count=n, subtype=t)
    types = {'list_head': rec(width * 2, dict(next=field(0, ptr('list_head')), prev=field(width, ptr('list_head')))), 'task_struct': rec(8, dict(nsproxy=field(0, ptr('nsproxy')))), 'nsproxy': rec(8, dict(net_ns=field(0, ptr('net')))), 'net': rec(48, dict(list=field(0, obj('list_head')), dev_base_head=field(16, obj('list_head')), proc_inum=field(32, base('u32')))), 'sock_common': rec(48, dict(skc_family=field(0, base('u16')), skc_state=field(2, base('u8')), skc_rcv_saddr=field(4, base('u32')), skc_daddr=field(8, base('u32')), skc_portpair=field(12, base('u32')))), 'sock': rec(96, dict(__sk_common=field(0, obj('sock_common')), sk_socket=field(64, ptr('socket')), sk_protocol=field(72, base('u16')), sk_type=field(74, base('u16')), sk_filter=field(80, ptr('sk_filter')), sk_destruct=field(88, ptr('void')))), 'socket': rec(16, dict(sk=field(0, ptr('sock')), state=field(8, base('u32')))), 'socket_alloc': rec(48, dict(socket=field(0, obj('socket')), vfs_inode=field(32, obj('inode')))), 'inode': rec(16, dict(i_ino=field(0, base('u32')))), 'file': rec(32, dict(f_path=field(8, obj('path')), f_op=field(24, ptr('void')))), 'path': rec(8, dict(dentry=field(0, ptr('dentry')))), 'dentry': rec(8, dict(d_inode=field(0, ptr('inode')))), 'unix_sock': rec(112, dict(sk=field(0, obj('sock')), addr=field(96, ptr('unix_address')), peer=field(104, ptr('sock')))), 'unix_address': rec(8, dict(len=field(0, base('u32')), name=field(8, arr(0, obj('sockaddr_un'))))), 'sockaddr_un': rec(110, dict(sun_family=field(0, base('u16')), sun_path=field(2, arr(108, base('char'))))), 'inet_sock': rec(104, dict(sk=field(0, obj('sock')), inet_sport=field(96, base('u16')))), 'void': rec(1, {}), 'sk_filter': rec(8, dict(len=field(0, base('u32'))))}
    for n in ('net_device', 'in_device', 'in_ifaddr', 'inet6_dev', 'inet6_ifaddr'):
        types[n] = rec(64, {})
    types['net_device'] = rec(64, dict(dev_list=field(0, obj('list_head')), ifindex=field(16, base('u32')), name=field(24, arr(16, base('char')))))
    data = bytearray(524288)

    def put(at, v, size=width):
        data[at:at + size] = v.to_bytes(size, 'little')

    def list_head(head, links):
        chain = [head] + links
        for i, at in enumerate(chain):
            put(at, chain[(i + 1) % len(chain)])
            put(at + width, chain[(i - 1) % len(chain)])
    put(65536, 65792)
    put(65792, 69888)
    put(69920, 99, 4)
    list_head(69632, [69888])
    list_head(69904, [])
    for i, at in enumerate((98304, 102400)):
        put(at, 1, 2)
        put(at + 2, 1 if i == 0 else 10, 1)
        put(at + 64, 180224 + i * 256)
        put(at + 74, 1, 2)
        put(at + 88, 34816)
        put(at + 96, 184320 + i * 256)
        put(at + 104, 167936 if i == 0 else 0)
        put(114688 + i * 256, 163840 + i * 4096)
        put(114696 + i * 256, 3, 4)
        put(114720 + i * 256, 100 + i, 4)
        put(106504 + i * 256, 176128 + i * 256)
        put(106520 + i * 256, 35072)
        put(110592 + i * 256, 180256 + i * 256)
        name = (b'/socket-a' if i == 0 else b'/socket-b') + b'\x00'
        put(118784 + i * 256, len(name) + 2, 4)
        put(118792 + i * 256, 1, 2)
        data[118794 + i * 256:118794 + i * 256 + len(name)] = name
    if width == 8:
        put(458752, 462851, 8)
        put(462848, 466947, 8)
        put(466944, 471043, 8)
    else:
        put(458752, 471043, 4)
    for p in range(128):
        put(471040 + p * width, (p - 16 if 40 <= p < 48 else p) * 4096 | 3)
    symbols = {'init_task': dict(address=65536, type=obj('task_struct')), 'net_namespace_list': dict(address=69632, type=obj('list_head')), 'sock_def_destruct': dict(address=34816, type=base('char')), 'socket_file_ops': dict(address=35072, type=base('char'))}
    if scenario == 'file-only':
        symbols.pop('sock_def_destruct')
    if scenario == 'destructor-only':
        symbols.pop('socket_file_ops')
    if scenario == 'missing-symbols':
        symbols.pop('sock_def_destruct')
        symbols.pop('socket_file_ops')
    if scenario == 'shared-source':
        symbols['socket_file_ops']['address'] = 34816
        for at in (106520, 106776):
            put(at, 34816)
    if scenario == 'file-first':
        data[94208:94240] = data[106496:106528]
        data[106496:106528] = bytes(32)
    if scenario == 'unknown':
        put(122880, 65535, 2)
        put(122954, 33064, 2)
        put(122944, 180736)
        put(115208, 999, 4)
        put(122968, 34816)
    if scenario in ('inet', 'inet-zero'):
        for at in (98304, 102400):
            put(at, 2, 2)
            put(at + 72, 6, 2)
            data[at + 4:at + 8] = b'\x01\x02\x03\x04'
            data[at + 8:at + 12] = b'\x7f\x00\x00\x01'
            data[at + 12:at + 14] = 8080 .to_bytes(2, 'big')
            data[at + 96:at + 98] = 443 .to_bytes(2, 'big')
        if scenario == 'inet-zero':
            for i, at in enumerate((98304, 102400)):
                put(at + 74, 2, 2)
                data[at + 4:at + 16] = bytes(12)
                put(at + 96, 0, 2)
                put(114696 + i * 256, 1, 4)
    if scenario == 'netlink':
        types['module'] = rec(16, dict(name=field(0, arr(16, base('char')))))
        types['netlink_sock'] = rec(128, dict(sk=field(0, obj('sock')), pid=field(96, base('u32')), dst_pid=field(100, base('u32')), groups=field(104, dict(kind='pointer', subtype=base('u32'))), dst_group=field(112, base('u32')), module=field(120, ptr('module'))))
        for i, at in enumerate((98304, 102400)):
            put(at, 16, 2)
            put(at + 72, 0, 2)
            put(at + 96, 10 + i, 4)
            put(at + 100, 20 + i, 4)
            put(at + 104, 184320 + i * 256)
            put(at + 112, 5 + i, 4)
            put(at + 120, 188416)
            put(118784 + i * 256, 1 + i, 4)
        data[122880:122896] = b'test-module\x00'.ljust(16, b'\x00')
    if scenario == 'unaligned':
        content = bytes(data[98304:98416])
        data[98304:98419] = bytes(115)
        data[98307:98419] = content
        put(114688, 163843)
    if scenario == 'cross-chunk':
        content = bytes(data[98304:98416])
        data[98304:98416] = bytes(112)
        data.extend(bytes(1572864))
        data[1048484:1048484 + len(content)] = content
        put(471040 + 40 * width, 1044483)
        put(114688, 167844)
    if scenario in ('cbpf', 'reuseport'):
        for at in (98304, 102400):
            put(at + 80, 192512)
        put(126976, 2, 4)
        if scenario == 'reuseport':
            types['sock']['fields']['sk_reuseport_cb'] = field(56, ptr('sk_filter'))
            for at in (98304, 102400):
                put(at + 56, 192768)
            put(127232, 3, 4)
    enums = {}
    if scenario in ('ipv6', 'ipv6-common-destination'):
        types['ipv6_pinfo'] = rec(32, dict(saddr=field(0, arr(16, base('u8'))), daddr=field(16, arr(16, base('u8')))))
        if scenario == 'ipv6-common-destination':
            del types['ipv6_pinfo']['fields']['daddr']
        types['inet_sock'] = rec(112, dict(sk=field(0, obj('sock')), pinet6=field(96, ptr('ipv6_pinfo')), inet_sport=field(104, base('u16'))))
        types['sock_common']['fields'].update(skc_v6_rcv_saddr=field(16, arr(16, base('u8'))), skc_v6_daddr=field(32, arr(16, base('u8'))))
        import ipaddress
        for i, at in enumerate((0x18000, 0x19000)):
            put(at, 10, 2)
            put(at + 72, 6, 2)
            put(at + 96, 0x2d000 + i * 0x100)
            data[at + 104:at + 106] = (443).to_bytes(2, 'big')
            data[at + 12:at + 14] = (8080).to_bytes(2, 'big')
            for delta, value in ((0, f'2001:db8::{i+1}'), (16, f'2001:db8::{i+3}')):
                data[0x1d000+i*0x100+delta:0x1d000+i*0x100+delta+16] = ipaddress.IPv6Address(value).packed
            data[at+32:at+48] = ipaddress.IPv6Address(f'2001:db8::{i+3}').packed
    if scenario in ('packet', 'packet-any'):
        types['packet_sock'] = rec(104, dict(sk=field(0, obj('sock')), ifindex=field(96, base('u32')), num=field(100, base('u16'))))
        for at in (0x18000, 0x19000):
            put(at, 17, 2)
            put(at+96, 3 if scenario == 'packet' else 0, 4)
            data[at+100:at+102] = (0x800).to_bytes(2, 'big')
        list_head(0x11110, [0x13000])
        put(0x13010, 3, 4)
        data[0x13018:0x13028] = b'eth-fixture\0'.ljust(16, b'\0')
    if scenario == 'vsock':
        types['sockaddr_vm'] = rec(8, dict(svm_cid=field(0, base('u32')), svm_port=field(4, base('u32'))))
        types['vsock_sock'] = rec(112, dict(sk=field(0, obj('sock')), local_addr=field(96, obj('sockaddr_vm')), remote_addr=field(104, obj('sockaddr_vm'))))
        for at in (0x18000, 0x19000):
            put(at, 40, 2)
            for off, value in ((96, 3), (100, 123), (104, 4), (108, 456)):
                put(at+off, value, 4)
    if scenario.startswith('bluetooth-'):
        protocols = {'l2cap': 0, 'l2cap-pointer': 0, 'hci': 1, 'sco': 2, 'rfcomm': 3}
        which = scenario[len('bluetooth-'):]
        proto = protocols[which]
        types['bt_sock'] = rec(96, dict(sk=field(0, obj('sock'))))
        types['bdaddr_t'] = rec(6, dict(b=field(0, arr(6, base('u8')))))
        types['l2cap_chan'] = rec(16, dict(src=field(0, obj('bdaddr_t')), dst=field(6, obj('bdaddr_t')), sport=field(12, base('u16')), psm=field(14, base('u16'))))
        if proto == 0:
            types['l2cap_pinfo'] = rec(112, dict(bt=field(0, obj('bt_sock')), chan=field(96, ptr('l2cap_chan') if which == 'l2cap-pointer' else obj('l2cap_chan'))))
        elif proto == 1:
            types['hci_pinfo'] = rec(104, dict(bt=field(0, obj('bt_sock')), hdev=field(96, ptr('hci_dev'))))
            types['hci_dev'] = rec(16, dict(dev_name=field(0, arr(16, base('char')))))
            data[0x1e000:0x1e010] = b'hci-fixture\0'.ljust(16, b'\0')
        else:
            types['sco_pinfo' if proto == 2 else 'rfcomm_pinfo'] = rec(112, dict(bt=field(0, obj('bt_sock')), src=field(96, obj('bdaddr_t')), dst=field(102, obj('bdaddr_t')), channel=field(108, base('u8'))))
        for at in (0x18000, 0x19000):
            put(at, 31, 2)
            put(at+72, proto, 2)
            if proto == 1:
                put(at+96, 0x2e000)
                continue
            address = at+96
            if which == 'l2cap-pointer':
                put(address, 0x2e000)
                address = 0x1e000
            data[address:address+12] = bytes(range(1, 13))
            put(address+12, 17 if proto == 0 else 7, 2)
            put(address+14, 25, 2)
    if scenario in ('ebpf', 'ebpf-legacy', 'ebpf-unknown', 'xdp'):
        enums['bpf_prog_type'] = dict(base='u32', size=4, constants={'BPF_PROG_TYPE_UNSPEC': 0, 'BPF_PROG_TYPE_SOCKET_FILTER': 1, 'BPF_PROG_TYPE_KPROBE': 2})
        types['sk_filter'] = rec(width, dict(prog=field(0, ptr('bpf_prog'))))
        types['bpf_prog'] = rec(16, dict(type=field(0, dict(kind='enum', name='bpf_prog_type')), aux=field(8, ptr('bpf_prog_aux'))))
        types['bpf_prog_aux'] = rec(24, dict(id=field(0, base('u32')), name=field(8, arr(16, base('char')))))
        if scenario == 'ebpf-legacy':
            del types['bpf_prog']['fields']['type']
            types['bpf_prog_aux']['fields']['prog_type'] = field(4, dict(kind='enum', name='bpf_prog_type'))
            put(0x1f204, 1, 4)
        for at in (0x18000, 0x19000):
            put(at+80, 0x2f000)
        put(0x1f000, 0x2f100)
        put(0x1f100, 2 if scenario == 'ebpf-unknown' else 1, 4)
        put(0x1f108, 0x2f200)
        put(0x1f200, 42, 4)
        data[0x1f208:0x1f218] = b'filter-prog\0'.ljust(16, b'\0')
        if scenario == 'xdp':
            enums['xdp_state'] = dict(base='u32', size=4, constants={'XSK_READY': 1, 'XSK_BOUND': 2})
            types['xdp_sock'] = rec(112, dict(sk=field(0, obj('sock')), dev=field(96, ptr('net_device')), state=field(104, dict(kind='enum', name='xdp_state'))))
            types['net_device']['fields']['xdp_prog'] = field(48, ptr('bpf_prog'))
            for at in (0x18000, 0x19000):
                put(at, 44, 2)
                put(at+96, 0x2e000)
                put(at+104, 2, 4)
            data[0x1e018:0x1e028] = b'xdp-fixture\0'.ljust(16, b'\0')
            put(0x1e030, 0x2f100)
    isf = dict(metadata={'format': '6.2.0'}, base_types={n: dict(kind='int' if n != 'char' else 'char', size=s, endian='little', signed=False) for n, s in [('pointer', width), ('char', 1), ('u8', 1), ('u16', 2), ('u32', 4)]}, user_types=types, enums=enums, symbols=symbols)
    banner = b"Linux version 6.1.0-gomem (synthetic physical socket fixture) #1 SMP\0"
    data[0x8000:0x8000+len(banner)] = banner
    isf["symbols"]["linux_banner"] = dict(address=0x8000, type=base("char"), constant_data=base64.b64encode(banner).decode())
    return (isf, bytes(data))

def run(width, scenario):
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.linux import extensions
    from volatility3.framework.symbols.linux.extensions import network as net_extensions
    from volatility3.plugins.linux.sockscan import Sockscan
    isf, data = fixture(width, scenario)
    ctx = contexts.Context()
    ctx.layers.add_layer(BufferDataLayer(ctx, 'physical', 'physical', data))
    ctx.config['memory.memory_layer'] = 'physical'
    ctx.config['memory.page_map_offset'] = 458752
    ctx.config['memory.kernel_virtual_offset'] = 0
    ctx.layers.add_layer((Intel32e if width == 8 else Intel)(ctx, 'memory', 'memory'))
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'kernel.json'
        p.write_text(json.dumps(isf))
        ctx.symbol_space.append(IntermediateSymbolTable(ctx, 'symbols', 'kernel', p.as_uri(), class_types={'list_head': extensions.list_head, 'file': extensions.struct_file, **{name: getattr(extensions,name) for name in ('bpf_prog','bpf_prog_aux') if name in isf['user_types']}, **{name:getattr(net_extensions,name) for name in ('net','net_device','socket','sock','inet_sock','unix_sock','netlink_sock','vsock_sock','packet_sock','bt_sock','xdp_sock') if name in isf['user_types']}}))
        ctx.module('kernel', 'memory', 0)
        methods = {n: getattr(Sockscan, n) for n in ('_canonicalize_symbol_addrs', '_find_memory_layer_name', '_find_file_ops_needles', '_find_sk_destruct_needles', '_walk_file_ops_needles', '_extract_sock_fields')}
        cls = type('Runner', (), methods)
        runner = cls()
        runner.context = ctx
        runner._progress_callback = None
        rows = list(Sockscan._generator(runner, 'kernel'))
        from volatility3.framework import interfaces
        normalized = [[None if isinstance(x, interfaces.renderers.BaseAbsentValue) else x for x in row] for _, row in rows]
        native_rows = [list(row) for row in normalized]
        if scenario.startswith('ipv6'):
            import socket
            for row in native_rows:
                physical_sock = ctx.object('kernel!inet_sock', layer_name='physical', native_layer_name='memory', offset=int(row[0]))
                info = physical_sock.pinet6.dereference()
                for column, member in ((4, 'saddr'), (6, 'daddr')):
                    if not info.has_member(member):
                        address = physical_sock.sk.__sk_common.skc_v6_daddr
                    else:
                        address = getattr(info, member)
                    raw = ctx.layers[address.vol.layer_name].read(address.vol.offset, 16)
                    row[column] = socket.inet_ntop(socket.AF_INET6, raw)

    writes = []
    at = 0
    while at < len(data):
        if data[at] == 0:
            at += 1
            continue
        start = at
        while at < len(data) and data[at] != 0:
            at += 1
        writes.append([start, data[start:at].hex()])
    return dict(width=width, scenario=scenario, isf=isf, size=len(data), writes=writes, rows=normalized, native_rows=native_rows)

def generate(source):
    if sys.platform != "linux":
        raise ValueError("sockscan baseline oracle requires Linux: upstream uses host AF_INET6; use a Linux container on other hosts")
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires locked unmodified source")
    sys.path.insert(0, str(source))
    scenarios = ("normal", "file-only", "destructor-only", "missing-symbols", "shared-source", "file-first", "unknown", "inet", "inet-zero", "netlink", "unaligned", "cross-chunk", "cbpf", "reuseport", "ipv6", "ipv6-common-destination", "packet", "packet-any", "vsock", "bluetooth-l2cap", "bluetooth-l2cap-pointer", "bluetooth-hci", "bluetooth-sco", "bluetooth-rfcomm", "ebpf", "ebpf-legacy", "ebpf-unknown", "xdp")
    cases = [run(width, scenario) for width in (4, 8) for scenario in scenarios]
    return json.dumps(dict(commit=COMMIT, scope="Unmodified Sockscan._generator and helpers, actual SockHandlers and file/list/network extensions on Intel-paged byte-backed data; native pointer targets differ from physical roots", cases=cases), indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("sockscan oracle differs")
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual paged socket scan cases verified")


if __name__ == "__main__":
    main()
