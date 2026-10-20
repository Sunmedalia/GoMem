#!/usr/bin/env python3
"""Independent selected RAW/legacy Linux x64 socket oracle.

Reuses only the independent raw page walker and ISF field resolver, verifies the
full descriptor set with verify_lsof, then identifies sockets from raw file ops.
Decodes socket ownership, bitfields, INET endpoints and length-delimited UNIX
names directly. Modern filter/family layouts are outside this corpus oracle.
"""
import argparse
import base64
import collections
import ipaddress
import json
from pathlib import Path

from verify_elf_extractions import RawX64, load_isf
from verify_lsof import resolve_field, verify as verify_fds


def abstract_display(raw):
    if raw[:1] == b'\0':
        return '@' + ''.join(chr(b) if 0x21 <= b <= 0x7e and b != 92 else f'\\x{b:02x}' for b in raw[1:])
    return raw.split(b'\0', 1)[0].decode('utf-8', errors='replace')


def verify(native, descriptors, active, image, isf, dtb):
    descriptor_oracle = verify_fds(descriptors, active, image, isf, dtb)
    table, _ = load_isf(isf)
    space = RawX64(image, dtb)
    rows = [json.loads(line) for line in native.read_text().splitlines()]
    fd_rows = [json.loads(line) for line in descriptors.read_text().splitlines()]
    build = descriptor_oracle['engine_build_sha256']

    def field(typ, path):
        offset = 0
        parts = path.split('.')
        for name in parts:
            f = resolve_field(table, typ, name)
            offset += f['offset']
            typ = f['type'].get('name')
        return dict(f, offset=offset)

    def has(typ, path):
        try:
            field(typ, path)
            return True
        except KeyError:
            return False

    def scalar(address, typ, path):
        f = field(typ, path)
        ref = f['type']
        bits = ref if ref['kind'] == 'bitfield' else None
        if bits:
            ref = bits['type']
        width = 8 if ref['kind'] == 'pointer' else table['base_types'][ref['name']]['size']
        v = int.from_bytes(space.read(address + f['offset'], width)[0], 'little')
        if bits:
            v = (v >> bits['bit_position']) & ((1 << bits['bit_length']) - 1)
        return v

    def raw_field(address, typ, path, length):
        return space.read(address + field(typ, path)['offset'], length)[0]

    def container(sock, typ):
        return sock - field(typ, 'sk')['offset']

    def equal(c, key, expected):
        if c[key].get('value') != expected:
            raise ValueError(f'independent socket field differs: {key}')

    def number(c, key, expected):
        v = c[key]
        if int(v['value'], 16 if v['kind'] == 'address' else 10) != expected:
            raise ValueError('independent numeric socket field differs: ' + key)

    def check_raw(c, key, expected):
        if base64.b64decode(c[key]['value'], validate=True) != expected:
            raise ValueError('raw endpoint bytes differ: ' + key)

    def unix_name(sock):
        at = scalar(container(sock, 'unix_sock'), 'unix_sock', 'addr')
        if not at:
            return None
        length = scalar(at, 'unix_address', 'len')
        start = field('sockaddr_un', 'sun_path')['offset']
        if not start <= length <= 110:
            raise ValueError('invalid selected UNIX address length')
        return space.read(at + field('unix_address', 'name')['offset'] + start, length - start)[0]

    def sock_inode(sock):
        ptr = scalar(sock, 'sock', 'sk_socket')
        if not ptr:
            return 0
        address = ptr - field('socket_alloc', 'socket')['offset'] + field('socket_alloc', 'vfs_inode')['offset']
        return scalar(address, 'inode', 'i_ino')

    try:
        ops = {table['symbols'][name]['address'] for name in ('socket_file_ops', 'sockfs_dentry_operations')}
        expected = {}
        for fd in fd_rows:
            c = fd['cells']
            pointer = int(c['Offset']['value'], 16)
            if scalar(pointer, 'file', 'f_op') not in ops:
                continue
            dentry = scalar(pointer, 'file', 'f_path.dentry')
            inode = scalar(dentry, 'dentry', 'd_inode')
            sock_alloc = inode - field('socket_alloc', 'vfs_inode')['offset']
            socket = sock_alloc + field('socket_alloc', 'socket')['offset']
            sock = scalar(socket, 'socket', 'sk')
            key = tuple(c[k]['value'] for k in ('PID', 'TID', 'FD'))
            expected[key] = (fd, socket, sock)
        found, families, abstract, raw_bytes, bt_gaps, cbpf = set(), collections.Counter(), 0, 0, 0, 0
        for row in rows:
            c, p = row['cells'], row['provenance']
            if p['engine_build'] != build or p['image_sha256'] != descriptor_oracle['image_sha256'] or p['symbols_sha256'] != descriptor_oracle['symbols_sha256']:
                raise ValueError('socket image/symbol/build provenance differs from independent descriptor check')
            key = tuple(c[k]['value'] for k in ('PID', 'TID', 'FD'))
            if key in found or key not in expected:
                raise ValueError('unexpected/duplicate socket descriptor')
            found.add(key)
            fd, socket, sock = expected[key]
            number(c, 'Socket', socket)
            number(c, 'Offset', sock)
            if scalar(sock, 'sock', 'sk_socket') != socket:
                raise ValueError('socket inode ownership differs')
            for name in ('FileOffset', 'Dentry', 'InodeOffset', 'Slot'):
                source = 'Offset' if name == 'FileOffset' else name
                number(c, name, int(fd['cells'][source]['value'], 16))
            for name in ('TaskIdentity', 'ProcessIdentity'):
                equal(c, name, fd['cells'][name]['value'])
            family = scalar(sock, 'sock', '__sk_common.skc_family')
            families[str(family)] += 1
            number(c, 'FamilyRaw', family)
            number(c, 'TypeRaw', scalar(sock, 'sock', 'sk_type'))
            number(c, 'ProtocolRaw', scalar(sock, 'sock', 'sk_protocol'))
            number(c, 'StateRaw', scalar(sock, 'sock', '__sk_common.skc_state'))
            task = int(c['TaskOffset']['value'], 16)
            nsproxy = scalar(task, 'task_struct', 'nsproxy')
            task_net = scalar(nsproxy, 'nsproxy', 'net_ns')
            number(c, 'TaskNet', task_net)
            if family in (2, 10):
                base = container(sock, 'inet_sock')
                for key, paths in (('SourcePort', ('sport', 'inet_sport')), ('DestinationPort', ('sk.__sk_common.skc_portpair', 'dport', 'inet_dport', 'sk.__sk_common.skc_dport'))):
                    path = next(path for path in paths if has('inet_sock', path))
                    raw = raw_field(base, 'inet_sock', path, 2)
                    equal(c, key, str(int.from_bytes(raw, 'big')))
                    check_raw(c, key + 'Raw', raw)
                for key in ('Source', 'Destination'):
                    typ, at = 'inet_sock', base
                    if family == 2:
                        paths = ('rcv_saddr', 'inet_rcv_saddr', 'sk.__sk_common.skc_rcv_saddr') if key == 'Source' else ('daddr', 'inet_daddr', 'sk.__sk_common.skc_daddr')
                        path = next(path for path in paths if has(typ, path))
                        if key == 'Destination' and scalar(at, typ, path) == 0 and has(typ, 'sk.__sk_common.skc_daddr'):
                            path = 'sk.__sk_common.skc_daddr'
                        length = 4
                    else:
                        length = 16
                        if has(typ, 'pinet6'):
                            at, typ = scalar(base, typ, 'pinet6'), 'ipv6_pinfo'
                            path = 'saddr' if key == 'Source' else 'daddr'
                            if key == 'Destination' and not has(typ, path):
                                at, typ, path = base, 'inet_sock', 'sk.__sk_common.skc_v6_daddr'
                        else:
                            path = 'sk.__sk_common.skc_v6_rcv_saddr' if key == 'Source' else 'sk.__sk_common.skc_v6_daddr'
                    raw = raw_field(at, typ, path, length)
                    check_raw(c, key + 'Raw', raw)
                    addr = ipaddress.ip_address(raw)
                    text = str(addr)
                    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                        text = '::ffff:' + str(addr.ipv4_mapped)
                    equal(c, key, text)
                    raw_bytes += len(raw)
            elif family == 1:
                peer = scalar(container(sock, 'unix_sock'), 'unix_sock', 'peer')
                for key, ptr in (('Source', sock), ('Destination', peer)):
                    if not ptr:
                        if c[key]['kind'] != 'missing' or c[key]['reason'] != 'no_peer':
                            raise ValueError('missing UNIX peer was fabricated')
                        continue
                    raw = unix_name(ptr)
                    if raw is None:
                        if c[key]['kind'] != 'missing' or c[key]['reason'] != 'not_bound':
                            raise ValueError('unbound UNIX endpoint was fabricated')
                    else:
                        equal(c, key, abstract_display(raw))
                        check_raw(c, key + 'Raw', raw)
                        abstract += raw[:1] == b'\0'
                        raw_bytes += len(raw)
                    equal(c, key + 'Port', str(sock_inode(ptr)))
            elif family == 17:
                packet = container(sock, 'packet_sock')
                index = scalar(packet, 'packet_sock', 'ifindex')
                if index >= 1 << 31:
                    index -= 1 << 32
                if index <= 0:
                    equal(c, 'Source', 'ANY')
                else:
                    namespace = int(c['DeviceNamespace']['value'], 16)
                    expected_net = scalar(sock, 'sock', '__sk_common.skc_net.net') if has('sock', '__sk_common.skc_net.net') else scalar(sock, 'sock', '__sk_common.skc_net')
                    if not expected_net:
                        expected_net = task_net
                    if namespace != expected_net:
                        raise ValueError('packet interface namespace differs')
                    head = namespace + field('net', 'dev_base_head')['offset']
                    link = space.uint(head)
                    seen, name = set(), None
                    while link != head:
                        if not link or link in seen or len(seen) > 131072:
                            raise ValueError('invalid packet namespace interface list')
                        seen.add(link)
                        device = link - field('net_device', 'dev_list')['offset']
                        if scalar(device, 'net_device', 'ifindex') == index:
                            count = field('net_device', 'name')['type']['count']
                            name = raw_field(device, 'net_device', 'name', count).split(b'\0')[0].decode('utf-8')
                        link = space.uint(link)
                    equal(c, 'Source', name)
            elif family == 31 and 'bt_sock' not in table['user_types']:
                bt_gaps += 1
                if c['Source']['kind'] != 'missing' or c['Source']['reason'] != 'bluetooth_layout_unavailable' or not c['Error'].get('error'):
                    raise ValueError('missing Bluetooth layout not retained')
            filter_ptr = scalar(sock, 'sock', 'sk_filter')
            if filter_ptr:
                cbpf += 1
                equal(c, 'Filter', 'filter_type=socket_filter,bpf_filter_type=cBPF')
        if found != set(expected):
            raise ValueError('socket set omits captured descriptor-backed sockets')
        return dict(verified=True, scope='selected RAW legacy Linux/x64 descriptor socket set, ownership, numeric fields, INET/UNIX bytes, packet interface and cBPF presence; netlink endpoints and modern layouts excluded', engine_build_sha256=build, descriptor_oracle=descriptor_oracle, sockets=len(found), families=dict(families), inet_sockets=sum(families[str(v)] for v in (2, 10)), abstract_endpoints_preserved=abstract, endpoint_address_bytes_verified=raw_bytes, missing_bluetooth_layouts_retained=bt_gaps, cbpf_filters_verified=cbpf, packet_interfaces_verified=families['17'])
    finally:
        space.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'descriptors', 'active', 'image'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--isf', required=True)
    p.add_argument('--kernel-dtb', type=lambda s: int(s, 0), required=True)
    args = p.parse_args()
    print(json.dumps(verify(args.native, args.descriptors, args.active, args.image, args.isf, args.kernel_dtb), indent=2))


if __name__ == '__main__':
    main()
