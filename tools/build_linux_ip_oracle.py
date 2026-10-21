#!/usr/bin/env python3
"""Exercise pinned interface flag, IP, scope and IPv4 chain helpers."""
import argparse
import json
import ipaddress
from pathlib import Path
import sys
from types import SimpleNamespace
from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-ip-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('IP oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.framework.symbols.linux.extensions.network import net_device, inet6_ifaddr, in_device
    from volatility3.framework.constants.linux import NET_DEVICE_FLAGS
    from volatility3.framework.renderers.conversion import convert_ipv4, convert_ipv6

    bits = {'__LINK_STATE_START': 0, '__LINK_STATE_NOCARRIER': 1, '__LINK_STATE_DORMANT': 2}

    class Device:
        is_running = net_device.is_running
        is_carrier_ok = net_device.is_carrier_ok
        is_dormant = net_device.is_dormant
        is_operational = net_device.is_operational
        get_operational_state = net_device.get_operational_state
        def _get_flag_choices(self):
            return self.choices
        def _get_netdev_state_t(self):
            return SimpleNamespace(choices=bits)

    cases = []
    for variant, choices in [('legacy', NET_DEVICE_FLAGS), ('composite', dict(NET_DEVICE_FLAGS, IFF_COMPOSITE=3, IFF_ZERO=0)), ('typo', dict(NET_DEVICE_FLAGS, **{'IFF_ALLMULTI)': 512}))]:
        for oper in range(8):
            for state in range(8):
                for flags, gflags in [(0, 0), (0x40143, 0), (0xffff, 0x300), (0x70000, 0x200)]:
                    d = Device()
                    d.flags, d.gflags, d.state, d.operstate, d.choices = flags, gflags, state, oper, choices
                    names = net_device.get_flag_names(d)
                    result = ','.join(n.replace('IFF_', '') for n in names if n != 'IFF_RUNNING')
                    cases.append(dict(choices=variant, flags=flags, gflags=gflags, state=state, oper=oper, result=result))
    ips = []
    for raw in ['00000000000000000000000000000000', '00000000000000000000000000000001', 'fe80000000000000020c29fffe8fedca', '20010db8000000000000000000000001', '00000000000000000000ffffc0000201', '00000000000000000000ffff00000001', '0102030405060708090a0b0c0d0e0f10']:
        b = bytes.fromhex(raw)
        text = convert_ipv6([int.from_bytes(b[i:i+4], 'little') for i in range(0,16,4)])
        address = ipaddress.IPv6Address(text)
        if address.ipv4_mapped is not None:
            text = '::ffff:' + str(address.ipv4_mapped)
        ips.append(dict(raw=raw, text=text))
    scopes = [dict(value=i, text=inet6_ifaddr.get_scope_type(SimpleNamespace(scope=i))) for i in range(128)]
    ip4 = [dict(value=i, text=convert_ipv4(i)) for i in [0, 1, 0x0100007f, 0xffffffff, 0x010200c0]]
    chains = []
    class Node:
        def __init__(self, i):
            self.vol = SimpleNamespace(offset=i+1)
        def __bool__(self):
            return True
    for size, cycle in [(0,-1),(1,-1),(2,0),(129,-1),(130,-1),(130,0)]:
        nodes = [Node(i) for i in range(size)]
        for i, n in enumerate(nodes):
            n.ifa_next = nodes[i+1] if i+1<size else (nodes[cycle] if cycle>=0 else None)
        obj = SimpleNamespace(ifa_list=nodes[0] if nodes else None)
        result = [n.vol.offset-1 for n in in_device.get_addresses(obj)]
        chains.append(dict(size=size, cycle=cycle, indices=result))
    return json.dumps(dict(commit=COMMIT, flags=cases, ipv6=ips, ipv4=ip4, scopes6=scopes, chains=chains), indent=2) + '\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=ROOT/'.cache'/('volatility3-'+COMMIT))
    p.add_argument('--check', action='store_true')
    args = p.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('IP helper oracle differs')
    else:
        OUTPUT.write_text(result)
    print('768 flag cases, 128 scopes, 12 IP encodings and 6 address chains verified')


if __name__ == '__main__':
    main()
