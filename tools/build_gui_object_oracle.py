#!/usr/bin/env python3
"""Run original GUI station/session/thread methods on byte-backed objects."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/wingui/testdata/object-oracle.json'
SCENARIOS = ['normal', 'session-255', 'session-256', 'session-max',
             'session-hole', 'next-hole', 'next-null', 'next-self', 'parent-null',
             'parent-hole', 'parent-session-hole', 'empty-threads', 'thread-cycle',
             'head-hole', 'link-hole', 'blink-hole', 'owner-hole', 'process-hole',
             'name-hole', 'pid-hole', 'name-invalid', 'name-empty', 'name-no-nul',
             'blink-mismatch', 'null-thread-head', 'null-owner', 'null-process',
             'second-owner-hole', 'thread-container-hole', 'name-tail-hole',
             'name-replacement', 'name-multibyte']


def generate(source):
    if tree_digest(source) != json.loads((ROOT / 'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.symbols.windows.extensions import gui
    base = lambda n: dict(kind='base', name=n)
    link = dict(kind='struct', name='_LIST_ENTRY')
    pointer = dict(kind='pointer', subtype=link)
    kernel = dict(metadata=dict(format='6.2.0'),
                  base_types={'pointer': dict(kind='int', size=8, signed=False, endian='little'),
                              'u8': dict(kind='int', size=1, signed=False, endian='little'),
                              'u64': dict(kind='int', size=8, signed=False, endian='little')},
                  user_types={'_LIST_ENTRY': dict(kind='struct', size=16, fields={
                      'Flink': dict(offset=0, type=pointer), 'Blink': dict(offset=8, type=pointer)}),
                      '_EPROCESS': dict(kind='struct', size=32, fields={
                          'ImageFileName': dict(offset=0, type=dict(kind='array', count=16, subtype=base('u8'))),
                          'UniqueProcessId': dict(offset=16, type=base('u64'))})}, enums={}, symbols={})
    cases = []
    layouts = {}
    for path in sorted((source / 'volatility3/framework/symbols/windows/gui').glob('*.json')):
        raw = path.read_bytes()
        layouts[path.stem] = hashlib.sha256(raw).hexdigest()
        types = json.loads(raw)['user_types']
        def off(typ, field): return types[typ]['fields'][field]['offset']
        for scenario in SCENARIOS:
            data, holes = bytearray(0x20000), []
            def q(at, value): struct.pack_into('<Q', data, at, value)
            root, desktop = 0x4000, 0x8000
            sid = {'session-255':255, 'session-256':256, 'session-max':0xffffffff}.get(scenario, 1)
            session_at = root + off('tagWINDOWSTATION', 'dwSessionId')
            struct.pack_into('<I', data, session_at, sid)
            q(root + off('tagWINDOWSTATION', 'rpwinstaNext'), 0 if scenario == 'next-null' else root if scenario == 'next-self' else 0x5000)
            q(0x5000 + off('tagWINDOWSTATION', 'rpwinstaNext'), 0x6000)
            q(desktop + off('tagDESKTOP', 'rpwinstaParent'), 0 if scenario == 'parent-null' else root)
            head = desktop + off('tagDESKTOP', 'PtiList')
            nodes = [0xa000 + off('tagTHREADINFO','PtiLink'), 0xb000 + off('tagTHREADINFO','PtiLink')]
            q(head, 0 if scenario == 'null-thread-head' else head if scenario == 'empty-threads' else nodes[0]); q(head+8, nodes[-1])
            for index, (thread, info, process) in enumerate([(0xa000, 0xc000, 0xe000), (0xb000, 0xd000, 0xf000)]):
                node = nodes[index]
                q(node, nodes[index+1] if index == 0 else nodes[0] if scenario == 'thread-cycle' else head)
                q(node+8, head if index == 0 else nodes[0])
                q(thread+off('tagTHREADINFO','ppi'), 0 if scenario == 'null-owner' and index == 0 else info)
                q(info+off('tagPROCESSINFO','Process'), 0 if scenario == 'null-process' and index == 0 else process)
                name = b'first\0' if index == 0 else b'second\0'
                if index == 0:
                    if scenario == 'name-invalid': name = b'X\xe1\x80Y\xf0\x9f\0'
                    if scenario == 'name-empty': name = b'\0'
                    if scenario == 'name-no-nul': name = b'1234567890ABCDEF'
                    if scenario == 'name-replacement': name = 'X\ufffdY\0'.encode()
                    if scenario == 'name-multibyte': name = '进程\0'.encode()
                data[process:process+len(name)] = name
                q(process+16, 100+index)
            if scenario == 'blink-mismatch': q(nodes[0]+8, 0xffffffffffffffff)
            fault = {'session-hole':(session_at,4), 'next-hole':(root+off('tagWINDOWSTATION','rpwinstaNext'),8),
                     'parent-hole':(desktop+off('tagDESKTOP','rpwinstaParent'),8),
                     'parent-session-hole':(session_at,4), 'head-hole':(head,1),
                     'link-hole':(nodes[0],1), 'blink-hole':(nodes[0]+8,1),
                     'owner-hole':(0xa000+off('tagTHREADINFO','ppi'),8),
                     'process-hole':(0xc000+off('tagPROCESSINFO','Process'),8),
                     'name-hole':(0xe000,1), 'pid-hole':(0xe010,8),
                     'second-owner-hole':(0xb000+off('tagTHREADINFO','ppi'),8),
                     'thread-container-hole':(0xa000,1), 'name-tail-hole':(0xe00f,1)}.get(scenario)
            if fault: holes.append(fault)
            class OriginalLayer(BufferDataLayer):
                @property
                def address_mask(self): return (1 << 64)-1
                def is_valid(self, at, length=1):
                    return super().is_valid(at,length) and not any(at < start+size and start < at+length for start,size in holes)
                def read(self, at, length, pad=False):
                    for start,size in holes:
                        if at < start+size and start < at+length:
                            raise exceptions.InvalidAddressException(self.name,max(at,start))
                    return super().read(at,length,pad)
            context = contexts.Context()
            context.layers.add_layer(OriginalLayer(context,'memory','memory',bytes(data)))
            with tempfile.TemporaryDirectory(prefix='gomem-gui-object-') as directory:
                kernel_path = Path(directory)/'kernel.json'
                kernel_path.write_text(json.dumps(kernel))
                context.symbol_space.append(IntermediateSymbolTable(context,'kernel','kernel',kernel_path.as_uri(),class_types={'_LIST_ENTRY':extensions.LIST_ENTRY}))
                context.symbol_space.append(IntermediateSymbolTable(context,'gui','gui',path.as_uri(),class_types=gui.GUIExtensions.class_types,table_mapping={'nt_symbols':'kernel'}))
                station = context.object('gui!tagWINDOWSTATION','memory',root)
                desk = context.object('gui!tagDESKTOP','memory',desktop)
                def result(call):
                    try: return dict(value=call())
                    except Exception as error: return dict(error=type(error).__name__)
                def session(obj):
                    value = obj.get_session_id()
                    return int(value) if value is not None else None
                results = dict(station_session=result(lambda:session(station)), station_valid=result(station.is_valid),
                               desktop_session=result(lambda:session(desk)), desktop_valid=result(desk.is_valid),
                               desktop_station=result(lambda:int(desk.get_window_station().vol.offset) if desk.get_window_station() is not None else None),
                               traverse=result(lambda:[int(s.vol.offset) for s in station.traverse()]),
                               traverse_one=result(lambda:[int(s.vol.offset) for s in station.traverse(max_stations=1)]),
                               traverse_zero=result(lambda:[int(s.vol.offset) for s in station.traverse(max_stations=0)]),
                               threads=result(lambda:[dict(thread=int(t.vol.offset), name=n, pid=int(p)) for t,n,p in desk.get_threads()]))
            cases.append(dict(layout=path.stem,scenario=scenario,size=len(data),root=root,desktop=desktop,holes=holes,
                              writes=[dict(offset=at,data=data[at:at+256].hex()) for at in range(0,len(data),256) if any(data[at:at+256])],results=results))
    assert len(cases) == len(SCENARIOS)*12
    for case in cases:
        r = case['results']
        if case['scenario'] == 'normal':
            assert r['station_session'] == dict(value=1)
            assert r['desktop_valid'] == dict(value=True)
            assert r['traverse'] == dict(value=[0x4000, 0x5000])
            assert r['threads'] == dict(value=[dict(thread=0xa000,name='first',pid=100),dict(thread=0xb000,name='second',pid=101)])
        if case['scenario'] == 'next-self':
            assert r['traverse'] == dict(value=[0x4000,0x4000])
        if case['scenario'] == 'parent-null':
            assert r['desktop_session'] == dict(value=0)
            assert r['desktop_valid'] == dict(value=True)
    return json.dumps(dict(commit=COMMIT,scope=__doc__,kernel=kernel,layouts=layouts,cases=cases),indent=2)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result: raise SystemExit('GUI object oracle drift')
    else: OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} original GUI object controls verified')


if __name__ == '__main__': main()
