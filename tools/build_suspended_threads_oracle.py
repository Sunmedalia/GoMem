#!/usr/bin/env python3
"""Run the pinned suspended-thread generator on real paged Windows objects."""
import argparse
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest
from build_pe_exports_oracle import fixture as pe_fixture

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/engine/testdata/windows-suspended-threads-oracle.json'


def fixture(width, scenario):
    b = lambda name: dict(kind='base', name=name)
    s = lambda name: dict(kind='struct', name=name)
    ptr = lambda name: dict(kind='pointer', subtype=s(name))
    field = lambda offset, typ: dict(offset=offset, type=typ)
    typ = lambda size, fields: dict(kind='struct', size=size, fields=fields)
    arr = lambda count: dict(kind='array', count=count, subtype=b('u8'))
    bases = {name: dict(kind='int', size=size, signed=False, endian='little') for name, size in [('pointer', width), ('uptr', width), ('u8', 1), ('u16', 2), ('u32', 4), ('u64', 8)]}
    types = {
        '_LIST_ENTRY': typ(width*2, dict(Flink=field(0, ptr('_LIST_ENTRY')), Blink=field(width, ptr('_LIST_ENTRY')))),
        '_LARGE_INTEGER': typ(8, dict(QuadPart=field(0, b('u64')))),
        '_KPROCESS': typ(width, dict(DirectoryTableBase=field(0, b('uptr')))),
        '_RTL_AVL_TREE': typ(width, dict(Root=field(0, ptr('_RTL_BALANCED_NODE')))),
        '_RTL_BALANCED_NODE': typ(24, dict(Left=field(0, ptr('_RTL_BALANCED_NODE')), Right=field(8, ptr('_RTL_BALANCED_NODE')), ParentValue=field(16, b('uptr')))),
        '_EPROCESS': typ(96, dict(ActiveProcessLinks=field(0, s('_LIST_ENTRY')), UniqueProcessId=field(16, b('uptr')), ImageFileName=field(24, arr(16)), CreateTime=field(40, s('_LARGE_INTEGER')), VadRoot=field(48, s('_RTL_AVL_TREE')), ThreadListHead=field(64, s('_LIST_ENTRY')), Pcb=field(80, s('_KPROCESS')))),
        '_CLIENT_ID': typ(16, dict(UniqueProcess=field(0, b('uptr')), UniqueThread=field(8, b('uptr')))),
        '_KTHREAD': typ(16, dict(State=field(0, b('u32')), SuspendCount=field(4, b('u8')), Process=field(8, ptr('_EPROCESS')))),
        '_ETHREAD': typ(96, dict(ThreadListEntry=field(0, s('_LIST_ENTRY')), Cid=field(16, s('_CLIENT_ID')), StartAddress=field(32, b('uptr')), Win32StartAddress=field(40, b('uptr')), CreateTime=field(48, s('_LARGE_INTEGER')), ExitTime=field(56, s('_LARGE_INTEGER')), Tcb=field(64, s('_KTHREAD')))),
        '_MMVAD_SHORT': typ(48, dict(VadNode=field(0, s('_RTL_BALANCED_NODE')), StartingVpn=field(24, b('u32')), EndingVpn=field(28, b('u32')))),
        '_MMVAD': typ(48, dict(VadNode=field(0, s('_RTL_BALANCED_NODE')), StartingVpn=field(24, b('u32')), EndingVpn=field(28, b('u32')), Subsection=field(40, ptr('_SUBSECTION')))),
        '_SUBSECTION': typ(width, dict(ControlArea=field(0, ptr('_CONTROL_AREA')))),
        '_CONTROL_AREA': typ(width, dict(FilePointer=field(0, s('_EX_FAST_REF')))),
        '_EX_FAST_REF': typ(width, dict(Value=field(0, b('uptr')), Object=field(0, b('uptr')))),
        '_UNICODE_STRING': typ(16, dict(Length=field(0, b('u16')), MaximumLength=field(2, b('u16')), Buffer=field(8, dict(kind='pointer', subtype=b('u16'))))),
        '_FILE_OBJECT': typ(16, dict(FileName=field(0, s('_UNICODE_STRING')))),
    }
    data = bytearray(2 << 20)
    def put(at, value):
        struct.pack_into('<Q' if width == 8 else '<I', data, at, value)
    put(0x18080, 0x400); put(0x18080+width, 0x400)
    put(0x400, 0x18080); put(0x400+width, 0x18080)
    for process, pid, name in [(0x400, 104, b'main.exe'), (0x500, 108, b'owner.exe')]:
        put(process+16, pid)
        data[process+24:process+24+len(name)] = name
        put(process+48, 0x1000)
        put(process+80, 0x8000)
    put(0x440, 0x600); put(0x440+width, 0x600)
    put(0x600, 0x440); put(0x600+width, 0x440)
    put(0x610, 999 if scenario == 'cid-mismatch' else 104)
    put(0x618, 8)
    put(0x620, 0x101200); put(0x628, 0x101200)
    struct.pack_into('<I', data, 0x640, 4 if scenario == 'terminated' else 2)
    data[0x644] = 0 if scenario == 'running' else 2
    put(0x648, 0x500 if scenario == 'different-owner' else 0x400)
    if scenario == 'xp-owner':
        types['_ETHREAD']['fields']['ThreadsProcess'] = field(88, ptr('_EPROCESS'))
        put(0x658, 0x500)
    if scenario == 'exited-suspended':
        put(0x638, 1)
    if scenario == 'no-vads':
        put(0x430, 0)
    data[0x1000-(12 if width == 8 else 4):0x1000-(12 if width == 8 else 4)+4] = b'Vadl'
    struct.pack_into('<II', data, 0x1018, 0x100, 0x103)
    put(0x1028, 0x2000); put(0x2000, 0x3000); put(0x3000, 0x4003)
    path = r'C:\Windows\fixture.dll'
    if scenario == 'exception':
        path = r'C:\Windows\WorkFoldersShell.dll'
    if scenario == 'lowercase-exception':
        path = r'C:\Windows\workfoldersshell.dll'
    if scenario == 'relative-name':
        path = 'module.dll'
    database = 'fixture.pdb'
    if scenario == 'sharp-s-name':
        path = 'C:\\Windows\\ß.dll'
        database = 'SS.pdb'
    if scenario == 'short-unicode-name':
        path = 'C:\\Windows\\éé'
        database = 'pdb'
    if scenario == 'unc-share-only':
        path = r'\\server\share'
        database = 'pdb'
    encoded = path.encode('utf-16le')
    struct.pack_into('<HH', data, 0x4000, len(encoded), len(encoded)+2)
    put(0x4008, 0x5000)
    data[0x5000:0x5000+len(encoded)] = encoded
    if scenario == 'unmapped':
        put(0x620, 0x200000); put(0x628, 0)
    if scenario == 'exact-end':
        put(0x620, 0x103fff); put(0x628, 0x104000)
    if scenario == 'export-fallback':
        put(0x620, 0x101700); put(0x628, 0x101700)
    if scenario == 'nearest-not-exact':
        put(0x620, 0x101201); put(0x628, 0x101201)
    if width == 8:
        put(0x8000, 0x9003); put(0x9000, 0xa003); put(0xa000, 0x83)
    else:
        put(0x8000, 0x83)
    module = bytearray(pe_fixture(width == 8, 'normal'))
    guid = bytes([0x12])*16
    debug = 0x98 + (112 if width == 8 else 96) + 6*8
    struct.pack_into('<II', module, debug, 0x1880, 28)
    record = b'RSDS'+guid+(1).to_bytes(4,'little')+database.encode('utf-8')+b'\0'
    struct.pack_into('<III', module, 0x1880+12, 2, len(record), 0x1900)
    module[0x1900:0x1900+len(record)] = record
    data[0x100000:0x100000+len(module)] = module
    pdb = dict(metadata=dict(format='6.2.0', windows=dict(pdb=dict(database=database, GUID=guid.hex().upper(), age=1, machine_type=0x8664 if width == 8 else 0x14c))), base_types=bases, user_types={}, enums={}, symbols={'AlphaPDB':dict(address=0x1200)})
    kernel_image = bytearray(module)
    struct.pack_into('<I', kernel_image, 0x1880+16, 36)
    kernel_image[0x1904:0x1914] = bytes([0x13])*16
    kernel_image[0x1918:0x1924] = b'kernel.pdb\0\0'
    data[0x10000:0x10000+len(kernel_image)] = kernel_image
    kernel = dict(metadata=dict(format='6.2.0', windows=dict(pdb=dict(database='kernel.pdb', GUID='13'*16, age=1, machine_type=0x8664 if width == 8 else 0x14c))), base_types=bases, user_types=types, enums={}, symbols={'PsActiveProcessHead':dict(address=0x8080)})
    # Alter only the collected user module; kernel identity stays independently
    # verifiable, including the control with no resident user-module PE header.
    base = 0x100000
    if scenario == 'rsds-directory-absent':
        data[base+debug:base+debug+8] = bytes(8)
    elif scenario == 'rsds-different-directory-name':
        data[base+0x1918:base+0x1924] = b'other.pdb\0\0\0'
        data[base+0x1b00:base+0x1b00+len(record)] = record
    elif scenario == 'rsds-no-mz':
        data[base:base+2] = b'ZZ'
    elif scenario in ('rsds-cross-page', 'rsds-exact-end', 'rsds-past-end'):
        data[base+0x1900:base+0x1900+len(record)] = bytes(len(record))
        relative = {'rsds-cross-page': 0x1ff0, 'rsds-exact-end': 0x4000-len(record), 'rsds-past-end': 0x4001-len(record)}[scenario]
        data[base+relative:base+relative+len(record)] = record
    elif scenario == 'rsds-first-guid-only':
        wrong = bytearray(record)
        wrong[4:20] = bytes([0x14])*16
        data[base+0x1800:base+0x1800+len(wrong)] = wrong
    elif scenario == 'rsds-candidate-priority':
        data[base+0x1904:base+0x1914] = bytes([0x14])*16
        upper = b'RSDS'+guid+(1).to_bytes(4,'little')+b'Fixture.pdb\0'
        data[base+0x1b00:base+0x1b00+len(upper)] = upper
        pdb['metadata']['windows']['pdb']['database'] = 'Fixture.pdb'
    return kernel, pdb, data


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, constants, interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel, Intel32e
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.automagic.symbol_cache import SqliteCache, WindowsIdentifier
    from volatility3.plugins.windows.suspended_threads import SuspendedThreads
    old_cache, old_offline = constants.CACHE_PATH, constants.OFFLINE
    cases = []
    try:
        for width in (4, 8):
            for scenario in ('normal', 'running', 'terminated', 'different-owner', 'cid-mismatch', 'xp-owner', 'exited-suspended', 'no-vads', 'relative-name', 'unmapped', 'exact-end', 'exception', 'lowercase-exception', 'export-fallback', 'nearest-not-exact', 'sharp-s-name', 'short-unicode-name', 'unc-share-only', 'rsds-directory-absent', 'rsds-different-directory-name', 'rsds-no-mz', 'rsds-cross-page', 'rsds-exact-end', 'rsds-past-end', 'rsds-first-guid-only', 'rsds-candidate-priority'):
                kernel, pdb, data = fixture(width, scenario)
                ctx = contexts.Context()
                ctx.layers.add_layer(BufferDataLayer(ctx, 'physical', 'physical', bytes(data)))
                ctx.config['memory.memory_layer'] = 'physical'
                ctx.config['memory.page_map_offset'] = 0x8000
                ctx.config['memory.kernel_virtual_offset'] = 0x10000
                ctx.layers.add_layer((Intel32e if width == 8 else Intel)(ctx, 'memory', 'memory'))
                with tempfile.TemporaryDirectory() as directory:
                    directory = Path(directory)
                    constants.CACHE_PATH, constants.OFFLINE = str(directory), True
                    kp, pp = directory/'kernel.json', directory/'pdb.json'
                    kp.write_text(json.dumps(kernel)); pp.write_text(json.dumps(pdb))
                    cachepath = str(directory/constants.IDENTIFIERS_FILENAME)
                    SqliteCache(cachepath)
                    with sqlite3.connect(cachepath) as db:
                        db.execute('INSERT INTO cache(location, identifier, operating_system, local) VALUES(?,?,?,1)',(pp.as_uri(), WindowsIdentifier.generate(pdb['metadata']['windows']['pdb']['database'], '12'*16, 1), 'windows'))
                    classes = {name:getattr(extensions,name.lstrip('_')) for name in ('_EPROCESS','_ETHREAD','_LIST_ENTRY','_MMVAD','_MMVAD_SHORT','_EX_FAST_REF','_UNICODE_STRING')}
                    classes['_RTL_BALANCED_NODE'] = extensions.MMVAD_SHORT
                    ctx.symbol_space.append(IntermediateSymbolTable(ctx, 'symbols', 'kernel', kp.as_uri(), class_types=classes))
                    ctx.module('kernel', 'memory', 0x10000)
                    runner = SimpleNamespace(context=ctx, config={'kernel':'kernel'}, config_path='analysis')
                    rows = [[None if isinstance(cell, interfaces.renderers.BaseAbsentValue) else int(cell) if isinstance(cell,int) else str(cell) for cell in row] for _,row in SuspendedThreads._generator(runner)]
                writes = [dict(offset=at, data=bytes(data[at:at+256]).hex()) for at in range(0,len(data),256) if any(data[at:at+256])]
                cases.append(dict(width=width, name=scenario, isf=kernel, pdb=pdb, size=len(data), writes=writes, expected=rows))
        return json.dumps(dict(commit=COMMIT,cases=cases),indent=2)+'\n'
    finally:
        constants.CACHE_PATH, constants.OFFLINE = old_cache, old_offline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    result=generate(args.source)
    if args.check:
        if OUTPUT.read_text()!=result:
            raise ValueError('suspended thread oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual paged suspended-thread generator cases verified")


if __name__=='__main__':
    main()
