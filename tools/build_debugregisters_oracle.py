#!/usr/bin/env python3
"""Run pinned DebugRegisters on real paged Windows objects and local symbol cache."""
import argparse
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest
from build_suspended_threads_oracle import fixture as suspended_fixture

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT/'internal/engine/testdata/windows-debugregisters-oracle.json'


def fixture(width,scenario):
    kernel,pdb,data=suspended_fixture(width,scenario)
    def f(offset,name):return dict(offset=offset,type=dict(kind='base',name=name))
    kernel['user_types']['_KTHREAD']['size']=24
    kernel['user_types']['_KTHREAD']['fields']['TrapFrame']=dict(offset=16,type=dict(kind='pointer',subtype=dict(kind='struct',name='_KTRAP_FRAME')))
    kernel['user_types']['_KTRAP_FRAME']=dict(kind='struct',size=40,fields={name:f(i*8,'uptr') for i,name in enumerate(('Dr0','Dr1','Dr2','Dr3','Dr7'))})
    struct.pack_into('<Q' if width==8 else '<I',data,0x650,0x7000)
    for offset,value in [(0,0x101200),(8,0),(16,0x101700),(24,0),(32,1)]:
        struct.pack_into('<Q' if width==8 else '<I',data,0x7000+offset,value)
    put = lambda at, value: struct.pack_into('<Q' if width == 8 else '<I', data, at, value)
    if scenario == 'dr7-zero':
        put(0x7020, 0)
    elif scenario == 'all-addresses-zero':
        for i in range(4):
            put(0x7000+i*8, 0)
    elif scenario == 'unmapped-registers':
        put(0x7000, 0x200000); put(0x7010, 0x200001)
    elif scenario == 'exact-register-end':
        put(0x7000, 0x103fff); put(0x7010, 0x104000)
    elif scenario == 'nearest-register':
        put(0x7000, 0x101201); put(0x7010, 0)
    elif scenario == 'dr7-high-bits':
        put(0x7020, 0x80000000)
    elif scenario == 'four-registers':
        for i, address in enumerate((0x101200, 0x101700, 0x101201, 0x103fff)):
            put(0x7000+i*8, address)
    return kernel,pdb,data


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
    from volatility3.plugins.windows.debugregisters import DebugRegisters
    old_cache, old_offline = constants.CACHE_PATH, constants.OFFLINE
    cases = []
    try:
        for width in (4, 8):
            for scenario in ('normal', 'running', 'terminated', 'different-owner', 'cid-mismatch', 'xp-owner', 'exited-suspended', 'no-vads', 'relative-name', 'unmapped', 'exact-end', 'exception', 'lowercase-exception', 'export-fallback', 'nearest-not-exact', 'sharp-s-name', 'short-unicode-name', 'unc-share-only', 'rsds-directory-absent', 'rsds-different-directory-name', 'rsds-no-mz', 'rsds-cross-page', 'rsds-exact-end', 'rsds-past-end', 'rsds-first-guid-only', 'rsds-candidate-priority', 'dr7-zero', 'all-addresses-zero', 'unmapped-registers', 'exact-register-end', 'nearest-register', 'dr7-high-bits', 'four-registers'):
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
                    runner = SimpleNamespace(context=ctx, config={'kernel':'kernel'}, config_path='analysis', _get_debug_info=DebugRegisters._get_debug_info)
                    rows = [[None if isinstance(cell, interfaces.renderers.BaseAbsentValue) else int(cell) if isinstance(cell,int) else str(cell) for cell in row] for _,row in DebugRegisters._generator(runner)]
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
            raise ValueError('debug-register oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} actual paged debug-register generator cases verified")


if __name__=='__main__':
    main()
