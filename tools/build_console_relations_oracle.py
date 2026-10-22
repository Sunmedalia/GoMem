#!/usr/bin/env python3
"""Run original console screen chains and alias text on all pinned layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'pkg/winconsole/testdata/relations-oracle.json'
SCENARIOS = ['normal', 'same-root', 'null-current', 'null-alternate', 'both-null',
             'shared-tail', 'screen-cycle', 'alternate-cycle', 'next-hole',
             'capacity-hole', 'rows-pointer-hole', 'alternate-root-hole',
             'negative-capacity', 'zero-capacity', 'source-length-1024',
             'source-hole', 'target-hole', 'exe-hole', 'nul-source',
             'bom-target', 'long-exe', 'empty-source', 'exe-target-hole', 'exe-nonascii']


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires pinned unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.intermed import IntermediateSymbolTable
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.symbols.windows.extensions import consoles
    original = json.loads((ROOT/'pkg/winconsole/testdata/console-oracle.json').read_text())
    assert original['commit'] == COMMIT
    kernel = original['kernel']
    layouts, cases = {}, []
    for path in sorted((source/'volatility3/framework/symbols/windows/consoles').glob('*.json')):
        raw = path.read_bytes()
        doc = json.loads(raw)
        types = doc['user_types']
        layouts[path.stem] = dict(source=raw.decode(), sha256=hashlib.sha256(raw).hexdigest())
        def off(typ, name): return types[typ]['fields'][name]['offset']
        for scenario in SCENARIOS:
            data, holes = bytearray(0x20000), []
            def q(at, value): struct.pack_into('<Q', data, at, value)
            def h(at, value): struct.pack_into('<h', data, at, value)
            root, exe, alias = 0x4000, 0xc000, 0xd000
            q(root+off('_CONSOLE_INFORMATION', 'CurrentScreenBuffer'), 0 if scenario in ['null-current', 'both-null'] else 0x6000)
            q(root+off('_CONSOLE_INFORMATION', 'GetScreenBuffer'),
              0 if scenario in ['null-alternate','both-null'] else 0x6000 if scenario == 'same-root' else 0x6200)
            for index, address in enumerate([0x6000, 0x6100, 0x6200, 0x6300]):
                buffer = 0x8000+index*0x200
                q(address+off('_SCREEN_INFORMATION','TextBufferInfo'), buffer)
                q(address+off('_SCREEN_INFORMATION','Next'), {0x6000:0x6100,0x6200:0x6300}.get(address,0))
                h(buffer+off('_TEXT_BUFFER_INFO','BufferCapacity'), 1)
                q(buffer+off('_TEXT_BUFFER_INFO','BufferRows'), 0x10000+index*0x200)
            if scenario == 'shared-tail': q(0x6200+off('_SCREEN_INFORMATION','Next'),0x6100)
            if scenario == 'screen-cycle': q(0x6100+off('_SCREEN_INFORMATION','Next'),0x6000)
            if scenario == 'alternate-cycle': q(0x6300+off('_SCREEN_INFORMATION','Next'),0x6200)
            if scenario == 'next-hole': holes.append([0x6100+off('_SCREEN_INFORMATION','Next'),8])
            if scenario == 'capacity-hole': holes.append([0x8200+off('_TEXT_BUFFER_INFO','BufferCapacity'),2])
            if scenario == 'rows-pointer-hole': holes.append([0x8200+off('_TEXT_BUFFER_INFO','BufferRows'),8])
            if scenario == 'alternate-root-hole': holes.append([root+off('_CONSOLE_INFORMATION','GetScreenBuffer'),8])
            if scenario == 'negative-capacity': h(0x8200+off('_TEXT_BUFFER_INFO','BufferCapacity'),-1)
            if scenario == 'zero-capacity': h(0x8200+off('_TEXT_BUFFER_INFO','BufferCapacity'),0)
            def command(at, value, target):
                raw = value.encode('utf-16le', errors='surrogatepass')
                if len(value) < 8:
                    data[at:at+len(raw)] = raw
                else:
                    q(at+off('_COMMAND','Pointer'),target)
                    data[target:target+len(raw)] = raw
                struct.pack_into('<I',data,at+off('_COMMAND','Length'),len(value))
                struct.pack_into('<I',data,at+off('_COMMAND','Allocated'),1024)
            source_at, target_at = alias+off('_ALIAS','Source'),alias+off('_ALIAS','Target')
            command(source_at, '' if scenario == 'empty-source' else 'A\0B' if scenario == 'nul-source' else 'ls', 0x12000)
            command(target_at, '\ufeffdir' if scenario == 'bom-target' else 'Get-ChildItem', 0x13000)
            if scenario == 'source-length-1024': struct.pack_into('<I',data,source_at+off('_COMMAND','Length'),1024)
            exe_at = exe+off('_EXE_ALIAS_LIST','ExeName')
            if types['_EXE_ALIAS_LIST']['fields']['ExeName']['type']['kind'] == 'pointer':
                q(exe_at,0x14000)
                data[0x14000:0x14008] = 'cmd\0'.encode('utf-16le')
            else:
                command(exe_at,'powershell.exe' if scenario == 'long-exe' else 'cmd.exe',0x14000)
            if scenario == 'exe-target-hole': holes.append([0x14000,1])
            if scenario == 'exe-nonascii':
                if types['_EXE_ALIAS_LIST']['fields']['ExeName']['type']['kind'] == 'pointer':
                    data[0x14000] = 0xff
                else:
                    command(exe_at,'é.exe',0x14000)
            if scenario == 'source-hole': holes.append([source_at+off('_COMMAND','Length'),4])
            if scenario == 'target-hole': holes.append([0x13000,1])
            if scenario == 'exe-hole': holes.append([exe_at,8])
            class OriginalLayer(BufferDataLayer):
                @property
                def address_mask(self):
                    # Preserve 64-bit pointers; a small physical buffer must not
                    # silently truncate damaged pointers into valid fixture bytes.
                    return (1 << 64) - 1
                def read(self, at, length, pad=False):
                    for start,size in holes:
                        if at < start+size and start < at+length:
                            raise exceptions.InvalidAddressException(self.name,max(start,at))
                    return super().read(at,length,pad)
            ctx = contexts.Context()
            ctx.layers.add_layer(OriginalLayer(ctx,'memory','memory',bytes(data)))
            with tempfile.TemporaryDirectory(prefix='gomem-console-relations-') as directory:
                kp=Path(directory)/'kernel.json';kp.write_text(json.dumps(kernel))
                ctx.symbol_space.append(IntermediateSymbolTable(ctx,'kernel','kernel',kp.as_uri(),class_types={'_LIST_ENTRY':extensions.LIST_ENTRY}))
                ctx.symbol_space.append(IntermediateSymbolTable(ctx,'console','console',path.as_uri(),class_types=consoles.win10_x64_class_types,table_mapping={'nt_symbols':'kernel'}))
                console=ctx.object('console!_CONSOLE_INFORMATION','memory',root)
                e=ctx.object('console!_EXE_ALIAS_LIST','memory',exe)
                a=ctx.object('console!_ALIAS','memory',alias)
                def result(call):
                    try:return dict(value=call())
                    except Exception as error:return dict(error=type(error).__name__,detail=str(error))
                screens=[];screen_error=None
                try:
                    for screen in console.get_screens():screens.append(dict(address=int(screen.vol.offset),target=int(screen)))
                except Exception as error:screen_error=type(error).__name__
                results=dict(screens=dict(value=screens,error=screen_error),exe=result(e.get_exename),source=result(a.get_source),target=result(a.get_target))
            cases.append(dict(layout=path.stem,scenario=scenario,size=len(data),root=root,exe=exe,alias=alias,holes=holes,
                              writes=[dict(offset=at,data=data[at:at+256].hex()) for at in range(0,len(data),256) if any(data[at:at+256])],results=results))
    assert len(cases)==264
    for c in cases:
        if c['scenario']=='normal':
            assert c['results']['screens']['error'] is None or c['layout']=='consoles-win10-17763-x64'
            if c['results']['screens']['error'] is None:
                assert [v['target'] for v in c['results']['screens']['value']] == [0x6000,0x6100,0x6200,0x6300]
            assert c['results']['source']==dict(value='ls')
            assert c['results']['target']==dict(value='Get-ChildItem')
    return json.dumps(dict(commit=COMMIT,scope=__doc__,layouts=layouts,cases=cases),indent=2)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT))
    p.add_argument('--check',action='store_true');args=p.parse_args()
    generated=generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text()!=generated:raise SystemExit('console relations oracle drift')
    else:OUTPUT.write_text(generated)
    print(f'{len(json.loads(generated)["cases"])} original console relation controls verified')


if __name__=='__main__':main()
