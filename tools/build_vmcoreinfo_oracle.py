#!/usr/bin/env python3
"""Evaluate the fixed VMCOREINFO descriptor parser and plugin renderer."""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch
from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT/'internal/plugins/testdata/linux-vmcoreinfo-oracle.json'


def generate(source):
    if tree_digest(source) != json.loads((ROOT/'baseline.lock.json').read_text())['python_tree_sha256']:
        raise ValueError('requires locked source')
    sys.path.insert(0,str(source))
    from volatility3.framework.symbols.linux import VMCoreInfo
    from volatility3.plugins.linux.vmcoreinfo import VMCoreInfo as Plugin
    descriptors = [b'', b'OSRELEASE=test\n', b'OSRELEASE=test\r\nPAGESIZE=4096\r', b'OSRELEASE=test\vPAGESIZE=4096\f', b'OSRELEASE=test\n\nBAD', b'OSRELEASE=a\nPAGESIZE=4096\nOSRELEASE=b\n', b'OSRELEASE=x\n=empty-key\nA=\nA=a=b\n', b'\nOSRELEASE=test', b'OSRELEASE=test\nBAD', b'OSRELEASE=test\0', b'OSRELEASE=test\n\n\xff', b'OSRELEASE=test\n X = value \n']
    values = ['', '0', '00', '0_0', '01', '-01', '+0', '-0', '4096', '  +4096\t', '1_024', '1__2', '_1', '1_', '0x10', '-0Xff', '0x_f', '0x__f', '0b101', '0o77', '0o_7', '+', '-', '  ', '0x', 'ff', 'f_f', '1 2', ':', '1e2', str(2**128), 'f'*40]
    for key in ['SYMBOL(test)', 'KERNELOFFSET', 'NUMBER(test)', 'LENGTH(test)', 'SIZE(test)', 'OFFSET(test)', 'PAGESIZE', 'OTHER']:
        descriptors += [('OSRELEASE=test\n'+key+'='+value+'\n').encode() for value in values]
    cases=[]
    for data in descriptors:
        result=dict(raw=data.hex())
        try:
            table=VMCoreInfo._vmcoreinfo_data_to_dict(data)
            result['accepted']=bool(table)
            result['entries']=[]
            if table:
                fake=SimpleNamespace(context=None,config={'primary':'test'})
                with patch.object(VMCoreInfo,'search_vmcoreinfo_elf_note',return_value=[(0x1000,table)]):
                    result['entries']=[dict(key=v[1],value=v[2],integer=str(table[v[1]]) if isinstance(table[v[1]],int) else '') for _,v in Plugin._generator(fake)]
        except ValueError:
            result['error']='ValueError'
        cases.append(result)
    return json.dumps(dict(commit=COMMIT,cases=cases),indent=2)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT))
    p.add_argument('--check',action='store_true')
    args=p.parse_args();result=generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text()!=result:
            raise ValueError('VMCOREINFO oracle differs')
    else:
        OUTPUT.write_text(result)
    print(f'{len(json.loads(result)["cases"])} pinned VMCOREINFO parser/renderer cases verified')


if __name__=='__main__':
    main()
