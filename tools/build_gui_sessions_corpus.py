#!/usr/bin/env python3
"""Rebuild a saved Windows crash context and run original GUI session discovery."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/'.cache'/('volatility3-'+COMMIT))
    parser.add_argument('--reference',type=Path,required=True,help='Existing pinned reference output prefix')
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--symbols',type=Path,required=True,help='Exact local kernel ISF also used by native control')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    lock=json.loads((ROOT/'baseline.lock.json').read_text())
    if tree_digest(args.source)!=lock['python_tree_sha256']:raise ValueError('requires locked source')
    config_path=args.reference.with_suffix('.config.json');manifest_path=args.reference.with_suffix('.manifest.json')
    cfg=json.loads(config_path.read_text());manifest=json.loads(manifest_path.read_text())
    image_hash=digest(args.image)
    if manifest['baseline']['commit']!=COMMIT or manifest['image_sha256']!=image_hash or manifest['config_sha256']!=digest(config_path):raise ValueError('reference provenance mismatch')
    if cfg['kernel.layer_name.class']!='volatility3.framework.layers.intel.WindowsIntel32e' or cfg['kernel.layer_name.memory_layer.class']!='volatility3.framework.layers.crash.WindowsCrashDump64Layer':raise ValueError('requires saved Windows x64 complete/bitmap crash context')
    sys.path.insert(0,str(args.source))
    from volatility3.framework import contexts,exceptions
    from volatility3.framework.layers.physical import FileLayer
    from volatility3.framework.layers.crash import WindowsCrashDump64Layer
    from volatility3.framework.layers.intel import WindowsIntel32e
    from volatility3.framework.symbols.windows import WindowsKernelIntermedSymbols
    from volatility3.plugins.windows.modules import Modules
    context=contexts.Context()
    context.config['file.location']=args.image.resolve().as_uri();context.layers.add_layer(FileLayer(context,'file','file'))
    context.config['physical.base_layer']='file';context.layers.add_layer(WindowsCrashDump64Layer(context,'physical','physical'))
    context.config['memory.memory_layer']='physical'
    for field in ['page_map_offset','kernel_virtual_offset']:context.config['memory.'+field]=cfg['kernel.layer_name.'+field]
    context.layers.add_layer(WindowsIntel32e(context,'memory','memory'))
    context.symbol_space.append(WindowsKernelIntermedSymbols(context,'symbols','symbols',args.symbols.resolve().as_uri(),symbol_mask=0))
    context.module('symbols','memory',cfg['kernel.offset'])
    rows=[];error=None
    try:
        for sid,layer_name in Modules._do_get_session_layers(context,'symbols'):
            layer=context.layers[layer_name]
            row=dict(session=int(sid),cr3=hex(int(layer.config['page_map_offset'])))
            try:row['probe']=layer.read(cfg['kernel.offset'],16).hex()
            except exceptions.InvalidAddressException:row['probe_error']='unavailable'
            rows.append(row)
    except Exception as exc:error=type(exc).__name__
    base=cfg['kernel.offset']
    if base & (1<<47):base|=0xffff000000000000
    output=dict(commit=COMMIT,image_sha256=image_hash,symbols_sha256=digest(args.symbols),reference_manifest_sha256=digest(manifest_path),config_sha256=digest(config_path),
                kernel_dtb=hex(cfg['kernel.layer_name.page_map_offset']),kernel_base=hex(base),probe_address=hex(base),rows=rows,error=error,
                scope='Original session map and 16-byte shared kernel probe only; same ISF, no GUI object/plugin or independent PDB acceptance')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as stream:stream.write(json.dumps(output,indent=2)+'\n')
    print(json.dumps(dict(sessions=len(rows),error=error)))


if __name__=='__main__':main()
