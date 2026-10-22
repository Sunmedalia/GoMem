#!/usr/bin/env python3
"""Run locked MFT/ADS/ResidentData generators and YARA over byte-backed records."""
import argparse
import datetime
import json
import importlib.metadata
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

from baseline_matrix import ROOT, tree_digest

COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/engine/testdata/windows-mft-oracle.json'


def fixture(signature, scenario):
    data = bytearray(0x6000)
    base = 0x1000
    data[base:base+4] = signature
    struct.pack_into('<HH', data, base+4, 0x2a if signature == b'FILE' and scenario == 'star-signature' else 0x30, 3)
    struct.pack_into('<HHB', data, base+18, 2, 0x38, 1)
    struct.pack_into('<II', data, base+24, 1024, 1024)
    struct.pack_into('<I', data, base+44, 42)
    cursor = base+0x38
    attrs = []
    stamp = 132537600001234567

    def attribute(kind, payload, *, name=b'', content_offset=24, nonresident=0):
        nonlocal cursor
        size = (max(24+len(name), content_offset+len(payload))+7) & ~7
        offset = cursor
        struct.pack_into('<IIBBHHHIH', data, offset, kind, size, nonresident, len(name)//2, 24 if name else 0, 0, len(attrs), len(payload), content_offset)
        data[offset+24:offset+24+len(name)] = name
        data[offset+content_offset:offset+content_offset+len(payload)] = payload
        attrs.append((kind, offset))
        cursor += size
        return offset

    def standard():
        return struct.pack('<QQQQI', stamp, stamp+10000001, stamp+20000002, stamp+30000003, 32)

    def filename(name, permission=32):
        payload = bytearray(66+len(name))
        struct.pack_into('<QQQQQQQ', payload, 0, 7, stamp, stamp+10000001, stamp+20000002, stamp+30000003, 2048, 123)
        struct.pack_into('<I', payload, 56, permission)
        payload[64:66] = bytes((len(name)//2, 1))
        payload[66:] = name
        return payload

    if scenario != 'no-standard':
        attribute(16, standard(), nonresident=scenario == 'nonresident-standard')
    if scenario == 'multiple-standard':
        attribute(16, standard())
    if scenario != 'no-filename':
        name = 'long-name.txt'.encode('utf-16le')
        if scenario == 'empty-filename':
            name = b''
        elif scenario == 'invalid-utf16':
            name = b'a\x00\x00\xd8b\x00'
        elif scenario == 'nul-filename':
            name = 'abc\x00suffix'.encode('utf-16le')
        attribute(48, filename(name, 0x1234 if scenario == 'unknown-permission' else 32))
        attribute(48, filename('SHORT.TXT'.encode('utf-16le')))
        if scenario == 'tie-filename':
            attribute(48, filename('equal-name.tx'.encode('utf-16le')))
    if scenario != 'no-data':
        attribute(128, b'' if scenario == 'empty-data' else b'primary\x00\xff', nonresident=scenario == 'nonresident-data')
    if scenario == 'duplicate-data':
        attribute(128, b'second-content')
    if scenario != 'no-ads':
        attribute(128, b'' if scenario == 'empty-ads' else b'secret\x00\xff', name='stream'.encode('utf-16le'), content_offset=40, nonresident=scenario == 'nonresident-ads')
    struct.pack_into('<I', data, cursor, 0xffffffff)
    if scenario == 'unknown-flags':
        data[base+22] = 5
    if scenario == 'high-flags':
        data[base+23] = 0xff
    if scenario == 'zero-length':
        struct.pack_into('<I', data, attrs[0][1]+4, 0)
    if scenario == 'unknown-attribute':
        data[attrs[0][1]] = 0x11
    if scenario == 'wide-attribute-type':
        struct.pack_into('<I', data, attrs[0][1], 0x10010)
    if scenario == 'nondefault-si-content':
        struct.pack_into('<H', data, attrs[0][1]+20, 40)
    if scenario in ('time-zero', 'time-small', 'time-overflow'):
        struct.pack_into('<Q', data, attrs[0][1]+24, {'time-zero':0, 'time-small':9999999, 'time-overflow':0xffffffffffffffff}[scenario])
    for kind, at in attrs:
        if kind == 128 and data[at+9] == 0:
            if scenario == 'data-content-offset':
                struct.pack_into('<H', data, at+20, 32)
            if scenario == 'data-content-oversize':
                struct.pack_into('<I', data, at+16, 0x400001)
            if scenario == 'data-content-hole':
                struct.pack_into('<I', data, at+16, 0x10000)
        if kind == 128 and data[at+9] != 0 and scenario == 'stream-name-hole':
            struct.pack_into('<H', data, at+10, 0xfff0)
    if scenario == 'header-truncated':
        data = data[:base+45]
    if scenario == 'attributes-truncated':
        data = data[:attrs[0][1]+40]
    return bytes(data)


def generate(source):
    lock = json.loads((ROOT/'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('requires locked unmodified source')
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts, interfaces, renderers
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.plugins.windows.mftscan import MFTScan, ADS, ResidentData
    from volatility3.plugins import yarascan

    if not yarascan.USE_YARA_X or importlib.metadata.version("yara-x") != "1.9.0":
        raise ValueError("requires development yara-x==1.9.0")
    cases = []
    scenarios = ('normal', 'star-signature', 'no-standard', 'multiple-standard', 'no-filename',
                 'empty-filename', 'invalid-utf16', 'nul-filename', 'tie-filename',
                 'unknown-permission', 'unknown-flags', 'high-flags', 'no-data',
                 'empty-data', 'nonresident-data', 'duplicate-data', 'no-ads', 'empty-ads',
                 'nonresident-ads', 'nonresident-standard', 'zero-length',
                 'unknown-attribute', 'wide-attribute-type', 'nondefault-si-content',
                 'time-zero', 'time-small', 'time-overflow', 'data-content-offset',
                 'data-content-oversize', 'data-content-hole', 'stream-name-hole',
                 'header-truncated', 'attributes-truncated', 'chunk-overlap', 'partial-chunk-overlap')
    def normalize(cell):
        if isinstance(cell, interfaces.renderers.BaseAbsentValue):
            return {'missing':type(cell).__name__}
        if isinstance(cell, renderers.LayerData):
            return dict(offset=cell.offset, length=cell.length,
                        raw=cell.context.layers[cell.layer_name].read(cell.offset, cell.length, pad=True).hex())
        if isinstance(cell, datetime.datetime):
            return cell.isoformat()
        if isinstance(cell, int):
            return int(cell)
        return str(cell)

    for signature in (b'FILE', b'BAAD'):
        for scenario in scenarios:
            data = fixture(signature, scenario)
            if scenario in ('chunk-overlap', 'partial-chunk-overlap'):
                template = fixture(signature, 'normal')[0x1000:0x1400]
                size = (16<<20) + (8192 if scenario == 'chunk-overlap' else 1000)
                data = bytearray(size)
                starts = [(16<<20)-2, (16<<20)+1024] if scenario == 'chunk-overlap' else [(16<<20)-1000]
                for start in starts:
                    data[start:start+len(template)] = template
                data = bytes(data)
            context = contexts.Context()
            context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', data))
            context.layers.add_layer(BufferDataLayer(context, 'primary', 'primary', data))
            context.config['primary.memory_layer'] = 'physical'
            expected = {}
            for name, cls in (('mftscan', MFTScan), ('ads', ADS), ('residentdata', ResidentData)):
                runner = SimpleNamespace(context=context, config={'primary':'primary'}, config_path='analysis',
                    parse_mft_records=MFTScan.parse_mft_records, parse_ads_data_records=ADS.parse_ads_data_records,
                    parse_resident_data=ResidentData.parse_resident_data)
                rows, error = [], None
                try:
                    for level, row in cls._generator(runner):
                        rows.append(dict(level=level, values=[normalize(cell) for cell in row]))
                except Exception as exc:
                    error = type(exc).__name__
                expected[name] = dict(rows=rows, error=error)
            writes = [dict(offset=at, data=data[at:at+256].hex()) for at in range(0,len(data),256) if any(data[at:at+256])]
            cases.append(dict(name=signature.decode()+'-'+scenario, size=len(data), writes=writes, expected=expected))
    backend = 'yara-x' if yarascan.USE_YARA_X else 'yara-python'
    # Backend identity is recorded; CI must use the same pinned development adapter.
    return json.dumps(dict(commit=COMMIT, scanner=backend, cases=cases),indent=2)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=ROOT/('.cache/volatility3-'+COMMIT))
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    data = generate(args.source)
    if args.check:
        if OUTPUT.read_text() != data:
            raise SystemExit('MFT oracle differs; regenerate with pinned development YARA adapter')
    else:
        OUTPUT.write_text(data)
    print(f'{len(json.loads(data)["cases"])} actual upstream MFT/ADS/ResidentData generators verified')


if __name__ == '__main__':
    main()
