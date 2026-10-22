#!/usr/bin/env python3
"""Explain reference-only IAT rows using independently verified failed DLL-name reads.

Does not remove reference rows or turn a mismatching differential into a pass.
Every explanation requires the descriptor, matching function and exact readable
DLL-name prefix, followed by a genuinely failed one-byte acquisition.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct


def cell(row, name):
    return row['cells'][name].get('value')


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def records(path):
    with path.open(encoding='utf-8') as source:
        for line in source:
            if line.strip():
                yield json.loads(line)


def explain(native, comparison, verification):
    diff = json.loads(comparison.read_text())
    verified = json.loads(verification.read_text())
    with native.open('rb') as source:
        native_hash = hashlib.file_digest(source, 'sha256').hexdigest()
    if (native_hash != diff['sha256']['native'] or native_hash != verified.get('jsonl_sha256')
            or verified.get('plugin') != 'windows.iat'
            or not verified.get('all_captures_independently_reread')
            or not verified.get('all_seals_and_provenance_verified')):
        raise ValueError('input does not match independently verified capture stream')
    if diff['extra']:
        raise ValueError('native-only differences require independent explanation')
    wanted = diff['missing']
    pids = {str(row['PID']) for row in wanted}
    processes = {}
    count = 0
    for row in records(native):
        count += 1
        if cell(row, 'RecordType') != 'diagnostic' or str(cell(row, 'PID')) not in pids:
            continue
        if row['cells'].get('Error', {}).get('reason') != 'imports_incomplete':
            continue
        pid = str(cell(row, 'PID'))
        info = dict(layer=row['provenance']['layer'], base=number(row['provenance']['offset']),
                    process_offset=cell(row, 'ProcessOffset'), identity=cell(row, 'ProcessIdentity'))
        if pid in processes and processes[pid] != info:
            raise ValueError('ambiguous process identity')
        processes[pid] = info
    if count != verified['rows'] or set(processes) != pids:
        raise ValueError('missing process diagnostics or capture count mismatch')
    layers = {p['layer'] for p in processes.values()}
    captures = {layer: {} for layer in layers}
    for row in records(native):
        if cell(row, 'RecordType') != 'memory_read' or row['provenance']['layer'] not in layers:
            continue
        if cell(row, 'Resolution').get('method') != 'imports':
            continue
        if cell(row, 'Resolution').get('grouped'):
            raise ValueError('grouped import evidence requires acquisition expansion')
        if row['cells']['Raw']['kind'] != 'bytes':
            raise ValueError('expected original byte capture')
        encoded = cell(row, 'Raw')
        data = base64.b64decode('' if encoded is None else encoded, validate=True)
        requested = number(cell(row, 'Requested'))
        if len(data) != number(cell(row, 'Captured')):
            raise ValueError('capture length mismatch')
        captures[row['provenance']['layer']][number(cell(row, 'Offset')), requested] = dict(
            raw=data, failed=row['cells']['Error']['kind'] != 'missing',
            error=cell(row, 'Error'), evidence=row['id'])

    explanations = []
    for missing in wanted:
        info = processes[str(missing['PID'])]
        reads = captures[info['layer']]
        base = info['base']
        dos = reads.get((base, 64), {}).get('raw', b'')
        if len(dos) != 64 or dos[:2] != b'MZ':
            raise ValueError('original DOS header unavailable')
        nt = struct.unpack_from('<I', dos, 60)[0]
        header = reads.get((base+nt, 24), {}).get('raw', b'')
        if len(header) != 24 or header[:4] != b'PE\0\0':
            raise ValueError('original NT header unavailable')
        machine = struct.unpack_from('<H', header, 4)[0]
        if machine not in (0x14c, 0x8664):
            raise ValueError('unsupported PE architecture')
        width = 8 if machine == 0x8664 else 4

        def string_at(address):
            value = bytearray()
            evidence = []
            for index in range(512):
                acquisition = reads.get((address+index, 1))
                if acquisition is None:
                    return None, None, []
                evidence.append(acquisition['evidence'])
                if acquisition['failed']:
                    if acquisition['raw'] or not acquisition['error']:
                        raise ValueError('expected an unavailable byte, not a successful terminator')
                    return bytes(value), acquisition, evidence
                if len(acquisition['raw']) != 1:
                    raise ValueError('invalid successful string acquisition')
                if acquisition['raw'] == b'\0':
                    return bytes(value), None, evidence
                value.extend(acquisition['raw'])
            return None, None, []

        candidates = []
        for (address, requested), descriptor in reads.items():
            if requested != 20 or descriptor['failed'] or len(descriptor['raw']) != 20:
                continue
            ilt, _, _, dll, iat = struct.unpack('<IIIII', descriptor['raw'])
            displacement = number(missing['Address'])-2*base-iat
            if displacement < 0 or displacement % width or displacement//width >= 4000000:
                continue
            lookup = reads.get((base+(ilt or iat)+displacement, width))
            if lookup is None or lookup['failed'] or len(lookup['raw']) != width:
                continue
            target = int.from_bytes(lookup['raw'], 'little')
            if target & (1 << (width*8-1)):
                continue
            function, fault, _ = string_at(base+target+2)
            if fault is not None or function is None or function.decode('ascii') != missing['Function']:
                continue
            prefix, fault, evidence = string_at(base+dll)
            if fault is None or prefix is None or prefix.decode('ascii') != missing['Library']:
                continue
            candidates.append(dict(reference=missing, process=info, descriptor_address=hex(address),
                                   descriptor_evidence=descriptor['evidence'],
                                   lookup_evidence=lookup['evidence'], dll_name_address=hex(base+dll),
                                   readable_prefix=prefix.decode('ascii'),
                                   first_unavailable_address=hex(base+dll+len(prefix)),
                                   first_unavailable_error=fault['error'], prefix_and_fault_evidence=evidence,
                                   explanation='reference reconstruction padding supplies a zero terminator after the readable prefix; native output does not invent the missing byte'))
        if len(candidates) != 1:
            raise ValueError(f'expected exactly one capture-backed explanation, got {len(candidates)}')
        explanations.extend(candidates)
    return dict(schema='gomem.iat-padded-name-differences/v1', image_sha256=verified['image_sha256'],
                native_sha256=native_hash, reference_sha256=diff['sha256']['reference'],
                full_differential_matched=diff['matched'], reference_only_rows=len(wanted),
                explained_rows=len(explanations), unexplained_rows=0,
                explanations=explanations, scope='explains source-backed differences only; full acceptance remains pending')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--comparison', type=Path, required=True)
    parser.add_argument('--verification', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = explain(args.native, args.comparison, args.verification)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(f"{result['explained_rows']} reference-only rows explained; full differential remains {result['full_differential_matched']}")


if __name__ == '__main__':
    main()
