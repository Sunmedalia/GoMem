#!/usr/bin/env python3
"""Independent selected RAW/x64/Linux scan oracle, with bounded reads.

Python bytes.find scans each scheduling signature; struct/ISF offsets decode
candidate inline fields, and a separate raw x64 page walker resolves parents
and active object coordinates. No GoMem execution or Volatility imports.
"""
import argparse
import base64
import collections
import hashlib
import json
from pathlib import Path
import struct

from compare_extractions import digest
from verify_elf_extractions import RawX64, load_isf


def scan_offsets(path, needles, chunk_size=1 << 20):
    """An independent C-backed literal search, including boundary matches."""
    width = len(needles[0])
    tail, offset = b'', 0
    with path.open('rb') as source:
        while block := source.read(chunk_size):
            window = tail + block
            hits = []
            for needle in needles:
                cursor = 0
                while (index := window.find(needle, cursor)) >= 0:
                    hits.append((offset - len(tail) + index, needle))
                    cursor = index + 1
            yield from sorted(hits)
            offset += len(block)
            tail = window[-(width - 1):]


def verify(native, active, image, isf, kernel_dtb):
    table, symbols_hash = load_isf(isf)
    image_hash = digest(image)
    if table['base_types']['pointer']['size'] != 8:
        raise ValueError('oracle supports RAW four-level x64 only')
    rows = [json.loads(line) for line in native.read_text().splitlines()]
    task_rows = [r for r in rows if r['cells']['RecordType'].get('value') == 'task']
    summaries = [r for r in rows if r['cells']['RecordType'].get('value') == 'scan_summary']
    if len(summaries) != 1 or len(task_rows) + 1 != len(rows):
        raise ValueError('oracle requires tasks and one summary, with no unreadable diagnostics')
    builds = {r['provenance']['engine_build'] for r in rows}
    if len(builds) != 1 or not task_rows:
        raise ValueError('mixed builds or empty selected task scan')
    for r in rows:
        p = r['provenance']
        if p['image_sha256'] != image_hash or p['symbols_sha256'] != symbols_hash or p['plugin'] != 'linux.psscan':
            raise ValueError('source image/symbol/plugin identity differs')
    scan = summaries[0]['cells']['Scan']['value']
    if scan['complete'] is not True or scan['candidate_read_failures'] != '0' or scan['ranges'] != [dict(start='0x0', length=str(image.stat().st_size))]:
        raise ValueError('oracle requires a complete RAW scan with no read failures')
    params = task_rows[0]['provenance']['parameters']
    slide, max_pid = int(params['engine.kernel-slide'], 0), int(params['max-pid'], 0)
    scheds = {}
    for name, sym in table['symbols'].items():
        if '_sched_class' in name:
            raw = sym['address'] + slide
            if raw >= 1 << 64:
                raise ValueError('scheduler address overflow')
            raw &= (1 << 48) - 1
            address = raw | (0xffff << 48) if raw & (1 << 47) else raw
            scheds.setdefault(address, []).append(name)
    needles = [struct.pack('<Q', v) for v in sorted(scheds)]
    if not needles:
        raise ValueError('no scheduling signatures')
    expected_needles = [dict(address=hex(v), symbols=sorted(scheds[v])) for v in sorted(scheds)]
    if scan['needles'] != expected_needles:
        raise ValueError('scheduler source/alias metadata differs')
    fields = table['user_types']['task_struct']['fields']

    def size(ref):
        if ref['kind'] == 'pointer':
            return 8
        return table['base_types'][ref['name']]['size']

    physical = image.open('rb')
    kernel = RawX64(image, kernel_dtb)

    def raw(address, length):
        physical.seek(address)
        data = physical.read(length)
        if len(data) != length:
            raise ValueError('uncaptured physical candidate field')
        return data

    def scalar(address, field):
        f = fields[field]
        return int.from_bytes(raw(address + f['offset'], size(f['type'])), 'little')

    hits = rejected_state = rejected_pid = rejected_underflow = 0
    candidates = {}
    try:
        for at, needle in scan_offsets(image, needles):
            hits += 1
            address = at - fields['sched_class']['offset']
            if address < 0:
                rejected_underflow += 1
                continue
            state = scalar(address, 'exit_state')
            if state not in (0, 16, 32, 48):
                rejected_state += 1
                continue
            tid = scalar(address, 'pid')
            if not 0 < tid <= max_pid:
                rejected_pid += 1
                continue
            tgid = scalar(address, 'tgid')
            comm = raw(address + fields['comm']['offset'], fields['comm']['type']['count'])
            parent = scalar(address, 'real_parent')
            ppid = int.from_bytes(kernel.read(parent + fields['tgid']['offset'], size(fields['tgid']['type']))[0], 'little') if parent else 0
            candidates[address] = dict(tgid=tgid, tid=tid, ppid=ppid, comm=comm, parent=parent, state=state, scheduler=struct.unpack('<Q', needle)[0])
        native_by_address = {int(r['cells']['Offset']['value'], 16): r for r in task_rows}
        if len(native_by_address) != len(task_rows) or set(native_by_address) != set(candidates):
            raise ValueError('independently scanned candidate set differs')
        invalid_start_counters = 0
        for address, expected in candidates.items():
            c = native_by_address[address]['cells']
            values = dict(PID=expected['tgid'], TID=expected['tid'], PPID=expected['ppid'], Parent=expected['parent'], SchedClass=expected['scheduler'], ExitStateRaw=expected['state'], PhysicalOffset=address)
            for key, val in values.items():
                actual = int(c[key]['value'], 16 if c[key]['kind'] == 'address' else 10)
                if actual != val:
                    raise ValueError('raw task field differs: ' + key)
            if base64.b64decode(c['CommRaw']['value'], validate=True) != expected['comm'] or c['Name']['value'] != expected['comm'].split(b'\0')[0].decode('utf-8', errors='replace'):
                raise ValueError('raw task name differs')
            start_field = fields['start_time']
            if start_field['type']['kind'] == 'struct':
                parts = table['user_types'][start_field['type']['name']]['fields']
                def component(name):
                    part = parts[name]
                    return int.from_bytes(raw(address + start_field['offset'] + part['offset'], size(part['type'])), 'little')
                seconds, nanos = component('tv_sec'), component('tv_nsec')
                start_ns = seconds * 1000000000 + nanos
                if nanos >= 1000000000 or start_ns >= 1 << 64:
                    start_ns = None
            else:
                start_ns = scalar(address, 'start_time')
            stamp = '' if start_ns is None else str(start_ns)
            if start_ns is None:
                invalid_start_counters += 1
                if c['StartTimeNS'].get('kind') != 'missing' or c['StartTimeNS'].get('reason') != 'invalid_start_time':
                    raise ValueError('invalid raw start counter was not retained as missing')
            elif c['StartTimeNS'].get('value') != stamp:
                raise ValueError('raw identity start counter differs')
            # The retained legacy start counter participates in the physical
            # task identity, alongside address/TID; PID alone cannot alias it.
            identity = hashlib.sha256(json.dumps(['thread-v1', image_hash, c['PhysicalLayer']['value'], format(address, 'x'), str(expected['tid']), stamp], separators=(',', ':')).encode()).hexdigest()
            if c['TaskIdentity']['value'] != identity:
                raise ValueError('physical task identity differs')
        counts = dict(pointer_hits=hits, accepted_candidates=len(candidates), rejected_exit_state=rejected_state, rejected_pid=rejected_pid, rejected_underflow=rejected_underflow)
        if any(scan[k] != str(v) for k, v in counts.items()):
            raise ValueError('scan accounting differs')
        active_rows = [json.loads(line) for line in active.read_text().splitlines()]
        active_offsets = set()
        for r in active_rows:
            c, p = r['cells'], r['provenance']
            if p['image_sha256'] != image_hash or p['symbols_sha256'] != symbols_hash or p['engine_build'] != next(iter(builds)) or p['plugin'] != 'linux.pslist' or p['parameters']['threads'] != 'true':
                raise ValueError('active comparison image/symbol/build/thread configuration differs')
            if c['RecordType']['value'] not in ('task', 'thread'):
                raise ValueError('active enumeration is incomplete')
            virtual = int(c['Offset']['value'], 16)
            address = kernel.translate(virtual)
            if address != int(c['PhysicalOffset']['value'], 16):
                raise ValueError('active object physical coordinate differs')
            if address not in candidates or int(c['TID']['value']) != candidates[address]['tid']:
                raise ValueError('active task was not found by the selected scan')
            active_offsets.add(address)
        residual = sorted(set(candidates) - active_offsets)
        if digest(image) != image_hash:
            raise ValueError('source image changed')
        return dict(verified=True, scope='selected RAW/Linux little-endian x64 only; scheduler/PID/exit-state checks remain heuristic', image_sha256=image_hash, symbols_sha256=symbols_hash, engine_build_sha256=next(iter(builds)), counts=counts, active_task_coordinates_verified=len(active_rows), scanned_tasks=len(candidates), valid_start_counters=len(candidates)-invalid_start_counters, invalid_start_counters_retained_as_missing=invalid_start_counters, exit_states=dict(collections.Counter(str(v['state']) for v in candidates.values())), absent_from_active=[dict(physical_offset=hex(a), tid=str(candidates[a]['tid']), exit_state=str(candidates[a]['state'])) for a in residual])
    finally:
        kernel.close()
        physical.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'active', 'image'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--isf', required=True)
    parser.add_argument('--kernel-dtb', type=lambda v: int(v, 0), required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.native, args.active, args.image, args.isf, args.kernel_dtb), indent=2))


if __name__ == '__main__':
    main()
