#!/usr/bin/env python3
"""Bind selected Malfind artifacts and padding logs to independently reread calls.

Run verify_pe_symbols --plugin windows.malfind first. Its JSONL hash binds the
source reread and seal checks; this tool verifies extraction bytes and gaps.
"""
import argparse
import base64
import json
import pathlib

from compare_extractions import digest, member


def rows(path):
    with path.open() as source:
        for line in source:
            yield json.loads(line)


def verify(stream, case, independent):
    bound = json.loads(independent.read_text())
    if (bound.get('plugin') != 'windows.malfind'
            or bound.get('jsonl_sha256') != digest(stream)
            or bound.get('all_captures_independently_reread') is not True
            or bound.get('all_seals_and_provenance_verified') is not True):
        raise ValueError('independent source verification is absent or not bound to this stream')
    results = []
    for row in rows(stream):
        cells = row['cells']
        if cells['RecordType']['value'] != 'finding':
            continue
        if cells['FileOutput']['kind'] != 'artifact':
            raise ValueError('selected finding has no extraction artifact')
        artifact = cells['FileOutput']['value']
        origin, layer = int(cells['Start']['value'], 16), row['provenance']['layer']
        size = int(cells['End']['value'], 16) - origin + 1
        provenance = artifact['provenance']
        if (size <= 0 or provenance['layer'] != layer
                or int(provenance['offset'], 16) != origin):
            raise ValueError('extraction coordinate mismatch')
        for key in ('image_sha256', 'engine_build', 'symbols_sha256', 'plugin', 'parameters'):
            if provenance[key] != row['provenance'][key]:
                raise ValueError('extraction provenance mismatch')
        if provenance['image_sha256'] != bound['image_sha256']:
            raise ValueError('source image mismatch')
        file, log = member(case, artifact['path']), member(case, artifact['gaps_path'])
        if (file.stat().st_size != size or artifact['size'] != str(size)
                or artifact['expected_size'] != str(size) or digest(file) != artifact['sha256']
                or log.stat().st_size != int(artifact['gaps_size'])
                or digest(log) != artifact['gaps_sha256']):
            raise ValueError('extraction file/log digest or size mismatch')
        offset, missing, count, calls = 0, 0, 0, 0
        with file.open('rb') as output, log.open() as gaps:
            for call in rows(stream):
                c = call['cells']
                if (c['RecordType']['value'] != 'memory_read'
                        or c.get('Resolution', {}).get('value', {}).get('method') != 'dump'
                        or call['provenance']['layer'] != layer):
                    continue
                at = int(c['Offset']['value'], 16)
                if not origin <= at < origin + size:
                    continue
                requested, captured = int(c['Requested']['value']), int(c['Captured']['value'])
                encoded = c['Raw']['value']
                if c['Raw']['kind'] != 'bytes' or encoded is None and captured != 0:
                    raise ValueError('invalid original byte evidence')
                raw = b'' if encoded is None else base64.b64decode(encoded, validate=True)
                if (at != origin + offset or requested != min(4096 - (at & 4095), size - offset)
                        or not 0 <= captured <= requested or len(raw) != captured
                        or output.read(captured) != raw):
                    raise ValueError('extraction source-call order, bounds or bytes differ')
                calls += 1
                if captured < requested:
                    gap = json.loads(next(gaps, '{}'))
                    error = c['Error'].get('value')
                    if (int(gap.get('offset', '-1'), 16) != offset + captured
                            or gap.get('length') != str(requested - captured)
                            or int(gap.get('address', '-1'), 16) != at + captured
                            or gap.get('layer') != layer or not error or gap.get('error') != error
                            or output.read(requested - captured) != bytes(requested - captured)):
                        raise ValueError('padding gap is not supported by original failed call')
                    missing += requested - captured
                    count += 1
                elif c['Error']['kind'] != 'missing':
                    raise ValueError('completed extraction has a failed full-length call')
                offset += requested
            if offset != size or output.read(1) or next(gaps, None) is not None:
                raise ValueError('missing extraction calls or extra gap/file data')
        state = 'completed_with_gaps' if count else 'completed'
        if (artifact['state'] != state or artifact['gap_count'] != str(count)
                or artifact['missing_bytes'] != str(missing)):
            raise ValueError('extraction gap totals/state differ')
        results.append(dict(name=artifact['name'], size=size, sha256=artifact['sha256'],
                            acquisition_calls=calls, gap_count=count, missing_bytes=missing,
                            gaps_sha256=artifact['gaps_sha256'], state=state))
    if not results or len(results) != bound['findings']:
        raise ValueError('extraction finding count differs')
    return dict(scope='Selected Malfind artifacts, source calls and padding only; full acceptance pending',
                jsonl_sha256=bound['jsonl_sha256'], independent_report_sha256=digest(independent),
                all_bytes_and_gaps_bound_to_original_calls=True, files=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('jsonl', 'case', 'independent', 'output'):
        parser.add_argument('--' + key, type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(verify(args.jsonl, args.case, args.independent), indent=2) + '\n')


if __name__ == '__main__':
    main()
