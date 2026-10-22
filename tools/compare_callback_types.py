#!/usr/bin/env python3
"""Compare callback values/absent classes; retain native errors as separate evidence.

Use reference_callback_types.py for the reference. This is a selected-field
comparison, not error parity, complete acquisition or release acceptance.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path

FIELDS = ('Type', 'Callback', 'Module', 'Symbol', 'Detail')
ABSENT = {'not_applicable': 'NotApplicableValue', 'not_available': 'NotAvailableValue',
          'unparsable': 'UnparsableValue', 'unreadable': 'UnreadableValue'}
EXCLUDED = {'memory_read', 'callback_symbols', 'callback_candidate', 'summary',
            'diagnostic', 'task_summary'}


def compare(native, reference):
    errors, excluded = collections.Counter(), collections.Counter()
    def projection(row, is_native):
        result = {}
        for key in FIELDS:
            value = row[key]
            if is_native:
                if value['kind'] == 'missing':
                    reason = value['reason']
                    if reason not in ABSENT:
                        raise ValueError(f'unknown native absent reason: {reason}')
                    if value.get('error'):
                        errors[f'{key}:{reason}'] += 1
                    value = {'__absent': ABSENT[reason]}
                else:
                    expected = 'address' if key == 'Callback' else 'string'
                    if value['kind'] != expected:
                        raise ValueError(f'invalid native {key} type')
                    value = value['value']
            if isinstance(value, dict):
                if set(value) != {'__absent'} or value['__absent'] not in ABSENT.values():
                    raise ValueError('invalid reference absent class')
                result[key] = value
            elif key == 'Callback':
                if isinstance(value, bool):
                    raise ValueError('boolean callback address')
                result[key] = str((int(value, 0) if isinstance(value, str) else int(value)) & ((1 << 48) - 1))
            elif isinstance(value, str):
                result[key] = value
            else:
                raise ValueError('reference must preserve absent classes instead of null')
        return json.dumps(result, sort_keys=True)
    actual = collections.Counter()
    for line in native.read_text().splitlines():
        if not line.strip():
            continue
        cells = json.loads(line)['cells']
        record = cells['RecordType']['value']
        if record == 'callback':
            actual[projection(cells, True)] += 1
        elif record in EXCLUDED:
            excluded[record] += 1
        else:
            raise ValueError(f'unknown callback evidence record: {record}')
    expected = collections.Counter()
    rows = json.loads(reference.read_text())
    if not isinstance(rows, list):
        raise ValueError('reference must be a TreeGrid array')
    for row in rows:
        if row.get('__children'):
            raise ValueError('unexpected callback hierarchy')
        expected[projection(row, False)] += 1
    return {'scope': __doc__.strip(), 'matched': actual == expected,
            'native_rows': sum(actual.values()), 'reference_rows': sum(expected.values()),
            'native_error_details_retained': dict(errors), 'excluded_records': dict(excluded),
            'missing': [json.loads(row) for row in (expected - actual).elements()],
            'extra': [json.loads(row) for row in (actual - expected).elements()],
            'sha256': {name: hashlib.sha256(path.read_bytes()).hexdigest()
                       for name, path in [('native', native), ('reference', reference)]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = compare(args.native, args.reference)
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end='')
    raise SystemExit(0 if result['matched'] else 1)


if __name__ == '__main__':
    main()
