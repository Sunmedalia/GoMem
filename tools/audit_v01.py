#!/usr/bin/env python3
"""Audit the frozen v0.1 native inventory; never certify forensic correctness."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(specs, matrix, root):
    by_name = {}
    for spec in specs:
        name = spec['name']
        if not name or name in by_name or not spec.get('description') or not spec.get('columns'):
            raise ValueError(f'invalid/duplicate native plugin: {name}')
        for field in ('parameters', 'columns'):
            seen = set()
            for item in spec.get(field, []):
                if not item['name'] or item['name'] in seen or not item.get('kind'):
                    raise ValueError(f'{name}: invalid/duplicate {field}')
                seen.add(item['name'])
        by_name[name] = spec
    if not by_name:
        raise ValueError('empty native inventory')
    mapped = {name: [] for name in by_name}
    seen_ids = set()
    for entry in matrix['plugins']:
        if entry['id'] in seen_ids:
            raise ValueError('duplicate upstream ID')
        seen_ids.add(entry['id'])
        name = entry.get('native')
        if not name:
            continue
        if name not in by_name or entry['status'] == 'missing':
            raise ValueError(f'unregistered/missing native mapping: {name}')
        if not entry.get('corpora') or not entry.get('comparison') or not entry.get('gaps'):
            raise ValueError(f'{name}: missing validation scope or limitations')
        relative = Path(entry['validation_record'])
        if relative.is_absolute() or '..' in relative.parts or relative.parts[0] != 'docs':
            raise ValueError(f'{name}: unsafe validation path')
        record = root / relative
        if not record.is_file():
            raise ValueError(f'{name}: absent validation record {relative}')
        mapped[name].append(dict(
            id=entry['id'], status=entry['status'], accepted=entry['accepted'],
            applicability=entry['applicability'], comparison=entry['comparison'],
            corpora=entry['corpora'], gaps=entry['gaps'],
            validation_record=relative.as_posix(), validation_sha256=digest(record)))
    result = []
    for name, spec in sorted(by_name.items()):
        entries = sorted(mapped[name], key=lambda e: e['id'])
        if spec.get('upstream') and spec['upstream'] not in {e['id'] for e in entries}:
            raise ValueError(f'{name}: declared upstream has no matrix mapping')
        result.append(dict(name=name, spec=spec, upstream=entries,
                           review='inventory_consistent',
                           behavioral_acceptance='pending'))
    return dict(schema='gomem.v01-inventory/v1', milestone='v0.1',
                release='development-preview', baseline=matrix['baseline'],
                scope='Frozen native schemas and documented support; no full capability certification',
                native_plugins=len(result), mapped_upstream_classes=sum(len(e) for e in mapped.values()),
                plugins=result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugins', required=True, type=Path,
                        help='JSON from gomem plugins --format json')
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/v0.1-plugin-inventory.json')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true', help='Explicitly update the reviewed inventory')
    mode.add_argument('--check', action='store_true', help='Fail on registration, schema, scope or record drift')
    args = parser.parse_args()
    matrix = json.loads((ROOT / 'docs/capabilities.json').read_text(encoding='utf-8'))
    result = inventory(json.loads(args.plugins.read_text(encoding='utf-8')), matrix, ROOT)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.write:
        args.output.write_text(rendered, encoding='utf-8')
    elif not args.output.is_file() or args.output.read_text(encoding='utf-8') != rendered:
        raise SystemExit('v0.1 inventory drift: review support/validation and explicitly update --write')
    print(f"{result['native_plugins']} native commands / {result['mapped_upstream_classes']} upstream classes audited; behavioral acceptance remains pending")


if __name__ == '__main__':
    main()
