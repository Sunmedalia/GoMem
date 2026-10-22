#!/usr/bin/env python3
"""Generate only the MIT pefile ordinal-name data used by native IAT lookup."""
import argparse
import importlib.metadata
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def generate():
    if importlib.metadata.version('pefile') != '2024.8.26':
        raise ValueError('requires pefile==2024.8.26')
    import ordlookup
    source = ('// Code generated from pefile 2024.8.26 ordinal name data; DO NOT EDIT.\n'
              '// Copyright (c) 2004-2024 Ero Carrera. MIT license: ../../LICENSES/pefile-MIT.txt.\n'
              'package pe\n\nvar importOrdinals = map[string]map[uint16]string{\n')
    for name, table in sorted(ordlookup.ords.items()):
        source += '\t' + json.dumps(name.decode()) + ': {\n'
        for ordinal, value in sorted(table.items()):
            source += f'\t\t{ordinal}: ' + json.dumps(value.decode()) + ',\n'
        source += '\t},\n'
    source += '}\n'
    code = subprocess.run(['gofmt'], input=source, text=True, check=True, capture_output=True).stdout
    license_text = importlib.metadata.distribution('pefile').read_text('LICENSE')
    if not license_text or 'Copyright (c) 2004-2024 Ero Carrera' not in license_text:
        raise ValueError('missing pefile license')
    return code, license_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    code, license_text = generate()
    for path, content in [(ROOT/'pkg/pe/import_ordinals.go', code), (ROOT/'LICENSES/pefile-MIT.txt', license_text)]:
        if args.check:
            if path.read_text() != content:
                raise ValueError(f'generated ordinal artifact differs: {path}')
        else:
            path.write_text(content)
    print('696 pefile ordinal names and MIT license verified')


if __name__ == '__main__':
    main()
