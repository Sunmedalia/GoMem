#!/usr/bin/env python3
"""Run v0.1 corpus regressions with explicit local reference inputs, without silent skips."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from summarize_go_tests import summarize

ROOT = Path(__file__).resolve().parents[1]
PREFIXES = {
    'GOMEM_FBDEV_REFERENCE', 'GOMEM_FTRACE_REFERENCE', 'GOMEM_HIDDEN_MODULES_REFERENCE',
    'GOMEM_KALLSYMS_REFERENCE', 'GOMEM_KMSG_REFERENCE', 'GOMEM_LIBRARY_LIST_REFERENCE',
    'GOMEM_MALFIND_REFERENCE', 'GOMEM_MALFIND_OBSERVATIONS', 'GOMEM_NETFILTER_REFERENCE',
    'GOMEM_PIDHASH_REFERENCE', 'GOMEM_PIDHASH_DECORATED_REFERENCE', 'GOMEM_PERF_EVENTS_REFERENCE',
    'GOMEM_PSCALLSTACK_REFERENCE', 'GOMEM_SOCKSCAN_REFERENCE', 'GOMEM_TRACEPOINTS_REFERENCE',
}
DIRECTORIES = {'GOMEM_CORPUS_DIR', 'GOMEM_BASELINE_DIR', 'GOMEM_MODULE_ELF_REFERENCE_DIR',
               'GOMEM_MODULE_EXTRACT_REFERENCE_DIR'}
FILES = {'GOMEM_KALI_IMAGE', 'GOMEM_FBDEV_KALI_IMAGE', 'GOMEM_FBDEV_KALI_SYMBOLS',
         'GOMEM_PE_EXPORT_REFERENCE', 'GOMEM_PE_EXPORT_MAPPED'}


def inputs(profile, root):
    if set(profile) != PREFIXES | DIRECTORIES | FILES:
        raise ValueError('corpus profile must declare all supported inputs, without unknown keys')
    result = {}
    for key, value in profile.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f'{key}: missing local path')
        path = (root / value).resolve()
        check = Path(str(path) + '.manifest.json') if key in PREFIXES else path
        if not (check.is_dir() if key in DIRECTORIES else check.is_file()):
            raise ValueError(f'{key}: unavailable local input {check}')
        result[key] = str(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    if args.log.exists() or args.report.exists():
        raise FileExistsError('choose new log/report paths to preserve earlier execution evidence')
    raw = args.inputs.read_bytes()
    environment = dict(os.environ, **inputs(json.loads(raw), ROOT))
    command = [args.go, 'test', '-json', '-count=1', '-timeout', '60m', './internal/engine',
               '-run', '^(TestOfficial|TestKaliARM64Fbdev)']
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation keeps earlier execution evidence from being overwritten.
    with args.log.open('x', encoding='utf-8') as stream:
        result = subprocess.run(command, cwd=ROOT, env=environment, stdout=stream)
    with args.log.open(encoding='utf-8') as stream:
        report = summarize(stream)
    report['command'] = command
    report['inputs_sha256'] = hashlib.sha256(raw).hexdigest()
    with args.log.open('rb') as stream:
        report['log_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    report['exit_code'] = result.returncode
    with args.report.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(state=report['state'], **report['top_level'])))
    if result.returncode or report['state'] != 'passed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
