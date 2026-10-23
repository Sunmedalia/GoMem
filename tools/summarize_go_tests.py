#!/usr/bin/env python3
"""Summarize actual Go JSON test events, keeping skips and unfinished runs explicit."""
import argparse
import hashlib
import json
from pathlib import Path


def summarize(lines):
    tests, packages, reasons = {}, {}, {}
    for line in lines:
        event = json.loads(line)
        package, test, action = event.get('Package'), event.get('Test'), event['Action']
        if not package:
            continue
        if test:
            key = (package, test)
            if action == 'run':
                if key in tests:
                    raise ValueError('duplicate test run; use -count=1')
                tests[key] = 'running'
            elif action in ('pass', 'fail', 'skip'):
                if tests.get(key) != 'running':
                    raise ValueError('terminal test event without an active run')
                tests[key] = action
            elif action == 'output' and test in event.get('Output', ''):
                # Ordinary output is intentionally excluded (may contain evidence).
                pass
            elif action == 'output' and ': ' in event.get('Output', ''):
                reasons[key] = event['Output'].strip()
        elif action in ('start', 'pass', 'fail', 'skip'):
            packages[package] = action
    if not tests or not packages:
        raise ValueError('empty test execution')
    unfinished = [f'{p}/{t}' for (p, t), state in tests.items() if state == 'running']
    if unfinished or any(state not in ('pass', 'fail', 'skip') for state in packages.values()):
        raise ValueError(f'incomplete execution: {unfinished[:3]}')
    top = [dict(package=p, test=t, state=state,
                **({'reason': reasons[(p, t)]} if state == 'skip' and (p, t) in reasons else {}))
           for (p, t), state in sorted(tests.items()) if '/' not in t]
    counts = {state: sum(t['state'] == state for t in top) for state in ('pass', 'fail', 'skip')}
    failed = counts['fail'] or any(s == 'fail' for s in tests.values()) or any(s == 'fail' for s in packages.values())
    skipped = any(s == 'skip' for s in tests.values()) or any(s == 'skip' for s in packages.values())
    return dict(schema='gomem.test-execution/v1',
                state='failed' if failed else 'completed_with_skips' if skipped else 'passed',
                scope='Executed test assertions only; no full capability acceptance implied',
                top_level=counts, all_test_events=len(tests), packages=packages, tests=top,
                skipped_subtests=[dict(package=p, test=t, reason=reasons.get((p, t), ''))
                                  for (p, t), state in sorted(tests.items()) if '/' in t and state == 'skip'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.log.open() as stream:
        result = summarize(stream)
    with args.log.open('rb') as stream:
        result['log_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(state=result['state'], **result['top_level'])))
    if result['state'] == 'failed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
