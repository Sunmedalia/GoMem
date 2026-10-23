#!/usr/bin/env python3
"""Actual fixed YaraScanner and YARA-X reference, without scanner mocks."""
import argparse
import base64
import importlib.metadata
import json
from pathlib import Path
import sys

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/yara/testdata/yarax-oracle.json"


def generate(source):
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified Volatility")
    import yara_x
    if importlib.metadata.version("yara-x") != "1.9.0":
        raise ValueError("requires yara-x 1.9.0")
    sys.path.insert(0, str(source))
    from volatility3.plugins.yarascan import YaraScanner, USE_YARA_X
    if not USE_YARA_X:
        raise ValueError("actual reference must select YARA-X")
    sources = [
        'rule r_literal {strings:$a="AbCd" condition:$a}',
        'rule r_nocase {strings:$a="AbCd" nocase condition:$a}',
        'rule r_wide {strings:$a="AbCd" wide ascii condition:$a}',
        'rule r_hex_jump {strings:$a={41 ?? [1-4] 44} condition:$a}',
        'rule r_regex {strings:$a=/ab+c/i condition:$a}',
        'rule r_overlap {strings:$a="aaa" condition:$a}',
        'rule r_multi {strings:$a="AB" $b="CD" condition:all of them}',
        'rule r_count {strings:$a="AB" condition:#a>=2}',
        'rule r_filesize {strings:$a="AB" condition:$a and filesize>8}',
        'rule r_offset {strings:$a="AB" condition:$a at 2}',
        'rule r_xor_string {strings:$a="AbCd" xor condition:$a}',
        'rule r_encoded {strings:$a="AbCd" base64 condition:$a}',
        'rule r_no_strings {condition:true}',
        'private rule helper {strings:$a="AB" condition:$a} rule public_rule {condition:helper}',
        'rule r_first {strings:$a="AB" condition:$a} rule r_second {strings:$b="CD" condition:$b}',
    ]
    inputs = [b"", b"xxABCDyyabcdABCD", b"AbCd\x00A\x00b\x00C\x00d\x00", b"aaaaa abbbc AB 12 CD QUJDRA==", bytes(range(256))]
    cases = []
    for text in sources:
        rules = yara_x.compile(text)
        for data in inputs:
            matches = []
            for offset, rule, pattern, value in YaraScanner(rules)(data, 0):
                matches.append(dict(offset=offset, rule=rule, pattern=pattern, bytes=base64.b64encode(value).decode()))
            matching_rules = [dict(namespace=r.namespace, rule=r.identifier) for r in rules.scan(data).matching_rules]
            cases.append(dict(source=text, data=base64.b64encode(data).decode(), matches=matches, matching_rules=matching_rules))
    return dict(schema="gomem.yarax-oracle/v1", baseline_commit=COMMIT, yara_x="1.9.0", cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / (".cache/volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    value = json.dumps(result, indent=2) + "\n"
    if args.check:
        if OUTPUT.read_text() != value:
            raise SystemExit("YARA-X oracle differs; regenerate")
    else:
        OUTPUT.parent.mkdir(exist_ok=True)
        OUTPUT.write_text(value)
    print(f"{len(result['cases'])} actual fixed YaraScanner controls verified")


if __name__ == "__main__":
    main()
