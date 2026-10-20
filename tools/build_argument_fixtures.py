#!/usr/bin/env python3
"""Generate deterministic Python UTF-8/argument display references for Go tests.

This is a development oracle only; the forensic runtime remains Go-only.
"""
import argparse
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "internal/plugins/testdata/linux-arguments.json"


def generate():
    cases = [bytes([b]) for b in range(256)]
    for lead in (b"\xc2", b"\xe0", b"\xe2", b"\xed", b"\xf0", b"\xf4"):
        for tail in (b"", b"A", b"\x80", b"\xa0", b"\x90\x80", b"\xbf\xbf\xbf", b"\x82A", b"\x82\0"):
            cases.append(lead + tail)
    cases += ["取证🔎".encode(), b"a\0b\0", b"a\0\0", b"\0", b"a ", b"\0\0", b"\xef\xbb\xbfa\0"]
    for i in range(128):
        cases.append(hashlib.sha256(str(i).encode("ascii")).digest()[:i % 32 + 1])
    result = []
    for raw in dict.fromkeys(cases):
        decoded = raw.decode("utf-8", errors="replace")
        args = " ".join(decoded.split("\0"))
        if len(args) > 1 and args[-1] == " ":
            args = args[:-1]
        vector = decoded.split("\0")
        if raw.endswith(b"\0"):
            vector.pop()
        result.append(dict(hex=raw.hex(), decoded=decoded, display=args, arguments=vector))
    return json.dumps(result, ensure_ascii=True, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = generate()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != data:
            raise ValueError("argument fixtures differ from the deterministic Python oracle")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(data)
    print(f"{len(json.loads(data))} UTF-8/argument reference cases verified")


if __name__ == "__main__":
    main()
