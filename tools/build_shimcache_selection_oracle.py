#!/usr/bin/env python3
"""Run the pinned Windows version distinguishers and Shimcache layout table."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "pkg/winshimcache/testdata/selection-oracle.json"


def fixture(width, version, symbols=(), members=(), types=()):
    """Build an ISF with explicit symbol/type/member presence controls."""
    pointer = dict(kind="int", size=width, endian="little", signed=False)
    all_types = {
        "_HANDLE_TABLE": dict(kind="struct", size=8, fields={}),
        "_OBJECT_HEADER": dict(kind="struct", size=8, fields={}),
        "_KPRCB": dict(kind="struct", size=8, fields={}),
    }
    for name in types:
        all_types.setdefault(name, dict(kind="struct", size=8, fields={}))
    for typ, member in members:
        all_types.setdefault(typ, dict(kind="struct", size=8, fields={}))
        all_types[typ]["fields"][member] = dict(
            offset=0, type=dict(kind="base", name="unsigned char")
        )
    windows = {}
    if version is not None:
        windows["pe"] = version
    return dict(
        metadata=dict(
            format="6.2.0",
            windows=windows,
            producer=dict(
                name="GoMem synthetic Windows version control",
                version="1.0.0",
                datetime="2026-10-23T00:00:00Z",
            ),
        ),
        base_types={
            "pointer": pointer,
            "unsigned char": dict(
                kind="int", size=1, endian="little", signed=False
            ),
        },
        user_types=all_types,
        symbols={
            name: dict(address=0x1000 + index * 0x10)
            for index, name in enumerate(symbols)
        },
        enums={},
    )


def cases():
    exact = [
        ("xp-x86", 4, dict(major=5, minor=1, revision=2600, build=1)),
        ("2003-x86", 4, dict(major=5, minor=2, revision=3790, build=1)),
        ("2003-x64", 8, dict(major=5, minor=2, revision=3790, build=1)),
        ("vista-x86", 4, dict(major=6, minor=0, revision=6002, build=1)),
        ("vista-x64", 8, dict(major=6, minor=0, revision=6002, build=1)),
        ("win7-x86", 4, dict(major=6, minor=1, revision=7600, build=1)),
        ("win7-x64", 8, dict(major=6, minor=1, revision=7601, build=1)),
        ("win8-x86", 4, dict(major=6, minor=2, revision=9200, build=1)),
        ("win8-x64", 8, dict(major=6, minor=2, revision=9200, build=1)),
        ("win81-x86", 4, dict(major=6, minor=3, revision=9600, build=1)),
        ("win81-x64", 8, dict(major=6, minor=3, revision=9600, build=1)),
        ("win10-x86", 4, dict(major=10, minor=0, revision=19041, build=1)),
        ("win10-x64", 8, dict(major=10, minor=0, revision=19041, build=1)),
    ]
    three = [
        ("xp-three-x86", 4, dict(major=5, minor=1, revision=2600),
         ("_MMFREE_POOL_ENTRY",), (("_HANDLE_TABLE", "HandleCount"),)),
        ("win7-three-x86", 4, dict(major=6, minor=1, revision=7600),
         (), (("_OBJECT_HEADER", "TypeIndex"), ("_HANDLE_TABLE", "HandleCount"))),
        ("win7-three-x64", 8, dict(major=6, minor=1, revision=7601),
         (), (("_OBJECT_HEADER", "TypeIndex"), ("_HANDLE_TABLE", "HandleCount"))),
        ("win8-three-x64", 8, dict(major=6, minor=2, revision=9200),
         ("KdCopyDataBlock",), (("_OBJECT_HEADER", "TypeIndex"),)),
    ]
    fallbacks = [
        ("fallback-win10-x64", 8, ("ObHeaderCookie",),
         (("_HANDLE_TABLE", "HandleCount"),)),
        ("fallback-win10-x86", 4, ("ObHeaderCookie",),
         (("_HANDLE_TABLE", "HandleCount"),)),
        ("fallback-win8-x64", 8, ("KdCopyDataBlock",),
         (("_HANDLE_TABLE", "HandleCount"), ("_KPRCB", "PendingTickFlags"),
          ("_OBJECT_HEADER", "TypeIndex"))),
        ("fallback-win8-x86", 4, ("KdCopyDataBlock",),
         (("_HANDLE_TABLE", "HandleCount"), ("_KPRCB", "PendingTickFlags"),
          ("_OBJECT_HEADER", "TypeIndex"))),
        ("fallback-win7-x64", 8, (),
         (("_OBJECT_HEADER", "TypeIndex"), ("_HANDLE_TABLE", "HandleCount"))),
        ("fallback-win7-x86", 4, (),
         (("_OBJECT_HEADER", "TypeIndex"), ("_HANDLE_TABLE", "HandleCount"))),
        ("fallback-vista-x64", 8, ("KdCopyDataBlock",),
         (("_OBJECT_HEADER", "TypeIndex"), ("_HANDLE_TABLE", "HandleCount"))),
        ("fallback-vista-x86", 4, ("KdCopyDataBlock",),
         (("_OBJECT_HEADER", "TypeIndex"), ("_HANDLE_TABLE", "HandleCount"))),
        ("fallback-2003-x64", 8, ("_MM_AVL_TABLE",),
         (("_HANDLE_TABLE", "HandleCount"), ("_OBJECT_HEADER", "TypeIndex"))),
        ("fallback-2003-x86", 4, ("_MM_AVL_TABLE",),
         (("_HANDLE_TABLE", "HandleCount"), ("_OBJECT_HEADER", "TypeIndex"))),
        ("fallback-xp-sp3-x86", 4, ("_MMFREE_POOL_ENTRY",),
         (("_HANDLE_TABLE", "HandleCount"),)),
        ("fallback-xp-sp2-x86", 4, (), (("_HANDLE_TABLE", "HandleCount"),)),
        ("fallback-xp-or-2003-x86", 4, (), (("_HANDLE_TABLE", "HandleCount"),)),
        ("fallback-win10-short-circuit", 8, ("ObHeaderCookie",), ()),
        ("fallback-win7-short-circuit", 8, (), (("_OBJECT_HEADER", "TypeIndex"),)),
        ("fallback-vista-short-circuit", 8, (), (("_HANDLE_TABLE", "HandleCount"),)),
        ("fallback-none", 8, (), ()),
    ]
    out = []
    for name, width, version in exact:
        out.append((name, width, fixture(width, version)))
    for name, width, version, symbols, members in three:
        out.append((name, width, fixture(width, version, symbols, members)))
    for name, width, symbols, members in fallbacks:
        out.append((name, width, fixture(width, None, symbols, members)))
    return out


def generate(source):
    if tree_digest(source) != json.loads(
        (ROOT / "baseline.lock.json").read_text()
    )["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.framework import contexts
    from volatility3.framework.symbols import intermed
    from volatility3.framework.symbols.windows import versions
    from volatility3.plugins.windows.shimcachemem import ShimcacheMem

    checks = {
        "is_win10": versions.is_win10,
        "is_windows_8_or_later": versions.is_windows_8_or_later,
        "is_windows_8_1_or_later": versions.is_windows_8_1_or_later,
        "is_windows_7": versions.is_windows_7,
        "is_vista_or_later": versions.is_vista_or_later,
        "is_2003": versions.is_2003,
        "is_windows_xp_sp3": versions.is_windows_xp_sp3,
        "is_windows_xp_sp2": versions.is_windows_xp_sp2,
        "is_xp_or_2003": versions.is_xp_or_2003,
    }
    generated = []
    with tempfile.TemporaryDirectory(prefix="gomem-shimcache-selection-") as temporary:
        path = Path(temporary) / "kernel.json"
        for name, width, isf in cases():
            path.write_text(json.dumps(isf))
            context = contexts.Context()
            context.symbol_space.append(
                intermed.IntermediateSymbolTable(
                    context, "kernel", "kernel", path.as_uri()
                )
            )
            values = {
                check: bool(function(context, "kernel"))
                for check, function in checks.items()
            }
            is64 = width == 8
            selected = next(
                (
                    filename
                    for function, for64, filename in ShimcacheMem._win_version_file_map
                    if is64 == for64
                    and next(
                        check
                        for check, candidate in checks.items()
                        if candidate is function
                    )
                    in values
                    and values[
                        next(
                            check
                            for check, candidate in checks.items()
                            if candidate is function
                        )
                    ]
                ),
                None,
            )
            if values["is_windows_8_or_later"]:
                route = "modern"
            elif (
                values["is_2003"]
                or values["is_vista_or_later"]
                or values["is_windows_7"]
            ):
                route = "2003-to-7"
            elif values["is_windows_xp_sp2"] or values["is_windows_xp_sp3"]:
                route = "xp"
            else:
                route = "unsupported"
            generated.append(
                dict(
                    name=name,
                    width=width,
                    isf=isf,
                    checks=values,
                    selected=selected,
                    route=route,
                    is_8_1_or_later=values["is_windows_8_1_or_later"]
                    or values["is_win10"],
                )
            )
    return (
        json.dumps(
            dict(
                commit=COMMIT,
                scope=(
                    "Unmodified Volatility OsDistinguisher functions and the "
                    "ShimcacheMem newest-to-oldest layout table over synthetic ISF "
                    "presence controls."
                ),
                cases=generated,
            ),
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=ROOT / (".cache/volatility3-" + COMMIT),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit("Shimcache version-selection oracle drift")
    else:
        OUTPUT.write_text(result)
    print(
        f"{len(json.loads(result)['cases'])} pinned Shimcache "
        "version-selection controls verified"
    )


if __name__ == "__main__":
    main()
