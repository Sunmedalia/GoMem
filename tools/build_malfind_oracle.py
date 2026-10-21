#!/usr/bin/env python3
"""Execute locked Linux Malfind heuristics and generator over mocked objects.

Actual _get_dirty_pages, _is_suspicious, _list_injections and _generator run
unchanged. Kernel objects, translated page state, reads and file output are
mocked boundaries; this does not establish real malicious-code acceptance.
"""
import argparse
import json
import logging
from pathlib import Path
import sys
from types import SimpleNamespace as NS
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-malfind-oracle.json"


def generate(source):
    if tree_digest(source) != json.loads((ROOT / "baseline.lock.json").read_text())["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.plugins.linux.malware.malfind import Malfind
    logging.getLogger(Malfind.__module__).setLevel(logging.ERROR)
    from volatility3.framework import exceptions, symbols
    from volatility3.framework.objects import utility

    class Runner:
        _get_dirty_pages = Malfind._get_dirty_pages
        _is_suspicious = Malfind._is_suspicious
        _list_injections = Malfind._list_injections
        _generator = Malfind._generator

    cases = []
    for bits in (32, 64):
        for scenario in ("standard", "clean", "vdso", "scan-hole", "data-hole", "zero-data"):
            for all_pages in (False, True):
                probe_addresses = []
                read_addresses = []

                def translate(address):
                    probe_addresses.append(address)
                    if scenario == "scan-hole" and address == 0x409000:
                        raise exceptions.InvalidAddressException("process", address)
                    return 0, 4096, "physical"

                def is_dirty(address):
                    return scenario != "clean" and address in (0x409000, 0x40a000)

                def read(address, size, pad):
                    assert pad
                    read_addresses.append(address)
                    if scenario == "data-hole" and address == 0x400000:
                        return bytes(size)
                    index = (address - 0x400000) // 4096
                    return (bytes([0xb8, index, 0, 0, 0, 0xc3, 0x90, 0x90]) + bytes(max(size - 8, 0)))[:size]

                layer = NS(_translate=translate, is_dirty=is_dirty, read=read, page_size=4096)
                context = NS(layers={"process": layer}, modules={"kernel": NS(symbol_table_name="kernel")})
                vmas = []
                for i, (start, end, protection, path, file) in enumerate([
                    (0x400000, 0x402000, "rwx", "Anonymous Mapping", 0),
                    (0x404000, 0x406000, "r-x", "[heap]", 0),
                    (0x408000, 0x40b000, "r-x", "/lib/libfoo.so", 0x13100),
                    (0x40c000, 0x40e000, "r-x", "/lib/libfoo.so", 0x13100),
                ]):
                    if scenario == "vdso" and i == 0:
                        path = "[vdso]"
                    vmas.append(NS(vm_start=start, vm_end=end,
                                   vm_file=NS(dereference=lambda file=file: NS(vol=NS(offset=file))),
                                   get_protection=lambda protection=protection: protection,
                                   get_name=lambda *_, path=path: path))
                task = NS(pid=100, comm="init", mm=NS(get_vma_iter=lambda: iter(vmas)), add_process_layer=lambda: "process")
                runner = Runner()
                runner.context = context
                runner.config = {"kernel": "kernel", "hexdump-size": 0 if scenario == "zero-data" else 64,
                                 "show-all-dirty-pages": all_pages, "dump-regions": False}
                with patch.object(symbols, "symbol_table_is_64bit", return_value=bits == 64), patch.object(utility, "array_to_string", side_effect=lambda x: x):
                    injections = list(runner._list_injections(task))
                    reads = list(read_addresses)
                    rows = list(runner._generator([task]))
                encoded = []
                for (_, row), injection, data_address in zip(rows, injections, reads):
                    pid, name, start, end, path, protection, data, disasm, output = row
                    _, _, _, region_start, region_size = injection
                    encoded.append(dict(pid=pid, process=name, start=start, end=end, path=path, protection=protection,
                                        data=bytes(data).hex(), data_address=data_address, region_start=region_start,
                                        region_size=region_size, disasm_address=disasm.offset,
                                        disasm_data=disasm.data.hex(), architecture=disasm.architecture, file_output=output))
                assert len(encoded) == len(rows) == len(injections)
                cases.append(dict(bits=bits, scenario=scenario, all_pages=all_pages, rows=encoded))
    # Pin the less usual permission combinations and large-page stepping too.
    flags = []
    runner = Runner()
    for protection in ("---", "--x", "-wx", "r--", "rw-", "r-x", "rwx"):
        for file in (0, 1):
            vma = NS(vm_start=0x401000, vm_end=0x403000,
                     vm_file=NS(dereference=lambda file=file: NS(vol=NS(offset=file))),
                     get_protection=lambda protection=protection: protection)
            layer = NS(_translate=lambda address: (0, 2 << 20, "physical"), is_dirty=lambda address: True, page_size=4096)
            value = runner._is_suspicious(layer, vma)
            flags.append(dict(protection=protection, file=file, result=list(value) if value else None,
                              dirty_pages=list(runner._get_dirty_pages(layer, vma))))
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases, flags=flags), indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / ".cache" / ("volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("Malfind oracle differs")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(result)
    data = json.loads(result)
    print(f"{len(data['cases'])} pinned Malfind traversals and {len(data['flags'])} flag/large-page cases verified")


if __name__ == "__main__":
    main()
