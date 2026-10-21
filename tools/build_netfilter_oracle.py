#!/usr/bin/env python3
"""Run pinned Netfilter traversal on deterministic kernel object boundaries.

The actual namespace/protocol/device loops, container decoders and flexible
orig_ops arithmetic run unchanged. Object access and module attribution are
mocked; this is not real modern-kernel acceptance.
"""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
from unittest.mock import patch

from baseline_matrix import ROOT, tree_digest

COMMIT = "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
OUTPUT = ROOT / "internal/engine/testdata/linux-netfilter-oracle.json"


class Pointer:
    def __init__(self, obj):
        self.obj = obj

    def __getattr__(self, name):
        return getattr(self.obj, name)

    def dereference(self):
        return self.obj


class Ops(NS):
    def cast(self, _):
        return self


class ListHead:
    def __init__(self, objects=()):
        self.objects = objects

    def to_list(self, _, member):
        assert member in ("list", "dev_list")
        return iter(self.objects)


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    if tree_digest(source) != lock["python_tree_sha256"]:
        raise ValueError("requires pinned unmodified source")
    sys.path.insert(0, str(source))
    from volatility3.plugins.linux.malware import netfilter as nf
    from volatility3.framework.symbols.linux.utilities.modules import Modules
    classes = {
        "list": nf.NetfilterImp_4_3_to_4_9,
        "entry": nf.NetfilterImp_4_9_to_4_14,
        "entries": nf.NetfilterImp_4_14_to_4_16,
        "split": nf.NetfilterImp_4_16_to_latest,
    }
    devices = {
        "list": nf.NetfilterNetDevImp_4_2_to_4_9,
        "entry": nf.NetfilterNetDevImp_4_9_to_4_14,
        "entries": nf.NetfilterNetDevImp_4_14_to_latest,
    }
    cases = []
    for bits in (32, 64):
        for kind, implementation in classes.items():
            for device in (False, True):
                original_arrays = {}
                object_reads = []

                def container(at):
                    ops = Ops(hook=0x8500, priority=-1)
                    shape = "entries" if kind == "split" else kind
                    if shape == "list":
                        return ListHead([ops])
                    if shape == "entry":
                        return Pointer(NS(hook=0xdeadbeef, orig_ops=Pointer(ops), next=0))
                    # Inline hooks intentionally differ from original operations.
                    array_at = at + 16 + 24
                    original_arrays[array_at] = [Pointer(ops)]
                    return NS(num_hook_entries=1, hooks=NS(vol=NS(offset=at + 16), hook=0xdeadbeef))

                empty = ListHead if kind == "list" else lambda: 0
                matrix = [[empty() for _ in range(8)] for _ in range(13)]
                matrix[2][1] = container(0x21800)
                namespace = NS(ns=NS(inum=42), nf=NS(hooks=matrix))
                if kind == "split":
                    namespace.nf = NS(hooks_ipv4=[0, matrix[2][1], 0, 0, 0])
                if device:
                    dev = NS(nf_hooks_ingress=container(0x21900), nf_hooks_egress=container(0x21a00))
                    namespace.dev_base_head = ListHead([dev])

                def object_array(**kwargs):
                    object_reads.append(kwargs["offset"])
                    assert kwargs["object_type"] == "kernel!array"
                    assert kwargs["count"] == 1
                    return original_arrays[kwargs["offset"]]

                layer = NS(is_valid=lambda at: at in original_arrays)
                context = NS(layers={"memory": layer}, object=object_array)
                kernel = NS(name="kernel", symbol_table_name="kernel", layer_name="memory", _context=context,
                            object_from_symbol=lambda _: ListHead([namespace]),
                            get_type=lambda name: NS(size=24 if name == "nf_hook_entry" else bits // 8,
                                                     has_member=lambda member: member in ("nf_hooks_ingress", "nf_hooks_egress")))
                rows = []
                selected = [implementation]
                if device:
                    selected.append(devices["entries" if kind == "split" else kind])
                with patch.object(Modules, "module_lookup_by_address", return_value=(NS(name="__kernel__"), "test_kernel_handler")):
                    for cls in selected:
                        instance = cls.__new__(cls)
                        instance._context, instance.vmlinux = context, kernel
                        instance.handlers = []
                        instance.layer_name = "memory"
                        for netns, proto, hook, priority, handler, owner, symbol, hooked in instance._run():
                            rows.append(dict(netns=netns, proto=proto, hook=hook, priority=priority,
                                             handler=handler, module=owner.name, symbol=symbol, hooked=hooked))
                cases.append(dict(bits=bits, kind=kind, device=device, rows=rows, original_array_reads=object_reads))
    return json.dumps(dict(commit=COMMIT, scope=__doc__, cases=cases), indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / ".cache" / ("volatility3-" + COMMIT))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError("Netfilter oracle differs")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(result)
    print(f"{len(json.loads(result)['cases'])} pinned Netfilter traversal cases verified")


if __name__ == "__main__":
    main()
