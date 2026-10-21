#!/usr/bin/env python3
"""Record the fixed process-ghosting helpers and active-process predicate."""
import argparse
import itertools
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from baseline_matrix import tree_digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/windows-processghosting-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('process-ghosting oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.windows.malware.processghosting import ProcessGhosting
    from volatility3.plugins.windows.pslist import PsList
    from volatility3.framework import exceptions, renderers

    def unreadable():
        raise exceptions.InvalidAddressException('fixture', 0xdead)

    class File:
        def __init__(self, address, pending):
            self.vol = SimpleNamespace(offset=address)
            self.pending = pending

        @property
        def DeletePending(self):
            return unreadable() if self.pending is None else self.pending

        def cast(self, _):
            return self

    class Pointer:
        def __init__(self, slot, target, pending):
            self.vol = SimpleNamespace(offset=slot)
            self.file = File(target, pending)

        @property
        def DeletePending(self):
            return self.file.DeletePending

        def dereference(self):
            return self.file

    class Flags:
        def __init__(self, close):
            self.close = close

        @property
        def DeleteOnClose(self):
            return unreadable() if self.close is None else self.close

    processes = []
    for member, slot, target, pending in itertools.product([False, True], [0, 0x480], [0, 0x4000], [None, 0, 1, 2, 255]):
        proc = SimpleNamespace(has_member=lambda _: member, ImageFilePointer=Pointer(slot, target, pending), SectionBaseAddress=0x1000, UniqueProcessId=104)
        expected = [list(row) for row in ProcessGhosting._process_checks(proc, {})]
        processes.append(dict(member=member, slot=slot, target=target, pending=pending, expected=expected))
    vads = []
    for path, pending, close in itertools.product(['a.exe', 'a.EXE', 'a.dll', 'A.DLL', 'a.exe.tmp', 'a.exe ', 'a.txt', '', 'Σ.dll'], [None, 0, 1, 2, 255], [None, 0, 1, 2]):
        control = SimpleNamespace(FilePointer=Pointer(0x3000, 0x4000, pending), u=SimpleNamespace(Flags=Flags(close)))
        expected = [list(row) for row in ProcessGhosting._vad_checks(control, path)]
        vads.append(dict(path=path, pending=pending, close=close, expected=expected))
    active = []
    predicate = PsList.create_active_process_filter()
    for valid, threads, pid, parent, exited, handles in itertools.product([False, True], [0, 2], [4, 104], [4, 100], [0, 1], [False, True]):
        proc = SimpleNamespace(is_valid=lambda: valid, ActiveThreads=threads, UniqueProcessId=pid, InheritedFromUniqueProcessId=parent, ExitTime=SimpleNamespace(QuadPart=exited), get_handle_count=lambda: 0 if handles else renderers.UnreadableValue())
        active.append(dict(valid=valid, threads=threads, pid=pid, parent=parent, exited=exited, handles=handles, expected=not predicate(proc)))
    return json.dumps(dict(commit=COMMIT, processes=processes, vads=vads, active=active), ensure_ascii=False, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('process-ghosting oracle differs')
    else:
        OUTPUT.write_text(result)
    data = json.loads(result)
    print(f'{len(data["processes"])} process, {len(data["vads"])} VAD and {len(data["active"])} active-filter cases verified')


if __name__ == '__main__':
    main()
