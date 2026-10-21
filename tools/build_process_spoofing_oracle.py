#!/usr/bin/env python3
"""Exercise pinned Linux process-name comparison and extraction helpers."""
import argparse
import itertools
import json
from pathlib import Path, PurePosixPath
import sys
from unittest.mock import patch
from types import SimpleNamespace

from baseline_matrix import tree_digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
OUTPUT = ROOT / 'internal/plugins/testdata/linux-process-spoofing-oracle.json'


def generate(source):
    lock = json.loads((ROOT / 'baseline.lock.json').read_text())
    if tree_digest(source) != lock['python_tree_sha256']:
        raise ValueError('process-spoofing oracle requires pinned Python source')
    sys.path.insert(0, str(source))
    from volatility3.plugins.linux.malware.process_spoofing import ProcessSpoofing
    from volatility3.framework.objects import utility
    from volatility3.framework.symbols.linux import LinuxUtilities
    checker = object.__new__(ProcessSpoofing)
    names = [None, '', 'bash', '-bash', 'sh', 'abcdefghijklmnop', 'abcdefghijklmno', '取证🔎abcdefghijklmnop', '取证🔎abcdefghijkl', 'a b', '😀', 'A\ufffd']
    comparisons = []
    for exe, cmd, comm in itertools.product(names, repeat=3):
        cmd_flag, comm_flag = checker._detect_spoofing(exe, cmd, comm)
        comparisons.append(dict(exe=exe, command=cmd, comm=comm, command_spoofed=cmd_flag, comm_spoofed=comm_flag))
    paths = ['', '.', '..', '/', '//', '///', 'a/', 'a/.', 'a/..', 'a/../b', 'a//b///', '/bin/bash', r'C:\bin\bash', 'prog (deleted)', '/a (deleted)', ' /a (deleted)', '/a (deleted) (deleted)', '/a/./b/../', '名字/🔎', 'a b/c d']
    paths = [dict(path=p, basename=PurePosixPath(p).name) for p in paths]
    decoded = []
    for raw in [b'', b'a\x00b', b'a\xffb', 'a\ufffdb'.encode(), b'\xe2\x82', b'a\xe2\x82b', b'\x00', b'/usr/bin/bash\x00--flag\x00', '取证🔎'.encode(), b'/a/.', b'/a/..']:
        value = utility.bytes_to_decoded_string(raw, encoding='utf-8', errors='replace')
        decoded.append(dict(raw=raw.hex(), decoded=value, basename=PurePosixPath(value).name))
    extracted = []
    for exe, cmd, comm in itertools.product([None, '', '/usr/bin/bash', '/tmp/bash (deleted)', ' /tmp/bash (deleted)', '/tmp/name (deleted) (deleted)'], [None, 'bash', 'sh'], [None, 'bash']):
        with patch.object(ProcessSpoofing, 'get_executable_path', return_value=exe), patch.object(ProcessSpoofing, 'get_cmdline_basename', return_value=cmd), patch.object(ProcessSpoofing, 'get_comm', return_value=comm):
            expected = ProcessSpoofing.extract_process_names(None, None)
        extracted.append(dict(exe=exe, command=cmd, comm=comm, basename=expected[1]))
    class Pointer(int):
        def __new__(cls, address, value=None, readable=True):
            obj = int.__new__(cls, address)
            obj.target, obj.readable = value, readable
            return obj

        def is_readable(self):
            return self.readable

        def dereference(self):
            return self.target

        def __getattr__(self, key):
            return getattr(self.target, key)

    dynamic = {}
    for mode in ['dynamic-simple', 'dynamic-alias', 'dynamic-unsupported', 'dynamic-socket', 'dynamic-invalid-inode', 'dynamic-unreadable']:
        callback = Pointer(0x300000 if mode == 'dynamic-unreadable' else 0x8100,
                           readable=mode != 'dynamic-unreadable')
        inode = Pointer(0x18200, SimpleNamespace(i_ino=123, is_valid=lambda: mode != 'dynamic-invalid-inode'))
        name = Pointer(0x19000, SimpleNamespace(cast=lambda *args, **kwargs: 'init'))
        dentry = SimpleNamespace(is_readable=lambda: True, d_inode=inode,
                                 d_op=SimpleNamespace(d_dname=callback), d_name=SimpleNamespace(name=name))
        file = SimpleNamespace(is_readable=lambda: True, get_dentry=lambda: dentry)
        names = ['simple_dname']
        if mode == 'dynamic-alias':
            names = ['alias', 'simple_dname']
        elif mode == 'dynamic-unsupported':
            names = ['custom_dname']
        elif mode == 'dynamic-socket':
            names = ['sockfs_dname']
        module = SimpleNamespace(get_symbols_by_absolute_location=lambda address: ['kernel!' + n for n in names])
        with patch.object(LinuxUtilities, 'get_module_from_volobj_type', return_value=module):
            dynamic[mode] = LinuxUtilities._get_new_sock_pipe_path(None, None, file)
    return json.dumps(dict(commit=COMMIT, comparisons=comparisons, paths=paths, decoded=decoded, extracted=extracted, dynamic=dynamic), ensure_ascii=False, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / '.cache' / ('volatility3-' + COMMIT))
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate(args.source.resolve())
    if args.check:
        if OUTPUT.read_text() != result:
            raise ValueError('Linux process-spoofing oracle differs')
    else:
        OUTPUT.write_text(result)
    data = json.loads(result)
    print(f'{sum(len(data[k]) for k in ("comparisons", "paths", "decoded", "extracted", "dynamic"))} pinned process-spoofing helper cases verified')


if __name__ == '__main__':
    main()
