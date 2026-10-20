#!/usr/bin/env python3
"""Record Python stat's independent oracle for every permission combination of Linux inode types, plus an unset type."""
import argparse
import hashlib
import json
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'internal/plugins/testdata/linux-inode-mode-oracle.json'


def oracle():
    types = [(stat.S_ISDIR, 'DIR'), (stat.S_ISREG, 'REG'), (stat.S_ISLNK, 'LNK'), (stat.S_ISFIFO, 'FIFO'), (stat.S_ISSOCK, 'SOCK'), (stat.S_ISCHR, 'CHR'), (stat.S_ISBLK, 'BLK')]
    sha = hashlib.sha256()
    for mode in range(65536):
        if stat.S_IFMT(mode) not in (0, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFDIR, stat.S_IFBLK, stat.S_IFREG, stat.S_IFLNK, stat.S_IFSOCK):
            continue
        kind = next((name for test, name in types if test(mode)), '')
        sha.update(f'{mode}\t{kind}\t{stat.filemode(mode)}\n'.encode())
    return dict(schema='gomem.posix-mode-oracle/v1', producer='Python standard library stat.filemode and S_IS*', cases=32768, encoding='UTF-8: decimal-mode TAB type-or-empty TAB filemode LF; ascending 16-bit modes whose type is unset or one of Linux FIFO/CHR/DIR/BLK/REG/LNK/SOCK; excludes host-specific whiteout/door/port types', sha256=sha.hexdigest())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check', action='store_true')
    args = p.parse_args()
    record = oracle()
    if args.check:
        if json.loads(OUTPUT.read_text()) != record:
            raise ValueError('inode mode oracle differs from the checked-in reference')
        print('32768 Linux POSIX modes verified against Python stat')
    else:
        OUTPUT.write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
