# Linux hidden modules — development preview

`linux.hidden_modules` is the native command for upstream
`linux.malware.hidden_modules.Hidden_modules`. The deprecated
`linux.hidden_modules.Hidden_modules` entry points at the same implementation.
It scans the kernel module allocation window for `struct module` objects that
are not on the active module list.

```sh
bin/gomem analyze linux.hidden_modules --image memory.raw --symbols kernel.json \
  --case case-001 --offline --format jsonl
```

Images stay read-only. Python and Volatility are development references only.

## Scan rules

The symbol producer must be `dwarf2json` 0.8.0 or newer. Missing producer
metadata, another producer, or an older version fails before any row, matching
the pinned version gate. x86, PAE, x64, and ARM64 are supported.

Active addresses come from the `modules` list. The scan bounds are
`mod_tree.addr_min/addr_max` when that symbol exists, otherwise typed
`module_addr_min` and `module_addr_max`. The step is the pointer width. If any
active address is not divisible by that width, the step becomes one byte, as in
the pinned alignment fallback. An empty active list keeps the pointer step.

Each in-range address is considered before it is read. Active addresses are
skipped. Other addresses read `module.mkobj.mod` through the same page-prefix
cache as `linux.modxview`. An unreadable pointer is counted and skipped. A
pointer that does not equal the candidate is skipped. A matching pointer is
then checked with the pinned size and self-reference rules: positive core and
text sizes at most 20000000, core plus init at least 4096, and a readable
module object whose `mkobj.mod` points at itself. Invalid objects are counted
and are not rows. They do not fail the task. The whole-module capture used for
that readability check is bounded at 4096 bytes.

Valid modules absent from the active list use the shared module display:
`Offset`, `Module Name`, `Code Size`, `Taints`, `Load Arguments`, and
`File Output`. `--param dump=true` reconstructs the ELF with the shared bounded
exporter. The final `hidden_scan_summary` row records the window, step, and
counts. It is not a module and is excluded from the selected-column diff.

## Verification

Nine synthetic x64/x86/PAE layouts find exactly `sys-only` and `scan-only`,
exclude the one active module, and reject the one invalid self-pointer. Cached
JSONL replay matches. Tables without a producer, and dwarf2json 0.7.9, fail
with no rows. Cancellation before the scan emits nothing. The step function
keeps a pointer step for aligned addresses and an empty set, and falls back to
one byte otherwise.

The supplied Debian 3.2 x64 sample (SHA-256
`8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) is a
negative control against unmodified Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. The reference returns no rows.
Native scans 587805 positions from `0xffffffffa0000000` up to but not including
`0xffffffffa047c0e5` with step 8, excludes all 79 active modules, skips 79919
unreadable prefilter positions, and rejects 22 invalid self-pointers. No hidden
module row is emitted. The empty selected-column diff matches, and cached JSONL
replay is byte-identical. These 22 rejects are the same additional self-pointer
candidates already observed by `linux.modxview`; they are not hidden modules.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_HIDDEN_MODULES_REFERENCE="$PWD/.cache/hidden-modules-validation/reference" \
go test -race ./internal/engine ./internal/plugins \
  -run 'Test(OfficialLinuxHiddenModules|LinuxHidden)' -count=1
```

The reference prefix must have `.json` and `.manifest.json` from
`tools/reference.py --plugin linux.malware.hidden_modules`. A skipped corpus
test is not acceptance. Positive hidden modules, modern kernels, actual x86/PAE
images, an independent ARM64 comparison, and full smeared-image acceptance remain open.
A local Kali 6.8.11 ARM64 smoke run completes with one scan-summary record and no
hidden-module rows; it is a clean bounded scan, not a positive hidden-module test.
