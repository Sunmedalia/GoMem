# Linux direct module extraction — development preview

`linux.module_extract` is the native command for upstream
`linux.module_extract.ModuleExtract`. It reconstructs one x86/x64 or ARM64 kernel module
from a required `struct module` address. It does not walk the active module
list, sysfs, code extents, taints, or load-parameter arrays. A module whose
parameter display fails in `linux.lsmod` can still be extracted directly.

```sh
bin/gomem analyze linux.module_extract --image memory.raw --symbols kernel.json \
  --case case-001 --offline --param base=0xffffa0426260 --format jsonl
```

Images stay read-only. Python and Volatility are development references only.

## Coordinates and columns

`base` is required and accepts decimal or `0x` hex. On x64 and ARM64, a value inside the
low 48 bits with bit 47 set is sign-extended to the canonical kernel address
used for reads and provenance. A full canonical address is kept as-is. Other
nonzero high bits, and values above 32 bits on x86 or PAE, are rejected before
any row. ARM64 module ELF reconstruction still needs a positive real-image test.

`Base` keeps the exact numeric input, including its rendered width in the
filename `kernel_module.{name}.{input:#x}.elf`. `KernelAddress` is the address
actually read. Decimal `50176` and `0xc400` therefore name the same synthetic
file and produce the same ELF bytes. Low-48 and canonical inputs for the same
real module produce identical ELF bytes and different filenames, matching the
pinned standalone renderer.

Baseline columns are `Base`, `File Size`, and `File output`. Native rows also
retain `KernelAddress`, `Name`, one-byte `BaseProbe` and name captures,
`DumpEvidence`, `RecordType`, and `Error`. `File Size` comes from the stored
artifact size. An unreadable base, name, or reconstruction emits one failed
row with missing file and size fields. The pinned plugin often returns no row
for those failures; the native diagnostic is intentional and is not counted as
a field match.

Reconstruction, gap padding, symbol-table strictness, and native bounds are the
shared exporter documented in [linux-module-elf.md](linux-module-elf.md).
`max-module-bytes` remains a 4KiB..1GiB allocation bound, default 64MiB.
`completed_with_gaps` means unavailable source ranges were zero-padded and
logged, not recovered. Output is the pinned reconstruction, not the original
on-disk module.

## Verification

The supplied Debian 3.2 x64 sample (SHA-256
`8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) was compared
with unmodified Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`.

| Profile | Input base | Module | Filename address | Size | SHA-256 | Gaps |
| --- | --- | --- | --- | --- | --- | --- |
| rfcomm-low48 | `0xffffa0426260` | rfcomm | low 48 bits | 51900 | `b6514a3316c31455e337db70fb1da794a72da07d18035d51c5e657f5b399c5a2` | 2 ranges, 8192 bytes |
| parport-low48 | `0xffffa031e2a0` | parport_pc | low 48 bits | 40468 | `2c03ec0cb9218359ec9916c980a79303d2f67592c4dcfa8d60b1511f2f08772d` | 1 range, 4096 bytes |
| parport-canonical | `0xffffffffa031e2a0` | parport_pc | full canonical | 40468 | same as parport-low48 | same padding log digest |

Each profile matches `Base`, `File Size`, and the artifact filename through
`docs/diff/linux.module_extract.json`, and the extracted file bytes match the
reference. The two `parport_pc` runs share ELF bytes and gap-log digest
`a4be3a3f4c4e59c2bddbe13bfdbe9892b98bf0f178652334081a46a37092efce` while using
different filenames. Each successful row rereads the one-byte probe, module
name, and original symbol table. Case artifact verification passes, and cached
JSONL replay is byte-identical. `parport_pc` parameter-array failures in
`linux.lsmod` are not a prerequisite here; both direct extractions complete.

Nine synthetic x64/x86/PAE profiles remove `modules`, `init_task`,
`module_kset`, and module list, layout, taint, and parameter members before the
symbol table is loaded. Direct extraction of the sysfs-only object still
succeeds and replays. Separate cases cover metadata, name, and symbol faults,
unmapped bases, invalid coordinates, padding, output errors, and cancellation
before and during emission. Failed tasks are not reused.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_MODULE_EXTRACT_REFERENCE_DIR="$PWD/.cache/module-extract-validation" \
go test -race ./internal/engine ./internal/plugins \
  -run 'Test(OfficialLinuxModuleExtract|LinuxModuleExtract|LinuxModuleInput)' -count=1
```

The reference directory must contain `profiles.json`, one manifest, reference
JSON, and extracted file per profile. Skipped optional corpus tests are not
acceptance. Actual native x86/PAE acquisitions, modern metadata, positive ARM64
module extraction, and full smeared-image acceptance remain open.
