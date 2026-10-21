# Linux active modules — development preview

`linux.lsmod` walks the active module list and now uses the same display decoder
as `linux.check_modules`. Existing `Name`, `Base` and core-only `Size` stay usable
by triage. The additional baseline columns are `Module Name`, `Code Size`
(init plus core), `Taints`, `Load Arguments`, and `File Output`.
`--param plain-taints=true` selects plain taint characters; this option and
`max-nodes` are native extensions. Module extents use legacy fields,
`module_layout`, or symbol-described `module_memory` arrays.

Raw list, name, extent, taint and parameter reads remain in `FieldEvidence`.
See [parameter semantics](linux-module-parameters.md) for typed values and bounds.
A required read/layout failure preserves the row and missing value/cause and
fails the task. Partially decoded arguments remain in
`FieldEvidence.LoadArgumentsPartial`. Failed tasks rerun; successful tasks can
replay their persisted evidence. Original images remain read-only.

## Pinned Debian differential

The image is the supplied compressed Debian sample decoded to
`.cache/corpus/linux-sample-1.bin`, SHA-256
`8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`.
Symbols are `Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz`,
auto-discovered DTB `0x1605000`. The reference is the unmodified locked
Volatility 3 v2.28.2 source (`881e970121c16f0932fb9d16fbd5fb258cbcbf75`).

All 79 module identities, code sizes and taints match in list order (addresses
compared modulo the reference Intel layer's low 48 bits). 73 complete six-column
displays match; 38 have nonempty recovered parameters. 1,348 raw captures from
those 73 rows were independently reread from the native kernel layer. The
multiset diff includes all 79 rows, reports `matched=false`, and retains six
missing/extra pairs. No error rows are filtered out of that comparison.

The six differences are `parport_pc`, `snd_ens1371`, `snd_rawmidi`, `snd_seq`,
`snd`, and `usbhid`. The pinned helper recursively interprets raw array elements
as `kernel_param` structures. Invalid/null ops targets are displayed as `None`
elements. GoMem preserves these read failures instead: six unavailable argument
displays, partial parameters, and a failed task. This does not prove successful
array recovery. Successful scalar, boolean and string parameters do have real
positive comparisons. A second run repeats the failed analysis rather than
replaying a completed cache entry. AVML reencoding of this same physical image
has the same expected failed task; it is not an independent acquisition.

## Verification and remaining work

- `TestLinuxLsmodDisplayEvidenceAndCache`: x64/x86/PAE × get/ops, typed argument
  evidence, taints, six-column display and byte-identical SQLite replay.
- `TestLinuxLsmodPartialReadAndEmitFailure`: preserved identity, explicit argument
  failure, failed-task rerun, output error and cancellation propagation.
- `GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(OfficialLinuxLsmodDisplay|OfficialCorpus|OfficialLinuxReencodedAVML)' -count=1 -v`
  checks real order, per-field comparisons, positive parameters and raw captures.
- Full selected-field mapping: [linux.lsmod.json](diff/linux.lsmod.json).

`--param dump=true` now exports reconstructed module ELF files through the
case artifact store; see [module ELF validation](linux-module-elf.md). Without
that option, `File Output` remains `not_requested`. Real modern kernels and x86/PAE acquisitions,
ARM64 virtual translation, all damaged-list behaviors and full baseline
acceptance remain open. This feature remains partial; no capability is accepted.
