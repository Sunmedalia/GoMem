# Linux kernel-module ELF reconstruction — development preview

`linux.lsmod` and `linux.check_modules` support `--param dump=true`. Selected
modules are reconstructed as Intel ELF32/ELF64 relocatable files in the case
artifact store. Enumeration without dumping leaves `File Output` and
`DumpEvidence` as `not_requested`. Images stay read-only; Python and Volatility
are development references only.

```sh
bin/gomem analyze linux.lsmod --image memory.raw --symbols kernel.json \
  --case case-001 --offline --param dump=true --format jsonl
```

The reader supports legacy module symbol fields, inline and pointer kallsyms,
inline section-attribute arrays, legacy `nsections` and the newer group pointer
list count, and pointer, inline-array and binary-attribute section names. Required
metadata and symbol entries use strict reads: missing metadata, null tables,
invalid ELF ABI field offsets/widths and truncated symbols produce an explicit
missing file result and fail the task. `DumpEvidence` retains metadata captures,
the original symbol table bytes and digest, section source coordinates, file
offsets and sizes. Artifact provenance retains the image, symbols, task and
parameters.

Data sections and strings use page-bounded padded reads. Each unreadable tail is
written with the artifact writer's `PadZero`, retaining its exact output offset,
source address, layer, length and read error in the gap log. Such files are
`completed_with_gaps`; that state does not mean their bytes were recovered.
Metadata errors do not become zero-filled symbols. Cancellation, write errors
and artifact finalization errors remain task failures. Artifact evidence now uses
the same canonical JSON object ordering as structured evidence, so successful
fresh rows and cached rows have identical bytes and valid seals.

## Fixed baseline behavior

Reconstruction follows locked Volatility 3 v2.28.2 `ModuleExtract` at commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`, including its heuristic choices:

- Filter section addresses against typed module-allocation bounds. Duplicate
  addresses retain their first position and last name. File sections sort by
  address; `.symtab` is written last.
- Infer ordinary sizes from the next address, with a 64KiB last-section default.
  Read `.strtab` from the module's current string pointer, at most 256 bytes per
  symbol, and trim at the first double NUL (keeping its first NUL).
- Rebuild symbols as local SECTION when unnamed; otherwise global FUNC for
  non-relocation text, OBJECT for other containing sections, and NOTYPE outside.
  Values in a section become relative. `st_size` and `st_other` remain intact.
- Preserve the baseline's original-insertion symbol indexes, zero-based section
  links, 24-byte relocation entry size even for ELF32, allocation flags, alignment
  1, and Python code-point indexing for Unicode section names.

These conventions can leave section links/indexes unsuitable for some ELF
consumers, especially when section order changes. The output is a baseline
reconstruction, not a claim to restore the original on-disk module or a fully
normalized ELF. No silent index repair is mixed into the byte differential.

Native resource limits are 4,096 sections, 65,536 symbols, 255-byte section names,
a 100-entry guard for newer count lists, and a default 64MiB source/output budget
per module. `--param max-module-bytes=N` accepts 4KiB through 1GiB. Inferred
ranges, untrimmed string reads and final output must fit the bound; malformed
sizes never justify unbounded allocation. Reconstruction holds bounded module
buffers, not an entire memory image. Complete behavior beyond these native
limits is not asserted as equivalent to the baseline.

## Verification

The supplied Debian 3.2 x64 sample (SHA-256
`8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`)
exports 79 files byte-for-byte identical to the unmodified pinned extractor:
matching filenames, lengths and SHA-256 hashes. All have gaps. The test
independently rereads 79 original symbol tables and 243 unavailable ranges,
checks all 933,903 padding bytes are zero at the recorded output positions, and
verifies artifact hashes and gap logs through the case store. The task still
fails because six parameter-array displays have the previously documented
[read-error differences](linux-lsmod.md); file parity does not establish argument
parity.

`tools/build_module_elf_oracle.py --check` invokes the actual pinned full
extractor and section parser for 18 deterministic ELF32/ELF64 cases. Only kernel
object/layer boundaries are mocked. Go's independent encoder matches their
complete output sizes and hashes, including reordered/duplicate sections,
Unicode names, relocation sections, last-section sizing, string tails, existing section-name tables and local
symbols. These encoding oracles do not validate real modern metadata layouts.

`TestLinuxModuleELFExportAndCache` covers nine x64/x86/PAE × legacy/inline/pointer
kallsyms profiles, successful SQLite replay, artifact verification and positive
synthetic `check_modules` export. Separate tests cover newer section count,
binary attribute names and inline names on each architecture, missing symtabs,
unreadable metadata, padding, bounds and failed-task reruns. `FuzzModuleELFRebuild`
exercises bounded encoding under arbitrary symbol bytes/addresses.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_MODULE_ELF_REFERENCE_DIR="$PWD/.cache/module-elf-validation" \
go test -race ./internal/engine -run 'Test(OfficialLinuxModuleELFExports|LinuxModuleELF)' -count=1 -v
```

The reference directory must contain `reference.manifest.json` and
`reference-files/`, produced by `tools/reference.py --plugin linux.lsmod`
with `--dump-dir .../reference-files -- --dump`. Skipped optional corpus tests
are not acceptance. Real modern kernels, actual 32-bit images, positive hidden
modules, ARM64 virtual translation and full damaged-image semantics remain open.
