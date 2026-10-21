# Linux suspicious executable mappings — development preview

`linux.malfind` implements the fixed `linux.malware.malfind.Malfind` selection
rules in native Go. The deprecated class name `linux.malfind.Malfind` delegates
to this command while retaining its own task/cache/provenance identity.

```sh
bin/gomem analyze linux.malfind --image memory.raw --symbols kernel.json \
  --case case-001 --offline --format jsonl
bin/gomem analyze linux.malfind --image memory.raw --symbols kernel.json \
  --case case-001 --offline --pid 100 --show-all-dirty-pages --dump-regions
```

The native reader supports Intel x64, x86 and PAE process page tables and
symbol-described linked-list or Maple Tree VMAs. It selects mappings in this
order:

1. `rwx` mappings, including file-backed mappings, select the entire VMA.
2. `r-x` mappings with a null file pointer select the entire VMA.
3. Remaining executable mappings select hardware pages with dirty bit 6 set.

Mappings named `[vdso]` are skipped. A permission label or dirty page is an
investigation lead, not proof of injected or malicious code. Ordinary runtime
behavior can produce both. Anonymous heap/stack labels and file paths use the
existing namespace-aware path reader.

By default the first dirty page produces a result. With
`--show-all-dirty-pages`, every dirty page produces a separate result. Page
iteration uses the full hardware mapping size, including 2 MiB/1 GiB x64,
2 MiB PAE and 4 MiB x86 pages. As in the pinned implementation, the stride is
the full size even when the VMA begins inside a large mapping; it is not
clamped to the remaining VMA extent. Dirty region extraction therefore may
extend beyond the VMA. Bounds and address overflow remain checked.

The fixed default dirty-page display reads bytes from the **VMA start**, but
constructs disassembly at the **first dirty page address**. GoMem preserves
that behavior and records `DataAddress` separately from `RegionStart` and the
structured disassembly address. The all-pages option reads each dirty page's
own bytes. Both variants retain the original VMA `Start`/`End` columns.

## Evidence and errors

`malfind_region` rows retain the VMA object, flags, file pointer, process mm
and pgd fields, object-based process identity, selected region, data address,
and raw display bytes. Dirty rows additionally retain the physical leaf-entry
address, width, original bytes, value and effective page size. The physical
bytes are reread to verify the cached entry before publication. The memory
translator exposes dirty state only when hardware interpretation is known;
Windows software-transition paths explicitly leave it unknown.

Display reads are bounded and page-aware. Missing bytes are zero-padded for
baseline display compatibility, with actual byte captures and read errors
retained separately. Later readable pages remain available. Extraction uses
the case artifact sink and retains gap addresses, sizes, source layer, hashes
and task provenance. The input image is opened read-only.

`dirty_scan` rows record every executable VMA that reaches the dirty-page
check, including mappings with no dirty pages. They include probe, missing
and dirty counts, first/last missing addresses, completion/early-stop state
and two SHA-256 digests. `LeafDigest` hashes little-endian uint64 tuples
`(virtual address, mapping size, physical entry address, raw entry, entry width)`.
`StateDigest` omits the physical entry address so the actual pinned Intel
helper can independently reproduce it. Both hash a failed probe as the
16-byte tuple `(virtual address, UINT64_MAX)`. Each probe contributes once in
traversal order. Digests do not replace raw positive finding captures.

Unmapped, swapped or unreadable executable pages are unavailable coverage,
not clean pages. The task fails when any such gap remains, while keeping
available results and scan summaries. Unlike the baseline's silent skips,
GoMem retries an incomplete task instead of reusing it as a completed cache
entry. Output errors and cancellation stop emission. Native list back-links,
VMA ownership/intervals, field extents and arithmetic receive stricter checks
than the fixed generator; complete damaged-image equivalence is pending.

## Parameters and disassembly

The upstream parameters are `pid`, `hexdump-size` (default 64),
`show-all-dirty-pages`, `dump-regions` and `dump-maxsize` (default 1 GiB).
The dump limit is strict: a region equal to or larger than the limit is
skipped; zero skips all extraction. GoMem retains typed artifact/missing
values rather than upstream filename strings or `Disabled`.

Native bounds add `max-nodes` (131072), `max-regions` (1000000) and `max-pages`
(16777216 total probes). Display bytes are limited to 64 MiB and captured
kernel structures to 4096 bytes. Invalid bounds fail explicitly. A zero-byte
display is supported. Numeric arguments are unsigned in this preview;
negative upstream integer-parameter behavior is not accepted as equivalent.

Disassembly uses `golang.org/x/arch/x86/x86asm` v0.32.0, with 64-bit decoding
for x64 and 32-bit decoding for x86/PAE, matching the pinned architecture
choice. It retains input bytes, PC, architecture, instruction bytes/addresses,
decoded extent and completeness. Decoding stops at unsupported/truncated
instructions or the native 4096-instruction bound. All input bytes remain
available. Text syntax and opcode coverage can differ from Capstone; full
renderer equivalence is not claimed.

See the [validation record](linux-malfind-validation.json) for exact corpus
identities, checked counts and remaining scope.

## Verification

The pinned-source oracle executes the actual `_get_dirty_pages`,
`_is_suspicious`, `_list_injections` and `_generator` over mocked kernel/read
boundaries. Its 24 traversal cases and 14 permission/large-page cases cover
default/all-pages behavior, original display address/PC, no dirty pages,
vdso, missing pages, padded bytes, zero-byte display and architecture. Native
rows compare region bounds, path, permission, bytes, read address, disassembly
bytes/PC/architecture and order; the oracle does not validate decoder text.

Native fixtures use independent process page tables for x64/x86/PAE, plus
x64 dense/range Maple Trees. They independently reread field, display and
physical-leaf captures, verify row seals after all emission, and replay
byte-identical completed results. Tests cover partial reads across page holes,
large mapping sizes, absent pgd, invalid VMA ownership, page/VMA limits,
cancellation, output failures, invalid/truncated instructions and decoder
output bounds. Extraction tests verify the strict size boundary, exact bytes,
artifact integrity and original source addresses in padding logs. Deprecated
name tests compare all cells except explicit alias markers and verify stored
task names, row provenance and cache replay.

```sh
python3 tools/build_malfind_oracle.py --check
go test ./internal/engine -run 'TestLinuxMalfind|TestDeprecatedMalfind' -count=1
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxMalfindDisassembly -fuzztime 10s
```

The supplied Debian 3.2 x64 image (decoded SHA-256
`8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`)
is a negative control. The unmodified pinned plugin returns zero findings.
A separate observation run delegates to the original page scanner, retaining
its decisions and output, and records 3192 executable VMA scans with 210847
probes, 149562 unavailable pages and zero dirty pages. Native selected rows
are also zero, and every scan's counts and `StateDigest` match. All 15960 VMA,
process, flag and file captures are independently reread. The native task is
failed/incomplete for 2880 scans and a rerun retries analysis with identical
evidence, rather than returning a cached clean result. This is not a claim
that the image is clean.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_MALFIND_REFERENCE="$PWD/.cache/malfind-validation/reference" \
GOMEM_MALFIND_OBSERVATIONS="$PWD/.cache/malfind-validation/observations" \
go test -race ./internal/engine -run TestOfficialLinuxMalfind -count=1 -v
```

The reference prefix requires `.json`/`.manifest.json` from `tools/reference.py`;
the observation prefix requires artifacts from
`tools/reference_malfind_observations.py`. Their image, baseline and output
hashes are checked. The observation probe is separately identified and never
substitutes for the unmodified plugin run. Optional skipped tests do not
establish acceptance. Positive real suspicious mappings, modern kernels,
actual x86/PAE acquisitions, ARM64 translation, complete parameter/corruption
and disassembly differentials remain pending. The capability stays partial.
