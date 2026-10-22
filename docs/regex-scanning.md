# Native regex scanning (development preview)

`regexscan` and `linux.vmaregexscan` now execute in native Go. Both are **partial**
against Volatility 3 v2.28.2, commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. They do not establish complete Python
regex compatibility, complete image coverage or release acceptance.

```sh
gomem analyze regexscan --image memory.raw --arch x64 --dtb 0x1000 \
  --case ./case --format jsonl --param 'pattern=MZ\x90\x00' --param maxsize=128

gomem analyze linux.vmaregexscan --image memory.raw --symbols kernel.json \
  --os linux --dtb 0x1000 --case ./case --format jsonl \
  --param pid=1 --param 'pattern=\x7fELF'
```

The generic command requires an Intel translation layer, without requiring
symbols. Linux scanning requires exact matching Linux symbols, a usable process
page root, task lists and VMA layouts. Both support x86, PAE and x64; ARM64 virtual
scanning is explicitly unsupported. The image remains read-only; results enter
the case directory. Python/Volatility are development tools only.

## Matching and selection

`pattern` must be explicitly supplied. An explicit empty string is a valid
pattern; omission is an error. This distinction is part of the shared plugin
parameter interface. Text becomes UTF-8 pattern bytes, and matching operates on
bytes with ASCII classes and folding. Scanning enables DOTALL; extraction from
result context uses a separately compiled non-DOTALL expression. Generic
extraction searches the context, while VMA extraction anchors at its beginning.
If extraction does not fit, the whole context is displayed.

Generic `maxsize` defaults to 128 and accepts 0..16 MiB. Linux accepts this
parameter but always acquires 128 context bytes, preserving the pinned behavior.
The original full scan match is retained separately from displayed context or
selection. Text replacement follows Python UTF-8 decoding; raw bytes remain
lossless. Null-mm tasks are recorded as skipped, and a pattern is not compiled
if all Linux tasks are skipped before a usable process layer is reached. Linux
PID output is `tgid`; the original task PID remains in `TID`. `comm` is truncated
at NUL or the first replacement character, matching the official helper.

Intel scans use physically and virtually coalesced mappings, fixed 16 MiB steps
and 4 KiB forward overlap. Physically discontinuous runs are separate, even when
virtual pages touch. Each coalesced section may begin with an empty chunk ending
at zero; an empty regex can match it without claiming any source bytes. Adjacent
VMAs are coalesced before scanning. The full reference behavior and independent
core tests are in [the scanner reference](regex-scanning-reference.md) and
[the byte engine](byte-regex.md).

## Evidence and failures

Result rows have `RecordType=regex_match`, `Offset`, `Text`, `Hex`, `MatchLength`,
`MatchRaw`, `VirtualAddress`, `Source` and `Context`. Linux adds process identity,
object address, PID/TID and available creation time. Offsets and all nested
addresses use typed lossless hexadecimal values; counts are typed integers.
`Offset` preserves the baseline flat coordinate; `VirtualAddress` is canonical.

`Source` binds original match bytes to physical/virtual spans and independently
checks native hardware translations and final page-table entries. A pinned
mapping can disagree with hardware translation, notably Windows high-PFN
present entries. Both addresses and an explicit disagreement are retained,
and the task fails coverage. Empty matches have no source bytes.

`Context` preserves original physical captures and explicitly marked missing
or unread suffixes. Display padding is zero-filled and is never reported as
acquired bytes. Full scan windows retain SHA256, exact requested/captured lengths
and original coordinates; failed prefixes are hashed but excluded from matching.
The end-minus-successful-length baseline coordinate can shift after failed
parts, so source correspondence is recorded separately.

Additional records retain address spaces, VMAs, mappings, scan chunks, raw
metadata/page-table reads, gaps and summary coverage. Chunk indices and section
coordinates distinguish repeated empty chunks as evidence parents. Source errors,
unmapped selected VMA spans, incomplete context, failed proofs or execution
limits preserve partial results, return an error and prevent successful cache
reuse. Ordinary unallocated kernel virtual space is not itself an error.
Unavailable captured physical mappings are explicit failures.

Successful tasks replay byte-identical sealed rows from SQLite. Failed tasks run
again. A row's hierarchy, image hash, engine build, symbol digest and parameters
remain sealed provenance; no unverified task is promoted to clean coverage.

## Resource bounds

Scans stream one planned chunk and use at most a 32 MiB scan buffer; individual
memory reads are at most 16 MiB. Defaults are 262,144 enumeration table reads,
268,435,456 inspected entries, 1,000,000 mappings/chunks/matches, 8 GiB of requested
physical reads and 1,048,576 hardware proof pages. Shared progress accounting
also bounds nested context walks. Each regex call defaults to 100 million VM
steps and one second; `regex-steps` adjusts the step bound. Native compile/input
limits and unsupported locale flags remain explicit restrictions.

`max-diagnostics` defaults to 4,096 detailed gap/unavailable-mapping rows. The
summary retains full failure and omitted-detail counts. Linux additionally
bounds process/per-mm traversal with `max-nodes` and task-wide VMAs with
`max-regions`. Bounds fail explicitly; they do not turn partial coverage into an
empty successful result. Paging evidence can be large and is streamed to disk;
no whole-image load is used.

## Validation

- 42 actual Linux VMA and 42 actual generic paged generator comparisons cover
  x86, PAE and x64. All 75 VMA and 147 kernel result rows match the selected
  fields, order, text and bytes. Linux tests verify sealed storage and cache
  replay, including uncached retries after failure.
- Tests cover invalid syntax, skipped null mm, PID/TID distinction, boundary
  signatures, absent pages, padded context, Windows mapping disagreement,
  cancellation, emitter failure, task bounds, empty matches and zero context.
  Original bytes and scan digests are independently reread.
- Foundational references include 35 actual scanner cases, 17 actual Intel
  iterator plans, 12,580 complete match-span comparisons and 80,093 Python UTF-8
  replacement-decoding inputs. These finite tests do not establish full grammar
  or version coverage.
- `FuzzRegexPluginPipeline` mutates real paged fixture metadata, payloads and
  regexes for both plugins, with bounded output and original match-byte checks.
  Core, acquisition and planner fuzz targets remain independently available.

Real-image selected-field controls:

| Image / scan | Compared results | Incomplete coverage |
| --- | ---: | --- |
| Debian 3.2 x64, PID 1 VMAs, `\x7fELF` | 8 / 8 | 44 unmapped VMA spans |
| Debian 3.2 x64, kernel banner | 4 / 4 | 33,351 unavailable physical mappings |
| Windows 10 19041 x64, kernel DOS stub string | 200 / 200 | 660 unavailable physical mappings |

All three tasks are failed/partial despite matching selected findings. The Linux
kernel control emits 4,096 detailed diagnostics and accounts for 29,255 omitted
details in its summary. These are mapping observations, not counts of missing
physical pages. The real references record their actual Python 3.14 interpreter;
the locked byte-language/decoding oracle uses Python 3.12. The tested real
patterns do not depend on minor-version empty-boundary changes.

`tools/verify_regex` independently rereads the original image, verifies row
seals and image hashes, reconstructs scan digests, checks original match/context
bytes and hardware proofs, and rejects duplicate parent identities or resealed
false source claims. The real controls verified 68,363 Windows chunks/200
matches, 738 Linux kernel chunks/4 matches and 128 Linux VMA chunks/8 matches.
The local Kali ARM64 control still reads 111 VMCOREINFO entries through the
physical layer; it is not an ARM64 regex validation.

```sh
go run ./tools/verify_regex --image memory.raw --rows results.jsonl \
  --dtb 0x1000 --arch x64 --os linux
```

See [the machine-readable validation](regex-scanning-validation.json) and
[differential profiles](diff/regexscan.json). Full OS/version/parameter coverage,
macOS controls, real Windows x86/PAE, missing swap/prototype pages, locale flags,
all renderers/exports and release performance acceptance remain outstanding.
