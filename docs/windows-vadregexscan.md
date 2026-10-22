# Native Windows VAD regex scanning (development preview)

`windows.vadregexscan` scans process VAD sections in native Go against the fixed
Volatility 3 v2.28.2 `windows.vadregexscan.VadRegExScan` baseline. It remains
**partial** and does not establish complete Windows or Python regex parity.

```sh
gomem analyze windows.vadregexscan --image memory.dmp --symbols ntkrnlmp.json \
  --os windows --arch x64 --dtb 0x1000 --kernel-base 0xfffff80000000000 \
  --case ./case --format jsonl --param pid=1234 --param 'pattern=MZ\x90\x00'
```

The command requires native Intel x86, PAE or x64 translation, matching Windows
symbols and a readable active-process/VAD index. `pid` filters process IDs.
`pattern` is required; explicitly empty text is valid. Each process has its own
DTB and identity including image, object address, PID and available creation
time. Process names use Python-compatible UTF-8 replacement decoding; a
replacement character does not terminate a Windows process name.

VADs are sorted and adjacent intervals coalesced before scanning. The scanner
uses DOTALL byte matching and forward overlap; displayed extraction uses an
anchored expression without implicit DOTALL. The pinned Windows generator
always reads 128 context bytes despite advertising `maxsize`. Native behavior
preserves this distinction and retains the original full match separately.
An invalid pattern fails for a selected process with no VADs; a PID filter
selecting no processes does not compile the pattern.

Evidence and task-wide read, table, entry, mapping, chunk, match and hardware
proof bounds use the [shared regex pipeline](regex-scanning.md). Original
process/VAD metadata, tags, page-table reads, scan digests, match bytes, context
captures and translation correspondence remain traceable. Context padding is
explicit. Process-root failures, damaged VAD indexes, cycles, overlaps, missing
selected pages and resource limits return errors with partial evidence. They
cannot become a clean empty result or successful cache entry.

`max-nodes` bounds process and per-process VAD traversal; `max-regions` bounds
the task's total successful VAD enumeration. Optional mapped-file fields are
not needed to select scan ranges. Successful tasks replay byte-identical
sealed rows from SQLite; failed tasks rerun.

The [actual reference fixture](windows-regex-reference.md) covers 57 paged
Windows generator cases and 39 selected result rows over all three Intel
architectures. Tests compare PID, name, offset, text and bytes, independently
reread raw evidence and verify storage/cache behavior. Additional tests cover
VAD cycles, overlapping ranges, zero process roots, read/table/region/chunk/proof
bounds, cancellation, output failure and uncached retries. The Windows pipeline
fuzzer mutates process/VAD/page-table metadata, regexes and payloads while
checking original match-byte correspondence and bounded output.

Real-image controls and checks are recorded in
[the validation record](windows-vadregex-validation.json). Selected matching
findings do not prove complete coverage. On the Windows 10 19041 x64 control,
`explorer.exe` PID 4912 produces 49/49 matching DOS-stub strings; `smss.exe`
PID 384 produces 0/0. Both are failed/partial: 4,623 and 57 unmapped VAD
interval observations remain, respectively. These are not missing-page counts.
The Explorer task emits 4,096 detailed gaps and accounts for 527 omitted
details. Independent original-image verification covers all 15,866 Explorer
chunks, 49 match/context captures and 49 hardware proofs; the SMSS control
verifies 129 chunks and has no matches. Reference manifests record Python 3.14;
the finite byte-language oracle is pinned to Python 3.12. The real literal
pattern does not depend on minor-version empty-boundary behavior.

Broader Windows versions, legacy VAD
layouts with regex scanning, real x86/PAE positive controls, swap/prototype-page
resolution, full regex grammar/locale behavior, all renderers/exports and
release performance acceptance remain outstanding. Python and Volatility are
development dependencies only; original images remain read-only.
