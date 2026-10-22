# Windows ETW patch observations (development preview)

`gomem analyze windows.etwpatch --image MEMORY --case CASE` implements the native counterpart of locked Volatility v2.28.2 `windows.etwpatch.EtwPatch`. It reports a first byte of `c3 (RET)` or `e9 (JMP)` at selected ETW functions. These opcode observations alone do not prove malicious patching or disabled ETW. Other instructions, including `RET imm16` (`c2`), are not reported by this baseline.

## Global symbols, individual process bytes

The command first collects file VADs across all active processes and resolves the fixed function list, before applying the optional comma-separated `pid` filter:

- `ntdll.dll`: EtwEventWrite, EtwEventWriteFull, NtTraceEvent, ZwTraceEvent, NtTraceControl, ZwTraceControl, EtwpEventWriteFull.
- `advapi32.dll`: EventWrite and TraceEvent.

Module suffix filtering, exact basename grouping, ordered PDB-name candidates, resident GUID/Age matching, all-instance PDB-first lookup and export fallback follow the shared [module-symbol behavior](module-symbols.md). Relative-only paths and paths without a backslash do not enter the module index. Missing functions remain listed in the summary, including those absent on a Windows version or unavailable without matching private symbols.

Each selected process then creates its own native address space and reads one byte at every globally resolved address. The function address can have been resolved from another process's module instance. A process without its own matching file VAD is still probed. This preserves the baseline's global lookup behavior; the finding's process address space and the symbol resolver's source layer remain distinct in provenance. Different bytes at the same virtual address in two processes produce different observations.

`finding` rows retain the six baseline columns (PID, Process, DLL, Function, Offset, Opcode), process object offset/identity, actual byte, and exact symbol method, source module layer/base/size, available table/source digests and acquisition attempts. Image addresses remain lossless hexadecimal strings. `summary` includes acquisition coverage, selected processes, probes, findings, resolved functions and unresolved names.

## Acquisition evidence and storage

Metadata, RSDS, exports and opcode reads produce `memory_read` evidence with source layer, address, raw bytes, requested/captured sizes and genuine errors. No missing bytes are padded into successful captures. An unreadable opcode is retained while later functions and processes continue. Source acquisition failures, stopped/corrupt lists, invalid metadata and exhausted limits make the task failed/partial while preserving useful rows. Cancellation and output errors stop further reads. Dynamic module symbol dependencies require fresh execution; dependency-aware cache replay remains pending.

Export parsing retains its original exact source reads, including one-byte string acquisitions up to a terminator. To avoid a separate sealed database row for each byte, ETW evidence groups consecutive successful export acquisitions in the same layer, with at most 64 calls and 4KB raw bytes per span. `Resolution.grouped=true` and `Resolution.acquisitions` preserve every original offset, requested length and captured length. `Requested`/`Captured` describe the combined contiguous span; individual call boundaries remain in the acquisition list. The acquisition coverage `Reads` counter counts original calls, not grouped rows. No grouping crosses a failed/partial read, address gap, layer change or unrelated metadata. This changes storage only; it does not add speculative reads past a NUL or across an unavailable page.

The development verifier supports `--plugin windows.etwpatch`. It checks row seals and image/kernel-symbol provenance, independently reconstructs each process address space, and rereads every original call, including calls inside grouped spans. It requires a terminal summary, rejects trailing records or invalid boundary lists, and reconciles the original-call count with the summary. A partially written or canceled JSONL stream cannot establish complete capture verification.

## Bounds

Defaults are 131,072 nodes per process/VAD list, 1,000,000 total indexed VADs, 10,000 matching module instances, 64 MiB captured metadata/symbol/opcode bytes, 1,000,000 acquired PDB symbols and 1,000,000 process/function probes. Parameters are `max-nodes`, `max-regions`, `max-modules`, `max-read-bytes`, `max-symbols`, and `max-probes`. The PID filter changes probes only; module resolution remains global. A byte limit may stop symbol acquisition before opcode probing, with an explicit failed task. Use a justified larger bound when analyzing a large image, for example:

```sh
bin/gomem analyze windows.etwpatch --image memory.dmp --case case-001 \
  --offline --param max-read-bytes=536870912 --format jsonl
```

## Validation

`tools/build_etwpatch_oracle.py` verifies the pinned source tree and runs the actual unmodified EtwPatch generator, process extensions, VAD traversal, process translators, SQLite PDB cache and PE exports. Fifty-six paged x86/x64 fixtures cover RET/JMP/clean/C2 controls, both DLL groups, mixed PDB/export lookup, unavailable names, PID filtering, path normalization/grouping boundaries, resident RSDS boundaries and separate process mappings with different bytes at the same virtual address. No upstream methods are patched.

Native tests also run the 28 x86 fixtures through PAE, giving 84 paging combinations. All six result columns, order and missing values are compared. Raw spans are checked against original fixture bytes and independently reconstructed address spaces. Case-store rows reseal and reproduce the complete JSONL stream; repeated analyses execute fresh. Fault tests cover process/VAD cycles, every declared bound, filename/root/opcode holes, short/invalid read counts, useful export matches alongside provider errors, offline fallback, output failure and cancellation during metadata/opcode/finding output. A bad function byte cannot hide readable later functions. Separate grouping tests check ownership, every original boundary, 64-call/4KB limits, errors, extra fields and output-stop propagation. Fuzzing exercises the complete bounded pipeline with arbitrary first bytes and symbol RVAs, missing opcode bytes, VAD cycles and emitter failures.

The Windows 10 19041 run examined 120 processes, 226 module instances and 19,999 VADs, resolving eight functions and probing 960 process/function addresses. With an explicit 512 MiB bound it captured 113,532,887 bytes in 3,957,291 original calls, stored in 358,840 evidence rows. The independent verifier reconstructed 120 process layers and verified every original acquisition and all 358,841 row seals. There were 52,402 source read faults (52,443 coverage errors including contextual errors), and `EtwpEventWriteFull` remained unresolved. The task therefore failed with useful partial evidence.

The selected-record differential tool streams raw JSONL and hashes files incrementally. Its single local macOS zero-finding comparison processed approximately 816 MiB in 3.23 seconds with 42,762,240 bytes peak RSS. Selected entity rows are still retained for duplicate/tree comparison; this measurement does not establish bounded memory for an arbitrarily large finding set or general performance acceptance.

Real-image validation is recorded in [windows-etwpatch-validation.json](windows-etwpatch-validation.json). The supplied Windows 10 19041 reference has zero findings; read/coverage faults must remain explicit, and this is not positive detection acceptance. Real positive samples, broad Windows builds, matching private symbols, Unicode module corpora, dynamic dependency cache replay and full investigative acceptance remain pending.

```sh
.cache/reference-venv/bin/python tools/build_etwpatch_oracle.py --check
go test -race ./internal/engine -run '^TestETWPatch' -count=1
go test -race ./internal/plugins -run '^TestWindowsReadSpans|^TestETWPatch'
go test ./internal/plugins -run '^$' -fuzz FuzzETWPatchPipeline -fuzztime 10s
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
```
