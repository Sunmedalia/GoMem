# Native Windows window stations

`windows.windowstations` is a development-preview implementation against
Volatility 3 v2.28.2 commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`.
It is partial and has no release acceptance.

```sh
gomem analyze windows.windowstations --image memory.dmp --symbols kernel.json \
  --os windows --case case-001 --format jsonl
```

## Acquisition and output

The native path selects an x64 GUI layout using pinned metadata/feature rules,
loads only digest-pinned data (automatically online unless `--offline`), and
records layout name, digest, selection method and source URL in `gui_symbols`.
Kernel and GUI tables have distinct roles; optional executive headers use the
kernel table, while body sizes and validity use the selected GUI table.

The scanner uses the original Wind constraints, OS-dependent physical/kernel
scan space, allocation filters and top-down/bottom-up executive carving.
Active processes produce the first address space for each session in original
forward/backward order. A pool candidate's session ID is read in the scan layer;
its object is then rebound at the same address to that session layer. No primary
kernel substitution occurs when the selected process layer is unusable.
`gui_session` records retain process/PID, session pointer, raw/normalized CR3 and
selection method. Layer names tie each translated result/read to that selection.

Station traversal preserves the original repeated root pointer and global
address deduplication. Names and session predicates follow original Unicode
and executive-header behavior, including unusual decoded names. They do not
independently prove live objects. `windowstation` rows retain Offset, Name,
SessionId, raw name bytes, header/name-info/buffer addresses and source-layer
provenance. Invalid/unbound candidates are explicit `gui_candidate` records.
No failed read is represented as an empty successful scan.

`memory_read` records retain source layer/address, requested/captured lengths,
SHA256 and completeness/error. Bounded metadata, session-name reads and session
page-table reads also preserve raw bytes; larger scan reads retain digests.
Nested physical/kernel/session reads are separate observations, so failure and
byte counters do not count distinct pages or unique source bytes.

The final `task_summary` records sessions, candidates, stations, unbound
candidates, read/byte/row totals and Completed. Read and semantic failures retain
partial evidence and fail the task. Output errors and cancellation terminate.
Bounds are max-read-bytes (default 16GiB), max-reads (4million), max-rows
(1million), max-processes (131072), max-sessions (4096), and max-stations
(15 additional stations per root; zero retains the root). Bounds are additional
native parameters; defaults preserve the original traversal limits.

GUI layouts are runtime dependencies. Until all dependencies can be revalidated
before cache lookup, successful executions explicitly run fresh and reload the
verified layout; completed task replay is disabled. Failed executions also run
fresh. This does not yet satisfy the plan's successful task resume/cache goal.

## Verification

`tools/build_windowstations_oracle.py` runs the unmodified original complete
WindowStations generator, including real pool scanning, session discovery,
Intel process page tables and executive name extensions. It uses 16 scenarios
on GUI layout 19041, with positive stations, repeated-root traversal, duplicate
PIDs, absent sessions/processes, invalid names/IDs, free/short pools, read holes,
null pointers and an unusable session CR3. A session-private object-page mapping
has a different name from the kernel mapping; both original and native return
the session text. The physical copy remains an additional scanned pool object,
and both implementations preserve that second row.

All 16 ordered Offset/Name/SessionId comparisons pass. Every emitted read is
independently reread using its physical/kernel/session coordinates. Additional
guards cover bounds, cancellation and emitter errors. 14 engine cases (all
without synthetic byte-layer holes) check identical streamed/stored sealed
rows, fresh task IDs, failed retry and rejection of corrupted GUI layout caches.
The optional real audit also verifies reference configuration and the same
kernel ISF archive member. Related component oracles separately cover 12 GUI
layouts; those are not 12 complete-plugin/version acceptance tests.

```sh
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_windowstations_oracle.py --check
go test -race ./internal/plugins -run '^TestWindowStations' -count=1
go test -race ./internal/engine -run '^TestWindowStationsSealed' -count=1
go test ./internal/plugins -run '^$' -fuzz '^FuzzWindowStationsPagedPipeline$' -fuzztime 1000x
```

The complete plugin package race passed in 58.053s, targeted engine race 30.629s,
and paged pipeline fuzzing completed 1119 inputs in 10.485s (1000-input budget).

## Real Windows 10 19041 control

Native independent pool discovery returns the same 13 ordered station rows as
the original, including the unusual names. The strict differential profile is
[windows.windowstations.json](diff/windows.windowstations.json); only the
canonical-vs-low48 address representation is normalized. The original reference
has no missing or extra selected rows. Native retains 3322 pool candidates,
22 without a selected session layer, and 3493 invalid/unbound candidate records.

The task remains **failed/incomplete**: 3723 failed read observations and 194
semantic failure observations are retained; these overlap/nest and are not
unique missing pages. Four unavailable session-ID reads at 0x8 are included.
The original silently skips many failures. Matching recovered rows therefore
does not prove complete acquisition or a clean image.

The audit verifies 187015 row seals, identical SQLite/streamed evidence,
183503 source reads, 805546216 captured bytes and 89487 raw captures against the
read-only image. The exact kernel ISF matches the original archive member.
See [validation hashes and limits](windows-windowstations-validation.json).
No independent PDB conversion or full supported-OS acceptance is claimed.

For the current sample, generate the original reference with the pinned
`tools/reference.py` invocation for plugin `windows.windowstations`, retaining
its adjacent configuration and manifest; acquire native JSONL with the command
above. Then audit the existing task (using its printed task ID):

```sh
GOMEM_WINSTA_IMAGE="$PWD/.cache/corpus/win-10_19041-2025_03.dmp" \
GOMEM_WINSTA_SYMBOLS="$PWD/.cache/corpus/symbols/windows/167FE94B5641C005AC3036212A01F8DC-1.json" \
GOMEM_WINSTA_CASE="$PWD/.cache/windowstations-validation/native" \
GOMEM_WINSTA_TASK=TASK_ID \
GOMEM_WINSTA_WIRE="$PWD/.cache/windowstations-validation/native.jsonl" \
GOMEM_WINSTA_REFERENCE="$PWD/.cache/gui-names-validation/windowstations-reference.json" \
GOMEM_WINSTA_AUDIT="$PWD/.cache/windowstations-validation/native-audit.json" \
go test -race ./internal/engine -run '^TestWindowStationsCorpusSealedOriginalAndReadAudit$' -count=1 -v
```

This optional audit currently uses the documented sample's fixed DTB 0x6d4000
and kernel base 0xfffff8043601f000; it skips without explicit inputs. The matrix
is 150 partial, 45 missing and zero accepted plugins. Desktop/thread generators,
other full-plugin layouts, modern/legacy real dumps, malformed type coverage,
swap/prototype pages, ARM64 virtual GUI scanning, safe successful cache reuse,
full exports/renderers and performance acceptance remain pending.

Subsequent integrations: [Desktops and DeskScan](windows-desktops.md) add partial
thread-owner recovery with full-generator and real-image controls.
