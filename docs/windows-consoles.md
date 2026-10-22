# Windows console recovery (development preview)

`gomem analyze windows.consoles` is a native implementation of the fixed
Volatility 3 v2.28.2 `windows.consoles.Consoles` generator, commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. Its matrix status is **partial**;
finite synthetic comparisons and incomplete real acquisition are not release
acceptance.

```sh
gomem analyze windows.consoles --image memory.dmp --case case-001 --format jsonl
gomem analyze windows.consoles --image memory.dmp --case case-001 --format jsonl \
  --param no-registry=true --param max-history=50,100 --param max-buffers=4,8
```

## Discovery and acquisition

The native scanner walks active processes using a case-insensitive conhost.exe
filter, resolves each process's own CR3, and selects its first VAD filename ending
in conhost.exe. Consoles scans that one executable mapping; CmdScan instead scans
all VADs smaller than 1 GiB. The two scopes share bounded page-map acquisition,
version measurement, pinned layout retrieval and read capture. Only acquired
pages are searched; holes never join or become zero-filled data.

The first eligible process selects the layout for the run. KUSER/debug metadata
and, when required, the PE product revision determine a compiled SHA-pinned
layout. Offline mode requires a verified layout cache. Baseline conhost layouts
are x64 only; the native Intel translation infrastructure does not establish
x86 conhost or ARM64 console support.

By default, native hive recovery reads root Console keys for HistoryBufferSize
and NumberOfHistoryBuffers. Valid integer values extend the signature and
validity sets. DWORD, big-endian DWORD and QWORD values must fit 0..65535; invalid
values or unreadable hives remain explicit errors. Registry rows retain raw
value bytes, hive address and cell coordinates. Full original-generator registry
positive differential remains pending; the real control below recovers both
settings while retaining independent hive failures.

Candidate addresses subtract the declared CommandHistorySize offset from each
unsigned little-endian short match. Every configured max-buffers validity test
runs, as in the original list comprehension. A title-read failure rescued by an
original title may recover properties, but still fails native completeness.
A not-found observation only describes the performed search, not a clean image.

## Results and errors

Properties include console dimensions, history sizes/counts, titles, attached
process IDs/handles, executable aliases and source/target pairs, active command
histories, and current/alternate screen chains. Unlike CmdScan's unused-slot
search, console histories stop at the declared active CommandBucket.End.
Screen rows retain the original circular ordering, character filtering and
trailing whitespace/row trimming. Node, candidate, command, screen, row, cell,
text-byte, page-map, total-read and output limits are explicit.

The six baseline display columns plus Depth match the original tree stream.
Parent IDs follow emitted depth, including metadata siblings at the same depth;
property-name punctuation does not imply another parent. ScreenBuffer addresses
are numeric pointer targets. Chain deduplication still follows pointer field
addresses, as in the original extension. Falsy Data values display as typed
`not_available`, while TypedData retains zero, empty strings or a missing reason.
Absent addresses use `not_applicable`. Addresses remain lossless hexadecimal.

Source reads retain layer/offset, length, completeness, hash and raw bytes up to
4096 bytes. Larger captures retain their digest. The process identity combines
object address, PID and available creation time. Rows carry image, parameters,
layout selection/digest and sealed provenance. Errors retain recovered property
prefixes and independent subtrees. Cancellation and emitter failure stop the run.
Failed tasks remain queryable and cannot replay as complete results. External
layout dependencies currently force fresh execution even on successful runs;
validated dependency-aware result reuse remains pending.

The original legacy pointer ExeName calls a missing String.get_string method.
Native recovery emits the same property prefix and an explicit unsupported
legacy decode error, then continues independent histories/screens. Some valid
older-layout controls therefore intentionally produce failed native tasks even
though all emitted display rows match. Cycles and swallowed read faults also
remain explicit failures rather than silent truncation.

## Verification and limits

- 156 actual complete original generators cover ten selectable layouts across
  twelve measured build/revision combinations, including the 20348.2520 and
  25398 aliases. Fields, absent values, depth and full parent paths match.
  Controls include attached processes, modern aliases, two positive commands,
  circular screen text, unused slots, uppercase process names, zero values,
  empty history/command lists, title/command/screen faults and history cycles.
  Original methods, process/VAD objects and Intel paging execute unchanged.
- Plugin race tests independently reread every captured source interval and
  verify raw bytes and digests. Bounds, cancellation, emitter and registry
  failure controls preserve independent results. The pipeline fuzz target also
  mutates console/list/history/alias/screen data and page mappings.
- 24 engine controls check sealed parents, byte-identical streamed/persisted
  rows and fresh successful/failed retries across all twelve version selections.
- The local Windows 10 build 19041 image yields the same three not-found rows
  in both registry modes. Requested bytes per executable VAD are 897024, but
  only 245760, 4096 and 266240 bytes are acquired for PIDs 4424, 3896 and 2044.
  Both native runs remain failed. Default registry mode recovers history size
  50 and buffer count 4, with additional unreadable-hive errors. Independent
  original-image auditing verifies all 6827/20358 captured reads and row seals.
  This is a negative partial-acquisition control, not positive real recovery.

Broader real positive/normal controls, registry-positive full generators,
version coverage, damaged indexes, swap/prototype pages, all parameter and
renderer/export semantics, validated resume/cache behavior and performance
acceptance remain outstanding. See the [validation record](windows-consoles-validation.json)
and [tree comparison profile](diff/windows.consoles.json).
