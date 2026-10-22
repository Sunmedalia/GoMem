# Windows command-history scanning (development preview)

`gomem analyze windows.cmdscan` is a native implementation of the fixed
Volatility 3 v2.28.2 `windows.cmdscan.CmdScan`, commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. Its matrix status is **partial**.
It does not establish complete conhost/version or release acceptance.

```sh
gomem analyze windows.cmdscan --image memory.dmp --case case-001 --format jsonl
gomem analyze windows.cmdscan --image memory.dmp --case case-001 --format jsonl \
  --param no-registry=true --param max-history=50,100
```

## Analysis and result model

The plugin traverses active processes and uses the original CmdScan.run's exact
case-sensitive `conhost.exe` filter. It resolves each process's VADs and selects
the first mapped filename ending in `conhost.exe`, ignoring case for that suffix.
The filename comes from VAD subsection/control-area/file objects, rather than a
string scan of arbitrary image bytes. Process address spaces use their own CR3.
Object address, PID and available creation time contribute to process identity.

The first eligible process selects the conhost layout for the run, as in the
baseline. OS version is measured from KUSER and KdVersionBlock. Ambiguous builds
use the native PE product-version reader, with physical `CONHOST.EXE` file-version
fallback. Failed direct revision probes remain diagnostics and fail task
completeness even when the fallback finds a revision. Native fallback is also
attempted after PE parse errors that can abort the original generator; broader
damaged-PE differential remains pending. Layouts are data-only and verified against a compiled SHA-256 pin;
`--offline` requires a verified cache entry. See [layout selection and
acquisition](windows-console-layout.md) and [command structure
semantics](windows-console-history.md).

By default, native hive enumeration reads each hive's root `Console` key and
adds exact `HistoryBufferSize` values to the history-size search set. Missing
Console keys are normal. Unreadable hives/values remain explicit failures.
Integer DWORD, big-endian DWORD and QWORD values that fit a two-byte signature
are supported. Invalid value types, lengths and values above 65535 are errors.
The baseline can silently skip errors or later fail while packing such values;
this implementation reports them while preserving independent results.
Registry-size observations anchor provenance at the kernel CMHIVE address and
retain HiveOffset, value cell index, cell address and decoded raw value; exact
backing reads remain separately captured. `no-registry=true` skips this step. Comma-separated `max-history` values are
validated, de-duplicated and sorted; zero is allowed, but can produce many
candidates in cleared memory. The default is 50.

VADs strictly smaller than `0x40000000` are scanned for each history size's
little endian unsigned short signature. Hardware page-map enumeration restricts
scanning to acquired mappings inside those VADs. Adjacent acquired intervals can
share a boundary match; holes never join and are never zero-filled. Mapped and
requested VAD byte totals are emitted. A difference fails task completeness,
even if some histories can be recovered. Missing process layers, malformed
VADs, arithmetic overflow, read errors and all configured limits also remain
explicit.

Candidates subtract the symbol-declared CommandCountMax offset and run the
original history validity checks. Valid histories emit the original six display
columns (`PID`, `Process`, `ConsoleInfo`, `Property`, `Address`, `Data`) plus Depth,
process identity and layout provenance. Root, property and command parent IDs
preserve the original tree. Data keeps the baseline's display text, including
`None`; `TypedData` retains the corresponding typed value or missing reason.
Text bytes remain available, and metadata/scanner/page-table reads retain exact
source coordinates, lengths, completeness and SHA-256. Reads up to 4096 bytes
also retain their original bytes. Larger scan requests retain a whole-read hash.

Command bucket scanning includes unused slots and preserves original indexes.
Invalid slots are skipped, including empty slots whose allocation fields need
not be read. Faults preserve earlier properties. A text fault skips only the
failed command and retains a diagnostic, as the original generator continues
with later entries; unreadable slot metadata stops that history's bucket walk.
A `history_not_found` row reports no valid history from the performed scan; it
is not proof of absence when coverage or read diagnostics report a gap.

Bounds include total requested bytes, reads, evidence rows, process/VAD nodes,
VAD count, signature candidates, command slots and page-map tables/entries.
Cancellation and emitter failures are terminal. Read captures count toward both
read and output bounds; budgets account for paging, physical and logical reads.
Failed tasks remain queryable. Auxiliary symbol dependencies currently force
fresh execution even for successful tasks; validated cache reuse remains work.

## Verification

- `tools/build_cmdscan_oracle.py` runs 132 complete original generators with real
  process/VAD/file objects, process layers, Intel PTEs and conhost types across
  all ten layouts reachable by the baseline version selector. Twelve measured
  build/revision combinations include the 20348.2520 and 25398 aliases. The
  bundled 25398 layout is intentionally not selected. On 88 revision-sensitive
  controls, actual PE reconstruction and pefile resource parsing read the
  product revision; a different file revision catches incorrect field use.
  120 controls match native display fields, depth and parent paths exactly: ordinary/unused slots,
  valid length 1024 with absent text, reversed sub-slot count, invalid handle,
  unreadable command/bucket/application, empty commands and case-sensitive
  process filtering. In the 12 missing-VAD-page controls the original raises
  `UnboundLocalError`; native emits explicit incomplete acquisition and a
  not-found observation instead of reproducing that exception.
- Plugin race tests independently reread every capture, compare raw bytes and
  digests, and test bounds, cancellation and emitter failures.
- Engine tests verify sealed parent relationships, persisted wire equality and
  fresh retries for successful and unreadable-command controls across all 12
  measured version selections (24 controls).
- `FuzzCmdScanPipeline` mutates history, bucket, process and VAD bytes through the
  bounded native pipeline; at least 1000 local executions pass. CI includes the
  oracle regeneration and fuzz control.
- Real Windows 10 19041 control with `no-registry=true`: all 15 displayed
  property/not-found rows and full parent paths match the unmodified reference.
  There are two partial history trees and one not-found observation; this is
  not a positive real command-string recovery control. Native remains failed
  with 167 error observations, including unacquired VAD bytes and unreadable
  candidates. The audit independently verifies 41,128 original reads and all
  41,233 sealed rows. Exported SQLite rows are identical to streamed JSONL.
- Default registry mode reads one HistoryBufferSize value of 50 and still matches
  all 15 display/tree rows. Native retains 196 failures. The final default-mode
  audit verifies 47,905 original reads and 48,012 sealed rows; SQLite export
  equals streamed JSONL. Both controls remain failed rather than certifying
  complete acquisition.

For an existing real control, the correspondence verifier supports process
spaces reconstructed independently from each recorded EPROCESS:

```sh
go run ./tools/verify_pool --plugin windows.cmdscan --image memory.dmp \
  --rows native.jsonl --dtb 0x6d4000 --arch x64 --symbols kernel.json \
  --kernel-base 0xfffff8043601f000
python3 tools/diff_results.py --native native.jsonl --reference reference.json \
  --mapping docs/diff/windows.cmdscan.json --output comparison.json
```

See [validation details](windows-cmdscan-validation.json). Full-generator
synthetic coverage of the reachable layouts does not establish acceptance on
other real systems. Registry-positive full
synthetic controls, independent real command recovery, other system versions,
PTE/swap damage, complete parameter behavior, case resume/cache, renderer/export
and performance acceptance remain pending. Hive enumeration reuses native
recovery helpers and can differ from the original list-only selection. Strict
native VAD validation can reject damaged indexes the baseline partially walks.

The initial registered-scanner snapshot passed `make check` (engine race suite
1348.310 seconds, 43 Python tests and 428 argument fixtures). Later provenance,
revision-probe and cache-lock changes passed focused race tests. The cache-lock
regression also passed five repetitions on the actual Windows CI runner in
run 39835965131; the full remote workflow remains in progress. Expanded layout
controls have separate local checks. The capability matrix remains partial.
