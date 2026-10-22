# Native Windows PE-symbol command (development preview)

`windows.pe_symbols` exposes the native exact-symbol resolver as a standalone
command, corresponding to locked Volatility 3 v2.28.2
`windows.pe_symbols.PESymbols`. Its runtime uses Go, native paging, ISF/PDB
conversion and the configured symbol cache/server policy. Python is only a
development reference.

```sh
gomem analyze windows.pe_symbols --image memory.dmp --case case-001 \
  --param source=kernel --param module=ntoskrnl.exe \
  --param 'symbols=["PsActiveProcessHead","PsLoadedModuleList"]'

gomem analyze windows.pe_symbols --image memory.dmp --case case-001 \
  --param source=processes --param module=ntdll.dll \
  --param 'addresses=["0x7ffb12345678","0x7ffb12345678"]' --offline
```

## Requests and module collection

`source` must be `kernel` or `processes`; `module` is required. `symbols` is a
JSON array of exact names. `addresses` is a JSON array of hexadecimal/decimal
strings or unsigned integer literals; parsing never passes through floating
point. Duplicate requests and order are preserved. A name can contain a comma.
A nonempty names array takes precedence over addresses, as in the upstream
command; the ignored addresses array is not parsed. With neither query, the
command emits a `no_query` summary after normal engine prerequisites, without
collecting modules. Empty symbol names are rejected as a native input bound.
Each encoded request array is limited to 16 MiB and one million values, and
each symbol name to 65,536 bytes.

Process collection walks active-list order, creates each process space and
walks file-backed VADs in preorder. File paths must contain a backslash. Names
are grouped by [Windows basename and Unicode 16 lowercase](windows-paths.md).
Kernel collection walks the loaded-module list using
`_KLDR_DATA_TABLE_ENTRY`, falling back to `_LDR_DATA_TABLE_ENTRY` when that type
is absent. The first process space for each session is retained, with the
`Session + 8` fallback for newer symbol tables lacking the old session type.
Null session pointers are not applicable. The first session space able to
read the module base supplies its memory. The kernel layer is not substituted
for the selected session space.

Collection filters names by lowercase suffix, but resolution uses an exact
group name. Thus asking for `TURE.DLL` can collect `fixture.dll` without
resolving it under the requested `ture.dll` group; the command preserves this
upstream behavior. Requesting `ntoskrnl.exe` aliases the first kernel-list
module to that name. Other collected names retain their own group names.

All module instances try PDB symbols before any instance's exports. Candidate
names, first GUID per candidate, exact identity checks and missing-symbol
behavior follow the [shared module resolver](module-symbols.md) and
[RSDS discovery](windows-rsds.md). Lookups are exact, with no nearest-address
guess. Native x64 addresses retain canonical high bits; differential comparison
uses the baseline's low 48-bit pointer representation. This normalization does
not change acquisition addresses or raw bytes.

## Evidence, partial results and limits

`RecordType=symbol` carries the three baseline columns `Module`, `Symbol` and
`Address`, plus module coordinates, address space, resolution method and
available symbol/source digests. `memory_read` carries owned raw bytes,
requested/captured lengths and actual errors. A `summary` records source,
modules, VADs, reads, bytes, errors, reported symbols, missing requests and all
resolver attempts. Missing addresses also use lossless address values.

An unreadable VAD filename excludes that mapping and retains the error while
other readable VADs continue. A stopped traversal retains previously collected
modules for partial resolution. Sparse RSDS discovery skips unreadable pages while clearing its overlap carry;
it cannot synthesize a record across a hole. Every failed read remains evidence.
A verified PDB table can supply exact symbols even when other scanned pages
were absent. The resolver returns those matches together with the acquisition
error. The task remains failed/partial, never a clean empty or complete result.
Corrupt export headers similarly remain errors even if other symbols resolved.
This is intentionally stricter than upstream skipping inaccessible or invalid
objects. Symbol-index corruption, server errors, missing process roots, list
cycles, limits and output failures do not become normal unavailability.

Defaults are 131,072 nodes per list/VAD, one million total VADs, 10,000 matching
module instances, 64 MiB cumulative captured metadata/symbol bytes, and one
million indexed PDB symbols. Corresponding `max-nodes`, `max-regions`,
`max-modules`, `max-read-bytes` and `max-symbols` parameters bound acquisitions.
The shared resolver retains its PE entry/string limits and uses the declared
analysis byte budget across instances; the analysis additionally enforces it
globally across metadata and every resolver. Read
failures retain at most 64 joined scan causes plus a count of further failures;
all raw read diagnostics remain in the case. Cancellation or emitter failure
stops subsequent reads. Dynamic-symbol tasks always execute fresh until runtime
dependency-aware replay is implemented. All input images remain read-only.

## Validation and remaining work

`tools/build_pe_symbols_oracle.py` runs the actual unmodified command generator
with byte-backed Windows objects, real page tables and a real SQLite upstream
ISF identity cache. No command, symbol lookup or module collection method is
mocked. Thirty-six fixtures produce 240 command queries. Native tests repeat
the x86 cases through PAE for 360 paging/query combinations, comparing all
three columns, order and duplicates, independently rereading captures and
checking byte-identical sealed case JSONL. Coverage includes both sources,
legacy module types, session-ID fallback, multiple sessions/modules, no VADs,
relative/Unicode names, filters, mixed query precedence, absent queries, eight
RSDS discovery conditions, exact misses and export fallback.

The no-MZ cases explicitly expect the same found symbols plus a native
`invalid DOS signature` failure when an unresolved request reaches exports;
upstream silently skips that invalid PE. Additional tests exercise limits,
cycles, holes, provider errors with useful export fallback, offline misses,
fresh tasks, cancellation and emitter failure. Separate sparse scanner tests
verify readable identities after holes, error retention on resolver reuse and
no joining across missing pages. The request parser's ten-second fuzz run
completed 457,917 executions.

The supplied Windows 10 19041 image has an exact kernel-symbol differential:
`PsActiveProcessHead` matches after address normalization. Its 6,009 acquisition
records (8,732,737 captured bytes) were independently reread, including 2,038
missing-page failures; the native task is explicitly partial. Stored evidence
verifies and another run executes fresh. This is one build and one exact
kernel query, not broad acceptance. The compiled CLI process-source query for `ntdll.dll!NtClose` also matches
the upstream symbol/address. It collected 118 module instances from 19,999
VADs and retained 341,491 acquisition records, including 35,917 failed reads,
with 97,500,541 captured bytes and a failed/partial task. That run explicitly
used `max-read-bytes=536870912`; default limits can stop earlier. The complete capture stream was independently reread through 120 process
roots collected afresh from the original image; all 341,493 row seals and
image/kernel-symbol provenance values were verified. The standalone
`tools/verify_pe_symbols` helper performs this streaming check without loading
the saved case into memory. Compiled CLI results
are recorded in [the validation record](windows-pe-symbols-validation.json).

Real version coverage, arbitrary Unicode PDB acquisition, live server policies,
and dynamic dependency-aware cache replay remain pending. The implementation
is partial, with no newly accepted plugin.

Reproduce the independent read validation with:

```sh
go run ./tools/verify_pe_symbols --image memory.dmp --symbols kernel.json \
  --jsonl pe-symbol-results.jsonl
```
