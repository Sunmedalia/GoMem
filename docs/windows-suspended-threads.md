# Windows suspended threads (development preview)

`gomem analyze windows.suspended_threads --image MEMORY --case CASE` enumerates nonterminated suspended threads and attributes both start addresses to mapped files and exact symbols. It implements the native command corresponding to locked Volatility v2.28.2 `windows.suspended_threads.SuspendedThreads`. Missing symbols are acquired using the existing Windows GUID/age cache and server policy; use `--offline` to restrict acquisition to local symbols.

## Selection and attribution

The plugin walks active processes and their thread lists. A nonzero `Tcb.SuspendCount` selects a candidate; `Tcb.State == 4` excludes it. `ExitTime` is deliberately not a filter. The owning process comes from `ThreadsProcess` on the XP layout or `Tcb.Process` on later layouts. Its name and VADs come from that object, while displayed PID comes from `Cid.UniqueProcess`, matching the baseline even when the two disagree. Process identity uses the owner object's address, real PID and available creation time; thread identity includes the thread object, TID and available raw creation time.

Only file-backed VAD names containing a backslash enter the attribution index. Empty or relative-only names and anonymous mappings do not. File ranges keep traversal preorder and use `start <= address <= end`, since VAD end is the last byte. The first overlapping range wins. A zero address has no file. Processes without file VADs produce no findings.

On the first needed lookup, the plugin gathers file mappings across all active processes in active-list and VAD-preorder order and creates their native process address spaces. It groups mapped instances by the lowercase Windows basename, accepting either path separator when splitting the basename. The shared [module resolver](module-symbols.md) tries all instances' PDB symbols before any instance's export symbols. PDB candidate names follow the pinned helper: replace the last three basename characters with `pdb`, also try its first-letter uppercase variant; `ntoskrnl.exe` uses the four locked kernel candidates. The engine checks resident database name before loading or downloading a table and still requires exact GUID/age and architecture. Export fallback retains genuine acquisition failures as errors. Address lookup is exact; no nearest-symbol guess is made. The pinned global-instance precedence can attribute a symbol from another instance sharing the same basename and address.

Both start addresses are resolved before applying the case-sensitive `\WorkFoldersShell.dll` suffix exclusion. A lowercase variant is not excluded. The nine baseline result columns retain typed missing values instead of invented empty strings. Native rows additionally contain object offsets, identity, state/suspend values and resolution attempts with module layer/base/size, method, table digest, available source digest, unavailability and errors.

## Evidence, bounds and task state

`RecordType=thread` identifies findings. `memory_read` rows retain owned raw bytes, requested and captured lengths, scope (`metadata`, `pdb`, `exports`), layer, address and actual read error. Metadata includes process/thread/VAD/file fields. Symbol reads come from the shared resolver, not reconstructed padding. An acquisition denied before any source read is an explicit failure without a fabricated successful capture. `summary` records traversal, selection, exclusion, module/VAD, read-byte and error counts and `Complete`.

List cycles, invalid links, VAD corruption, incomplete filenames, missing pages, conversion errors and exhausted budgets fail the task while preserving earlier rows. This is intentionally stricter than upstream's silent invalid-object skipping. Cancellation and emitter failure stop further acquisitions. Failure summaries retain at most 64 individual causes plus one truncation notice; raw read rows and counts preserve the rest. Missing optional identity time remains typed unavailable; actual attempted read failures still fail the analysis.

Native bounds default to 131,072 nodes per process/list/VAD, 1,000,000 threads, 1,000,000 total indexed VADs, 64 MiB cumulative captured metadata and symbol bytes, and 1,000,000 cumulative acquired PDB symbols. Module collection allows at most 10,000 instances. `--param max-nodes=...`, `max-threads`, `max-regions`, `max-read-bytes` and `max-symbols` adjust these within declared bounds. Export parsing additionally retains its own entry/string/acquisition bounds. Data streams into the case store; the image remains read-only.

`Spec.ExternalSymbols` requires fresh execution because an unavailable PDB may later become available, or an indexed table may change. Existing completed evidence remains queryable and exportable; it is not replayed as the result of a new analysis. Task provenance retains offline policy, a hash of the server configuration and this cache policy. Server configuration is hashed so credentials in a URL are not copied into provenance. Dependency-aware cache revalidation is pending; this is not a completed implementation of the plan's resume/caching requirement for dynamically acquired symbols.

## Validation

`tools/build_suspended_threads_oracle.py` verifies the locked Python tree and invokes the actual unmodified suspended-thread generator. Its paged x86/x64 fixtures use actual process/thread list extensions, owner lookup, VAD traversal, process address-space creation, SQLite GUID caches, ISF loading, PDB lookup, PE reconstruction and export lookup. No upstream methods are patched. Filename-helper tests separately cover Windows path and full Unicode 16 casing; see [windows-paths.md](windows-paths.md). Thirty-six cases cover normal suspension, running/terminated controls, owner/CID differences, XP owner precedence, suspended threads with nonzero ExitTime, missing/relative-only VADs, unmapped and boundary addresses, exact versus nearby symbols, export fallback and both DLL-exclusion cases.

Native tests run those 36 cases and repeat the 18 x86 cases through PAE, totaling 54 paging combinations. They compare all nine result columns, order and typed missing values. All captures are independently compared to original fixture bytes and reread through the native page translator. Persisted rows reseal identically and reproduce the complete JSONL stream. Repeating a task proves dynamic-symbol results are not replayed. Additional tests cover cycles, total thread/VAD bounds, holes in owner and suspension fields, byte and symbol limits, provider errors retained alongside successful export fallback, offline fallback, cancellation and emitter failure. Resolver tests cover candidate validation/ownership and engine tests verify candidate rejection before acquisition. Pipeline fuzzing exercises selection values, arbitrary start addresses, bounds and output failure.

The supplied Windows 10 19041 image (SHA256 `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`) is a negative control. The saved pinned output has zero rows (SHA256 `a3cbe01dad52836a7ac8efc91954cf64867f4dee8a6f046c4bb0838d11f48589`). Native traversal visits 1,752 threads with zero nonzero suspension counts, reports no threads, and completes with no errors. All 6,098 metadata reads totaling 37,360 bytes were independently reread from the original image. The compiled CLI also completed this analysis and its differential profile matched the empty pinned finding set, while retaining 6,098 acquisition rows and one summary. This does not establish positive real-world detection or PDB attribution on that image.

```sh
.cache/reference-venv/bin/python tools/build_suspended_threads_oracle.py --check
go test -race ./internal/engine -run '^TestSuspendedThreads|^TestModulePDB'
go test -race ./internal/plugins -run '^TestSuspendedPath'
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialWindowsSuspendedThreads$' -count=1 -v
go test ./internal/plugins -run '^$' -fuzz FuzzSuspendedThreadPipeline -fuzztime 10s
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
```

CI checks the pinned oracle and fuzz target. Optional corpus checks require the documented reference alongside the Windows image and symbols. The differential profile [diff/windows.suspended_threads.json](diff/windows.suspended_threads.json) selects only `thread` rows and compares the nine baseline columns; raw acquisition and summary rows are explicitly excluded from finding counts.

Real positive samples, broad Windows versions, real Unicode-module acquisition and cross-Unicode-version semantics, modules with multiple or unusual/non-directory RSDS identities, comprehensive PDB discovery differences and runtime symbol dependency cache validation remain pending. The plugin is partial and no plugin is newly accepted.
