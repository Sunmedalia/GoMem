# Windows debug registers (development preview)

`gomem analyze windows.debugregisters --image MEMORY --case CASE` implements the native command corresponding to locked Volatility v2.28.2 `windows.debugregisters.DebugRegisters`. Use `--offline` to restrict module symbol acquisition to local sources.

## Selection and attribution

The command walks active processes and their thread lists, then reads the saved `Tcb.TrapFrame` registers. Any nonzero Dr7 selects a candidate unless `Tcb.State == 4`. It skips candidates whose Dr0–Dr3 are all zero, whose owner has no file VADs, or whose addresses map to no file VAD. It does not interpret Dr7 enable/type bits. Saved trap-frame values are observations, not proof of live CPU state or malicious behavior.

Owner lookup prefers XP `ThreadsProcess` when present, otherwise `Tcb.Process`. Displayed Process and PID come from the owner object; TID comes from `Cid.UniqueThread`. This preserves the baseline's distinction from the CID PID used by the suspended-thread command. Process/thread identities include object addresses, real IDs and available creation times.

File attribution uses the first inclusive preorder VAD range containing each nonzero address. File paths must contain a backslash; anonymous and relative-only mappings are excluded. All active process module instances use the shared [PDB-first exact symbol resolver](module-symbols.md). No nearest-symbol guess is made. There is no `WorkFoldersShell.dll` exclusion. The seventeen baseline columns retain typed missing values; Dr7 and Dr0–Dr3 use lossless hexadecimal address values.

## Evidence and failures

`thread` rows include the seventeen columns, thread/owner/trap-frame offsets, identities, resolution attempts and errors. `memory_read` rows preserve actual metadata, RSDS and export bytes, requested/captured lengths, layer, offset and read status. `summary` includes traversal, module/VAD, read/byte/error counts and `Complete`.

An unreadable individual thread retains its acquisition error and permits later threads to continue. Structural list/VAD corruption and exhausted traversal bounds stop the affected traversal. Symbol acquisition errors retain useful matches. Any genuine acquisition error makes the task failed/partial, even when the baseline silently skips the object. Cancellation and output errors stop further acquisitions. A typed trap-frame pointer and exact symbols are required. A mapped zero pointer is read normally; unavailable pages are never fabricated as zeros.

Bounds are inherited from thread attribution: 131,072 nodes per list/VAD, 1,000,000 total threads, 1,000,000 indexed VADs, 64 MiB captured bytes and 1,000,000 acquired PDB symbols, configurable with `max-nodes`, `max-threads`, `max-regions`, `max-read-bytes`, and `max-symbols`. Shared module collection permits at most 10,000 instances. Failed results are not replayed; dynamic symbol tasks always execute fresh until dependency-aware cache validation is implemented.

## Validation

The generator `tools/build_debugregisters_oracle.py` verifies the pinned upstream tree and invokes actual unmodified `_get_debug_info` and `_generator` methods. Real paged objects, process/thread extensions, VAD traversal, local SQLite GUID cache, PDB symbols and PE exports supply 66 cases. The fixtures reuse the suspended-thread image builder, adding typed trap frames. No upstream method is patched.

Native tests repeat x86 fixtures through PAE, giving 99 x86/PAE/x64 combinations. They compare all seventeen columns, order and missing values, independently reread every raw capture, verify sealed case-store JSONL and require fresh execution. Controls cover zero/high Dr7, terminated/running threads, four address registers, zero/unmapped/boundary/nearby addresses, owner/CID disagreements, XP owner precedence, Unicode paths, exact symbols, exports and unusual RSDS boundaries. Missing PE headers retain useful PDB matches while failing unresolved export acquisition explicitly. Fault tests cover list/VAD cycles, thread/region/byte/symbol limits, unreadable owner/register fields, cancellation, output errors, offline/provider failures, failed retries and a readable second thread following an unreadable one. `FuzzDebugRegisterPipeline` exercises the native bounded pipeline.

The supplied Windows 10 19041 image (SHA256 `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`) produces zero rows in the pinned baseline. Native traversal visits 1,752 threads and also produces zero thread rows. All 20,932 metadata reads, totaling 162,441 captured bytes, were independently reread, including 615 actual read faults. The native task is failed/partial with `Complete=false`; this result does not establish clean absence of hardware breakpoints. Error counts include raw faults and contextual errors, so they need not equal the number of failed reads. The control has no real positive symbol attribution.

```sh
.cache/reference-venv/bin/python tools/build_debugregisters_oracle.py --check
go test -race ./internal/engine -run '^TestDebugRegisters' -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialWindowsDebugRegisters$' -count=1 -v
go test ./internal/plugins -run '^$' -fuzz FuzzDebugRegisterPipeline -fuzztime 10s
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
```

The [differential profile](diff/windows.debugregisters.json) selects thread records, compares all seventeen columns and declares raw/summary rows separately. See the [validation record](windows-debugregisters-validation.json). Real positive samples, broad Windows versions, real Unicode module acquisition, runtime symbol dependency caching and full acceptance remain pending.
