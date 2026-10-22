# PDB-first module symbols (development preview)

`pkg/pesymbols` resolves exact names or addresses across an explicitly ordered list of mapped PE instances. It tries every instance's matching PDB before trying any instance's export table. The engine supplies `Environment.ModulePDB` on Windows, using the configured offline, cache, index and symbol-server policy. This is a shared component; it does not implement `windows.pe_symbols`, `windows.suspended_threads` or automatic cross-process module collection.

## Resolution and evidence

PDB acquisition reads the resident PE's RSDS GUID, age and database name. An exactly matching loaded kernel ISF can be reused; otherwise the provider checks the configured local index, then the native PDB cache/converter and optional server. Identity conflicts, architecture mismatches, corrupt indexes, read failures and conversion/network errors remain errors. Only a genuinely absent supported identity or offline cache miss is expected unavailability, which permits clean export fallback. A real acquisition failure remains in the returned joined error even when exports subsequently resolve the query. Tables and original PDB sources carry their available SHA256 digests.

Matching is exact, without nearest-symbol guessing. PDB aliases at one address select the lexicographically first name, following the pinned finder. Duplicate requests remain duplicate matches. The pinned helper stops when either active request group (names or addresses) empties, even when the other group still has values. `StoppedOnGroup` and `Missing` expose this behavior; callers requiring independent searches should make separate requests. Export matches preserve forwarder-string addresses; forwarders are not recursively resolved. Non-ASCII export names fail explicitly instead of silently changing an encoding.

Every actual mapped-memory acquisition reports module index, method, address, requested length, owned raw bytes and error to `Options.Observe`. A read is bounded by the collected module extent before reaching the source. Cancellation or observer failure stops further acquisitions, including when a provider tries to continue reading after an observer failure. An exhausted budget does not fabricate a successful read or an empty table. Failed acquisitions are retained on subsequent requests to the same resolver. Resolver instances belong to one analysis and must not be shared concurrently; independent engine providers can run concurrently without mutating engine configuration.

Required limits include cumulative captured bytes across all instances and both methods, cumulative indexed PDB symbols, export entries and string length. Modules are limited to 10,000 instances, requests to 1,000,000 values, mapped images to 256 MiB, cumulative bytes to 1 GiB and PDB symbols to 10,000,000. Default export limits are available through `pe.DefaultExportLimits`; callers must explicitly choose `MaxSymbols`. CLI consumers must represent addresses through the evidence model's lossless hexadecimal values.

## Validation

`tools/build_module_symbols_oracle.py` verifies the locked Volatility v2.28.2 source digest and creates 18 controls using actual upstream PDB GUID scanning, SQLite identifier caches, ISF loading, PE reconstruction and `PESymbols._resolve_symbols_through_methods`. It does not replace upstream resolution methods. Two module orders and nine requests cover PDB-before-export precedence, aliases, duplicate requests, exact addresses, missing values and the mixed-request early stop. Native tests compare ordered matches and all remaining requests, and independently compare captured bytes against memory fixtures.

Engine tests use compiled x86 and x64 PE/PDB pairs: seed only the original PDB in the exact GUID/age cache, convert natively offline, resolve `entry`, and independently reread captured memory. Concurrent provider calls verify cache reuse without configuration mutation. Additional tests cover unavailable cache entries, exact kernel-table reuse, indexed tables and malformed indexes, truncated images, invalid extents, identity mismatch, count/byte budgets, cancellation, observer failure and retained failures. Shared mapped-PE identity parsing distinguishes absent directories from truncated or malformed records.

An optional real Windows 10 19041 control (image SHA256 `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`) opens the engine normally and resolves `PsActiveProcessHead`, `PsLoadedModuleList` and `NtBuildLab` using the loaded exact kernel ISF. All three addresses match that table; five resident-identity reads totaling 449 bytes are independently reread. This proves the engine hook and exact identity reuse on that image, not full symbol or module-enumeration acceptance. Existing real-kernel export validation remains documented in [pe-exports.md](pe-exports.md).

```sh
.cache/reference-venv/bin/python tools/build_module_symbols_oracle.py --check
go test -race ./pkg/pesymbols
go test -race ./internal/engine -run '^TestModulePDB|^TestNativePDBToVerifiedProcessEvidence'
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialWindowsKernelModuleSymbols$' -count=1 -v
go test ./pkg/pesymbols -run '^$' -fuzz FuzzModuleSymbolRequests -fuzztime 10s
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
```

CI checks the deterministic oracle with pinned pefile and exercises the fuzz target. Optional corpus tests remain optional and do not establish release acceptance. Before a plugin uses dynamically acquired module tables, its case task/cache identity must incorporate resolution policy and symbol dependencies, with provenance for all used digests. No existing plugin consumes this hook in this milestone. Automatic VAD/module collection, process-instance attribution, positive suspended-thread validation, broader Windows versions and complete upstream parameter/extension coverage remain pending. No plugin is newly accepted.
