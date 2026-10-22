# Bounded native module RSDS discovery

Modules with ordered `PDBNames` now discover PDB identities by scanning their
collected address range, rather than requiring a PE debug-directory entry.
This closes observed differences against the locked Volatility 3 v2.28.2
`PESymbols` / `PDBUtility` pipeline. Generic modules without candidate names and
kernel identity verification continue to use the existing PE parser.

The scanner reads at most 4 KiB at a time and retains at most 280 bytes between
reads. Records match `RSDS`, the 16-byte mixed-endian GUID, a four-byte age,
the exact candidate bytes and a terminating NUL. Every byte, including that
NUL, must lie inside the declared module extent. A record can cross a read or
page boundary. No MZ header is required. The exact collected module base still
anchors symbol RVAs; scanning does not change the module's address space.

Only the first matching identity for each candidate is retained. Candidates
are acquired in caller order, even if a later candidate occurs earlier in
memory. An unavailable first candidate permits the next candidate. A second
GUID for the same name is never substituted for the first. Exact database,
GUID and age matching still applies to loaded tables, indexed symbols and the
native cache/converter. Without a PE header this mode has no independent PE
machine field to compare; exact PDB identity remains mandatory.

All scan reads pass through the existing resolver observer and cumulative
acquisition budget. Owned raw bytes, addresses, layers, requested lengths and
read errors are persisted by the caller. Reads stop on cancellation, evidence
output failure or an exhausted budget. The scanner does not materialize a
module or image in memory. It scans the complete extent once, then attempts
acquisition. Missing pages are skipped with their explicit errors, and the
overlap carry is cleared. Readable identities remain available alongside the
errors, so callers can retain useful symbols while marking the task partial.
Cancellation, observer and budget failures stop the scan. This is stricter than
upstream layers that skip inaccessible regions.
Corrupt symbol indexes and other genuine acquisition failures remain errors;
they are not silently recast as an offline miss or empty finding set.

Candidate encoding retains the pinned scanner's Latin-1 boundary and matched
names must decode as UTF-8. Unencodable candidates or undecodable matches
produce explicit errors. This does not establish arbitrary Unicode PDB
acquisition, real positive detection, or full parity for every malformed or
partially resident image. Runtime dependency-aware symbol cache replay is
still pending; dynamic-symbol tasks execute fresh.

## Validation

The unmodified upstream suspended-thread generator runs on byte-backed paged
objects, including 16 new cases (eight scenarios at each pointer width):

| Scenario | Expected symbol behavior |
| --- | --- |
| PE debug directory absent | Resident RSDS resolves the PDB symbol |
| Directory points to another name | Requested resident RSDS resolves |
| MZ signature absent | Resident RSDS resolves |
| RSDS crosses a page boundary | Complete record resolves |
| NUL is the final module byte | Complete record resolves |
| NUL is one byte past the module | Record excluded; export fallback |
| First GUID unavailable, second same-name GUID available | Second GUID ignored; export fallback |
| Lowercase candidate unavailable, uppercase variant available | Next candidate resolves |

There are now 52 actual generator cases and 78 native x86/PAE/x64 combinations.
All nine baseline columns, order and missing values match; captures are
independently reread through paging and the stored JSONL reseals identically.
Separate tests cover candidate priority, module overflow, malformed names,
Latin-1/UTF-8 failures, missing reads, cancellation, observer failure and byte
budgets. `FuzzModuleRSDS` compares bounded discovery with an independent
whole-buffer regex oracle; a Latin-1 rune representation gives Go's regex the
same byte-count semantics as Python's bytes regex. The retained regression
seed covers non-ASCII GUID bytes. A 10-second run completed 209,299 executions.

```sh
.cache/reference-venv/bin/python tools/build_suspended_threads_oracle.py --check
go test -race ./internal/engine -run '^Test(Module(PDB|RSDS)|SuspendedThreads)'
go test ./internal/engine -run '^$' -fuzz FuzzModuleRSDS -fuzztime 10s
```

The compiled CLI also reran the six original discovery reproductions; all six now match the upstream symbols and exit successfully. The supplied Windows image was rerun with 1,752 threads, zero findings and 6,098 independently reread acquisitions (37,360 bytes), with no errors. It is still only a negative suspended-thread control;
see [its validation record](windows-suspended-threads.md). These synthetic
positive identity controls do not close real-world positive or Windows version
acceptance. No plugin changes from partial to accepted. Sparse-scan continuation and the standalone command are additionally validated in [windows-pe-symbols.md](windows-pe-symbols.md).
