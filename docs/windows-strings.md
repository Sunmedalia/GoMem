# Windows Strings (development preview)

`windows.strings` associates offsets from an external strings file with Windows address spaces using native Go. It implements the locked Volatility v2.28.2 `windows.strings.Strings` behavior and retains additional acquisition evidence. It does not extract strings or verify that the supplied text occurs in the memory image.

```sh
bin/gomem analyze windows.strings --image memory.dmp --case case-001 \
  --param strings_file=strings.txt --param pid=2968 --format jsonl
```

Use the usual exact symbol/DTB options when discovery cannot establish them. `pid` filters active processes; the kernel mapping is always included. `strings_file` accepts a local path or file URI. Remote input protocols are not implemented.

## Input and reproducibility

The engine copies declared file inputs to bounded temporary snapshots before cache lookup, computing SHA256 over the bytes actually used. The snapshot is reopened read-only, held for the run and removed on exit. Input digest and size enter task provenance and the cache key. Unchanged content replays sealed results; same-size content changes invalidate the cache even when mtime is unchanged. A removed input cannot replay an old successful task. Ordinary size/mtime mutation during copying is rejected; the digest identifies the acquired bytes, not a guarantee that an external producer never changed the file during acquisition.

Strings input is limited to 64 MiB. The parser preserves the pinned ASCII byte-word classes, greedy decimal backtracking, Latin1 decoding and retained newlines. For example, `123\n` parses as offset 12 and text `3\n`. Original lines, line numbers, byte offsets, digest and query pages remain evidence. Invalid lines and offsets beyond uint64 retain explicit diagnostics and fail coverage. This deliberately differs from silently skipped lines or Python's arbitrary-size offsets.

## Baseline coordinates and physical claims

`Result` preserves two upstream coordinate quirks. Kernel associations report the virtual base of the merged run, without per-page displacement. Process associations index only the first virtual page of a merged run and report its physical base. Consequently `FREE MEMORY` in this field does not establish that no process maps the queried physical bytes. Set members are sorted for deterministic output; the differential normalizes upstream set order only.

`PhysicalAssociations` separately supplies physical-match candidates with the run displacement and canonical virtual address. Each claim requires a successful native hardware translation to the queried physical coordinate. Association records preserve the process object, PID, creation-based identity, page root, original run and translation leaf. Kernel PID/object/identity fields are typed missing. Translation disagreements retain the baseline coordinate but fail coverage and suppress the physical claim.

These candidates inherit the pinned mapping enumerator's omissions, including uniform tables and whole-large-page availability rules. They are not an exhaustive native hardware reverse map. Extended PFN disagreements are covered by synthetic tests. `StringVerified=false` is always explicit. `MappingComplete` reports acquisition/parser errors for this task; it does not certify exhaustive native mapping or string content.

## Bounded acquisition

Page-table enumeration streams merged runs and indexes only queried pages. The task retains at most 64 MiB of raw input plus bounded indices and associations. Parameters bound input lines/line length, process nodes, page tables, inspected entries, mapping runs, associations and captured bytes. Defaults are 1,000,000 lines, 1 MiB per line, 131,072 nodes, 262,144 tables, 268,435,456 entries, 1,000,000 runs/associations and 512 MiB captured bytes.

Every original metadata/page-table read is retained as `memory_read`. Read failures, invalid process roots, unavailable physical mappings and budgets fail the task while preserving partial evidence. Up to 64 unavailable-mapping details are emitted; summary counts include all omissions. Cancellation and emitter failures stop further acquisition/output. Failed tasks are not reused as completed cache entries. An aborted streaming walk may leave its final coalesced run unreported.

## Validation

The fixed unmodified upstream parser and actual byte-backed generator produced 24 cases and 1,038 parser examples. Native x86, PAE and x64 testing expands these to 36 paging combinations, covering PID filters, missing tables, transition entries, uniform roots, aliases, merged runs, high PFNs, malformed input, Latin1 and empty input. Tests independently reread captures and physical claims, verify sealed SQLite round trips and cache replay, and exercise limits, cancellation, output errors and failed-task retry. Input snapshot tests cover mutation, deletion, cleanup and invalid URI/declaration cases.

The Windows 10 19041 control uses 154 external query lines and PID 2968, including 120 process-name locations and selected virtual/physical/displacement controls. All 154 `String`, `PhysicalAddress` and normalized `Result` records match the pinned baseline. The task has 14,791 evidence records, 14,143 successful reads (56,437,615 captured bytes), 274 associations and 143,331 enumerated runs. There are 1,320 unavailable kernel mappings, so the task remains failed/partial; 64 details and the full count are retained. Successful read captures do not eliminate these mapping omissions.

The independent verifier rereads all original captures, checks input bytes/digest, process identities, roots and claimed physical translations, and verifies seals/provenance. This validates claimed candidates and selected baseline fields, not completeness of every mapping. The control input contains labels as well as process names; no universal text-in-memory match is claimed. The streaming refactor is also checked against the existing real Windows Memmap control.

```sh
python3 tools/build_windows_strings_oracle.py --check
python3 tools/diff_results.py --native NATIVE.jsonl --reference REFERENCE.json \
  --mapping docs/diff/windows.strings.json --output diff.json
go run ./tools/verify_pe_symbols --plugin windows.strings --image MEMORY \
  --symbols SYMBOLS --input STRINGS --jsonl NATIVE.jsonl
```

The diff profile explicitly projects `string` children of retained `query_page` evidence into the baseline's flat rows. Missing or undeclared parents are rejected; evidence hierarchy is tested separately. The pipeline fuzz target passed 60,122 executions in ten seconds. Real x86/PAE, broader Windows versions, remote inputs, complete parameter/renderer acceptance and exhaustive investigation acceptance remain pending. See [machine-readable validation](windows-strings-validation.json).
