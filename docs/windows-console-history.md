# Windows conhost command/history reader (development dependency)

`pkg/winconsole` provides native, bounded readers for `_COMMAND` and
`_COMMAND_HISTORY`. This is a dependency for future `windows.cmdscan` and
`windows.consoles`; neither plugin is registered or counted as implemented by
this milestone. It does not scan conhost processes or accept a kernel version
as proof of a conhost layout match.

The fixed Volatility 3 v2.28.2 commit is
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. The development oracle executes its
original, unmodified command/history extensions using actual byte-backed objects
and all 11 bundled conhost x64 ISFs. Python is not a runtime dependency.

## Behavior

- Command validity checks Length and Allocated independently in 1..1024. A
  Length greater than Allocated is allowed by the baseline. Empty commands
  short circuit before reading Allocated.
- Text shorter than eight UTF-16 code units is inline; lengths 8..1023 follow
  the pointer. Decoding replaces invalid surrogate sequences, consumes either
  BOM, and truncates at the first decoded NUL. Original text bytes are retained.
  Length 1024 remains valid but its text is absent (`nil`, no read error).
- Command count preserves the baseline's floating division followed by integer
  truncation toward zero, including reversed intervals shorter than one slot.
  Counts outside native int64 are explicit errors.
- History validity checks count, signed LastDisplayed and the dereferenced
  handle, with the original short circuits. It does not validate Maximum or
  capacity. `History` reads full metadata and may therefore report a fault in
  metadata which `ValidHistory` does not need.
- Active bucket walks use an explicit exclusive end; default walks use the
  greater of EndCapacity and Begin + sizeof(history) * Maximum. The baseline
  uses the history size here (96), rather than the command size (32).
  Original slot indexes and valid duplicate records are retained.
- Bucket walks check arithmetic, impose a caller-selected 1..1,000,000 slot
  limit, and terminate on a read fault, cancellation or emitter error. Already
  emitted commands remain available to callers; a fault is never a clean empty
  result. Text read errors are distinct from the baseline's absent text.

`ParseHistoryLayout` projects four required command/history types into a native
ISF table without modifying their definitions. Unrelated screen types contain
negative synthetic offsets unsupported by the general native ISF reader. This
adapter does not expose or claim support for those types. Its table digest
identifies the projection: integration must also retain the original file hash
and matched conhost identity in provenance/cache keys. Layout selection,
downloading and cache verification are supplied by the separate
[layout acquisition component](windows-console-layout.md).

## Validation

- `tools/build_console_history_oracle.py`: 385 controls (11 original layouts ×
  35 scenarios), each comparing original validity, text, count, history validity,
  application, active commands and unused-slot scanning. Controls include
  inline/pointer boundaries, BOMs, unpaired surrogates, NULs, negative and
  unaligned intervals, capacity bounds, invalid handles, metadata/text holes,
  and invalid candidates whose handle/allocation metadata must not be read.
- `go test -race ./pkg/winconsole`: passes all original controls plus malformed
  layouts, overflow, slot limits, cancellation and emitter error checks.
- `go test ./pkg/winconsole -run '^$' -fuzz FuzzHistoryBucket -fuzztime 10000x`:
  passes 10,000 runs; mutates addresses, capacities, maxima and backing command
  bytes under a 32-slot bound.
- Complete `make check` passes (Go vet, full race suite, 43 Python tests and
  428 argument fixtures); the unchanged engine suite reused its successful
  result from the mapped-acquisition milestone.
- Python 3.12 generator regeneration check, package vet, matrix validation,
  local build and offline doctor pass. CI runs the generator check, package
  tests and 10,000 fuzz executions.

This is synthetic component validation. It does not establish real-image
cmdscan parity, process/VAD discovery, registry history settings, correct
per-process conhost version selection, console screen recovery, evidence-store
integration, or complete generator parity. These remain required before either
plugin can advance in the capability matrix.
