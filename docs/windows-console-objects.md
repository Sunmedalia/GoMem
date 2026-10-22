# Native console objects (development dependency)

`pkg/winconsole.ConsoleReader` adds title, scalar and list primitives for the
planned `windows.consoles` plugin. It uses Volatility 3 v2.28.2, commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`, as its fixed reference. The plugin
remains missing and unregistered. This component does not discover candidates
or produce a complete console property tree.

`ParseConsoleLayout` retains the exact source SHA-256 and validates x64 pointers,
consumed integer widths and signed offsets. Console metadata can precede the
nominal object or lie beyond its declared size in the original synthetic ISFs.
The adapter checks address arithmetic without relaxing the general ISF parser.
The existing command/history projection is also available for later integration.

`Scalar` returns the field address, raw bytes, signedness and value. Signed
scalars are sign-extended into the uint64 value; consumers use int64 for display.
`Title` reads the declared pointer and all 512 bytes requested by the original
UTF-16 string cast, including bytes after an early NUL. It preserves BOM and
replacement semantics, source coordinates and partial bytes on a failed read.
A failed read returns an error and does not invent a decoded empty title.
A successfully read empty string remains distinct from that failure.

`Valid` checks HistoryBufferCount before touching titles, then tries Title and
only reads OriginalTitle when needed. Its Boolean follows the original finite
controls. Unlike the original, suppressed title read errors remain in the
returned error. A candidate can therefore return **true and an error** when a
readable original title rescues an unreadable current title. Consumers must
retain both the candidate and the failure when this happens.

`WalkList` resolves either an embedded or pointer head from the console layout,
and resolves `_LIST_ENTRY` from the supplied kernel ISF. It supports console
histories, attached process lists, executable alias lists and alias lists.
It captures node readability, checks container subtraction, bounds entities to
1..1,000,000, and stops on cancellation or emitter failure. Backlink values do
not filter nodes. An unreadable optional backlink retains an error while
independently readable nodes continue. Null links, non-sentinel cycles and
read failures remain errors; a healthy empty sentinel list succeeds.

## Verification

`tools/build_console_object_oracle.py` executes the unmodified title, validity,
history/process/executable-alias/alias list methods, plus attached-process and
scalar projections on real byte-backed objects. It uses all 11 exact bundled
console layouts and a real external kernel `_LIST_ENTRY` symbol table. There
are 319 controls (11 layouts × 29 scenarios), with no analysis method mocks.
The bundled 25398 layout remains a component-only control; the baseline version
selector maps that build to the 22000 layout.

Controls cover empty/original-only titles, BOMs, malformed surrogates, NULs,
512-byte strings, holes after an early terminator, count/title short circuit,
negative dimensions, pointer/embedded list heads, empty lists, null heads,
cycles, metadata holes and ignored mismatched backlinks. Native tests compare
successful projections, independently reread scalar/title/process captures,
and verify bounds, partial bytes, cancellation and emitter failures.

Differences remain explicit:

- Original title methods swallow read errors; native preserves them, including
  errors in otherwise valid candidates.
- Original list methods can silently stop on nulls/cycles or range failures;
  native retains an error and its acquired prefix.
- Two injected physical-read fault scenarios abort the original iterator after
  it yields an unreadable node. Native requires a readable container byte and
  returns the preceding node plus the read error. This is an acquisition
  difference, not a complete-plugin parity claim.
- An unreadable optional backlink can fail the native read audit even when the
  original never consumes that backlink and both enumerate the same nodes.

Package race tests pass. Data acquisition fuzzing passes 10,000 executions and
layout parsing passes 1,000; CI regenerates the oracle and runs both targets.
See [validation record](windows-console-objects-validation.json) and the
[screen buffer component](windows-console-screen.md).

Remaining work includes full console candidate scanning, screen-chain behavior,
executable/alias strings, command/property trees, registry settings, real-image
positive controls, task/store/export/cache/resume integration and performance
acceptance. Component controls do not advance `windows.consoles` to partial.
