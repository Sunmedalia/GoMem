# Native console screen chains and alias text (development dependency)

`ConsoleReader.WalkScreens`, `CommandText` and `ExeName` extend the native
console components against Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. They are dependencies of the planned
`windows.consoles` plugin, which remains missing and unregistered.

`WalkScreens` reads both current and alternate roots before enumeration, omits
the alternate when both pointer values are equal, then follows each Next chain.
The original `CONSOLE_INFORMATION.get_screens` yields **pointer objects**:
`vol.offset` is the pointer field's address, while its integer value is the
screen target. `ScreenLink.Address` and `Target` retain these separately.
Deduplication follows pointer field addresses. Shared tails can therefore yield
the same target more than once; deduplicating target addresses would lose
baseline observations. The actual target is used for buffer metadata reads.

A bound applies across both roots. Each screen's capacity and row-array pointer
are read before emission, matching the original method's metadata dependencies.
Negative capacity is rejected explicitly. A repeated pointer within one chain
retains a cycle error while the independent alternate chain continues. A later
read or emitter error preserves prior diagnostics. Cancellation and emitter
failures are terminal. Screen/object layouts must share their exact original
source digest, preventing mixed-version reads.

`CommandText` reads a declared embedded `_COMMAND`, returning its object address,
typed optional string and original text bytes. It supports alias Source/Target
and modern executable names. Length 1024 retains the original `None` result;
inline/pointer boundaries, BOMs and NUL behavior reuse the command reader.
The shared command text reader now preserves partial bytes on a failed read.
It returns no decoded string for those partial bytes.

The older pointer-valued `_EXE_ALIAS_LIST.ExeName` method invokes `get_string`
on a string object, raising `AttributeError` in the pinned baseline. Native
returns `ErrLegacyExeName` and retains the pointer field capture. The original
controls also raise the same missing-method error when the target byte is unreadable
or non-ASCII; native preserves that outcome without introducing an extra
target read. It does not fabricate an executable name or claim that legacy decoding is implemented.

## Verification

`tools/build_console_relations_oracle.py` executes the actual unmodified
screen-chain generator, executable name and alias source/target methods.
264 controls cover all 11 exact original layouts × 24 scenarios. Screen results
include both pointer field addresses and target values, retaining the prefix
when the original iterator raises. No analysis methods are mocked.

The original physical fixture layer explicitly uses a 64-bit address mask.
Without this override, Volatility masks pointers to the small fixture's address
width and can turn damaged pointers into apparently readable data. In the
17763 layout, Next at offset 36 overlaps the TextBufferInfo pointer at offset
32. Nonzero Next values in these controls corrupt the high pointer bits; both
implementations retain the resulting failure. The layout is not rewritten to
make that case pass. This is a finite component failure control, not acceptance
of real 17763 console recovery.

Tests compare ordered pointer/target pairs and optional text, independently
reread emitted pointers and successful text captures, and cover equal/null
roots, shared tails, cycles, metadata holes, zero/negative capacities,
length-1024, empty strings, NUL/BOM text and read errors. Native-only controls
verify node bounds, emitter failure, cancellation, source-digest mismatch,
partial text bytes and preservation of a cycle diagnostic before a later read
failure. A memory mutation fuzz target exercises the whole bounded relation
pipeline, with 10,000 local executions and the same CI budget.

Explicit differences: original cycles stop silently but native returns an error
while retaining all original emitted links; a negative capacity stops native
before the invalid link while the original still yields it. Legacy ExeName's
original `AttributeError` is a native typed unsupported error. Other original
read failures retain their acquired prefixes and errors.

Full plugin candidate/registry scanning, property/history trees, real positive
console corpus, sealed task storage/export/cache/resume and release performance
acceptance remain pending. See [validation record](windows-console-relations-validation.json),
[console objects](windows-console-objects.md) and [screens](windows-console-screen.md).
