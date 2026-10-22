# Windows callbacks — development preview

`gomem analyze windows.callbacks` combines native index readers and pool object
decoding with module/symbol attribution. The capability is **partial**. It is
not a release-acceptance claim.

`pkg/wincallbacks` reads the original data-only callback ISFs against separate
kernel symbols. Local callback types and their base types use the `callbacks!`
namespace. External kernel aggregates and all their children retain
`nt_symbols!`, preventing same-named local types from changing kernel field
widths. Width mismatch, unknown namespaces, nil kernel tables and malformed
ISFs are explicit errors.

The catalog retrieves only the fixed baseline's `callbacks-x86.json` and
`callbacks-x64.json`. Both downloaded and cached bytes must match compiled
SHA256 pins; cache replacement is atomic. Offline operation, corrupt-cache
repair, concurrent resolution, response size bounds, HTTP failures and active
cancellation have native controls. Both official pinned HTTP sources and
subsequent offline replay were exercised locally. This validates auxiliary
layout acquisition, not independent kernel PDB parsing.

## Native index reader

`Index.Walk` streams notification arrays, ordinary BugCheck callbacks,
BugCheck reason callbacks and registry callbacks in the pinned method order.
It preserves duplicate entries and the baseline's individual decisions:

- Image notifications have eight slots; Vista-and-later process/thread arrays
  have 64. Fast-reference masks are 7 on x86 and 15 on x64. Even a zero reference
  is cast at offset zero; the callback field decides whether a row is emitted.
  Explicit controls populate the last selected slot and the first excluded slot,
  and map a nonzero callback at offset zero to verify these boundaries.
- Ordinary BugCheck component addresses are relative to the kernel module
  because the pinned method omits `absolute=True`. Reason components are
  absolute. Both paths check 64 callback bytes and read at most 64 component
  bytes, preserving replacement-character decoding.
- Legacy registry vectors take precedence over the new list when both roots
  exist. A zero callback count stops either path. New registry lists use count
  only as a zero/nonzero guard, and preserve entries whose function is zero.

The reader uses bounded field reads, checked address arithmetic, finite node
limits, cancellation, terminal emitter errors and strict linked-list integrity.
An independent readable root survives a damaged root, but the returned error
retains failed completeness. A kernel exposing no usable index roots is
explicitly unsupported. All reads pass through the caller's memory layer so
the analysis plugin captures their original bytes and coordinates.

`tools/build_callback_index_oracle.py` executes four **unmodified original
methods** on each of 88 byte-backed controls: two pointer widths, two Vista
modes, two registry formats and eleven scenarios. That is 352 method runs,
using the original callback ISFs and actual fast-reference, list-entry and
Unicode-string extensions. It does not replace analysis methods or field
decoding. Native tests compare ordered type/address/detail projections and
independently reread callback addresses from original source bytes using the
original schema's field offsets.

The damaged-input differences are explicit:

- Eight missing-callback-field controls abort the baseline notification method
  after the image entry. Native preserves the later independent process entry
  and returns a failure.
- Four new-registry controls have unreadable altitude bytes. The baseline
  displays `Altitude: None`; native keeps a typed missing altitude and returns
  a failure. Tests verify this exact difference rather than counting it as
  result parity.
- Unreadable fast-reference slots and component strings keep failed coverage,
  even where the original method silently skips a slot or displays an absent
  value. Stricter cycle, backlink and resource-limit failures are intentional.

The pool dependency is documented with its **1,984 actual header controls** in
[the shared pool-scanner notes](windows-poolscanner.md#callback-pool-index-dependency).
Shutdown's zero-valued index endpoints are ignored by the baseline; PnP tags
require index 1. The independent pool-scanner plugin retains its original
fifteen built-in tags.

```sh
python3 tools/build_callback_pool_oracle.py --check
python3 tools/build_callback_index_oracle.py --check
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" \
  go test -race ./pkg/wincallbacks -count=1
go test -race ./internal/plugins -run '^TestCallbackPool' -count=1
go test ./pkg/wincallbacks -run '^$' -fuzz FuzzCallbackIndexes -fuzztime 10000x
```

The optional live-source test requires `GOMEM_NETWORK_FETCH=1`. Local-server
catalog controls that need original source files skip without
`GOMEM_BASELINE_DIR`; CI supplies it explicitly. Skips do not establish
acceptance.

## Pool decoding and analysis

Five callback structures are decoded from their allocation layer; device and
driver pointers are followed in the native kernel layer. The original x86
shutdown validity extension checks links, device readability/type and driver
alignment. The original x64 schema has no such extension, so the same checks
are deliberately not imposed there. Device/driver object-type checks omit the
header cookie, as the pinned callback methods do, even on encoded-index headers.
PnP names come from object-header NameInfo; shutdown uses DriverName and major
function slot 16. Zero callback functions and duplicate rows are preserved.

`tools/build_callback_object_oracle.py` records 360 actual original processor
controls: two widths, three header formats, five structures and twelve input
scenarios. Source allocations and native pointer targets occupy separate layers.
Native tests compare validity and selected type/address/detail values. A missing
PnP NameInfo aborts the baseline processor; native preserves the readable callback
with an explicit detail error. Other unavailable fields remain explicit errors,
including baseline paths which substitute an absent value. These differences
are tested rather than counted as parity.

Attribution preserves overlapping modules and multiple symbols at an address;
projected rows own separate cell maps. Cancellation and emitter failures are
terminal. `PoolHeader`, source offsets, layout pins, original read bytes/digests
and final completeness remain evidence. Read, byte, row and node budgets are
finite. Missing symbol layouts respect `--offline`.

## Real Windows control

The Windows 10 19041 image with SHA256
`ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`
produces 204 callback rows in both the unmodified pinned generator and native
analysis. Exact multiset comparison of **Type, Callback, Module and Symbol**
matches all 204 rows, including duplicates. The documented profile masks callback
addresses to 48 bits to reconcile canonical native and reference addresses.
Both analyses use the same kernel ISF; this is not independent PDB-parser parity.

The stricter **five-column** comparison deliberately **fails** for 156 rows:
one ordinary BugCheck and 155 BugCheck-reason details are reference null but
native typed unreadable values with explicit errors. The other 48 rows match
all five selected fields. This profile does not discard errors or collapse them
to ordinary nulls. The task remains failed with 280 failure observations
(including nested reads/decoding, not a count of distinct missing pages).
A second reference run used an output-only JSON renderer that preserves actual
absent-value class names while leaving all analysis methods unchanged. All 204
five-column values and missing classes match: the 156 baseline details are
`UnreadableValue`, not ordinary empty strings. Native additionally retains
156 explicit detail errors. This does not make the failed acquisition complete.

An independent audit verified all 107,509 row seals and reread all 107,302
captured reads from the original image, checking coordinates, lengths, raw bytes,
digests and completeness. This establishes provenance, not complete acquisition.

```sh
python3 tools/build_callback_object_oracle.py --check
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" \
  go test -race ./internal/engine -run '^TestWindowsCallbacksPagedStorageCacheAndFailedRetry$' -count=1
go test -race ./internal/plugins -run Callback -count=1
go test ./internal/plugins -run '^$' -fuzz FuzzCallbackPoolObjects -fuzztime 10000x
python3 tools/diff_results.py --native native.jsonl --reference reference.json \
  --mapping docs/diff/windows.callbacks-identity.json
# Ordinary reference JSON collapses missing classes; this strict comparison
# intentionally retains the native detail errors:
python3 tools/diff_results.py --native native.jsonl --reference reference.json \
  --mapping docs/diff/windows.callbacks.json
python3 tools/reference_callback_types.py --offline -q --cache-path .cache/reference-cache \
  -s REFERENCE_SYMBOL_DIR -f memory.dmp -r typedcallbackjson windows.callbacks.Callbacks \
  > reference-typed.json
python3 tools/compare_callback_types.py --native native.jsonl --reference reference-typed.json
go run ./tools/verify_pool --plugin windows.callbacks --image memory.dmp \
  --rows native.jsonl --dtb 0x6d4000
```

The composed native engine controls exercise real x86, PAE and x64 page tables,
six original-method index rows and one pool allocation per architecture. They
compare projected values, sealed SQLite storage and byte-identical successful
cache replay; two bounded failures per architecture each create fresh failed
tasks. These controls compose dependencies and do not replace a complete
unmodified synthetic generator comparison. The real failed task also exported
107,509 rows identical to emitted evidence; two real budget failures were
re-executed without a cache hit.

Complete synthetic generator controls, broader real Windows/x86/PAE coverage, investigation
rules, renderer/export and performance acceptance remain open. See
[the validation record](windows-callbacks-validation.json).
