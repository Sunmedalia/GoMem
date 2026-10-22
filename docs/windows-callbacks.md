# Windows callback acquisition dependencies

`windows.callbacks.Callbacks` remains **missing** as an end-to-end native
analysis plugin. The components here are development-preview dependencies;
they are not a complete implementation or a release-acceptance claim.

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
the eventual analysis plugin can capture their original bytes and coordinates.

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

Pool callback validity/decoding (including shutdown and PnP object names),
module/symbol attribution, full original generator comparison, CLI/TUI
registration, sealed engine storage/cache, real-image differentials, broader
Windows coverage, investigation rules, renderer/export and performance
acceptance remain open. See [the validation record](windows-callbacks-validation.json).
