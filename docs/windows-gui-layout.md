# Windows GUI layout selection and acquisition

Development dependency for window-station, desktop and window enumeration, fixed
to Volatility 3 v2.28.2 commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`.
No GUI plugin is registered at this milestone. The matrix remains 149 partial,
46 missing and zero accepted out of 195 plugins.

## Native behavior

`pkg/wingui.Select` selects an x64 GUI layout using the original descending
11-rule order. It preserves PE metadata order **major, minor, revision, build**,
including the original four-value unpack before comparison. A three-value tuple
falls back to kernel symbol/type features. Metadata exact-match checks for
Windows 7 compare tuples of different lengths and therefore cannot succeed;
the feature fallback can still select either Windows 7 layout. Missing types
and missing members follow the original distinct fallback behavior. Selection
returns both the layout name and whether metadata or symbol fallback chose it.
Malformed metadata controls exercise selector behavior, not upstream schema
acceptance. x86/PAE kernels are explicitly unsupported by this GUI selector.

`ParseLayout` preserves sizes and offsets of four consumed types: window
stations, desktops, thread information and process information. It validates
pointer targets and bounds, unsigned little-endian session IDs, and explicit
external kernel list/process references. External `_LIST_ENTRY` and `_EPROCESS`
must be resolved against matching kernel symbols; this package does not guess
kernel offsets. Unconsumed GUI types are excluded from the projection. Original
and projected symbol digests are distinct and must both be retained by future
plugin evidence.

`Load` acquires only the 12 SHA-256-pinned original data-only GUI ISFs (including
17735, bundled upstream but unused by the automatic selector). It verifies
online responses and offline cache entries, limits reads to 4 MiB, supports
cancellation, and publishes completed temporary files atomically. A cancellable
per-path transaction lock coalesces concurrent same-process loads and releases
idle locks. On Windows it repairs an invalid regular cache file only after a
verified replacement exists. Unknown names, path traversal, HTTP errors,
oversized data, missing offline entries and digest mismatches are explicit
failures. No Python or executable extension is fetched or run by this package.

## Verification and limits

`tools/build_gui_version_oracle.py` runs the actual unmodified
`WindowStations.create_gui_table` with real upstream intermediate symbol tables.
749 controls compare selection and its provenance, covering x86 rejection,
metadata boundary/order/shape errors, individual fallback vectors and 512 seeded
mixed fallback combinations. The fixture retains exact compressed original
bytes for all 12 GUI layouts; native catalog tests compare SHA-256 pins, field
projections, concurrent acquisition, offline reuse, corrupt-cache repair and
cancellation. Setting `GOMEM_BASELINE_DIR` also checks those bytes against the
locked checkout. JSON maps in the generator are ordered explicitly so its
`--check` result is independent of Python's randomized hash seed.

```sh
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_gui_version_oracle.py --check
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" go test -race ./pkg/wingui
go test ./pkg/wingui -run '^$' -fuzz '^FuzzGUILayout$' -fuzztime 1000x
```

The local layout fuzz control passed 1000 executions. CI regenerates the
original oracle, runs package race checks against the checkout, repeats catalog
checks on Windows/Linux/macOS and runs the fuzz target. A scheduled CI step is
not evidence of completed remote success.

These checks do not establish window-station, desktop or window recovery.
Session address-space acquisition, GUI pool scanning, object-header names,
thread/process ownership, window recursion, raw evidence, store/cache/retry
integration, full original plugin generators and positive real-image controls
remain unfinished. See [the validation record](windows-gui-layout-validation.json).

Exact original GUI layout data in `pkg/wingui/testdata/version-oracle.json` is
Copyright Volatility Foundation and remains subject to the
[Volatility Software License 1.0](../LICENSES/Volatility-Software-License-1.0.txt).

The subsequent [GUI object reader](windows-gui-objects.md) implements station and
desktop sessions, pinned station traversal and desktop thread ownership. Pool
scanning, session discovery and full GUI plugins remain unfinished.
