# Windows GUI external executive pool carving

Development dependency for pinned Volatility 3 v2.28.2. No GUI plugin is
registered here; this does not establish real-image native GUI discovery.

`guiPoolConstraints` provides the original separate Wind/Desk constraints:
Wind has a 0x90-byte minimum; Desk has no size bounds. Both accept paged and
nonpaged pools, exclude free pools, and skip executive type-index checks.
Kernel built-in constraints remain separate.

The shared scanner uses matching kernel symbols for pool headers, executive
body displacement, optional-header ordering, type map, cookie and OS rules.
External body sizes come from the selected GUI table during bottom-up carving;
the kernel table is not expected to contain GUI types. An explicit callback
validates station sessions or desktop parent/session pointers in the scanner
layer. Pointer widths must agree. Callback validity is per candidate: unreadable
candidates are rejected as upstream does; wrapped acquisition readers retain
read errors for later partial-task reporting. The helper by itself does not
seal those failures or establish a clean task. Cancellation is terminal.

`tools/build_gui_pool_oracle.py` uses the original constraint factory,
PoolHeaderScanner and POOL_HEADER.get_object, actual GUI extensions and original
layouts. 480 controls cover 12 layouts, both carving directions, Wind/Desk,
normal/invalid/unavailable session IDs, parent holes/nulls, signed pointer-count
limits, free/paged pools and short allocations. Native tests compare constraints,
header filters, ordered carved addresses and the shared scanner. All GUI body
types are absent from the kernel fixture. Independent source byte checks run
on successful reads; holes must cause explicit incomplete scanner results.
Bounds tests cover unsupported layouts/tags/widths, cancellation and output
failures. Fuzz mutates pool headers and bodies under fixed window/read bounds.
A 10000-input local run passed in 1.753 seconds.

```sh
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_gui_pool_oracle.py --check
go test -race ./internal/plugins -run '^(TestGUIPool|TestPool|TestCallbackPool)' -count=1
go test ./internal/plugins -run '^$' -fuzz '^FuzzGUIPoolCarving$' -fuzztime 10000x
```

This is synthetic pool acquisition only. Session rebinding, complete station and
desktop/thread generators, positive real native pool comparisons, raw acquisition
sealing, failed-task retry and cache behavior still require integration tests.
The capability matrix remains 149 partial, 46 missing and zero accepted plugins.

Subsequent integration: [WindowStations](windows-windowstations.md) registers the
native station plugin with full generator, storage and real source controls.
