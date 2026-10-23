# Shimcache AVL validation foundation

Development component for Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. `windows.shimcachemem` remains
unimplemented in the official capability matrix; no plugin is registered by
this component and no full capability acceptance is claimed.

`pkg/winshimcache.ParseAVLLayout` projects the AVL table and balanced-root Parent
fields from a supplied data-only layout. It checks type/field extents, pointer
width (4 or 8), little-endian unsigned pointer representation and embedded/
parent target types. Input is bounded to 4 MiB and each projected type to 1 MiB.
The complete input's SHA-256 remains available alongside the projected table.
It does not yet select or acquire a layout for a kernel, or validate the entry,
handle and external kernel structures required by the full plugin.

`Reader.AVLValid` reads an explicitly supplied memory layer and follows the
original candidate predicate:

- BalancedRoot.Parent must equal the embedded BalancedRoot's address.
- AllocateRoutine and CompareRoutine targets must lie within the supplied PAGE
  range, including both endpoints.
- The three routine fields must occupy distinct storage addresses. Their values
  may be equal; comparing the values instead would reject valid original cases.
- FreeRoutine is read to construct its pointer object, but its target has no
  PAGE range check. A zero or out-of-range FreeRoutine is accepted if readable.
- Routine-field storage equality short-circuits later reads just as in the
  original. Table address zero is not automatically rejected.

A readable rejected candidate returns false without an error. A missing page,
overflow, malformed environment or cancellation returns an explicit error
instead of a successful negative result. Callers must retain those errors and
can wrap the supplied layer to capture the original reads. At most four scalar
reads are needed per candidate. This is the pinned heuristic predicate, not a
general validation of all AVL links or evidence that a cache exists.

`tools/build_shimcache_avl_oracle.py` invokes the unmodified original
RTL_AVL_TABLE.is_valid method on byte-backed objects using all 12 shipped
Shimcache layouts. Its 264 controls cover x86/x64, range endpoints/reversal,
parent mismatch, zero table/parent, equal routine values, unchecked free targets,
maximum pointer values, missing fields and an unreachable free-field fault.
Native tests compare each boolean and the exact ordered read addresses/lengths;
captured bytes are independently checked against the fixture image. Further
tests cover malformed layouts, storage aliases, overflow and cancellation.

Original layout bytes use raw base64. The first CI execution found fixture
drift because Python 3.12's zero-time gzip compression embeds the platform OS
byte (macOS versus Linux). Removing compression preserves all 12 original layout
byte streams and all 264 controls while avoiding platform-dependent headers.

Package race tests passed. Scalar validation fuzz passed 20000 executions and
layout parsing fuzz passed 2000. CI regenerates the original oracle and runs
both fuzz targets. The embedded original data-only layouts retain the Volatility
Foundation copyright and [Volatility Software License 1.0](../LICENSES/Volatility-Software-License-1.0.txt).

The preceding unsharded full race run reached its 30-minute package timeout
during a one-second GUI subtest without an assertion failure. `make check` now
uses the existing CI partitioner: every other package runs with race detection,
then all four engine shards run sequentially with race detection. The partition
audit includes every test/example/fuzz seed exactly once and retains the
30-minute limit per shard. Go executable overrides apply to both discovery and
execution. A complete run of that updated command is still pending.

Remaining work includes version selection and pinned runtime layout acquisition,
handle/entry validation, modern and legacy cache discovery, XP VAD
discovery, path/time/size/flag fields, bounded list walking, plugin/timeline
integration, sealed source audits and positive real-image comparisons. No real
image or full original-plugin generator has been validated by this component.

Kernel ERESOURCE validation now has a separate [native component and original
method controls](windows-shimcache-resource.md); it does not register the plugin.
