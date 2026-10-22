# Shimcache kernel resource validation

Development dependency for `windows.shimcachemem`, which remains missing in the
capability matrix. No full plugin or real-image acceptance is established here.

`winshimcache.NewResourceReader` takes an explicit memory layer and the parsed
kernel ISF. It validates the `_ERESOURCE`, `_LIST_ENTRY`, `_KSEMAPHORE` types,
field extents, scalar representation, pointer targets and unsigned little-endian
32/64-bit pointers. SharedWaiters accepts `_KSEMAPHORE*` and the `void*` declaration
present in the local Windows 10 kernel ISF. Semaphore probes are bounded to 1 MiB. No kernel offsets are
hardcoded, and the Shimcache layout's external placeholders are not kernel types.

`ResourceReader.Valid` follows the ERESOURCE predicate from the fixed Volatility
3 v2.28.2 commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`:

- The resource's first byte must be available.
- A nonzero SharedWaiters checks a semaphore-sized span at the **pointer storage
  address**, not its target. An unmapped target can pass.
- Forward and backward list pointer values must differ. Zero pointers are not
  explicitly rejected; they can pass if the subsequent fields at zero map.
- Flink.Blink and Blink.Flink must equal the **resource base**, including when
  SystemResourcesList is embedded at a nonzero offset.
- NumberOfSharedWaiters must be zero. Rejected links short-circuit later reads.

The native reader probes mapping availability with bounded reads, since its
layer interface exposes reads rather than the original `is_valid` operation.
Consequently its read sequence includes additional probe reads. These reads
remain visible to evidence wrappers. Read failures return errors rather than
being silently converted to a negative candidate. Cancellation and short reads
also remain explicit. A successful call requires at most eight reads.

`tools/build_shimcache_resource_oracle.py` invokes the unmodified original
ERESOURCE method on real byte-backed objects. It uses four **synthetic** kernel
schemas (two pointer widths and two list offsets, including typed and void waiter
pointers), with 84 controls covering
null/equal links, backlink mismatches, shared waiters, zero resource addresses,
unmapped waiter targets, holes in fields/targets/probe spans and short-circuiting.
These are method controls, not actual kernel-version layout fixtures. Native
tests compare booleans and independently verify every captured byte. They also
check malformed kernel metadata, cancellation and overflow. The oracle records
original uncaught waiter-read exceptions separately from false predicates.

Handle/entry validation, kernel/layout matching, cache discovery, full entry
fields, bounded traversal, plugin integration, sealed persistence and positive
real-image differential tests remain outstanding.
