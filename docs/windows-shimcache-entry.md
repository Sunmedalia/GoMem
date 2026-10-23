# Shimcache linked entry predicate

Development dependency for `windows.shimcachemem`; the plugin remains missing
and no full capability acceptance is claimed. XP uses a separate timestamp/size
predicate and is explicitly outside this reader.

`winshimcache.NewLinkedEntryReader` takes an explicit memory layer, data-only
Shimcache layout, parsed kernel ISF, and native-layer address mask. It projects
only SHIM_CACHE_ENTRY.ListEntry and validates its external kernel type, embedded
extent, 32/64-bit pointer representation, kernel link types, and a contiguous
low-bit mask within the pointer width. Input is bounded to 4 MiB; entry and list
types to 1 MiB. The full input layout SHA-256 is preserved. It does not select a
layout/kernel, fetch symbols, decode entry fields or walk the cache.

`LinkedEntryReader.Valid` follows the fixed Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`, including its weak list heuristic:

- The masked Flink value must be nonzero.
- Blink must be readable, but its target need not be mapped. Two distinct
  pointer objects produce distinct dereferenced structures, even when their
  numeric values are equal. Equal link values therefore do not reject the entry.
- Flink.Blink must be readable. The original compares that masked pointer value
  with its own dereference address, making the equality true after a successful
  read. It does **not** require a backlink to the candidate entry.
- The candidate address may be zero if the required fields are mapped.

This predicate does not establish list integrity. Native faults, short reads,
cancellation, invalid environments and address overflow return explicit errors;
a readable zero Flink returns false without an error. At most three scalar reads
occur, with no traversal or whole-structure read. Raw pointer bytes remain
available through a wrapping evidence layer even when high bits are masked.

`tools/build_shimcache_entry_oracle.py` invokes the unmodified original
SHIM_CACHE_ENTRY.is_valid on byte-backed objects for all ten shipped non-XP
layouts. The harness supplies synthetic kernel list types and the original
x86/x64 native scalar tables, matching the plugin's use of native types. These
are predicate controls, not real kernel-version or full-plugin acceptance.
The 270 controls cover x86 and x64 (48-bit/full-width masks), null/equal/self
links, null/arbitrary back pointers, inaccessible target bytes versus required
member bytes, high-bit pointers and short-circuit reads. Native tests compare
booleans and exact ordered read addresses/lengths and independently check every
captured byte. Fixture layout bytes and SHA-256 values are shared with the
[AVL controls](windows-shimcache-avl.md), which retain their upstream VSL license.

Additional tests cover malformed layouts, kernel width mismatch, external type
mismatch, bounds, cancellation and missing environments. Scalar and layout fuzz
targets are included in Makefile and CI. No memory-image discovery or extracted
entry has been validated by this component. Handles, full entry fields, version
selection, modern/legacy/XP discovery, bounded traversal, sealed persistence and
positive real-image original-plugin comparisons remain outstanding.
