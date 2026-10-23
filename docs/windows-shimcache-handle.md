# Shimcache cache handle validation

Development dependency for the partial `windows.shimcachemem` Windows 8+ route.
This component validates candidates; its controls do not establish complete
real-image plugin acceptance.

`winshimcache.NewHandleReader` composes the kernel resource, Shimcache AVL and
non-XP linked-entry readers using the selected layout, image kernel ISF, explicit
memory layer and native address mask. All offsets are obtained from those
symbols. Layout input is bounded to 4 MiB, types and handle field offsets to
1 MiB. Pointer widths and external targets are checked. XP is rejected here
because its entry predicate and discovery path are separate.

Four original non-XP layouts declare SHIM_CACHE_HANDLE smaller than a required
field: 2003 x86, Vista x86, Windows 7 x64 and Windows 8 x64. The original object
reader still accesses the declared offsets. The native handle reader preserves
those original offsets using bounded scalar reads and reports each exception
in `LayoutAnomalies`, which discovery evidence must retain. It preserves the
unmodified layout SHA-256, never silently rewrites the source type size, and
rejects unbounded offsets or wrong pointer targets. An anomaly does not mean
that every byte in the enclosing structure has been recovered.

The implementation follows the fixed Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`:

- `Head` validates the resource, constructs the table from its masked pointer,
  and checks availability of the **pointer storage byte**. It then validates an
  entry at **table target + table type size**. It does not validate the AVL and
  does not require the AVL target's first byte to be readable.
- `Valid` rejects a zero handle, probes the first byte, validates its resource
  and AVL, and evaluates the head property twice. Null resource/table pointers
  may pass if memory at zero satisfies their respective predicates.
- Native masks apply to handle pointers and resource/AVL pointers, as in the
  original pointer constructor. Raw captured bytes retain the unmasked values.
- Read failures and short reads return explicit errors; readable rejected
  predicates return false without errors. Overflow and cancellation stay errors.

Mapping probes use evidence reads. Repeated native predicates re-read fields;
the original caches scalar and dereference objects within an operation. Tests
therefore compare predicate results and head addresses on static images, not
identical read sequences. They independently check every native captured byte.
There are at most 43 reads for a successful handle check and 14 for a head check
with the synthetic kernel layouts used by these controls. Read sizes remain
bounded by validated scalar widths and semaphore size (at most 1 MiB).

`tools/build_shimcache_handle_oracle.py` invokes the unmodified original
SHIM_CACHE_HANDLE.is_valid and head property using all ten shipped non-XP
layouts, original native scalar tables and synthetic kernel metadata on real
byte-backed objects. Its 525 controls each compare both operations, across x86
and x64 48-bit/full-width masks. Cases include null/zero/high-bit pointers,
resource/AVL rejection, missing fields and targets, probe-span holes, equal/null
entry links, arbitrary entry backlinks and declaration-size anomalies. Additional
native tests cover address addition overflow before a head read, short reads,
malformed schemas, cancellation and constructor validation against the local
Windows 10 kernel ISF. That last test checks metadata only, not memory discovery.

The original data-only layout bytes are shared with the [AVL fixtures](windows-shimcache-avl.md)
and retain their upstream VSL license. CI regenerates the oracle and runs the
handle and handle-layout fuzz targets. Legacy/XP discovery, real x86/PAE
acquisition, timeline integration and complete failure/parameter acceptance
remain outstanding.
