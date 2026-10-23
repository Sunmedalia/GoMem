# Shimcache timestamps and execution flag

Development dependency for `windows.shimcachemem`; the plugin remains missing and
no full capability acceptance is claimed. This component decodes three more
properties from an explicitly supplied entry and selected layout. It does not
discover an entry, validate cache membership, select a Windows-version layout,
or establish a positive real-image plugin comparison.

`winshimcache.NewTemporalReader` takes the memory layer, data-only layout,
kernel ISF and native address mask. It validates the selected entry and optional
detail types, `_LARGE_INTEGER.QuadPart`, pointer widths, scalar representations,
field extents and the `nt_symbols!` mapping used by the original symbol table.
The raw layout and kernel SHA-256 values remain available as provenance.

`LastModified` follows the pinned Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`:

- It prefers `ListEntryDetail.LastModified.QuadPart` and falls back to
  `LastModified.QuadPart` only when the detail field is absent.
- A detail-pointer or selected-field read fault is unreadable and does not
  trigger a fallback.
- Ticks use Python floor division by 10,000,000, discarding subsecond precision.
  Zero is not applicable; an invalid UTC conversion is unparsable.
- A 48-bit native mask applies to the detail pointer. `BlobBuffer`, by contrast,
  is a scalar in the original layout and is not masked.

`LastUpdate` reads only the direct `LastUpdate.QuadPart`. A layout without that
field is not applicable; a present field with a read fault is unreadable.

`ExecFlag` preserves the original property's actual control flow. It prefers
detail `InsertFlags`, then direct `InsertFlags`, then detail
`BlobBuffer`/`BlobSize`. Successful reads are subsequently replaced by the
original's unconditional `else` branch, so the emitted value is not applicable.
Only a read fault remains unreadable, and an empty blob remains unparsable.
The blob's validity check requires the native layer to accept the exact address
and length; zero-length reads at zero are rejected before the empty-value branch.
This reproduces the fixed implementation rather than silently repairing its
documented behavior.

Each property returns a typed value, source address, requested length, captured
prefix and completeness. Short reads without errors become
`io.ErrUnexpectedEOF`; genuine faults remain errors. At most four scalar reads
are needed by an execution-flag lookup, with the blob bounded to the native
16 MiB read limit.

`tools/build_shimcache_temporal_oracle.py` invokes the unmodified original
properties on byte-backed objects across all twelve shipped layouts. Its 595
controls cover x86/x64, XP and every post-XP layout, 48-bit/full-width masks,
epoch and before-epoch ticks, signed high bits, out-of-range dates, detail
pointer faults, direct-field faults, empty/short/odd blobs, missing fields and
the original successful-execution branch. Native tests compare all three values,
read captures and error classification, then add cancellation, overflow,
short-read, malformed-schema, real kernel metadata and field/schema fuzz targets.

The original data-only layouts retain their upstream VSL license. Remaining work
includes XP validation, version-to-layout selection, modern/legacy/XP discovery,
bounded cache traversal, plugin/timeline integration, sealed persistence and a
positive real-image full-plugin differential comparison.
