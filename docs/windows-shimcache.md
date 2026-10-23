# Windows Shimcache

`windows.shimcachemem` implements a native development-preview route for
Windows 8 and later Intel kernels. It maps to the fixed Volatility 3 v2.28.2
`windows.shimcachemem.ShimcacheMem` class at commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. The capability remains **partial**,
`accepted=false`; XP through Windows 7 discovery and traversal are explicitly
unsupported.

The plugin uses the pinned newest-to-oldest version and fallback table to select
one of the embedded data-only layouts. It walks `PsLoadedModuleList`, requires an
exact `ahcache.sys` or `shimcache.sys` module identity, locates the mapped `.data`
and `PAGE` sections from the PE headers, scans pointer-aligned slots within the
declared `.data` extent, and requires two independently valid Shimcache handles.
The selected handle's AVL head is then traversed as a bidirectional list with
cycle, backlink and entry-count checks.

Null pointers are aggregated. On x64, masked 48-bit pointers are restored to
their canonical high-half form for native page-table reads. Candidate mapping is
probed through the original kernel layer before the evidence wrapper, so an
unmapped candidate is counted without creating a false object-read failure.
Actual reads through module headers, handles, resources, AVL links, list entries,
paths, sizes and timestamps remain in the result stream.

Each entry reports the six pinned columns: `Order`, `Last Modified`,
`Last Update`, `Exec Flag`, `File Size` and `File Path`. Native columns retain
layout and module coordinates, handle/storage provenance, per-field acquisition
digests and a summary. Missing fields are typed as not applicable, unavailable,
unreadable, unparsable or invalid; a fault is never converted to an empty value.
The fixed baseline's successful execution-flag path ultimately yields N/A and is
preserved.

`max-nodes` bounds module and entry traversal, `max-pointers` bounds `.data`
slots, `max-entries` bounds emitted entities, and `max-evidence` bounds retained
non-null candidate evidence. Cancellation and emitter errors stop work. Failed
tasks retain partial evidence and execute fresh on retry rather than replaying a
successful cache.

## Validation

`tools/build_shimcache_selection_oracle.py` invokes the unmodified pinned
`OsDistinguisher` functions and `ShimcacheMem._win_version_file_map` over 34
synthetic ISF presence controls. The Go test consumes the resulting oracle and
checks exact layout, family, pointer width and fallback decisions.

The supplied Windows 10 19041 bitmap crash dump
(`ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`) with
symbol archive SHA-256
`17fcda47d3dc232b1ef4a56e255c737f57954191d54ec301acd348096b92c5ce`
selects `shimcache-win10-x64`, examines 117 loaded modules and matches one
`ahcache.sys`. It scans 886 aligned slots, aggregates 77 null and 37
noncanonical pointers, rejects 425 unmapped candidates, validates two handles,
and emits four entries.

The six selected fields match the pinned reference for all three readable paths:
`cmdl32.exe`, `cmdkey.exe` and `whoami.exe`, including order, last-modified time
and N/A fields. The fourth entry's time and order match. Its path is `null` in
the pinned output after a prototype/swap page fault; native output retains the
typed unreadable path and original page-table error. The strict differential
therefore remains intentionally unmatched rather than erasing that evidence.

The real task fails with 343 read failures. These do not prove a clean cache and
prevent successful cache reuse. Real x86/PAE, other Windows builds, legacy routes,
timeline integration, investigative positive/normal corpora, renderer/export
parity and full capability acceptance remain pending. See
[the machine-readable validation](windows-shimcachemem-validation.json) and
[the field mapping](diff/windows.shimcachemem.json).
