# Shimcache path and file-size fields

Development dependency for `windows.shimcachemem`; the plugin remains missing and
no full capability acceptance is claimed. This component decodes two properties
from an explicitly supplied entry and selected layout. It does not discover an
entry, validate the complete cache, or prove that a layout matches the kernel.

`winshimcache.NewEntryFieldsReader` takes the memory layer, data-only layout,
kernel ISF and native address mask. Path and optional FileSize offsets come from
the selected layout; Unicode-string and scalar definitions come from the kernel.
Input is bounded to 4 MiB, types to 1 MiB, inline paths to 65535 bytes and path
lengths to the 16-bit Unicode Length field. It checks pointer representation,
pointer-width agreement, path targets, scalar types, extents and mask validity.
The raw layout and kernel SHA-256 values remain available as provenance.

`FilePath` preserves the fixed Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75` behavior:

- Descriptor paths mask and read `Path.Buffer` before reading `Path.Length`.
  `MaximumLength` neither limits nor validates the read.
- The original UTF-16 codec is modeled, including replacement characters,
  malformed surrogates, odd tails, and little/big-endian BOMs. Unlike inline
  paths, descriptor text retains embedded NUL characters.
- XP/2003 inline bytes are decoded as UTF-16LE. The first NUL or replacement
  character truncates the text, and a BOM is retained rather than consumed.
- Successful reads return the text plus its start address, requested length,
  captured bytes and completeness. A fault after a readable prefix returns the
  bytes and native read error; XP keeps the translated readable prefix as text,
  while a descriptor reports the path unreadable. Short reads without errors are
  converted to `io.ErrUnexpectedEOF`, never an empty successful path.

`FileSize` reads the kernel-declared scalar and clamps negative values to zero.
An absent field is `not_applicable`; a present but unreadable field returns an
error with `unreadable` evidence. This distinction is retained rather than
converting absence and faults to zero.

`tools/build_shimcache_fields_oracle.py` invokes the unmodified original
`file_path` and `file_size` properties on byte-backed objects across all twelve
shipped layouts. Its 493 controls include x86/x64, XP and every post-XP layout,
x64 48-bit/full-width masks, embedded NULs, malformed UTF-16, BOMs, zero and
65535-byte lengths, high/null pointers, read holes and signed/extreme sizes.
Native tests compare path text or absence classification, size values, returned
captures and independently re-read bytes. They add malformed schemas,
short-read recovery, cancellation, overflow, actual Windows 10 kernel metadata
and schema/field fuzz targets. The synthetic Unicode descriptor types are method
controls, not version acceptance.

The original data-only layouts are shared with the [AVL fixtures](windows-shimcache-avl.md)
and retain their upstream VSL license. Remaining work includes time and execution
fields, XP validation, kernel/layout selection, modern/legacy/XP discovery,
bounded cache traversal, plugin/timeline integration, sealed persistence and
positive real-image full-plugin differential comparison.
