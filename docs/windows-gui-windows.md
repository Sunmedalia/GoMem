# Window inspection foundation

Development component for the pinned Volatility 3 v2.28.2 baseline
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. This does not register or complete
`windows.windows`; the capability matrix remains unchanged.

`wingui.ParseWindowLayout` extends the station layout with a bounded projection
of the desktop-info, window, thread-desktop header and large Unicode string
types. It checks embedded structure types, pointer targets, field extents and
the unsigned 32-bit string length. Optional `directName` and `subPointer` fields
are retained only when present in the selected layout. Kernel fields remain
external to the GUI table.

`Reader.DesktopWindow`, `WindowDesktop`, `WindowSession` and `WindowProcedure`
read through the caller's session layer. For layouts containing `subPointer`,
the procedure comes from the pointed-to `subTagWNDType`, even when the inline
procedure is different. Other layouts use the inline procedure. Zero remains
a readable address; unmapped memory and cancellation return explicit errors.
These readers do not apply the plugin's procedure-address filter.

`WindowOwner` follows `head.pti.ppi.Process` and reads the kernel process name
and PID in that same session layer, retaining the raw name and owner addresses.
`WindowName` reads up to 256 bytes through `directName` when present, then uses
`strName` after a failed direct read. A direct name truncates at the first NUL
or replacement character; the embedded large Unicode string truncates only at
NUL. UTF-16 BOMs, malformed surrogates and odd tails use the existing Python
codec-compatible decoder. The embedded name has an explicit native 65535-byte
allocation bound; a larger declared length is an error. MaximumLength is not
consulted, matching the original method. Successful fallback text can accompany
the failed direct read's error; callers must retain both.

Unit tests exercise all 12 pinned layout fixtures, distinct inline/indirect
procedures, session resolution, zero procedures, unmapped procedure bytes,
cancellation and malformed schema rejection. These are native byte-backed
unit controls. `tools/build_gui_window_oracle.py` additionally runs the
unmodified original GUI methods against 312 byte-backed controls (26 scenarios
for each of the 12 layouts), using the real symbol extensions and a 64-bit
address mask. Native tests compare names, procedure, desktop, session, process
name/PID and top window; they independently recheck captured source bytes.
The controls include missing pointers/buffers, empty and malformed names,
unused MaximumLength faults, direct-name fallback and differing inline versus
indirect procedure addresses. Regeneration is wired into CI. A bounded field
fuzz target covers both old and modern layouts; 20000 local executions passed.

The oracle currently uses a physical byte buffer. Translation-layer contiguous
prefix behavior across a later missing page has not yet been differentially
verified. Native direct-name partial reads retain the acquired prefix and read
error. These component controls do not establish full plugin or OS acceptance.

Remaining work includes bounded adjacent/child traversal with the original ordering and
duplicate semantics, plugin integration, sealed source-read auditing, and a
real-image differential. No Windows window-enumeration acceptance is claimed.
