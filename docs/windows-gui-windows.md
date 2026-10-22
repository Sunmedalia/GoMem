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

Unit tests exercise all 12 pinned layout fixtures, distinct inline/indirect
procedures, session resolution, zero procedures, unmapped procedure bytes,
cancellation and malformed schema rejection. These are native byte-backed
unit controls, not an independent original window-method differential.

Remaining work includes original-method oracles, window-name and process
resolution, bounded adjacent/child traversal with the original ordering and
duplicate semantics, plugin integration, sealed source-read auditing, and a
real-image differential. No Windows window-enumeration acceptance is claimed.
