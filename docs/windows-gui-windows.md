# Window inspection foundation

Development component for the pinned Volatility 3 v2.28.2 baseline
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`.
`windows.windows` is registered separately as a partial plugin; see
[plugin validation](windows-windowlist.md). These component controls do not
establish full capability acceptance.

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

The field-method oracle uses a physical byte buffer. The complete plugin oracle
now additionally verifies a translated direct-name prefix ending at a later
missing page. Native partial reads retain both the prefix and read error. These
finite controls do not establish full plugin or OS acceptance.

## Adjacent and child traversal

`Reader.Windows` adds bounded traversal from the desktop-info's `spwnd` field.
`WindowRef.Offset` preserves the original displayed offset, while
`WindowRef.Address` identifies the actual window whose fields are read. The
initial window and recursively visited children are pointer objects in the
original; their displayed offsets identify pointer storage. Adjacent windows
are dereferenced structures and display the target address. These two locations
must not be silently conflated in evidence or owner/session lookup.

The original mixes pointer values and structure identity hashes in its local
sets. Its sibling-cycle check recognizes a return to the first pointer's target,
but a cycle between other siblings runs to the local window bound. Its child
null check examines the pointer-field offset, so a zero-valued child can still
yield an entry with a nonzero displayed offset before reads at zero fail. Native
controls preserve these behaviors rather than replacing them with a conventional
address-only tree walk. Pointer member/dereference caches are modeled locally.

Original child-parent iteration uses an identity-hashed Python set and has no
stable cross-process order. Native traversal uses parent discovery order;
complete child entities are normalized for comparison, and the stable adjacent
prefix is compared in order. A native active-child-cycle check and explicit
depth/step bounds stop recursive corruption with an error. The original can
instead raise RecursionError. Previously emitted rows and raw source reads are
retained. A bound hit is an explicit incomplete result, not silent exhaustion.
The original max-windows bound applies within frames and to outer unique
display offsets; both are retained. Native bounds require positive values.

`tools/build_gui_window_walk_oracle.py` runs 168 actual original generator
controls (14 scenarios over 12 layouts), covering sibling and child links,
shared children, null targets, cycles, faults and small bounds. A test-harness
recursion limit of 128 bounds the original's child-cycle case; no method is
replaced. Native tests independently verify every captured source byte and
check emitter failure, cancellation before/after output, and invalid/depth/step
bounds. The traversal fuzz target patches image bytes and missing regions.

The partial plugin has complete original-generator controls on one paged layout
and a sealed/read-audited real-image negative partial control. Remaining work
includes broad paged/version coverage, positive real window recovery, and
analysis of how unstable child order interacts with truncated/cyclic multi-branch
results. No full Windows window-enumeration acceptance is claimed.
