# Native Windows window enumeration

Development preview against Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`; partial implementation, not accepted
as complete. GUI component behavior is documented in
[window inspection](windows-gui-windows.md).

```sh
gomem analyze windows.windows --image memory.dmp --symbols kernel.json \
  --os windows --case case-001 --format jsonl
```

The native x64 pipeline discovers process session address spaces, scans Wind
pool objects, rebinds each valid station to its session and follows the original
desktop enumeration. It reads window owner, name, session and procedure through
that session layer. The enumerating station/desktop remain separate from the
window's own desktop-derived session. A procedure of zero is valid, values from
1 through 0x1000 are rejected, and an unreadable procedure remains an explicitly
unavailable field on an otherwise readable window row. Empty or unreadable
window names are unavailable rather than empty strings in the displayed result.

`RecordType=window` exposes the original eight fields: Offset, Station, Session,
Desktop, Window, Procedure, Process and PID. `WindowAddress` and ObjectOffset
retain the actual window object address separately from Offset: the original
top-level/child pointer objects can display the pointer field's storage address.
Owner/thread addresses, raw names, name-buffer addresses and procedure errors
remain available as evidence. Failed owner/session checks become `gui_candidate`
rows. Session discovery, station/desktop metadata and every acquired read are
also persisted. Read failures preserve partial results and fail the task; zero
window rows are not a clean absence claim.

Native bounds are max-desktops=12 (0..1000000), max-windows=10000
(1..1000000), max-window-steps=1000000 (1..10000000), and max-window-depth=128
(1..256), plus the shared process/session/station/read/byte/output limits.
The original internal per-frame and outer unique-offset window limits are
preserved. Native active-child-cycle detection, step/depth limits and allocation
bounds return explicit errors. The original can recurse until RecursionError.
Original child-parent iteration uses identity-hashed Python sets; native uses
discovery order. Complete child entities are compared without that unstable
order; truncated/cyclic multi-branch selection still needs investigation.

GUI data-only layouts are selected, pinned and verified with SHA-256. Runtime
GUI dependencies force a fresh task until safe dependency revalidation/reuse is
implemented; failed tasks are never replayed as successful completed work.
Python/Volatility are used only by development validation tools.

## Validation

`tools/build_windows_oracle.py` executes the complete unmodified original plugin
generator with real GUI extensions, pool scanning, kernel types and Intel x64
translation. Its 16 scenarios compare all eight output fields in order and cover
adjacent/child windows, missing/zero/invalid procedures, empty/unreadable/fallback
names, owner faults, private process names, a different window session, invalid
top/next/child pointers and a direct-name prefix ending at a missing page. Every
captured physical/kernel/session read is independently reread and checked.

All 16 engine cases check entity fields, evidence seals, byte-identical SQLite
and streamed records, fresh execution, failed retry and corrupt-layout rejection.
The underlying components additionally have 312 original field-method controls
and 168 original traversal controls across 12 layouts. The paged pipeline fuzz
target verifies bounded reads, source bytes and stream termination; 2066 local
executions passed for a 2000-execution budget.

The selected official Windows 10 19041 dump (SHA-256
`ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`)
emits **zero windows in both tools**. The native task
`89241d782c401a4a553ba49e6a718ff2` remains failed/incomplete with 4725 failed
read observations, including nested/repeated reads rather than unique missing
pages. This is a negative partial control, not positive real-image recovery.
The audit verified 195233 seals, all 191179 source reads, 805863444 acquired
bytes and 97163 raw captures, and checked original image/config/output hashes
and exact symbol archive-member parity. There are 13 station/desktop metadata
rows each and 4022 candidate rows; none are promoted into a successful window.

The original CLI needs `windows.windows.Windows` because `windows.windows` is
ambiguous with WindowStations. Native GoMem uses `windows.windows` directly.
The diff profile is [windows.windows.json](diff/windows.windows.json).
`TestWindowListCorpusSealedOriginalAndReadAudit` audits an existing acquisition
using absolute GOMEM_GUI_IMAGE, SYMBOLS, CASE, TASK, WIRE, REFERENCE paths and
GOMEM_GUI_PLUGIN=windows.windows; GOMEM_GUI_AUDIT optionally writes the audit.

Full supported-version/architecture, positive real windows, malformed layouts,
independent PDB, swap/prototype pages, ARM64, all renderers/exports, performance
and dependency-aware task reuse/resume remain unaccepted.
