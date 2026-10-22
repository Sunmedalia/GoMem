# Windows GUI session address-space discovery

Development dependency against Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. This implements the session-map
producer needed by GUI scans; no GUI plugin is registered at this milestone.

## Native behavior

`wingui.SessionReader.Visit` enumerates active process objects forward and then
backward, deduplicating object addresses in the same order as pinned PsList.
It constructs a native x64 process layer for each selected candidate and retains
only the first process for each session ID. It reads neither process names nor
timestamps; an unavailable image name does not discard a usable session layer.
An empty PID filter includes all processes.

The session ID is read through the **kernel layer**. Despite its comment, the
original `Modules._do_get_session_layers` does not read this ID through the new
process layer. Synthetic process-private shadow pages deliberately contain
conflicting IDs, so substituting that layer fails the comparison.

When `_MM_SESSION_SPACE` exists, its `SessionId` field must exist too. A missing
member is a schema error, matching the original AttributeError, and does not
activate a guessed offset. Only a missing type activates the pinned opaque
Windows session fallback: an unsigned little-endian 32-bit `unsigned long` at
`Session + 8`. Its use is explicitly marked `opaque-offset-8`; normal reads are
marked `typed`. No station-validity limit of 255 is imposed on the session map.

Each result retains the process object, PID, session pointer, original CR3,
normalized CR3, method and native layer. CR3 arrays are cast to a full 64-bit
value, including both halves of `u32[2]`. Low CR3 flags are retained in the raw
value and removed only for hardware translation. Layer identity includes the
kernel layer name, process object and PID; callers must provide the image's
kernel namespace and preserve image provenance when storing evidence.

Constructing a process layer does not prove it can translate memory. Like the
original method, a zero or unavailable CR3 can be selected when its session ID
is readable. Later reads fail explicitly; the kernel root is never substituted.
Session selection must not be presented as a clean or usable address-space test.

Native traversal additionally retains read faults, null links and non-sentinel
cycles as explicit errors while preserving useful rows. An unreadable pointer
target ends that directional walk, allowing reverse recovery; a pointer-value
read exception terminates discovery as in the original. Invalid-address errors
for one process do not discard later candidates. Schema failures, cancellation,
emitter failure and exhausted process/session bounds terminate the stream.
Failure aggregation retains a count and first cause under bounded memory.

## Verification

`tools/build_gui_sessions_oracle.py` calls the unmodified original
`Modules._do_get_session_layers`, with actual EPROCESS/LIST_ENTRY extensions,
process-layer construction and x64 page tables. **75 controls** cover 25 cases
across typed, missing-type and missing-member layouts. They compare selected
session order, raw CR3 and process-private translated probe bytes. Cases include
duplicate sessions/PIDs, null/unavailable session pointers, damaged lists,
reverse recovery, PID filters, ignored name holes, CR3 arrays (including a
nonzero high 32-bit half), CR3 flags and unavailable roots. Native tests require
explicit errors for original silent skips and audit successful physical reads
against the source fixture. Exact limits, bounded prefixes, cancellation and
emitter failures have additional guards. A 10,000-execution fuzz run mutates
processes, memory, page tables and holes under strict read/node limits.

```sh
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_gui_sessions_oracle.py --check
go test -race ./pkg/wingui
go test ./pkg/wingui -run '^$' -fuzz '^FuzzGUISessions$' -fuzztime 10000x
```

On the Windows 10 19041 crash image, the original and native methods select the
same three sessions (0, 1, 2), raw CR3 values and 16-byte shared kernel probes.
The native scan also reports four unavailable session reads at address `0x8`;
the original silently skips them. This is a partial-acquisition control, not
clean absence or positive GUI object recovery. The native audit independently
rereads 1,206 kernel accesses and 2,457 physical accesses (211,396 captured
physical bytes). These audit counters include nested rereads/cache activity;
they are not sealed evidence-row counts. See the
[validation record](windows-gui-sessions-validation.json) for hashes and roots.

To reproduce the optional corpus control, first generate a reference from a
hash-verified saved reference configuration (currently supports Windows x64
complete/bitmap crash contexts), using the exact same kernel ISF as native:

```sh
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_gui_sessions_corpus.py \
  --reference .cache/consoles-validation/reference \
  --image .cache/corpus/win-10_19041-2025_03.dmp \
  --symbols .cache/corpus/symbols/windows/167FE94B5641C005AC3036212A01F8DC-1.json \
  --output .cache/gui-sessions-validation/reference.json
GOMEM_GUI_SESSION_IMAGE="$PWD/.cache/corpus/win-10_19041-2025_03.dmp" \
GOMEM_GUI_SESSION_SYMBOLS="$PWD/.cache/corpus/symbols/windows/167FE94B5641C005AC3036212A01F8DC-1.json" \
GOMEM_GUI_SESSION_REFERENCE="$PWD/.cache/gui-sessions-validation/reference.json" \
GOMEM_GUI_SESSION_AUDIT="$PWD/.cache/gui-sessions-validation/native-audit.json" \
go test -race ./pkg/wingui -run '^TestGUISessionsCorpusOriginalMapAndReadAudit$' -count=1 -v
```

The reference generator refuses an existing output. Corpus tests skip without
explicit inputs, verify image/symbol hashes, and compare the resulting maps.
They do not validate independent PDB parsing, session-private GUI pages on the
real dump, GUI pool/name recovery, full plugin generators or sealed
store/cache/retry behavior. These remain required. The matrix stays at 149
partial, 46 missing and zero accepted plugins.
