# Native desktop enumeration and pool scanning

`windows.desktops` and `windows.deskscan` are partial native implementations of
Volatility3 v2.28.2 at `881e970121c16f0932fb9d16fbd5fb258cbcbf75`.
Both currently require matching Windows x64 symbols and a pinned GUI layout.
No Python or Volatility code runs in the analysis engine.

```sh
gomem analyze windows.desktops --image memory.dmp --symbols kernel.json \
  --os windows --case case-001 --format jsonl
gomem analyze windows.deskscan --image memory.dmp --symbols kernel.json \
  --os windows --case case-001 --format jsonl
```

## Enumeration semantics and evidence

Both paths reuse native kernel pool parsing, pinned layout acquisition,
first-process-per-session discovery and explicit session rebinding described in
[WindowStations](windows-windowstations.md). They intentionally differ:

* `desktops` scans window stations and follows each station's original repeated
  root desktop pointer. Its station name/session come from the station being
  enumerated, even when a desktop's parent pointer names a different station.
* `deskscan` independently carves Desk allocations and derives the desktop's
  session from its parent in the scan layer. After rebinding, it requires a
  nonempty desktop name and valid parent station name/session. Free pools are
  excluded. No station-global deduplication is applied to these pool objects.

The desktop thread list is walked forward. Each thread yields its owning
process name/PID, so several threads belonging to one process produce repeated
owner rows. These duplicates are retained. The thread's process-info and
EPROCESS pointers are read in the selected session layer, including private
process-page mappings. Unreadable owners are recorded as failures while useful
later nodes remain recoverable. Null links, cycles, node exhaustion and missing
pages return an explicit failed prefix. Failure aggregation stores a bounded
count and first cause; individual read errors remain in acquisition records.

The `desktop` entity fields are Offset, WindowStation, Session, Desktop,
Process and PID. Additional fields retain the parent station, thread,
process-info and process object addresses, raw process-name/name bytes and
executive header/name-info/buffer coordinates. A missing desktop name differs
from an empty decoded name: `desktops` can retain a missing-name owner tuple,
whereas `deskscan` suppresses missing and empty desktop names as upstream does.

`gui_desktop` metadata records retain enumerated objects even when they have no
thread owners. `gui_station`, `gui_session`, `gui_symbols`, `gui_candidate` and
raw `memory_read` records remain separate from owner entities. SQLite sealing
preserves the full streamed evidence. Every read retains exact layer, offset,
requested/captured lengths, digest and completeness/error; bounded metadata,
page-table and name reads also retain bytes. Failure counts can include nested
observations and are not counts of distinct absent pages.

`max-desktops` defaults to 12 per station (0..1000000); it applies only to list
enumeration. `max-threads` defaults to 131072 per desktop (1..1000000). Shared
read/byte/row/process/session/station limits have the WindowStations defaults.
A zero desktop limit emits no enumerated desktop owners; it does not restrict
DeskScan's independent pool search. The summary's Stations counter counts the
Wind traversal path; DeskScan does not perform that station enumeration.

Read failures fail the task while preserving partial evidence. Cancellation and
output errors stop immediately. Runtime GUI symbol dependencies force fresh
execution until safe dependency revalidation before cache reuse is implemented.
An offline missing/corrupt GUI layout fails explicitly.

## Differential and robustness controls

`tools/build_desktops_oracle.py` runs the unmodified full original Desktops and
DeskScan generators: 32 controls across 16 scenarios on GUI layout 19041. Actual
pool carving, kernel and process Intel page tables, session selection, GUI
extensions, executive names and thread-list decoding are exercised. The
reference compares all six ordered fields and duplicate rows.

Controls cover duplicate owners, unreadable owners, thread cycles/unmapped
links, empty lists, missing/empty/one-character names, unavailable desktop names,
unmapped parents, different parent sessions, invalid station names, absent
sessions, free desktop pools and session-private process-name bytes. Component
oracles separately cover 12 layouts; those are not 12 complete-plugin acceptance
runs. Extra guards cover bounds, zero desktop limits, cancellation and emitter
failures before and during streaming.

32 engine cases check sealed SQLite/stream identity, original entity fields,
fresh runtime-symbol task IDs, failed-task retry and corrupt-cache rejection.
The existing 14 WindowStations engine cases also run after extracting the shared
fixture helper. A combined race run passed in 118.812s. GUI package race passed
in 25.382s; desktop-focused race passed in 14.003s. Paged pipeline read/provenance fuzz
controls passed 1042 inputs in 11.453s with a 1000-input CI budget.

```sh
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_desktops_oracle.py --check
go test -race ./internal/plugins -run '^TestDesktops' -count=1
go test -race ./internal/engine -run '^(TestDesktopsSealed|TestWindowStationsSealed)' -count=1
go test ./internal/plugins -run '^$' -fuzz '^FuzzDesktopsPagedPipeline$' -fuzztime 1000x
```

## Real Windows 10 19041 control

The native independent scans match all ordered original fields and duplicates:

| Plugin | Entity rows | Verified seals | Source reads | Captured bytes | Raw captures | Failed reads |
|---|---:|---:|---:|---:|---:|---:|
| desktops |401|193328|189402|805742504|95386|3729|
| deskscan |418|125040|124594|803962386|30578|2592|

Both tasks remain **failed/incomplete**. There are 200/1 semantic failure
observations respectively, in addition to the nested captured read counts.
Four unavailable session-ID reads at 0x8 are included. Matching recovered rows
is not proof of complete acquisition, clean objects or the absence of others.

Strict profiles [desktops](diff/windows.desktops.json) and
[deskscan](diff/windows.deskscan.json) normalize only canonical-vs-low48 address
representation and the declared missing desktop-name representation. They
report no missing/extra selected rows. Both audits verify image hash, original
reference/configuration digests, equality of the original symbol archive member,
all row seals, identical SQLite/JSONL streams, every captured source read and
all raw captures. See [hashes and validation limits](windows-desktops-validation.json).

To reproduce, retain the original `tools/reference.py` results for each plugin
with adjacent manifest/config files, acquire native JSONL, and supply the
printed native task ID to the optional audit:

```sh
GOMEM_GUI_PLUGIN=windows.deskscan \
GOMEM_GUI_IMAGE="$PWD/.cache/corpus/win-10_19041-2025_03.dmp" \
GOMEM_GUI_SYMBOLS="$PWD/.cache/corpus/symbols/windows/167FE94B5641C005AC3036212A01F8DC-1.json" \
GOMEM_GUI_CASE="$PWD/.cache/gui-desktops-validation/deskscan-native" \
GOMEM_GUI_TASK=TASK_ID \
GOMEM_GUI_WIRE="$PWD/.cache/gui-desktops-validation/deskscan-native.jsonl" \
GOMEM_GUI_REFERENCE="$PWD/.cache/gui-desktops-validation/deskscan-reference.json" \
GOMEM_GUI_AUDIT="$PWD/.cache/gui-desktops-validation/deskscan-audit.json" \
go test -race ./internal/engine -run '^TestDesktopsCorpusSealedOriginalAndReadAudit$' -count=1 -v
```

Use `windows.desktops` and its corresponding files/task ID for enumeration.
The optional real audit currently uses this sample's fixed DTB 0x6d4000 and
kernel base 0xfffff8043601f000; it skips without inputs. Full supported-version,
malformed-layout, swap/prototype-page, ARM64 virtual GUI, independent PDB,
successful cache/resume, renderer/export and performance acceptance remains
pending. The matrix is 152 partial, 43 missing and zero accepted plugins.
