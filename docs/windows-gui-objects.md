# Windows GUI station, session and thread objects

Development dependency against Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`, using the
[pinned GUI layouts](windows-gui-layout.md). No GUI plugin is registered or
accepted by this component milestone.

## Native reader

`wingui.Reader` reads station/desktop session IDs, desktop parent stations,
station traversal and desktop thread owners in an explicitly supplied session
layer. GUI fields use the selected four-type layout; `_LIST_ENTRY` and
`_EPROCESS` fields use matching external kernel symbols in that same layer.
Callers must discover/select the correct session layer and record its identity.
A recording layer can retain every scalar, pointer, list readability and string
read. `ThreadOwner` also retains the original process-name bytes and both owner
addresses, independently of its displayed name and PID.

The native reader preserves these observed original behaviors:

- A station is valid when its readable unsigned session ID is below 256.
- A desktop follows its parent and uses that station's session ID. A null parent
  pointer still constructs an object at address zero; when its session field is
  mapped and zero, the original considers the desktop valid. A null pointer is
  therefore not automatically converted to absent data.
- `traverse` repeatedly reads the **original root's** next pointer, rather than
  advancing along a linked chain. A self target can yield the root twice and a
  null target can yield zero. The bound counts extra stations: zero emits just
  the root and one can emit root plus one target. Filtering names, session
  validity and global duplicates belongs to the outer plugin.
- Thread lists require the full target kernel list entry to be readable and the
  container's first byte to be mapped. Blink contents are not compared; a wrong
  but readable backlink does not prevent enumeration. Sentinel and previously
  seen nodes stop traversal. A non-sentinel cycle is additionally reported as a
  native error, with the already emitted rows preserved.
- Each thread follows `ppi -> Process` before reading the kernel process name
  and PID. An unreadable owner is skipped while later independent nodes remain
  available. Names use Python-compatible UTF-8 decoding, then stop at the first
  NUL or U+FFFD, retaining the full raw input separately.

Unlike the original's silent missing-page/list stops, native faults return
explicit errors alongside the successfully emitted prefix. Station/session
failures preserve unavailable values instead of returning a fabricated zero.
Node bounds, cancellation and emitter failures are terminal. Thread bounds count
all candidate nodes, including owners that could not be read. Names are bounded
to 256 bytes, and list/node bounds to 1,000,000; exhausting a thread budget is an
error. A nil callback or missing layout/layer/kernel table is rejected.

## Verification and remaining integration

`tools/build_gui_object_oracle.py` runs unmodified GUI extension and kernel
`LIST_ENTRY` methods on real upstream intermediate symbol tables and byte-backed
objects. All **384 controls** (32 scenarios across 12 original layouts) compare
session values, validity, parent addresses, station order/duplicates and thread
address/name/PID rows. Controls cover session boundaries, null/self pointers,
cycles, head/link/container/owner/name/PID holes, a hole after a name's NUL,
incorrect backlinks, UTF-8 replacement and multibyte names. Original swallowed
faults agree on rows, while native checks require visible errors.

Native tests additionally verify bounded prefixes, cancellation before and
during streaming, emitter termination, absent/invalid kernel types, overflow
and equality of successful recorded reads to the original fixture bytes.
`FuzzGUIObjects` mutates pointers, memory and holes with strict read/node budgets;
10,000 local executions passed. CI regenerates the oracle and runs the package
race suite and mutation budget. These steps must finish remotely before remote
success can be claimed.

```sh
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_gui_object_oracle.py --check
go test -race ./pkg/wingui
go test ./pkg/wingui -run '^$' -fuzz '^FuzzGUIObjects$' -fuzztime 10000x
```

This milestone does not discover session address spaces, scan GUI pool objects,
resolve station/desktop object-header names, enumerate desktop names/windows,
or run complete WindowStations/Desktops/DeskScan/Windows generators. It has no
translated or real-image recovery control and no sealed store/cache/retry
integration. In particular, fragmented translated process-name acquisition is
not established by the byte-backed controls. Those remain required before
claiming plugin parity or release acceptance. The 195-plugin matrix stays at
149 partial, 46 missing, zero accepted.

Machine-readable scope and checks: [validation record](windows-gui-objects-validation.json).

The subsequent [session-map producer](windows-gui-sessions.md) discovers native
process address spaces. GUI pool and name integration remains pending.
