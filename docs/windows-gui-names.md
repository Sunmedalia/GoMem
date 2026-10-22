# Windows GUI executive names and desktop enumeration

Development dependency against Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. No GUI plugin is registered by
this milestone. Pool discovery, complete plugin generators and sealed evidence
remain required; the capability matrix is unchanged.

## Native behavior

`wingui.Reader.ObjectName` uses the matching kernel `_OBJECT_HEADER.Body`
offset to find an executive header in the supplied session layer. It prefers a
declared `NameInfoOffset`; otherwise it reads `InfoMask` and the kernel-relative
`ObpInfoMaskToOffset` table in that same session layer. The primary kernel layer
is not substituted for the session layer. Zero displacement means no name.

The name-info `_UNICODE_STRING` follows the original short circuits: zero
length does not read maximum length or buffer; zero maximum length or a length
above maximum means no name. Reads are bounded to 65535 bytes. A nil display
string (original None) differs from a present empty string. Read faults stay
explicit, with partial raw bytes retained separately and no fabricated text.
Header underflow, schema errors and invalid reader byte counts are explicit.

UTF-16 decoding follows Python's replacement codec, including optional endian
BOMs, unpaired surrogates, odd tails and NUL truncation. It retains U+FFFD; the
GUI path does not use the unrelated utility decoder that truncates on it.
`StationInfo` requires more than one Unicode codepoint and a session below 256;
when invalid, both display name and session are absent while acquisition data
and errors remain available. An emoji alone has one codepoint.

`Desktops` preserves the pinned repeated-root `rpdeskList` traversal, including
reading the name before checking for a repeated address. It does not silently
correct this into a different linked-list algorithm. Original swallowed name
faults still yield a tuple with no name; native also returns the read error.
Schema failures, cancellation and emitter failures terminate. Caller limits
are restricted to 0..1000000, with bounded failure aggregation.

## Verification

`tools/build_gui_names_oracle.py` calls original, unmodified executive name,
station `get_info` and desktop methods with actual ISF extensions and byte
layers. 768 controls cover 12 GUI layouts, two header mechanisms and 32 cases.
Cases cover missing headers/masks/tables/string fields, zero/invalid lengths,
read holes, invalid sessions, null desktop pointers, repeated traversal,
Unicode codepoint validity and replacement decoding. Another 512 deterministic
codec vectors come from Python's actual UTF-16 codec. Native tests independently
reread captures and additionally cover partial reads, invalid byte counts,
missing schema, bounds, cancellation and emitter errors.

```sh
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_gui_names_oracle.py --check
go test -race ./pkg/wingui
go test ./pkg/wingui -run '^$' -fuzz '^FuzzGUINames$' -fuzztime 10000x
```

The complete package race run passed in 24.246 seconds; 10000 fuzz executions
passed in 1.205 seconds. CI runs the original oracle and the same fuzz budget;
`make fuzz` uses 20000 inputs. Windows/Linux package test binaries also compile.

## Real image control

The Windows 10 19041 crash image returned 13 original `windows.windowstations`
rows. Native `StationInfo`, using independently discovered session layers,
matched all 13 original-selected addresses, names and session IDs, including
unusual names returned by the original. 91 session reads (974 bytes) were
independently reread with zero name-acquisition faults. Session discovery still
reports the four unavailable session-ID reads documented in
[session discovery](windows-gui-sessions.md); this is not a clean full scan.

Both sides use the same kernel ISF (its archive member digest was independently
checked), and GUI layout `gui-win10-19041-x64` is checked against the compiled
catalog pin. This control starts from original pool-selected addresses: it does
**not** establish native pool coverage, station ordering, complete desktop/thread
recovery, sealed storage, retry, cache correctness or independent PDB parity.
Full hashes and limits are recorded in
[the validation record](windows-gui-names-validation.json).

Generate the original rows with `tools/reference.py` using the pinned source,
image and matching symbol archive, plugin `windows.windowstations`, output
`.cache/gui-names-validation/windowstations-reference.json`. Its adjacent
manifest must be retained. Run the session corpus command in
[session discovery](windows-gui-sessions.md) with these additional variables:

```sh
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75"
GOMEM_GUI_NAMES_REFERENCE="$PWD/.cache/gui-names-validation/windowstations-reference.json"
GOMEM_GUI_NAMES_AUDIT="$PWD/.cache/gui-names-validation/native-audit.json"
```

Export the variables or prefix the test invocation. The optional extension
requires positive original rows, verifies manifest baseline/image/output hashes,
and compares every supplied row. Without explicit corpus inputs no real-image
acceptance is established.
