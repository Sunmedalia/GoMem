# Native Windows TCP/IP index traversal

`windows.netstat` is a **partial development preview** of the pinned Volatility
3 v2.28.2 `windows.netstat.NetStat`. It follows live TCP/IP indexes independently
of pool carving; recovered candidates do not prove complete or live coverage.

```sh
bin/gomem analyze windows.netstat --image memory.dmp --case ./case-001 \
  --symbols kernel.json --format jsonl
```

The plugin selects the same SHA-pinned network layout as
[`windows.netscan`](windows-netscan.md), then finds the exact `tcpip.sys` loaded
module, acquires its matching `tcpip.pdb` through the native provider and retains
both driver symbol/source hashes. Missing driver symbols are explicit errors,
not successful empty results. A verified symbol table can still be used when
its acquisition retained source page failures; those failures remain evidence
and fail task completeness. The case remains read-only with respect to images.

Traversal order is partitions, TCP listener ports, then UDP ports. The partition
count is the original one-byte value. Hash slots use two-pointer alignment,
exclude self-address sentinels and preserve repeated entities. Port bitmaps use
byte-wise reads and least-significant-bit order; port zero is skipped. Both
direct `UdpPortPool`/`TcpPortPool` and newer compartment chains are supported.
Assignment entries and `Next` links clear the original low two pointer bits.
Container offsets, array strides and pointer targets are checked independently.
Network schemas keep external `nt_symbols!` types separate from kernel symbols,
including the external aggregate's own base types.

Actual unreadable bytes, missing/wrong symbols, container underflow, pointer
arithmetic overflow, chain cycles, oversized hashes/bitmaps and resource limits
fail coverage explicitly. The baseline silently skips several such cases;
GoMem preserves readable independent entities plus the error. It never turns
failed reads into clean absence. Hashes are bounded at 4,096 slots and bitmaps
at 81,920 bytes. `max-nodes` bounds all partition/hash/bitmap/chain steps (default
one million, maximum 16,777,216). Shared read-byte/read-count/output bounds and
cancellation also apply. Emitter failures stop traversal. Each network record
retains its index route/port, source coordinates, matching symbol digests and
the same owner identity/time/typed-error model as NetScan.

The plugin declares external symbols, so the engine executes it fresh rather
than replaying a success without revalidating driver dependencies. Successful
cache reuse remains pending; it is not advertised as complete.

## Controls

`tools/build_netstat_index_oracle.py` runs actual unmodified
`NetStat.list_sockets` and all its traversal helpers on original byte-backed
layouts. It does not replace field readers, pointer decoding, bitmap parsing,
partition parsing or chain traversal. There are **256 controls** across 16
applicable layouts, direct/compartment pools and eight scenarios: normal,
empty, duplicate entity, missing bitmap, missing hash, oversized hash,
oversized bitmap and zero partitions. Native entry addresses, types and order
match. Missing bytes remain failed; oversized indexes preserve the same other
entities but fail explicitly. Nine other shipped schemas lack one or more
required traversal fields; the oracle records their exact missing fields.
Loading a schema is not evidence that NetStat applies to it.

Native x86/PAE/x64 plugin controls combine independently referenced version,
network object and index bytes, retain all five normal entities and verify
bounds, cancellation, emitter stop, unavailable symbols and usable symbols with
partial acquisition. The module list is actual typed memory; only the matching
PDB provider is injected at the acquisition boundary. Separate complete-generator and native-provider controls are described below.
Additional mutation
controls cover cycles, underflow, corrupt symbols, width mismatch and overflow.
A 10,000-input traversal fuzz run passes with finite step/output bounds.

`tools/build_netstat_oracle.py` exercises the actual complete upstream generator,
including resident RSDS scanning and the official SQLite symbol lookup. It uses
48 byte-backed allocations across x86/PAE/x64, two address families and eight
scenarios, each with both corrupt modes: **96 runs**. Ninety runs match all ten
columns. In six missing-family/corrupt-mode runs, the baseline raises `TypeError`
while formatting a debug message before yielding. GoMem instead preserves two
TCP endpoint rows with typed errors and fails completeness; this difference is
explicitly tested, not counted as parity. The reference cache is preseeded with
a matching data-only driver ISF; this does not establish PDB conversion parity.

A separate engine test uses the actual native module PDB provider, resident
RSDS and verified local symbol index, without an injected provider. All three
architectures retain five normal rows and verify sealed SQLite readback, fresh
execution for external symbols and two failed retries without reuse.

```sh
python3 tools/build_netstat_oracle.py --check
python3 tools/build_netstat_index_oracle.py --check
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" \
  go test -race ./pkg/winnet -count=1
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" \
  go test -race ./internal/plugins -run '^TestNetStat' -count=1
```

Tests needing original schemas skip without that environment variable. CI sets
it after baseline fetch. A skipped optional control is not acceptance.

## Real Windows 10 control

The initial reference lacked matching driver symbols and returned no rows with
an error. This is an unsupported negative control, not positive parity. The
native provider recovered GUID `822833E2F09280241D136E5E1F087784`, age 1, from
resident driver bytes and obtained the matching PDB. Supplying its native
converted ISF to the **unmodified reference** yielded **74 rows**: 30 TCPv4,
10 TCPv6, 25 UDPv4 and 9 UDPv6. Native default output matches all ten upstream
columns under [the explicit profile](diff/windows.netstat.json), including
multiset duplicates and low-48-bit address normalization. This proves traversal
and selected result equality with the same symbols, not independent PDB parser
parity.

An independent verifier checks **45,502 original source reads and 45,594 sealed
rows**. The native task retains **267 failure observations**, including driver
scan, nested reads and callbacks, not unique missing pages. It stays
failed/incomplete. With `include-corrupt=true`, all **88 rows** match the same
ten columns; an independent audit verifies **45,276 reads and 45,368 sealed
rows**, with **295 failure observations**. SQLite JSONL export preserves all
45,594 default-mode rows. Positive/normal corpus breadth, additional Windows
versions, real x86/PAE, PDB dependency cache, timeline integration, full
renderer/export acceptance, performance and release acceptance remain open.

See [machine-readable controls](windows-netstat-validation.json). Images,
PDBs, cases, output and manifests remain ignored under `.cache/netstat-validation`.
