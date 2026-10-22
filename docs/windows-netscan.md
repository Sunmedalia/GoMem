# Native Windows network pool acquisition

`windows.netscan` is a **partial development-preview implementation** of the
fixed Volatility 3 v2.28.2 `windows.netscan.NetScan`. `windows.netstat` remains
missing. Matching recovered rows does not certify complete acquisition.

```sh
bin/gomem analyze windows.netscan --image memory.dmp --case ./case-001 \
  --symbols kernel.json --format jsonl
bin/gomem analyze windows.netscan --image memory.dmp --case ./case-001 \
  --symbols kernel.json --param include-corrupt=true --format jsonl
```

The plugin reads KUSER and debug version structures and the kernel's PE/type
18363 distinguisher. Windows 8.1 x64 additionally uses the native TCP/IP file
version scan. The measured tuple selects a SHA-pinned data-only network ISF
from the fixed upstream commit. Downloads and cached data have identical digest,
width, parser and size checks; `--offline` forbids HTTP. The network cache uses
the explicit `--symbol-cache` root's `network-symbols` subdirectory, or the OS
user cache when that root is unspecified. The selected schema bytes, digest,
source URL, measured inputs and exact/fallback decision become case evidence.
See [catalog behavior](windows-network-catalog.md).

Native pool constraints cover `TcpL`, `TcpE`, `UdpA`, and the extra `TTcb` tag
for the selected 20348 x64 layout. Allocation size filtering uses original ISF
declared sizes; field reads retain independently checked extents even when a
shipped layout places members outside its declared allocation size. Older
Windows pool allocations are scanned physically; their pointer targets are
resolved in kernel virtual memory. Windows 10 allocations are scanned in the
kernel layer. No Python or Volatility executes in the runtime.

Network validity is separate from process attribution. TCP state/family and
the baseline's conditional raw owner PID check are preserved. A readable local
address permits an invalid owner; an unavailable local address can still pass
with a raw owner PID in 1..65535. Owner PID/name attribution uses native
`EPROCESS` validity checks. Process identity includes the image, kernel layer,
object address, PID and available creation counter. Raw creation counters are
retained alongside UTC seconds or typed absent reasons. Listener/UDP wildcard
and dual-stack expansion retain the baseline's layout-specific behavior.
`include-corrupt=true` bypasses network validity, labels that choice and keeps
unreadable fields and unknown states explicit.

Every allocation, pointer-target and page-table read retains original source
coordinates, requested/captured lengths, SHA256, completeness and any error.
Small metadata reads retain bytes; large scan reads retain digests. Rejected
candidates are separate evidence. A final task summary records candidates,
rejections, output rows, read failures and completeness. Actual source failures
fail the task even when the baseline skips them, so they cannot become a
successful cached empty scan. Unknown state alone is semantic corruption, not a
source read error. Cancellation, emitter failure and finite read/byte/row bounds
stop execution. Defaults are 16 GiB requested bytes, four million reads and one
million evidence rows; these include all proof records, not only network rows.

## Validation

- 25 original network layouts and 1,200 actual byte-backed extension-method
  observations match native selected validity, owner PID/name, creation time,
  ports, addresses, state and socket expansion, including typed absence.
- 99 actual x86/PAE/x64 version factories match measured native selection and
  every pool constraint's tag, type, declared minimum and page mask.
- 144 real paged synthetic allocations produce 288 **complete unmodified
  upstream NetScan generator** runs: all three architectures, all three object
  types, both address families, eight scenarios and both corrupt modes.
  Native acquisition matches all ten output columns and source-unavailability
  distinctions. Original upstream methods are not replaced. The reference
  separately records failed physical reads and actual failed validity checks;
  pointer validation can reject an address before issuing a read.
- Nine additional native acquisition controls independently re-read captured
  bytes/digests. Bounds, cancellation, emitter stop, semantic corruption and
  missing pages retain their distinct outcomes. A deliberately unavailable
  pointer is beyond the fixture's physical extent, avoiding accidental readable
  zero-filled memory.
- x86/PAE/x64 engine controls verify sealed SQLite readback, byte-identical
  successful cache replay and two failed retries without successful reuse.
- A 10,000-input bounded acquisition fuzz run passes, independently checking
  original bytes/digests and cancellation. The existing layout fuzz target
  remains registered separately.

```sh
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" \
  go test -race ./internal/plugins -run '^TestNetwork' -count=1
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" \
  go test -race ./internal/engine -run '^TestWindowsNetScanStorageCacheAndFailedRetry$' -count=1
python3 tools/build_netscan_oracle.py --check
```

Original-layout controls require the environment variable. CI sets it after
fetching the pinned source; a skipped local control is not acceptance.

## Real Windows 10 control

On the official Windows 10 19041 image, the default mode recovers **108 rows**
(40 TCPv4, 10 TCPv6, 42 UDPv4, 16 UDPv6), matching all ten baseline columns under
[the explicit profile](diff/windows.netscan.json). Canonical native addresses
are normalized to the reference's low 48 bits. An independent source verifier
checks **106,321 original reads and 106,483 sealed rows**. SQLite-backed JSONL
export preserves every original row identically inside its evidence wrapper.
There are **115 failure observations**, including nested reads and callbacks;
these are not 115 unique missing pages. The task is failed/incomplete.

Corrupt mode recovers the same **159 entities and selected values/absence** as
the baseline, but the strict evidence comparison correctly reports differences
on **51 rows**: 49 local-address errors, three remote-address errors, three
invalid-state reasons and 34 pairs of owner PID/name read errors are retained where the reference outputs null. No failed
cell is silently normalized into a clean absence in the strict profile. These
are 123 cell differences across 51 rows. All other selected fields match.
An independent verifier checks **107,376 reads and 107,538 sealed rows**;
261 failure observations retain failed/incomplete task status. The additional
rows are corrupt candidates, not validated active connections.

See [machine-readable evidence](windows-netscan-validation.json). Dumps, cases,
raw outputs and manifests remain ignored under `.cache/netscan-validation`.

Complete acquisition across supported Windows versions, broad real positive
and normal controls, real x86/PAE images, swap/prototype resolution, NetStat
traversal, network timeline integration and full renderer/export/performance
acceptance remain open. Synthetic generator controls use Windows 7 layouts;
other layouts have object/factory controls and one real Windows 10 control.
