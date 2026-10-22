# Native Windows pool scanner (development preview)

`windows.poolscanner` exposes the shared native pool engine as an independent
plugin corresponding to Volatility 3 v2.28.2 `windows.poolscanner.PoolScanner`.
It remains **partial**. Python and Volatility are development tools only.

```sh
gomem analyze windows.poolscanner --image memory.dmp --symbols ntkrnlmp.json \
  --os windows --arch x64 --dtb 0x1000 --kernel-base 0xfffff80000000000 \
  --case ./case --format jsonl
```

The plugin scans all 15 built-in tag constraints, including protected legacy
tags. These represent atom tables, processes, threads, files, mutants, drivers,
modules, symbolic links and registry hives. The underlying engine selects the
kernel virtual layer for Windows 10 and later and physical memory for earlier
versions, using symbol/version-dependent pool classification, alignment,
optional headers, object carving and type checks.

`Offset` is the **pool header address**, preserving the official generator's
column; `ObjectOffset` is the separate recovered object address. `Type` is the
declared ISF structure name. Its upstream `Tag` column contains a dynamically
qualified symbol type, while native `Tag` retains the original four tag bytes.
`Layer` identifies the scanned address space. Process and file objects have
names; other rows preserve a typed not-applicable value.

Every source read records original layer/address, requested and captured
lengths, SHA256 and completeness. Small metadata captures retain up to 256 raw
bytes; page-table reads retain up to 4 KiB. Large scan reads retain their exact
coordinates and digest for independent rereading, avoiding repeated full-page
payload copies. Read failures remain explicit even when an upstream validity
check would skip the candidate. The final `task_summary` contains cumulative
read counts and task completeness; the shared `summary` contains scanner
candidate/skip counters. A failed task cannot become a successful cache entry.

Task defaults are 16 GiB of requested layer reads, four million read calls and
one million evidence rows. These include paging and nested metadata calls;
requests at different layers are counted separately. `max-read-bytes`,
`max-reads` and `max-rows` can adjust the bounds. Exhaustion, output failure and
cancellation stop further output and fail the task. Image access is read-only.

Validation includes the [1,440 actual header cases](windows-pool-header-reference.md)
and 36 complete unmodified official generator runs over real nonexecutive
allocations, producing 56 reference rows across 32/64-bit pre-Vista/Vista
layouts. Native tests compare structure names, header addresses, source layers,
not-applicable names and recovered object positions. A file-object integration
test checks original bytes and digests, object/header separation and names.
Failure tests cover metadata holes, every task budget, cancellation and emitter
errors. A 50,000-input fuzz run mutates pool headers, names, object metadata and
type-map slots while checking bounded output and original capture attribution.

`tools/verify_pool` independently rereads original physical/virtual source
captures and verifies row seals, image/plugin identity, lengths, digests,
raw bytes and read completeness. It does not independently establish object
validity; object recovery requires separate differential controls.

```sh
go run ./tools/verify_pool --image memory.dmp --rows results.jsonl --dtb 0x1000
```

The final-source Windows 10 19041 control recovered 8,090 objects, matching every
selected type, header address and name from the unmodified reference. Runtime
type namespaces and canonical address representations are normalized explicitly;
all native objects separately retain the expected kernel layer and symbol digest.
Independent rereading verified all 441,271 original reads and 449,363 row seals.
The task remains failed/incomplete because it recorded 5,702 failure
observations (not unique missing pages), including unavailable prototype/swap
encodings, nested reads and three name callbacks. Matching recovered rows does
not prove complete acquisition. Native symbol bytes equal the reference archive
member; the validation record includes input/output and comparison hashes.

Across 36 synthetic engine cases, sealed SQLite readback and successful cache
replay preserve byte-identical JSONL. Two failed read-budget retries per case
remain uncached. These cases add a matching PE/PDB identity independently of the
original pool allocations used by the official generator oracle.

```sh
python3 tools/diff_results.py --native results.jsonl --reference reference.json \
  --mapping docs/diff/windows.poolscanner.json --output diff.json
```

Full executive-object differential fixtures, GUI constraints,
broader Windows/version/architecture coverage, swap/prototype pages, arbitrary
malformed layouts, all renderers/exports and release performance acceptance
remain outstanding. See [validation status](windows-poolscanner-validation.json).


## Callback pool-index dependency

The shared scanner also supports the callback factory's pool-index bounds.
`tools/build_callback_pool_oracle.py` runs the actual unmodified callback
constraint factories with both original x86/x64 data-only symbol tables, and
runs the original `PoolHeaderScanner` on **1,984 byte-backed headers** across
pre-Vista/Vista, seven callback tags, minimum/maximum allocation boundaries,
eight pool types and index values 0, 1, 2 and 255. Native constraint sizes,
page masks, index endpoints and header acceptance match these observations.

The pinned scanner ignores zero-valued index endpoints: the shutdown callback
constraint `(0, 0)` does **not** require `PoolIndex == 0`. PnP callback tags
require index 1. The native scanner preserves that behavior. An absent or
nonscalar `PoolIndex` schema fails before scanning when a nonzero bound is
needed. An unreadable index retains an explicit failure rather than successful
empty output. Pipeline tests exercise accepted/rejected indices and a field
read hole, including callers without the task capture wrapper.

This is a shared-scanner dependency for `windows.callbacks`, which remains
missing until callback enumeration, decoding, attribution and end-to-end
validation are implemented. Callback tags are not added to the independent
plugin's fifteen upstream built-in tags.

```sh
python3 tools/build_callback_pool_oracle.py --check
go test -race ./internal/plugins -run '^TestCallbackPool' -count=1
```
