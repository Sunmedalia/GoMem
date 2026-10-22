# Conhost layout selection and acquisition

Development support for `windows.cmdscan` / `windows.consoles`, against Volatility
3 v2.28.2 commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`.
Neither plugin is registered by this component milestone. The capability matrix
remains 195 plugins: 147 partial, 48 missing, zero accepted.

## Native behavior

`winconsole.VersionFromMemory` reads the kernel debug block's MinorVersion and
KUSER's NT major/minor version through the supplied Intel address space. It uses
the symbol-relative debug address plus kernel base, checks arithmetic, and does
not replace missing bytes with symbol-file PE metadata. x86/PAE kernel reads are
supported, but the fixed baseline has no x86 conhost layout selections.

`Version.NeedsRevision` requests conhost revision inspection for exact OS builds
17763, 20348 and 22621 on x64. `Select` implements the baseline's exact key and
fallback ordering: same NT major/minor, no greater OS build, no greater measured
revision, sorted first by build then revision. Other builds ignore revision,
matching the original decision to skip inspection. Returned metadata preserves
the effective revision, matched build/revision and whether the match is exact.

Pinned details include the 20348 revision 2520 alias to the 2461 layout and the
25398 alias to the 22000 layout. The bundled 25398 file is still in the catalog,
but automatic selection never chooses it. A measured revision of zero on an
ambiguous build can select an older layout or reject the OS, depending on the
available keys. This fallback must remain visible to investigators.

`Load` acquires one of 11 explicitly named, SHA-256-pinned, data-only conhost ISFs
from the fixed upstream commit or a verified local cache. It returns original
bytes, original digest, URL, cache path and the history projection table. Unknown
names and path traversal are rejected before network access. HTTP failures,
size bounds, digest mismatches, offline cache misses and cancellation are
explicit errors. Writes use complete temporary files, then rename. On Windows,
an invalid regular cache entry can be removed only after its replacement is
verified; concurrent resolvers accept an identical verified winner. A transient
cache miss during repair is possible, but partially written symbol data is never
published. No Python or executable extensions are downloaded at runtime.

The loaded native table remains the four-type history projection documented in
[the command/history reader](windows-console-history.md). Its digest differs
from the original file hash; both are available and must be retained when this
component is integrated into evidence and cache provenance.

## Verification and remaining work

`tools/build_console_version_oracle.py` executes the unmodified
`Consoles.determine_conhost_version` with real Intel x86/PAE/x64 translations,
kernel/KUSER objects and physical version markers. All 663 controls agree with
the Go selector. Controls cover revision boundaries, unknown builds, revision
inspection being skipped, aliases, fallback ordering and unsupported systems.
Ambiguous builds exercise the original failed PE access and physical fallback,
with deliberately different file/product revisions. They do not validate a
successful direct conhost PE reconstruction.

Go tests also perform native version measurements on the same hardware-backed
memory templates, including cancellation, kernel address overflow and missing
KUSER bytes. Original file tests validate all 11 hashes and four concurrent
resolvers per file, offline reuse, corrupt-cache rejection and reacquisition.
The fixture retains exact original bytes so these checks run on all native CI
platforms; the optional baseline environment additionally checks the fixture
against the source checkout. Run them with:

```sh
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" go test -race ./pkg/winconsole
uv run --no-project --python 3.12 --with pefile==2024.8.26 python tools/build_console_version_oracle.py --check
```

`FuzzConsoleHistoryLayout` mutates complete layout documents and exercises the
resulting projected table through text, count and bucket reads under strict
bounds. The local 10,000-run fuzz control passes; CI runs the same budget.

A manual real-image control on the Windows 10 19041 crash dump (SHA-256
`ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`),
with DTB `0x6d4000` and kernel base `0xfffff8043601f000`, measured NT 10.0 build
19041. Both native reads and the original complete selector chose
`consoles-win10-19041-x64`; no conhost revision inspection is required for this
build. Both used the same kernel ISF, so this does not validate independent PDB
parsing. It also does not validate conhost discovery or command recovery. See
[the validation record](windows-console-layout-validation.json).

Full `make check`, matrix, package tests with original catalog data, local build
and offline doctor pass. These are component checks. Process discovery,
conhost/VAD identification, direct PE revision acquisition, physical fallback
integration, registry history settings, byte-pattern candidate scanning,
property-tree evidence, task caching/retry and complete CmdScan generator parity
remain to be integrated. Screen and console enumeration remain separate work.
