# Native TCP/IP version selection and symbol catalog

This component supplies the partial native [`windows.netscan`](windows-netscan.md)
plugin. Full version/platform acquisition acceptance remains open.

`pkg/winnet.Select` takes measured NT major/minor, debug build, pointer width,
the kernel 18363 distinguisher and, when applicable, the TCP/IP file revision.
The selection preserves the fixed baseline's exact version map and fallback:

- A debug build of 18362 becomes 18363 when the kernel distinguisher says so.
- The TCP/IP revision is consulted only for Windows 8.1 x64 build 9600. Other
  versions ignore it, even if a caller has a value available.
- An unknown build falls back to the latest entry with the same NT major/minor
  and a permitted TCP/IP revision. This can select a layout newer than the
  measured debug build; it is not a nearest-lower-build rule.
- The selected 20348 x64 profile enables the additional `TTcb` pool tag.
- Unsupported NT versions and pointer widths return explicit errors.

The selection result retains whether the tuple matched exactly and the
effective debug build. Callers must preserve fallback evidence rather than
claiming that a newer or unlisted Windows build is fully supported.

The native selector matches 99 unmodified baseline factory runs on original
byte-backed x86, PAE and x64 Intel layers. The factory reads actual KUSER/debug
structures, evaluates actual Windows metadata/type distinguishers, and scans
real UTF-16BE filename/version bytes for the Windows 8.1 TCP/IP revision.
The same runs record the actual generated pool constraints. No factory,
version accessor or file-version scanner is replaced. The generator checks
under Python 3.12 and 3.14.

```sh
python3 tools/build_windows_network_version_oracle.py --check
```

`pkg/winnet.Load` retrieves data-only ISF files from the fixed upstream commit.
All 25 catalog entries have compiled SHA256 and pointer-width pins. A cache
entry and a network download must pass the same pin, parser and width checks.
Downloads/cache reads are limited to 4 MiB. Unknown names cannot become paths
or URLs. Cache publication uses temporary files and rename; concurrent readers
accept only verified complete data. The `offline` API option never makes HTTP
requests and rejects missing, corrupt or oversized cache entries.

Tests cover successful fetch/offline replay, corrupt-cache repair, concurrent
resolution, unknown names, wrong digests, HTTP errors, oversized responses,
oversized cache files and cancellation before/during HTTP. A separate live
control fetched the pinned 19041 x64 layout from the official URL and replayed
it offline. Normal tests use a local HTTP server; the live control is optional:

```sh
GOMEM_NETWORK_FETCH=1 go test -race ./pkg/winnet \
  -run '^TestCatalogOfficialPinnedServer$' -count=1
```

The field decoder also distinguishes the allocation's source layer from its
native pointer-target layer. A physical pool allocation can refer to kernel
virtual structures. A separate nonidentity-address-space control verifies
family, TCP addresses and listener expansion; same-layer fixtures alone do not
establish this behavior.

The CLI plugin now reads version inputs, honors cache/offline settings, validates
network/owner objects and scans pools. Full acquisition/version acceptance,
custom layout overrides and complete NetStat acceptance remain open.
[Partial native NetStat traversal](windows-netstat.md) has separate controls. See the
[network validation record](windows-netscan-validation.json).
