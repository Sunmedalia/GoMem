# Linux physical socket scanning (development preview)

`gomem analyze linux.sockscan` scans physical memory for symbol-resolved socket destructor and file-operation pointers. It uses native Go, read-only image access, and Intel x64/x86/PAE kernel translation. Results are socket candidates, including stale or unknown objects; they do not establish that a socket is live or that an image contains no hidden sockets.

```sh
bin/gomem analyze linux.sockscan --image memory.raw --symbols kernel.json --case ./case-001 --offline --format jsonl
```

## Layers and baseline behavior

The reference is Volatility 3 v2.28.2, commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`. The scan uses `socket_file_ops`, `sockfs_dentry_operations`, and five socket destructor symbols when available. If none exist, analysis fails explicitly. Physical roots and embedded objects stay in their physical data layer; dereferenced kernel pointers use the native kernel layer. File candidates follow dentry/inode/socket pointers and translate the resulting socket address back to a physical root. Subtype casts retain the exact root address.

The implementation covers UNIX, INET/INET6, NETLINK, PACKET, VSOCK, Bluetooth HCI/L2CAP/SCO/RFCOMM and XDP handlers, plus legacy/classic/eBPF filter metadata. Missing optional fields differ from malformed layouts and failed reads. Unknown family/type values remain visible with raw values; they are not classified as valid live sockets.

Pinned ordering, filtering and deduplication are preserved: the file branch overrides a direct branch for a shared needle; file-only candidates share the upstream `None` dedup key; the first constructible object reserves its key before extraction; direct candidates use physical offsets. Consequently two rows may refer to one physical socket. Empty endpoint filtering retains the upstream repeated-source check. UNIX names truncate at NUL or the first Unicode replacement character; original acquisition bytes remain evidence.

Two IPv6 reference issues require separate treatment. The upstream network extension compares against the host's `socket.AF_INET6` (30 on macOS, 10 on Linux), so the deterministic oracle must run on Linux. Separately, pointer-derived IPv6 addresses are read through the original physical root layer upstream. GoMem defaults to the native pointer target layer. `--param baseline-ipv6=true` reproduces that physical-layer read for comparison, while preserving its actual errors. It does not convert unreadable addresses into clean nulls.

## Bounds and evidence

| Parameter | Default | Allowed range |
| --- | --- | --- |
| `baseline-ipv6` | `false` | boolean |
| `max-candidates` | 1000000 | 1..1000000 |
| `max-scan-bytes` | 1099511627776 | 1..17592186044416 |
| `max-bytes` | 268435456 | 1..1073741824 object-read bytes |
| `max-nodes` | 131072 | 1..1000000 per device/namespace list |

Physical scanning uses bounded 1 MiB chunks with pointer overlap across adjacent ranges, never across holes. Every byte position is considered, including unaligned pointers. Physically cast socket subtypes assume the relevant object bytes are physically contiguous, matching the baseline; virtual contiguity alone does not establish this condition.

| RecordType | Meaning |
| --- | --- |
| `socket` | Decoded candidate and ten reference display fields |
| `socket_candidate` | Suppressed, rejected, duplicate or unreadable candidate |
| `socket_read` | Actual object read: layer, address, raw bytes, requested/captured lengths, completeness, error and read index |
| `socket_scan_read` | Physical chunk acquisition, lengths, completeness and SHA256 |
| `socket_layout_error` | Malformed optional layout, distinct from an absent field |
| `socket_scan_summary` | Scan, candidate, acquisition and completion counters |

Root `FieldEvidence` records matched pointer bytes, symbols, root/decoded type, data/native layers, and `FirstReadIndex`/`ReadCount` linking object acquisitions. Scan chunks retain digests rather than copying the whole image into the case. Null-pointer rejection is explicit and is not a read failure. Actual read errors, invalid layouts, scan holes and exhausted bounds fail the task while retaining partial evidence. Cancellation/output errors stop further work. Failed tasks are retried rather than reused as successful cache entries. `CandidateFailureEvents` counts both acquisition and candidate failure events; it is not a unique-error count. `PhysicalScanComplete=true` does not imply `Completed=true`.

## Validation

The Linux-only oracle executes unmodified upstream Sockscan/SockHandlers and real ISF-backed extension objects over actual Intel page tables, with physically distinct pointer targets. Its 56 cases cover 28 layouts/scenarios at two pointer widths; native tests exercise 84 paging combinations and six additional IPv6 comparison profiles. Captures are independently reread, SQLite seals verified, and successful cache output compared byte-for-byte. Fault tests inject short reads at each normal acquisition occurrence, cancellation/output errors at each emission boundary, malformed layouts, range holes/overlaps/overflow and exhausted bounds. CI checks the oracle and fuzz target.

The supplied Debian 3.2 x64 image (512 MiB, SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) was compared with a Linux Python 3.12 reference. The comparison profile produces 404 rows, with all ten display fields and order matching the reference. They represent 403 distinct physical offsets, including six unknown-family candidates. Its 616 actual object-read failures remain evidence, and the task fails.

The default native-layer profile produces 478 rows, including 74 additional IPv6 candidates. All 86 IPv6 rows' endpoints were independently reread through their symbol-described pointers. It retains 444 object-read failures and also fails. Both profiles inspect 1946 candidates, capture 9925 object reads and 512 scan chunks, and complete the physical scan. Failed retries retain evidence and do not reuse a success cache. The structured diff deliberately retains error-versus-null differences: 392 rows match; the comparison profile has 12 missing/12 extra rows, and the default has 12 missing/86 extra rows. Display-value equality alone is not evidence equivalence.

```sh
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
# Linux Python 3.12, with the pinned baseline available:
python3 tools/build_sockscan_oracle.py --check
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxSockscan -fuzztime 10s
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_SOCKSCAN_REFERENCE="$PWD/.cache/sockscan-validation/reference-linux312" \
go test ./internal/engine -run '^TestOfficialLinuxSockscan$' -count=1 -v
```

This capability remains `partial`, `accepted=false`. Modern positive real images, real x86/PAE, broader version/corruption/parameter coverage and complete export equivalence are pending. The supplied Kali ARM64 image cannot validate this Intel virtual-memory plugin. See [validation measurements](linux-sockscan-validation.json) and the [strict field mapping](diff/linux.sockscan.json).
