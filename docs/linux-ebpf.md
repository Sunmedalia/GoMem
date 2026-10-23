# Linux eBPF program inventory (development preview)

`gomem analyze linux.ebpf` natively enumerates the kernel `prog_idr` with symbol-described objects. The runtime uses Go only and opens images read-only. This is a program inventory, not proof that no hidden eBPF objects exist or a malicious-program verdict.

## Layouts and baseline semantics

The fixed reference is Volatility 3 v2.28.2, commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`. Native x64/x86/PAE and ARM64 kernel layers support embedded radix/XArray IDR roots, optional `idr_base`, direct/empty roots, multilevel trees, and legacy 256-slot `idr_layer` trees. Traversal requires declared pointer/array types, aligned pointers, consistent heights, signed-integer ID bounds and no repeated nodes. Modern IDR leaves must have unit span. Tagged values remain diagnostic evidence and are never dereferenced as programs.

`Address`, `Name`, `Tag`, and `Type` are the four reference columns. Type comes from the `bpf_prog.type` enum, or `bpf_prog_aux.prog_type` only when the first field is absent. Tags retain all declared bytes as lowercase hex. Names use the declared aux byte array, truncate at NUL, and reproduce the reference utility's truncation at the first Unicode replacement character. Original bytes, decoded text, validity and truncation flags remain available.

The legacy reference computes `idr_max` with `min(INT_SIZE, layers * 8, 31)`, where `INT_SIZE` is 4, limiting its view to IDs 0–15. GoMem preserves all entries below the exclusive `cur` bound. `Selected=true` identifies the program subset used for reference comparison; higher legacy IDs remain visible with `Selected=false`. This deliberate extension is not full output equivalence.

## Evidence and failures

| RecordType | Meaning |
| --- | --- |
| `ebpf_program` | Candidate program, ID/index/slot, baseline fields and raw metadata captures |
| `idr_read` | Every actual index read, including zero slots, partial bytes and errors |
| `idr_tagged_entry` | Tagged tree entry retained without speculative dereference |
| `idr_summary` | Layout, node/entry/read/program counters and completion state |

Each raw capture records address, requested/captured byte counts, completeness and any read error. Program provenance points to its kernel object. An absent optional name/tag/type field or null aux pointer yields a typed missing value. Unknown enum values, malformed layouts, unavailable bytes, repeated nodes and exhausted bounds retain partial evidence and fail the task. A failed task is retried rather than reused as a successful cached result. Missing `prog_idr` explicitly rejects the kernel; it does not report a successful empty inventory. Cancellation and output failures terminate without further output.

`max-nodes` defaults to 131072 and `max-programs` to 1000000; each accepts 1..1000000. The latter bounds nonzero tree leaves, including tagged observations. Index-read evidence can exceed program count. Names/tags are bounded to declared byte arrays of 1..256 bytes.

## Verification

`tools/build_ebpf_oracle.py` verifies the pinned source digest, then executes the unmodified EBPF generator and real IDR/radix/XArray/program/aux ISF objects over byte-backed framework layers. It does not mock plugin or field methods. Architecture-width address masks prevent fixture-buffer length from changing pointer semantics.

The 96 cases combine 32/64-bit pointers, eight root/tree profiles and six metadata profiles. Native engine tests run the 32-bit cases through both x86 and PAE, giving 144 paging cases. All selected reference fields and all native IDs are checked. Index/metadata captures are independently reread; SQLite seals, successful cache reuse and byte-identical failed-task retries are verified. Additional tests cover missing symbols, read holes, unknown enums, malformed arrays/pointers, cycles, bounds, cancellation and output failures. The shared page-cache walker retains its existing tests plus independent-root/wrapper equivalence coverage.

The supplied Debian 3.2 x64 image (SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) has no `prog_idr`. Both engines reject it as an unsupported kernel: this is a negative control only. The local Kali 6.8.11 ARM64 smoke run completes with 14 BPF programs, 68 IDR read records and one summary. No independent ARM64 or positive-modern reference comparison is claimed.

```sh
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
python3 tools/build_ebpf_oracle.py --check
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxEBPFIDR -fuzztime 10s
```

CI checks the deterministic oracle and fuzz target. The capability stays `partial`, `accepted=false`; modern positive real images, real x86/PAE, damaged-image/version/parameter coverage and complete export equivalence remain pending. Measurements are recorded in [linux-ebpf-validation.json](linux-ebpf-validation.json).
