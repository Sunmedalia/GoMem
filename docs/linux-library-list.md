# Linux dynamic-linker library enumeration

`linux.library_list` is a native Go implementation of the locked `linux.library_list.LibraryList` capability. This is a development preview, not full platform acceptance.

```sh
bin/gomem analyze linux.library_list --image memory.raw --symbols kernel.json --case ./case-001 --offline --format jsonl
bin/gomem analyze linux.library_list --image memory.raw --symbols kernel.json --case ./case-001 --offline --param pids=100,200
```

The four baseline columns are `Name`, `Pid`, `LoadAddress`, and `Path`. Select only `RecordType=library` for upstream row comparisons: `library_scan` records retain per-VMA observations, and `library_error` retains acquisition/traversal or name failures. These records are never libraries or a claim that no library exists.

## Algorithm and compatibility

Tasks use the shared active-task enumeration, with an optional `pids` filter. VMA enumeration uses declared linked-list or Maple Tree layouts with owner, interval and overlap validation. Kernel threads with null `mm` are skipped. Each readable VMA start is checked for ELF magic; unavailable signatures are errors, not non-ELF observations.

The parser reads ELF32/ELF64 program headers at their class-specific fixed structure sizes, as the pinned implementation does. It follows `PT_DYNAMIC` and up to 256 dynamic entries per segment. `ET_DYN` dynamic addresses use VMA start plus `p_vaddr`; other types use `p_vaddr` directly. This intentionally follows the baseline rather than inferring an alternative load bias from PT_LOAD segments. Runtime `d_ptr` is already absolute and is not rebased again.

Only `DT_PLTGOT` supplies a link map. Its second entry is addressed using the ELF class width; the pointer value is read using the kernel pointer width, including the fixed baseline's ELF32/64-bit-kernel behavior. `DT_DEBUG` is not a fallback. Link-map records use ELF-class widths. Traversal follows `l_next`; `l_prev` and `l_ld` remain in the captured record. Null load addresses and null name pointers are skipped. A per-VMA object set prevents repeated traversal across GOT roots. A per-process load-address set performs deduplication **before** name reading, so an empty or unreadable first name is not replaced by a later duplicate.

Names require an exact 256-byte read, even when a NUL appears earlier. A NUL terminates the displayed name; absent NUL retains all 256 bytes. Python-compatible UTF-8 replacement decoding preserves the original name bytes separately. Empty names do not produce library rows. An unreadable name produces a diagnostic candidate with the available load/object coordinates and partial bytes; it is not silently presented as a valid path.

Native safety bounds are explicit:

| Parameter / bound | Default / limit |
| --- | --- |
| `max-nodes` | 131072 task and per-mm VMA traversal bound |
| `max-regions` | 1000000 total VMA bound; range 1..1000000 |
| `max-link-maps` | 131072 total object reads; range 1..1000000 |
| ELF program headers | 4096, with table offset at most 16 MiB |
| Dynamic entries | 256 per segment, 4096 total per VMA |

Cycles, unavailable pages, invalid ELF class/byte order, missing DT_NULL and exhausted bounds fail the task while retaining prior evidence. Additional tasks/VMAs continue when their evidence remains available. Cancellation and output errors terminate promptly. Failed tasks are retried rather than cached as successful results.

## Evidence and visibility limits

Each library retains process object, PID, creation counter/state, stable process identity, process layer, VMA object/start/end, link-map object and load address. The library row's provenance points to the link map in the process layer. Raw `FieldEvidence` captures the ELF header, matching program header, dynamic entry, GOT pointer, link map and the entire requested name read, plus kernel VMA, `mm` and `pgd` captures. Each capture retains address, requested/captured byte counts, completeness and read errors. Scan rows preserve signatures, parsed header/dynamic/GOT captures, read/duplicate counters and `Completed`.

This is a loader view, not an exhaustive mapped-library or hidden-library detector. Static executables, resolved/overwritten GOT state, other loader namespaces, acquisition gaps and corrupted chains can limit it. It does not substitute filesystem mapping paths for unavailable loader names. The reader accepts x64/x86/PAE and little-endian ARM64 process address spaces. A local Kali ARM64 PID 1 smoke run emitted 110 library-scan records, then failed on 87 unmapped link-map reads; complete modern-kernel, real 32-bit/compat and damaged-image acceptance remains pending.

## Validation

The pinned-source byte oracle executes real Volatility ELF objects over byte-backed framework layers and actual `LibraryList` filtering/deduplication; only task/VMA boundaries are mocked. Thirty cases cover ELF32/64, ET_EXEC/ET_DYN, empty and unavailable first names, repeated loads and dynamic entries, cycles, zero pointers, DT_DEBUG-only negatives and ELF32/kernel64 GOT-pointer behavior. The byte-backed layer retains architecture-width pointer masking instead of deriving a short mask from the fixture buffer length.

Native synthetic engine tests cover x64/x86/PAE, list/dense/range Maple VMAs, process filters, bounds, partial failures, cancellation/output errors, SQLite evidence seals and byte-identical cached/retried JSONL. Parser tests independently compare original capture bytes, and fuzzing targets malformed byte buffers.

Debian 3.2 x64 image SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`: all **2673** readable library rows match the four fixed upstream fields. Native additionally retains 14045 VMA scans and 29 unreadable-name candidates. The task fails due acquisition gaps; matching readable rows does not establish complete memory coverage. The optional corpus test independently reread 16038 process-space captures and 8019 kernel captures, then verified a failed-task retry produced byte-identical sealed JSONL without cache reuse (381.16 seconds under the race detector).

```sh
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
python3 tools/build_library_list_oracle.py --check
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxLibraryList -fuzztime 10s
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_LIBRARY_LIST_REFERENCE="$PWD/.cache/library-list-validation/reference" \
go test -race ./internal/engine -run TestOfficialLinuxLibraryList -count=1 -v
```

The matrix remains `partial`, `accepted=false`; no full-version equivalence is claimed. Machine-readable measurements are in [linux-library-list-validation.json](linux-library-list-validation.json).
