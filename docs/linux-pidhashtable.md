# Linux PID index enumeration

Development preview; partial capability, not release acceptance. Native `linux.pidhashtable` maps to pinned Volatility 3 v2.28.2 `linux.pidhashtable.PIDHashTable`.

The plugin enumerates tasks independently of the active-process list. It supports x64, x86, PAE and ARM64 with matching typed symbols. Legacy kernels use `pid_hash`, `pidhash_shift`, `upid.pid_chain` and `pid.numbers`. Newer kernels use embedded `init_pid_ns.idr` with radix/XArray roots, optional `idr_base`, and typed PID task links. Namespace IDR detection takes precedence over legacy hash symbols. Unsupported layouts fail explicitly.

`OFFSET`, `PID`, `TID`, `PPID` and `COMM` preserve the pinned task view, sorted stably by TGID/TID. `decorate-comm=true` wraps kernel threads in square brackets and user threads in braces. Names truncate at NUL or the first Unicode replacement character; raw reads retain the original bytes. Duplicate task objects reached through different PID entries remain visible. The legacy reference subtracts `pid.numbers` itself even for nonzero namespace levels; task container subtraction uses the link field offset without an enum-index stride. GoMem retains these pinned coordinates rather than claiming independent namespace completeness.

## Evidence and limits

| RecordType | Meaning |
| --- | --- |
| `task` | Selected task, PID/index coordinates, identity and available creation counter |
| `task_candidate` | Rejected candidate, including no PID task, invalid TID or explicit read error |
| `index_read` | Every actual index and task read, including empty slots, parent probes and errors |
| `index_summary` | Layout, read/candidate/task/rejection counts and completion state |

Every capture records address, raw bytes, requested and captured lengths, completeness and read error. Addresses remain lossless hexadecimal values. Task identity combines image, address space, object, TID and available creation counter. Missing creation counters remain typed missing. Existing but unreadable counters fail the analysis with partial evidence. Unreadable parents, malformed symbols, cycles, repeated nodes across buckets and exhausted bounds also fail; they cannot masquerade as a complete empty inventory. Successful rows already recovered remain available. Failed tasks are not reused as successful cache entries. Cancellation and output errors terminate output.

`max-nodes=131072`, `max-tasks=1000000` and `max-buckets=65536` each accept 1..1000000. `max-nodes` counts index nodes; `max-tasks` counts PID candidates. A single XArray node may contain multiple candidates. Bucket bounds apply to the legacy hash. Results are bounded in memory for stable sorting; raw trace records stream to case storage.

## Validation

The deterministic oracle executes unmodified pinned PIDHashTable methods and PsList task-field extraction against real ISF-backed byte objects. It covers 96 cases: two pointer widths, six layouts (legacy hash, radix, XArray, pid_links, direct, empty) and eight task scenarios (normal, empty/invalid name, null parent, zero TID, absent task, duplicate task, zero real parent). Plain and decorated modes are compared. Native tests exercise 144 paging cases using x64, x86 and PAE. All five reference fields, every captured read, SQLite row seals and identical cached JSONL are checked.

Fault tests mutate actual paged fixture bytes to introduce task/parent/index holes and index cycles, check independent task preservation, and require explicit failed uncached retries. Bounds, output errors and cancellation are covered. Fuzzing mutates index and task bytes with finite traversal bounds and independently validates captured raw bytes.

On the supplied Debian 3.2 x64 image, SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`, all 316 tasks match the pinned reference on five fields in both modes. The comparison profile explicitly masks addresses to 48 bits because the reference emits masked virtual addresses while native output retains canonical addresses. Six PID candidates have no linked task. Plain mode records 6492 reads; decorated mode records 6808 (316 additional flags reads). The optional corpus test verifies the pinned manifest/output/image hashes, rereads all captures, checks ordered task output, pages through all stored seals and checks byte-identical cache reuse.

```sh
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
python3 tools/build_pidhashtable_oracle.py --check
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxPIDHash -fuzztime 10s
# Set absolute paths to local corpus and tools/reference.py output prefixes:
GOMEM_CORPUS_DIR=/path/to/corpus \
GOMEM_PIDHASH_REFERENCE=/path/to/reference \
GOMEM_PIDHASH_DECORATED_REFERENCE=/path/to/decorated-reference \
go test ./internal/engine -run TestOfficialLinuxPIDHash -count=1
```

This establishes selected-field parity on one real legacy kernel. Positive real modern IDR images, real x86/PAE, complete namespace/version/parameter coverage, damaged-image equivalence and complete renderer/export acceptance remain pending. PID-index enumeration alone does not establish hidden-process detection. See [validation measurements](linux-pidhashtable-validation.json) and [comparison mapping](diff/linux.pidhashtable.json).
