# Linux bash history (development preview)

`linux.bash` recovers `hist_entry` records from the heaps of tasks named `bash`, `sh`, or `dash`. It corresponds to Volatility 3 v2.28.2 `linux.bash.Bash` on Intel kernels. A recovered command is history evidence, not a judgment about the command. This capability remains partial.

```sh
bin/gomem analyze linux.bash --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

The heap selection uses verified VMA boundaries and the pinned predicate `vma.start <= mm.brk && vma.end >= mm.start_brk`. It scans the whole selected VMA, intersected with resident page mappings. A merged page-table run cannot extend the scan into unrelated VMAs. Each shell has a `coverage` record with selected, mapped and unmapped byte counts. Unmapped bytes or candidate read errors emit diagnostics and fail the task; results already recovered remain evidence, and failed tasks are not cache hits. No swap recovery is claimed.

The first scan finds `#` marker addresses. Pointer searches use batches of up to 4096 markers, with at most one million markers and one million candidate entries per shell. Unaligned timestamp pointers are valid. Subtracting the pointer width (4 or 8 bytes) locates the candidate's line pointer. The pinned structure is 12 bytes on 32-bit and 24 bytes on 64-bit; the two dereferenced pointer fields are captured. Valid records have a nonempty bounded command and a timestamp beginning with `#`, at least 10 characters long, followed by a decimal integer. ASCII signs, whitespace, separators between digits, and arbitrarily large integers are supported. Unicode decimal digits remain a compatibility gap. Times at or below zero or outside the supported datetime range remain explicitly unavailable, while the history record and raw timestamp are retained.

Histories sort stably by numeric Unix second after restoring timestamp-pointer hit address order across batches. Evidence includes the line/timestamp pointer bytes, bounded raw command and timestamp reads, capture lengths, completion flags and read errors. Reads stop at page boundaries so a terminated string does not demand the next page. Process layer identities combine image, kernel layer, task address, PID and available creation time. Output failures and cancellation stop immediately.

Default task/VMA traversal is bounded by `max-nodes=131072`, retained histories by `max-entries=100000`, and selected heap bytes by `max-heap-bytes=1073741824`. Exceeding a bound fails the task explicitly. Limits are GoMem additions, not upstream parameters.

The Debian 3.2 x64 image has three shell tasks and 27 valid entries. All four displayed fields and the exact sequence (including equal-time ties) match the fixed reference. The corrected run has 31 records: 27 histories, three coverage records and one summary; all selected heap bytes are resident and no shell errors were reported. The multiset differential and separate ordered comparison are recorded in [linux-bash-validation.json](linux-bash-validation.json).

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(OfficialLinuxBash|LinuxBash)' -count=1 -v
go test ./internal/plugins -run TestBash -count=1
```

The corpus test independently reconstructs each task's process page table and rereads all 81 captures. It repeats those checks for cached output and requires byte-identical fresh/cached JSONL. Synthetic tests cover x64/x86/PAE layouts, a decoy outside the heap but inside the same mapped run, holes, invalid and empty entries, unaligned pointers across scanning boundaries, more than 4096 markers, bounds, partial reads, output failure and cancellation. These synthetic checks do not replace real 32-bit or alternate Bash-build differentials. Timeline output, modern kernels and broader acceptance remain pending. ARM64 heap mapping now uses bounded VMA walks through the native 4KiB/48-bit translator; synthetic ARM64 history recovery rereads the three captured fields in process space and checks heap scope. Missing physical page-table bytes remain read failures, distinct from invalid descriptors. A positive real ARM64 Bash history differential remains pending.


Local Kali ARM64 default-run check (2026-10-23): `linux.pslist` returns 169 tasks. Two are named `zsh`; none are named `bash`, `sh`, or `dash`. `linux.bash` completes with zero shells, zero history entries and one summary record. This is an empty control, not proof of positive ARM64 recovery. Zsh history has a different layout and is outside this plugin's scope. PID is an optional filter; omitting it enumerates all eligible shell tasks.

TUI Enter now runs plugins with their declared defaults when no required input is missing. Use `e` to edit optional filters or bounds. Plugins requiring a pattern or another explicit input still open the form.
