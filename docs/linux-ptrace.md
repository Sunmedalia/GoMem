# Linux ptrace (development preview)

`linux.ptrace` corresponds to pinned Volatility 3 v2.28.2 `linux.ptrace.Ptrace`. This capability is **partial**, not accepted for a formal release. It requires matching task/list symbols and a supported kernel address space.

```sh
bin/gomem analyze linux.ptrace --image memory.raw --symbols kernel.json --case case-001 --format jsonl
```

The plugin enumerates active task-list entries (excluding init_task), followed by each process's threads. It supports legacy `thread_group` and newer `signal.thread_head`/`thread_node` layouts. Each checked object emits a `task` observation. Selection is nonzero `task.ptrace` or a readable, nonself `ptraced.next` target. Pointer target readability is checked over the list_head extent. Task/thread ownership, forward list back-links, uniqueness, and native traversal bounds are checked; this is stricter than the fixed bidirectional enumeration and validity/skip behavior. Damaged-list parity remains pending.

For selected tasks, `Tracer TID` comes from **task.parent.pid**, not real_parent or tgid. A tracer PID of zero renders unavailable, matching the fixed truth-value fallback, while its raw object details remain. Tracee TIDs come from `ptraced`/`ptrace_entry` objects and can include tasks outside the active task list. Zero tracee TIDs and repeated TIDs on distinct objects are retained. Raw `PtraceRaw`, the twelve pinned PT_FLAGS members in declaration order, and `UnknownFlagBits` are recorded. Unknown bits make the pinned enum throw ValueError; native output retains the value/error and marks the task failed rather than dropping the relationship.

The pinned generator gives successive tracee rows for a task depths **0, 1, 2, ...**. Native `relationship` rows preserve that unusual renderer hierarchy using `Depth` and sealed `parent_id`. **This display tree does not mean one tracee traces the next.** Actual relationships are in `Tracer` and `Tracee`, including object offsets, TID and image/layer/object/TID/available creation-counter-based `TaskIdentity`. `ProcessOffset` identifies the enumerated leader; `Offset` identifies the actual task/thread. PID reuse cannot merge objects solely by TID. Do not infer a malicious debugger from ptrace alone.

FieldEvidence retains addresses, raw byte captures, requested/captured sizes and errors for task identity fields, comm, ptrace state, ptraced head and next, tracer parent fields, and any additional target/owner reads. Tracee records retain their PID field and ptrace_entry captures. Failed tracee captures remain under FailedTracee. Names follow the pinned UTF-8/NUL/replacement termination semantics, with incomplete captures explicit. Raw pointers remain canonical in native evidence.

Native parameters are `max-nodes=131072` (per list), `max-tasks=1000000` (all inspected tasks/threads), and `max-relations=1000000` (all tracee entries), each 1..1000000. Individual field captures are bounded to 4096 bytes. Bounds, bad pointers, unreadable fields, unknown flags and list corruption retain available evidence and fail the task. A partial tracee list has `TraceesComplete=false`; an unreadable list is not represented as a successfully empty list. An incomplete next target on an otherwise unselected task is retained as a failed observation. Independent process groups continue after thread-group errors. Cancellation/output errors propagate. The final summary counts inspected, checked, selected and traced/tracer tasks, relationship rows, tracee entries, and diagnostic observations.

## Validation and limits

- The fixed-source oracle runs all **4096 known-flag combinations** and five unknown-bit values, plus **12 mocked task-selection/generator scenarios**: negative, tracee, tracer, both, multiple tracees, zero/repeated TIDs, unknown flags, user threads, and unreadable next targets. Mocks exercise the original task helper methods and generator; they do not establish real task validity or acquisition behavior.
- Native synthetic tests cover the oracle, list/name/parent/flag faults, partial flag/tracee captures, signal and legacy thread enumeration, x64/x86/PAE translation, corrupt lists, bounds, cancellation, emitter errors, sealed SQLite rows and cache replay. Positive synthetic relationship fields/depth/ancestor paths are compared through the same differential tool.
- The user-provided Debian sample (decompressed SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) has **133 leaders and 183 threads**, all 316 with zero ptrace state and no tracer list. Native returns zero relationship rows and zero diagnostics, matching the **unmodified** fixed full-plugin output. This is a **negative control**, not a successful real positive detection.
- A separate probe, `tools/reference_ptrace_observations.py`, observes each task yielded by the original PsList without changing its selection or ptrace plugin code. The probe records task name/PID/TID/object offset/raw ptrace/traced/tracer state. All **316 observations** match native. The reference stores masked x64 object offsets; this profile explicitly compares low 48 address bits. Native addresses remain full, lossless canonical values. The instrumented output is kept separate from the unmodified reference output and has source/script/image/output digests.
- All **2262** field captures are independently reread from kernel memory, persisted row hashes verify, and cache replay is checked. [The validation record](linux-ptrace-validation.json) records exact reference and native digests and export checks.

```sh
python3 tools/build_ptrace_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(LinuxPtrace|OfficialLinuxPtrace)' -count=1
make check
```

Real positive ptrace acquisition, modern kernels (including a real signal-based thread-list image), actual x86/PAE images, ARM64, all task validity/corruption/parameter conditions, and full capability acceptance remain pending. The Kali ARM64 user image is not supported by an address translator yet.
