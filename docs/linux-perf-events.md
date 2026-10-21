# Linux performance events

Development preview; partial capability, not full release acceptance. Native `linux.perf_events` maps to pinned Volatility 3 v2.28.2 `linux.tracing.perf_events.PerfEvents`.

The reader visits active process leaders and their threads, then follows each `task_struct.perf_event_list` through `perf_event.owner_entry`. Both legacy `thread_group` and modern `signal_struct.thread_head`/`thread_node` layouts are supported on Intel x64, x86 and PAE. List fields must be embedded `list_head` structures with the declared pointer layout. Runtime field pointers must be typed pointers; scalar values are not guessed as addresses.

Rows preserve the six reference fields: `PID` (the task's PID/TID, including thread IDs), `Process`, `Event`, `Short Program Name`, `Full Name` and `Address`. The program address is the event's `bpf_prog` pointer, not a claimed bytecode location. Additional coordinates identify the event, task, leader, PMU and aux object. Task identity combines image, address space, task object, TID and available creation counter, rather than associating by numeric PID alone.

## Selection and strings

Event names follow `event.pmu.name` and read exactly 64 bytes. Short names follow `event.prog.aux.name` and read the declared byte-array length, bounded to 1..256. Full names use embedded `event.prog.aux.ksym.name` and read exactly 512 bytes, including beyond a shorter declared array, matching the fixed utility call. Raw reads remain bounded by mapped memory and the acquisition budget. Missing `ksym`/`name` fields make the full name unavailable; wrong layouts and actual read failures remain explicit errors.

String conversion truncates at NUL or the first Unicode replacement character, as the pinned utility does. Empty event/program names become typed unavailable values at rendering time. Successfully read events with all three names empty are still retained: the reference checks for Python `None` before its empty-string rendering conversion. A null program is excluded only after the reference's name-reading sequence; mapped address zero is not treated as a substitute for a read failure.

Before associating events, the reader checks the whole task extent, signed PID/TGID, optional non-null/readable signal, nsproxy and real-parent pointers, active-mm readability and `mm == active_mm` for non-null mm. Pointer probes use the declared pointed-type extent. Native thread TGID ownership checks additionally reject foreign tasks. Invalid tasks and unreadable data produce failed observations; the fixed listing often silently filters these. This deliberate error policy preserves uncertainty instead of reporting complete negative evidence. Forward/backward damaged-list recovery and complete unusual task/thread relationships remain unaccepted.

## Evidence and bounds

| RecordType | Meaning |
| --- | --- |
| `perf_event` | Selected event/program and task identity |
| `event_observation` | Candidate event excluded or incomplete, retaining available fields and error |
| `task_observation` | Task event-list count/completion or invalid-task/thread diagnostic |
| `event_read` | Actual acquisition attempt with original bytes, address, requested/captured sizes, completeness and error |
| `event_summary` | Task/event/selected/read counts, acquired bytes and overall completion |

A task observation's `Coverage.Completed` describes its list traversal; individual event-field errors still make the overall summary incomplete. Failed tasks are retried instead of reused as completed cache entries. Independent events and task groups remain available after recoverable candidate errors. Cancellation and sink failures stop all further output.

`max-nodes=131072` bounds each list, `max-tasks=1000000` bounds inspected task candidates, and `max-events=1000000` bounds visited event candidates. Each accepts 1..1000000. `max-bytes=268435456` bounds cumulative captured bytes, including task/pointer probes and repeated metadata; it accepts 1..1073741824. Requests over the remaining budget fail before touching the underlying image and retain explicit acquisition errors. Images remain read-only; traces and results enter case storage.

## Verification

`tools/build_perf_events_oracle.py` verifies the locked source digest, then runs unmodified PerfEvents generation and actual PsList/task/list extensions against ISF-backed byte objects. No plugin/field methods are mocked. Forty-four cases combine two pointer widths, two thread layouts and eleven scenarios: normal, empty lists/names, invalid UTF-8, Unicode, absent ksym, a short full-name array, null program, invalid thread mm, invalid leader parent and negative thread PID.

Engine tests exercise 66 paging cases across x64, x86 and PAE. All six ordered fields, every acquired byte, SQLite seals and byte-identical replay are checked. Invalid task cases match the reference's selected rows while requiring native failure and a fresh uncached retry. Direct tests inject pointer holes, list cycles, foreign threads, bad pointer symbols, budget exhaustion and failures/cancellation at every output position. Fuzzing mutates task/list/event/program memory and independently checks captured bytes under finite limits.

The supplied Debian 3.2 x64 image (SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) has **zero linked events** in 316 inspected task/thread objects. Both engines return zero selected events. Native records 5928 acquisition attempts covering 2017448 bytes. The optional corpus test verifies pinned reference/image/output hashes, independently rereads all captures, pages through all 6245 persisted seals and checks identical cache replay. This is an empty-event control only; it does not validate real positive perf/eBPF detection.

```sh
make check
make matrix
python3 tools/build_inode_mode_oracle.py --check
python3 tools/build_perf_events_oracle.py --check
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxPerfEvents -fuzztime 10s
GOMEM_CORPUS_DIR=/path/to/corpus \
GOMEM_PERF_EVENTS_REFERENCE=/path/to/reference \
go test ./internal/engine -run TestOfficialLinuxPerfEvents -count=1
```

Positive real events, real x86/PAE, broader kernel versions, complete damaged-input/parameter/renderer/export coverage and full acceptance remain pending. Event inventory alone does not establish maliciousness or recover program instructions. [Measurements](linux-perf-events-validation.json), [field mapping](diff/linux.perf_events.json).
