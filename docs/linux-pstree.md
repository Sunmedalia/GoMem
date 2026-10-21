# Linux process hierarchy (development preview)

`linux.pstree` corresponds to pinned Volatility 3 v2.28.2 `linux.pstree.PsTree`. It remains **partial**, without full capability or release acceptance.

```sh
bin/gomem analyze linux.pstree --image memory.raw --symbols kernel.json --case case-001 --format jsonl
bin/gomem analyze linux.pstree --image memory.raw --symbols kernel.json --case case-001 -p threads=true -p decorate-comm=true
```

The hierarchy is keyed by **task.pid (TID)**. A thread-group leader's edge uses `real_parent.tgid`; a user thread's edge uses its own `tgid`, while displayed PPID still reports `real_parent.tgid`. `HierarchyParentTID` records the edge choice separately. PID 1 and 2 may anchor at a zero parent. A task with PID greater than 2 and parent zero does not add that edge. A missing nonzero parent becomes a root. The algorithm follows the fixed seen-parent and seen-object stops, insertion order for roots and numerically sorted child TIDs. Repeated TIDs use the last object, preserving the first TID insertion position. Native evidence never merges the distinct underlying objects' identities.

`pid` is a comma-separated task-list PID filter applied **before** hierarchy construction. It does not automatically add ancestors or descendants. With `threads=true`, threads of selected process groups are included even when their own TIDs are outside the filter. A selected task whose parent is outside that filtered set becomes a new root. `decorate-comm=true` brackets PF_KTHREAD names and braces user-thread names; the raw comm capture remains available. Names stop at NUL or the first UTF-8 replacement character as in the fixed string helper.

Every selected candidate streams an `observation` before graph construction, with `HierarchyState=candidate`, task/leader offsets, object-based TaskIdentity, and raw field captures for PID/TGID/comm/real_parent plus read parent TGID, ownership and decoration fields. Capture coordinates, requested/captured lengths, partial bytes and errors remain explicit. For a nonnull parent the fixed parent helper requires the whole parent object to be readable; native checks that extent and retains a diagnostic if it is unreadable. The displayed fallback PPID is zero, and the read failure marks the task failed.

After construction, `selection` records say `included`, `replaced_duplicate_tid`, or `not_root_reachable`; an interrupted work-bound pass reports `hierarchy_incomplete`. Process rows preserve the five reference columns (`OFFSET (V)`, PID, TID, PPID, COMM), `GeneratorDepth` and actual renderer `Depth`, plus sealed `parent_id`. The generator's raw level can differ from the actual rendered depth on malformed hierarchies; both remain available. All candidate evidence survives ordinary list/work failures, and observations already emitted survive cancellation. Missing required layout fails explicitly. Unknown reads are never silently treated as a successful empty tree.

A PID hierarchy is a **displayed relationship**, not proof of historical parent object identity. Parent pointers, task offsets, image/layer/object/TID/available-creation-counter TaskIdentity and raw fields provide investigation coordinates. Use those coordinates for evidence association instead of joining solely on PID.

Native limits are `max-nodes=131072` per list (1..1000000), `max-tasks=1000000` total candidates (1..1000000), `max-work=10000000` ancestor/child steps (1..100000000) and 4096 bytes per captured field. The graph walk is iterative, including cycle termination, and does not reproduce Python recursion failures. Task/thread traversal checks forward back-links, object uniqueness and thread owner consistency; full fixed bidirectional and validity/skip behavior is pending. Raw field capture is shared with ptrace; the refactor is covered by ptrace real-corpus regression.

## Validation

- **19 fixed-source mocked hierarchy cases** cover ordinary/reversed/sorted trees, absent parents and leaders, zero-parent smear suppression, swapper, threads, duplicate TIDs, self/ancestor cycles and shared offsets. They exercise the actual pinned hierarchy generator and emulate its renderer parent-stack rule, not acquisition or task validity.
- Synthetic native readers cover x64/x86/PAE translation, legacy and signal-based thread lists, user/kernel decorations, UTF-8, duplicate TIDs with different object identities, real_parent failures, thread owner/list faults, bounds, cancellation after one persisted observation, output errors, SQLite row verification and cache reuse. A 10-second hierarchy fuzz run passed 193721 executions with unique-row and renderer-parent invariants.
- The user-provided Debian sample (decompressed SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) matches the **unmodified** pinned plugin in all five columns, exact enumeration order, rendered depth and full ancestor paths: **133 default rows**, **316 decorated process/thread rows**, and **3 filtered PID-3924 group rows**. Diagnostics are zero. **665 / 2262 / 22** field captures are independently reread from kernel memory. The offset comparison explicitly masks x64 addresses to low 48 bits to match the fixed object offsets; full canonical native addresses remain preserved.
- [Validation records](linux-pstree-validation.json) record reference/native hashes, coverage, cache equality and bundle verification. The differential explicitly selects process rows and accounts for observations/selections/diagnostics/summary; unknown record types are errors.

```sh
python3 tools/build_linux_pstree_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(LinuxPsTree|OfficialLinuxPsTree)' -count=1
make check
```

Real modern kernels, actual signal-based thread-list/x86/PAE images, ARM64, all corruption/parameter/version conditions and complete release acceptance remain pending. No ARM64 translator support is implied for the user's Kali image.
