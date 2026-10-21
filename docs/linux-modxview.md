# Linux module cross-view (development preview)

`linux.modxview` implements the three module gatherers used by the pinned Volatility 3 v2.28.2 `linux.malware.modxview.Modxview`. It retains the six upstream result columns, raw fields, candidate decisions and source coverage. This is a **partial** capability; one real Debian x64 differential and synthetic layout tests do not establish full kernel/version acceptance.

```sh
bin/gomem analyze linux.modxview --image memory.raw --symbols kernel.json --offline --case case-001 --format jsonl
bin/gomem analyze linux.modxview --image memory.raw --symbols kernel.json --offline --case case-001 -p plain-taints=true
```

The shared native module discovery layer implements:

- **Lsmod:** `modules` through `module.list`, with bounded traversal and forward/backlink/tail validation. Root and module list fields are retained.
- **SysFs:** typed `module_kset`, `kset.list`, `kobject.entry` and `module_kobject.mod`. Candidates require a nonzero name pointer and refcount greater than two. Names use the fixed helper's 32-byte decoded string. Both `kref.refcount.counter` and modern `kref.refcount.refs.counter` layouts are supported. Duplicate names keep the last candidate at the first name insertion position. Candidate rows precede explicit included/excluded/replaced selection records.
- **Scanner:** typed `mod_tree.addr_min/addr_max` or `module_addr_min/module_addr_max` allocation bounds. The actual baseline advances by pointer size (4/8 bytes). A self-referencing `module.mkobj.mod` prefilter precedes full struct readability, nonzero self pointer, core/text sizes in 1..20,000,000 and core+init size at least 4,096. Every self-match remains a `scan_candidate`, including invalid structures.

Module layouts cover legacy `module_core/core_size/core_text_size/init_size`, `core_layout/init_layout`, and the Linux 6.4+ `module.mem` array with typed `mod_mem_type` constants. The modern helper's sum of core segment sizes is preserved; this range model does not assert contiguous mapped memory. Missing layout members, untyped allocation bounds and overflowing address ranges are explicit failures. No guessed integer type is substituted for missing symbol metadata.

Scanner reads use bounded page prefixes, preserving candidates with completely captured pointer bytes. Unreadable allocation positions increment `scan_unreadable`; module allocation ranges can contain unmapped holes. This count does not establish the absence of modules in those locations. Read or layout errors in an actual self-match, source traversal or module field remain failed evidence. Independent sources continue when possible, preserving partial observations and a failed task; cancellation and output errors stop immediately.

Cross-view rows aggregate by module object offset in Lsmod, SysFs, Scanner order. Source duplicates remain visible in Gatherers. A separate shared helper flattens by masked module base for future pointer consumers; Modxview does not use that flattening. Addresses in native evidence remain canonical and lossless. The differential mapping explicitly masks to the baseline's lower 48 bits for this x64 corpus. The source booleans mean that the gatherer yielded the object; a false value with incomplete coverage is not a complete negative finding.

Default taints are comma-separated pinned descriptions. `plain-taints=true` preserves the exact upstream character behavior, including legacy bit zero yielding `PG` while parsed output yields only `PROPRIETARY_MODULE`. Typed dynamic `taint_flags` arrays use module-specific flags and non-space `c_false` characters; absent or empty arrays use legacy flags. Unknown characters produce `<UNKNOWN_TAINT_CHAR_X>`. Arrays are capped at 256 entries. Out-of-Unicode-range characters follow the baseline's skip behavior; Unicode surrogates fail explicitly because Go strings cannot preserve Python's surrogate output without changing evidence.

`FieldEvidence` retains raw bytes, kernel coordinates, requested/captured sizes and read status. Record types are `source_observation`, `module_observation`, `sysfs_candidate`, `source_selection`, `scan_candidate`, `module`, `diagnostic` and `summary`. The differential mapping selects final `module` records and explicitly lists other types; unknown types fail comparison. Native bounds are `max-nodes=131072` (1..1,000,000 shared source visits) and `max-scan-bytes=268435456` (1..8 GiB allocation span); exhaustion fails rather than silently completing. Individual raw module/field captures are capped at 4,096 bytes.

On the user's Debian RAW image, both default and plain profiles match **79 modules, all six columns and enumeration order** against the unmodified fixed reference. Each emits **627 records** and **1,973 complete raw field captures**, independently reread from kernel memory. Each source yields 79 modules. Of 587,805 allocation positions, 79,919 are unreadable; 101 self-matches include 22 rejected candidates. There are no failed diagnostics or read/layout errors. CLI fresh/cache outputs are byte-identical and exported bundles verify. See [the validation record](linux-modxview-validation.json).

Synthetic tests cover x64/x86/PAE across all three module layouts, source-only modules, duplicate names, modern refcounts and bounds, damaged lists, missing/unreadable fields, allocation holes, dynamic taints, limits, cancellation, output failure, sealed storage and cache replay. Pinned unmodified helpers provide 14 legacy taint, 32 dynamic taint, three aggregation/flattening and 12 validity cases. The module layout fuzz target passed 506,962 executions in the recorded run.

```sh
python3 tools/build_modxview_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(OfficialLinuxModxview|LinuxModxview)' -count=1 -v
make check
```

Actual modern, x86 and PAE corpus comparisons, all damaged-image behavior and complete parameter/version acceptance remain pending. Native strict list checks and partial-error retention can differ from baseline traversal on damaged inputs. The user's Kali ARM64 image still requires an ARM64 virtual translator and actual kernel symbols for this plugin; its successful physical VMCOREINFO test does not establish module support. Kernel-thread enumeration and function-symbol attribution are exposed separately by the [linux.kthreads preview](linux-kthreads.md); Modxview itself does not enumerate kernel threads.
