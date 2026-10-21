# Linux check_modules (development preview)

`linux.check_modules` compares `module_kset` with the active `modules` list. It corresponds to Volatility 3 v2.28.2 `linux.malware.check_modules.Check_modules`. A kset-only name is a lead, not a malware verdict. This capability remains partial.

```sh
bin/gomem analyze linux.check_modules --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

Sysfs selection follows the pinned rule: a nonzero name pointer and a reference count above 2. Duplicate **kobject names** keep the last selected object. Comparison uses the kobject dictionary keys against active `module.name` values; it does not compare the selected object's internal module name. Output still displays the selected module's internal name and retains `KObjectName` as the selection key. A mismatched name alone is not proof of malicious behavior.

Only the active list and module kset are read. Allocation scanning, scanner bounds, active-module code extents and display fields for excluded sysfs objects are not prerequisites. The former GoMem-only `max-scan-bytes` argument is removed from this command. Other module consumers retain their three-source gatherer. The shared task/list visit bound remains `max-nodes`.

An empty difference is a completed comparison. Unreadable required fields retain raw captures and fail the task. `File Output` explicitly records `not_requested` for enumeration, matching the reference default null. Module ELF reconstruction and the upstream `dump` option are not implemented here. Output failure and cancellation propagate immediately.

The Debian 3.2 x64 image has 79 active modules and 79 selected sysfs keys. Both the fixed reference and native report zero kset-only modules. The corrected native task has 288 rows, retaining list observations and sysfs selection decisions, with zero read failures and no allocation-scan records. The corpus test checks source scope, summary counts and byte-identical cache replay. This negative sample cannot establish that hidden-module detection is generally correct.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(OfficialLinuxCheckModules|LinuxCheckModules)' -count=1 -v
```

Synthetic x64/x86/PAE tests cover kset-only objects, module/kobject name divergence in both directions, duplicate keys, absent scanner symbols, comparisons without irrelevant display layouts, corrupt pointers/lists, source-byte rereads and cache consistency. These tests supplement the negative real image; real hidden-module, modern-kernel and 32-bit differentials remain pending. Parameter decoding (including string/array handlers), module ELF extraction and full acceptance are not established by these tests.
