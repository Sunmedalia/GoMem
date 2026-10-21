# Linux check_modules (development preview)

`linux.check_modules` compares `module_kset` with the active `modules` list. It corresponds to Volatility 3 v2.28.2 `linux.malware.check_modules.Check_modules`. A kset-only name is a lead, not a malware verdict. This capability remains partial.

```sh
bin/gomem analyze linux.check_modules --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

Sysfs selection follows the pinned rule: a nonzero name pointer and a reference count above 2. Duplicate kset names keep the last selected object. A name present in the active list is not emitted. An empty difference is a completed comparison. Unreadable required module fields remain diagnostics and fail the task. `File Output` stays unavailable because module ELF reconstruction is separate.

The Debian 3.2 x64 image has 79 active modules and 79 selected sysfs modules. Their names match, so both the unmodified reference and native emit zero kset-only rows. Native still records the shared list observations. The task completed with 548 rows and zero read failures.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxCheckModules -count=1 -v
```

A real kset-only module, modern kernels, 32-bit images, ARM64, parameter decoding differentials, and complete acceptance remain pending.
