# Linux bash history (development preview)

`linux.bash` recovers `hist_entry` records from the heaps of tasks named `bash`, `sh`, or `dash`. It corresponds to Volatility 3 v2.28.2 `linux.bash.Bash` on Intel kernels. A recovered command is history evidence, not a judgment about the command. This capability remains partial.

```sh
bin/gomem analyze linux.bash --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

The heap is every readable range inside a VMA that overlaps `[mm.start_brk, mm.brk]`. A `#` marker is packed as a native pointer and scanned again. The candidate 8 bytes before that pointer is `hist_entry.line`; the pointer itself is `timestamp`. A valid entry has a nonempty command and a `#` timestamp whose remainder is a decimal Unix second of at least 10 characters. Entries sort by that second, then by entry address when the second is equal.

The Debian 3.2 x64 image has three shell tasks and 27 valid entries. PID, process name, UTC command time, command text, and order match the unmodified reference. The task completed with 28 rows and zero read failures. Raw command and timestamp captures are retained.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxBash -count=1 -v
```

The bundled bash profile is fixed at the pinned 24-byte/16-byte `hist_entry` layout. Other bash builds, 32-bit images, modern kernels, ARM64, and complete acceptance remain pending.
