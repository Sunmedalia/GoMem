# Linux keyboard notifier chain (development preview)

`linux.keyboard_notifiers` walks `keyboard_notifier_list` and attributes each `notifier_call`. It follows Volatility 3 v2.28.2 `linux.malware.keyboard_notifiers.Keyboard_notifiers` for x64/x86/PAE and ARM64 kernels. A module or symbol outside the expected kernel range is an investigation lead, not a malware verdict. This capability remains partial.

```sh
bin/gomem analyze linux.keyboard_notifiers --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

The symbol `keyboard_notifier_list` and types `atomic_notifier_head` and `notifier_block` are required. The walk starts at `head`. It yields the pointer before following `next`, including a pointer at address zero. A repeated pointer stops the walk. The fixed helper's limit is inclusive: entry number 4096 is emitted, then the walk stops. A one-byte readability probe is recorded for every yielded pointer. Module ranges come from the existing Lsmod, sysfs, scanner, and kernel-text sources. Exact symbols use the selected matching module, not the pinned helper's final loop variable.

The user's Debian 3.2 x64 image has a null list head. The unmodified reference prints an empty table and still exits successfully, because its object layer treats the zero pointer as unreadable and stops quietly. GoMem records that one-byte read at address zero, keeps the module-discovery evidence, and fails the task. A failed task is not reused as a completed cache entry. An empty displayed table therefore does not mean the check succeeded.

Synthetic x64, x86, and PAE profiles cover a kernel callback, a module callback, an unknown address, a qualified symbol, a two-node cycle, a missing symbol, an unreadable head, and a null head whose zero page is absent. Positive runs reread complete raw captures and reuse cache. The fixed-source oracle separately checks the inclusive 4096 bound: 4097 nodes are visited and the last offset is 4097.

```sh
python3 tools/build_keyboard_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(LinuxKeyboard|OfficialLinuxKeyboardNotifiers)' -count=1 -v
```

Real hooked notifier chains, native 32-bit images, independent ARM64 differentials, and complete acceptance remain pending. The local Kali ARM64 smoke run completes with 838 records and a zero-row summary; it is not a hooked-chain positive test.
