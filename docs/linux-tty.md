# Linux tty receive handlers (development preview)

`linux.tty_check` walks `tty_drivers` and reads each device's line-discipline `receive_buf`. It corresponds to Volatility 3 v2.28.2 `linux.malware.tty_check.Tty_Check` on Intel kernels. A handler outside the kernel is a lead, not a malware verdict. This capability remains partial.

```sh
bin/gomem analyze linux.tty_check --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

Drivers come from the `tty_driver.tty_drivers` list. Each driver's `ttys` pointer array is read up to `max-devices` (default 4096, range 1..1,000,000). A larger declared `num` is recorded as coverage and does not by itself fail the task. Null device pointers are counted and skipped. Unmapped device slots are counted as `unreadable_device_slots`; the fixed plugin also skips those slots, and native does not turn absent slots into a failed task. Name and `receive_buf` reads that fail on a present device are retained and fail the task.

On this Debian 3.2 symbol table, `tty_struct.ldisc` and `tty_ldisc.ops` are pointers. Native follows both pointers before reading `tty_ldisc_ops.receive_buf`. The handler is attributed with the shared module ranges and exact kernel or module symbols.

The Debian 3.2 x64 image has five drivers and seven present devices, `tty1` through `tty7`. All seven handlers are `__kernel__` / `n_tty_receive_buf`, matching the four baseline columns and order after the low-48 address mask. Native output has 556 rows. The corpus test rereads 1,836 complete raw captures. Cache output is byte-identical and the task bundle verifies. There are 344 null slots and 8,192 unmapped slots inside the inspected bound. This is a normal-image control, not a hooked tty sample.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxTTY -count=1 -v
```

Synthetic positive and damaged driver chains, modern kernels, 32-bit images, ARM64, and complete acceptance remain pending.
