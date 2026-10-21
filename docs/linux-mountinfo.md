# Linux mountinfo (development preview)

`linux.mountinfo` lists mount points from each task mount namespace. It corresponds to Volatility 3 v2.28.2 `linux.mountinfo.MountInfo` on Intel kernels. A deleted mount point is a lead about the filesystem, not a malware verdict. This capability remains partial.

```sh
bin/gomem analyze linux.mountinfo --image memory.raw --symbols kernel.json --case case-001 --offline --format jsonl
```

Without `pids`, one representative task is used for each namespace and rows are unique by mount id. `pids` repeats every mount for each selected task, matching the baseline. `mntns` filters by the namespace inode when that field exists. Kernels without `proc_inum` or `ns.inum` keep the rows and record that the filter cannot be applied. `mount-format` keeps the brief devname, path, type and combined option columns beside the detailed mountinfo columns.

Mount options use the pinned `MNT_*` bits. Superblock options use `SB_RDONLY`, sync, dirsync, mand and lazytime. The device number is `major:minor` with a 20-bit minor. A deleted mount point keeps the baseline display: one leading space, the absolute path, and ` (deleted)`. Shared, slave and unbindable tags are included when those fields are present.

The Debian 3.2 x64 image has no namespace inode. Native records `namespace_inode_not_in_layout`, which compares as the reference null. All 13 mounts match id, parent, device, root, mount point, options, fields, type, source and superblock options, including the deleted binfmt_misc path. The task completed with 14 rows and zero read failures. The test independently compares ordered mount-id/parent/path tuples and asserts the multiset report has `matched=true`. All 91 scalar/text captures are independently reread both before and after byte-identical SQLite cache replay. This is a normal-image control, not a hidden-mount sample.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxMountInfo -count=1 -v
```

Modern kernels, 32-bit images, ARM64, shared/slave propagation samples and complete acceptance remain pending.

## Failure handling verification (2026-10-21)

Null mount roots and superblocks, partially readable superblocks and invalid
filesystem type targets now produce a failed task with diagnostic rows and
nonzero `read_layout_errors`. A non-null unreadable filesystem type is distinct
from an absent type pointer. Failed tasks rerun instead of replaying completed
results. These are explicit diagnostic differences from skipped or unavailable
baseline records, not full damaged-image parity.

Scalar field captures are saved before decoding, including a short raw prefix,
requested/captured lengths and the read error. Missing layout also leaves its
missing reason. Output errors retain their original identity and stop further
emission immediately; cancellation stops traversal before diagnostic output.

`TestLinuxMountInfoDiagnosticsFailAndRerun`,
`TestLinuxMountInfoOutputFailureStops`, and
`TestLinuxMountNumericFailedCaptureRetained` cover those failure paths.
`TestLinuxMountInfoSynthetic` now requires all seven scalar/text captures on
each fixture mount to pass wire-format decoding and independent byte rereads;
unrecognized capture structures cannot silently skip verification.
