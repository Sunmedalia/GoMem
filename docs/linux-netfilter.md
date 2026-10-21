# Linux Netfilter hooks — development preview

`linux.netfilter` is the native command for upstream
`linux.malware.netfilter.Netfilter`. This preview reads the global
`nf_hooks` table used through Linux 4.2.

```sh
bin/gomem analyze linux.netfilter --image memory.raw --symbols kernel.json \
  --case case-001 --offline --format jsonl
```

The symbol must be `list_head[13][8]`. Each protocol/hook slot is a
`nf_hook_ops` list. IPV4, ARP, BRIDGE, IPV6, and DECNET are visited. INET and
NETDEV are skipped, matching the legacy implementation. `Net NS` is
`global_table` because these hooks are not stored per namespace. Kernels from
4.3 onward, which keep hooks inside `struct net`, are rejected before any row.

`Priority` is the signed `nf_hook_ops.priority`. `Handler` is the function
pointer. Module and symbol attribution uses one shared module-source scan and
the existing exact-address lookup. Kernel aliases use the first lexicographic
name. For non-kernel handlers the native lookup uses the selected matching
module, retaining the known difference from the pinned helper
(see [linux-kthreads.md](linux-kthreads.md)). A handler inside the kernel or a module is
`Is Hooked=False`. A handler with no owner is `True` only when every module source completed.
Incomplete module discovery leaves that classification missing and fails the
task. Module source observations and all 25 list-head captures remain evidence. A broken list emits one
error row for that slot and keeps walking the remaining slots. The task fails
if any module source, slot, or handler lookup fails. Output callback errors
and cancellation stop emission immediately. The stricter native list walk
checks backward links; full damaged-list equivalence is pending.

## Verification

The synthetic x64 fixture has one IPV4 `LOCAL_IN` operation at priority -1.
Separate cases validate an unknown handler, a kernel handler with an exact
symbol, and incomplete module-source coverage. Complete runs have sealed rows
and byte-identical cached JSONL. Empty slots have self-linked list heads.
Broken-list, callback-error, and cancellation cases retain failures and stop
output as appropriate. A positive module-owned handler differential remains
pending.

The supplied Debian 3.2 x64 sample (SHA-256
`8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`) is a
negative control. Unmodified Volatility 3 v2.28.2 commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75` returns no rows. Native
`linux.netfilter` completes with zero hook rows. The verified CLI task
`5987e5964cc0841a80f49d70fe59625a` retains 548 module-source observations
and 25 list-head captures. All 25 head captures are independently
reread and the cached run emits identical JSONL. These diagnostic rows are
excluded from the hook comparison. The earlier exploratory task
`3e3a92976654ea5ac430bdd42f8d73b9` predates source-evidence retention and does
not prove the corrected implementation. An empty result does not cover later
Netfilter layouts.

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_NETFILTER_REFERENCE="$PWD/.cache/netfilter-validation/reference" \
go test -race ./internal/engine -run 'Test(OfficialLinuxNetfilter|LinuxNetfilter)' -count=1
```

The reference prefix must include `.json` and `.manifest.json` produced by
`tools/reference.py --plugin linux.malware.netfilter`. Skipped optional corpus
tests do not establish acceptance.

Per-namespace arrays, singly linked `nf_hook_entry` layouts, ingress and
egress hooks, actual x86/PAE images, positive real hooks, and full version
acceptance remain open.
