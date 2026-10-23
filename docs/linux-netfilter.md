# Linux Netfilter hooks — development preview

`linux.netfilter` is the native command for upstream
`linux.malware.netfilter.Netfilter`. This preview selects all applicable global, namespace and device layouts
from symbol types, using the fixed upstream implementation order. The reader supports x64/x86/PAE and
ARM64 symbol-described pointer widths.

```sh
bin/gomem analyze linux.netfilter --image memory.raw --symbols kernel.json \
  --case case-001 --offline --format jsonl
```

The global `nf_hooks` symbol must describe a `list_head[13][8]` matrix.
For kernels with `net_namespace_list`, the native reader also supports:

| Symbol-described container | Native layout |
| --- | --- |
| `net.nf.hooks` matrix of `list_head` | `namespace-list` |
| Matrix of `nf_hook_entry *` | `namespace-entry` |
| Matrix of `nf_hook_entries *` | `namespace-entries` |
| Per-protocol `net.nf.hooks_ipv4/arp/bridge/ipv6/decnet` arrays | `namespace-split` |
| `net_device.nf_hooks_ingress`, optional `nf_hooks_egress` | `device-list`, `device-entry`, `device-entries` |

All applicable layouts run, including global and device hooks on the same
kernel. IPV4, ARP, BRIDGE, IPV6 and DECNET protocol slots are visited in fixed
order. Device hooks visit INGRESS then EGRESS. As in the baseline, ingress
metadata selects the device implementation; egress-only metadata does not.
Missing per-protocol arrays represent disabled kernel families.

List containers walk `nf_hook_ops.list`. Single-entry chains read `orig_ops`
and `next`. Entries arrays use the declared `hooks` offset plus
`num_hook_entries * sizeof(nf_hook_entry)` to find the adjacent original-ops
pointer array. The callback is always read from those original operations,
even when the inline hook differs. Typed offsets and pointer widths are used;
no kernel banner thresholds select a layout.

`Net NS` comes from `net.ns.inum`; the global layout marks it unavailable.
`Namespace`, `Device`, `Layout` and `Slot` retain native scope. A shared
operation referenced from different namespaces remains separate evidence.
Namespace/device list heads, namespace IDs and list links, slot pointers,
entry links, counts and original pointers are retained as raw captures.
Empty namespace/device lists and zero-count containers emit observations.
These observations and module-source rows are not hook rows.

`Priority` is the signed `nf_hook_ops.priority`. `Handler` is the function
pointer. Module and symbol attribution uses one shared module-source scan and
the existing exact-address lookup. Kernel aliases use the first lexicographic
name. For non-kernel handlers the native lookup uses the selected matching
module, retaining the known difference from the pinned helper
(see [linux-kthreads.md](linux-kthreads.md)). A handler inside the kernel or a module is
`Is Hooked=False`. A handler with no owner is `True` only when every module source completed.
Incomplete module discovery leaves that classification missing and fails the
task. Module source observations and all traversed slot captures remain evidence. A broken container emits an
error row for that slot and keeps walking the remaining slots. The task fails
if any module source, slot, or handler lookup fails. Output callback errors
and cancellation stop emission immediately. The stricter native list walk
checks backward links. Null original-ops pointers, unreadable pointers/counts,
cycles and exceeded `max-nodes` bounds fail the task rather than disappearing
as empty results. Matrix dimensions are bounded to 13..256 by 8..256, entry
stride to 4096 bytes and captured operation size to 4096 bytes. Arithmetic is
checked before reading. These stricter failures and bounds are native
behavior differences; full damaged-input equivalence is pending.

See [the validation record](linux-netfilter-layout-validation.json) for the
verified cases and remaining gaps.

## Verification

The synthetic x64 fixture has one IPV4 `LOCAL_IN` operation at priority -1.
Separate cases validate an unknown handler, a kernel handler with an exact
symbol, and incomplete module-source coverage. Complete runs have sealed rows
and byte-identical cached JSONL. Empty slots have self-linked list heads.
Broken-list, callback-error, and cancellation cases retain failures and stop
output as appropriate. A positive module-owned handler differential remains
pending.

Twenty-four namespace/device paging cases run across x64, x86 and PAE. They
verify namespace identity, INGRESS/EGRESS ordering, disabled protocol fields,
original rather than inline callbacks, flexible-array padding, byte captures,
seals after all emissions and byte-identical cached JSONL. A pinned-source
oracle executes the actual `_run`, namespace/protocol/device loops and three
container decoders over mocked kernel object boundaries. Its 16 cases cover
32/64-bit pointers, four namespace layouts, and presence/absence of device
hooks; native rows and adjacent-array addresses must match. Module attribution
is mocked for this oracle and tested separately above. It does not establish
modern real-image acceptance.

Additional tests exercise multiple original pointers, zero/oversized counts,
null/unreadable originals, absent members, malformed dimensions, cycles,
unreadable next entries, broken namespace links, cancellation and output
errors. Separate fixtures verify simultaneous global/namespace execution,
device-only metadata, absent egress, and two namespaces sharing one original
operation. Partial results retain failures rather than claiming clean output.

```sh
python3 tools/build_netfilter_oracle.py --check
go test ./internal/engine -run TestLinuxNetfilter -count=1
```

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

Modern namespace/device differentials, actual native x86/PAE acquisitions, positive
module-owned/unknown real hooks, an independent ARM64 comparison, all parameter/corruption
branches and full version acceptance remain open. A local Kali 6.8.11 ARM64 smoke run
completed with 994 records, including 38 Netfilter hooks. The plugin remains partial;
this work does not close a release acceptance item.
