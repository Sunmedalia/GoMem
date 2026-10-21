# Linux network interfaces and addresses (development preview)

`linux.ip.link` and `linux.ip.addr` provide native counterparts for the pinned Volatility 3 v2.28.2 `linux.ip.Link` and `linux.ip.Addr`. Both remain **partial**. Matching Linux symbols, a supported Intel kernel address space, `net_namespace_list` and the relevant network types are required. Missing required symbols/layouts fail explicitly.

```sh
bin/gomem analyze linux.ip.link --image memory.raw --symbols kernel.json --case case-001 --format jsonl
bin/gomem analyze linux.ip.addr --image memory.raw --symbols kernel.json --case case-001 --format jsonl
```

Both walk the namespace list, then each namespace's device list in order. `NamespaceOffset` identifies the enumerated namespace, while displayed `NS`/`NetNS` comes from each device's `nd_net` (or `possible_net_t.net`) and its `net.proc_inum` or `net.ns.inum`. These can differ. Older kernels lacking either inode layout have a missing value with an explicit reason; zero inode IDs also remain unavailable. Raw device namespace pointers are retained even when there is no inode layout. An unreadable inode or malformed declared field is an error, rather than an old-kernel exception.

Link exposes the eight upstream columns: NS, Interface, MAC, State, MTU, Qdisc, Qlen, Flags. Names use the pinned UTF-8 replacement/NUL/U+FFFD truncation rule. MAC selection first checks the `addr_len` prefix of `perm_addr`, falling back to `dev_addr` when it is all zero or no permanent array exists. Captures preserve the complete declared permanent array. A nonzero truncated permanent array is formatted with its available declared length as in the fixed helper. Missing fallback bytes remain an explicit error; they are never zero-padded into a trusted MAC. A zero hardware length remains an empty address. Unknown operational state values remain unparsable. Qdisc follows `qdisc.ops.id`; empty names are unavailable and unreadable fields are errors.

Flags combine `flags`, `gflags`, `state`, `operstate`, the `net_device_flags` enum (legacy constants only when absent) and required `netdev_state_t` bit indices. Native output preserves sorted any-bit mask selection, drops IFF_RUNNING and removes IFF_ for display. The pinned `IFF_ALLMULTI)` gflags spelling is preserved, including its effect on ALLMULTI output. No substitute mask is invented when a declared enum is incomplete.

Addr exposes NetNS, Index, Interface, MAC, Promiscuous, IP, Prefix, Scope Type, State. It visits IPv4 before IPv6 for each interface, including multiple addresses. Index and prefix preserve signed symbol semantics. IPv4 integers are packed little endian as in the pinned helper; scopes use `rt_scope_t` names and unknown values display `unknown`. Different-meaning aliases for one enum value fail explicitly: native symbol maps do not retain the declaration order needed to reproduce the pinned first-alias choice. IPv6 requires the post-3.0 `inet6_dev.addr_list`/`inet6_ifaddr.if_list` list layout and four 32-bit address scalars; each scalar is packed little endian. Scope priority is host, link, site, global. IPv4-mapped IPv6 tails display dotted IPv4; older Python `ipaddress` versions may display hexadecimal tails. The oracle normalizes only this textual difference.

`Offset` is the device object and `AddressOffset` is the address/list object. `FieldEvidence` retains per-field virtual addresses, raw bytes, requested/captured lengths and read status, including partial captures. All interface rows and address rows have provenance; addresses retain device coordinates for association. Addr additionally streams `device_observation` and `address_list_observation` rows, preserving interfaces without addresses and empty/unreadable list roots. These are separate record types, excluded explicitly by the differential mappings. Maps are copied before emission so later reads cannot mutate sealed observations. The summary reports visits, devices, address/interface rows, diagnostic rows and read/layout errors. It is not a claim that an image is intact.

Native `max-nodes=131072` (1..1000000) is a shared namespace/device/address visit bound. Field/MAC captures are capped at 4096 bytes. The IPv4 chain yields at most 129 addresses per device, reflecting the pinned helper's `len(seen) > 128` test. A cycle or excess address becomes a diagnostic and a failed task rather than silently looking complete. Forward doubly-linked walks validate backlinks/tails; they do not reproduce every pinned bidirectional recovery case. Unsupported pre-3.0 IPv6 produces an explicit failed diagnostic, whereas the fixed helper warns and omits that family. Other read/layout errors preserve partial evidence, continue independent devices/families when possible and fail the task. Cancellation/output errors propagate immediately; emitted rows remain in SQLite.

Validation includes:

- 768 pinned flag cases, including all operational/state combinations, composite/zero masks and the gflags spelling; 128 IPv6 scopes; 12 address encodings; six IPv4 chains (empty, cycle and 129/130 limits). Helpers use mocked objects and are checked against the locked Python source tree.
- Native synthetic x64/x86/PAE paging, modern/legacy namespace layouts, differing device namespace pointers, unavailable/zero IDs, permanent/fallback/zero-length MACs, malformed fields, partial reads, missing enums, wrong IPv6 arrays, ambiguous scope aliases, broken list backlinks/tails, bounds, cancellation, output errors, sealed storage and cache reuse.
- The user's Debian image, decompressed SHA256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`: **two interfaces** match all eight Link columns and **four addresses** match all nine Addr columns, including enumeration order. **36 Link and 52 Addr raw captures** are independently reread. Zero diagnostic/read/layout errors occur. [Validation record](linux-ip-validation.json) retains reference manifests and CLI/export checks.

```sh
python3 tools/build_linux_ip_oracle.py --check
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'Test(LinuxIP|OfficialLinuxIP)' -count=1
make check
```

Real modern kernels, native x86/PAE images, unusual link hardware, IPv4 aliases, full corrupted-list behavior and complete version/parameter acceptance remain pending. The Kali user image is ARM64 and still lacks a native translator; this x64 differential does not establish Kali network support.
