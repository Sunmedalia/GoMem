# Windows network reference preparation

`windows.netscan` and `windows.netstat` remain **missing** in the capability
matrix. These reference artifacts and the native `pkg/winnet` field decoder
prepare their plugin implementations; they do not constitute native network
acquisition, complete plugin parity or release acceptance.

`tools/build_windows_network_oracle.py` runs the unmodified network extension
methods from the locked Volatility 3 v2.28.2 tree. All 25 shipped network ISF
layouts are loaded by the actual intermediate symbol table, with a separate
minimal kernel table and its actual `EPROCESS` extension. Original buffer
bytes, pointer widths, layout source digests and declared sizes are retained.
No network method, field reader or validity function is replaced.
The physical byte-buffer layer uses the layout's full 32/64-bit address mask;
its actual reads are delegated unchanged and failed read coordinates are
recorded. This prevents a small fixture buffer from masking an intentionally
unavailable pointer into readable address zero.

The 1,200 cases exercise listeners, TCP endpoints and UDP endpoints, IPv4 and
IPv6, and eight scenarios: normal, wildcard local address, unavailable local
address, invalid address family, invalid TCP state, null owner, zero creation
time and unavailable address-family structure. Every normal case has an actual
valid System process owner with PID 4. Ports use the layout's big-endian fields.
Methods preserve absent values and exceptions rather than converting them into
empty records. TCP states, address strings, wildcard/dual-stack expansion and
creation times are reference observations for subsequent Go comparisons.
All 150 normal cases have no failed source reads; all 300 unavailable-address
cases have recorded actual source read failures. The generator is checked under
Python 3.12 (CI) and Python 3.14 locally. See the [validation record](windows-network-reference.json).

The native decoder passes selected decoding comparisons across all 1,200
cases using the original layout files, each checked against its reference
digest. Comparisons cover family, ports, TCP state, local/remote IPs and socket
expansion, including missing data and class-extension failures. Raw owner
addresses and creation counters are checked against the original fixture
bytes. Kernel process validity, owner PID/name attribution, timestamp conversion
and network `is_valid()` are not implemented by this component.

Declared sizes remain unchanged. The dedicated network layout reader permits
outlying members with independent bounded offsets, lengths and original-source
reads; the general ISF/object reader keeps its existing bounds. Layout input is
limited to 4 MiB, field extents to 1 MiB and nesting to 64 levels. End-address
overflow, truncated reads and cancellation remain errors. Wildcard fallback
results retain actual read errors instead of becoming successful absence.
Malformed/bounds tests and a 100,000-input layout fuzz run pass locally.

```sh
GOMEM_BASELINE_DIR="$PWD/.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75" \
  go test -race ./pkg/winnet -count=1
```

The original-layout comparison skips when this variable is absent. CI sets it
explicitly after fetching the pinned tree; an optional local skip does not
establish acceptance.

The catalog contains important conditions a native implementation must retain:

- Some field extents exceed the declared type size, including Windows 10 TCP
  owner/time members, address-info fields and IPv6 arrays. Declared allocation
  size and independently bounded field reads must be treated separately.
- The shipped `netscan-win10-19041-x86` UDP layout refers to a class extension
  which the general x86 class map does not install. Its 14 socket-method calls
  raise `AttributeError`; the fixture retains these errors. The pinned version
  selection map does not select this file for x86. Merely loading every shipped
  file is therefore not proof that the version factory supports every layout.
- All 50 intentionally invalid TCP state observations retain `ValueError`.
  The complete plugin generator handles this separately from these object
  methods; object-method observations are not full-generator comparisons.

```sh
python3 tools/build_windows_network_oracle.py --check
```

A separate unmodified `windows.netscan.NetScan` run on the official Windows 10
19041 control produced 108 rows: 40 TCPv4, 10 TCPv6, 42 UDPv4 and 16 UDPv6.
The ignored output/config/manifest are under `.cache/netscan-validation`.
There is no native full-image comparison yet. Version selection, TCP/IP symbol acquisition,
pool carving, owner provenance, read failures, `include-corrupt`, timeline/export
semantics, NetStat traversal and native malformed-input controls remain open.
