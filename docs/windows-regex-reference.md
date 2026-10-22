# Windows VAD regex reference (implementation pending)

`tools/build_windows_regex_oracle.py` executes the unmodified Windows
`vadregexscan.VadRegExScan` generator from Volatility 3 v2.28.2, commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. It verifies the pinned source-tree
digest and requires Python 3.12. Python remains a development dependency.

```sh
uv run --no-project --python 3.12 python tools/build_windows_regex_oracle.py --check
```

The fixture in `internal/engine/testdata/windows-regex-oracle.json` contains
39 cases using actual byte-backed EPROCESS, VAD and process-layer objects over
x86, PAE and x64 translation. Process enumeration, VAD traversal, translation,
scanner and result extraction methods are not mocked. The process/VAD layout
comes from the existing suspended-thread oracle fixture; scan pages are
independently mapped with small page entries.

The 27 selected result rows cover literal bytes, DOTALL extraction differences,
backreferences, lookbehind, UTF-8 patterns, invalid bytes, context truncation and
zero-width matches. Other cases preserve missing pages, absent VADs, signatures
crossing a VAD boundary and six syntax failures across the three architectures.
An invalid pattern still fails when a Windows process has no VADs: its scanner
is constructed for an empty section list. Linux's null-mm early skip therefore
cannot be reused for this case. Windows also reads 128 context bytes despite
the advertised `maxsize`, set to four in every case.

These are baseline expectations for the next native implementation. They do
not establish native Windows VAD regex support, real-image acceptance, storage,
cache, renderer or export parity. The plugin remains missing in the capability
matrix. Native kernel and Linux VMA scanning have a separate
[implementation and validation record](regex-scanning.md).
