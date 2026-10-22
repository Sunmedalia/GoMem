# Native console screen reader (development dependency)

`pkg/winconsole.ScreenReader` reads `_ROW` character cells and circular
`_SCREEN_INFORMATION` buffers using the fixed Volatility 3 v2.28.2 source,
commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`. It is a component used by the
[partial native `windows.consoles` plugin](windows-consoles.md). Component
controls alone do not establish full plugin, real screen recovery or release
acceptance.

`ParseScreenLayout` consumes the screen fields from an original data-only ISF
and keeps its exact SHA-256. Newer `_ROW` definitions include negative offsets;
a dedicated adapter checks subtraction and addition without changing the
general ISF parser. Both pointer-row arrays and inline-row arrays use their
declared strides. Field types, little-endian x64 pointers and three-byte cells
are checked before reads. The pinned catalogue can supply its original `Data`
to the parser; layout matching and acquisition remain the caller's responsibility.

`Row` preserves the original three-byte cells and their address. Text follows
the original DBCS allowlist and rejects cells whose UTF-16 high byte is nonzero;
this intentionally excludes many non-Latin characters from the display. Raw
bytes remain available. Embedded NULs are preserved. Optional right trimming
includes Python's U+001C–U+001F whitespace behavior. The raw cells are never
replaced by filtered display bytes.

`Dimensions` uses the first physical row's `RowLength2` and the buffer capacity,
matching `ScreenX`/`ScreenY`. `Buffer` follows `(BufferStart + i) % capacity`,
including Python's modulo for negative starts. Line and trailing-row trimming
are independent. `AcquiredRows` retains raw bytes for rows removed from `Rows`
by display trimming. Failed reads return the acquired prefix and an error; `FailedRow` retains
a partial cell read, including its original coordinates.
Callers can supply a traced memory layer for metadata/read evidence.

Every call requires explicit bounds: at most 32,767 rows/cells and at most
16 MiB of total cell bytes per buffer. Per-row reads remain bounded. Exact byte
budgets permit subsequent zero-length rows. Invalid lengths/capacities, bounds,
signed-address overflow/underflow and cancellation remain errors. The default
zero-valued limit structure is invalid.

## Verification

`tools/build_console_screen_oracle.py` executes the actual unmodified
`ROW.get_text`, `SCREEN_INFORMATION.ScreenX`, `ScreenY` and all four
`get_buffer` trimming combinations. There are 209 byte-backed controls
(11 original layouts × 19 scenarios), or 1,672 original method results.
No analysis methods are mocked. The bundled 25398 layout is a component control;
the baseline selector maps build 25398 to the 22000 layout.

Controls cover circular/negative/large starts, zero/negative capacities, all
256 DBCS attributes, high-byte characters, NULs, Python whitespace, empty rows,
trailing rows and metadata/cell holes. Native tests compare dimensions, text
and ordering, independently reread each acquired cell capture, and test exact
budgets, partial prefixes, cancellation during reads and malformed layouts.

Two differences are intentional and explicitly checked:

- The original byte-backed layer accepts negative read lengths as empty slices.
  Native rejects a negative row length, retaining only the previously acquired
  rows instead of appending an empty row.
- The original silently stops when a row fails and treats a negative capacity
  as an empty iteration. Native returns an error with any acquired prefix.

Package race tests and native source-layout digest checks pass. The memory
pipeline fuzz target passes 10,000 executions; the signed layout parser target
passes at least 1,000 executions. CI regenerates the oracle, runs package race
checks and includes both fuzz targets. These finite synthetic controls do not
establish real-image, plugin, renderer/export or performance acceptance.

See [machine-readable validation](windows-console-screen-validation.json),
[command history scanning](windows-cmdscan.md) and
[layout acquisition](windows-console-layout.md).

The subsequent [console object reader](windows-console-objects.md) adds titles,
validity, scalar metadata and list primitives; full plugin integration remains
pending.
