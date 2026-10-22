# Windows pool-header reference

`tools/build_pool_header_oracle.py` executes the actual `PoolHeaderScanner`,
`PoolScanner.builtin_constraints` and original `POOL_HEADER` / `POOL_HEADER_VISTA`
extensions from Volatility 3 v2.28.2, commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. The generator verifies the complete
pinned Python source-tree digest before execution. It uses real byte-backed ISF
objects and does not mock header fields or scanner methods.

```sh
uv run --no-project --python 3.12 python tools/build_pool_header_oracle.py --check
go test -race ./internal/plugins -run '^TestPoolHeadersActualPinnedScanner$'
```

The fixture compares all 15 built-in tag constraints, object/structure names,
object-type checks, minimum/maximum sizes, skip-type flags and additional
structures. It exercises 1,440 actual headers across four layouts: 32/64-bit
alignment and pre-Vista/Vista pool classification. For every constraint,
allocation sizes immediately below, at and above the minimum are tested with
free, paged, nonpaged and higher-bit pool-type values. Native tests decode the
same bytes through `object.Reader` and compare size acceptance and individual
pool classifications against the actual reference scanner.

The shared native pool implementation already supports process, thread, file,
mutant, driver, module, symbolic-link and hive consumers. This record establishes
only the built-in constraints and header-filtering boundaries. It does not
establish standalone `windows.poolscanner` support, complete object carving,
object validity/type checks, optional-header handling, GUI pool constraints,
version/image coverage, renderers or exports. The standalone official plugin
remains missing in the capability matrix until implemented and independently
validated. Python and Volatility remain development tools only.
