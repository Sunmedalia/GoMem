# Linux module load parameters (development preview)

The `linux.check_modules` display decodes module parameters natively, following the handler decisions in `Modules._get_param_val` and `_get_param_handlers` at Volatility 3 v2.28.2 commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`. This is a parameter-decoder validation, not acceptance of the whole plugin or of a real hidden-module scenario.

The decoder reads `module.kp` and `num_kp`, uses the symbol-described `kernel_param` stride, and resolves either an old inline `get` pointer or an explicitly dereferenced `ops` pointer and its `get` member. It recognizes the fixed integer, boolean, inverted boolean, string and array getters. Integer widths, byte order and signedness come from symbols; negative short/int/long values are sign extended, and unsigned values retain all 64 bits. Bool/invbool render `Y`/`N`. Handler aliases preserve the fixed scalar-map insertion order before special boolean rendering.

`FieldEvidence` retains parameter names, getter/ops pointers, scalar bytes, string bytes, array counts, element coordinates and decoded typed values. Keys `param_value@ADDRESS` hold a typed number/string or an explicit missing reason. `param_elements@ADDRESS` retains each array element's decoded value. `None` in the legacy display can therefore be distinguished from an unknown handler, a null getter or an empty array. It is never represented as a fabricated empty string or `<param>` placeholder.

An unreadable value produces a failed task and a missing `Load Arguments` cell. Valid remaining parameters are retained under `FieldEvidence.LoadArgumentsPartial`; failed captures keep requested/captured byte counts, raw partial bytes and an error. Unknown/null getters are explicit unavailable values rather than read errors. Failed tasks are not replayed as completed cache entries.

The fixed string/array algorithm has address choices that are deliberately preserved for differential work: `param_get_string` obtains its bound from `param.str.maxlen` but reads characters at `param.str` itself, without chasing the nested `kparam_string.string` pointer. `param_get_charp` similarly reads at `param.str`, bounded to 256 bytes. Arrays recursively interpret `arr.elem + i*arr.elemsize` as `kernel_param` objects and join their displayed values with commas. The oracle contains cases that distinguish these choices from reading a different target. This does not establish that those choices decode every real kernel module's parameter storage correctly.

Bounds are explicit: at most 128 module parameters, 32 elements per array, 16 recursion levels, 4096 decoded objects per module, 4096 bytes per bounded string and 1 MiB of requested string bytes per module. Cycles, overflows, null nonempty tables and bounds violations fail with retained diagnostics. The baseline may instead return `None`, omit parameters, return a partial string or recurse without these bounds. GoMem's stricter failures are intentional evidence distinctions, not silent parity claims. Missing pages anywhere in a requested string extent remain errors even if a readable prefix exists.

Verification uses 224 deterministic cases across pointer width, endian and getter layout. [The generator](../tools/build_module_params_oracle.py) verifies the pinned source digest and calls the actual upstream handler functions. Its mock boundary supplies byte-backed kernel objects and string reads; it does not replace handler dispatch, scalar selection, bool conversion, array recursion or string address selection. This is independent decision-level evidence, not a real memory-image differential. Go independently interprets the sparse bytes using an ISF fixture, compares typed/displayed values and rereads every successful capture.

```sh
python3 tools/build_module_params_oracle.py --check
go test ./internal/plugins -run 'TestLinuxModule(Params|Argument|Parameter)' -count=1
go test ./internal/engine -run TestLinuxModuleParameter -count=1
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxModuleParameterGraph -fuzztime 5s
```

Synthetic x64/x86/PAE engine tests cover both getter layouts, kernel-address-space proof rereads, byte-identical cache replay, unknown handlers and failed argument reads. Malformed-input tests exercise partial pointers/scalars/strings, missing types, table/array bounds, cycles, recursion and aggregate budgets, overflow and cancellation. The Debian image's `check_modules` result remains a negative control and cannot validate positive parameter decoding. Real kernel/build variations, parameter-array interpretation on real modules and module ELF extraction remain pending. See [validation metadata](linux-module-parameters-validation.json).
