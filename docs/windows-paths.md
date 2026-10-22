# Native Windows module names and Unicode casing

`pkg/winpath` supplies host-independent Windows basenames, full Unicode lowercase and first-character uppercase, and the locked PE-symbol helper's PDB-name candidates. The suspended-thread collector uses it before grouping module instances or selecting PDBs. Python is a development reference only.

The previous implementation split only on separators, used Go's simple lowercase mapping, removed the last three UTF-8 bytes, and uppercased one byte. This produced incorrect UNC/drive basenames, lost multi-character mappings and could split a Unicode character. The replacement handles Windows drive-relative, UNC and device paths, both separators and empty basenames. Candidate construction removes three Unicode characters, then uppercases the entire first character mapping, including expansions such as `ß` to `SS`.

## Fixed casing semantics

The implementation explicitly uses Unicode **16.0.0**, matching the local Python 3.14 reference. It does not inherit the host OS locale or whichever Unicode version a Go toolchain provides. UnicodeData supplies simple mappings, SpecialCasing supplies unconditional full mappings, and DerivedCoreProperties supplies `Cased` and `Case_Ignorable`. Default-language Final Sigma uses the original input's context, skipping case-ignorable characters. Language-specific Turkish, Azeri and Lithuanian conditional mappings are excluded, as with Python's locale-independent `str.lower()`.

The lowercase implementation computes right-hand contexts once, then walks forward. Long combining-character runs do not cause repeated rescanning. Generated sorted tables are private; callers cannot mutate them. `Lower` and `Basename` interpret Go strings as Unicode characters, replacing invalid UTF-8 sequences; `UpperInitial` expects a Unicode string and preserves bytes after its first character. These APIs do not read memory or access the filesystem. Acquisition limits and failures remain the caller's responsibility.

`tools/build_unicode_case_tables.py` downloads only the three Unicode 16 data files when missing, bounds each download, verifies fixed SHA256 digests, and checks or regenerates the Go source deterministically. Generated data is distributed under [Unicode License V3](../LICENSES/Unicode-3.0.txt); native handwritten code retains the repository's MIT license. Source digests are recorded directly in the generator.

## Independent validation

`tools/build_windows_path_oracle.py` verifies the locked Volatility tree and calls the actual `PESymbols.filename_for_path` and `_get_pdb_module` methods. For candidate-construction tests, only the PDB-acquisition boundary is replaced to record requested names and return unavailable; these are helper controls, not successful PDB-conversion controls. The 1,109 paths cover drive/share-only inputs, device and mixed separators, short names, non-BMP characters and Unicode mappings. Eighty-seven independent casing strings cover Final Sigma and intervening combining marks, joiners and punctuation.

A separate Python 3.14 / Unicode 16 reference evaluates **all 1,112,064 Unicode scalar values**, excluding surrogate code points. It records nonidentity mappings and contextual casing properties inferred independently from Python's string behavior. Native tests compare lowercase, first-character uppercase and effective casing/ignorable properties for every scalar, including identity/default cases. This is a scalar/property conformance result, complemented by contextual-string tests; it is not a claim that every possible string was enumerated. A 65,536-character combining run checks nonquadratic context handling. Fuzzing exercises arbitrary paths, invalid UTF-8, output validity and expansion bounds.

The actual paged suspended-thread generator also covers `ß.dll` selecting `SS.pdb`, a short Unicode basename selecting `pdb`, and an UNC share-only path selecting an empty module basename. With these additions there are **36 actual generator cases and 54 native x86/PAE/x64 combinations**, with all nine baseline columns, missing values, independent acquisition rereads and sealed case JSONL comparisons. The supplied Windows image still provides a negative suspended-thread control, documented in [windows-suspended-threads.md](windows-suspended-threads.md).

```sh
python3 tools/build_unicode_case_tables.py --check
.cache/reference-venv/bin/python tools/build_windows_path_oracle.py --check
# Requires Python 3.14 with Unicode 16.0.0:
python3 tools/build_windows_path_oracle.py --full --check
go test -race ./pkg/winpath
go test ./pkg/winpath -run '^$' -fuzz FuzzWindowsModulePath -fuzztime 10s
.cache/reference-venv/bin/python tools/build_suspended_threads_oracle.py --check
```

CI retains Python 3.12 for existing acceptance tooling and uses a separate Python 3.14 job to reproduce the complete scalar reference. Normal native builds need neither Python nor Unicode source downloads.

The locked upstream PDB scanner encodes candidate names as Latin-1 and decodes matched names as UTF-8. Some Unicode candidates therefore raise encoding/decoding errors before lookup. Helper parity does not establish arbitrary Unicode PDB acquisition, and the new end-to-end controls specifically use candidates that the upstream pipeline can acquire. Real Unicode-module corpora, compatibility across other Python Unicode versions, unusual RSDS layouts, full symbol-dependent caching and complete plugin acceptance remain pending. This change closes filename helper gaps without adding a newly accepted plugin. Measurements are recorded in [windows-paths-validation.json](windows-paths-validation.json).
