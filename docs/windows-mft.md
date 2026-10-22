# Windows MFT candidates and resident streams (development preview)

The native Go commands `windows.mftscan`, `windows.ads` and `windows.residentdata` implement the fixed Volatility v2.28.2 `windows.mftscan` classes. They carve physical memory candidates. Kernel symbols and virtual translation are unnecessary; RAW input needs the Windows OS selection if discovery cannot identify it.

```sh
bin/gomem analyze windows.mftscan --image memory.raw --os windows --offline --case case-001
bin/gomem analyze windows.ads --image memory.dmp --offline --case case-002 --format jsonl
bin/gomem analyze windows.residentdata --image memory.dmp --offline --case case-003 --format jsonl
```

These are physical candidates, not proof of current filesystem membership. An alternate stream does not establish malicious intent. The commands do not reconstruct a filesystem, apply/validate NTFS fixups or recover nonresident runs.

## Selection and pinned behavior

The fixed patterns are the exact bytes `FILE0`, `FILE*` and `BAAD`. Native scanning requires no runtime YARA library. It uses the pinned scanner's 16 MiB windows and 4 KiB forward overlap, retaining repeated overlap matches in order. The final window follows the actual upstream iterator's variable step, including its extra overlap when the remaining span is only slightly larger than 16 MiB. Adjacent physical ranges join; gaps do not contribute synthetic signature bytes. Container-specific scan traversal still needs broader acceptance.

MFT records retain signature, record number, link count, flags and the declared first attribute. Attribute traversal follows declared positive lengths until an unrecognized type or read failure. A zero-length attribute is included once, then fails coverage. Limits and checked address arithmetic prevent unbounded chains. RealSize/AllocatedSize do not confine the pinned walk. Unrecognized terminating type bytes are not interpreted as valid attributes.

The pinned auxiliary ISF declares attribute types, MFT flags and permission enums as one-byte values. Native results preserve that interpretation and also retain the full original type/permission/flag words. This includes unknown values rendered as hexadecimal. SI and FILE_NAME payloads start at attribute +24 regardless of the declared content offset. Resident DATA uses its declared content offset and length. Metadata structs are read only for the command that needs them.

`windows.mftscan` emits all standard-information rows before file-name rows for each candidate. Four FILETIME values are converted at whole-second precision; raw ticks remain lossless values. Zero subsecond-only times are not applicable; out-of-range dates are unparsable. UTF-16 names honor BOMs, replace malformed surrogates and stop at NUL. Empty names remain empty strings. Filename rows reproduce the baseline TreeGrid parent behavior, including attachment to a preceding result when a record has no SI row. `RecordOffset` retains the actual source record independently of that display hierarchy.

`windows.ads` emits every resident named DATA attribute. `windows.residentdata` emits only the first resident unnamed DATA attribute, even if its content is unavailable. Neither command falls back to nonresident data. The longest decoded filename wins; equal lengths keep the first encountered name. The resident command preserves the baseline's literal `N/A` filename fallback, while ADS uses typed missing. `FilenameAvailable` distinguishes that fallback from an acquired name.

Resident content is limited to the pinned 4 MiB bound. Its exact bytes, original offset and declared length remain evidence. Empty content reproduces the baseline's unavailable Hexdump cell with `ContentLength=0`; this differs from unreadable content, which retains a read error and fails coverage. The ResidentData JSON renderer's `N/A` Hexdump token is explicitly normalized only in that field's diff profile. Available bytes are compared exactly, not as display text. JSON evidence uses lossless base64 bytes.

## Evidence, limits and failures

Candidate and attribute records retain original coordinates and raw header metadata. Each parsed source acquisition becomes a `memory_read`, including requested/captured lengths, bytes and errors. Large scan windows use `scan_read` records with original coordinates, lengths and SHA256, avoiding a second complete image copy in SQLite. Their bytes can be reread from the image bound by its task SHA256. Scan hashes do not replace the raw parsed-field captures.

Default task bounds are 100,000 candidates, 1,000,000 attributes, 512 MiB parsed reads and 64 GiB actual scan reads including overlap. A single record is additionally bounded to 1,048,576 attributes. Candidate repeats count separately. `max-records`, `max-attributes`, `max-read-bytes` and `max-scan-bytes` expose these controls. Partial results and acquisition diagnostics persist; failed tasks are not cached as completed. Cancellation or emitter failure stops further reads and output. A hard acquisition stop can precede the terminal summary; the task error remains explicit.

## Validation

The pinned unmodified YARA scanner and all three actual generators run over 70 byte-backed cases each, using development `yara-x==1.9.0`. Cases cover both signatures, FILE0/FILE*, 16 MiB/partial-window overlap repeats, SI/file names, multiple/empty/nonresident streams, missing pages, truncated headers, invalid UTF-16, NUL names, unknown/wide enum values, zero-length attributes and time/content bounds. Native package and engine tests compare columns, order, hierarchy and resident bytes; every acquisition is independently reread, then sealed SQLite results and successful cache replays are checked. Failed tasks must execute fresh. Separate tests exercise resource limits, short source reads, cancellation and emitter failure at each output stage.

On the Windows 10 19041 bitmap crash dump with SHA256 `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`, all selected baseline results match:

| Command | Results | Parsed source reads | Captured bytes |
| --- | ---: | ---: | ---: |
| `windows.mftscan` | 16,370 | 85,112 | 2,122,574 |
| `windows.ads` | 5 | 79,864 | 1,954,540 |
| `windows.residentdata` | 925 | 80,387 | 2,069,478 |

Each task observes 5,585 candidates and 23,232 attributes, with 251 scan acquisitions totaling 2,094,338,048 bytes including overlap. Seven original reads fail. Eleven candidate diagnostics include those faults and four zero-length attributes; the summary counts 18 error events because acquisition and candidate errors are separately retained. All three tasks remain failed/partial, and the matched results do not establish exhaustive coverage.

The independent verifier uses original image reads plus the exact upstream auxiliary ISF, without the native NTFS candidate parser. It verifies seals/provenance, every raw capture and scan digest, typed baseline result fields, attribute-chain membership, resident stream selection, names, bytes, source coordinates and baseline hierarchy. It does not claim to prove candidate completeness or full filesystem integrity. Its auxiliary ISF SHA256 is `12b8ede2f1c5c43ba2af1f7c550153bd3afd8bac90d36014c05155c51534da36`; the table has no pointer fields and needs no invented kernel pointer architecture.

```sh
.cache/reference-venv/bin/python tools/build_mft_oracle.py --check
go run ./tools/verify_mft --plugin windows.ads --image MEMORY \
  --layout PINNED_SOURCE/volatility3/framework/symbols/windows/mft.json --jsonl NATIVE.jsonl
python3 tools/diff_results.py --native NATIVE.jsonl --reference REFERENCE.json \
  --mapping docs/diff/windows.ads.json --output diff.json
```

Pipeline fuzzing passed 311,786 executions and the parser entry passed 4,189,889 executions in ten-second runs. Real x86/PAE, additional Windows versions/formats, timeline integration, full renderer/export acceptance and investigative positive/normal controls remain pending. See [machine-readable validation](windows-mft-validation.json).
