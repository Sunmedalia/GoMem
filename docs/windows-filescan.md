# Windows 文件对象池扫描

`windows.filescan` 对应固定基线的 `windows.filescan.FileScan`。它寻找池标签 `Fil\xe5` 和 `File`，雕出 `_FILE_OBJECT`，输出对象地址和文件名。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.filescan --image memory.dmp --case ./case-001 --offline --format jsonl
```

Windows 10 及以后扫描内核虚拟层，更早的系统扫描物理内存。版本优先用符号里的 PE 版本。没有这份元数据时，存在 `ObHeaderCookie` 视为 Windows 10 及以后，`_HANDLE_TABLE` 没有 `HandleCount` 视为 Windows 8 及以后，存在 `KdCopyDataBlock` 视为 Vista 及以后。Windows 8 及以后按 `InfoMask` 和符号里实际存在的可选对象头自上而下定位对象体，包含填充头。更早的系统按对齐后的 `_FILE_OBJECT` 大小自下而上取对象。64 位指针对齐 16 字节，32 位指针对齐 8 字节。

对象类型必须是 `File`。类型表优先用 `ObTypeIndexTable`，否则用 `ObpObjectTypes`。存在 `ObHeaderCookie` 时，索引用 `(对象头地址 >> 8) ^ cookie ^ TypeIndex` 的低 8 位。`FileName.Length` 为 0，或者文件名缓冲区的第一个字节在内核层读不到，就不是有效文件对象。随后整段文件名读失败时丢掉这一行并计数，不输出空名字。长度为奇数时，末尾那个字节保留为 `U+FFFD`。遇到 NUL 就截断。

扫描范围来自页表。条目完全相同的页表页会跳过。Windows 驻留的 transition 页包含在内。已经列入范围的读取如果不是缺页，会写出诊断并让任务失败；缺页空洞直接跳过。摘要行记录范围数、扫描字节、命中和跳过原因，不计入文件实体。

官方 Windows 10 19041 样本有 6416 个内核范围，共 387,543,040 字节。结果是 4866 个文件，低 48 位地址和文件名与固定基线一致。另外跳过 4118 个类型不符的候选、3 个读不完整的文件名和 1 个无效池头，没有读取失败。参考 JSON 丢掉了规范地址的高位，比较时只掩低 48 位，本地结果仍保留完整地址。其中一个文件名长度是 1，两边都是 `U+FFFD`。

合成样本覆盖 Windows 10 自上而下的类型检查和文件名，以及没有 cookie 时的自下而上雕刻，还有 Vista 前后的池类型极性。32 位真实镜像、Windows 8 以前的真实镜像，驱动、符号链接和模块对象都还没有验收。`windows.hivescan` 仍然只读 `PoolBigPageTable`，不用这次的池头扫描恢复 hive。

```sh
python3 tools/diff_results.py \
  --native native-windows-filescan.jsonl \
  --reference reference-windows-filescan.json \
  --mapping docs/diff/windows.filescan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestFileScanKnownOffsets|TestOfficialWindowsFileScan' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.filescan.FileScan` 生成。当前保持 partial、accepted=false。
