# Windows 符号链接池扫描

`windows.symlinkscan` 对应固定基线的 `windows.symlinkscan.SymlinkScan`。它用和 `windows.filescan` 相同的池头扫描寻找 `Sym\xe2` 和 `Symb`，但页类型是换页池或空闲池。Windows 10 上奇数 `PoolType` 才是换页池。雕出 `_OBJECT_SYMBOLIC_LINK`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.symlinkscan --image memory.dmp --case ./case-001 --offline --format jsonl
```

两个标签都要求对象类型是 SymbolicLink。固定基线的检查接受每一个雕出来的对象。来源名是对象头 `NameInfo.Name`，不做互斥体那种长度和最大长度比较。长度为 0 的名字是空字符串。名字信息偏移为 0，或者名字读失败，丢掉整行。目标是 `LinkTarget`。长度为 0 时不读缓冲区，保留空字符串；读失败丢掉整行。创建时间是 `CreationTime.QuadPart` 的 Windows FILETIME，不右移。这次读取失败会让任务失败，而不是跳过该行。秒数为 0 记为未设置，年份超出 1 到 9999 记为不可解析。时间线还没有做。摘要行不是符号链接。

官方 Windows 10 19041 样本扫过 6416 个内核范围、387,543,040 字节，得到 219 个符号链接。低 48 位偏移、创建时间、来源名和目标名与固定基线一致。其中一个目标是空字符串。12 个名字或目标读失败的候选被丢掉。另有 523 个候选因为类型不是 SymbolicLink 被丢掉。扫描本身没有读失败。参考地址丢掉了规范形式的高位，比较时只掩低 48 位。年份窗口用运行时的本地年，这次对照在 2026 年。

合成样本覆盖换页池里的命名链接、长度为 0 的目标和来源名、名字偏移为 0 而被丢掉的链接、目标地址无效而被丢掉的链接，以及非换页池候选。创建时间读失败会使任务失败。自下而上的路径走共享扫描器，没有单独夹具。32 位真实镜像和 Windows 8 以前的真实镜像还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-symlinkscan.jsonl \
  --reference reference-windows-symlinkscan.json \
  --mapping docs/diff/windows.symlinkscan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsSymlinkScan -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.symlinkscan.SymlinkScan` 生成。当前保持 partial、accepted=false。
