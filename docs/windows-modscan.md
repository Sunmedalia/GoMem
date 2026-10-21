# Windows 模块池扫描

`windows.modscan` 对应固定基线的 `windows.modscan.ModScan`。它用和 `windows.filescan` 相同的池头扫描寻找 `MmLd`，但没有执行体对象类型，对象紧跟在池头后面。页类型是非换页池或空闲池，最小块 76 字节。雕出 `_LDR_DATA_TABLE_ENTRY`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.modscan --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.modscan --image memory.dmp --case ./case-001 --offline --param name=ntoskrnl --param dump=true
```

`DllBase` 和 `SizeOfImage` 必须能读，读失败会让任务失败。`BaseDllName` 和 `FullDllName` 按 `UNICODE_STRING.String` 读取：长度为 0 是空字符串，不读缓冲区；读失败留在行上。对照列去掉错误，和基线的空值对齐，错误留在 `NameError` 或 `PathError`。`name` 是可读基础名的区分大小写子串；基础名读失败时不按这个条件丢掉该行。`base` 精确匹配 `DllBase`，0 不筛选。默认 `dump=false` 时 `FileOutput` 是字面量 `Disabled`。`dump=true` 复用内核层再到已验证会话层的 PE 提取。找不到可读 DOS 头时输出基线的 cannot-find 字符串，重建失败时输出 `Error outputting file`。摘要行不是模块。

官方 Windows 10 19041 样本扫过 6416 个内核范围、387,543,040 字节，得到 177 个模块。低 48 位偏移、基址、大小、基础名、完整路径和 `Disabled` 与固定基线一致。1 个基础名和 20 个路径读失败，对照列为空，错误留在对应的 Error 列。没有因为类型检查丢掉候选，因为这个标签本来就没有执行体对象类型。参考地址丢掉了规范形式的高位，比较时只掩低 48 位。

该原生输入也用于 Windows 自动分诊的模块对象差异检查。选定镜像 176 个活动对象全部匹配，唯一额外候选的名称/路径不可读且基址异常，保留为信息级线索，不能确认恶意模块；详见[模块分诊](windows-module-triage.md)。

合成样本覆盖非换页池中的命名模块、基础名读失败但仍保留的模块、长度为 0 的基础名、换页池候选被丢掉，以及 `name` 和 `base` 筛选。`DllBase` 读失败会使任务失败。`dump` 还没有和固定基线做文件差分。32 位真实镜像和 Windows 8 以前的真实镜像还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-modscan.jsonl \
  --reference reference-windows-modscan.json \
  --mapping docs/diff/windows.modscan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsModScan -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.modscan.ModScan` 生成。当前保持 partial、accepted=false。
