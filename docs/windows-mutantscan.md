# Windows 互斥体池扫描

`windows.mutantscan` 对应固定基线的 `windows.mutantscan.MutantScan`。它用和 `windows.filescan` 相同的池头扫描寻找 `Mut\xe1` 和 `Muta`，雕出 `_KMUTANT`。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.mutantscan --image memory.dmp --case ./case-001 --offline --format jsonl
```

两个标签都要求对象类型是 Mutant。固定基线的 `_KMUTANT` 检查接受每一个雕出来的对象，所以 Windows 8 及以后会保留指针计数落在范围内、类型又匹配的每个对齐位置。名称来自对象头。有 `NameInfoOffset` 成员时用它；否则按 Windows 7 及以后的方式读取 `ObpInfoMaskToOffset`，下标是 `InfoMask & 3`。偏移为 0、长度为 0、最大长度为 0，或者长度大于最大长度，名称不可用，这一行仍然保留。读失败也留在行上，并带上错误，不会写成空名字。摘要行不是互斥体。

官方 Windows 10 19041 样本扫过 6416 个内核范围、387,543,040 字节，得到 742 个互斥体。低 48 位地址和名称与固定基线一致。448 个名称不可用，这些行没有读错误。另有 2199 个候选因为类型不是 Mutant 被丢掉。没有读失败。参考地址丢掉了规范形式的高位，比较时只掩低 48 位。

合成样本覆盖 Windows 10 自上而下的命名互斥体、偏移为 0 的不可用名称，以及类型不符的候选。自下而上的互斥体位置走共享扫描器，没有单独的夹具。32 位真实镜像和 Windows 8 以前的真实镜像还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-mutantscan.jsonl \
  --reference reference-windows-mutantscan.json \
  --mapping docs/diff/windows.mutantscan.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsMutantScan -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.mutantscan.MutantScan` 生成。当前保持 partial、accepted=false。
