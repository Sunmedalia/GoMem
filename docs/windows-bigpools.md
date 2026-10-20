# Windows 大页池表

`windows.bigpools` 对应固定基线的 `windows.bigpools.BigPools`。它读取 `PoolBigPageTable`，按 `_POOL_TRACKER_BIG_PAGES` 列出大页分配。没有调用 Python、Volatility 或目标系统代码，也不加载基线在类型缺失时使用的备用符号 JSON。

```sh
bin/gomem analyze windows.bigpools --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.bigpools --image memory.dmp --case ./case-001 --offline --param show-free=true --param tags=CM10,MmLd
```

`PoolBigPageTable` 始终按 8 字节 `unsigned long long` 读取，`PoolBigPageTableSize` 按 4 字节 `unsigned long` 读取，32 位符号也一样。`Key` 为 0 的条目直接跳过。`Va` 最低位为 1 表示已释放。默认 `show-free=false` 不输出这些行；打开之后 `Allocation` 仍保留这个最低位。状态是 `Allocated` 或 `Free`。

标签是 `Key` 的四个小端字节，只留下严格大于 32 且小于 127 的字节，其余字节删掉而不是替换。结果可以是空字符串。`tags` 是逗号分隔的精确列表，不去空格；空字符串表示不筛选。比较的是处理之后的标签。

`PoolType` 用 `_POOL_TYPE` 的名字。同一个数值有多个名字时保留字母序的第一个，和这份 ISF 里 293 个已排序枚举的选择一致。不认识的值写成 `Unknown choice N`。没有 `PoolType` 或 `NumberOfBytes` 成员时，单元格是不适用，不是 0。有 `PoolType` 成员但符号里没有 `_POOL_TYPE` 时，任务失败。这两个字段读失败会让任务失败。`show-free=false` 时，已释放的行在读字节数之前就丢掉，所以它的缺页不会失败；`show-free=true` 会先读字节数。标签对不上的行不再读后面的字段。

`max-entries` 默认 2000000，范围 1..5000000。表长超过上限时失败，不截断。这是本地保护，不是上游参数。摘要行不是分配。

官方 Windows 10 19041 样本的大页表有 32768 条。默认参数得到 7425 个仍在使用的分配，和固定基线逐行一致：完整分配地址、标签、池类型、字节数和状态都相同。另外 1543 条已释放，23800 条 `Key` 为 0。没有读失败。地址保留了规范形式的高位，这次没有做低 48 位掩码。样本里有 `NonPagedPoolNx`、`PagedPool`，也有 `Unknown choice 1025` 这类基线原样输出的未知值。`show-free` 和 `tags` 只在合成样本里验证，没有拿这张崩溃转储再跑一遍对照。

合成样本覆盖一个已分配的 `CM10`、一个默认隐藏的释放行、`Key` 为 0、不可打印字节被删短的标签、`NonPagedPoolNx`、重复枚举值里的 `NonPagedPool`、`Unknown choice`、`show-free`、精确标签和带空格的标签。32 位指针宽度下，表指针仍读 8 字节，低 4 字节单独看会指错地方。没有 `_POOL_TRACKER_BIG_PAGES` 时明确失败。缺 `PoolType` 成员时该列不适用。真实 32 位镜像和 Vista 以前的布局还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-bigpools.jsonl \
  --reference reference-windows-bigpools.json \
  --mapping docs/diff/windows.bigpools.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsBigPools|TestOfficialWindowsBigPools' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.bigpools.BigPools` 生成。当前保持 partial、accepted=false。
