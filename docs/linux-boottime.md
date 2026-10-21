# Linux 启动时间和时间命名空间

`linux.boottime` 对应固定基线 `linux.boottime.Boottime`。原生读取内核时钟及时间命名空间，不调用 Python。

```sh
bin/gomem analyze linux.boottime --image memory.raw --symbols exact.json.xz --case ./case-001 --offline --format jsonl
```

遍历默认活动任务链，不包含 init_task 或额外用户线程。按第一次遇到的时间命名空间 ID 去重，保留任务枚举顺序；同一 ID 的后续任务不会再次读取时间偏移。旧内核没有 task.nsproxy 或 nsproxy.time_ns 字段时，以及 time_ns 指针为空时，使用 None 去重键和根时钟。真实 ID 0 与 None 是不同的键，但上游 TIME NS 列将二者都显示为不可用；原生的 NamespaceID 和 NamespaceState 保留区别。

根启动时间支持 tk_core.timekeeper.offs_real-offs_boot（标量或 tv64）、旧 timekeeper 的 wall_to_monotonic/total_sleep_time，以及更旧的全局 wall_to_monotonic 和可选 total_sleep_time（timespec 或秒）。声明存在但读取失败时不会换成另一个时钟。每个命名空间的 offsets.boottime 从根启动时间中减去，支持负偏移。没有 offsets 成员是已知的零偏移，读取失败不能当作零偏移。

所有时钟计算使用任意精度整数纳秒。Boot Time 按固定 Python datetime 行为，将秒加小数转换为 binary64，再舍入至微秒；这层兼容显示与精确值分开。BootTimeExact 保留有效 UTC 日期的纳秒，BootEpochNS 保留整数计算结果。零/负时间或越过 UTC 年份 9999 的显示为 unparsable_boot_time，原始数值仍可审查。TIME NS 和 Boot Time 是两个上游对照列。

ClockEvidence 保留根时钟来源、字段地址、原始字节和 RootEpochNS；NamespaceEvidence 保留 nsproxy/namespace 地址、ID、offset 原始捕获及请求/实际长度、读取状态和纳秒值。TaskOffset、RepresentativePID 表示所选的第一个任务。原生行还提供 TimelineType=CREATED 及与基线相同的事件描述。全局 timeliner 聚合命令仍待实现，这些字段可通过现有 JSONL、HTML 或证据包导出。

原生 `max-nodes` 默认 131072。namespace/偏移读取失败会输出 diagnostic，保留已取得的元数据及偏移字节，继续其他命名空间，最终任务失败。偏移失败后该 ID 仍已去重，后续同 ID 不会代替第一次观察。结构性任务链、时钟解析、遍历界限、取消和输出故障会直接终止。原生拒绝坏纳秒值和声明了新布局却为空的 nsproxy；上游可能规范化坏时间或尝试从零地址读取，这些损坏场景不宣称已对齐。

summary 的 tasks 是访问任务数，namespaces 是首次遇到的命名空间键数（包括偏移读取失败的已知 ID），duplicates 是重复键数，times_read 是已输出时间观察数，unparsable_times 是其中日期不可解析的数量，diagnostics 是命名空间/偏移读取诊断数。summary 和 diagnostic 均不是启动时间实体。

## 验证与缺口

固定源码产生 79 个时间显示用例和 6 个命名空间分组用例，覆盖微秒边界、binary64 舍入、零/负及超大日期、None 与 0、去重和顺序。合成原生对象覆盖多个命名空间、正/负偏移、无 offsets、坏指针/ID/纳秒、重复 ID 的偏移短路、旧/新时钟 ABI、x86/PAE 页表、参数边界、取消、输出错误、SQLite 每行封存核验和复用。

现有 Debian 3.2 x64 镜像（SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`）中，133 个任务归于一个旧内核默认时间命名空间。未修改的固定 Volatility 和 GoMem 都显示 `2014-06-24T10:22:33.691776Z`，原生另保存精确值 `2014-06-24T10:22:33.691776031Z`、132 个重复键、0 个读取诊断。真实案件回读和缓存验证通过，最终 CLI 新任务/缓存 JSONL 逐字节一致，独立证据包校验及 make check 通过；详情见 [验证记录](linux-boottime-validation.json)。该样本没有现代时间命名空间，不构成现代版本验收。

```sh
.cache/reference-venv/bin/python tools/build_boottime_oracle.py --check
go test ./internal/plugins ./internal/engine -run 'TestLinuxBootDisplay|TestLinuxBoottime' -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxBoottime -count=1 -v
```

现代真实命名空间、实际 x86/PAE 镜像、ARM64、全局时间线聚合、完整损坏链/布局/版本条件仍待验收。矩阵保持 partial、accepted=false。
