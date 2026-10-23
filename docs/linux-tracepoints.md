# Linux tracepoint 检查开发预览

`linux.check_tracepoints` 对应固定 Volatility 3 v2.28.2 的 `linux.tracing.tracepoints.CheckTracepoints`。原生枚举 tracepoint 表、探针函数、优先级、数据指针及模块归属，支持 x64/x86/PAE 和 ARM64，尚未完整验收。

```sh
bin/gomem analyze linux.check_tracepoints --image memory.raw --symbols kernel.json.xz \
  --offline --case case-tracepoints --format jsonl
```

## 布局与显示语义

通过 `__start___tracepoints_ptrs` 的类型选择布局：子类型为名为 `int` 的基础类型时，按有符号四字节 PREL32 解码；其余指针/数组按目标指针宽度读取绝对地址。结束符号为 `__stop___tracepoints_ptrs`，不整除步长的尾部字节保留在摘要中，与固定基线向下取整一致。PREL32 加减溢出明确失败。

绝对数组的上游迭代器产生 Pointer 对象，其 `vol.offset` 是**数组槽位地址**，因此官方 `tracepoint address` 列保留槽位地址；PREL32 迭代器创建实际对象，该列显示实际对象地址。原生额外输出 `TracepointObject` 和 `Slot`，证据坐标始终指向实际对象。

探针数组按声明的 `tracepoint_func` 大小前进，空函数指针结束。缺少 `prio` 时优先级不可用；优先级为零时官方显示也不可用，原生 `RawPriority` 仍保留零；负值按有符号整数输出。`Data` 保留可用的数据指针。名称读取 512 字节，按固定基线在 NUL 或首个 Unicode 替换字符处终止。部分读取保留名称前缀、完整性和错误，任务明确失败。

模块通过真实 Lsmod、SysFs、Scanner 和内核范围收集，选择首个匹配范围，保留重叠匹配。只使用精确地址符号。`Module address` 是模块对象地址，区别于模块加载基址。非内核符号按选中模块对象读取 ELF；固定基线共用 helper 用最后迭代的范围对象，两者有意不同，`symbol_owner_policy` 留存依据。这一差异仍是完整对齐的缺口，未知归属本身不作为恶意判定。

## 证据与边界

`tracepoint_probe` 对应官方七列实体；`probe_observation` 保存无法完整解析的探针；`tracepoint_observation` 保留每个 tracepoint（包含无探针情况）；`tracepoint_read` 保存实际读取的地址、原始字节、请求/采集长度、完整标记和错误。共用模块源记录一并保存。`tracepoints_summary` 记录布局、条目、探针、读取、字节、模块范围及错误计数。所有记录带镜像、地址空间、符号、参数及对象坐标，可从 SQLite 和 JSONL 回溯。

- `max-nodes` 默认 131072，范围 1..1000000，限制模块来源遍历。
- `max-scan-bytes` 默认 256 MiB，范围 1..8 GiB，限制模块分配区扫描跨度。
- `max-tracepoints` 和 `max-probes` 默认 1000000，范围 1..1000000；后者是全局非空探针数。
- `max-bytes` 默认 512 MiB，范围 1..1 GiB，限制累计实际采集字节，包含模块与符号读取。

单次对象可读性探测上限 1 MiB。类型损坏、缺页、空条目、溢出、不可用来源或预算耗尽明确失败，保留已产生的证据。失败任务不能作为成功缓存复用；取消和输出错误立即停止后续输出。模块扫描中的正常候选读洞单独留存，不自动等同于 tracepoint 解析失败。

## 验证与限制

`tools/build_tracepoints_oracle.py` 校验固定源摘要，以真实 ISF 和字节内存层运行未修改的数组遍历、探针遍历、解析及内核符号查询，并从固定源 AST 执行原始结果格式表达式，验证零优先级显示。显式给定内核范围，不 mock 解析方法，也不将该 oracle 视为模块 gatherer 验收。

60 个对象案例覆盖两种指针宽度、两种数组布局及普通、空表、无探针、无优先级、短步长、无数据、空名、损坏 UTF-8、Unicode、跨边界 UTF-8、无终止符、未知归属、无精确符号、负偏移和尾部字节。90 个 x64/x86/PAE 分页案例对照七个官方字段及原始优先级；原始采集独立重读，验证输出不可变、SQLite 封存及缓存 JSONL 逐字节一致。独立完整模块管线测试验证非内核符号与模块对象地址。附加测试覆盖错误类型、缺页、上限、失败重试、部分名称、取消、每个输出边界及 Go fuzz。

Debian 3.2 x64 镜像 SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc` 中，原生检查 202 个 tracepoint，零探针，固定基线也返回 `[]`。检查全部 5128 条实际读取（包含扫描读洞），5879 条证据封存及缓存一致性。这是受支持的空探针对照，**不能证明真实阳性检测能力**。

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_TRACEPOINTS_REFERENCE="$PWD/.cache/tracepoints-validation/reference" \
go test ./internal/engine -run '^TestOfficialLinuxTracepoints' -count=1
```

真实阳性、原生 x86/PAE、并发损坏采集及全部参数/渲染方式仍待验证。Kali 6.8.11 ARM64 本机烟雾运行完成，662 个 tracepoint 产生 13,800 条记录，尚缺独立 ARM64 差分。参见[验证记录](linux-tracepoints-validation.json)和[字段对照配置](diff/linux.check_tracepoints.json)。
