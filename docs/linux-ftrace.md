# Linux ftrace 检查开发预览

`linux.check_ftrace` 对应固定 Volatility 3 v2.28.2 的 `linux.tracing.ftrace.CheckFtrace`。枚举 `ftrace_ops_list` 到 `ftrace_list_end`，解析回调、过滤函数和 flags，并通过原生模块枚举、sysfs、分配区扫描及内核范围关联回调归属。仅支持固定基线声明的 Intel x64/x86/PAE；尚未完整验收。

```sh
bin/gomem analyze linux.check_ftrace --image memory.raw --symbols kernel.json.xz \
  --offline --case case-ftrace --param show-ftrace-flags=true --format jsonl
```

`show-ftrace-flags` 对应上游 `show_ftrace_flags`，默认 false。无论展示开关，`RawFlags` 保留原值；开启后 `Flags` 以固定顺序显示基线定义的 19 个 `FTRACE_OPS_FL_*` 名称，未知位不添加推测性名称。

## 遍历与证据

支持旧式 `ftrace_ops.filter_hash`，以及新式指针或内嵌 `func_hash`。`filter_hash` 和 `buckets` 也通过类型明确区分指针/内嵌结构。只遍历 `buckets.first` 的链表，**不会遍历其余哈希桶**，与固定基线一致。因此没有实体行不能证明所有过滤桶均为空。节点坐标直接转换为 `ftrace_func_entry`，保留基线的零偏移转换行为。

`ftrace_hook` 是官方结果对应的实体行；附加 `Hook address`、`Entry`、原始 flags 和范围匹配证据。`ftrace_ops` 保存每个操作对象的检查结果，空过滤链也保留观察；`ftrace_read` 记录所有实际内存读取的地址、原始字节、请求/实际长度、完整标记和错误。模块源观察与诊断沿用共用实现。`ftrace_summary` 记录操作/节点/输出/读取计数、预算及不完整状态。字段和记录可追溯到镜像、虚拟层、参数、符号摘要及对象地址；任务失败时仍保留已产生的证据。

回调按第一个匹配的模块范围关联，重叠范围均保留。内核回调使用第一个精确地址符号；被挂接地址保留全部精确别名并以逗号连接。没有精确符号时标记缺失，不把相邻函数名称作为解析结果。不对模块外回调直接作恶意判定。

非内核回调沿用原生共用解析策略：从**选中的匹配模块对象**读取 ELF 符号。固定基线 `module_lookup_by_address` 的循环结束后却用最后一个范围的对象解析非内核符号；两者有意不同。`symbol_owner_policy` 保留选中对象、基线末对象及差异标记。原生完整管线测试覆盖 active 模块回调及 `module_entry`，但不将该行为差异计为完整对齐。

## 边界与失败

- `max-nodes` 默认 131072，范围 1..1000000，限制模块来源及各条链表遍历。
- `max-entries` 默认 1000000，范围 1..1000000，限制全局过滤节点数。
- `max-scan-bytes` 默认 256 MiB，范围 1..8 GiB，限制模块分配区扫描范围。
- `max-bytes` 默认 512 MiB，范围 1..1 GiB，限制累计实际采集字节，包含模块来源和符号读取。

单次对象可读性探测限制为 1 MiB。循环、空指针提前终止、损坏类型、缺页、不可用来源和资源上限均明确使任务失败。固定基线有些场景静默结束或跳过，原生保留诊断，不伪装为成功的空结果；失败任务再次运行创建新任务，不能作为成功缓存复用。取消和输出错误立即停止后续输出。

## 对照与限制

`tools/build_ftrace_oracle.py` 校验锁定源摘要，以真实 ISF、字节内存层、原生框架对象和已知内核范围执行未修改的 `iterate_ftrace_ops_list`、`extract_hash_table_filters`、`parse_ftrace_ops` 和实际模块内核符号查询；不 mock 这些方法。零地址在对象 oracle 的可读性探测中明确设为不可读，模拟正常内核空指针。此 oracle 不执行上游模块 gatherer，不能证明其完整等价。

48 个对象案例覆盖两种指针宽度、三种哈希布局及八种场景：普通、空操作链、空过滤链、未知回调、回调无精确符号、被挂接地址无符号、只有第二桶含条目、全部已知 flags。72 个 x64/x86/PAE 分页案例各测试两个展示模式，对照六个常规字段及可选 Flags。内核回调 oracle 的原生管线运行真实但为空的模块 gatherer；完整的模块来源阳性与 ELF 解析另有独立管线测试，避免每个内核案例重复不变的扫描检查。原始采集独立重读，输出后再次校验记录未被修改；SQLite 封存行逐条验证，成功缓存 JSONL 逐字节一致。

附加测试覆盖完整原生模块归属、错误类型、超大对象、缺失符号、链表循环、过滤链循环、缺页、读取/遍历预算、取消、每个输出错误边界和失败重试；采集入口有 Go fuzz。

真实 Debian 3.2 x64 镜像 SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc` 的符号没有 `ftrace_ops_list`。固定基线记录不支持并返回 `[]`；原生任务明确失败、零行，重复执行不复用缓存。该场景是**不支持场景验证，不是清洁阴性对照，也不是成功差分**。

```sh
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" \
GOMEM_FTRACE_REFERENCE="$PWD/.cache/ftrace-validation/reference" \
go test ./internal/engine -run '^TestOfficialLinuxFtrace' -count=1
```

真实受支持/阳性镜像、更多内核版本、损坏采集的一致性及全部参数/渲染方式仍待验证。ARM64 不属于此固定插件的架构要求，当前入口明确拒绝。[机器可读记录](linux-ftrace-validation.json)、[常规字段对照配置](diff/linux.check_ftrace.json)。
