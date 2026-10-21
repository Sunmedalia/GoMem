# Linux 栈内符号线索（开发预览）

`linux.pscallstack` 原生实现固定基线 `linux.pscallstack.PsCallStack` 的栈字扫描。它从 `task.thread.sp` 逐指针字读取到规范化的 `task.stack + (4096 << 2)`，用驻留的 [统一符号解析器](linux-resolver.md)按 core → module → BPF → ftrace 查找。**这是栈中的符号地址线索，不是帧展开，也不能独立证明调用顺序。** 四页范围沿用基线，不自动适配 KASAN 栈大小。

```sh
bin/gomem analyze linux.pscallstack --image memory.raw --symbols kernel.json --dtb 0x... --os linux --arch x64 --param pid=1 --format jsonl
bin/gomem analyze linux.pscallstack --image memory.raw --symbols kernel.json --dtb 0x... --os linux --arch x64 --param pid=1 --param unresolved=true --format jsonl
```

支持 Intel x64、x86、PAE；需要对应任务、线程和驻留符号的类型及根。`pid` 筛选任务链表中的组长，选中的组长连同其 `thread_group` 或 `signal_struct.thread_head` 线程一起分析；它不单独选择同组线程的 TID。PF_KTHREAD 使用内核层，用户任务通过 `mm.pgd` 建立独立进程页表。缺少可用地址空间会保留诊断并使任务不完整。Position 包括零值的槽位，但零值永不输出；`unresolved=true` 才输出非零未命中值。未对齐的有效 SP 沿用基线逐字扫描，包括最后一次可能跨过四页上界的完整指针读取。

八个主要字段是 TID、Comm、Position、Address、Value、Name、Type、Module。地址无损十六进制保存。差分配置仅把无错误的 `unresolved` 缺失值归一化为上游 null；读取或解析错误不会归一化。`stack_entry` 是正常输出；`stack_error` 保存符号解析错误时的槽位及原始值；`diagnostic` 保留任务级失败。`stack_read` 记录任务遍历、元数据、栈和符号解析的每次虚拟读取，含地址、原始字节、请求/实得长度、读取序号和错误。正常项附带完整来源顺序、不可用来源原因、符号区间、模块范围/缓存/树选择及 BPF/ftrace 对象坐标。`task_stack_summary` 保留对象地址、TID、可用创建计数生成的身份、已扫描字数和完成状态；即使全零也有显式任务摘要。`stack_summary` 汇总全局计数。暖符号查询依赖之前的索引读取，证据范围明确包含整个分析任务的先前采集。

`max-nodes` 约束各链表/来源搜索及缓存模块对象数，`max-tasks`、`max-words`、`max-bytes` 分别约束整个分析的任务数、栈字数和实际虚拟采集字节数；`max-symbols` 约束 core 符号数和累计缓存模块符号数。原始镜像保持只读。取消和输出错误立即终止；缺页、损坏类型、列表循环、无效 SP、读取失败或上限耗尽保留已有结果并使分析失败，失败任务不会作为成功缓存回放。

## 对照与差异

固定版本为 Volatility 3 v2.28.2，提交 `881e970121c16f0932fb9d16fbd5fb258cbcbf75`。`tools/build_pscallstack_oracle.py` 核对源码摘要，用字节支撑的实际 ISF 对象、Intel 页表、任务扩展、驻留解析器直接运行未修改的 `_generator`、`get_task_callstack` 和 `PsList.list_tasks`，没有方法 mock。44 组覆盖 32/64 位、旧/新线程链、四来源优先级、未对齐/非法 SP、全零栈、独立进程页表与不同于内核映射的栈页、无 mm、栈页缺失和后续来源缺符号。每组包含默认、unresolved、组长过滤及线程 TID 过滤四个配置。66 组原生 x64/x86/PAE 组合共 264 个初次分析逐项比较八字段；成功结果验证封存、落盘读取和逐字节缓存复用，失败配置验证不复用。读取及输出边界逐次注入失败/取消并重试；另有布局、循环、全局上限、参数和 fuzz 检查。

上游完整生成器可能在一项失败后停止，栈页错误或无法创建进程层也可能静默结束。GoMem 继续独立任务并记录失败，因而脚本同时保存未修改完整生成器和共享解析器的逐任务记录：正常配置核对完整生成器，错误配置核对逐任务内容，绝不把继续输出声称为完整生成器等价。共用任务遍历器严格检查前向链表/反向链接；完整的上游双向容错、所有 task.is_valid 条件和损坏任务筛选语义尚未验收。已声明但读取失败的可选创建时间也会使原生任务失败。legacy BPF 缺失方法修正、模块范围和 Elf32 字段的固定语义见统一解析器文档。

真实官方 Debian 3.2.57 镜像（SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`）中 PID 1 的默认 37 条及 unresolved 383 条与未修改上游八字段和顺序完全一致。两种模式均独立重读 3,771 条采集、验证 SQLite 封存并逐字节回放缓存。PF_KTHREAD 的 PID 2 控制另有 6 条八字段匹配，也通过独立重读、封存和缓存检查。这是一个旧内核进程的对照，不建立现代 module/BPF/ftrace 栈阳性验收。Kali ARM64 不作为此插件的等价语料。

```sh
python3 tools/build_pscallstack_oracle.py --check
go test -race ./internal/engine -run TestLinuxPsCallStack -count=1
go test ./internal/plugins -run '^$' -fuzz '^FuzzLinuxPsCallStack$' -fuzztime 10s
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" GOMEM_PSCALLSTACK_REFERENCE="$PWD/.cache/pscallstack-validation/reference" go test ./internal/engine -run TestOfficialLinuxPsCallStack -count=1 -v
```

语料测试要求 `tools/reference.py` 的 JSON、配置和 manifest，校验固定提交、镜像和输出摘要以及参数。未提供环境变量时跳过不能计为验收。更多内核、真实 x86/PAE、现代模块/BPF/ftrace 栈阳性、所有参数/渲染器和性能仍待完成；能力矩阵标为部分实现。见[机器验证记录](linux-pscallstack-validation.json)与[差分字段配置](diff/linux.pscallstack.json)。
