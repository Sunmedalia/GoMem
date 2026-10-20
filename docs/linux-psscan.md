# Linux 物理任务扫描与活动任务对照

`linux.psscan` 在物理内存中寻找符号表所有名称含 `_sched_class` 的指针值，以 task_struct.sched_class 偏移定位候选对象，再检查 exit_state 和 task.pid。扫描一次读取所有签名，匹配不要求指针对齐；跨读取块及连续物理段保留最多 7 字节，物理空洞打断匹配。签名按精确符号加内核 slide 生成，支持小端 32/64 位、重复地址的符号别名以及省略了 Intel64 符号扩展的 48 位地址。

```sh
bin/gomem analyze linux.psscan --image memory.raw --symbols exact.json.xz --case ./case-001 --format jsonl
bin/gomem analyze linux.psscan --image memory.raw --symbols exact.json.xz --param max-pid=4194304
bin/gomem triage --image memory.raw --symbols exact.json.xz --case ./case-001
```

PID 输出 task.tgid，TID 输出 task.pid，PPID 通过物理对象的 real_parent 指针在内核虚拟空间读取 parent.tgid。Offset/PhysicalOffset 明确属于物理层，不能当作内核虚拟地址或容器文件偏移。CommRaw 保存完整声明的原始名称数组，Parent、SchedClass、符号别名及启动计数分别保留。TaskIdentity 使用镜像、物理层、对象地址、TID 和可用 start_time，避免仅以 PID 关联。

默认接受 0 < task.pid < 65535，退出状态限 0/16/32/48（TASK_RUNNING、EXIT_DEAD、EXIT_ZOMBIE、EXIT_TRACE），与固定基线一致。TASK_RUNNING 是此处 exit_state=0 的基线标签，仅表示未标记退出，不代表正在 CPU 上运行。`max-pid` 可以显式扩大到 uint32；此选项会改变候选集合。`max-candidates` 和 `max-results` 默认及上限均为 1,000,000。超过上限使任务失败，保留先前行和未完成扫描摘要；没有调度符号或类型声明时明确失败。读缓冲区约 1 MiB，候选逐条输出，不将整镜像载入内存。

RecordType 为 task、diagnostic 或 scan_summary。摘要保存计划物理范围、实际使用的签名/别名、指针命中及各类启发式拒绝计数、候选读取错误和物理扫描是否完成。退出状态/PID 不满足条件属于已声明的启发式拒绝；字段不可读是错误，不会冒充正常拒绝或空结果。父对象读取失败也不替换为 PPID 0。取消、输出错误立即停止；任务输出已写入部分仍可追溯。

这是一种候选发现算法。它假设对象内联字段在物理地址上连续，指针、PID 和退出状态检查不能证明分配仍有效；旧分配、部分采集、未经过调度类的任务或不完整物理对象均影响解释。零候选只表示指定范围内未发现满足这些条件的候选，不能证明没有隐藏进程。

Linux `triage` 现在以 `linux.pslist threads=true` 对照 `linux.psscan`。活动任务多保留 PhysicalOffset/PhysicalLayer；两个视图按相同镜像和物理对象坐标比较，跨镜像、混合地址空间、无法转换的坐标和不完整数据会拒绝比较。不会把用户线程误当作隐藏进程，也不以 PID 相同合并不同对象。运行状态但不在活动链表的候选作为高优先级线索；已退出候选保留为 info，并注明“残留或退出中的候选，缺席本身不是隐藏证据”。白名单使用含地址与可用启动时间的物理任务身份。每条发现引用原始扫描行，并保存活动/扫描任务 ID、完成状态、行数及完整任务来源，便于重查负向对照所依据的完整枚举。

差异评估每次读取 500 行，仅将活动对象键保留在内存中（最多 1,000,000），不一次载入全部证据。扫描摘要不会成为实体；诊断、读取失败或未完成生产任务使对应检查不可用/失败。其他缺失生产者仍保持 unavailable，整体分诊继续报告未完整覆盖，不能解读为完整成功。

分享完整对照证据时使用整案导出（不传 `--task`）：`gomem export --case ./case-001 --format bundle --output investigation.zip`。单任务导出保留证据引用和比较任务来源，但不会自动带入其他任务的原始行；本次同时验证了六个单任务包和两个整案包，后者包含所有引用及比较任务。

固定 Debian 3.2 x64 样本中，321 个任务候选的 Offset、PID、TID、PPID、Name、ExitState 六字段全部匹配固定基线。373 个调度指针命中中，33 个被退出状态条件拒绝，19 个被 PID 条件拒绝；没有候选读取错误；一个僵尸候选的启动计数无效，保留为 missing，不伪造时间或身份计数。316 个 exit_state=0 候选均在包含线程的活动视图中，剩余 5 个为僵尸候选，分诊全部保留为 info。独立工具以 Python bytes.find 重扫原始字节、ISF/struct 解码内联字段和单独的 RAW 页表遍历核对这些集合、原始名称及活动坐标，不执行 GoMem 引擎或导入 Volatility。[机器验证记录](linux-psscan-validation.json)

```sh
python3 tools/diff_results.py --native native.jsonl --reference reference.json --mapping docs/diff/linux.psscan.json
python3 tools/verify_task_scan.py --native native.jsonl --active active-with-threads.jsonl --image memory.raw --isf exact.json.xz --kernel-dtb 0x1605000
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialLinuxPhysicalTaskScan$' -count=1
go test ./pkg/memory -run '^$' -fuzz '^FuzzPointerScan$' -fuzztime 10s
```

独立工具只验证选定 RAW、小端 ISF 来源的四级 x64 场景；不为其他格式/架构背书。重编码 AVML 同一采集另核对任务字段及扫描计数，不算新的采集版本。合成测试包含非对齐候选、32 位 x86/PAE、签名别名/规范地址、边界/空洞、坏父指针、截断字段、限制、取消、PID 复用、可见线程、残留对象、白名单和恢复缓存。真实新内核/32 位、更多分配布局和完整参数/失败语义仍待补齐；保持 partial、accepted=false。
