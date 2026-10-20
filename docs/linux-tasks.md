# Linux 进程身份、创建时间与线程

`linux.pslist` 读取活动任务，输出 PID（tgid）、TID（task.pid）、PPID（real_parent.tgid）、名称、UID/GID/EUID/EGID 和创建时间。凭据支持标量 ID 与 `kuid_t`/`kgid_t` 的 `.val`；Cred 保留对象地址，空指针与每个字段的读取失败分别记录。输出是内核保存的原始 ID，不推断用户命名空间中的映射身份。

```sh
bin/gomem analyze linux.pslist --image memory.raw --symbols exact.json.xz --case ./case-001 --format jsonl
bin/gomem analyze linux.pslist --image memory.raw --symbols exact.json.xz --case ./case-001 --param threads=true --param decorate-comm=true
bin/gomem analyze linux.pslist --image memory.raw --symbols exact.json.xz --param pid=2652,3576 --param threads=true
```

PID 筛选按固定基线先作用于任务主链表的 task.pid，再展开所选任务的线程，不对每个子线程再次筛选。单独指定不在主链表的线程 TID 不会隐式选择所属进程。旧布局遍历 thread_group；Linux 6.7 后的布局通过 signal.thread_head 与 thread_node。链表验证双向链接、循环、上限及 TGID；符号含 group_leader 时还要求对象地址与所属进程一致。全局 max-tasks（默认及上限 1,000,000）约束选中任务及其线程，max-nodes 继续约束主链表和每个线程链表。

RecordType 区分 task、thread、diagnostic。线程的 Identity/ProcessOffset 指向所属进程，TaskIdentity 以独立线程命名空间、对象、TID 和可用启动计数生成，防止把 PID 复用或同进程的不同线程关联为同一任务。已有进程身份继续使用原有 start_time 计数，不因增加 UTC 展示或名称装饰而改变。NameRaw 保留任务名；`decorate-comm` 依据 PF_KTHREAD 装饰内核线程，再依据 PID/TID 区分用户线程，不以空 mm 猜测类型。

创建计数按 `start_boottime`、`real_start_time`、`start_time` 的声明顺序选择，支持 timespec 和标量纳秒。CreationCounterNS/CreationCounterField 保留选择依据，StartTimeNS 继续保存原有身份计数。启动时钟支持 tk_core 的 offs_real/offs_boot（标量或 tv64）、旧 timekeeper 的 wall_to_monotonic/total_sleep_time，以及旧全局时钟（睡眠时间支持 timespec 或秒）。声明存在但读取失败时不会悄悄换用其他时钟。所有偏移运算使用整数，保留纳秒，拒绝坏纳秒、负计数和超范围日期。

Created 按固定基线采用“root 启动时钟的整秒 + 任务启动计数”；CreatedExact 则保留启动时钟的小数部分。BootTime 与 ClockProof 保存原始启动时间、符号地址、来源和公式，不应用进程时间命名空间偏移。二者都是对内核时钟的解释，不能推导为外部认证的真实时间。凭据或时钟字段不可读时保留对应 missing/error，基本枚举仍可完成；线程链表不完整或无法完成所请求的名称装饰时任务失败，保留已产生行与诊断，继续其他独立组。取消和输出错误立即停止。

官方 Debian 3.2 x64 样本中，默认 133 条记录、启用线程/装饰的 316 条记录（183 个用户线程）均通过十字段比较，含四类 UID/GID、时间及精确对象地址。39 个 PF_KTHREAD 任务被正确装饰。PID 2652/3576 联合筛选得到 92 条记录。Created 的纳秒原值原样保留；对照配置明确使用向偶数舍入到微秒，与 Python datetime 显示精度比较，不使用整秒截断。另核验 CreatedExact 与 BootTime/计数的整数关系。[验证记录](linux-tasks-validation.json)

```sh
python3 tools/diff_results.py --native native.jsonl --reference reference.json --mapping docs/diff/linux.pslist.enriched.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxTaskFieldsAndThreads -count=1
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxClockArithmetic -fuzztime 10s
```

对照工具支持显式选择 task/thread 行，同时单独报告 diagnostic 数量；不能将排除诊断后的字段相等冒充完整成功。合成测试覆盖旧/新线程链表、所有时钟布局、包装凭据、部分读取、坏归属、循环、计数边界、装饰、筛选和取消。真实现代内核、32 位、损坏主链表双向恢复、ELF dump 和时间线参数仍待补齐；保持 partial、accepted=false。
