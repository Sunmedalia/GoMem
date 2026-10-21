# Windows 原生检查的自动分诊

Windows 的模块对照另见[模块分诊](windows-module-triage.md)。

Windows 的 `triage` 自动执行 `windows.psxview`、`windows.suspicious_threads`、`windows.hollowprocesses` 和 `windows.processghosting`，然后从案件 SQLite 每次读取 500 行进行评估。分别产生 `hidden-process`、`suspicious-thread-start`、`hollow-process-mapping` 和 Windows 版 `deleted-or-memfd-execution` 规则。Linux 保留原生任务扫描与活动链的隐藏进程对照及 executable VMA 的删除/memfd 检查；线程和空洞检查是 `not_applicable`，不运行 Windows 插件。

```sh
bin/gomem triage --image memory.dmp --case ./case-001 --offline
```

规则的依据和误报说明记录在每条发现中。实体采用原始 `Identity`（多视图）或 `ProcessIdentity`（线程/映射），结合镜像、地址空间、对象地址、PID 和可用创建时间。线程和加载模块信息不按 PID 重新猜测归属。每条分诊发现保存原始行引用、镜像/符号/参数来源、原生子规则、原始判断说明，以及适用的进程、线程、VAD 和加载条目地址。案件白名单按分诊规则和进程实体抑制发现，原始行和插件任务不变。再次执行复用已完成的原生任务，再重新应用当前白名单。

多视图仅对 `pslist=false` 的 process 行产生线索，正常活动对象不产生发现。同 PID 不同对象不合并，`Sources` 保留四种视图实际坐标、显示坐标和转换失败。非空的可解析 `ExitTime` 将线索降为 `info`，说明残留分配可以解释差异；空退出时间也不能证实进程隐藏。多视图遵循上游对象有效性和名称过滤条件，不能解释为所有进程的完整枚举。

原生输出含 process、finding、diagnostic、summary，后两者不会变成发现。评估器校验原始证据摘要、插件及镜像身份、对象来源坐标、子规则和最终汇总计数。多视图额外校验四个布尔来源、每源坐标、代表对象、退出时间格式和四个视图的最终行计数。缺失汇总不能认作干净空结果。计数错误、未知记录或篡改的证据使检查失败。

多视图缺少活动 csrss 或对象类型表，或者池读取失败、csrss 句柄表不可读/循环时，检查标为 `incomplete`。`pool_read_failures`、`pool_type_map_entries` 从原始池摘要平铺到 coverage；完整池摘要仍在 `Sources.pool`。基线有效性和名称过滤的拒绝数独立展示，不自动作为读取覆盖失败。

诊断会保留在原始任务，评估会继续处理后续页。原生 summary 中的诊断、线程 gather 跳过或路径读取错误使相应检查标为 `incomplete`，附带 coverage 和原因。已发现线索仍保存。路径读取失败的 finding 降为 `info`，带 `Confidence=limited_by_path_read_error`，保留 `PathError`；不可读文件名不证明没有文件映射。合法运行时、JIT、解包、退出进程和采集不一致仍可能产生线索。

正常的最少 VAD/DLL 数筛选保持原插件语义，计数展示在 coverage；`completed` 仅表示在这些适用条件下检查执行完毕。它不代表所有进程都通过检查，也不确认没有恶意行为。当前完整分诊仍有其他输入缺口，整体返回非零并将案件分诊任务标为失败，已运行的发现仍可查询和导出。

## 验证

选定 Windows 10 19041 x64 镜像只读运行完整分诊并重跑缓存：

- 进程多视图：113/114/112/103 个来源偏移、1 条信息级差异（已退出的 `MpCmdRun.exe` PID 408），检查状态 `completed`。发现引用已封存的原始对象和四源坐标。
- 可疑线程检查：1749 个线程、0 条发现、gather 和文件路径错误均为 0，检查状态 `completed`。
- 文件删除状态检查：113 个通过过滤的进程、18125 个 VAD、8214 个具名映射、0 条发现；3482 条路径/控制区读取诊断使检查为 `incomplete`。
- 进程空洞检查：99 个进程进入检查、0 条发现、330 条原生读取/覆盖诊断，检查状态 `incomplete`。
- 原有 RWX 检查产生 30 条映射线索，加上已退出进程和模块候选差异，合计 32 条；这些不是上述原生检查的真实恶意阳性验证。第二次执行的已完成输入任务全部复用，检查状态和发现数量一致。

这份镜像是正常对照。新检查的真实恶意阳性和完整版本、误报验收仍待补齐，能力矩阵保持 partial、accepted=false。

删除状态检查另校验三个原生子规则、标志原值和文件/VAD/控制区坐标。FILE_OBJECT 为零的进程线索降为信息级并保留读取原因；删除标志本身不证明执行。详情见 [ProcessGhosting](windows-processghosting.md)。

构造测试覆盖四个原生输入规则的阳性与正常输出，以及 1001 条诊断后位于后续页的阳性。多视图另覆盖 501 个正常对象后的两个同 PID 不同身份候选、已退出降级、缺少 csrss/类型表和句柄/池覆盖不足。完整案件流程验证 SQLite 分页、原始证据回溯、符号摘要、白名单、源任务复用、原始行不被删除及覆盖不足状态。篡改、缺失汇总、错误计数、混合镜像、错误插件、来源地址不一致、取消和输出失败都有负例。原生内存读取的完整流程测试分别记录在[多视图](windows-psxview.md)、[可疑线程](windows-suspicious-threads.md)和[进程空洞](windows-hollowprocesses.md)。

```sh
go test ./internal/triage -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/triage -run TestOfficialWindowsNativeTriageCoverage -count=1 -v
```
