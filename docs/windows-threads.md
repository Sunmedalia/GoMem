# Windows 活动线程与启动路径

`windows.threads` 对应固定基线 `windows.threads.Threads` 的部分原生能力，当前保持开发预览和 `accepted=false`。

```sh
bin/gomem analyze windows.threads --image memory.dmp --case ./case-001 --format jsonl
bin/gomem analyze windows.threads --image memory.dmp --case ./case-001 --offline --param pid=104,108
```

插件沿活动进程的 `ThreadListHead` 枚举 `_ETHREAD.ThreadListEntry`，保留完整对象地址、CID PID/TID、两个启动地址、时间与原始时间值。进程身份与 pslist 使用同一计算方法：镜像、地址空间、进程对象、PID 和可用创建时间。线程身份另设命名空间并包含线程对象、TID 和原始创建时间。CID 与所属进程链表不一致时，保留实体、设置 `OwnerPIDMatches=false`，不关联到该进程的文件路径。

启动路径使用[共用 VAD 读取器](windows-vadwalk.md#旧版入口与对象级对照)，原生支持直接指针、BalancedRoot、MM_AVL_NODE、RTL 和 Core 结构。旧版结构只有合成参考，真实镜像仍只验收选定 19041 x64 字段。每个进程建立一次有界区间索引，校验父节点、循环、深度、VPN 范围和重叠；文件名沿 Subsection、ControlArea、FAST_REF 和 FILE_OBJECT 读取。结构损坏标记 `vad_index_incomplete`，文件缺页保留读取错误；不能转成“没有文件”。System 线程的用户 VAD 路径明确标为不适用。`max-nodes` 限制进程和每个 VAD 树，`max-threads` 限制总遍历与输出；超限、损坏线程链表和取消保留部分结果，并令任务失败。

Windows 专用页表策略支持驻留 transition 编码（Transition=1、Prototype=0）。x64 软件页表项按固定基线的 45 位 PFN 范围处理高位标志；通用硬件项和 Linux 不采用该规则。转换结果带 `Transition=true` 和 `PermissionsKnown=false`，不把软件保护位当作 RW/NX 权限。原型页、外部 pagefile 和缺失物理页仍返回错误。此实现并未验收高物理地址 Windows 系统或全部软件页表编码。规则对照来源为锁定提交的 [Intel Windows 层](https://github.com/volatilityfoundation/volatility3/blob/881e970121c16f0932fb9d16fbd5fb258cbcbf75/volatility3/framework/layers/intel.py)。

时间输出保留 FILETIME 的 100ns 精度和原始无符号 64 位值；其 UTC 起点为 1601 年。[Microsoft FILETIME 定义](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)。低于一秒的值采用固定基线的 `not_set` 语义，同时保留原始值；超过 GoMem 支持的 RFC3339 年份 9999 上限标记 `invalid_filetime`。旧 `ThreadsProcess` 布局会将打包的创建时间右移三位再显示，但原始值不变；旧版系统尚未通过真实语料验收。

官方 Windows 10 19041 样本共有 1,752 条线程，八字段多重集对照一致：Offset、PID、TID、两个启动地址、两个路径和创建时间。归一化明确列于 [比较映射](diff/windows.threads.json)：上游地址掩码为 48 位，时间按上游的整秒精度比较，仅显式的无错误缺失原因可对应上游 null。GoMem 原始输出仍保留完整地址和时间精度。最初一个路径缺页差异由 Windows transition 页解析修复，未用 null 归一化掩盖读取失败。

退出时间单独核验：91 条有效日期按秒一致；1,661 条原始值的最高位为 1，上游按有符号联合体解释后显示 1600 年日期。GoMem 保留原始位模式并标记超出支持范围，未将该差异算作全字段一致。聚合结果与摘要见 [验证记录](windows-threads-validation.json)，原始镜像、结果和案件不提交。

可复现验证：先按 [验证说明](validation.md) 生成固定上游 `windows.threads` JSON，再运行 `tools/diff_results.py` 的八字段映射。`GOMEM_CORPUS_DIR` 设为语料的绝对路径，运行 `go test ./internal/engine -run TestOfficialWindowsThreads -v`，同时检查八字段、无读取错误以及 91/1661 个退出时间类别。常规测试还覆盖 PID 集合、精确时间、进程关联、线程/VAD 循环、父节点错误、文件缺页和输出上限；页表测试覆盖 x86/PAE/x64 的驻留/缺失 transition、原型和交换编码。

其余 Windows 版本和旧 VAD 的联合镜像验收、完整参数、损坏链表恢复、线程池扫描、提取和其他官方输出仍待实现或验收。GoMem 保留异常 CID 及归属信息，不复制上游的静默 PID 合法性过滤；该行为也需进一步差分确认。
