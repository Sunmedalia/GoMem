# Windows 可疑线程

`windows.suspicious_threads` 原生实现固定基线 `windows.malware.suspicious_threads.SuspiciousThreads` 的分析逻辑；旧路径 `windows.suspicious_threads.SuspiciousThreads` 是上游弃用别名。运行时不使用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.suspicious_threads --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.suspicious_threads --image memory.dmp --case ./case-001 --offline -p pid=384,488
```

活动进程按 VAD 前序建立一次范围索引，并解析 `MmProtectToValue` 的保护字符串。支持直接 `u.VadFlags.Protection` 和 `Core.u.VadFlags.Protection`。只读用到的表项，不要求整张表的每一页都存在；超出 32 项的索引按基线返回空保护名，未命名的保护位不影响字符串。VAD 少于 5 个的进程直接跳过。进程主映像路径取包含 `SectionBaseAddress` 的 VAD。

遍历活动线程时，正数的有符号 `ExitTime.QuadPart` 或 `Tcb.State == 4` 表示退出/终止并跳过。随后读取 CID、两个启动地址和创建/退出时间；PID 必须非零、不大于 `0xFFFFFFFC` 且是 4 的倍数。读取失败保留 diagnostic 行及计数。对每个进程先检查 Start，再检查 Win32Start；同一个地址跨线程只检查一次，因此后续使用相同入口的线程不会重复产生线索。未落入 VAD 的地址也会被记为已检查。

每个入口可以产生多条线索：

- VAD 没有可读的文件映射路径。
- 初始保护字符串不是恰好 `PAGE_EXECUTE_WRITECOPY`，包括有额外修饰位的字符串。
- VAD 路径以 `.exe` 结尾，且与进程主映像路径忽略大小写后不同。

保留基线的两处细节：范围命中使用 `start <= address < end`，尽管 end 是最后一个可访问字节；第三类 Note 的 `{vad_base:#x}` 在上游是未展开的普通字符串，原生比较列也保留它，同时在 `VADBase` 输出真实基址。名称、上下文、PID/TID、地址、路径、Note 通过全部 7 个官方列比较。额外记录进程/线程身份、对象地址、VAD 对象地址、原始未掩码地址及规则，证据来源偏移指向线程本体。

无法读取文件名时，基线也使用 `<Non-File Backed Region>`，所以该线索不能证明该区域原本没有映射文件。原生 `PathError` 保留读取错误。内存采集时的不一致、进程退出、JIT 和其他合法运行时代码均可能产生线索，需要结合原始 VAD、PEB、代码和其他证据调查。VAD 或保护读取失败、坏链表和遍历上限让任务失败；不转换成干净空结果。

`max-nodes` 默认 131072，限制活动进程和各 VAD 树；`max-threads` 默认 1000000，限制总线程数。它们不是上游参数。摘要及 diagnostic 不是发现。Coverage 记录进程、短 VAD 集、线程、退出、gather 跳过、去重、范围外地址、发现和带文件读取错误的发现数量。

## 验证与缺口

选定 Windows 10 19041 x64 镜像在两个引擎中均返回 0 条发现。GoMem 实际遍历 120 个进程，3 个 VAD 数不足，检查 1749 个线程，88 个退出/终止；892 个地址首次出现、2430 次重复、156 个范围外地址，gather 和文件读取错误均为 0。该结果是正常对照，不能证明阳性检测的真实镜像准确性。

721 个参考直接调用固定源码的 `_get_range` 和 `_check_thread_address`，覆盖非文件/空字符串、正常与异常保护、大小写、其他 EXE、DLL、Unicode、边界和重叠范围；比较精确路径及 Note。合成完整流程覆盖三类阳性、正常对照、地址去重和上下文顺序、退出/状态/PID 过滤、少于 5 个 VAD、Core 布局、表项越界/未知位/未使用项缺页、字段读取 diagnostic、文件错误原因、取消和输出/遍历失败。

```sh
.cache/reference-venv/bin/python tools/build_suspicious_thread_oracle.py --check
go test ./internal/plugins -run TestSuspiciousThread -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsSuspiciousThreads -count=1 -v
```

真实阳性、其他 Windows 版本、真实 x86、完整参数与损坏布局验收仍缺失。保持 partial、accepted=false。
