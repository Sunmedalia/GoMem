# Windows 进程和映射文件的删除状态

`windows.processghosting` 对应固定基线 `windows.malware.processghosting.ProcessGhosting`。原生读取进程对象、VAD、控制区及文件对象；运行时不调用 Python 或 Volatility。旧路径 `windows.processghosting.ProcessGhosting` 是上游弃用别名。

```sh
bin/gomem analyze windows.processghosting --image memory.dmp --case ./case-001 --offline --format jsonl
```

仅检查通过固定 `create_active_process_filter` 的进程：有效 EPROCESS、ActiveThreads 大于零、PID 与父 PID 都不是 4、ExitTime 原值为零。名称不使用 PsXView 的字母过滤器。固定源码对 `get_handle_count() != UnreadableValue()` 的判断是两个新对象的身份比较；实际不可读的句柄数仍会通过，不能误加“必须有 HandleCount”的适用限制。coverage 展示字段是否存在，实际句柄读取失败另留 diagnostic。

具名 VAD 按起点建立字典，重复起点最后值覆盖，检查顺序保留第一次插入位置。支持直接 ControlArea 和 Subsection.ControlArea，以及普通文件指针、32/64 位 EX_FAST_REF。只有 FileName.Length 大于零的 VAD 进入字典；短 VAD 没有文件名。文件名遵循基线 UTF-16 替换及首个 NUL 截断；Length 大于零但解码为空字符串仍是有效字典项。Length 为零时不会读取 Buffer。

进程检查仅在存在 ImageFilePointer 字段时启用。保留固定源码的实际语义：先判断的是字段所在地址，不是指针值；字段地址非零时，即使目标为零也尝试读取 DeletePending。目标读失败会产生 FILE_OBJECT=0 的线索，并另存读取诊断。目标零地址可读时按实际字节判断。文件对象为零或 DeletePending 等于 1 时产生进程线索，基址为 SectionBaseAddress；其他非 0/1 的 DeletePending 当作采集不一致并在比较列中显示为不适用，原值保留。

对非 private 的具名 VAD，先检查控制区 DeleteOnClose，值非零且路径以 `.exe` 或 `.dll` 结尾时输出；后缀比较忽略大小写，不忽略尾随空格。然后独立检查文件对象 DeletePending 是否恰好等于 1。同一个 VAD 可输出两条不同线索；进程检查也可与映射检查重复命中，不能去重成单一结论。比较列中的零值按基线显示为不适用，原生额外列保留原值。

每条 finding 保存原始进程身份、对象地址和适用的 VAD、ControlArea、ImageFilePointer 字段地址与原始指针。身份结合镜像、层、对象地址、PID 和可用创建时间。案件引擎补全参数、符号摘要、镜像哈希并封存原始行。读取错误输出 diagnostic；summary 记录候选与通过过滤的进程数、VAD 和具名映射数、private 跳过数、发现和诊断数、ImageFilePointer/HandleCount 字段可用性。缺少 ImageFilePointer 的系统仍可运行 VAD 检查。

损坏活动链/VAD 树、必需布局错误、遍历上限、取消和输出失败明确终止任务。`max-nodes` 默认 131072，限制进程及每个 VAD 树；`max-vads` 默认 1000000，限制全任务累计 VAD。这些是原生参数。插件没有上游 PID 过滤参数。diagnostic、summary 不计为发现；即使任务完成且 finding 为零，也需审阅过滤和读取覆盖。

## 验证及缺口

固定 Windows 10 19041 x64 镜像 SHA-256 为 `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460`。120 个活动链条目中 113 个通过过滤，遍历 18125 个 VAD、8214 个具名映射。双方均为零发现，七个比较列一致；这是正常对照，不能证明阳性路径真实恶意验收。原生保留 3482 条诊断：3478 个文件路径、4 个控制区读取失败；没有把这些错误伪装成完整的空结果。HandleCount 字段不存在，ImageFilePointer 存在。

284 个固定源码参考用例包含 40 个进程检查、180 个 VAD 检查、64 个活动过滤组合，覆盖阳性/正常、无字段、空指针、缺页、无效删除值、路径后缀和不可读值对象的比较行为。完整合成内存读取测试覆盖重叠三类线索、正常/系统/已退出/私有映射、空及可读零地址、重复起点覆盖、直接和 subsection 控制区、指针与 fastref、x86 掩码、空/内嵌 NUL/奇数 UTF-16、布局错误、读取失败、取消、输出失败、循环和上限。

```sh
.cache/reference-venv/bin/python tools/build_processghosting_oracle.py --check
go test ./internal/plugins -run TestProcessGhosting -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsProcessGhosting -count=1 -timeout 10m -v
```

真实 ghosting 恶意阳性、其他版本与真实原生 x86、旧系统、完整误报与损坏镜像差分仍待补齐。矩阵保持 partial、accepted=false。
