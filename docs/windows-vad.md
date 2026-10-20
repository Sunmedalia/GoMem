# Windows 现代 VAD 与直接 RWX 分诊

`windows.vadinfo` 对应固定基线 `windows.vadinfo.VadInfo` 的部分能力。适用 `_EPROCESS.VadRoot.Root`、`_RTL_BALANCED_NODE`、`_MMVAD_SHORT` / `_MMVAD` 的现代布局。状态保持开发预览、`accepted=false`；旧版树布局、`dump`、`maxsize` 和提取文件尚未实现，未知参数会被拒绝。

```sh
bin/gomem analyze windows.vadinfo --image memory.dmp --case ./case-001 --format jsonl
bin/gomem analyze windows.vadinfo --image memory.dmp --case ./case-001 --offline --param pid=104,108 --param address=0x700000
bin/gomem triage --image memory.dmp --case ./case-001 --offline
```

区间起止为包含端点的完整虚拟地址，VPN 高位由类型声明读取。输出保留 VAD 对象与父节点、池标签、PID/进程名、提交页数、私有标志、文件路径，以及与 pslist 相同的进程身份。`CommitCharge` 跟随基线的声明字段值，`CommitChargeHigh` 另存，尚未合并为完整页数。结构、循环、重叠和父子关系检查与线程启动路径共用。`max-nodes` 限制单树和进程遍历，`max-regions` 限制总遍历量；包含地址筛选不会绕过遍历上限。结构损坏使任务失败，保留此前其他进程已输出的证据。

权限索引通过符号位字段解析；权限值读取目标内核的 32 项 `MmProtectToValue` 数组，支持页面权限修饰符。未知权限位、不可读的表或字段产生带原因和错误的 missing 单元格；原始索引和可读数值仍保留。文件路径与缺页错误分开记录，不能将失败转换成无文件。

固定官方 Windows 10 19041 样本得到 19,999 个 VAD。十个核心字段完全匹配：PID、Process、Offset、Start、End、Tag、Protection、CommitCharge、PrivateMemory、Parent。[核心比较映射](diff/windows.vadinfo.json) 没有地址掩码或数值精度归一化。

同一镜像还通过原生 `ntkrnlmp.pdb` 直接加载并完成全部 19,999 行的十字段对照，独立于提供的 ISF；输入 PDB、转换表和实际二进制摘要另记于验证记录。

包含文件路径的 [扩展映射](diff/windows.vadinfo.paths.json) 保留 39 个差异：同一对象的全部核心字段相同；上游 File 为 null，GoMem 为带具体缺页错误的 `unreadable_or_unavailable`。其余路径字段匹配。锁定上游的 `MMVAD.get_file_name` 会抑制 `InvalidAddressException`，其返回值无法区别这种缺页与没有文件；GoMem 保留区别，未将错误归一化为 null。[上游实现](https://github.com/volatilityfoundation/volatility3/blob/881e970121c16f0932fb9d16fbd5fb258cbcbf75/volatility3/framework/symbols/windows/extensions/__init__.py)。聚合结果和原始输出摘要见 [验证记录](windows-vad-validation.json)，不提交镜像或原始路径列表。

Windows 分诊现按依赖运行进程、模块和 VAD。直接 RWX 规则从持久化 VAD 每次读取 500 行，以 `PAGE_EXECUTE_READWRITE` 数值位判断，支持 GUARD 等修饰符。`PAGE_EXECUTE_WRITECOPY` 作为正常对照；这是窄范围权限线索，无法代表全部注入或恶意内存检测。样本产生 30 条线索，每条引用封存的 VAD 行、进程身份和来源；JIT 等正常程序也可能产生该权限。

合成测试覆盖真实解析链到分诊的阳性、正常权限和未知权限，验证原始行回溯、白名单及完整输入任务复用。未知权限不能算作正常，结构失败不能算作空树。隐藏进程、模块扫描差异和持久化输入仍未贯通，完整分诊保留 `incomplete` 并返回非零。现有 30 条线索仍会落盘，其他检查未运行不代表没有异常。Linux 的删除文件/memfd 输入另见 [Linux 映射](linux-maps.md)。

复现使用 [固定对照工具](validation.md) 的 `windows.vadinfo` 输出，再分别运行两个映射。设置绝对路径 `GOMEM_CORPUS_DIR`，运行 `go test ./internal/engine -run TestOfficialWindowsModernVADs -v`：检查全部核心值、可读文件名和恰好 39 个有原因的缺页差异。原生 Windows/Linux 进程、模块及 Windows 线程回归仍需同时运行。
