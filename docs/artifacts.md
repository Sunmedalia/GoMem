# 提取文件存储与证据包

当前完成编译插件可用的提取文件底座、导出，以及 Windows VAD/Linux VMA 的原生 `dump` 生产者。所有官方能力仍未完整验收；内存区域提取不等于文件、模块或进程映像恢复能力全部完成。

运行中的插件获得任务专属 `Environment.Artifacts`，通过 `ArtifactRequest` 声明文件名、大小和源地址空间/偏移。后台绑定任务、镜像、符号、构建和参数来源，插件不能覆盖这些标识。文件在 `CASE/artifacts/TASK_ID/ARTIFACT_ID/` 内独占新建；路径使用 Go `os.Root` 限定在案件中，拒绝目录穿越、流名称、保留设备名和非持久案件。单次写入最多 16MiB，总写入不得超过声明长度。

正常数据流式写入并计算 SHA-256。读取失败需要显式调用 `PadZero` 才能填充零字节，同时将确切文件偏移、长度、源虚拟地址、层与错误写入单独 JSONL 日志。日志也具有独立大小和摘要；不会将缺页伪装成捕获到的零。两个流均按块处理，日志不随提取大小积累在内存中。VAD/VMA 生产者使用进程自身的页表逐 4KiB 页面读取；保留读取成功的前缀，仅对失败部分填充，取消直接保留部分文件。

文件状态包括 writing、completed、completed_with_gaps、partial、failed 和 interrupted。只有写够声明长度、成功同步/关闭且没有写入错误才能得到完整状态；有缺页时必须使用 completed_with_gaps。插件忘记结束文件或忽略写入/结束错误，会使所属分析任务失败。取消保留已写字节和终态；进程异常退出后，原始部分文件保留，未最终核验的大小/摘要留空。写入原始镜像从来不是该接口的一部分。

schema v2 以事务添加提取文件表并迁移 v1；不删除已有结果。迁移后旧版程序拒绝打开 v2 案件。重新打开时，未完成提取被标为 interrupted，所属未结束任务仍按既有规则标为失败。

```sh
bin/gomem case artifacts --case ./case-001 --limit 100 --offset 0
bin/gomem case artifacts --case ./case-001 --task TASK_ID
bin/gomem case verify-artifacts --case ./case-001
bin/gomem export --case ./case-001 --format bundle --output evidence.zip
python3 tools/verify_bundle.py case-001/exports/evidence.zip
```

区域提取使用 `analyze windows.vadinfo ... --param dump=true` 或 `analyze linux.maps ... --param dump=true`，结合 PID/地址筛选控制范围。默认 maxsize 为 1GiB。按固定基线，Windows 在 `size > maxsize` 时跳过，零表示不设此限制；Linux 在 `size >= maxsize` 时跳过，零会跳过全部区域。跳过记录为 `maxsize_exceeded`，不会产生空提取文件。结果的 FileOutput 保留完整 artifact 元数据；缺失页、未知进程空间和写出错误有明确不同状态。

`windows.pedump` 和 DLL、进程、内核模块的 `dump` 使用同一存储底座，先验证并规划 PE 头部修改，再逐页写出文件。模块可选择已验证会话层并记录尝试。Patches 保留原始/替换字节，参见 [PE 重建](pe-reconstruction.md) 与 [进程/模块验证](windows-process-modules.md)；重建 PE 与原始虚拟区间是不同导出语义。

完整任务的提取文件在缓存复用前重新校验大小、数据/日志摘要和任务来源。文件丢失、同长度修改和来源不一致都会报错；需要重新提取时使用 `analyze --fresh`，新任务与原始失败证据分别保存。分页列表只展示所选页；verify-artifacts 校验所选任务或全案的全部提取文件，不把未知任务当作成功空范围。

无提取文件的导出保持 evidence/v1。有提取元数据的证据包使用 evidence/v2：结果成员及其摘要照旧，`artifact_index` 指向流式 `artifacts.jsonl`，数据和日志使用案件内相对路径。导出先核验源文件，再对实际复制的数据再次散列；损坏或中途改变会令导出失败并移除不完整 ZIP。未完成且无可靠摘要的文件不作为已验证字节打包，索引保留未包含原因。HTML/JSONL 保留全部提取元数据和失败状态；运行中任务需要先完成或取消，以免产生不一致快照。

独立 Python 核验器兼容 v1/v2，检查成员集合、任务/引用归属、文件大小与摘要、填充日志范围和计数，并确认完整文件中被标记填充的字节确实全为零。partial/failed 文件保留其状态与错误，只核验可导出的字节完整性，不能由摘要推导捕获完整性。散列仍不提供数字签名或外部时间戳认证。

验证覆盖：填充与原始数据区别、取消、未关闭写入器、忽略错误、超长写入、日志写失败、同长度篡改、错误来源、目录越界、schema v1 迁移、中断恢复、缓存拒绝损坏文件及强制新任务、HTML/JSONL/ZIP 导出和独立核验器负例。合成测试还验证不同进程页表、捕获前缀与部分读取、平台 maxsize 的相等/零边界。官方镜像中，Linux 36KiB 和 Windows 4KiB/200KiB 选定区域通过上游文件逐字节对照，缺页比例与实际捕获内容分别记录。[区域提取验证](region-extraction-validation.json) 包含 ISF/原生 PDB 路径与摘要。更多系统/架构、损坏镜像、性能及跨系统磁盘故障语料仍待补齐。
