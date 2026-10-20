# 发布验收与剩余工作

本仓库实现了可运行的开发预览，没有完成原计划的全部取证框架范围。版本保持 `0.1.0-dev`，正式发布门槛关闭。

| 阶段 | 当前状态 |
| --- | --- |
| 固定基线、盘点官方插件 | 锁定提交；AST 清单覆盖 195 个官方插件类，包含需求和参数表达式、别名、来源及未验收状态 |
| 验收语料和差分工具 | 官方资产 SHA-256 清单、合成 Windows/Linux 样本、锁定对照入口、保留重复与树关系的比较器、证据包校验工具 |
| 共同底座 | 原生读取、RAW/LiME/AVML/ELF/Windows 完整与 bitmap 路径、三类 Intel 转换、压缩 ISF、对象、流式插件、SQLite 案件、取消、缓存与恢复已打通；符号及其余格式仍不完整 |
| Windows/Linux 端到端 | 活动进程、内核模块、Windows 线程/VAD/进程 DLL/命令行/注册表 hive 列表、Linux socket/物理任务扫描/打开文件/VMA/路径/进程参数/ELF、banner、ASCII/IOC 扫描；指定字段对照及诊断差异范围见各验证记录 |
| 调查交互 | CLI、三栏异步 TUI、分页/筛选/详情/书签、shell、类型/地址/进程空间探索、HTML/JSONL/ZIP 导出 |
| 分诊 | 六类独立规则评估器；Linux 任务枚举/物理扫描差异、IOC、Windows/Linux 直接 RWX、Linux 删除文件/memfd 执行已连接原生输入；其余缺口明确 unavailable |
| 全能力补齐与 v1.0 | 未完成 |

后续工作按原计划保留，不用“空插件”或无依据跳过抵消缺口：

1. 补齐 Linux/macOS 在线符号索引与自动获取，以及完整内核、DTB、进程空间识别；已有 Windows 完整/bitmap 转储的自动配置、精确身份 PDB 获取与持久转换缓存、原生 PDB/MSF 7.0、DWARF、本地身份索引和部分 Linux x64 DTB 发现。仍需 RAW/虚拟机格式的 Windows 自动识别、旧 MSF、CAB 传输、更多 CodeView/DWARF 语义、KASLR、架构和版本验证。
2. Windows/Linux 的线程完整版本与参数覆盖、扫描进程完整版本与参数、VAD/VMA 完整版本与提取验收、网络、文件恢复、注册表 hive 重建与键枚举、凭据、服务、持久化、内核检查、恶意代码、时间线与其全部参数、导出。当前已有 Windows 活动线程/VAD、Linux 任务线程/凭据/创建时间、链表及 Maple Tree VMA、Windows 活动 hive 链表、默认根键的 `windows.printkey`、NTUSER 的 `windows.userassist`，hive `GetCellRoutine` 是否落在内核模块内的 `windows.getcellroutine`，以及 `windows.amcache` 的程序与文件树、`windows.scheduledtasks` 的动作/触发器笛卡尔积，带空洞日志的稳定 hive 重建，64 位 Windows 8.1 及以后的 `windows.hivescan`，以及 `windows.hashdump` 的 boot key / SAM 解密、`windows.lsadump` 的 LSA secret 和 `windows.cachedump` 的域缓存凭据；递归/筛选验收、逐字节 hive 差分和旧式池头扫描仍未完成。现代 Linux 线程/时钟和 Maple Tree 仅有合成验证，真实新内核与完整元数据验证待补。已有 Linux ELF 段提取及主映像 dump，保留基线地址差异；尚无线程池扫描，ELF 完整版本验收仍待补齐。
3. macOS、VMware、QEMU、Xen、外部交换页及上游其余地址空间和格式语义；AVML v2 已有帧索引、按需解码、CRC/长度核验及重编码语料，真实版本矩阵仍待补齐。Windows 已支持镜像内驻留的 transition 页，prototype 和外部 pagefile 未实现。
4. HTTP/FTP/S3/GS 等远程数据源，以及 YARA、反汇编、LeechCore；正式验收使用完整扩展构建。
5. 将各分诊规则连接到经验证的原生数据生产者；增加真实恶意与正常 VM 对照、共享扫描索引、通用证据图、扩大提取文件管理与持续任务日志。
6. TUI 按列排序、树形浏览、历史导航、快捷切换、全文索引/游标分页和更完整的详情交互；其余上游 renderer 与文件/模块/进程映像完整提取验收；现已有 VAD/VMA 区域、显式地址/DLL/主映像/内核与会话模块的 PE 提取及证据包。
7. 扩大系统版本/架构/格式/损坏场景语料；完成所有字段、类型、层级、缺失值和提取文件差分；测量固定硬件冷启动、扫描吞吐、真实 RSS 与全部交互的 P95。

能力矩阵中的 partial 仅表示存在部分原生实现。`accepted=false` 表示尚未通过完整验收。当前所有官方能力均保持未完全验收，差分字段一致不会自动提升为 complete。

2026-10-20：新增 linux.inodepages 的显式 inode 页缓存枚举与可审计稀疏恢复；四个旧 x64 inode 的 9 页及导出字节完成选定对照。随后新增 Files/find 路径；RecoverFs、大 folio、现代实机版本矩阵仍未完成，详见 [页缓存验证](linux-pagecache.md)。

2026-10-20：linux.files 实现挂载命名空间、超级块缓存目录遍历及类型/路径筛选；inodepages 接入 find 并保留查找证据。选定旧 x64 采集的 9,434 个 inode 和 28,302 个时钟有独立 RAW 验证，现代真实镜像及 RecoverFs/时间线/全部挂载可见性仍待补齐。[详情](linux-files.md)
2026-10-20：linux.recoverfs 将缓存目录、正规文件和快符号链接写入带清单的压缩包。选定 Debian 3.2 采集在 64KiB 上限下核对了 syslog 成员字节；该内核没有 i_link，符号链接失败关闭。完整基线压缩包差分、现代内核和 32 位仍未完成。[详情](linux-recoverfs.md)
2026-10-20：linux.envars 从各任务页表读取环境变量块。选定旧 x64 采集的 1,402 条变量与基线一致，11 个基线跳过的任务改为显式失败。现代内核、32 位和完整参数矩阵仍未完成。[详情](linux-envars.md)

2026-10-21：windows.hivelist 从 `CmpHiveListHead` 枚举活动注册表 hive，保留签名、三个路径字段和链表断裂。选定 Windows 10 19041 样本的 24 个偏移和名称与固定基线一致；稳定 hive 可重建但尚未做逐字节差分，物理扫描仍未完成，根键枚举见 printkey。[详情](windows-hivelist.md)

2026-10-21：windows.hashdump 按固定基线解密 SAM。合成 RC4/AES 向量一致，NT 盐在 `nt_offset+8`。选定 Windows 10 19041 样本的 JD class 页不在内存中，基线 0 行且仍成功，本地改为显式失败。还没有驻留哈希的账户级对照。[详情](windows-hashdump.md)

2026-10-21：windows.lsadump 和 windows.cachedump 复用同一 boot key。Vista secret 用独立 AES 块，更早的系统用 DES；缓存凭据在 Vista 上用 AES-CBC，更早的系统用 HMAC-MD5 加 RC4。合成向量与固定基线一致。选定 Windows 10 19041 样本的 JD class 页不在内存中，基线两条命令都是 0 行且成功，本地改为显式失败。还没有驻留 secret 或缓存账户的对照。[LSA](windows-lsadump.md)，[缓存](windows-cachedump.md)

2026-10-21：windows.hivescan 枚举 64 位 Windows 8.1 及以后的在用 `CM10` 大页分配。选定 Windows 10 19041 样本的 24 个偏移与固定基线一致，签名均为 `0xBEE0BEE0`。Windows 8 以前的分页池头扫描仍未实现。[详情](windows-hivescan.md)
2026-10-21：windows.hivelist 在 `dump=true` 时重建稳定 hive。缺页写入零字节并记入空洞日志，任务失败但保留文件。合成样本与源页一致；真实 SAM 冒烟看到 `hbin` 和两处不可读区间。逐字节 hive 文件对照仍未完成。[详情](windows-hivelist.md)
2026-10-21：windows.printkey 按 HMAP 枚举活动 hive 的稳定与易失子键及值。选定 Windows 10 19041 样本的 478 个根行在偏移、类型、键、名称和 Volatile 上与固定基线一致；100ns 时间分数和 SZ 引号差异单独保留。hive 重建、物理扫描、递归与其他版本仍未完成。[详情](windows-printkey.md)
2026-10-21：windows.userassist 解码 NTUSER hive 的 UserAssist 计数。选定 Windows 10 19041 样本的 37 个键和值中，36 行选定字段与固定基线一致。`UEME_CTLSESSION` 的值单元格不在内存中，基线补 1612 个零字节后解析为 0，本地保留读取错误。XP 语料、32 位和时间线仍未完成。[详情](windows-userassist.md)
2026-10-21：windows.getcellroutine 检查活动 hive 的 `GetCellRoutine` 是否落在内核模块内。选定 Windows 10 19041 样本与固定基线都是 0 行，没有读失败。合成样本覆盖外部模块、区间右端点、大小写、未映射指针和重复模块名。还没有真实挂钩 hive 的对照。[详情](windows-getcellroutine.md)
2026-10-21：windows.amcache 读取 Amcache hive 的程序和文件。选定 Windows 10 19041 样本的 56 个程序、101 个文件及其父子关系与固定基线一致。`InstallDate` 和 `LinkDate` 保持基线中不可达的日期解析。没有驱动项，Windows 8 布局只有合成分组测试。[详情](windows-amcache.md)
2026-10-21：windows.scheduledtasks 从 SOFTWARE hive 解码计划任务的动作、触发器和运行时间。选定 Windows 10 19041 样本的 311 行与固定基线一致。创建时间和上次运行时间保持基线中的对调；时间触发器描述保持不可用，因为 TimeMode 的枚举值是字符串。时间线导出仍未实现。[详情](windows-scheduledtasks.md)

2026-10-21：windows.bigpools 枚举 `PoolBigPageTable`。选定 Windows 10 19041 样本的 7425 个在用分配与固定基线一致，地址保留规范高位；1543 条已释放默认隐藏，23800 条 `Key` 为 0。没有类型时明确失败，不使用备用符号 JSON。真实 32 位和 Vista 以前的布局还没有验收。[详情](windows-bigpools.md)
2026-10-21：windows.unloadedmodules 读取 `MmUnloadedDrivers`。选定 Windows 10 19041 样本的 9 个已卸载模块与固定基线一致；计数为 9，没有截断、跳过或读失败。缺少符号时明确失败。真实 32 位镜像和时间线还没有验收。[详情](windows-unloadedmodules.md)
2026-10-21：windows.envars 读取活动进程的 PEB 环境块。选定 Windows 10 19041 样本的 2960 条变量与固定基线一致。26 个进程的参数或环境页不可读，任务失败并保留诊断；基线跳过这些进程。`silent` 不过滤。真实 32 位镜像还没有验收。[详情](windows-envars.md)
2026-10-21：windows.sessions 列出活动进程的会话和用户。选定 Windows 10 19041 样本的 120 行与固定基线一致。26 个环境页不可读的进程仍保留行，任务失败。时间线和 Windows 11 会话结构还没有验收。[详情](windows-sessions.md)
2026-10-21：windows.crashinfo 读取崩溃转储头。选定 Windows 10 19041 样本的 1 行与固定基线一致，类型是 Bitmap Dump，页数 511191。系统时间使用 `+00:00`。非崩溃镜像明确失败。真实 32 位镜像还没有验收。[详情](windows-crashinfo.md)
2026-10-21：windows.privileges 列出活动进程令牌特权。选定 Windows 10 19041 样本的 4200 行与固定基线一致，120 个进程都读到了令牌。真实 32 位镜像和时间线还没有验收。[详情](windows-privileges.md)
2026-10-21：windows.getsids 列出活动进程令牌 SID。选定 Windows 10 19041 样本的 1752 行与固定基线一致，120 个进程、239 个不可用名称、4 个 ProfileList 用户。没有不可读令牌。真实 32 位镜像和时间线还没有验收。[详情](windows-getsids.md)
2026-10-21：windows.getservicesids 计算 SYSTEM hive 中未知服务的 SID。选定 Windows 10 19041 样本的 189 行与固定基线一致，另有 161 个已知服务名被跳过。真实 32 位镜像和时间线还没有验收。[详情](windows-getservicesids.md)
2026-10-21：windows.kpcrs 列出处理器 KPCR 和 PRCB。选定 Windows 10 19041 样本的 1 行低 48 位与固定基线一致，原生地址保留规范高位。没有跳过的 PRCB。真实 32 位和多处理器镜像还没有验收。[详情](windows-kpcrs.md)
