# 发布验收与剩余工作

本仓库实现了可运行的开发预览，没有完成原计划的全部取证框架范围。版本保持 `0.1.0-dev`，正式发布门槛关闭。

2026-10-23 起，当前阶段调整为 [v0.1 开发验收](v0.1-acceptance.md)：冻结新增插件，先验收已有 133 个命令及 154 个官方类映射，再补案件验证、分诊与关联、报告和 TUI 工作流。下列完整基线范围保留为长期缺口，不作为当前开发迭代的发布要求。

v0.1 增量：`case verify` 现已核对存储 Seal、任务来源、父子关系、分诊引用和提取文件；同样保留 failed/canceled 任务状态。[验证范围](case-verification.md)。

| 阶段 | 当前状态 |
| --- | --- |
| 固定基线、盘点官方插件 | 锁定提交；AST 清单覆盖 195 个官方插件类，包含需求和参数表达式、别名、来源及未验收状态 |
| 验收语料和差分工具 | 官方资产 SHA-256 清单、合成 Windows/Linux 样本、锁定对照入口、保留重复与树关系的比较器、证据包校验工具 |
| 共同底座 | 原生读取、RAW/LiME/AVML/ELF/Windows 完整与 bitmap 路径、三类 Intel 转换、压缩 ISF、对象、流式插件、SQLite 案件、取消、缓存与恢复已打通；符号及其余格式仍不完整 |
| Windows/Linux 端到端 | 活动进程、内核模块、Windows 线程/VAD/进程 DLL/命令行/注册表 hive 列表、Linux socket/物理任务扫描/打开文件/VMA/路径/进程参数/ELF、banner、ASCII/IOC 扫描；指定字段对照及诊断差异范围见各验证记录 |
| 调查交互 | CLI、三栏异步 TUI（多结果标签页、树形浏览、FTS5 全文筛选与按列筛选、游标分页、分组可滚动能力列表/能力搜索、横向列窗口、服务端按列排序、任务快捷切换、命令历史、详情展开与复制、键位帮助）、分页/筛选/详情/书签、shell、类型/地址/进程空间探索、HTML/JSONL/ZIP 导出 |
| 分诊 | 六类独立规则评估器；Linux 任务枚举/物理扫描差异、IOC、Windows/Linux 直接 RWX、Linux 删除文件/memfd 执行已连接原生输入；其余缺口明确 unavailable |
| 全能力补齐与 v1.0 | 未完成 |

后续工作按原计划保留，不用“空插件”或无依据跳过抵消缺口：

1. 补齐 Linux/macOS 在线符号索引与自动获取，以及完整内核、DTB、进程空间识别；已有 Windows 完整/bitmap 转储的自动配置、精确身份 PDB 获取与持久转换缓存、原生 PDB/MSF 7.0、DWARF、本地身份索引和部分 Linux x64 DTB 发现。仍需 RAW/虚拟机格式的 Windows 自动识别、旧 MSF、CAB 传输、更多 CodeView/DWARF 语义、KASLR、架构和版本验证。
2. Windows/Linux 的线程完整版本与参数覆盖、扫描进程完整版本与参数、VAD/VMA 完整版本与提取验收、网络、文件恢复、注册表 hive 重建与键枚举、凭据、服务、持久化、内核检查、恶意代码、时间线与其全部参数、导出。当前已有 Windows 活动线程/VAD、Linux 任务线程/凭据/创建时间、链表及 Maple Tree VMA、Windows 活动 hive 链表、默认根键的 `windows.printkey`、NTUSER 的 `windows.userassist`，hive `GetCellRoutine` 是否落在内核模块内的 `windows.getcellroutine`，以及 `windows.amcache` 的程序与文件树、`windows.scheduledtasks` 的动作/触发器笛卡尔积，带空洞日志的稳定 hive 重建，64 位 Windows 8.1 及以后的 `windows.hivescan`，以及 `windows.hashdump` 的 boot key / SAM 解密、`windows.lsadump` 的 LSA secret 和 `windows.cachedump` 的域缓存凭据；递归/筛选验收、逐字节 hive 差分和旧式池头扫描仍未完成。现代 Linux 线程/时钟和 Maple Tree 仅有合成验证，真实新内核与完整元数据验证待补。已有 Linux ELF 段提取及主映像 dump，保留基线地址差异；尚无线程池扫描，ELF 完整版本验收仍待补齐。
3. macOS、外部交换页及上游其余地址空间和格式语义；VMware/QEMU/Xen 已有原生映射与选定控制，真实采集器和完整版本验收仍待补齐；AVML v2 已有帧索引、按需解码、CRC/长度核验及重编码语料，真实版本矩阵仍待补齐。Windows 已支持镜像内驻留的 transition 页，prototype 和外部 pagefile 未实现。
4. GS/LeechCore 等远程数据源，以及 YARA、Capstone、Arrow；HTTP/HTTPS 条件读取、FTP 本地快照、S3 版本固定读取、Go 原生反汇编和 Mermaid 已接入，完整协议、指令集与渲染验收仍待补齐。正式验收使用完整扩展构建。
5. 将各分诊规则连接到经验证的原生数据生产者；增加真实恶意与正常 VM 对照、共享扫描索引、通用证据图、扩大提取文件管理与持续任务日志。
6. 其余上游 renderer 与文件/模块/进程映像完整提取验收；现已有 VAD/VMA 区域、显式地址/DLL/主映像/内核与会话模块的 PE 提取及证据包。
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
2026-10-21：windows.vadwalk 遍历活动进程 VAD 树。选定 Windows 10 19041 样本的 19999 行与固定基线一致，120 个进程里有 3 个空根。节点地址保留规范高位。真实 32 位和旧式平衡树还没有验收。[详情](windows-vadwalk.md)
2026-10-21：windows.info 报告内核版本和 KUSER。选定 Windows 10 19041 样本的 24 行与固定基线一致，版本 15.19041，系统时间 2025-03-06 17:59:20+00:00。真实 32 位和非崩溃层列表还没有验收。[详情](windows-info.md)
2026-10-21：windows.pstree 按父进程列出活动进程。选定 Windows 10 19041 样本的 120 行与固定基线一致，8 个根，最深 5 层。24 条命令行和 1 条审计名不可用。子节点顺序按活动链表，不复刻 Python set 的迭代顺序；父子关系仍然一致。真实 32 位镜像和时间线还没有验收。[详情](windows-pstree.md)
2026-10-21：windows.joblinks 列出带 Job 的活动进程和 Job 进程链表。选定 Windows 10 19041 样本的 69 行与固定基线一致，41 个作业进程、28 个链接进程。没有 Job 的进程被跳过。真实 32 位镜像和时间线还没有验收。[详情](windows-joblinks.md)
2026-10-21：windows.devicetree 列出驱动和它链接的设备、附着设备。选定 Windows 10 19041 样本的 281 行与固定基线一致，142 个驱动、106 个设备、33 个附着设备，最深 5 层。空指针会停下当前驱动剩余节点。真实 32 位镜像和时间线还没有验收。[详情](windows-devicetree.md)
2026-10-21：windows.handles 列出活动进程的打开句柄。选定 Windows 10 19041 样本的 50967 行与固定基线一致，120 个进程里 109 个 PID 有句柄，41 张 0 层表、76 张 1 层表，最大句柄值 12200。37909 个名称不可用，5 个不可读。真实 32 位镜像和时间线还没有验收。[详情](windows-handles.md)
2026-10-21：windows.ssdt 列出原生系统服务表。选定 Windows 10 19041 样本的 783 行与固定基线一致，473 个服务全部落在 ntoskrnl，18 个地址有多个符号。真实 32 位镜像和时间线还没有验收。[详情](windows-ssdt.md)
2026-10-21：windows.driverirp 列出驱动 IRP 处理函数。选定 Windows 10 19041 样本的 3972 行与固定基线一致，142 个驱动，7 个低地址槽位，3 个模块外地址，2005 个空符号。真实 32 位镜像和时间线还没有验收。[详情](windows-driverirp.md)
2026-10-21：windows.drivermodule 列出起始地址不在已加载模块里的驱动。选定 Windows 10 19041 样本的 1 行与固定基线一致，142 个驱动里 141 个落在模块中，输出的是起始地址为 0 的 RAW。真实 32 位镜像和时间线还没有验收。[详情](windows-drivermodule.md)
2026-10-21：windows.timers 列出内核定时器。选定 Windows 10 19041 样本的 44 行与固定基线一致，512 条链表里检查了 317 个对象，273 个 DPC 被跳过，23 个符号不可用。真实 32 位镜像和时间线还没有验收。[详情](windows-timers.md)

2026-10-21：windows.virtmap 列出内核系统虚拟地址区。选定 Windows 10 19041 样本的 13 行与固定基线一致，名称来自 `SystemVaRegions` 下标。`Size` 是字节数，不是结束地址。真实 32 位镜像和类型数组路径还没有验收。[详情](windows-virtmap.md)

2026-10-21：windows.orphan_kernel_threads 在线程池扫描上寻找模块外的内核线程。选定 Windows 10 19041 样本的 1752 个线程里，1490 个不是 System 或其子进程，3 个已退出或已终止，2 个起始地址在内核范围之下，257 个落在模块里，输出 0 行，与固定基线一致。带孤儿线程的样本还没有验收。[详情](windows-orphan-kernel-threads.md)

2026-10-21：windows.memmap 列出活动进程的内存映射。选定 Windows 10 19041 样本里 PID 2968 的 74969 行与固定基线一致，共 415870976 字节；导出的 `pid.2968.dmp` 逐字节相同。原生地址保留规范高位。其余进程和真实 32 位镜像还没有验收。[详情](windows-memmap.md)

2026-10-21：windows.mbrscan 扫描物理内存里的主引导记录。选定 Windows 10 19041 样本有 8494 个 `55 AA`，29 个引导代码全零被丢掉，8465 条记录和 33860 个分区项与固定基线一致。默认列和 `full=true` 都对照过，325 个分区可启动。真实 32 位镜像和 capstone 反汇编还没有验收。[详情](windows-mbrscan.md)

2026-10-21：windows.truecrypt 在 truecrypt.sys 的 .data 段寻找缓存口令。选定 Windows 10 19041 样本没有该模块，固定基线和原生都输出 0 行。合成样本覆盖了口令长度、可打印范围和对齐填充。带真实口令的镜像还没有验收。[详情](windows-truecrypt.md)

2026-10-21：windows.verinfo 列出内核模块和进程 DLL 的 PE 产品版本。选定 Windows 10 19041 样本的 5918 行与固定基线一致，176 个内核模块版本都不可用，1715 个 DLL 有版本。5 条加载链表在缺页的下一节点停下。`extensive=true`、真实 32 位镜像和时间线还没有验收。[详情](windows-verinfo.md)

2026-10-21：windows.ldrmodules 对照 MZ 开头的 VAD 和 PEB 三条链表。选定 Windows 10 19041 样本的 3193 行与固定基线一致，120 个进程里 103 个有此类 VAD。2660 个在加载链表，2580 个在初始化链表，2660 个在内存链表。真实 32 位镜像、pid 筛选和时间线还没有验收。[详情](windows-ldrmodules.md)

2026-10-21：windows.svcscan 扫描 services.exe 里的 serH 服务记录。选定 Windows 10 19041 样本的 1578 行与固定基线一致，142 个服务头，350 个注册表服务。746 个偏移互不相同，426 个服务正在运行。其他 Windows 版本、32 位和时间线还没有实现。[详情](windows-svcscan.md)

2026-10-21：windows.svclist 在 services.exe 的主映像 VAD 搜索 Sc27 并遍历服务链表，选定 Windows 10 19041 样本的 646 行与固定基线一致。windows.svcdiff 对比扫描和链表的服务名，双方都是 646 个名称，差异为 0。真实隐藏服务阳性及其他布局仍待语料验收；合成测试覆盖同名最后记录、大小写和输出失败。[详情](windows-services.md)

2026-10-21：`linux.pidhashtable` 新增原生旧式 PID 哈希与命名空间 IDR 枚举。Debian 3.2 x64 的 316 条任务在普通/装饰名称两种模式下通过五字段对照；96 个固定基线对象案例通过 144 个原生分页案例验证，读取原始字节、落盘证据及缓存回放均有校验。现代内核真实语料、真实 x86/PAE 和完整验收仍待补齐。[详情](linux-pidhashtable.md)

2026-10-21：`linux.kmsg` 新增文本、`log`、`printk_log` 和现代 `printk_ringbuffer` 原生读取。Debian 3.2 x64 的 1,445 条日志通过五字段有序对照；64 个固定对象案例及 4 个 ID 边界控制覆盖 102 个原生分页案例。完整读取证据、存储校验、缓存、循环/预算/取消/输出失败均有测试；现代真实语料与完整验收仍待补齐。[详情](linux-kmsg.md)

2026-10-21：`linux.perf_events` 新增任务/线程性能事件与 BPF 程序枚举，支持旧式线程组和现代 signal 线程链表。44 个固定对象案例覆盖 66 个分页案例，六字段、读取证据、存储校验、缓存与失败重试均有对照。Debian 镜像只建立 316 个任务、零事件的阴性对照；真实阳性与完整验收仍待补齐。[详情](linux-perf-events.md)

2026-10-21：`linux.fbdev` 新增 framebuffer 枚举和案件内 PNG/原始导出。26 个固定对象案例覆盖 39 个分页案例，比较元数据与像素；Debian 空结果对照及 Kali ARM64 原生阳性导出已验证。固定基线不能翻译该 ARM64 镜像，不将其计为真实阳性差分；完整验收仍待补齐。[详情](linux-fbdev.md)

2026-10-22：`linux.check_ftrace` 新增旧/新 ftrace 哈希布局、首桶过滤链、回调归属和可选 flags。48 个真实对象基线案例覆盖 72 个分页案例及两种展示模式，原始读取、封存和缓存均有验证。Debian 镜像仅验证缺符号时明确失败；尚无真实受支持/阳性差分，非内核符号使用选中模块对象，与基线末范围对象行为有已记录差异。[详情](linux-ftrace.md)

2026-10-22：`linux.sockscan` 新增物理指针扫描与显式内核指针层，保留未知类型、重复、读取证据和失败状态。56 个固定对象案例覆盖 84 个原生分页组合；Debian 对照选项的 404 行显示值及顺序匹配，默认修正 IPv6 指针层后有 478 行，其中 86 条 IPv6 端点独立重读。两种真实运行分别保留 616/444 次对象读取失败，任务均失败，不复用成功缓存；现代真实语料和完整验收待补齐。[详情](linux-sockscan.md)

2026-10-22：新增原生映射 PE 导出表底座，保留名称别名、序号、转发字符串、精确地址查询和逐次读取证据。18 个 pefile/固定 ExportSymbolFinder 对照案例通过；真实 Windows 10 内核的 3,093 条导出及名称查询匹配，原镜像中 70,938 次读取独立重读。此为挂起线程等能力的依赖，尚未实现完整 PDB 优先的跨进程模块符号解析，不增加已验收插件数。[详情](pe-exports.md)

2026-10-22：新增有界 PDB 优先模块符号解析底座，18 组真实固定上游方法对照，原生 x86/x64 PDB 缓存转换、并发获取和错误保留测试通过；真实 Windows 内核 3 个精确符号及 5 次身份读取独立核对。挂起线程插件、跨进程模块收集和动态符号任务缓存接入仍待实现。[详情](module-symbols.md)

2026-10-22：新增原生 `windows.suspended_threads`，30 组真实固定生成器对照、45 组 x86/PAE/x64 原生分页组合、案件落盘和错误控制通过。真实 Windows 阴性对照遍历 1,752 个线程、6,098 次读取独立核对。动态符号任务暂强制重新执行以避免过期结果；真实阳性、版本覆盖及符号依赖缓存仍待验收。插件矩阵 130 项部分实现、65 项未实现、0 项完整验收。[详情](windows-suspended-threads.md)

2026-10-22：模块文件名处理改用主机无关 Windows 路径和固定 Unicode 16 完整映射，修复 UNC/驱动器名、UTF-8 截断、多字符大小写及 Final Sigma 上下文。1,109 组固定路径/候选、87 组上下文字符串和全部 1,112,064 个 Unicode 标量值独立对照；挂起线程分页对照扩充至 36/54 组。真实 Unicode PDB、特殊 RSDS 和符号依赖缓存仍待完成。[详情](windows-paths.md)

2026-10-22：模块 PDB 候选发现扩充为有界 RSDS 扫描，保留跨页、末尾、无调试目录/无 MZ、候选顺序和首 GUID 语义；挂起线程固定生成器扩充至 52 组、分页组合 78 组。读取故障和预算耗尽保留错误，真实阳性与动态缓存仍待验收。[详情](windows-rsds.md)

2026-10-22：新增原生 `windows.pe_symbols`，支持进程 VAD 与会话内核模块来源、精确名称/地址查询、PDB 优先与部分证据。36 个真实分页语料、240 个固定上游命令查询、360 组原生组合核对。真实内核符号命中一致，缺页任务明确失败并保留读取证据。插件矩阵 131 项部分实现、64 项缺失、0 项正式验收。[详情](windows-pe-symbols.md)

2026-10-22：新增原生 `windows.debugregisters`，66 组固定生成器、99 组 x86/PAE/x64 分页组合比较全部 17 列与原始证据。真实 Windows 对照遍历 1,752 个线程并核对 20,932 次读取；零条结果伴随 615 次读失败，明确保留为不完整覆盖。插件矩阵 132 项部分实现、63 项未实现、0 项完整验收。[详情](windows-debugregisters.md)

2026-10-22：新增原生 `windows.etwpatch`，56 个固定生成器案例、84 组分页组合核对全部六列与读取证据。真实 Windows 对照覆盖 120 个进程、960 次函数探测；3,957,291 次原始采集逐次独立重读并核验封印。双方零条结果，但 52,402 次读失败与一个未解析函数使任务保持不完整。插件矩阵 133 项部分实现、62 项未实现、0 项完整验收。[详情](windows-etwpatch.md)

2026-10-22：新增原生 `windows.iat`，90 个固定生成器案例、135 组分页组合对照全部六列、原始字节和封印缓存。真实 Windows 输出 6,404 条导入，上游 6,406 条；两条差异均独立关联到 DLL 名缺页后补零生成的截断名称，完整差分明确保持未匹配。184,362 次原始采集及可用 IAT 指针逐次独立核验。插件矩阵 134 项部分实现、61 项未实现、0 项完整验收。[详情](windows-iat.md)

2026-10-22：新增原生 `windows.malfind` 与旧名称转发，70 个固定生成器案例、105 组分页组合覆盖 VAD 筛选、脏页、非零页、原始字节及提取空洞。真实 Windows 的 6 条发现十个字段匹配，1,670 次缺页明确保持部分覆盖；反汇编文本和真实脏页路线未完成验收。插件矩阵 136 项部分实现、59 项未实现、0 项完整验收。[详情](windows-malfind.md)

2026-10-22：新增原生 `windows.strings`，输入快照摘要进入缓存；24 个固定上游生成器、1,038 个解析案例及 36 组原生分页组合通过。真实样本 154 条选定字段全部匹配，14,143 次读取独立重验，1,320 个不可用映射保持部分覆盖。插件矩阵 137 项部分实现、58 项未实现、0 项完整验收。[详情](windows-strings.md)

2026-10-22：新增原生 `windows.mftscan`、`windows.ads`、`windows.residentdata`。70 个真实上游 YARA/生成器案例覆盖扫描重叠、类型表字节宽度、驻留流和损坏输入；真实 Windows 的 16,370 / 5 / 925 行与基线字段、树形及内容匹配。每项保留 7 次缺页和 11 条候选诊断，仍为部分覆盖。插件矩阵 140 项部分实现、55 项未实现、0 项完整验收。[详情](windows-mft.md)

2026-10-22：新增原生 Go 字节正则匹配核心，支持回溯引用、固定宽度后向断言、条件、原子组、空匹配推进及取消/资源边界。12,580 组 Python 3.12 匹配区间完成差分；通用及 Linux VMA 取证扫描管线尚未接入，矩阵仍为 140 partial / 55 missing / 0 accepted。[详情](byte-regex.md)

2026-10-23：Shimcache 底座新增固定基线 `last_modified`、`last_update` 和 `exec_flag` 解码，保留时间缺失/不可解析/不可读分类、detail 指针掩码、原始读取证据及原版成功执行标记最终归为 N/A 的控制流。595 个上游对象案例覆盖 12 个布局、x86/x64、48 位/全宽掩码、负时间和 blob 故障。[详情](windows-shimcache-temporal.md)

2026-10-23：`windows.shimcachemem` 新增 Windows 8+ 原生路径：34 个固定版本选择控制、模块 `.data`/`PAGE` 定位、双 handle 校验、链表遍历及路径/大小/时间投影。Windows 10 样本输出 4 条，前三路径和全部可读字段与固定基线一致；第 4 条缺页在基线为 `null`，原生保留错误并明确令任务失败。XP 至 Windows 7、真实 x86/PAE、时间线和完整验收仍待补齐，插件保持 partial。[详情](windows-shimcache.md)

2026-10-23：开始补齐 v0.1 非插件底座，新增 HTTP/HTTPS 原生随机读取源。强 ETag 与条件 Range 读取固定远程版本，完整 SHA-256、任务前后及缓存回放前均核对身份；支持 TLS、取消、关闭和来源凭据脱敏。HTTP/TLS 传输控制与 Linux 分页分析/缓存/案件校验建立合成测试；无强 ETag/Range 的快照回退及其余远程协议仍待实现。[详情](http-sources.md)

2026-10-23：shell 新增 `dis/disasm ADDRESS [LENGTH] [ARCH]`，在当前物理/内核/进程空间进行原生 x86/x64/ARM/ARM64 反汇编，输出层、地址、机器码与指令，验证源身份并保留读取和解码失败。所选层、架构、跳转目标、取消与输出失败均有控制测试；完整 volshell、Capstone 与指令集差分验收仍待完成。[详情](shell-disassembly.md)

2026-10-23：新增 `analyze --format mermaid` 原生流式树图，以证据父链接连线，保留每条结果和列顺序，标签转义并明确报告写出失败。6 组真实固定 TreeGrid/MermaidRenderer 输出逐字节一致，另有父链接、重复 PID、缺失值和注入控制；报告导出、复杂值与浏览器/大图验收待补齐。[详情](mermaid-renderer.md)

2026-10-23：新增原生 Xen ELF64 Core 的 PFN/P2M 来宾物理层及有界 ELF 元数据校验。11 组真实固定层对照保留 3 组字节一致和 8 组明确差异；Windows/Linux 合成分页、封存和缓存通过，Debian 512MiB RAW 的两种流式重编码保留完整物理散列与 133 条指定进程列。重编码不是实际 Xen 采集器语料，完整验收保持未完成。[详情](xen-core.md)

2026-10-23：新增 VMware VMEM + VMSS/VMSN 配套区域映射，绑定两个成员的散列、元数据变化检测及案件别名保护；26 组实际固定上游控制保留 18 组合法读出一致、1 组无序差异及 7 组无效控制，Windows/Linux 合成分页与缓存通过。真实 VMware 采集、嵌入式快照与完整自动配置仍待验收。[详情](vmware.md)

2026-10-23：新增 QEMU v3 / RAM v4 原生层，覆盖普通/填充页、迁移连续节、默认 PCI 空洞及 VM 描述的设备字段边界。20 组控制保留 14 组固定层页面一致及 6 组明确差异，并与固定 QEMU v9.2.0 官方分析器的 RAM 页面散列一致（记录 Python 3 ord 兼容适配）。Windows/Linux/HTTP 合成管线及 Debian 512MiB 重编码的完整物理散列、133 条指定进程字段与缓存通过；真实采集器和其余压缩/布局仍待补齐。[详情](qemu.md)

2026-10-23：新增 FTP 二进制本地快照源，支持 EPSV/PASV、可用 SIZE/MDTM 校验、凭据脱敏、取消/超时和失败清理；快照散列绑定 provenance，任务与缓存使用固定本地字节。固定 ResourceAccessor 的完整散列和 seek/read 控制、Windows/Linux 分页与 FTP VMware 配套均通过；Debian 512MiB 回环 FTP 完整散列、自动发现和 133 条指定进程字段一致。公网协议矩阵、FTPS、持久缓存与断点续传待补齐。[详情](ftp-sources.md)

2026-10-23：新增 AWS Go SDK 原生 S3 条件范围源，固定版本/ETag，接入默认凭据链、显式兼容端点、匿名读取和 offline；来源身份参与任务缓存。独立 SigV4、实际固定 cloudstorage+s3fs 的 seek/read、Windows/Linux 分页及 S3 VMware 配套测试通过；官方 Debian 512MiB 回环 S3 完整散列、自动发现和 133 条指定进程字段一致。真实云服务、其余凭据提供者与特殊 bucket 仍待验收。[详情](s3-sources.md)
