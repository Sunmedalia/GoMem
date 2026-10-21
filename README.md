# GoMem

Go 原生、只读的内存取证引擎与交互式 TUI。当前版本 **0.1.0-dev，开发预览**，不能作为完整 Volatility 替代品或“镜像正常”的判断依据。

固定基线为 [Volatility 3 v2.28.2](https://github.com/volatilityfoundation/volatility3/releases/tag/v2.28.2)，提交 `881e970121c16f0932fb9d16fbd5fb258cbcbf75`。已经盘点 **195 个官方插件类**（包含旧名称入口），完整验收通过 **0 项**。原生进程、模块和 banner 能力已有指定字段对照，仍缺少参数、场景及全部字段验收。[能力矩阵](docs/capabilities.json)、[验证记录](docs/validation.json)、[剩余工作](docs/roadmap.md) 是发布依据。

运行时不调用 Python、Volatility 或外部进程。Python 仅用于开发期生成清单、下载公开测试资料、运行固定对照工具和核验导出。

## 构建与快速体验

需要 Go 1.26.2 或更新的 1.26 工具链。

```sh
go build -trimpath -o bin/gomem ./cmd/gomem
bin/gomem doctor --offline
bin/gomem plugins
go run ./tools/fixture --out .cache/fixtures

bin/gomem analyze linux.pslist \
  --image .cache/fixtures/linux.raw --symbols .cache/fixtures/linux.json \
  --os linux --dtb 0x1000 --case .cache/demo --format jsonl

bin/gomem tui --image .cache/fixtures/linux.raw \
  --symbols .cache/fixtures/linux.json --os linux --dtb 0x1000 --case .cache/demo
```

生成的是确定性的合成内存，适用于演示和回归测试。真实镜像仍需提供确切匹配的符号和物理页表根。

Windows 合成样本：

```sh
bin/gomem analyze windows.pslist \
  --image .cache/fixtures/windows.raw --symbols .cache/fixtures/windows.json \
  --os windows --dtb 0x1000 --kernel-base 0x4000 --format table
```

## 已实现的分析路径

| 原生命令 | 当前适用条件 |
| --- | --- |
| `generic.info` | 物理段、大小与文件偏移 |
| `banners` | ASCII Linux/Darwin 内核 banner、Windows 内核 RSDS 身份 |
| `generic.strings` | ASCII 可打印字符串；`--param min=8`；长字符串明确标记截断 |
| `generic.ioc` | 精确字节串；`--param needle=example`；支持块边界、连续物理段边界和重叠命中 |
| `windows.pslist` | 活动进程、线程/句柄/会话/WoW64/时间；物理偏移显示及主映像 PE 提取 |
| `windows.modules` | 内核模块与路径；基址/名称子串筛选；支持从已验证会话层重建 PE |
| `windows.cmdline` | 读取各进程原生 PEB 命令行；保留原始 UTF-16、捕获长度和明确读取错误；PID 集合筛选 |
| `windows.envars` | 读取各进程 PEB 环境块；`Block` 是指针字段地址；`silent` 不过滤；读失败保留诊断并令任务失败；[说明](docs/windows-envars.md) |
| `windows.sessions` | 列出活动进程的会话 ID，并用 `USERDOMAIN`/`USERNAME`/`SESSIONNAME` 组成用户和会话类型；环境页读失败仍保留该行；[说明](docs/windows-sessions.md) |
| `windows.crashinfo` | 读取 Windows 崩溃转储头；完整转储的 bitmap 字段不适用，bitmap 转储给出页数和头大小；非崩溃镜像明确失败；[说明](docs/windows-crashinfo.md) |
| `windows.privileges` | 列出活动进程令牌特权；未知索引不输出；令牌指针读失败保留诊断，位图读失败则任务失败；[说明](docs/windows-privileges.md) |
| `windows.getsids` | 列出活动进程令牌 SID；名称按已知 SID、服务 SID、ProfileList 和正则顺序解析；令牌不可读保留空名称，不让任务失败；[说明](docs/windows-getsids.md) |
| `windows.getservicesids` | 为 SYSTEM hive 里不在锁定服务表中的服务计算 SID；已知服务名不输出；[说明](docs/windows-getservicesids.md) |
| `windows.kpcrs` | 列出每个处理器的 KPCR 和 PRCB；未映射的 PRCB 跳过，数组槽读失败则任务失败；[说明](docs/windows-kpcrs.md) |
| `windows.vadwalk` | 遍历活动进程的 VAD 树，输出父节点、左右子节点和地址范围；空根不输出；坏树令任务失败；[说明](docs/windows-vadwalk.md) |
| `windows.info` | 报告内核基址、版本、KUSER 和内核 PE；崩溃转储同时给出固定基线的层名称；[说明](docs/windows-info.md) |
| `windows.pstree` | 按父进程把活动进程排成树；PID 筛选保留祖先和后代；审计名、命令行或路径读不到时记为不可用，任务仍然成功；[说明](docs/windows-pstree.md) |
| `windows.joblinks` | 列出带有 Job 对象的活动进程，以及该 Job 进程链表里的进程；没有 Job 就跳过，不把空结果当成失败；[说明](docs/windows-joblinks.md) |
| `windows.devicetree` | 列出池扫描得到的驱动，以及它的设备和附着设备；空名称保留，空指针会停下该驱动剩余节点；[说明](docs/windows-devicetree.md) |
| `windows.handles` | 列出活动进程的打开句柄；`offset` 非 0 时改为池扫描单个进程；空名称保留为不可用，读取错误留在 `NameError`；[说明](docs/windows-handles.md) |
| `windows.ssdt` | 列出原生系统服务表；64 位按有符号位移解析，32 位使用绝对指针；模块外地址不输出；[说明](docs/windows-ssdt.md) |
| `windows.driverirp` | 列出池扫描驱动的 IRP 处理函数、所在模块和符号；低地址和读失败的槽位跳过；驱动名错误留在 `DriverNameError`；[说明](docs/windows-driverirp.md) |
| `windows.drivermodule` | 列出起始地址不在已加载内核模块里的驱动；对象头名称为六个内置例外之一时做标记；三个名称都没有则跳过；[说明](docs/windows-drivermodule.md) |
| `windows.timers` | 列出内核定时器和 DPC 例程所在的模块、符号；读不到的 DPC 跳过，类型或到期时间读失败则任务失败；[说明](docs/windows-timers.md) |
| `windows.virtmap` | 列出内核系统虚拟地址区；`SystemVaRegions` 用下标取枚举名，`Size` 是字节数而不是结束地址；类型数组沿用基线里记错对象的长度；[说明](docs/windows-virtmap.md) |
| `windows.orphan_kernel_threads` | 列出起始地址不在已加载模块里的内核线程；System 及其子进程才检查，已退出或用户地址跳过；[说明](docs/windows-orphan-kernel-threads.md) |
| `windows.memmap` | 列出活动进程的虚拟地址、物理地址和长度；相同条目的页表整段跳过，物理空洞的大页整段丢掉；[说明](docs/windows-memmap.md) |
| `windows.mbrscan` | 在物理内存中扫描 `55 AA` 并解析主引导记录和四个分区项；全零引导代码丢弃，分区字段缺页则任务失败；[说明](docs/windows-mbrscan.md) |
| `windows.truecrypt` | 在 `truecrypt.sys` 的 `.data` 段寻找缓存口令；没有该模块时不输出口令；长度不是 4 的倍数则任务失败；[说明](docs/windows-truecrypt.md) |
| `windows.verinfo` | 列出内核模块和进程加载顺序 DLL 的 PE 产品版本；内核基址按 48 位截断后读取，缺页的下一链表项结束当前链表；[说明](docs/windows-verinfo.md) |
| `windows.ldrmodules` | 对照 MZ 开头的 VAD 与 PEB 三条加载链表；页表建不起来则任务失败，文件名错误留在 `PathError`；[说明](docs/windows-ldrmodules.md) |
| `windows.suspicious_threads` | 检查活动线程入口所在 VAD 的文件映射、保护和 EXE 路径，保留线程及 VAD 证据；[说明](docs/windows-suspicious-threads.md) |
| `windows.hollowprocesses` | 检查 PEB 映像基址与 EXE/DLL VAD 初始保护，保留不可读数据的诊断；[说明](docs/windows-hollowprocesses.md) |
| `windows.processghosting` | 检查活动进程与具名文件映射的删除状态，保留重叠线索与读取诊断；[说明](docs/windows-processghosting.md) |
| `windows.pebmasquerade` | 读取内核审计名称与原生 PEB 字符串，检查长度声明并保留原始字节和错误；[说明](docs/windows-pebmasquerade.md) |
| `windows.psxview` | 对照活动进程、进程池、线程池所属进程及 csrss 进程句柄，保留各来源坐标；[说明](docs/windows-psxview.md) |
| `windows.svcscan` | 在 `services.exe` 中扫描 `serH` 服务记录；后续记录的偏移是上一条 `PrevEntry` 的地址，不可用字段不按值去重；[说明](docs/windows-svcscan.md) |
| `windows.svclist` | 在 `services.exe` 主映像 VAD 中搜索 `Sc27` 并遍历服务链；[说明](docs/windows-services.md) |
| `windows.svcdiff` | 比较扫描与链表中的服务名，保留仅在扫描中出现的服务及其原始证据；[说明](docs/windows-services.md) |
| `windows.hivelist` | 从 `CmpHiveListHead` 枚举注册表 hive；保留签名、三个路径字段和链表断裂；`dump` 重建稳定 hive，缺页记入空洞日志并令任务失败 |
| `windows.hivescan` | 在 64 位 Windows 8.1 及以后扫描 `PoolBigPageTable` 的在用 `CM10` 分配；旧式池头扫描会明确失败；[说明](docs/windows-hivescan.md) |
| `windows.filescan` | 扫描池头中的文件对象，输出规范虚拟地址和文件名；Windows 10 扫内核层，更早的系统扫物理内存；[说明](docs/windows-filescan.md) |
| `windows.psscan` | 扫描池头中的 `_EPROCESS`，字段与活动进程列表相同；可按 PID 过滤；[说明](docs/windows-psscan.md) |
| `windows.thrdscan` | 扫描池头中的 `_ETHREAD`，输出线程、启动地址、文件路径和创建/退出时间；[说明](docs/windows-thrdscan.md) |
| `windows.mutantscan` | 扫描池头中的 `_KMUTANT`，输出对象地址和对象头名称；没有名称时保留该行；[说明](docs/windows-mutantscan.md) |
| `windows.driverscan` | 扫描池头中的 `_DRIVER_OBJECT`，保留起始地址为 0 或落在内核空间的驱动，并输出三个名称；[说明](docs/windows-driverscan.md) |
| `windows.symlinkscan` | 扫描换页池头中的 `_OBJECT_SYMBOLIC_LINK`，输出来源名、目标名和创建时间；[说明](docs/windows-symlinkscan.md) |
| `windows.modscan` | 扫描非换页池头中的 `_LDR_DATA_TABLE_ENTRY`，输出基址、大小、名称和路径；[说明](docs/windows-modscan.md) |
| `windows.bigpools` | 读取 `PoolBigPageTable`，输出分配地址、可打印标签、池类型、字节数和分配状态；默认隐藏已释放行；[说明](docs/windows-bigpools.md) |
| `windows.unloadedmodules` | 读取 `MmUnloadedDrivers`，输出已卸载内核模块的名称、起止地址和时间；计数超过 1024 时截断；[说明](docs/windows-unloadedmodules.md) |
| `windows.printkey` | 枚举活动 hive 的稳定与易失子键和值；内核 HMAP 优先，低地址只走 Registry 进程；不可读 hive 保留为行而不单独失败任务；[说明](docs/windows-printkey.md) |
| `windows.userassist` | 解码名称含 `ntuser.dat` 的 hive 里的 UserAssist 计数；Win7 及以后用 CookiePad 和已知文件夹 GUID；值读失败不补零；[说明](docs/windows-userassist.md) |
| `windows.getcellroutine` | 报告不在 `ntoskrnl` / `ntkrnlmp` / `ntkrnlpa` / `ntkrpamp` 内的 hive `GetCellRoutine`；未映射保留为行，读失败不当成内核处理函数；[说明](docs/windows-getcellroutine.md) |
| `windows.amcache` | 从第一个名称含 `amcache` 的 hive 读取执行痕迹；程序和文件按程序 ID 组成树；日期字符串沿用基线里走不到的解析；[说明](docs/windows-amcache.md) |
| `windows.scheduledtasks` | 从第一个名称含 `software` 的 hive 解码计划任务；动作和触发器做笛卡尔积；沿用基线里对调的运行时间、走不到的时间模式和去掉前导零的 CLSID；[说明](docs/windows-scheduledtasks.md) |
| `windows.hashdump` | 用 SYSTEM 的 LSA boot key 解密 SAM 的 LM/NT 哈希；缺 hive、boot key 或用户记录时失败，不把空结果当成功；[说明](docs/windows-hashdump.md) |
| `windows.lsadump` | 用同一 boot key 解密 SECURITY 的 LSA secret；Vista 走独立 AES 块，更早的系统走 DES；缺 hive、密钥或 CurrVal 时失败；[说明](docs/windows-lsadump.md) |
| `windows.cachedump` | 用 NL$KM 解密域缓存凭据；Vista 为 AES-CBC，更早的系统为 HMAC-MD5 加 RC4；空槽位跳过，缺密钥时失败；[说明](docs/windows-cachedump.md) |
| `windows.dlllist` | 进程自身地址空间内的 PEB 加载器链表；原生和 WoW64 列表；支持 PID、基址及 RE2 名称筛选 |
| `windows.pedump` | 从显式进程/内核/已验证会话空间重建 PE32/PE32+；保留修改、缺页与读取尝试；上限 256MiB |
| `windows.threads` | 活动进程线程链表、创建/退出时间与进程证据关联；现代 VAD 启动路径；支持 `--param pid=104,108` |
| `windows.vadinfo` | 现代 VAD 区间、动态权限表、提交页数、私有标志和文件路径；支持 PID 集合、包含地址筛选及区域提取 |
| `linux.pslist` | 活动任务与凭据、root 时钟创建时间、可选线程及名称装饰；保留原始计数和身份 |
| `linux.psscan` | 一次物理扫描寻找调度类指针任务候选，保留退出状态、启发式与覆盖信息 |
| `linux.sockstat` | 文件描述符关联的 socket、网络字节序端点、UNIX 原始名称、任务/socket 命名空间和过滤器元数据 |
| `linux.files` | 挂载命名空间及超级块缓存目录枚举；保留路径作用域、硬链接别名、负条目计数和精确 inode 元数据；[说明](docs/linux-files.md) |
| `linux.recoverfs` | 将缓存目录、正规文件和快符号链接写入可复现的压缩包；未缓存区间和超限文件明确失败，不假装已完整恢复；[说明](docs/linux-recoverfs.md) |
| `linux.inodepages` | 正规 inode 或精确路径的 radix/XArray 缓存页及有空洞记录的文件导出；[适用条件](docs/linux-pagecache.md) |
| `linux.lsof` | 任务/线程的文件描述符、带作用域原始路径、inode/设备/权限和纳秒时间；保留部分读取 |
| `linux.elfs` | ELF 映射枚举及分段提取，记录布局、段来源与缺页；提供显式基线布局 |
| `linux.psaux` | 进程自身页表中的参数区、原始字节和参数列表；无用户 mm 时明确显示来源；PID 集合筛选 |
| `linux.process_spoofing` | 对照可执行文件、argv[0] 和 comm，保留原始字节与未完成比较；[说明](docs/linux-process-spoofing.md) |
| `linux.capabilities` | 读取 cred/real_cred 权限位图，保留内核掩码、原始字节和未知位；[说明与基线兼容差异](docs/linux-capabilities.md) |
| `linux.check_creds` | 按凭据对象地址检查活动任务共享，保留成员身份与读取诊断；[说明](docs/linux-check-creds.md) |
| `linux.pstree` | 按进程和线程构建父子树，保留候选对象、筛选与原始证据；[说明](docs/linux-pstree.md) |
| `linux.ptrace` | 检查进程/线程 ptrace 关系，保留标志、对象身份和原始字段；[说明](docs/linux-ptrace.md) |
| `linux.keyboard_notifiers` | 遍历键盘通知链并关联模块和精确符号；空头的零地址读取失败会保留，不把空表当成功；[说明](docs/linux-keyboard-notifiers.md) |
| `linux.check_syscall` | 在没有原生反汇编时按元数据和下一符号确定系统调用表长度，核对精确符号并保留指针字节；[说明](docs/linux-syscall.md) |
| `linux.check_idt` | 检查 0..19 和 128 号中断入口，关联模块与精确符号并保留描述符原始字段；[说明](docs/linux-idt.md) |
| `linux.check_afinfo` | 按符号声明顺序检查网络操作指针的精确内核符号，保留零指针与每项决策；[说明](docs/linux-afinfo.md) |
| `linux.kthreads` | 枚举 Linux 5.8+ 内核线程入口，关联模块与精确符号并保留读取证据；[说明](docs/linux-kthreads.md) |
| `linux.modxview` | 对照活动链表、sysfs 与内存扫描中的内核模块，保留候选、来源及 taint；[说明](docs/linux-modxview.md) |
| `linux.vmcoreinfo` | 无需符号扫描物理内存中的 VMCOREINFO，保留原始 note 与无损键值；[说明](docs/linux-vmcoreinfo.md) |
| `linux.ip.link` / `linux.ip.addr` | 枚举网络接口、链路状态及 IPv4/IPv6 地址，保留命名空间与原始字段；[说明](docs/linux-ip.md) |
| `linux.iomem` | 枚举内核 I/O 内存资源树，保留范围、父子关系与原始字段；[说明](docs/linux-iomem.md) |
| `linux.boottime` | 按时间命名空间枚举启动时间，保留原始时钟、纳秒值与时间线字段；[说明](docs/linux-boottime.md) |
| `linux.envars` | 进程页表中的环境变量块；保留原始字节，缺 `=` 时停止该任务，未映射或超限明确失败；[说明](docs/linux-envars.md) |
| `linux.lsmod` | 匹配 ISF、DTB；旧布局和 `module_layout`；6.4+ `module_memory` 字段尚未补齐 |
| `linux.maps` | VMA 链表或 Maple Tree、权限、inode、设备及带作用域的路径；PID/地址集合筛选；可提取所选区域 |

支持 RAW、LiME v1、AVML v2 Snappy 帧、具有物理 `PT_LOAD` 的 ELF core，以及 Windows 32/64 位完整转储与 bitmap 转储。AVML 按需解码、核验帧 CRC 和长度尾部，使用有界随机读取缓存；[适用条件与验证](docs/avml.md)。其他已识别的容器会明确拒绝；通用 ELF 不代表 Xen 格式已实现。

支持 x86、PAE、四级 x64 页表、4KiB 页及相应大页。Windows 支持镜像中仍驻留的 transition 页，保留权限未知状态；外部交换页、prototype 及未支持的非驻留编码返回读取错误。输入以只读方式打开，按块散列，检查修改时间与大小变化。分析期间仍应保持采集文件不可变。

符号支持 ISF JSON、gzip、xz、ZIP 中的压缩成员，例如 `symbols.zip#linux/kernel.json.xz`。解压限制为 128MiB，xz 字典上限 64MiB。Linux 在目标虚拟地址比对完整 banner；Windows 从内存中 PE debug directory 比对 PDB 名称、GUID 和 Age。[上游符号规则](https://volatility3.readthedocs.io/en/stable/symbol-tables.html)

支持从带 DWARF 的 ELF 或 Mach-O 原生读取符号，也可用 `symbols convert DEBUG_FILE --output kernel.json` 转为 ISF。可选 `--system-map`、`--symbols-from` 合并地址；多架构 Mach-O 使用 `--binary-arch x86_64` 选择切片。类型覆盖 typedef、递归结构、匿名成员、数组、枚举和位字段。[原生符号验证与限制](docs/native-symbols.md)

Windows 可直接传入原生 PDB/MSF 7.0：`--symbols ntkrnlmp.pdb`，或通过同一 `symbols convert` 命令转换。原生解析 CodeView 类型、公共/全局/模块符号、PE 段和 OMAP；符号保持 RVA，由引擎按内核基址重定位并验证 GUID/Age。[PDB 范围与验证](docs/pdb-symbols.md)

可为本地符号建立索引，给定 DTB 后按目标虚拟内存中的完整 Linux banner 或 Windows PDB 身份选择符号：

```sh
bin/gomem symbols index exact-linux.json.xz exact-windows.json --case ./case-001
bin/gomem analyze linux.pslist --image memory.raw --case ./case-001 --dtb 0x123000 --offline
```

默认读取 `CASE/symbols/index.json`，也可用 `--symbol-index INDEX`；`--symbols` 优先。索引核验完整表摘要，拒绝过期来源和多个不同表同时匹配。Windows 仍需 `--kernel-base`。索引不会根据文件名猜测版本。

已有精确符号时，支持部分 Linux x64 内核的 DTB 自动发现：从物理 banner 和初始页表符号的相对位置生成候选，同时验证页表根自身映射和完整 banner。显式 `--dtb` 优先；虚拟 KASLR slide 仍需 `--kernel-slide`。`doctor --image ... --symbols ...` 显示发现依据。[适用条件与验证](docs/linux-discovery.md)

Windows 在已提供 DTB 和内核基址时可自动获取缺失符号：从目标 PE 读取 PDB 身份，在 Microsoft HTTPS 符号服务器下载并原生转换，写入案件的 `symbols/windows` 缓存。`--offline` 禁止网络并允许验证后的缓存复用；也可用 `--symbol-cache`、`--symbol-server` 指定缓存和 HTTPS 服务器。[自动获取与缓存](docs/pdb-symbols.md)

Windows 完整/bitmap 转储可进一步自动选择架构、DTB 和内核基址：转储头线索经 KDBG/模块链表、映射 PE 和精确符号交叉验证。可直接运行 `gomem analyze windows.pslist --image memory.dmp --case ./case-001`；详细条件与失败行为见 [Windows 自动配置](docs/windows-discovery.md)。

`windows.pslist --param physical=true` 显示物理偏移并保持虚拟进程身份；`pslist` 与 `modules` 可用 `--param dump=true` 提取主映像或内核/会话模块 PE。120 个进程通过扩展字段及物理偏移对照，路径读取差异与会话导出范围单独记录。[进程与模块验证](docs/windows-process-modules.md)

`windows.cmdline` 使用各进程自身地址空间读取命令行，显示值、完整声明字符串和原始字节分别保留。官方样本中 96 条可读内容一致，21 条读取错误使全量任务失败并保留结果；嵌入 NUL 和空 PEB 分别记录。[命令行验证](docs/windows-cmdline.md)

`windows.envars` 读取同一 PEB 的环境块。UTF-16LE 按 NUL 切开后丢掉最后一段，没有 `=` 时名称少一个字符。`Block` 是 `Environment` 指针字段的地址，不是块本身。Windows 10 19041 样本有 2960 条变量，PID、进程名、`Block`、名称和值与固定基线一致。另有 29 条诊断，其中 26 个进程的参数或环境页不可读，任务失败；基线会跳过这些进程。`silent` 不隐藏变量，因为基线读取的配置键是 `SILENT`。真实 32 位镜像还没有验收。[环境变量验证](docs/windows-envars.md)

`windows.sessions` 给每个活动进程配上会话 ID，并从环境块拼出 `域/用户`。变量名不区分大小写，后者覆盖前者。只有结果正好是 `/` 时用户名才不适用。Windows 10 19041 样本的 120 行会话 ID、会话类型、PID、进程名、用户名和创建时间与固定基线一致。4 个会话 ID 不适用，10 个会话类型是 `RDP-Tcp#0`。26 个环境页不可读的进程仍保留行，任务失败；基线跳过环境块后仍然成功。真实 32 位镜像和时间线还没有验收。[会话验证](docs/windows-sessions.md)

`windows.crashinfo` 直接读崩溃转储头，不需要内核符号。签名只取 4 字节，`PAGEDU64` 显示为 `PAGE`。Windows 10 19041 样本是 Bitmap 转储，1 行的地址、版本、CPU 数、运行时间、注释、系统时间和 bitmap 摘要与固定基线一致。系统时间写成 `+00:00`。注释在第一个 NUL 或无法解码的字节处截断。普通 RAW 镜像会失败。真实 32 位镜像还没有验收。[崩溃转储头验证](docs/windows-crashinfo.md)

`windows.privileges` 从活动进程的 `_EX_FAST_REF` 令牌读取特权位。64 位清低 4 位，32 位清低 3 位。Windows 10 19041 样本有 120 个进程、4200 行，PID、进程名、特权值、名称、属性和描述与固定基线一致。没有跳过的令牌。真实 32 位镜像和时间线还没有验收。[特权验证](docs/windows-privileges.md)

`windows.getsids` 从同一令牌列出 SID。标识机构只取 6 字节里的最后一个字节。Windows 10 19041 样本有 120 个进程、1752 行，PID、进程名、SID 和名称与固定基线一致。239 个名称不可用，4 个来自 ProfileList。没有不可读令牌。真实 32 位镜像和时间线还没有验收。[SID 验证](docs/windows-getsids.md)

`windows.getservicesids` 只看名称包含 `machine\system` 的 hive。服务名在锁定的 461 项表里就不输出。其余名称用大写后每个字符补 NUL 再做 SHA1，得到 `S-1-5-80` SID。Windows 10 19041 样本有 1 个 SYSTEM hive、189 行，跳过 161 个已知服务。SID 和服务名与固定基线一致。真实 32 位镜像和时间线还没有验收。[服务 SID 验证](docs/windows-getservicesids.md)

`windows.kpcrs` 从 `KiProcessorBlock` 读取每个处理器的 `_KPRCB`，再按 `_KPCR.Prcb` 的偏移回推 KPCR。有 `CurrentPrcb` 时 PRCB 列用这个指针的值。Windows 10 19041 样本有 1 个处理器，KPCR 和 PRCB 的低 48 位与固定基线一致；原生地址保留规范高位。真实 32 位和多处理器镜像还没有验收。[KPCR 验证](docs/windows-kpcrs.md)

`windows.vadwalk` 走和 `windows.vadinfo` 相同的现代 VAD 树。Windows 10 19041 样本有 120 个进程、19999 个节点，另有 3 个空根。父节点、左右子节点、起止地址和池标签与固定基线一致。节点地址保留规范高位，对照时这四列只比较低 48 位。真实 32 位和旧式平衡树还没有验收。[VAD 树验证](docs/windows-vadwalk.md)

`windows.info` 读取内核基址、DTB、KDBG、`KdVersionBlock`、`KUSER_SHARED_DATA` 和内核 PE。Windows 10 19041 样本的 24 行与固定基线一致，版本是 15.19041，系统时间是 `2025-03-06 17:59:20+00:00`。地址按低 48 位输出。真实 32 位和非崩溃镜像的层列表还没有验收。[系统信息验证](docs/windows-info.md)

`windows.pstree` 用活动进程的 PPID 组树。Windows 10 19041 样本有 120 个进程、8 个根，最深 5 层。PID、PPID、名称、线程、会话、WoW64、创建/退出时间、审计名、命令行、路径和父子关系与固定基线一致。24 条命令行和 1 条审计名不可用。句柄列因为没有 `HandleCount` 全部不可读。节点地址保留规范高位。真实 32 位镜像、物理偏移和时间线还没有验收。[进程树验证](docs/windows-pstree.md)

`windows.joblinks` 只输出 Job 指针能解开的活动进程，再顺着 `ProcessListHead` 走 `JobLinks`。Windows 10 19041 样本有 41 个作业进程和 28 个链表进程，计数、会话、路径和父子关系与固定基线一致。没有 Job 的进程被跳过。真实 32 位镜像、物理偏移和时间线还没有验收。[作业链接验证](docs/windows-joblinks.md)

`windows.devicetree` 复用驱动池扫描，但不因为三个名称都缺失而丢掉驱动。驱动、设备和附着设备分别是 `DRV`、`DEV`、`ATT`。显示用的偏移始终是驱动对象，设备自己的地址留在 `ObjectOffset`。Windows 10 19041 样本有 142 个驱动、106 个设备、33 个附着设备，最深 5 层，名称和设备类型与固定基线一致。空字符串会保留。空指针或附着驱动名读失败会停下该驱动剩下的节点，已经输出的行保留，任务仍然成功。真实 32 位镜像和时间线还没有验收。[设备树验证](docs/windows-devicetree.md)

`windows.handles` 走活动进程的句柄表。`offset` 非 0 时忽略 PID，只保留池扫描里那个进程。Windows 10 19041 样本有 120 个进程、41 张 0 层表、76 张 1 层表和 50967 个句柄，来自 109 个 PID，最大句柄值 `0x2fa8`。PID、进程名、低 48 位偏移、句柄值、类型、访问掩码和名称与固定基线一致。37909 个名称不可用，5 个不可读；对照列不带错误，错误留在 `NameError`。3 张句柄表读不到。真实 32 位镜像、Windows 8 以前的真实句柄表和时间线还没有验收。[句柄验证](docs/windows-handles.md)

`windows.ssdt` 读取 `KiServiceTable`。64 位表项先丢掉低 4 位，再按有符号位移加到表基址；32 位表项就是绝对指针。Windows 10 19041 样本有 473 个服务、783 行，全部在 `ntoskrnl`，和固定基线的索引、低 48 位地址、模块名、符号一致。18 个地址有多个符号。没有模块外地址。真实 32 位镜像和时间线还没有验收。[系统服务表验证](docs/windows-ssdt.md)

`windows.driverirp` 用同一套驱动池扫描，但不因为三个名称都缺失而丢掉驱动。`DriverStart` 和处理函数都先按 64 位低 48 位、32 位低 32 位做掩码。处理函数小于掩码后的内核起始地址，或者槽位读不到，就跳过该槽位，任务仍然成功。Windows 10 19041 样本有 142 个驱动、3972 行。7 个低地址槽位都属于同一个读不到名称的驱动，该驱动输出 21 行；没有不可读槽位。3 个地址在模块外，2002 个地址在模块内但没有符号。`IRP_MJ_PNP` 和 `IRP_MJ_SYSTEM_CONTROL` 各有一个地址对应多个符号。低 48 位偏移、驱动名、IRP、地址、模块和符号与固定基线一致。真实 32 位镜像和时间线还没有验收。[驱动 IRP 验证](docs/windows-driverirp.md)

`windows.drivermodule` 对应 `windows.malware.drivermodule.DriverModule`。上游的 `windows.drivermodule.DriverModule` 只是弃用别名。它复用驱动池扫描，起始地址为 0 的驱动保留，落在任一已加载模块里的驱动不输出。三个名称都不可用时跳过。只有对象头名称正好是 `ACPI_HAL`、`PnpManager`、`RAW`、`WMIxWDM`、`Win32k` 或 `Fs_Rec` 时，已知例外为真。Windows 10 19041 样本有 142 个通过起始检查的驱动，141 个落在模块里，只输出 `RAW`。它的起始地址是 0，服务键不可用，备选名是 `\FileSystem\RAW`，已知例外为真。另外五个内置名称都在模块里，没有输出。真实 32 位镜像和时间线还没有验收。[隐藏驱动验证](docs/windows-drivermodule.md)

`windows.timers` 从每个处理器的 KPCR 定时器表走 `Flink`。Windows 10 19041 样本有 1 个处理器、512 条链表、317 个定时器对象。类型不是 8 或 9 的没有出现。273 个 DPC 读不到或例程为 0，被跳过。剩下 44 行与固定基线的低 48 位偏移、到期时间、周期、信号、例程、模块和符号一致。9 个已信号，35 个是 `-`。23 个例程在模块内但没有符号，没有落在模块外的例程。`KiWaitNever` 和 `KiWaitAlways` 存在，DPC 指针按固定算法解码。真实 32 位镜像、Windows 7 和旧的 `KiTimerTableListHead` 路径还没有验收。[定时器验证](docs/windows-timers.md)

`windows.virtmap` 列出内核系统虚拟地址区。有 `MiVisibleState.SystemVaRegions` 时，名称来自下标对应的 `_MI_SYSTEM_VA_TYPE`，不是槽内字节。`BaseAddress` 按指针掩码，`NumberOfBytes` 原样保留。固定基线把字节数放在名为 `End offset` 的列里。Windows 10 19041 样本的 13 行低 48 位起始地址和字节数与固定基线一致，路径是 `SystemVaRegions`，大页尺寸算出 2097152 但没有使用。`MiVaPagedPool` 起始于 `0xfcf68050b648`。没有 `SystemVaRegions` 时沿用基线的类型数组状态机：连续区段的长度记到下一个名称，末段多出的页被丢掉。真实 32 位镜像和那两条旧路径还没有语料差分。[系统地址区验证](docs/windows-virtmap.md)

`windows.orphan_kernel_threads` 在线程池扫描上只保留 System 或其子进程里、尚未退出、起始地址处于内核范围、且没有落入任何已加载模块的线程。Windows 10 19041 样本有 1752 个线程：1490 个不是这类进程，3 个已退出或已终止，2 个起始地址在内核范围之下，257 个落在模块里。输出 0 行，与固定基线的空结果一致。真实 32 位镜像和带孤儿线程的样本还没有验收。[孤儿内核线程验证](docs/windows-orphan-kernel-threads.md)

`windows.memmap` 走活动进程的页表。Windows 10 19041 样本里 PID 2968 `notepad.exe` 有 74969 段、415870976 字节，虚拟地址、物理地址、长度、文件偏移和 `Disabled` 与固定基线一致。虚拟地址保留规范高位，对照时只比较低 48 位。整页相同的页表被丢掉，物理范围不完整的大页也不输出。`dump=true` 写出的 `pid.2968.dmp` 与固定基线逐字节相同。其余进程和真实 32 位镜像还没有验收。[内存映射验证](docs/windows-memmap.md)

`windows.mbrscan` 在物理层搜索 `55 AA`。记录起点在签名前 `0x1FE` 字节，长度 `0x200`。引导代码是前 `0x1B8` 字节，全零就丢掉。磁盘签名是偏移 440 的四个字节。四个分区项从 446 开始，只有标志 `0x80` 可启动。类型名来自固定的 `mbr.json`。Windows 10 19041 样本扫到 8494 个签名，29 个引导代码全零，剩下 8465 条主引导记录和 33860 个分区项。默认列和 `full=true` 都与固定基线一致，其中 325 个分区可启动。参考环境没有 capstone，反汇编列是带一层额外引号的十六进制。分区字段有缺页时任务失败。真实 32 位镜像还没有验收。[主引导记录验证](docs/windows-mbrscan.md)

`windows.truecrypt` 只检查已加载模块里第一个名为 `truecrypt.sys` 的驱动，大小写不敏感。它把 `.data` 按有符号 32 位长度扫描，口令字节必须落在 `0x20` 到 `0x7E`，长度后面跳过一个字节，再要求三个对齐字节为 0。Windows 10 19041 样本没有这个模块，固定基线发出警告后不输出行，原生结果同样是 0 条口令。合成样本覆盖了长度、字符范围、对齐填充和缺少 `.data` 段。真实口令镜像还没有验收。[TrueCrypt 验证](docs/windows-truecrypt.md)

`windows.verinfo` 列出内核模块和进程 DLL 的产品版本。内核模块只在每个会话的第一个进程地址空间里读，指针先按低 48 位截断，所以规范内核地址的版本不可用，展示用的基址仍保留原值。进程 DLL 走加载顺序链表，下一节点不可读就结束该链表。产品版本来自 `VS_FIXEDFILEINFO[0]`。Windows 10 19041 样本有 176 个内核模块和 5742 个 DLL，共 5918 行，与固定基线一致。其中 1715 个 DLL 有版本，328 个名称不可用，5 条链表在缺页处停下。`extensive=true` 会改报文件版本，还没有语料差分。真实 32 位镜像和时间线还没有验收。[版本信息验证](docs/windows-verinfo.md)

`windows.ldrmodules` 找出进程里以 `MZ` 开头的 VAD，并记录基址是否在加载、初始化和内存三条 PEB 链表中。WoW64 链表使用固定基线 `wow64.json` 的 32 位偏移。Windows 10 19041 样本检查了 120 个进程，103 个有此类 VAD，共 3193 行，与固定基线一致。2660 个在加载链表，2580 个在初始化链表，2660 个在内存链表，3 个路径不可用。PID 4 的 `\Windows\SysWOW64\ntdll.dll` 不在三条链表里。真实 32 位镜像、`pid` 筛选和时间线还没有验收。[加载模块验证](docs/windows-ldrmodules.md)

`windows.svcscan` 在 `services.exe` 里搜索 `serH`，并沿 `PrevEntry` 读取 Windows 10 19041 x64 服务记录。链上第一条偏移是记录本体，后面每条是上一条 `PrevEntry` 字段的地址。只有 PID、路径都读到且服务名在注册表映射里时，重复元组才会截断当前链。Windows 10 19041 样本有 1 个 `services.exe`、142 个服务头、350 个注册表服务和 1578 行，与固定基线一致。1196 个按需启动，426 个正在运行，1373 个 PID 为空。其他版本、32 位和时间线还没有实现。[服务扫描验证](docs/windows-svcscan.md)

`windows.svclist` 从 `services.exe` 的主映像 VAD 中搜索 `Sc27`，沿服务链表输出记录。Windows 10 19041 样本的 646 行、11 个字段与固定基线一致，其中 189 个服务正在运行。`windows.svcdiff` 按服务名比较这份列表与 `svcscan`，同名时保留最后一次扫描的记录；该样本两边都是 646 个服务名，差异为 0。真实隐藏服务尚待语料验证，阳性逻辑由合成测试覆盖。缺少进程层、主映像 VAD 或可比较名称时，差异检查明确失败。[服务对照验证](docs/windows-services.md)

`windows.hivelist` 正向遍历内核 hive 链表，签名不符或链表断裂时改为反向补齐，并保留已经读到的 hive。名称按 `FileFullPath`、`FileUserName`、`HiveRootPath` 取第一个非空值，三个字段都保留。Windows 10 19041 样本的 24 个偏移和名称与固定基线一致；该样本的 `FileFullPath` 成员均为空，选中名称来自另外两个字段。`dump=true` 写出 base block 和稳定存储；读不到的页是带日志的零字节，任务失败，不会把空洞说成原始数据。[注册表 hive 验证](docs/windows-hivelist.md)

`windows.hivescan` 从大页池表找出在用的 `CM10` 分配。Windows 10 19041 样本的 24 个地址与固定基线一致，并且都带有 `0xBEE0BEE0` 签名。32 位和 Windows 8 以前的 hive 仍会明确失败，不从文件对象扫描里恢复。[池扫描验证](docs/windows-hivescan.md)

`windows.filescan` 在池头中寻找分配态 `Fil\xe5` 和释放态 `File`，雕出 `_FILE_OBJECT`。Windows 10 19041 样本扫过 6416 个内核范围、387,543,040 字节，4866 个文件的低 48 位地址和文件名与固定基线一致。3 个文件名读不完整的对象被丢掉并计入摘要，没有写成空名字。32 位和 Windows 8 以前的真实镜像还没有验收。模块池扫描见 `windows.modscan`。[文件对象扫描验证](docs/windows-filescan.md)

`windows.psscan` 用同一套池头扫描寻找 `Pro\xe3` 和 `Proc`。Windows 10 19041 样本得到 121 个进程，选定字段与固定基线一致，比活动链表多一个不在链表上的 PID 408 `MpCmdRun.exe`。句柄列因为没有 `HandleCount` 而保持为空。32 位、Windows 8 以前的真实镜像和时间线还没有验收。[进程池扫描验证](docs/windows-psscan.md)

`windows.thrdscan` 用同一套池头扫描寻找 `Thr\xe5` 和 `Thre`。`Thre` 还要对象类型是 Thread。Windows 10 19041 样本得到 1752 个线程，偏移、PID、TID、两个启动地址、两个路径、创建时间和退出时间都与固定基线一致，并且和活动线程链表是同一组对象。4 个创建时间为空。退出时间沿用基线的有符号 FILETIME，包括落到 1600 年的值。32 位、Windows 8 以前的真实镜像和时间线还没有验收。[线程池扫描验证](docs/windows-thrdscan.md)

`windows.mutantscan` 用同一套池头扫描寻找 `Mut\xe1` 和 `Muta`，类型必须是 Mutant。固定基线的 `_KMUTANT` 检查接受每一个雕出来的对象。名称来自对象头：Windows 7 及以后用 `ObpInfoMaskToOffset` 在 `InfoMask & 3` 处取偏移。偏移或长度无效时名称不可用，行仍然保留。Windows 10 19041 样本有 742 个互斥体，低 48 位地址和名称与固定基线一致，其中 448 个名称不可用。类型不符的候选有 2199 个，没有读失败。32 位和 Windows 8 以前的真实镜像还没有验收。[互斥体扫描验证](docs/windows-mutantscan.md)

`windows.driverscan` 用同一套池头扫描寻找 `Dri\xf6` 和 `Driv`，类型必须是 Driver。`DriverStart` 要能读 8 字节，并且是 0 或者严格高于 `MmSystemRangeStart`。三个名称里至少要有一个；空字符串和无效地址都算不可用。Windows 10 19041 样本有 142 个驱动，低 48 位偏移、起始地址、大小和三个名称与固定基线一致。其中一个服务键缓冲区是非规范地址 `0x508f8d480000017d`，对照列和基线一样为空，读取错误留在 `ServiceKeyError`。另有 804 个候选类型不符。32 位和 Windows 8 以前的真实镜像还没有验收。[驱动扫描验证](docs/windows-driverscan.md)

`windows.symlinkscan` 用同一套池头扫描寻找 `Sym\xe2` 和 `Symb`，但只接受换页池和空闲池，类型必须是 SymbolicLink。来源名不做互斥体的长度检查；长度为 0 仍是空字符串。名字缺失或目标读失败会丢掉该行。目标长度为 0 时保留空字符串。创建时间读取失败会让任务失败。Windows 10 19041 样本有 219 个符号链接，低 48 位偏移、创建时间、来源名和目标名与固定基线一致，其中一个目标为空。另有 12 个名字或目标读失败、523 个类型不符。32 位、Windows 8 以前的真实镜像和时间线还没有验收。[符号链接扫描验证](docs/windows-symlinkscan.md)

`windows.modscan` 用同一套池头扫描寻找 `MmLd`。它没有执行体对象类型，模块对象紧跟在池头后面，只接受非换页池和空闲池。`DllBase` 或 `SizeOfImage` 读失败会让任务失败。名称长度为 0 时保留空字符串，读失败留在 `NameError` 或 `PathError`。Windows 10 19041 样本有 177 个模块，低 48 位偏移、基址、大小、名称、路径和字面量 `Disabled` 与固定基线一致。其中 1 个基础名和 20 个路径不可读。`dump` 还没有做文件差分。32 位和 Windows 8 以前的真实镜像还没有验收。[模块池扫描验证](docs/windows-modscan.md)

`windows.bigpools` 直接读 `PoolBigPageTable`，不是池头扫描。`Key` 为 0 的条目丢掉，`Va` 最低位表示已释放，默认不输出。标签只保留可打印字节。Windows 10 19041 样本有 32768 条表项，7425 个在用分配的地址、标签、池类型、字节数和状态与固定基线一致，地址保留规范高位。1543 条已释放，23800 条 `Key` 为 0。没有 `_POOL_TRACKER_BIG_PAGES` 时明确失败，不加载备用符号。真实 32 位镜像还没有验收。[大页池验证](docs/windows-bigpools.md)

`windows.unloadedmodules` 读取 `MmUnloadedDrivers`。64 位记录 40 字节，32 位记录 24 字节，布局来自锁定的符号 JSON，不在内核 PDB 里。名称长度为 0 时是空字符串；单条读失败跳过，表指针或计数读失败则任务失败。计数超过 1024 截断。Windows 10 19041 样本有 9 个已卸载模块，名称、起止地址和时间与固定基线一致，没有跳过或读失败。本地地址保留完整值，对照时套低 48 位掩码。缺少符号时明确失败，不返回空成功。真实 32 位镜像和时间线还没有验收。[已卸载模块验证](docs/windows-unloadedmodules.md)

`windows.hashdump` 读取 `ControlSet001` 的 LSA 类数据并解密 SAM。合成向量与固定基线的 RC4/AES 路径一致，NT 盐保持在 `nt_offset+8`。Windows 10 19041 样本的 `JD` class 页不在内存中，基线输出 0 行，本地任务失败并保留读取错误，没有可对照的账户哈希。[SAM 哈希验证](docs/windows-hashdump.md)

`windows.lsadump` 用同一 boot key 解密 SECURITY 的 LSA secret。Vista 及以后对 `PolEKList` 做独立 AES 块，更早的系统对 `PolSecretEncryptionKey` 做 MD5/RC4，再用 DES 解 CurrVal。合成密文与固定基线一致。同一张 Windows 10 19041 样本读不到 `JD`，基线 0 行，本地失败并保留读取错误。[LSA secret 验证](docs/windows-lsadump.md)

`windows.cachedump` 用解出的 `NL$KM` 解密 `Cache`。Vista 是 AES-CBC，更早的系统是 HMAC-MD5 加 RC4。合成条目解出 `alice` / `CORP` / `corp.example`。选定样本同样没有 boot key，所以没有可对照的缓存账户。[缓存凭据验证](docs/windows-cachedump.md)

`windows.printkey` 在同一活动 hive 列表上读取根键的子键和值。单元格索引走精确 HMAP；内核规范地址先读内核层，缺页时再试 Registry 进程，用户地址只读该进程。官方 Windows 10 样本的 478 个根行在偏移、类型、键路径、名称和 Volatile 上与固定基线一致，7 个不可读 hive 保持可见。时间保留 100ns，文本值不额外加引号；这两点和递归、筛选、hive 文件重建都还没有当作全字段验收。[注册表键验证](docs/windows-printkey.md)

`windows.userassist` 只处理名称含 `ntuser.dat` 的 hive，读取 UserAssist 下每个 GUID 的 Count 键。Windows 7 及以后看 `CookiePad`，用 72 字节布局和 101 个已知文件夹 GUID；更早的系统用 16 字节并把不小于 5 的计数减 5。值名做 ROT-13。官方 Windows 10 19041 样本的 37 个键和值里，36 行选定字段与固定基线一致。另一行 `UEME_CTLSESSION` 的值单元格不在内存中，基线补了 1612 个零字节再解析成 0 次，本地保留读取错误、不补零。另外两个不在内存中的值单元格基线跳过，本地记为不可读行。[UserAssist 验证](docs/windows-userassist.md)

`windows.getcellroutine` 读取每个活动 hive 的 `GetCellRoutine`，再用 `PsLoadedModuleList` 的基址和 `SizeOfImage` 判断它落在哪个模块。名称去掉最后一个扩展名后，只有 `ntoskrnl`、`ntkrnlmp`、`ntkrnlpa`、`ntkrpamp` 视为内核处理函数，比较区分大小写，区间含 `base+size`。落在其他模块里就是挂钩；哪个模块都不包含时记为不可用，而不是静默跳过。指针读失败单独成行。官方 Windows 10 19041 样本没有挂钩，也没有读失败，和固定基线的 0 行一致。这只是否定对照。[GetCellRoutine 验证](docs/windows-getcellroutine.md)

`windows.amcache` 打开第一个名称含 `amcache` 的活动 hive。Windows 10 读 `InventoryApplication`、`InventoryApplicationFile` 和 `InventoryDriverBinary`；Windows 8 读 `Programs` 和两层 `File`。文件按程序 ID 挂到对应程序下面。SHA-1 去掉所有前导 0。`InstallDate` 和 `LinkDate` 保持基线那个始终返回不可解析的分支，不另做日期解析。官方 Windows 10 19041 样本有 56 个程序和 101 个文件，选定字段和父子路径与固定基线一致，没有驱动项。[Amcache 验证](docs/windows-amcache.md)

`windows.scheduledtasks` 打开第一个名称含 `software` 的活动 hive，读取 `TaskCache\Tasks` 的直接子键。动作和触发器按笛卡尔积展开。官方 Windows 10 19041 样本的 311 行选定字段与固定基线一致，包括对调后的创建/上次运行时间、始终为空的时间触发器描述，以及去掉前导零的 COM CLSID。[计划任务验证](docs/windows-scheduledtasks.md)

`linux.psaux` 读取任务参数区并保留原始字节、参数元素、捕获长度与来源。用户 Linux 样本的 92 条参数内容和 39 条无 mm 显示与基线一致，2 条读取错误仍保留，完整任务报告失败。[Linux 参数验证](docs/linux-psaux.md)

`linux.envars` 读取同一任务页表中的环境变量。选定 Debian 3.2 采集的 1,402 条变量与固定基线的顺序和字段一致；另外 11 个被基线跳过的任务保留为未映射、超限或格式错误，因此整个任务失败。[环境变量验证](docs/linux-envars.md)

`linux.pslist` 可用 `--param threads=true --param decorate-comm=true` 展开线程并按 flags 装饰名称。UID/GID、内核创建时间与原始启动计数分别保留；旧样本的 133 个进程/316 个任务通过十字段对照，现代线程/时钟布局目前仅有合成验证。[Linux 任务验证](docs/linux-tasks.md)

`linux.elfs --param dump=true` 和 `linux.pslist --param dump=true` 提取页对齐的 PT_LOAD 内存段。默认 `elf-layout=mapped` 使用实际映射地址；`reference` 保留固定基线的地址算法，无法表示的地址明确失败。输出不代表原始磁盘 ELF。[ELF 验证与差异](docs/linux-elf.md)

`linux.psscan` 按物理对象地址与包含线程的活动任务对照。运行中未链接候选作为高优先级线索，已退出候选降为信息项；两者都不是隐藏行为的定论。[扫描与分诊验证](docs/linux-psscan.md)

`linux.lsof` 枚举活动任务及线程的打开文件，记录描述符槽位、文件/inode 地址及进程身份。`--param files-only=true` 切换为文件系统路径解析；不按普通文件类型筛选。[文件证据验证](docs/linux-lsof.md)

`linux.sockstat` 保留抽象 UNIX 名称的完整字节及 IPv6 地址，与固定基线的展示差异分别记录。缺少 socket 类型布局时保留记录和错误；网络命名空间筛选沿用基线的任务命名空间语义。[网络证据验证](docs/linux-sockstat.md)

`windows.threads` 输出无损线程地址、CID、100ns 精度时间及原始时间值，并用进程身份关联 pslist 证据。官方 Windows 10 样本的 1,752 条线程通过八字段对照；退出时间联合体的差异单独核验，未作为全字段一致。路径读取失败会保留原始错误。[线程验证与适用范围](docs/windows-threads.md)

`windows.dlllist` 的 5,742 个模块通过官方样本核心字段对照，保留 19 条上游未显示的读取诊断并令全量任务失败。WoW64 暂不解释未验证的加载时间/计数布局；物理进程扫描尚未接入。[DLL 验证与限制](docs/windows-dll.md)；可用 `--param dump=true` 重建所选 DLL PE，读取失败会保留诊断。

`windows.pedump --param base=ADDRESS --param pid=PID` 或 `--param kernel-module=true` 重建内存布局 PE；文件保留 slack 并调整 ImageBase 和节字段。内核高位地址保留导致的两个字节差异单独记录，不能把重建结果视为原始磁盘文件。[PE 重建验证](docs/pe-reconstruction.md)

**其余情况仍需提供符号或本地索引，并显式指定未发现的地址空间参数。** 通用 DTB/内核基址识别、Linux/macOS 默认自动下载尚未实现。已知 ISF 可通过 `symbols fetch HTTPS_URL --sha256 CHECKSUM --case CASE` 获取，再由分析路径验证身份；镜像不会上传。

## 调查工作流

```sh
bin/gomem analyze generic.ioc --image memory.raw \
  --param needle=example.org --case ./case-001 --format jsonl

bin/gomem shell --image memory.raw --case ./case-001
bin/gomem case tasks --case ./case-001
bin/gomem export --case ./case-001 --format html --output report.html
bin/gomem export --case ./case-001 --format bundle --output evidence.zip
python3 tools/verify_bundle.py case-001/exports/evidence.zip
```

输出文件只在案件的 `exports` 目录中新建，不覆盖已有文件。HTML 会转义证据内容；ZIP 附带任务状态、图像标识、调查笔记、逐文件 SHA-256 和结果行数。JSONL 导出包含 manifest 和带任务标识的 evidence 记录；`analyze --format jsonl` 则逐行输出原始 Row。

案件使用 SQLite WAL，保存镜像位置与摘要、任务参数、结构化结果、错误、书签、历史及白名单。一个案件同时只允许一个 GoMem 进程打开。重新打开后，未结束任务被标记为失败并保留部分证据；只有完成的任务可复用。缓存同时包含镜像摘要、引擎版本及实际二进制摘要、符号摘要、地址空间配置和参数。

案件 schema v2 增加编译插件的提取文件接口：文件与任务绑定，保存数据和缺页填充日志的独立摘要，支持分页列表、缓存完整性检查与证据包 v2。`gomem case artifacts --case CASE` 查看元数据，`case verify-artifacts` 校验文件。旧 v1 案件自动迁移后，需要当前版本读取。Windows VAD 与 Linux VMA 可用 `--param dump=true` 提取所选区域，缺页单独记录。[提取文件模型与验证](docs/artifacts.md)

地址和无符号整数在证据 JSON 中采用字符串，避免数值精度丢失。缺失单元格记录原因及原始读取错误。链表损坏、缺页、输出失败和取消均不能变成成功的空结果。失败前的已产生结果仍保留在案件中。

TUI 至少需要 85×18 终端：左侧能力、中间结果、右侧详情、底部任务状态。`enter` 运行，`tab` 切换焦点，`/` 筛选，`n/p` 分页，`s` 反转结果顺序，`b` 书签，`h` 编辑地址跳转，`ctrl+x` 取消，`:` 命令面板。表格最多展示前四列，完整字段在详情中。任务异步执行，每页最多 100 条。

shell 与命令面板支持 `help`、`hex`、`type`、`use physical`、`use kernel`、`use process EVIDENCE_ID`、`search`、`run`、`tasks` 和 `bookmark`。进程空间按封存的 pslist 证据选择；Linux 的 `PGDVirtual` 会先转换到物理根。命令不进行 shell、环境变量或子进程展开。

## 分诊覆盖

```sh
bin/gomem triage --image memory.raw --os linux --case ./case-001 \
  --symbols exact.json.xz --dtb 0x123000 --ioc example.org
```

当前连接了进程、模块枚举、精确 IOC 扫描、Windows 现代 VAD 和 Linux VMA 输入。Windows/Linux 的直接可读写执行权限检查、Linux 删除文件/memfd 执行线索已贯通原生解析、分页评估、证据引用、案件白名单和任务复用。[Windows VAD 验证](docs/windows-vad.md)、[Linux 映射验证](docs/linux-maps.md) 分别记录真实与合成场景范围；权限线索也可能来自正常程序。

Windows 分诊执行 `windows.psxview`、`windows.suspicious_threads`、`windows.hollowprocesses`、`windows.processghosting` 和 `windows.pebmasquerade`，每 500 行分页读取。原生发现关联到含对象地址的进程身份和原始证据；读取诊断使检查标为 `incomplete`，后续页的发现仍保留。路径不可读的发现降为信息级，原始原因、规则、线程/VAD/加载条目地址均保留。多视图缺少活动链的候选按对象身份关联，已退出对象降为信息级，来源坐标和覆盖不足均保留；PEB 长度不一致为信息级线索，附原始字节与读取覆盖；Linux 中 Windows 原生检查标为 `not_applicable`。[原生检查分诊验证](docs/windows-native-triage.md)

Windows 模块差异对照现已接入 `windows.modscan`，按 loader 对象的物理坐标比较；名称或路径读取失败的差异降为信息级，来源和错误保留。[模块分诊验证](docs/windows-module-triage.md)

八类规则具有独立评估器及阳性/正常输入测试；Windows/Linux 隐藏进程、删除相关检查和 Windows 模块差异已有原生输入；Linux 扫描模块及持久化关联仍缺少完整输入，真实恶意阳性和版本覆盖也待验收。**因此当前完整分诊会报告 unavailable 或 incomplete，返回非零状态，并把分诊任务记录为失败。** 已运行规则的发现仍会保存，包含规则依据、严重程度、误报提示、原始证据引用和来源。

进程身份结合镜像、地址空间、对象地址、PID 和可用启动时间，不能仅按 PID 关联。白名单只抑制明确实体，不删除原始证据：

```sh
bin/gomem case whitelist --case ./case-001 \
  --rule literal-ioc --entity ENTITY_FROM_FINDING --reason '已核实的测试样本'
```

## 验证与发布

```sh
make test
make check
make fuzz
make bench
make baseline matrix
make dist
```

`make dist` 为 Windows/Linux/macOS 的 amd64、arm64 生成开发预览、校验和及扩展清单。跨编译不等同于在目标系统执行验证。CI 配置了三个系统的原生测试。

`gomem doctor --strict` 在验收未完成时失败；测试和打包程序会阻止把缺口未关闭的构建标成正式版。YARA、Capstone、LeechCore 均未接入，发布清单会如实标注。

公开语料来自 [Volatility 官方测试资料库](https://github.com/volatilityfoundation/volatility3-test-data)，受其许可证约束，存放在忽略提交的 `.cache` 中。[验证说明](docs/validation.md) 包含下载、固定对照、字段归一化和基准的复现步骤。
