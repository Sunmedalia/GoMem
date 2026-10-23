# Windows 捕获交换文件（v0.1 开发预览）

```text
gomem shell --image memory.raw --os windows --arch x64 --dtb 0x1000 --pagefile '0=/captures/pagefile.sys' --offline --case ./case
use kernel
translate 0x123
hex 0x123 8
```

`--pagefile NUMBER=LOCAL_PATH` 可重复使用，编号为 0..15，不允许重复编号。当前接受非空普通本地文件，按原始字节读取，不把 pagefile 当内存镜像格式检测。要求 Intel Windows（x86、PAE、x64）；Windows crash 可从头识别 OS，其余输入须指定 `--os windows`。缺少文件、错误系统/架构和损坏参数在开始分析前明确失败。

原始内存和交换文件均只读打开、分块计算完整 SHA-256。`gomem.pagefile-acquisition/v1` 把原镜像或 VMware 配套采集身份与按编号排序的交换文件大小/散列组合，成为案件的 ImageSHA256；它不再等于单个 RAW 文件散列。每条证据参数保存 base-acquisition SHA-256、各 pagefile 的编号/大小/SHA-256 和版本标识，参与任务缓存键和证据封存。文件路径不参与内容身份；同一捕获字节移动目录不会改变身份。各成员的句柄在引擎关闭或打开失败时关闭，创建案件前拒绝交换文件与 case.db、WAL、SHM、journal、lock 的硬链接/路径别名。

打开散列前后、每次实际外部字节读取前后，以及每次任务/缓存回放的前后检查交换文件大小和修改时间，`translate` 也执行源校验。变化时失败，不复用成功缓存。该检查不保证 live 原子捕获，也不能检测恶意保留时间戳的同长写入；和原镜像一样，分析期间必须保持捕获文件不可变。当前不下载远程交换文件、不自动搜索页文件、不内嵌或复制全部源文件进证据包；应单独保管每个捕获源。

Windows swap 判定与固定 Intel 层相同：Present、Prototype、Transition 均为零，bit 7 为一，页索引非零；文件编号为 bits 1..4。x86 页索引从 bit 12 开始，PAE/x64 从 bit 32 开始。按失败页表层级的跨度计算交换偏移，检查移位溢出。当前没有恢复保存在交换文件中的页表树，只有固定层的直接块映射语义；上层软件项按固定层相同跨度解释，但真实采集验收未完成。

`Translator.Translate` 始终表示物理 RAM：交换项返回带编号、PTE 原值、PTE 物理地址、映射大小和交换文件基址的 `SwappedPageError`，不会用交换偏移冒充 Physical。`Intel.Resolve` / `Virtual.Resolve` 提供带来源层、文件偏移和可用范围的 `BackingTranslation`；外部字节的权限、dirty 状态保留未知。`Virtual.ReadAt` 使用这个接口，所以已使用同一虚拟层的对象、hex 和反汇编读取可以跨 RAM/pagefile 边界；缺文件、缺范围、短读与取消均明确失败，不补零。shell `translate ADDRESS` 显示当前层的来源、偏移、PTE 及权限是否已知，描述映射而不承诺目标字节一定可读。

差分与验证：

- `tools/build_swap_oracle.py --check` 用未修改的固定 WindowsIntel/WindowsIntelPAE/WindowsIntel32e 和真实 BufferDataLayer 验证 54 个映射，覆盖三种模式、全部页表层级、编号 0/1/15 和对齐/非对齐地址。native 校验全部交换基址、跨度、PTE、编号；叶子另核对实际读取字节。
- 固定 `_translate_swap` 返回块基址时没有加页内位移，因此非对齐 `read` 返回了块开头的字节。GoMem 明确加上页内位移；对齐读取与实际基线一致，非对齐读取保留为已验证的刻意差异，不声称逐字节完全对齐。夹具保存两种结果，没有修改上游方法。
- native 控制覆盖 Prototype/Transition 标志组合、空项/零索引、缺文件、短文件、跨来源读取、取消、无权限猜测及物理扫描接口的明确失败；fuzz 检查任意叶项解析后的来源和字节边界。
- 引擎控制验证任务证据/SQLite 封存、缓存复用、内容变化改变采集身份、修改源拒绝回放，以及案件输出别名不会改写 pagefile。CLI 从 `--pagefile` 到 `use kernel`、translate、hex 和反汇编覆盖中文/空格路径。
- 本地 Windows 10 19041 dump 配置额外的 16KiB 合成 pagefile 后，原有驻留进程枚举仍完成 120 行，并保留 pagefile 哈希。这只是配置/驻留读取回归；该文件不是与镜像配套的真实交换捕获，不建立外部交换字节的真实阳性验收。

当前不支持 Linux swap、Windows prototype/compressed store，也没有真实配套 pagefile 的阳性语料验收。只有 RAM 坐标的 `MappedRanges` / `PageMappings` 在配置 pagefile 时明确返回 unsupported，防止扫描器把未遍历的外部区域算作完整覆盖。原生框架已有 [带来源的映射与扫描接口](backing-scans.md)，保留跨 RAM/pagefile 命中和逐段字节回溯；各插件独立创建/包装地址空间的全面迁移、提取及报告接入仍待完成，不能据此认为已验收。矩阵保持 partial，开发预览继续保留完整交换页能力缺口。
