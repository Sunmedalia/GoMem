# 原生 DWARF 与类型解析

`symbols convert` 在 Go 内解析带 DWARF 的 ELF 或 Mach-O，包括 FAT32/FAT64 中显式选择的切片。分析命令的 `--symbols` 也可直接接收这些调试文件；转换得到的确定性 ISF 摘要用于缓存和证据回溯。

```sh
bin/gomem symbols convert /path/to/vmlinux --output kernel.json
bin/gomem symbols convert /path/to/vmlinux --system-map /path/to/System.map --case ./case-001
bin/gomem symbols convert /path/to/kernel.dSYM/Contents/Resources/DWARF/kernel \
  --symbols-from /path/to/kernel --binary-arch x86_64 --output mac.json
bin/gomem symbols inspect kernel.json
```

输出默认写标准输出，转换报告写标准错误；提供 `--case` 时默认独占创建 `CASE/symbols/摘要.json`。已有输出文件不会覆盖。`--symbols-from` 用于补充地址和 banner，双方平台、架构、字节序、指针宽度和可用构建标识必须一致。`System.map` 的地址优先于其他来源。

已实现递归结构、typedef 和限定类型、匿名结构/联合体、固定/柔性/多维数组、整数和函数指针、枚举别名、有符号数与大小端位字段。类型读取保留错误；未知枚举值保留原始数值。外部 ISF 的枚举若以 `void` 为基类且没有可证明的符号性，不将其擅自解释为有符号数。

位字段保留声明的整数或枚举基类，读取时只访问实际包含目标位的最小字节区间。紧凑结构可小于基类的完整分配单元，但字段实际占用范围必须在结构内；稀疏映射中相邻字节缺失不会导致已驻留字段读取失败。枚举位字段按实际位宽扩展符号，再查找常量名称，原始位值仍单独保留。

默认调试数据上限 512MiB、DIE 上限 200 万，另有累计解析读取和类型递归限制；可用 `--max-debug-bytes`、`--max-entries` 调整至受限上限。不支持的动态成员位置、冲突类型定义、无有效调试信息、超限或截断输入会失败。拆分 DWARF、所有语言扩展和真实内核版本覆盖尚未验收。Linux/macOS 在线索引与自动获取仍待实现。Windows 的原生 PDB/MSF 转换与自动获取见 [PDB 符号](pdb-symbols.md)。

仓库自带 C 源码和七个小型编译产物，固定摘要在 [manifest](../pkg/symbols/testdata/manifest.json)。覆盖 ELF DWARF 2/4/5、i386、x86_64、PowerPC64 大端，以及 x86_64/arm64 Mach-O；测试直接读取编译后的负数、位字段、枚举和递归对象，不在运行时调用编译器。FAT32/64 切片选择、取消、读取预算和输入损坏另有测试。ARM64/PowerPC 符号解析不表示具有对应内存地址转换器。

所有转换输出均通过固定 Volatility 源码中的 ISF 6.2.0 schema。使用固定 dwarf2json 提交比较选定的三个类型和四个符号地址，结果与归一化范围见 [dwarf-validation.json](dwarf-validation.json)。比较保留实际内存位位置；PowerPC64 样本的上游位字段位置存在差异，原生结果按已编译的 C 对象内容验证。枚举底层类型元数据未纳入这项差分，因为对照输出可能用 `void` 替代整数基类。上述检查不计为完整 DWARF 或插件验收。

## 本地符号索引

`symbols index PATH... --case CASE` 将明确给定的表或 ZIP 内所有 ISF 成员索引到 `CASE/symbols/index.json`。不解包 ZIP 成员、不扫描任意目录；无有效身份或损坏的输入使构建失败。也可用 `--output INDEX` 创建独立索引，或写标准输出。已有文件不覆盖；重新构建时选择新路径，再通过 `--symbol-index` 使用。

索引保存完整 banner/符号地址或 PDB 名称、GUID/Age，以及解压后的表摘要、指针宽度和来源。自动查找只在已给定 DTB 时运行：Linux 先按候选地址与 slide 从内核空间验证 banner，Windows 从给定内核基址的 PE CodeView 验证身份。选择后重新加载并核验完整内容摘要及元数据；多个不同摘要同时匹配时要求显式指定符号。读取失败、过期索引和无匹配会报告错误，不产生成功的空分析。

不提供 DTB 时，通用物理分析不会因案件中存在索引而尝试选择内核符号。显式 `--symbols` 优先于索引。本地查找可用于离线分析；DTB 发现、网络索引下载和默认自动下载尚未实现。索引当前最多一万条、16MiB，位置为本机路径；跨机器迁移需重新建立索引或调整相对路径。

两份官方样本不显式指定符号和操作系统的结果见 [symbol-index-validation.json](symbol-index-validation.json)。Linux 133 个进程/79 个模块、Windows 120 个进程/176 个模块的指定字段与固定基线一致；不代表 DTB 发现或全部符号场景验收。
