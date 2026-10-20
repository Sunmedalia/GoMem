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
| `generic.ioc` | 精确字节串；`--param needle=example`；支持块边界和重叠命中 |
| `windows.pslist` | 匹配 ISF、DTB、内核基址；活动进程链表 |
| `windows.modules` | 匹配 ISF、DTB、内核基址；内核模块链表 |
| `linux.pslist` | 匹配 ISF、DTB；活动任务链表；可选 `--kernel-slide` |
| `linux.lsmod` | 匹配 ISF、DTB；旧布局和 `module_layout`；6.4+ `module_memory` 字段尚未补齐 |

支持 RAW、LiME v1、具有物理 `PT_LOAD` 的 ELF core，以及 Windows 32/64 位完整转储与 bitmap 转储。其他已识别的容器会明确拒绝；通用 ELF 不代表 Xen 格式已实现。

支持 x86、PAE、四级 x64 页表、4KiB 页及相应大页。非驻留、交换、transition/prototype 页不能解析时返回读取错误。输入以只读方式打开，按块散列，检查修改时间与大小变化。分析期间仍应保持采集文件不可变。

符号支持 ISF JSON、gzip、xz、ZIP 中的压缩成员，例如 `symbols.zip#linux/kernel.json.xz`。解压限制为 128MiB，xz 字典上限 64MiB。Linux 在目标虚拟地址比对完整 banner；Windows 从内存中 PE debug directory 比对 PDB 名称、GUID 和 Age。[上游符号规则](https://volatility3.readthedocs.io/en/stable/symbol-tables.html)

支持从带 DWARF 的 ELF 或 Mach-O 原生读取符号，也可用 `symbols convert DEBUG_FILE --output kernel.json` 转为 ISF。可选 `--system-map`、`--symbols-from` 合并地址；多架构 Mach-O 使用 `--binary-arch x86_64` 选择切片。类型覆盖 typedef、递归结构、匿名成员、数组、枚举和位字段。[原生符号验证与限制](docs/native-symbols.md)

**本预览需要显式指定符号和地址空间参数。** 自动识别、默认自动下载与 PDB/MSF 原生转换尚未实现。`--offline` 会禁止显式符号下载。已知 ISF 可通过 `symbols fetch HTTPS_URL --sha256 CHECKSUM --case CASE` 获取，再由分析路径验证身份；镜像不会上传。

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

地址和无符号整数在证据 JSON 中采用字符串，避免数值精度丢失。缺失单元格记录原因及原始读取错误。链表损坏、缺页、输出失败和取消均不能变成成功的空结果。失败前的已产生结果仍保留在案件中。

TUI 至少需要 85×18 终端：左侧能力、中间结果、右侧详情、底部任务状态。`enter` 运行，`tab` 切换焦点，`/` 筛选，`n/p` 分页，`s` 反转结果顺序，`b` 书签，`h` 编辑地址跳转，`ctrl+x` 取消，`:` 命令面板。表格最多展示前四列，完整字段在详情中。任务异步执行，每页最多 100 条。

shell 与命令面板支持 `help`、`hex`、`type`、`use physical`、`use kernel`、`use process EVIDENCE_ID`、`search`、`run`、`tasks` 和 `bookmark`。进程空间按封存的 pslist 证据选择；Linux 的 `PGDVirtual` 会先转换到物理根。命令不进行 shell、环境变量或子进程展开。

## 分诊覆盖

```sh
bin/gomem triage --image memory.raw --os linux --case ./case-001 \
  --symbols exact.json.xz --dtb 0x123000 --ioc example.org
```

当前连接了进程、模块枚举和精确 IOC 扫描。六类规则的独立评估器及阳性/正常输入测试已经建立；隐藏进程、可执行区域、扫描模块差异、删除文件/memfd 执行、持久化关联仍缺少原生数据生产者。**因此当前完整分诊会报告 unavailable，返回非零状态，并把分诊任务记录为失败。** IOC 发现仍会保存，包含规则依据、严重程度、误报提示、原始证据引用和来源。

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
