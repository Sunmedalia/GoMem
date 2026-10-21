# Windows 模块枚举差异分诊

Windows `triage` 现在执行 `windows.modules` 和 `windows.modscan`，从 SQLite 每页读取 500 行，运行 `module-enumeration-difference`。该原生规则比较 loader 对象，而不是模块名称、加载基址、PID 或驱动名称。

```sh
bin/gomem triage --image memory.dmp --case ./case-001 --offline
```

案件流程将对象地址经当前内核页表转换为物理内存坐标。旧系统池对象已经位于物理层，可直接对照活动链虚拟对象的物理坐标；虚拟别名指向相同物理对象时不会形成差异。未知来源层、对象地址与 provenance 不一致、混合镜像和错误插件都明确失败。这里的物理地址是镜像地址空间的物理地址，不是 crash 文件里的字节偏移。

活动链和池扫描分别建立有界索引，各最多 1000000 个不同坐标。重复池候选只产生一次发现。状态跨页保留；原始行、来源层和地址、符号摘要、参数及证据 ID 不改写。发现另存 `ComparisonOffset`、`ComparisonLayer` 和 `ComparisonSpace`，并在 `Comparison` 引用双方已完成的任务。实体结合镜像及比较坐标。白名单只抑制该对象的发现，原始池扫描行继续存在；重跑复用源任务。

默认差异为 medium 调查线索。名称或路径不可读时降为 info，标记 `Confidence=limited_by_module_metadata`，保留原始 Missing、NameError、PathError。它可能是失效分配、错误池命中或采集不一致，不能据此确认隐藏驱动或恶意模块。坐标对照不依赖名称，因此名称读取失败不冒充对象坐标缺失。

活动链对象转换失败时，无法确定它是否就是某个池候选，因此抑制所有未匹配候选并把检查标为 incomplete；仍保留匹配计数及原始行。池候选转换失败时跳过该候选的比较、计数并标 incomplete。空活动链、空扫描范围、零扫描字节、读取诊断、池读取失败或候选字段读取跳过也标 incomplete。最终 summary 必须存在，模块数必须等于消费的原始模块行数；计数错误、非字符串计数、未知记录和 summary 后出现数据都失败。正常池大小/页类型筛选仍按上游适用条件执行。

独立 `Evaluate` 接口没有镜像环境，只能对照同一来源层中的原始坐标；跨层必须使用具有页表和物理层的案件流程。比较任务元数据在封存前转换为 JSON 基本类型，行数用十进制字符串保存，避免 SQLite 回读时结构体字段顺序变化或大整数精度损失。Linux 隐藏任务对照也使用这一修正。

## 已验证范围

选定 Windows 10 19041 x64 镜像的 176 个加载链对象均在 177 个池候选中，双方对象地址转换都没有失败。唯一额外候选位于 `0xfffff80436391342`，物理坐标 `0x6f72342`。名称和路径读取失败，DllBase 是 `0xccccccccccebebc0`，它保留为 1 条信息级低置信度线索，尚无真实恶意模块结论。原始 modules/modscan 对照记录分别见[进程与模块](windows-process-modules.md)和[模块池扫描](windows-modscan.md)。

完整分诊现在保留 32 条线索：原有 30 条 RWX、1 条已退出多视图进程差异、1 条模块候选差异。整体仍因其他输入缺口及空洞检查的 330 条诊断而 incomplete。第二次执行复用全部已完成输入，发现数量、原始证据引用和校验摘要一致。

构造测试覆盖 1001 个同名同基址正常对象后的差异、重复候选、每 500 行分页、501 个正常对象后的完整案件白名单/缓存流程、虚拟别名与物理池坐标、活动和扫描转换失败、元数据读取错误、缺失汇总、错误计数、篡改、错误来源、取消及输出失败。它们不是各版本真实镜像或真实恶意阳性的替代。真实 x86、旧系统物理池、更多损坏镜像和恶意 VM 对照仍待验收；矩阵保持 partial、accepted=false。

```sh
go test ./internal/triage -run 'TestModuleViews|TestComparisonTask|TestLinuxHiddenTask' -count=1
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/triage -run TestOfficialWindowsNativeTriageCoverage -count=1 -timeout 10m -v
```
