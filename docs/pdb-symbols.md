# Windows 原生 PDB/MSF

GoMem 原生解析 MSF 7.0 容器、PDB 信息流、DBI、TPI/CodeView、公共/全局及模块符号。运行时不调用 DIA、LLVM、Python 或 Volatility。

```sh
bin/gomem symbols convert ntkrnlmp.pdb --output kernel.json
bin/gomem symbols convert renamed.pdb --pdb-name ntkrnlmp.pdb --output kernel.json
bin/gomem analyze windows.pslist --image memory.dmp --symbols ntkrnlmp.pdb \
  --dtb 0x123000 --kernel-base 0xfffff80000000000 --offline
bin/gomem symbols index ntkrnlmp.pdb --case ./case-001
```

数据库名称默认取输入文件名；重命名文件转换时用 `--pdb-name` 指定映像 RSDS 记录中的名称。类型/符号转为确定性 ISF，直接使用 PDB 和使用相同转换结果具有相同符号摘要。符号地址为 RVA，内核基址由引擎添加。GUID、DBI Age、数据库名称必须与目标 PE 的 CodeView 身份匹配。公开 PDB 的 Info Age 可能因符号剥离而不同，报告会披露，映像匹配使用 DBI Age。

MSF 只加载所需流，检查文件块几何、目录、块重复、截断、流索引与累计预算。默认累计流数据上限 512MiB、记录上限 200 万、类型/字段链递归深度 128；CLI 可用 `--max-debug-bytes`、`--max-entries` 调整。大小端转换遵循 Windows ABI；TPI 数字叶支持带符号及无符号的 8/16/32/64/128 位整数，不把偏移/大小截成较窄整数。

已实现前向结构引用、递归指针、结构/联合/枚举、修饰类型、数组、位字段、固定基类与 vtable 指针、UDT 别名、32 位指针嵌入 64 位表。模块局部存储和公共符号均保留；代码地址按段重定位，支持 OMAP FromSrc。映射到无效段、损坏字段链、未知的被引用类型、动态虚拟基类布局或资源超限会失败。

链接后的 PDB 可包含同名但不同布局的类型，早期定义保留为 `NAME@0xINDEX`，普通名字采用最后一个定义；符号名称冲突保留为 `NAME@0xRVA`，普通别名采用最后一个记录。转换报告列出这些情况。DBI 声明为绝对地址的链接器常量单独写入报告的 `absolute_symbols`，不会伪装成内核 RVA。OMAP 明确移除的符号进入 `omap_removed_symbols`，保留原始 RVA，不作为地址 0 输出。使用标准 ISF 文件时应同时保留转换报告以保存这些非地址常量与移除记录。

MSF 2.0、所有旧 CodeView 变体、类型服务器/FASTLINK、动态虚拟继承、函数参数/调用约定的完整展示尚未验收。ARM/ARM64 可解析机器标识与相应类型，但尚无对应内存转换器。未知或不适用的语义不会计为完整支持。

仓库包含自行编译的 x86/x64 C/PE/PDB 小型语料及 [摘要清单](../pkg/symbols/testdata/pdb-manifest.json)。测试读取实际 PE 中的有符号数、枚举、位字段、数组和函数指针，并将 PE 放入合成页表后经真实 GUID/Age 验证执行 `windows.pslist`。另有目录损坏、数值溢出、前向/同名类型、Info/DBI Age 差异、取消、预算和 fuzz 测试。

与官方 Windows 10 19041 样本匹配的 Microsoft PDB，通过原生路径得到 120 个进程、176 个模块，指定字段与固定基线一致；详细摘要、范围和对照差异见 [pdb-validation.json](pdb-validation.json)。小型语料中，上游转换把负枚举常量保留为无符号值，且漏掉最后一段的公共数据符号；原生结果通过已编译对象验证。这些差异被保留并披露，不在归一化时忽略。所有输出另按基线的 ISF 6.2.0 schema 校验。本能力保持 partial，未完成全部 PDB/插件验收。

真实 PDB 的选定类型对照也保留差异：原生 `wchar` 使用 [Microsoft 声明的无符号 16 位范围](https://learn.microsoft.com/en-us/cpp/cpp/data-type-ranges?view=msvc-170)，上游将其标为有符号；原生保留零大小的未完成前向声明，上游可能没有对应类型。指针宽度和声明形状参与比较，指针目标的全部字段只在明确选择该类型时比较，避免递归展开整个内核对象图。`_ETHREAD`、`_KTHREAD` 及选定的三个全局符号地址一致；其余差异的具体字段路径保存在报告中。

格式依据为 [LLVM MSF](https://llvm.org/docs/PDB/MsfFile.html)、[TPI](https://llvm.org/docs/PDB/TpiStream.html)、[DBI](https://llvm.org/docs/PDB/DbiStream.html) 和 [CodeView 类型](https://llvm.org/docs/CodeViewTypes.html) 文档。开发期对照使用锁定版本，入口如下：

```sh
.cache/reference-venv/bin/python tools/pdb_reference.py \
  --source .cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75 \
  --pdb pkg/symbols/testdata/native-x64.pdb --output .cache/reference-pdb-x64.json
```
