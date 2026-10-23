# Mermaid 结果渲染（v0.1 开发预览）

```sh
bin/gomem analyze windows.pstree --image memory.dmp --case ./case-001 --format mermaid > processes.mmd
```

`analyze --format mermaid` 输出原始 `graph TD` 文本，供支持 Mermaid 的 Markdown/图形工具读取。按插件声明的列顺序显示 `列名:值`；每条结果分配独立序号节点，父子关系来自封存证据 `ParentID`，不从 PID/PPID 或其他插件特定列猜测。没有父链接的结果显示为独立根节点。

流式写出节点，不缓存完整结果文本。为了解析父链接，内存保存已输出证据 ID 到节点序号的索引，空间随不同证据数量增长。重复证据记录仍输出独立节点；其身份作为父引用时指向第一次出现。引用尚未输出的父记录明确失败，不悄然创建虚构父节点。结果图只表达结构，不额外断言实体关联或恶意性。

标签转义双引号、HTML 字符、反引号、反斜线和控制字符；换行转换为 `<br>`。列名也转义。读取错误、缺失原因、地址、字节和复合值使用 GoMem 的类型化值文本，不伪装成空字符串。部分输出/写出失败会通过 CLI 返回错误，已有文本可能是不完整图。

验证：`tools/build_mermaid_oracle.py --check` 在锁定的未修改 Volatility 源码上实际构造 TreeGrid 并调用 MermaidRenderer。6 组空结果、平铺、树形、深层、引号/换行及 Unicode 图通过逐字节对照。Go 测试另覆盖重复 PID/证据、父链接缺失、最大地址、列缺失、标签注入与写出失败。合成值只覆盖选定标量及树结构，不代表全部上游格式提示完成验收。

尚未完成：`export` 的持久化 Mermaid 报告、TUI 图形预览、全部复杂值/缺失值/时间/反汇编格式提示的差分验收、浏览器版本兼容与大图展示验收。上游针对 HTML 字符的转义较少，GoMem 明确增加转义，恶意或含 HTML 标签的字段不承诺逐字节相同。Arrow 已有原生 IPC 预览，详见 [Arrow 输出](arrow-renderer.md)。
