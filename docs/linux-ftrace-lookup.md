# Linux ftrace 地址查找底座（开发预览）

`pkg/kallsyms.LookupFtrace` 在驻留的 `ftrace_mod_maps` 和
`ftrace_ops_trampoline_list` 中查找包含查询地址的函数，供后续统一符号解析及调用栈分析使用。
取证运行时为原生 Go；Python/Volatility 仅用于开发对照。

- 优先返回第一个匹配的模块函数，再查找 trampoline；保持各自链表顺序。
- 区间为 `[start, start+size)`，不采用最近符号猜测。查询及函数起始地址应用地址掩码；trampoline 指针按照层掩码规范化，标量字段保留原值。
- 按固定基线，函数名称在区间判断前读取，所属模块名称只在命中后读取；名称保留 NUL/首个替换字符前的内容。
- `FtraceFromSymbols` 根据类型和符号判断来源是否存在；模块映射类型存在却缺少根符号时返回错误。可选来源不存在不等同于读取失败。
- 模块、函数和 trampoline 节点共享一个查询预算。循环、损坏类型、缺页、负长度、地址溢出和取消均显式返回错误，不伪装成无匹配。
- 返回对象、映射、模块及名称地址和访问节点数；内存采集、总字节预算和证据持久化由调用者提供。

`tools/build_ftrace_lookup_oracle.py` 校验固定提交
`881e970121c16f0932fb9d16fbd5fb258cbcbf75` 的源码摘要，使用真实 ISF、字节内存层及未修改的 Kallsyms/list_head 对象方法，不 mock 来源或查找方法。
46 组 1,242 次参考查询覆盖 32/64 位、重叠和反向链表、多模块/跳板、零地址/长度、Unicode、损坏名称、缺失类型/符号和非零链表成员偏移，以及高位 trampoline 的指针/标量类型差异。
其中 54 次缺失根符号错误在 Go 配置阶段拒绝；其余 1,188 次查询比较名称、类型、地址、长度、导出状态、模块和来源，或对应读取错误。

69 组 Intel 分页组合中，3 组缺失根符号在配置阶段拒绝；其余 66 组（x86、PAE、x64）比较与参考验证过的平坦内存控制，并独立核对每次成功虚拟读取。所有成功/无匹配路径的每次采集均注入读取失败和取消，并检查同一 Reader 可重试。另测试共享预算、循环、截断、符号滑移、负长度和溢出。

```sh
python3 tools/build_ftrace_lookup_oracle.py --check
go test -race ./pkg/kallsyms -count=1
go test ./pkg/kallsyms -run '^$' -fuzz '^FuzzFtraceLookup$' -fuzztime 10s
```

另外直接执行基线 `get_ftrace_symbols`，以 4 组高位指针/整数字段对象验证现有枚举：6 组 Intel 分页比较八字段，独立核对原始采集并验证 SQLite 封存和逐字节缓存回放。原始指针的高位仍保存在采集字节中，展示地址遵循声明类型。

地址查找本身是独立 Go API，尚未接入完整来源优先级、CLI 地址查询或 `linux.pscallstack`。
没有真实现代内核 ftrace 阳性、动态镜像一致性或完整插件验收；矩阵仍为部分实现。
合成对照和分页控制不能计为正式版本验收。见[机器验证记录](linux-ftrace-lookup-validation.json)。
