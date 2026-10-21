# Linux 模块地址查找底座（开发预览）

`pkg/kallsyms.LookupModule` 原生实现固定基线的模块区间查找，供统一解析器和调用栈分析使用。支持旧式模块符号字段、指针/内嵌 `mod_kallsyms` 和独立 typetab。运行时不依赖 Python。

`ModuleFromSymbols` 保存全局地址门槛与来源根。查找顺序是全局门槛、显式模块或 latch tree、树未命中时的模块链表回退，最后选择第一个包含查询地址且名称非空的 ELF 条目。它不返回最近符号。显式指定模块仍须通过全局和模块 ELF 边界检查。模块列表先完整采集所有边界，再按列表顺序选择；节点和符号数分别共享查询级预算。

`ModuleLookup` 无匹配时也保留全局门槛、候选范围及是否倒置、原始首/末 ELF 值、末项长度、树查找路径、树选择的模块和读取计数。命中结果另外保留对象、条目、索引、表和名称地址，以及独立的 `RawABIValue`、`RawABISize`。缺页、类型错误、截断、循环、预算耗尽或取消返回错误；错误结果的 `Match` 必为 nil，已取得的选择依据仍可检查。采集字节、总字节预算、地址的无损序列化和证据持久化由调用者提供。

## 固定基线的特殊语义

这些语义与模块枚举不同，不能直接复用枚举输出推导包含关系：

- 没有 mod_tree 时，全局上下界采用 `module_addr_min/max` 的 ISF 符号地址，加 slide 后掩码，**不是解引用后的变量值**。全局区间含两端。
- 模块范围按未掩码的 ELF 值稳定排序，取排序后索引 1 和末项；它不搜索第一个非零地址。模块和函数区间不含上界。
- 固定表达式 `last_value & mask + last_size` 按 Python 优先级等价于 `last_value & (mask + last_size)`。有效 ELF 也可能得到倒置或零长度边界；结果显式保留这些推导值和倒置标记，不能把无匹配解释为该模块不存在。
- 固定 `Elf32_Sym` 的 value 和 size 都读取八字节，分别跨入后续字段。查找、排序及官方展示值保留此行为，ABI 四字节值另行记录。这不代表这些跨度符合 ELF ABI。
- mod_tree 比较器保留 `node + module_memory.mtn.offset + mod_tree_node.mod.offset` 的加法坐标，以及共享 latch tree 的双份节点坐标语义。
- 区间查找的 Type 直接取 st_info/typetab，Exported 由类型字符推导；它不查询枚举路径使用的导出表，因此 `num_syms=0` 不会改变此处的大小写或导出状态。

这些规则是可审查的固定版本兼容底座，不是现代内核通用边界推断，也不是完整模块发现验收。后续调查界面须展示异常范围及来源，不能把它们静默当作正常空结果。

## 验证

`tools/build_module_lookup_oracle.py` 校验固定源码摘要，直接运行未修改的 `module_lookup_address`、模块/ELF 扩展、模块链表及 latch tree；没有方法或来源 mock。

240 组、8,400 次查询覆盖两种指针宽度、四种模块布局、显式/自动模块选择、重叠及反序符号、多个及反序模块、空/缺失链表、空字符串表、单条 ELF、非零末项长度、高位地址、零导出表、两种序列布局和四种序列值。树的两份副本和列表使用不同模块名称/对象，直接核对来源选择；空树用例验证有匹配的链表回退。1,440 次七字段命中、6,496 次无匹配和 464 次固定错误对应原生结果；错误包括固定索引异常、无边界解包异常及缺失列表符号，原生返回明确错误。

360 组 x86/PAE/x64 分页组合比较完整查找结果和错误状态，并独立核对每次成功虚拟采集。平坦内存对照也独立重读全部采集。成功及无匹配路径逐次注入读取失败/取消，并验证相同 Reader 可重试；另覆盖共享节点/符号预算、循环、错误类型、截断、负长度、滑移和地址溢出。

```sh
python3 tools/build_module_lookup_oracle.py --check
go test -race ./pkg/kallsyms -count=1
go test ./pkg/kallsyms -run '^$' -fuzz '^FuzzModuleLookup$' -fuzztime 10s
```

尚无真实现代内核模块树阳性或完整性能验收；已接入[统一解析器 API](linux-resolver.md)的来源优先级和驻留缓存；独立 CLI 地址查询尚未提供；调用栈接入见 [`linux.pscallstack`](linux-pscallstack.md)。本 API 不增加完成验收的插件数量。见[机器验证记录](linux-module-lookup-validation.json)。
