# Linux latch tree 查找底座开发预览

`object.Reader.FindLatchTree` 从 `latch_tree_root.seq` 读取 sequence 最低位，选择 `tree[0]` 或 `tree[1]`，沿 `rb_left/rb_right` 搜索。支持 `seq.sequence` 和 5.10+ 的 `seq.seqcount.sequence`；比较函数由调用者提供，以保留模块半开区间、BPF 包含末端返回地址等不同语义。

结果包含是否命中、latch/RB 节点坐标、sequence、选中树和已访问节点数。`Found` 与节点地址分开表示，因此容器地址零仍可表达为命中。所有读取经过调用者的内存层，可接入现有原始字节采集；本方法本身不保存案件证据。

## 固定基线行为

固定 Volatility v2.28.2 的 `latch_tree_root.find` 以 `node` 字段偏移加 `index * pointer_size` 从 RB 节点反算 latch 节点，而非采用实际 `rb_node` 大小。原生接口明确保留此坐标行为。第二份树上的返回坐标可能因此不同于内核结构的真实容器起点；后续来源比较与回溯需要保留该区别，不能把它当成正确内核布局的证明。

方法只读取选中的树，验证每个沿途 RB 节点完整可读，并对指针对齐、容器减法下溢、重复节点、节点上限、元数据、读取错误和取消明确报错。没有全树遍历、父指针或红黑平衡验收。基线遇到不可读指针会返回未命中，原生返回错误；基线比较函数返回 `None` 时结束，原生要求调用者以错误表达不可比较原因，不将失败伪装为未命中。布局验证在空树上也会执行，属于更严格的原生行为。

## 验证范围

`tools/build_latch_tree_oracle.py` 先校验固定源码树摘要，再执行未修改的真实扩展方法和 ISF 对象；比较函数作为搜索 API 的调用者提供，不替换扩展的查找或节点定位逻辑。96 组案例、3,840 次查询覆盖：

- 4/8 字节指针，新旧 sequence 布局，sequence 0/1/2/3。
- 节点数组偏移 0/16、正常/空/单节点树及两份树不同的区间。
- 包含/不包含末端的比较函数、命中/未命中及完整比较路径。

Go 测试逐项对照节点、比较路径和选中树，每次原始读取独立重读一致，并确认未读取另一棵树。另测零地址容器、合成大端布局、缺页/截断、错误字段类型、指针和算术错误、循环、节点上限，以及每个比较边界的取消和回调错误。`FuzzLatchTree` 在节点上限内扰动根、sequence、链接及比较字段。

```sh
python3 tools/build_latch_tree_oracle.py --check
go test -race ./pkg/object -count=1
go test ./pkg/object -run '^$' -fuzz '^FuzzLatchTree$' -fuzztime 10s
```

这仅验证可复用搜索底座；来源专用 API 的后续验证见 [BPF 查找底座](linux-bpf-lookup.md)和 [模块查找底座](linux-module-lookup.md)。完整调用栈插件尚待完成，也没有真实现代内核 latch tree 阳性语料、远程动态修改数据一致性或完整插件验收；能力矩阵不因此增加完成验收的插件。见[机器验证记录](linux-latch-tree-validation.json)。
