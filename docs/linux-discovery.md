# Linux x64 页表根发现

已提供精确符号、未提供 `--dtb` 时，引擎可使用初始页表与 banner 在内核映射中的相对位置寻找物理根。此推导要求二者属于同一线性内核镜像映射；不能作为所有 Linux 内存布局的假设。背景见 [Linux x86-64 内存映射文档](https://docs.kernel.org/arch/x86/x86_64/mm.html)。

```sh
bin/gomem analyze linux.pslist --image memory.raw --symbols exact.json.xz --offline
bin/gomem doctor --image memory.raw --symbols exact.json.xz --offline
```

适用条件是 x64、8 字节指针、Linux 身份元数据、完整 `linux_banner` 常量，以及 `init_top_pgt`、`init_level4_pgt` 或 `swapper_pg_dir` 之一。当前只实现四级 Intel 页表。存在已知非 Intel 原生架构时不尝试此方法；无初始页表符号时仍要求显式 DTB。

扫描按块读取，目标包含完整 banner 和 NUL 终止符。连续物理段之间保留匹配重叠，稀疏洞不会拼接。根据符号差值推导页对齐的候选根，随后验证：初始页表的虚拟地址确实映射回该物理根；banner 虚拟地址确实指向观察到的物理副本；经转换读取的完整 banner 和终止符一致。多个有效根、无有效根、扫描读取失败或候选超限均报错，不把任意 banner 副本视为成功。

显式 `--dtb` 优先，且地址参数规范为十六进制后进入任务缓存。`--kernel-slide` 仍由用户提供；物理位置与符号的差值不等于已自动识别虚拟 KASLR slide。本地符号索引查找目前仍需要 DTB；索引与根发现的联合搜索、Windows 根/基址发现、32 位、五级页表和 ARM64 尚未实现。

`doctor` 返回方法、DTB、物理 banner、页表符号及其虚拟地址和使用的 slide；案件任务记录最终地址空间参数、图像及符号摘要。合成测试覆盖错误/重复 banner、损坏根、明确的虚拟 slide、歧义根与显式参数缓存复用。官方 Debian 样本发现 `0x1605000`，进程和模块指定字段验证见 [linux-discovery-validation.json](linux-discovery-validation.json)。仅此样本与合成场景，不计为完整自动配置验收。
