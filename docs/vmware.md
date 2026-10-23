# VMware 配套内存层（v0.1 开发预览）

支持只读 `.vmem` 内存与 `.vmss` / `.vmsn` 元数据配对：

```text
gomem doctor --offline --image capture.vmem
gomem analyze linux.pslist --image capture.vmem --vmware-metadata metadata.vmss --symbols kernel.json --os linux --arch x64 --dtb 0x1000 --case ./case
```

VMEM 默认优先查找同名 VMSS，其次 VMSN。也可选择 VMSS/VMSN 为输入，自动打开同名 VMEM。缺少配套文件、无效元数据均明确失败，不退回 RAW。HTTP(S) 同名配套发现沿用强 ETag / Range 和 offline 限制；查询参数用于实际请求，来源展示不包含凭据。远程路径相同或本地同一文件不能充当两个成员。

解析四种固定基线签名、80 字节组记录、带索引标签及 32/64 位区域值。无关扩展标签（62/63）按版本读取长度并跳过载荷，采用单个 64KiB 元数据缓存；区域标签必须为明确的整数标量。组与区域上限 65536，标签上限 1048576，遍历上限 1GiB；检查溢出、重叠、重复区域标签、截断和终止符。物理空洞保持读取错误。

案件身份为 `gomem.vmware-acquisition/v1` 固定 JSON 清单的 SHA-256，包含 VMEM 和元数据各自完整 SHA-256 及长度，文件名不参与计算。`image_sha256` 在此代表采集组合身份；`doctor` 的 `vmware_acquisition` 提供两个原始散列。任务 provenance 保存成员散列和长度。更改元数据会改变案件身份与缓存键；任务/回放前后检查两个成员。案件数据库和日志不得与任一成员为同一文件。本地变化检查使用长度和修改时间，不能检测恶意恢复时间戳后的等长写入，输入应为不可变采集。

`tools/build_vmware_oracle.py` 调用未修改的固定 Volatility VmwareLayer：26 个字节后端控制中，18 个合法有序控制的实际读出散列一致；1 个无序区域控制原生排序后正确读取，而固定层在查找时产生 InvalidAddressException。7 个无效控制原生均拒绝。固定层会接受重复计数标签、物理重叠和超出 64 位物理地址的值；这些差异保留在 fixture，未归类为对齐成功。

Go 测试覆盖完整字节映射、每个元数据截断位置、损坏组/区域字段、配套发现、缺失文件、相同文件、输入成员选择不影响身份、本地和 HTTP 元数据变化、取消及重复关闭。Windows/Linux 合成进程字段与 RAW 相同，SQLite 封存、成功缓存复用、元数据变更阻止回放和数据库别名保护有端到端测试。模糊测试入口为 `FuzzVMwareMetadata`。

Debian 3.2 官方 512MiB RAW 流式重编码为配套文件后，完整物理 SHA-256、自动 DTB 发现、133 条有序进程指定字段、案件封存和缓存回放均通过（`GOMEM_CORPUS_DIR=.cache/corpus go test ./internal/engine -run TestOfficialVMwareReencodedLinux -count=1 -v`）。重编码仅验证映射链路，不是实际虚拟机采集器验收。

尚无真实 VMware 采集器输出的验收。未支持内存嵌入式快照、完整 CPU 状态解析、通用虚拟机内核自动配置或全部版本。TUI 库导入仍按单文件操作，应先把两个成员放入同一目录再打开；尚无原子配套导入。以上合成控制不代表完整格式或平台验收。
