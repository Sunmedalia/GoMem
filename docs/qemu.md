# QEMU 迁移内存层（v0.1 开发预览）

```text
gomem doctor --offline --image guest.qemu
gomem analyze linux.pslist --image guest.qemu --symbols kernel.json --os linux --arch x64 --dtb 0x1000 --case ./case
```

原生读取 `QEVM` version 3、RAM version 4。支持 START/FULL/PART/END、节尾 ID 校验、普通页、单字节填充压缩页、CONTINUE、RAM 块大小和 EOS；只把 `pc.ram` 映射为来宾物理内存，其他块仍按实际载荷长度解析。重复页以流中最后一次更新为准，并报告更新数量。压缩页按需扩展，不把填充值或不存在的页伪装成线性源偏移；`Ranges` 的 `qemu-fill` 编码和 stored_length=1 保留物理页与存储字节的区别。

机器标识来自配置节或有界分块扫描及 VM 描述的设备标识。支持固定基线的 i440fx、Q35、microvm、Xen 默认 PCI 空洞与小内存关闭空洞的规则；尚不推断自定义 `max-ram-below-4g`。未知机器的大内存布局明确拒绝，不能据此推断所有架构已支持。

捕获末尾的长度封装 VM 描述，在完整解析流后验证它确实紧跟 EOF，避免将 RAM 中的 JSON 误认作元数据。除 pbs-state、dirty-bitmap 和 spapr/htab 专用边界外，可按设备 name/instance/version 匹配描述，读取普通字段、数组、结构体和子段的明确长度以跨过 FULL 设备节。设备缺少字段描述、版本不符、自定义不明边界或未支持的流标记均失败，不能返回截断的成功内存层。CPU 字段仅用于确定载荷边界，不解释为寄存器证据。

解析保留单个 64KiB 元数据缓存，页载荷只索引、不整镜像加载。VM 描述尾部预算 16MiB，页大小 512 字节至 1MiB且必须为二次幂；页索引上限 2^24，RAM 记录 2^26，节 2^20，节索引 65536，设备字段展开 2^20，嵌套深度 64。读取、物理地址和文件偏移检查边界与溢出；取消、缺页和源读取失败保留错误。

验证：

- `tools/build_qemu_oracle.py` 调用实际未修改的固定 Volatility QemuSuspendLayer，20 个字节后端控制中 14 组的页面散列一致。两个重复更新页控制在上游读取失败，4 个描述设备控制因上游不跳过设备载荷而失败；原生按流顺序和描述恢复，差异不算基线对齐成功。
- 同一生成器运行 [QEMU v9.2.0 官方迁移分析脚本](https://github.com/qemu/qemu/blob/v9.2.0/scripts/analyze-migration.py)，20 组 RAM 页散列全部一致；比较显式把 RAM 块相对地址换为默认 PC 物理坐标。脚本 SHA-256 固定为 `5d92df832acebee546695648f378dde7b303798effaaea17048ec6dd2f33a7c9`。该脚本保留 Python 2 的 `ord(bytes-item)` 调用，测试启动器仅兼容 Python 3 的 `ord(int)`，不修改源文件、解析方法或内存数据；此运行时适配记录在 fixture 中。首次执行生成器联网下载该固定脚本，随后校验本地散列；它仅为开发对照工具。
- Go 测试覆盖压缩与普通页的全页、部分和跨页读取、连续节、不同页大小、其他 RAM 块、五类 PCI 空洞、设备数组/结构/子段、重复页、截断、损坏标记、节 ID、页界限、错误描述和字段资源限制。`FuzzQEMUSuspend` 覆盖解析与接受后的页可读性。
- Windows/Linux 合成物理字节与指定进程字段保持 RAW 一致，封存 SQLite 与缓存回放通过；HTTP 强 ETag/Range 源的同一链路通过。
- `GOMEM_CORPUS_DIR=.cache/corpus go test ./internal/engine -run TestOfficialQEMUReencodedLinux -count=1 -v` 验证官方 Debian 3.2 的 512MiB RAW 重编码：完整物理 SHA-256、自动 DTB、133 条有序进程指定字段、案件封存和缓存均一致。重编码不是 QEMU 采集器原生输出验收。

当前不支持 XBZRLE、mapped RAM、hooks、未知自定义设备布局、现代配置 capabilities 和自定义 PCI 空洞。没有真实 QEMU 生产者语料、完整架构/版本/损坏场景验收、CPU 状态恢复或完整来宾 automagic；仍标记 partial。Python/QEMU/Volatility 均不是 GoMem 取证运行时依赖。
