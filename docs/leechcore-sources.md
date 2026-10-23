# LeechCore 原生采集（v0.1 开发预览）

```text
gomem doctor --image 'leechcore:///absolute/path/memory.raw' --leechcore-library /absolute/path/leechcore.so
gomem analyze linux.pslist --image 'leechcore://DEVICE' --leechcore-library /absolute/path/leechcore.so --symbols kernel.json --os linux --dtb 0x1000 --case ./case
```

可选原生 LeechCore v2 ABI 适配，使用 cgo 在 Windows/Linux/macOS 动态加载显式绝对路径的 DLL/SO/dylib。编译不要求安装 LeechCore，不把第三方库或其源码打包进 GoMem；禁用 cgo 或其他平台时 doctor 的扩展字段为 false，调用明确失败。doctor 扩展 true 仅表示编译包含适配器，不表示本机库已安装或设备可用。

`leechcore://` 后全部文本按固定基线作为设备配置传递，不把嵌套协议当普通 URL 解码。设备及 `--leechcore-remote` 配置受 ABI 的 259 字节上限约束，拒绝控制字符；这些值、库路径和原生错误正文不进入快照名称、诊断或证据。原生库默认不启用详细日志。加载的本地库属于受信任的本地代码。

只绑定创建、关闭、读取、释放内存及只读内存映射查询，不提供写入、任意命令、回调或 option setter。读取使用实际 LcRead 的成功标志；声明范围内任何读取失败均中止采集、关闭设备并删除部分快照，不把不可读页补零。映射检查非空、数量、溢出、重叠和总大小；按物理地址排序并生成私有 LiME 快照，保留地址空洞。`--leechcore-max-bytes` 限制含 LiME 头的输出大小，默认允许可用本地磁盘容纳的采集。

采集写入案件 sources 目录（无案件时使用临时目录），封存前同步文件并重新以只读句柄打开，完整 SHA-256 由分析引擎再次核对。后续随机读取、缓存和 SQLite 封存只使用捕获的固定字节；不重复访问设备。关闭删除临时快照，重新打开重新采集。证据记录 leechcore 协议、快照长度和内容哈希；LiME 哈希包含地址映射头，与原始 RAW 内容哈希不同。原始设备配置被隐藏，调查人员应另外保管采集来源与授权记录。

采集不是原子 live snapshot：各范围读取时刻不同，真实设备可能变化。Go 上下文取消在创建前、每次原生读取前后检查，清理已写出部分；LeechCore 的同步 C 调用没有通用中断 API，因此不能强行打断挂起的创建、读取或关闭调用。真实远程驱动超时、隔离工作进程及硬件一致性验收仍待补齐。进程异常终止可能留下临时文件。`--offline` 在加载库和打开任何设备前拒绝 LeechCore 来源，包括其文件设备。

验证：

- leechcore.lock.json 固定上游源码提交 7436c5e9720c7bc816260f29c705332197ea286d（2.23.4 源码）及归档 SHA-256。`python3 tools/fetch_leechcore.py` 下载并校验，原始源码仅在忽略的 .cache 中。使用上游 Makefile.macos 构建真实通用 dylib，未修改库源码。
- 实际库读取双范围稀疏 LiME，采集后的每个物理区域、空洞及全部文件字节一致。故障控制覆盖重叠、溢出、空映射、读取失败、取消、输出预算和部分文件清理；故障注入属于 Go acquisition 控制，不冒充真实硬件故障验收。
- `GOMEM_LEECHCORE_LIBRARY=/absolute/library go test -race ./pkg/memory ./internal/engine -run LeechCore -count=1` 运行实际库的 Windows/Linux 合成分页进程指定字段、provenance、案件封存及缓存控制。缺少库变量时真实库测试跳过，不建立验收。
- 再设置 `GOMEM_CORPUS_DIR=.cache/corpus` 运行 TestOfficialLeechCoreLinux，官方 Debian 512MiB RAW 经真实库 file provider 采集后，完整物理 SHA-256、自动 DTB、133 条有序指定进程字段、案件封存和缓存与直接读取 RAW 一致。
- CI 为 Linux/macOS 下载固定源码、构建真实库并启用上述测试；Windows 当前只编译适配器及执行不依赖实际库的控制。FuzzLeechCoreURI 覆盖输入边界。

当前没有 live hardware、内核驱动、LeechAgent、远程传输/认证及完整版本矩阵验收。固定基线 LeechCoreFile 的写入与补零行为不属于 GoMem 只读接口；完整 handler 对照仍待补齐。矩阵保持 partial。

外部 LeechCore 采用 GPLv3，独立于 GoMem 自研代码的 MIT 许可；分发含该库的组合构建时需遵守其许可。仓库仅提供可选动态适配，不分发第三方二进制。原始许可见 LICENSES/LeechCore-GPL-3.0.txt，上游为 https://github.com/ufrisk/LeechCore。
