# FTP 镜像快照（v0.1 开发预览）

```text
gomem doctor --image ftp://host/path/memory.raw
gomem analyze linux.pslist --image ftp://user:password@host/path/memory.raw --symbols kernel.json --os linux --dtb 0x1000 --case ./case
```

FTP 先以二进制 RETR 完整获取到私有本地快照，校验传输完成状态后，通过只读文件句柄提供随机访问。分析和缓存回放使用本次捕获的固定字节，不在每次读取时重新连接服务器。每次重新打开 URL 都重新获取并计算完整 SHA-256；这避免固定 URL 的旧下载缓存被误认为当前镜像。`--offline` 在连接和创建快照之前拒绝远程访问。

默认匿名登录，也支持 URL 用户名与密码、非标准端口、EPSV 和 PASV。PASV 数据连接使用控制连接的对端地址。单个 URI 路径前导斜杠表示登录目录；`/%2Fabsolute/file.raw` 可以选择绝对路径。支持文件名转义与 `;type=i`，拒绝文本/目录模式、控制字符、URL 查询和片段。FTP 传输并非 FTPS；FTPS、代理与主动模式尚未实现。

有案件目录时，临时快照位于 `CASE/sources/`，否则使用系统临时目录。创建采用独占文件和私有权限，写完 sync、关闭并重开只读句柄；镜像与远程服务器只读，不执行 STOR、DELE、APPE。文件大小和修改时间在后续任务/缓存回放时验证，案件数据库与任何快照的文件别名均被拒绝。快照在正常关闭、获取失败和合作式取消时删除；硬终止进程可能留下临时文件，当前没有持久下载缓存或断点续传。

SIZE/MDTM 可用时，在获取前后校验，已声明大小的传输必须精确完成；不支持这些命令时仍支持完整流获取，并把对应元数据保留为不可用。SIZE 和修改时间不能保证服务器提供原子快照或检测同时间粒度内的等长修改；本功能固定的是实际捕获的完整流，不能据此宣称远程采集原子性。公开服务器、代理和版本矩阵仍待验收。

获取使用 1MiB 流缓冲，控制回复总预算 1MiB，URL 上限 64KiB；默认 30 秒 socket 空闲超时。上下文取消会关闭控制和数据连接，涵盖连接欢迎、登录、数据和结束确认阶段。Go API `OpenFTP` 可配置空闲超时、快照目录及字节上限；无字节上限时仍需足够本地磁盘，写出失败不保留成功源。错误仅显示操作名称，服务器可能回显凭据的回复不进入错误文本；URL 展示去除认证信息。

`doctor` 的 `remote_snapshot` 以及任务的 `engine.source.*` provenance 保存协议、完整内容散列、长度和可用的远程大小/修改时间。`image_sha256` 为捕获字节的散列，与相同本地 RAW 一致。VMware 的 FTP VMEM/VMSS/VMSN 配套捕获沿用双成员身份清单，两个成员的快照均由组合源负责关闭。

验证包含：

- 原生 wire-level FTP 控制服务器，覆盖 EPSV/PASV、二进制特殊字节、并发本地读取、无 SIZE/MDTM、认证回显脱敏、截断、错误结束状态、大小/时间变化、获取字节上限、快照变化、取消、超时与清理；`FuzzFTPURI` 检查命令和来源边界。
- `GOMEM_BASELINE_DIR=... go test ./pkg/memory -run TestFTPActualPinnedResourceAccessor -count=1` 调用实际未修改的固定 Volatility ResourceAccessor，完整流 SHA-256、长度和四处 seek/read 一致。参考程序为 `tools/ftp_reference.py`，缓存隔离在临时目录；未启用环境变量时跳过，跳过不算验收。
- Windows/Linux 合成分页分析的指定进程字段、源 provenance、SQLite 封存与缓存回放一致。服务器在获取后替换文件不改变已打开快照；重新打开获取新散列并重新执行任务。FTP VMware 配套关闭后不遗留两个快照。
- `GOMEM_CORPUS_DIR=.cache/corpus go test ./internal/engine -run TestOfficialFTPSnapshotLinux -count=1 -v` 将官方 Debian 512MiB RAW 经本地 FTP 传输，完整散列、自动 DTB、133 条有序进程指定字段、封存和缓存与本地一致。这是回环服务器控制，不是公网兼容验收。

FTP 传输依赖纯 Go 的 [jlaffaye/ftp v0.2.4](https://github.com/jlaffaye/ftp/tree/v0.2.4)（ISC 许可证），不引入 Python/Volatility 运行时依赖。能力矩阵保持 partial，未声明完整上游资源协议或采集验收。
