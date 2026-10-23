# S3 版本固定读取（v0.1 开发预览）

```text
gomem doctor --image s3://bucket/memory.raw --s3-region us-east-1
gomem analyze linux.pslist --image 's3://bucket/memory.raw?versionId=VERSION' --s3-region us-east-1 --symbols kernel.json --os linux --dtb 0x1000 --case ./case
gomem doctor --image s3://bucket/memory.raw --s3-region us-east-1 --s3-anonymous
```

通过 AWS SDK for Go v2 访问 S3，运行时不依赖 Python、s3fs 或 Volatility。默认使用 AWS 配置和凭据链（包括环境变量、配置文件及 SDK 提供的角色/SSO 等提供者）；地域由 `--s3-region` 或 AWS 配置提供，未配置时明确报错。`--s3-anonymous` 显式选择公共匿名读取，不在认证失败时自动切换。`--s3-endpoint` 与 `--s3-path-style` 支持兼容端点；显式端点必须是 HTTPS，只有回环 IP 可使用 HTTP。标准 AWS SDK endpoint 配置也适用，操作方应正确配置 TLS 端点。认证错误不持久化 SDK 的 URL、服务器正文或密钥信息。

支持普通 bucket/key URI，键长度上限 1024 字节，保留转义空格、加号、百分号和路径字符。可选且唯一的查询参数为 `versionId`；不在 URI 中接收凭据，拒绝片段及控制字符。SSE-C 客户端密钥、requester-pays、ARN/access-point、S3 Express 和其他特殊 bucket 类型尚未实现。

打开时读取 HeadObject，固定非空大小、强 ETag 和可用版本 ID。非 null 版本的后续 GET/HEAD 均携带版本号，同时携带 If-Match。没有版本或 null 版本时，继续以 If-Match 验证当前对象。每次读取要求准确的 Content-Range、Content-Length、总长度、ETag 和版本，并检查短读/多余内容。仅执行 HEAD/GET，不上传、改写或删除。S3 的 ETag 是服务端身份标记，不假定它是 MD5；案件仍对完整对象流计算 SHA-256。

任务开始/结束及缓存回放都会校验相同对象版本。新增最新版本不改变已打开的旧版本；旧版本被删除或不带版本的对象被替换时明确失败。重新打开不带版本号的 URI 会选择当时的最新版本并重新散列。provenance 的 `engine.source.*` 保存 bucket、key、版本、ETag、地域、端点和长度，参与任务缓存键；相同字节的不同来源/版本也不混用来源信息。`doctor` 输出 `cloud_object`；URI 名称不保留查询，实际版本由该结构记录。

读取有 `MaxRead` 上限，不整镜像加载或下载整份快照，暂不提供本地块缓存与断点续传。SDK 请求支持并发；每次操作最长 60 秒，用户取消或 Close 会取消正在进行的请求。`--offline` 在读取 AWS 凭据配置或联网前拒绝远程源。首选官方 SDK 的重试、签名和凭据刷新实现；客户自定义 SDK Client 可通过 Go API `S3Options.Client` 注入。

VMware 配套对象分别固定各自身份。自动发现 VMSS/VMSN 时不把 VMEM 的 versionId 误传给另一对象；需要精确指定元数据历史版本时使用 `--vmware-metadata 's3://bucket/capture.vmss?versionId=...'`。两个成员不能指向同一云对象版本，采集组合散列仍包含两份内容。

验证：

- 独立 wire-level 控制服务通过 HMAC/SHA-256 重算收到的 SigV4，验证 SDK 静态/环境凭据的 HEAD/GET；覆盖并发范围、截断读取、显式旧版本、null/无版本替换、身份变化、错误范围/长度、缺失/弱 ETag、错误状态、重定向、取消及关闭。其他凭据提供者使用 SDK 支持但尚未单独验收。
- `GOMEM_BASELINE_DIR=... GOMEM_CLOUD_REFERENCE_PYTHON=... go test ./pkg/memory -run TestS3ActualPinnedCloudHandler -count=1` 使用实际未修改的固定 `cloudstorage.S3FileSystemHandler` / ResourceAccessor 和 s3fs 2026.9.0；服务端点通过正常 fsspec 配置选择，没有替换解析器或客户端方法。完整 SHA-256、长度和四处 seek/read 与原生一致。参考脚本为 `tools/s3_reference.py`；开发环境缺少上述变量时跳过，CI 单独启用。完整 s3fs 参数语义不是本次已验收范围。
- Windows/Linux 合成分页的指定进程字段、provenance、SQLite 封存、成功缓存、版本切换重新执行、可变对象拒绝回放和 S3 VMware 配套通过；CLI doctor / offline 有端到端控制。
- `GOMEM_CORPUS_DIR=.cache/corpus go test ./internal/engine -run TestOfficialS3Linux -count=1 -v` 用官方 Debian 512MiB RAW 经回环 S3 协议服务核对完整 SHA-256、自动 DTB、133 条有序指定进程字段、封存和缓存，与本地 RAW 一致。
- `FuzzS3URI` 验证 URI 和来源身份边界。

以上未使用真实 AWS 账户或第三方 S3 服务，不代表公网、全部认证提供者、兼容服务或上游完整资源配置验收；矩阵保持 partial。SDK 及 Smithy 采用 Apache 2.0，许可和 NOTICE 保留于 LICENSES。
