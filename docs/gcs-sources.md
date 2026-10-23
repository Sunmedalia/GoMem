# GCS 版本固定读取（v0.1 开发预览）

```text
gomem doctor --image gs://bucket/memory.raw
gomem analyze linux.pslist --image 'gs://bucket/memory.raw?generation=123' --symbols kernel.json --os linux --dtb 0x1000 --case ./case
gomem doctor --image gs://bucket/public.raw --gcs-anonymous
```

原生 Go JSON API 读取，认证使用 golang.org/x/oauth2/google 的 Application Default Credentials（ADC），请求只读 Storage scope。运行时不依赖 Python、gcsfs 或 Volatility。显式 `--gcs-anonymous` 用于公共对象，不自动降级认证。`--gcs-endpoint` 可指定 JSON API origin，必须 HTTPS；只有回环 IP 允许 HTTP。拒绝重定向，错误不包含令牌、凭据路径、服务端正文或请求 URL。凭据留在认证层，不进入证据；Google ADC 支持的其他提供者尚未逐项验收。

URI 接受 `gs://bucket/key` 和唯一的正整数 `generation` 参数；保留转义键名，拒绝 URI 凭据、片段及未知查询。打开时读取并固定非空大小、generation、metageneration、JSON ETag 和内容编码。每个 media GET 都携带固定 generation 及两个匹配条件，要求精确的 206、Content-Range、Content-Length、代际响应头，并检查短读/多余内容。JSON ETag 与 media HTTP ETag 可能不同，不混用。只执行 GET，不改写云对象。

对 gzip 存储对象明确请求 gzip 原始表示，禁用自动解压与服务端 decompressive transcoding；返回编码改变则失败，镜像 SHA-256 始终针对原始字节。支持 identity/gzip，其他存储编码明确拒绝。metadata 限制 64KiB，单次读取受 MaxRead 限制。每次操作最长 60 秒，可取消；Close 取消正在进行的读取。ADC 刷新采用当前操作上下文，缓存具体令牌，避免保留已结束打开操作的上下文。并发刷新串行且等待可取消。

任务前后和缓存回放均验证固定元数据；新增最新 generation 不改变已打开的旧版本，原版本被删除或 metageneration 改变则明确失败。重新打开无 generation 的 URI 获取新版本并重新散列。`engine.source.*` 保存协议、bucket、key、generation（version）、metageneration、ETag、端点与长度，参与缓存身份。doctor 提供 cloud_object。offline 在认证/联网前拒绝远程来源。

VMware 两个对象分别固定版本；自动寻找 VMSS/VMSN 时不继承 VMEM generation。可用 `--vmware-metadata 'gs://bucket/capture.vmss?generation=456'` 显式指定历史版本；拒绝同一对象版本充当两个成员。

验证：

- 独立 JSON API 控制服务覆盖并发范围、键名、旧版本、元数据变化、gzip 存储字节、错误 JSON/范围/长度/代际/状态、重定向、短读、取消、关闭和错误脱敏。
- 临时生成 RSA 服务账户凭据，独立验签 ADC JWT 及只读 scope，验证首次换取和过期刷新；上下文提供者测试覆盖取消与失效打开上下文。测试凭据不写入仓库。
- Windows/Linux 合成分页比较指定进程字段、完整 provenance、案件封存和缓存；版本切换重新执行、元数据变化拒绝缓存、VMware 双对象及 CLI doctor/offline 均有控制。
- `GOMEM_BASELINE_DIR=... GOMEM_CLOUD_REFERENCE_PYTHON=... go test ./pkg/memory -run TestGCSActualPinnedCloudHandler -count=1` 运行实际未修改固定版本的 GSFileSystemHandler / ResourceAccessor 和 gcsfs 2026.10.1，完整 SHA-256、长度及四处 seek/read 与原生一致。通过正常 fsspec 配置指定匿名 JSON 端点，关闭 gcsfs 实验性 zonal/gRPC 模式，没有替换客户端方法。缺少变量时跳过，不建立验收。
- `GOMEM_CORPUS_DIR=.cache/corpus go test ./internal/engine -run TestOfficialGCSLinux -count=1 -v` 以官方 Debian 512MiB RAW 经回环协议服务比较完整哈希、自动 DTB、133 条有序指定进程字段、案件封存及缓存，与本地 RAW 一致。
- FuzzGCSURI 检查 URI 边界。

尚无真实 Google Cloud 环境、完整 ADC 提供者、requester-pays、客户加密密钥、zonal/gRPC、全部 fsspec 参数、持久块缓存或断点续传验收。以上回环控制不代表公网完整覆盖；矩阵保持 partial，非正式发布验收。
