# HTTP/HTTPS 镜像源（v0.1 开发预览）

`--image` 支持本地文件和 HTTP/HTTPS URL，分析、doctor 和 shell 共用同一只读源。远程源可进入现有 RAW、LiME、AVML、ELF 和 Windows 转储检测路径，不在内存中载入整幅镜像。

```sh
bin/gomem analyze generic.info --image 'https://example.org/acquisition.raw' --case ./case-remote
bin/gomem analyze linux.pslist --image 'https://example.org/acquisition.raw' --symbols kernel.json --dtb 0x1605000 --case ./case-remote
```

当前服务端必须提供字节范围读取（206、精确 Content-Range）及强 ETag。首次使用 `GET Range: bytes=0-0` 获取大小和身份；之后所有读取携带 `If-Match`。响应状态、范围、总长度、ETag、编码和正文长度均校验。不接受悄然返回整个文件的 200 响应，也不对截断内容补零。每次读取上限 16MiB，启动时仍完整流式读取计算 SHA-256；远程访问不代表省略镜像散列。

引擎启动结束、任务执行前后及缓存回放前会重新验证远程身份。不同 ETag 即使长度相同也拒绝使用；服务端必须正确实现不可变 ETag 语义，客户端无法识别故意复用同一 ETag 的错误服务端。这与外部签名采集认证是不同问题。

TLS 使用系统可信根；不提供跳过证书校验选项。允许最多十次重定向，HTTPS 不允许降级为 HTTP；身份固定后不再接受资源 URL 重定向，以免把另一资源的同名 ETag 当作原镜像。`--offline` 在发起请求前拒绝远程镜像，即使案件里已有分析结果。取消操作和关闭源会取消正在执行的请求；默认单次请求超时为 60 秒。

案件中的镜像来源和读取错误使用移除用户名、密码及查询参数的 URL；原 URL 仅用于请求。不要将鉴权信息放在路径中，路径会保留。命令行 URL 自身仍可能进入用户 shell 历史或进程参数；当前没有独立的凭据提供器。

## 验证范围

- `pkg/memory/http_test.go`：本地 HTTP 和真实 TLS 服务，强 ETag/条件请求、并发读取、边界/EOF、读取预算、错误状态、缺失/弱 ETag、错误范围、编码、截断、超长正文、同长度版本变化、大小变化、取消、关闭及 URL 凭据错误脱敏。
- `internal/engine/http_source_test.go`：通过 HTTP 提供原生 Linux 分页样本，核对全镜像 SHA-256，运行 pslist、缓存回放、案件证据校验，并拒绝变化后的远程版本及离线访问；缓存输出期间或分析期间发生变化均返回错误，分析期间已输出的证据保留为失败任务。
- `FuzzHTTPContentRange`：范围头的整数、格式和边界解析，10,000 次执行通过。
- `GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run '^TestOfficialHTTPSource$' -count=1 -v`：真实 Debian 3.2 的 512MiB RAW（SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`）经本地 HTTP 服务读取，全镜像哈希、133 条进程的全部单元格与顺序和本地读取一致；缓存与案件封存验证通过。此项是传输等价性对照，不是新增上游插件验收。

当前是部分实现：不支持无 Range/强 ETag 服务端的本地快照回退；还没有远程请求块缓存、断点下载、专用凭据接口或真实公网/代理兼容性验收。FTP、S3、Google Cloud Storage 和 LeechCore 已有独立适配，适用条件见各自说明。没有以这些限定测试代替完整上游资源访问能力验收。
