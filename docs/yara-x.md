# 可选原生 YARA-X（v0.1 开发预览）

```text
gomem shell --image memory.raw --os windows --dtb 0x1000 --yarax-library /absolute/path/libyara_x_capi.so --case ./case
use kernel
yara 0x7ff600000000 0x10000 "/captures/rules.yar" 5
```

GoMem 用原生 C API 动态调用 YARA-X，运行时不依赖 Python。当前提供 `pkg/yara` 框架接口及 shell `yara ADDRESS BYTE_LENGTH RULEFILE [TIMEOUT_SECONDS]`。不新增分析插件；现有 yarascan/VadYaraScan 等官方插件及完整参数语义尚未接入。缺少 `--yarax-library`、禁用 cgo 或非 Windows/Linux/macOS 平台时明确失败，不替换成字符串/正则扫描。doctor 的 extensions.yara=true 只表示编译包含适配器，不表示本机库已安装或验收通过；默认 tools/dist.py 的无 cgo 裁剪包仍标记扩展不可用。

库路径必须为绝对 UTF-8 路径，Windows 使用 UTF-16 LoadLibraryExW。加载的原生库属于调用者选择的受信任代码。绑定固定 1.9.0 的公开 C API，规则/编译器/扫描器/模式保持 opaque，仅复制 YRX_MATCH、YRX_BUFFER 公开字段。该 C API 不提供版本查询，因此不能根据加载成功宣称任意库版本 ABI 已验证；仅锁定的源码构建经过对照。yarax.lock.json 固定版本、提交和源码归档 SHA-256，`python3 tools/fetch_yarax.py` 验证后解压，`cargo build --release --locked --manifest-path SOURCE/Cargo.toml -p yara-x-capi` 使用归档内 Cargo.lock 构建。第三方源代码和二进制不提交。

**运行时生命周期**：YARA-X/Wasmtime 会安装进程级信号处理器，安全卸载需要满足不适用于一般 Go 进程的前置条件。因此成功加载的库保留到进程退出，不调用 yrx_finalize/dlclose。最多加载 8 个不同路径；规则和扫描器在关闭/失败时独立销毁，不保留 Go 指针供异步 native 使用。使用同一 Rules 的扫描和 Close 串行；不同 Rules 可以同时使用各自扫描器。每次扫描创建/销毁 scanner，不把上一缓冲的匹配状态复用到下一缓冲。

规则源限制为 1MiB UTF-8、禁止 NUL。shell 只读本地非空普通规则文件，读取前后验证大小/修改时间，规则内容 SHA-256 标识本次捕获字节。禁用 include，防止编译时隐式读取未记录的其他文件；compiled rules、外部变量、namespace 创建、include 路径和自定义模块数据尚未接入。标准内置模块使用实际库提供的实现，其全量行为仍待验收。语法错误提供至多 64KiB 的结构化 JSON diagnostics；编译警告也原样以 JSON 传递，不把警告丢掉。shell 的错误/警告记录是 JSON，不直接打印规则源的控制字符。

每次扫描输入上限 32MiB，超时默认 5 秒、可设 1..60 秒；Go deadline 会向上取整为秒并收紧 native 超时。native 超时只是尽力停止，不是严格硬截止；规则编译本身没有强制中断 API。取消在调用前/后检查，无法强行中断同步 C 调用，超时或取消不返回伪装成成功的部分结果。匹配收集默认限制 10000 条、8MiB 名称及原始匹配字节；框架调用可在 100000 条/64MiB 内调整。回调预算耗尽会快速忽略后续收集，但底层同步扫描仍可能运行至结束/超时。结果预算、分配/收集失败和 native 错误明确返回，无部分成功列表。

shell 完整读取一次请求区间（底层每次读取不超过 16MiB），不把不同窗口分别扫描；这样 `filesize`、`#pattern`、`at` 及多模式全局条件针对同一份输入。区间有缺页/空洞时直接失败，不补零、不压缩。规则中的 offset 相对于本次缓冲，shell 输出的绝对命中地址再加请求起点。任意大小的整镜像、多块累计、进程 VAD 区间的完整全局扫描语义仍待补齐。

输出 interactive_yara_match 包含采集哈希、规则哈希、层、namespace、rule、pattern、匹配原始字节及字节 SHA-256；地址/来源偏移为无损十六进制，匹配跨页或 RAM/pagefile 时保留各来源片段。无 pattern instance 的匹配规则另输出 rule_only，不凭空产生地址或匹配字节；固定 YaraScanner 会丢掉这类规则，这部分是显式额外信息。正常结束有 complete=true 摘要，native 超时/超限等扫描错误输出 complete=false 并返回错误；读取、编译、源变化或输出失败也返回错误，未必有完整摘要。输出是交互视图，没有创建封存插件任务、缓存或证据书签。

验证：

- 实际固定 YaraScanner（选择 yara-x 1.9.0）与真实 Python YARA-X 生成 75 个案例，包括字面量、nocase、wide/ascii、hex jump、regex、重叠命中、多模式、计数、filesize、at、xor、base64、private/helper 与多规则。native 按上游顺序比较 namespace.rule、模式名、偏移及全部原始字节，同时核对规则级匹配。
- 真实固定 C 库通过语法/禁 include 错误、结构化警告、无字符串规则、空缓冲、结果预算、关闭和并发扫描控制。实际慢规则触发 native 一秒超时，结果不被标为成功。
- shell 用真实库验证跨 RAM/pagefile 的 YARA 命中和原始来源、规则级匹配、编译错误、输出失败与取消；不把合成内存控制当真实恶意内存验收。
- `GOMEM_YARAX_LIBRARY=/absolute/library go test -race ./pkg/yara ./internal/explore ./internal/cli -run Yara -count=1` 启用真实库测试；没有环境变量的 native 测试明确跳过，不建立验收。`FuzzYaraNativeScan` 用真实固定多模式规则扫描任意缓冲，检查匹配字节与边界，1000 次通过。
- CI 在 Windows/Linux/macOS 从固定归档构建 C 库，强制 cgo 并运行真实库测试；平台结果以实际工作流为准，增加配置不等于已验收通过。

YARA-X 采用 BSD 3-Clause，原始许可保留于 LICENSES/YARA-X-BSD-3-Clause.txt。外部 Rust/Wasmtime 及其他传递依赖仍受各自许可约束；当前 GoMem 不分发第三方原生库，组合分发前需保留其完整第三方声明。完整模块/编译文件/插件集成、扫描持久化、性能及真实各平台语料验收未完成，矩阵保持 partial。
