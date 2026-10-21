# Linux 进程 capabilities

`linux.capabilities` 原生读取进程的凭据权限位图，对应固定基线 `linux.capabilities.Capabilities`，运行时不使用 Python。当前仍是开发预览，能力矩阵保持 partial、accepted=false。

```sh
bin/gomem analyze linux.capabilities --image memory.raw --symbols exact.json.xz --case ./case-001 --offline --format jsonl
bin/gomem analyze linux.capabilities --image memory.raw --symbols exact.json.xz --param pids=1,100 --offline
```

输出上游十列：Name、Tid、Pid、PPid、EUID、cap_inheritable、cap_permitted、cap_effective、cap_bounding、cap_ambient。Tid 使用 task.pid，Pid 使用 task.tgid，`pids` 按 task.pid 过滤；二者不混用。PPid 使用整个父 task 对象可读时的 real_parent.tgid，否则按基线显示 0，并保留原生读取诊断。活动任务链不包含 init_task 或额外用户线程，`max-nodes` 默认 131072。

EUID 来自 task.cred.euid，支持整数和嵌入 kuid_t.val。五组权限来自 **task.real_cred**；不会把有效凭据和真实凭据当作同一指针。支持实际符号布局中的 cap 标量 u32、含一/两个 u32 的 cap 数组，以及 val u64。cap 数组的高低字顺序固定为 cap[1]<<32|cap[0]，每个字按符号声明的字节序解释。内嵌结构、字段范围、标量宽度和数组长度均检查。

内核 cap_last_cap 决定有效位掩码。符号不存在时，按固定基线回退到已知列表末尾 40；符号存在但不可读、布局错误或值越过原生 0..4095 边界时任务失败，不猜测掩码。原始置位在掩码外时不参与显示，但仍保留在 Unmasked。非零值等于完整内核掩码时显示 `all`，零值显示空字符串，其他值按固定顺序以逗号和空格连接名称。内核上限超过 63 时，64 位存储不可能等于完整内核掩码，因此不会显示 all。缺失 cap_ambient 是明确的 not_available，不是空权限集。

额外证据包含每组位图的地址、布局、原始捕获、请求/实际长度、读取完成状态、Unmasked/Masked/UnknownBits，以及内核上限的地址和原始字节。名称只使用基线的 0..40 定义；未知位保留为十六进制，内核上限超过 40 时 NamesComplete=false。NameRaw 保存 comm 原始字节，名称解码按基线在 NUL 或替换字符处停止。进程身份结合镜像、对象地址、task.pid 和可用启动时间；SQLite、缓存和导出保留封存摘要。

每个独立字段失败留在原任务行的 Error 列表中，剩余任务继续读取，最终任务状态为 failed。summary 记录 processes、sets_read、ambient_not_available 和 diagnostics，不是进程记录。链结构、PID/comm 读取故障、取消及输出错误直接终止任务。

## 验证及明确的基线差异

固定源码辅助函数提供 1680 个对照用例，覆盖四种布局、逐位权限、空/全掩码、缺少上限符号的回退、未知位及未来上限。原生读取器以两种字节序运行这些用例。合成对象和真实页表测试另外覆盖 x64、x86、PAE、cred/real_cred 分离、EUID 新旧布局、父线程组 ID、Tid/Pid 分离、缺失 ambient、坏布局/指针、部分读取、负数/损坏上限、PID 参数、遍历边界、取消、输出错误、案件回读封存与复用。

现有 Debian 3.2 x64 镜像（SHA-256 `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`）的原始 ISF 把旧 cap[2] 结构命名为 kernel_cap_t。**未修改的固定 Volatility 插件中止，抛出 Unsupported kernel capabilities implementation**：它为该名字选择的扩展只接受 val。因此本镜像没有成功的原版插件输出，不能宣称完整插件对齐。

为单独核验旧布局，开发工具 [reference_capabilities_layout_adapter.py](../tools/reference_capabilities_layout_adapter.py) 明确在进程内适配这一个方法：有 val 时调用原方法，否则调用固定 kernel_cap_struct.get_capabilities。源码、镜像和 ISF 均未改动；manifest 记录适配器摘要、调用次数与 NOT unmodified plugin parity 的范围。它仅用于辅助函数/字段比较，不能替代正式基线验收。

在该明确适配条件下，133 行十列全部匹配；独立筛选 PID 1、2388、2575、3754、8503 的 5 行十列也匹配。原生分别读取 532/20 组位图，测试逐组将原始字节和地址与镜像重新核验，两次运行均验证 SQLite 回读封存与缓存复用。全量 effective 中 85 个 all、44 个空集、4 个具名权限集；133 个任务均没有 ambient 字段，0 个读取诊断。权限高低本身不被自动认定为恶意。最终 fresh CLI 与缓存 JSONL 逐字节一致，单任务证据包通过独立 verify_bundle 校验；make check 全部通过。

```sh
.cache/reference-venv/bin/python tools/build_capability_oracle.py --check
go test ./internal/plugins ./internal/engine -run TestLinuxCapability -count=1
# 必须先用明确适配器分别生成 adapter-linux-capabilities[-filtered].json：
.cache/reference-venv/bin/python tools/reference_capabilities_layout_adapter.py \
  --source .cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75 \
  --image .cache/corpus/linux-sample-1.bin --symbols .cache/corpus \
  --output .cache/corpus/adapter-linux-capabilities.json
# filtered 使用新输出名，并附 --pids 1 2388 2575 3754 8503
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxCapabilitiesLayoutAdapter -count=1 -v
```

仍需成功运行未修改基线的真实语料、现代内核、实际 x86/PAE 镜像、ARM64，以及完整任务链容错/凭据损坏分支。原生严格任务链读取与上游的双向容错和无效对象跳过行为尚未完整验收。本次对照范围和摘要另见 [验证记录](linux-capabilities-validation.json)；映射文件名称包含 layout-adapter，避免与原版插件差分混淆。
