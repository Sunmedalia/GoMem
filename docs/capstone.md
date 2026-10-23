# Capstone 原生反汇编（v0.1 开发预览）

```text
gomem shell --image memory.raw --capstone-library /absolute/path/libcapstone.so
dis 0x1000 128 x64
dis 0x1000 2 thumb
```

显式指定 `--capstone-library` 时，shell 的 `dis/disasm` 使用可选 Capstone v5 动态库。默认仍使用 Go x/arch。Windows/Linux/macOS 的 cgo 构建包含适配器，编译和默认运行不要求安装库；禁用 cgo 或其他平台时显式调用返回不可用。doctor 的 capstone 字段只表示编译包含适配器，不表示本机库已安装或通过测试。加载失败直接报错，不自动回退。

库路径必须为绝对路径；原生库是调用者选择的受信任本地代码。Windows 使用 UTF-16 LoadLibraryExW，支持包含空格和中文的路径。绑定 cs_version/open/close/option/malloc/free/disasm_iter，校验 v5 主 ABI 后才分配和读取指令。使用库自身的分配/释放函数；不启用 detail 和 skipdata。x86/x64 使用 Intel 语法，另支持小端 ARM、ARM64 和 Thumb。ARM 两种模式要求四字节地址/长度对齐，Thumb 要求两字节对齐；架构别名和 PAE 行为见 shell-disassembly.md。

每次解码上限 64KiB，保留地址和原始机器码，校验 native 消耗长度、地址推进、指令长度和原始字节。无效、截断或不支持的指令在实际位置明确失败，并保留先前有效输出；固定上游 display_disassembly 在这里静默停止，这是刻意保留的错误语义差异。取消在原生调用前后检查；每次调用只解码一条指令，不能强制中断同步 C 调用。每段输入重建 native 解码状态，避免上一段未完成的 Thumb IT 条件影响新输入；同一 Decoder 同时只能处理一段输入，交错调用明确失败。关闭和解码的 native 访问串行，输出回调在锁外运行，可以取消或关闭解码器。镜像身份在读取前和正常输出结束时校验。

验收记录：

- capstone.lock.json 固定 5.0.9 提交及归档 SHA-256；`python3 tools/fetch_capstone.py` 校验后解压。使用官方 CMake 生成共享库，源码不改动，第三方源码和二进制不提交。
- `tools/build_capstone_oracle.py` 使用锁定且未修改的 Volatility display_disassembly 和实际 Python Capstone。270 个案例覆盖五种模式、三个地址（含高位地址）、正常/空/截断指令与固定随机输入。x86/x64/ARM/ARM64 共 216 个对照实际上游渲染；54 个 Thumb 案例为直接 Capstone 对照，不声称上游提供 Thumb。
- Python 发行包版本固定 5.0.9；其模块 `__version__` 仍写作 5.0.7，因此生成器校验发行包 metadata。C API 只暴露 5.0，不能据此识别补丁版本。
- `GOMEM_CAPSTONE_LIBRARY=/absolute/library go test -race ./pkg/disasm ./internal/explore ./internal/cli` 验证全部指令地址、机器码、助记符、操作数和上游文本，及 shell 当前层、分支目标、Thumb、取消、输出失败、源变化和无回退。缺少环境变量的 native 测试明确跳过，不计作验收。
- 原生控制另外验证连续独立 Thumb 输入不会继承 IT 条件，及把实际库复制到中文/空格路径后仍可加载、解码和关闭。三平台 CI 从固定归档构建真实共享库，并强制启用 cgo，防止原生测试因构建配置而跳过。
- `GOMEM_CAPSTONE_LIBRARY=/absolute/library go test ./pkg/disasm -run '^$' -fuzz '^FuzzCapstoneDecode$' -fuzztime 10000x` 使用实际五种原生解码器检查指令边界和明确失败。

当前只接入交互 shell，没有改变分析插件的解码和大小推导逻辑。全指令集、其他大小端/模式、符号化反汇编、真实各平台采集语料、完整 volshell 和插件级 Capstone 差分验收仍未完成，矩阵保持 partial。Capstone BSD 许可与上游第三方许可见 LICENSES/Capstone-LICENSE.txt 及 LICENSES/Capstone-THIRD-PARTY.txt；GoMem 不分发原生库。
