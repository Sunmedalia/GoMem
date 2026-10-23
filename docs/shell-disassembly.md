# Shell 原生反汇编（v0.1 开发预览）

在 `gomem shell --image ...` 中使用：

```text
use kernel
dis 0xfffff80436020000 128 x64
use process EVIDENCE_ID
dis 0x400000 64
use physical
disasm 0x1000 32 arm64
```

`dis ADDRESS [LENGTH] [ARCH]`（别名 `disasm`）读取当前选中的地址空间。默认长度 128 字节，上限 65536 字节；地址按无损十六进制显示，结果同时包含层名、架构、指令地址、原始机器码和汇编文本。长度是字节数而非指令数，沿用固定基线 volshell 的默认读取长度。

架构默认取引擎已选择的架构。支持 x86（32 位）、x64（64 位）、ARM（小端 ARM 模式）和 ARM64（小端）；PAE 按 x86 解码，`intel`/`intel64` 是显式架构别名。手工选择 ARM 解码器不意味着引擎已支持 ARM32 页表。ARM 模式要求地址和字节长度四字节对齐；不支持 Thumb。

解码使用已有 Go `golang.org/x/arch` 库，无 Python 或本地 Capstone 运行时依赖。x86 使用 Intel 语法；ARM 使用 GNU 语法。解码库的指令覆盖和别名可能与固定基线 Capstone 不同，当前没有对全部指令集建立差分验收。

源身份在读取前和输出结束时验证，远程镜像也执行条件验证。读取缺页、越界、地址溢出或源变化均返回错误，不补零。无效/截断指令在实际位置报错，之前已经输出的有效指令可供检查；取消和输出失败会立即中止。输出只用于交互探索，保存命令历史，不会自动创建封存的插件证据或反汇编文件。

`internal/explore/disassembly_test.go` 覆盖 x86/x64/PAE、显式 ARM 和 ARM64、所选层、x86 相对调用目标、显式覆盖、读取边界/缺页、无效/截断输入、架构与长度限制、取消、输出失败及镜像变化；CLI/shell race 回归通过。

完整 volshell 仍未对齐：通用层注册/创建、任意模块/符号上下文切换、各种整数显示、完整类型/对象遍历和搜索接口等仍需单独实现。Capstone 适配、Thumb、符号化反汇编、全部架构/指令验收仍待补齐。
