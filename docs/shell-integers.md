# Shell 字节与整数显示（v0.1 开发预览）

```text
use kernel
db 0xfffff80436020000
dw 0xfffff80436020001 32 le
dd 0xfffff80436020000 32 be
dq 0xfffff80436020000 128
```

`db/dw/dd/dq ADDRESS [BYTE_LENGTH] [le|be|native]` 分别显示 1、2、4、8 字节无符号整数。对应长名称为 display_bytes、display_words、display_doublewords、display_quadwords。长度按字节计，默认 128，上限 65536；零长度只输出本次请求的层/地址说明。起点不要求按整数宽度对齐。

默认采用固定 little endian，保证同一镜像跨主机输出稳定。`be` 显式采用 big endian，`native` 跟随执行主机；同时接受 struct 风格 `<`、`>`/`!`、`@`/`=`。Python 的这些符号只表示此命令的字节序选项，没有脚本求值能力。db 中字节序不改变单字节值。原有 `hex` 的 Go 十六进制转储格式保留。

每行最多 16 个原始字节，整数按固定宽度十六进制显示，保留行地址及 ASCII 栏。ASCII 沿用固定上游语义：从已显示的数值十六进制反解字节，little endian 多字节组看起来会反序；值不在 33..126 的字节（包括空格）显示点号。这个栏用于对照上游，不应误认为原始内存中的字节次序；db 或 hex 可以显示原始顺序。

先完整读取请求区间，缺页、越界、源变化及读取错误不输出伪造内容。请求长度不是整数宽度的倍数时，完整整数部分与上游文本一致，额外列出尾部地址、字节数量和原始十六进制；固定上游直接丢弃它们。命令在行循环内检查取消，输出失败立即返回，并在读取前后和正常输出结束时验证采集身份。当前所选物理/内核/进程层均可读取，已配置的 Windows pagefile 通过共享 Virtual 接口接入；显示本身不创建封存证据任务。

`python3 tools/build_shell_integers_oracle.py --check` 使用锁定未修改的 Volshell.display_*，配合实际 BufferDataLayer，生成 288 个案例：四种宽度、两种字节序、三个起点和十二种长度。native 的完整数值行与实际上游 stdout 逐字节一致。固定 BufferDataLayer 在 offset=0,count=0 会拒绝请求；夹具记录这一读取异常，GoMem 将零长度视为合法空请求，是显式差异，不冒充读取行为一致。

shell 控制覆盖长/短名称、当前选中层、非对齐地址、little/big/native 模式、默认/空长度、尾部原始字节、取消、输出失败、越界和源变化；CLI 从 Windows pagefile 到 dq 的八字节值验收通过。完整类型/对象探索、模块/符号上下文管理和全部 volshell helper 仍未完成，矩阵保持 partial。
