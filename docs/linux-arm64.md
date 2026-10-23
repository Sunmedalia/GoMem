# Linux ARM64

原生 Go 地址翻译现支持 little-endian ARM64 stage-1、4KiB granule、48 位虚拟地址和至多 48 位物理地址，包含 4KiB 页、2MiB/1GiB 块、表及叶子权限。读取共享有界同步页表缓存；稀疏表页只要求实际使用的完整描述符驻留，不补零、不吞掉缺失描述符错误。未解释 ARM64 脏页标记，DirtyKnown 保持 false。

`--arch auto` 从完整 ISF 的 `metadata.zero.architecture` 自动识别 `aarch64`/`arm64`。目前必须在同一表的 `metadata.zero` 提供 `page_shift: 12`、`va_bits: 48`；16KiB/64KiB granule、39/52 位地址、LPA2、TBI/MTE tagged 地址及 ARM64 Windows 尚不支持。配置缺失或不支持时报明确错误，不能靠文件名推断页配置。内核和进程地址空间分别选择对应的物理页表根，shell、TUI 和插件的进程内存读取共用该分派。

没有 `--dtb` 时，沿用线性内核镜像的符号相对位置生成根候选，同时验证根自身映射、banner 物理副本及完整 banner。显式 DTB 优先；非零虚拟 KASLR 仍须提供正确 `--kernel-slide`。几何及地址布局参考 [Linux ARM64 内存布局](https://docs.kernel.org/arch/arm64/memory.html)。

本地 Kali 6.8.11 LiME 镜像验证：自动选择 arm64，DTB `0xb387e000`，banner 物理地址 `0xb3079a38`，slide `0`；linux.pslist 完成 169 条记录，linux.pstree 完成 508 行（其中 169 个进程，其余为观察、选择和摘要记录），linux.psaux 的 PID 1 参数读取成功（验证独立进程页表翻译），TUI 按 o 正常进入分析页。linux.lsmod 返回 110 条模块记录，但模块参数读取保留 11 个失败，任务状态为 failed。已修正现代模块枚举的 MOD_INVALID=-1 哨兵处理，实际使用的负数组下标仍拒绝。

这些是本机烟雾验证，未与独立取证工具逐字段比对，也不代表所有 Linux 插件的 ARM64 支持。依赖 Intel 指令、模块 ELF 重建或特定架构布局的插件继续明确拒绝 ARM64。验证摘要见 [linux-arm64-validation.json](linux-arm64-validation.json)。镜像和符号表不随代码提交。

```sh
make build
bin/gomem tui
# 选择 kali.raw，enter 扫描并匹配本地符号，o 进入分析
# / 搜索 linux.pslist，enter 结束搜索，再 enter 按默认参数运行；e 编辑可选参数
bin/gomem analyze linux.pslist --image images/kali.raw \
  --symbols symbols/kali-6.8.11-arm64.json.xz --offline
```

2026-10-23 默认参数复测（不指定 PID）：`linux.pslist` 完成 169 个任务；`linux.psscan` 输出 873 个启发式候选和一条扫描摘要，其中一个候选父地址无法读取，保留结果并将任务标为 failed，不能把全部候选视为真实进程。`linux.bash` 完成，零历史记录：进程列表含两个 `zsh`，没有 `bash/sh/dash`。现已补上 Bash 堆扫描的 ARM64 地址翻译路径并通过合成正例及捕获字节回读测试；这份 Kali 镜像仅为无 Bash 的空结果验证，不代表真实 ARM64 Bash 历史恢复已完成独立验证。
