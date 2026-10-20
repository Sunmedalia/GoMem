# Linux 进程参数

`linux.psaux` 通过活动任务的 `mm.arg_start` 与 `mm.arg_end` 定位参数字节，在各自进程地址空间读取；`mm.pgd` 先经内核虚拟地址转换为物理页表根。PID 筛选使用 task.pid；PPID 使用 real_parent.tgid，与 getppid 的线程组语义一致。ProcessIdentity 与 linux.pslist 的对象地址、PID 和启动时间身份一致。

```sh
bin/gomem analyze linux.psaux --image memory.raw --symbols exact.json.xz --case ./case-001 --format jsonl
bin/gomem analyze linux.psaux --image memory.raw --symbols exact.json.xz --case ./case-001 --param pid=1,100
```

ARGS 按锁定基线把 NUL 替换为空格，并在显示长度大于一时仅去掉一个末尾空格。Arguments 保存按 NUL 分割的元素（去掉单个终止分隔产生的额外空元素），ArgsRaw 保留确切字节，JSON 为 base64。无效 UTF-8 使用 Unicode 替换解码，Validation 标记 `invalid_utf8`；缺少终止 NUL 也单独记录。428 个确定性 Python 解码/显示参考样本验证了无效前导字节、残缺多字节序列、代理项编码、Unicode、空元素及空格行为，生成器仅用于开发测试。

`mm=0` 的任务显示 `[COMM]`，ArgsSource 明确为 `comm_without_mm`，ArgsRaw 为 `no_user_mm`。该显示来自任务名，并不是读取的用户参数；退出中的用户任务也可能没有 mm，不能据此断言原先是内核线程。mm 指针不可读会记录错误，不会伪装成方括号任务。

默认 max-args=4096 与固定基线一致。可显式提高至 16MiB；零、倒置范围、超上限各有明确状态。空范围标记 `empty_argument_range`，不创造已捕获空串。读取失败保存原始前缀、声明长度、CapturedBytes 和 ReadComplete=false，ARGS/Arguments 保持 missing；所属任务失败，但其他独立任务继续。取消及输出错误立即停止。原始字节最多按声明上限读取，参数向量另限制 65,536 个元素；超限时保留完整原始捕获和 ARGS，只将 Arguments 标记 `argument_count_limit` 并令任务失败，避免大量 NUL 导致过多元素分配。

用户提供的 Linux 样本解压后与官方 linux-sample-1 的 SHA-256 一致。在这份 Debian 3.2 x64 镜像上，133 条 PID/PPID/COMM 全部一致；92 条用户参数捕获及显示一致，39 条无 mm 显示一致，另外 2 条缓冲区不可读对应上游 null。两个读取错误仍保留，四字段原始比较保持 matched=false，任务失败并保留 133 行。不能将 131 条显示一致描述为整个插件通过验收。[差分与证据包记录](linux-psaux-validation.json) 包含构建/符号摘要和错误来源。

```sh
python3 tools/diff_results.py --native native-psaux.jsonl --reference reference-psaux.json --mapping docs/diff/linux.psaux.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialLinuxProcessArguments -count=1
python3 tools/build_argument_fixtures.py --check
go test ./internal/plugins -run '^$' -fuzz FuzzLinuxArgumentDisplay -fuzztime 10s
```

锁定参考入口为 `tools/reference.py --plugin linux.psaux ...`，详见 [验证说明](validation.md)。常规测试覆盖 x64、x86/PAE、独立页表、PPID 线程组、PID 筛选、无 mm/不可读 mm、倒置/空/超限范围、缺页前缀、无效 Unicode、向量上限、独立失败、取消和输出错误；真实 x86/PAE 以及更多 Linux 内核仍待语料验证。命令行缓冲区可由进程修改，结果只描述镜像中的捕获内容。外部交换页、完整系统版本/参数组合及所有损坏行为尚未通过验收，保持 partial、accepted=false。
