# Windows 命令行证据

`windows.cmdline` 使用精确内核符号，遍历活动进程，经各自页表读取原生 `_EPROCESS.Peb`、`_PEB.ProcessParameters` 和 `_RTL_USER_PROCESS_PARAMETERS.CommandLine`。支持 PID 集合与 max-nodes 上限；没有调用 Python、Volatility 或目标系统代码。WoW64 也按固定基线读取原生 PEB，不混入另一个 32 位 PEB 的值。

```sh
bin/gomem analyze windows.cmdline --image memory.dmp --case ./case-001 --format jsonl
bin/gomem analyze windows.cmdline --image memory.dmp --case ./case-001 --param pid=488,628
```

Args 显示到第一个 NUL，与上游字符串展示规则一致；ArgsFull 保留 Length 声明范围内的完整字符串，ArgsRaw 保留确切 UTF-16LE 字节（JSON 为 base64）。Buffer、Length、MaximumLength、CapturedBytes 和 ReadComplete 区分声明长度与捕获长度。嵌入 NUL、长度超过容量、奇数字节长度、孤立代理项及 BOM 分别记录在 Validation，不会悄悄丢弃后缀或修改原始字节。UTF-16LE 无效序列显示为替换字符，BOM 保留；与上游自动 BOM/编码处理的差异需要独立验证。

读取长度最多 65,535 字节，检查结构字段范围和地址溢出。读取中断或缺页时保存已经捕获的原始前缀，Args/ArgsFull 标记 missing，不能把前缀当作完整命令行。空的、已完整捕获的字符串仍是 string；空 PEB 和空 ProcessParameters 分别记录为不适用状态。非空地址的实际读取错误使任务失败，其他独立进程继续处理；取消和输出错误立即停止。来源记录实际进程层和到达的对象/描述符/缓冲区偏移，ProcessIdentity 与 pslist 保持一致。

官方 Windows 10 19041 样本的 120 个进程中，96 条可读 Args 与固定基线完全一致，24 条对应上游 null。其中 3 条为空 PEB，21 条保留确切错误：14 条 PEB 的参数指针不可读、6 条命令行描述符不可读、1 条缓冲区不可读。全量任务因此失败，结果保留 120 行。原生 PDB 与 ISF 路径得到相同内容、原始字节及缺失分类。

两条已捕获命令行包含嵌入 NUL，Args 与上游显示一致，ArgsFull/ArgsRaw 保留额外内容。这说明显示值的相等不能代替原始字节验证。该样本未出现已捕获空字符串，空值、奇数字节、中文/代理对、孤立代理项及 BOM 使用合成样本验证。

原始三字段比较保留 21 个读取错误与 null 的差异，matched=false；两字段 PID/Process 的 120 行完全一致。对 96 条可读内容的检查逐行核对 PID、名称、Args、身份、捕获长度、原始字节和完整解码，不通过丢弃错误行宣称整个插件一致。[验证记录](windows-cmdline-validation.json) 保存比较摘要、错误分类、ISF/PDB 构建身份及证据包核验结果。

```sh
python3 tools/diff_results.py --native native-cmdline.jsonl --reference reference-cmdline.json --mapping docs/diff/windows.cmdline.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsCommandLines -count=1
go test ./internal/plugins -run '^$' -fuzz FuzzWindowsCommandLineUTF16 -fuzztime 10s
```

参考结果使用锁定入口 `tools/reference.py --plugin windows.cmdline ...` 生成，步骤见 [验证说明](validation.md)。常规测试覆盖 x64、x86/PAE、独立页表、PID 筛选、损坏/未设置指针、部分捕获、异常 Unicode、失败后的继续执行、取消及输出错误。Fuzz 检查解码边界、源字节不变、UTF-8 有效性及告警分类；不等同于对整个对象解析入口的 fuzz 验收。

完整版本/架构、所有损坏布局和参数组合、外部交换页/prototype 解析仍未完成。命令行位于可被进程修改的用户空间，只代表该缓冲区在镜像中的内容；不推导最初启动命令。当前保持 partial、accepted=false。
