# Windows 进程树

`windows.pstree` 对应固定基线的 `windows.pstree.PsTree`。它只读活动进程链表，按父进程 ID 组成树，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.pstree --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.pstree --image memory.dmp --case ./case-001 --offline --param pid=684
```

同一个 PID 出现两次时，保留它在链表里的第一次位置，对象内容用最后一次。父进程 ID 等于自己的进程不输出。层级从 `InheritedFromUniqueProcessId` 往上走，直到父进程不在链表里，或者这条链已经见过。`pid` 用逗号分开，保留选中的进程、它们的祖先，以及选中进程的后代。没有 `pid` 时输出整棵树。

子节点按活动链表的顺序输出。固定基线把子节点放进 Python `set`，迭代顺序和链表不一样。对照比较的是父子关系的多重集合，不要求兄弟顺序相同。树深度是层数减一，父节点用和 JSON 渲染器一样的深度栈。

`Offset` 默认是规范虚拟地址。`physical=true` 时改成物理地址，身份仍然用虚拟地址。这次官方样本没有做物理偏移对照。

句柄在 `_HANDLE_TABLE` 没有 `HandleCount` 时不可读，不写成 0。会话指针为 0 时不适用。符号里没有 `SessionId` 时，改读会话地址加 8 的 `unsigned long`。`Wow64` 在两个指针成员都不存在时是 false；指针读失败会让任务失败。

创建时间和退出时间按有符号 `QuadPart` 做 Python 向下整除。整除后的秒数为 0 时不适用。年份不在 1 到 9999 之间时无法解析。读不到时间会让任务失败。

审计名来自 `SeAuditProcessCreationInfo.ImageFileName`。空字符串或读不到的缓冲区不适用，读取错误留在 `AuditError`。命令行和路径来自进程自己的 PEB。两个字符串里有一个读不到，两列都不适用，任务仍然成功，错误留在 `CmdError` 和 `PathError`。摘要行不是进程。

官方 Windows 10 19041 样本有 120 个进程、8 个根，最深 5 层。PID、父进程、名称、线程、会话、WoW64、创建时间、退出时间、审计名、命令行、路径和父子关系与固定基线一致。24 条命令行和路径不可用，1 条审计名不可用，4 个会话不适用，117 个退出时间不适用，句柄全部不可读，2 个进程是 WoW64。地址对照时只比较低 48 位。真实 32 位镜像、`pid` 筛选的官方样本、物理偏移和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-pstree.jsonl \
  --reference reference-windows-pstree.json \
  --mapping docs/diff/windows.pstree.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestArrangePsTree|TestOfficialWindowsPsTree' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.pstree.PsTree` 生成。当前保持 partial、accepted=false。
