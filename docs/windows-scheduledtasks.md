# Windows 计划任务

`windows.scheduledtasks` 对应固定基线的 `windows.registry.scheduled_tasks.ScheduledTasks`。它从活动 hive 里找第一个名称包含 `software` 的 hive，解码 `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` 下的任务。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.scheduledtasks --image memory.dmp --case ./case-001 --offline --format jsonl
```

名称比较不区分大小写。打不开的候选会跳过，换下一个。一个都没有时任务仍完成，并留下一行 `RecordType=absent`。`Tasks` 键不存在时同样留下一行，不把“没有任务键”说成一次成功的空结果。`Tree` 键缺失时任务仍然输出，只是任务名不可用。

每个任务键是 `Tasks` 的直接子键。名称来自 `Tree` 下面任意深度的第一个 `Id` 值，类型必须是 `REG_SZ`。显示出来的是那个树键自己的名字，不是完整路径。同一个 GUID 后出现的名字覆盖先出现的。键名和 `Id` 做精确匹配，空的已映射名字保留为空字符串。

每个任务把动作和触发器做成笛卡尔积。某一侧没有记录时，用一行不可用的动作或触发器补上，不把整条任务丢掉。读不到的值保持错误，不补零。`REG_DWORD` 一类整数不会被当成二进制结构。

二进制布局沿用固定基线，包括这些结果：

- `TimeMode` 的枚举值是字符串。整数模式索引对不上，时间触发器的描述保持不可用。Once、Daily 等描述函数仍在，但解码路径走不到。
- Idle 和 Registration 按 Logon 类型保存，描述也是 Logon。
- 邮件动作会把字段读完，但基线没有返回这个对象，所以对应行的动作不可用。
- `DynamicInfo` 把磁盘上的第二个 FILETIME 放进创建时间，第一个放进上次运行时间。输出列保持这个对调。
- COM CLSID 用基线的十六进制格式，不补前导零。
- 主体、显示名、描述和工作目录的空字符串是不可用。动作参数的空字符串保留。上下文只要不是缺失就保留。
- 时间只保留整秒。`0` 和 `0xFFFFFFFFFFFFFFFF` 是不可用，不写成纪元时间。

合成样本覆盖启动、时间、事件、WNF、Idle 后接启动、可执行文件、邮件、COM、消息框，以及创建时间对调。这些样本直接交给锁定的 Python 解码器比较。官方 Windows 10 19041 样本有 311 行：COM 动作 181、可执行文件 83、动作不可用 47；WNF 121、时间 45、Logon 40、事件 15、启动 14、会话 7、触发器不可用 69。选定字段全部一致。45 个时间触发器的描述都不可用。没有消息框行。

```sh
python3 tools/diff_results.py \
  --native native-windows-scheduledtasks.jsonl \
  --reference reference-windows-scheduledtasks.json \
  --mapping docs/diff/windows.scheduledtasks.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsScheduledTasks -count=1
go test ./internal/plugins -run 'TestScheduledTask|TestWindowsTaskGUID' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.scheduled_tasks.ScheduledTasks` 生成。当前保持 partial、accepted=false。32 位、其他 Windows 版本和时间线导出还没有对照。
