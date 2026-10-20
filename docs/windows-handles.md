# Windows 句柄表

`windows.handles` 对应固定基线的 `windows.handles.Handles`。默认从 `PsActiveProcessHead` 枚举活动进程的句柄表。`offset` 非 0 时忽略 `pid`，改为复用 `Pro\xe3` / `Proc` 池扫描，只保留指定进程。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.handles --image memory.dmp --case ./case-001 --offline --format jsonl
```

`TableCode` 的低 3 位是层数，其余是表基址。高于 0 的层是指针页。0 层是 `_HANDLE_TABLE_ENTRY`。句柄值是 `索引 * 4 + 深度 * 每页项数 * 4`。读不到的指针槽不消耗这一层的深度序号；指针本身能读、但目标页不在内存中时，深度仍然前进。同一页再次出现就记一次循环并停止这一支。页数超过 100000，或槽位超过 2000000，任务失败。

Windows 8 以前，`Object` 按 `_EX_FAST_REF` 解释：64 位清低 4 位，32 位清低 3 位，访问掩码用 `GrantedAccess`。Windows 8 及以后，64 位用 `ObjectPointerBits << 4` 和 `GrantedAccessBits`；32 位用 `InfoTable` 去掉低 3 位。原始 `TypeIndex` 为 0 的项在 cookie 解码前丢掉。类型表优先是 `ObTypeIndexTable`，否则是 `ObpObjectTypes`。存在 `ObHeaderCookie` 时，索引用 `(对象头地址 >> 8) ^ cookie ^ TypeIndex` 的低 8 位。

`File` 用 `\Device\` 加上设备对象头的名称。设备名不可用时不追加文件名。设备对象小于对象头大小时丢掉这一行。`Process` 是映像名加 `Pid`，`Thread` 是 `Tid` 和 `Pid`，`Key` 沿 `ParentKcb` 拼路径。只有符号里存在 `_CM_KEY_BODY.Trans` 时，才跳过标志含 `0x4` 的 hive 项，并且移动之后再读名称块。其余类型用 `NameInfoOffset`；没有该字段时，用 `ObpInfoMaskToOffset[InfoMask & 3]`。空字符串记为不可用。读失败时 `Name` 是不可读且不带错误，错误留在 `NameError`。地址保留规范高位。

官方 Windows 10 19041 样本走活动链表，访问了 120 个进程。41 张表是 0 层，76 张是 1 层，没有 2 层或更深。3 张句柄表读不到并计数，没有跳过对象表，也没有页循环。得到 50967 个句柄，来自 109 个 PID，最大句柄值是 `0x2fa8`。其中 37909 个名称不可用，5 个不可读。PID、进程名、低 48 位对象偏移、句柄值、类型、访问掩码和名称与固定基线一致。摘要行不是句柄。

合成样本覆盖文件、进程、线程、注册表键和普通对象名，1 层表、重复页、Windows 8 以前的快速引用、32 位 `InfoTable`，以及 `offset` 只选择一个池进程。真实 32 位镜像、Windows 8 以前的真实句柄表、`offset` 的真实池选择和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-handles.jsonl \
  --reference reference-windows-handles.json \
  --mapping docs/diff/windows.handles.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsHandles|TestOfficialWindowsHandles' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.handles.Handles` 生成。当前保持 partial、accepted=false。
