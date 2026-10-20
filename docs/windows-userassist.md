# Windows UserAssist 计数

`windows.userassist` 对应固定基线的 `windows.registry.userassist.UserAssist`。它从活动 hive 链表里挑出名称包含 `ntuser.dat` 的 hive，读取 `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` 下每个 GUID 的 `Count` 键。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.userassist --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.userassist --image memory.dmp --case ./case-001 \
  --param offset=0xc2040000
```

`offset` 可以省略。给出时按 hive 地址匹配，完整虚拟地址和只保留低 48 位都可以。没有这个键的 hive 直接跳过，不产生行，任务继续。基线在这里写一条警告后同样不产出行。hive 打不开，或 GUID、Count 列表中途失败且没有读到子键时，发出一行 `RecordType=unreadable`。相关字段的缺失原因是 `unreadable`，错误原因是 `hive_unreadable`。

版本看 `_KUSER_SHARED_DATA`。有 `CookiePad` 就是 Windows 7 及以后，值结构 72 字节：`ID` 不适用，`Count` 在偏移 4，`FocusCount` 在偏移 8，焦点时间在偏移 12，`LastUpdated` 是偏移 60 的 8 字节 FILETIME。更早的系统用 16 字节：`ID` 在偏移 0，计数在偏移 4，大于等于 5 时减 5，`LastUpdated` 在偏移 8，焦点字段不适用。符号里没有这个类型时只保留原始字节，计数标成 `unparsable`，不猜版本。短于结构长度的值同样不解析，原始十六进制仍保留。

值名先做 ROT-13。Windows 7 及以后，若第一个 `\` 之前的部分与内置的 101 个已知文件夹 GUID 完全一致（区分大小写），就把名称里每一处该 GUID 换成文件夹路径。更早的系统只做 ROT-13。`Count` 键的路径是 hive 名的最后一段，加上从 UserAssist 起的键名。键和子键的 `RawData` 是字符串 `N/A`，对应基线 JSON 对不适用 HexBytes 的渲染，不是空值。值的 `RawData` 是空格分隔的小写十六进制，原始字节另放在 `RawBytes`。读不到值数据时原因是 `registry_value_unreadable`，不补零，也不把计数写成 0。

键行深度为 0，子键和值深度为 1，并挂到该 Count 键。Last Write 用 Count 键的时间。显示时间与其他 Windows 插件一样保留 100ns，时区为 `Z`。焦点时间按 `timedelta(seconds=(FocusTime+500)/1000)` 的字符串，包括 `0:00:00.500000`。

合成样本覆盖 Win7 布局、已知文件夹替换、短值、读失败、`offset` 筛选，以及没有 UserAssist 键时的跳过。XP 的减 5 和焦点时间有单元向量。官方 Windows 10 19041 样本里，名称含 `ntuser.dat` 的 hive 有三个，只有 `\??\C:\Users\generic-user\ntuser.dat` 含有该键：9 个 Count 键、28 个值，没有子键，共 37 个实体。另外两个值单元格不在内存中，基线跳过，本地各发一条 `RecordType=unreadable`，任务仍完成。

选定字段里 36 行一致：hive 偏移的低 48 位、hive 名、路径、截断到秒的时间、类型、名称、ID、Count、FocusCount、TimeFocused、LastUpdated、RawData，以及父路径。不一致的一行是 `UEME_CTLSESSION`，路径为 `ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`，Last Write 为 `2025-03-06T17:57:40Z`。基线把读失败的值单元格补成 1612 个零字节，再解析出 count 0、focus 0、时间 `0:00:00.500000`。本地保留 `registry_value_unreadable`，不解析这些零。这不是完整验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-userassist.jsonl \
  --reference reference-windows-userassist.json \
  --mapping docs/diff/windows.userassist.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsUserAssist|TestOfficialWindowsUserAssist' -count=1
go test ./internal/plugins -run 'TestUserAssist|TestFocus' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.userassist.UserAssist` 生成。当前保持 partial、accepted=false。32 位、真实 XP 镜像和时间线导出还没有对照。
