# Windows Amcache

`windows.amcache` 对应固定基线的 `windows.registry.amcache.Amcache`。它从活动 hive 里找第一个名称包含 `amcache` 的 hive，读取其中的程序、文件和驱动记录。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.amcache --image memory.dmp --case ./case-001 --offline --format jsonl
```

名称比较不区分大小写。打不开的候选会跳过，换下一个。一个都没有时任务仍完成，并留下一行 `RecordType=absent`，不会把“没有 hive”说成一次成功的空清点。同一镜像里只使用第一个能打开的 hive。

Windows 10 读取 `Root\InventoryDriverBinary`、`Root\InventoryApplication` 和 `Root\InventoryApplicationFile`。Windows 8 读取 `Root\Programs`，以及 `Root\File` 下面再进一层的文件键。某一节不存在就跳过，不让整个任务失败。

程序 ID 重复时保留第一次出现的位置和最后一次的内容。文件按程序 ID 排序后分组。对得上的程序先输出，它的文件深度为 1；对不上的文件留在根上。没有文件的程序排在这组文件之后。驱动键名里有 `/` 时，路径用键名，SHA-1 用 `DriverId`；否则 SHA-1 用键名，路径用 `DriverName`。

字符串按 UTF-16LE 解码，末尾的 NUL 去掉，奇数个字节的最后一字节变成 U+FFFD。`REG_DWORD` / `REG_QWORD` 不会被当成字符串。SHA-1 先按基线去掉开头的 `0000`（仅驱动），再去掉剩余的前导 `0`。读不到的值保持 `unparsable`，不补零。

`InstallDate` 和 `LinkDate` 走固定基线的 `_get_datetime_str_value`。那个函数在进入字符串解析之前就把所有已读到的值判成不可解析，后面的 `strptime` 实际执行不到。本地保持同样的结果，不另外把日期解析出来。键的 Last Write 和其他 FILETIME 仍按 100ns 保留；和基线比较时截断到秒。

合成测试覆盖前导零、奇数长度、死掉的日期分支、重复程序 ID、孤儿文件和没有文件的程序。官方 Windows 10 19041 样本只有 `InventoryApplication` 和 `InventoryApplicationFile`：56 个程序、101 个文件，共 157 行。其中 57 个文件挂在程序下面，44 个文件没有父程序。没有驱动项。选定字段、秒级时间和父路径与固定基线一致。

```sh
python3 tools/diff_results.py \
  --native native-windows-amcache.jsonl \
  --reference reference-windows-amcache.json \
  --mapping docs/diff/windows.amcache.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run TestOfficialWindowsAmcache -count=1
go test ./internal/plugins -run TestAmcache -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.amcache.Amcache` 生成。当前保持 partial、accepted=false。Windows 8 真实 hive、驱动项、32 位和时间线导出还没有对照。
