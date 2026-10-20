# Windows 进程令牌 SID

`windows.getsids` 对应固定基线的 `windows.getsids.GetSIDs`。它列出活动进程令牌里的 SID，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.getsids --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.getsids --image memory.dmp --case ./case-001 --offline --param pid=4
```

令牌地址来自 `_EPROCESS.Token.Object`。64 位清掉低 4 位，32 位清掉低 3 位。`Token.Object` 读不到时输出一行，`SID` 是 `Token unreadable`，`Name` 是空字符串，任务仍成功。空字符串不是缺失值。

`UserAndGroupCount` 大于等于 `0xFFFF` 时，这个令牌不输出 SID。`UserAndGroups` 指针读失败则任务失败。单个 SID 指针或 SID 头读失败则跳过该 SID。`Revision` 的低 4 位不是 1，或 `SubAuthorityCount` 大于 15 时，停止这个令牌后面的 SID，任务仍成功。字符串里的修订号用完整字节。标识机构只取 6 字节 `Value` 的最后一个字节。权限字节是 `0x10, 0x05` 且没有子机构时，结果是 `S-1-5`。

名称按这个顺序解析：锁定的 86 个已知 SID、461 个服务 SID、ProfileList 用户、第一条命中的 20 条正则。`S-1-5-21-...-553` 先匹配 `RAS Servers`。没有命中时 `Name` 是 `not_available`，对照里是 JSON null。

用户名来自名称包含 `config\software` 的 hive。键是 `Microsoft\Windows NT\CurrentVersion\ProfileList`，值是 `ProfileImagePath`。路径先做成 Python `bytes` 的 `repr`，删掉字面量 `\x00`，再去掉最后一个字符，然后取 Windows 基名。hive 打不开就跳过。`pid` 是逗号分隔的进程号。摘要行不是 SID。真实 32 位镜像和时间线还没有验收。

官方 Windows 10 19041 样本有 120 个进程、1752 行 SID，没有不可读或提前停止的令牌。ProfileList 解析出 4 个用户。239 个名称不可用。PID、进程名、SID 和名称与固定基线一致。

合成样本覆盖 `S-1-5`、`S-1-5-18`、`S-1-5-21-...-553` 的正则顺序、ProfileImagePath 的 `repr` 截断，以及不可读令牌的空名称。

```sh
python3 tools/diff_results.py \
  --native native-windows-getsids.jsonl \
  --reference reference-windows-getsids.json \
  --mapping docs/diff/windows.getsids.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsSIDNamesQuirksAndTokenRows|TestOfficialWindowsGetSIDs' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.getsids.GetSIDs` 生成。当前保持 partial、accepted=false。
