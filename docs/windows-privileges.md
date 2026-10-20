# Windows 进程令牌特权

`windows.privileges` 对应固定基线的 `windows.privileges.Privs`。它列出活动进程令牌里的特权，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.privileges --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.privileges --image memory.dmp --case ./case-001 --offline --param pid=4
```

令牌地址来自 `_EPROCESS.Token.Object`。64 位清掉低 4 位，32 位清掉低 3 位，这是固定基线的 `_EX_FAST_REF` 掩码，不会再把这个值当成指针解一次。没有这个成员时任务失败。

现代令牌的 `_SEP_TOKEN_PRIVILEGES` 有 `Present`、`Enabled` 和 `EnabledByDefault`。索引从 0 到 63。只有锁定特权表里的 35 个索引会输出，位都没置上的行也保留，属性是空字符串。属性顺序是 `Present`、`Enabled`、`Default`，用逗号连接。

`Privileges` 是指针时走旧布局。`PrivilegeCount` 小于 1024 才读取 `_LUID_AND_ATTRIBUTES`。这时 Present 恒为真，`Attributes` 的第 1 位是 Enabled，第 0 位是 Default。计数大于等于 1024 时该令牌不输出行，摘要里记为 broken，任务仍成功。未知的特权值跳过。

`Token.Object` 读不到时跳过该进程，留下诊断行，任务不失败。特权位或 LUID 数组读失败则任务失败。`pid` 是逗号分隔的进程号。摘要行不是特权。真实 32 位镜像和时间线还没有验收。

官方 Windows 10 19041 样本有 120 个进程、4200 行特权，没有跳过或 broken。PID、进程名、特权值、名称、属性和描述与固定基线一致。其中 2352 行属性为空，594 行是 `Present,Enabled,Default`。

合成样本覆盖低位引用计数、空属性、不可读令牌、一条 `SeDebugPrivilege` 的 LUID 记录，以及计数 1024 的 broken 令牌。

```sh
python3 tools/diff_results.py \
  --native native-windows-privileges.jsonl \
  --reference reference-windows-privileges.json \
  --mapping docs/diff/windows.privileges.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestWindowsPrivileges|TestOfficialWindowsPrivileges' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.privileges.Privs` 生成。当前保持 partial、accepted=false。
