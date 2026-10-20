# Windows 会话

`windows.sessions` 对应固定基线的 `windows.sessions.Sessions`。它列出活动进程，并从进程环境块取出用户和会话类型。不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.sessions --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.sessions --image memory.dmp --case ./case-001 --offline --param pid=488
```

会话 ID 复用 `windows.pslist` 的读法。`Session` 指针为 0 时记为不适用，不是整数 0。指针非 0 时读取 `_MM_SESSION_SPACE.SessionId`，这时 0 是真正的会话 0。Windows 11 那种没有类型信息的 `_PSP_SESSION_SPACE` 不靠固定偏移猜测。

用户名把环境变量 `USERDOMAIN` 和 `USERNAME` 拼成 `域/用户`。比较时变量名不区分大小写，同名的后者覆盖前者。两边都空，或两个变量都不存在时，结果是不适用。只有一边有值时保留斜杠，例如 `/SYSTEM`。`SESSIONNAME` 同样不区分大小写；没出现时会话类型不适用，出现了即使是空字符串也保留。

环境块的切分和 `windows.envars` 相同。读不到参数或环境页时，用户和会话类型记为不适用，行仍然保留，读取错误留在 `Error`，任务失败。固定基线直接跳过这个环境块，任务仍然成功。没有 PEB 只记不适用，不因此失败。

创建时间沿用 FILETIME。对照只比较 UTC 整秒。时间线还没有实现。`max-env` 默认 1048576，是本地上限，不是上游参数。

官方 Windows 10 19041 样本有 120 个进程。会话 ID、会话类型、PID、进程名、用户名和创建时间与固定基线一致。其中 4 个会话 ID 不适用，110 个没有 `SESSIONNAME`，10 个是 `RDP-Tcp#0`，34 个没有用户名。另外 26 个进程的环境页不可读，行仍在，任务失败。这些页是 prototype 或交换页。真实 32 位镜像还没有验收。

合成样本覆盖 `CORP/alice`、大小写覆盖、会话 1、`Console`、会话指针为 0，以及环境块不可读时仍保留行。

```sh
python3 tools/diff_results.py \
  --native native-windows-sessions.jsonl \
  --reference reference-windows-sessions.json \
  --mapping docs/diff/windows.sessions.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsSessions|TestOfficialWindowsSessions' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.sessions.Sessions` 生成。当前保持 partial、accepted=false。
