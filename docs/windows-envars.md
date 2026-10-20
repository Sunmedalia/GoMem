# Windows 进程环境变量

`windows.envars` 对应固定基线的 `windows.envars.Envars`。它从每个活动进程的原生 PEB 读取环境块，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.envars --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.envars --image memory.dmp --case ./case-001 --offline --param pid=384 --param silent=true
```

环境块在进程自己的页表里。`Environment` 是 `_RTL_USER_PROCESS_PARAMETERS` 里的指针，`EnvironmentSize` 是字节数。没有 `EnvironmentSize` 时改读 `Length`，这是 Windows XP 的布局。指针按地址掩码截断：64 位是 `0x0000ffffffffffff`，32 位是 `0xffffffff`。大小为 0 时不读缓冲区。

块按 UTF-16LE 解码，不成对的代理项和末尾多余字节变成 U+FFFD。然后按 NUL 切开，并丢掉最后一段。没有结尾 NUL 的最后一条变量因此不会出现。末尾多余的一个字节只落在被丢掉的那段里，不会改变前面的变量。每段用第一个 `=` 分开。没有 `=` 时，名称是去掉最后一个字符后的文本，值是整段；名称或值为空都丢掉。所以 `NOEQUALS` 会变成名称 `NOEQUAL`、值 `NOEQUALS`。这是固定基线的切分方式。

`Block` 不是环境块本身，而是 `Environment` 指针所在的地址，格式和 Python `hex()` 一样。环境块地址留在 `Environment`。单条读失败不输出半截变量。没有 PEB、参数指针为 0、空块或切完没有变量时保留诊断行，不因此失败。指针、大小或缓冲区读失败会保留诊断并让任务失败；固定基线遇到无效地址就跳过该进程，任务仍然成功。

`max-env` 默认 1048576，上限是 16777216。超过上限的块不读。这是本地保护，不是上游参数。

`silent` 接受 `true` 或 `false`，但不会过滤。固定基线声明的参数名是 `silent`，生成器却读取 `SILENT`，所以注册表里的持久变量和内置常见变量名单都走不到。本地同样不隐藏变量，并在摘要里记录 `silent_requested` 和 `silent_applied=false`。

官方 Windows 10 19041 样本有 2960 条变量，PID、进程名、`Block`、变量名和值与固定基线一致，来自 91 个进程。另外 29 条诊断：3 个进程没有 PEB，14 个参数指针不可读，5 个大小不可读，1 个环境指针不可读，6 个缓冲区不可读。后 26 个让任务失败。不可读的页是 prototype 或交换页，当前地址转换还不能处理。真实 32 位镜像还没有验收。

合成样本覆盖有效变量、空值、无等号、丢掉最后一段、末尾奇数字节、`silent` 不生效、`max-env`、不可读缓冲区，以及没有 `EnvironmentSize` 时改用 `Length`。

```sh
python3 tools/diff_results.py \
  --native native-windows-envars.jsonl \
  --reference reference-windows-envars.json \
  --mapping docs/diff/windows.envars.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsEnvars|TestOfficialWindowsEnvars' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.envars.Envars` 生成。当前保持 partial、accepted=false。
