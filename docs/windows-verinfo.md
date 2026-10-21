# Windows PE 版本信息

`windows.verinfo` 对应固定基线的 `windows.verinfo.VerInfo`。它列出已加载内核模块和进程加载顺序 DLL 的 PE 产品版本。没有调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.verinfo --image memory.dmp --case ./case-001 --offline --format jsonl
bin/gomem analyze windows.verinfo --image memory.dmp --case ./case-001 --offline --format jsonl -p extensive=true
```

内核模块来自 `PsLoadedModuleList`。每个模块只在会话的第一个进程地址空间里读取，不使用内核层。`is_valid` 只看基址的 1 个字节。读取 PE 之前，64 位指针按 `0x0000ffffffffffff` 截断，32 位按 `0xffffffff`。规范的内核地址截断后不再规范，版本读不到，四列都是不可用。展示用的 `Base` 仍是原来的指针。PID 和进程名对内核模块不适用。

进程 DLL 先走原生 PEB 的加载顺序链表，再走 WoW64。`DllBase` 读不到就跳过这一条，不走物理回退。前向遍历和固定基线的 `LIST_ENTRY.to_list` 一样：下一节点的整个链表项不可读、`Flink` 为 0，或者对象第一个字节不可读，就结束当前链表，任务仍然成功。哨兵的 `Flink` 必须能读。不检查 `Blink`。进程名在第一条 DLL 之前读不到时任务失败。

产品版本取资源目录里第一份能解析的 `VS_VERSION_INFO`，使用 `VS_FIXEDFILEINFO[0]`。`Major` 和 `Minor` 是 `ProductVersionMS` 的高低 16 位，`Product` 和 `Build` 是 `ProductVersionLS` 的高低 16 位。这和 pefile 2024.8.26 一致。对照列里的缺失值不带错误。`NameError` 和 `VersionError` 保留原因。

`extensive` 默认关闭，参考命令没有打开它。打开后，模块资源解析失败并且名称可读时，在物理层搜索 UTF-16BE 的 `OriginalFilename`、一个 NUL，再加 DLL 名。返回的是文件版本 `(FV1, FV2, FV3, FV4)`，不是产品版本。找不到标记时仍从窗口偏移 3 解析。`max-nodes` 默认 131072，`max-modules` 默认 1000000，都不是上游参数。摘要行的 `RecordType` 是 `summary`，差分时排除。

官方 Windows 10 19041 样本有 176 个内核模块和 5742 个进程 DLL，共 5918 行。176 个内核模块的版本都不可用。1715 个 DLL 有产品版本，4027 个没有。328 个名称不可用。5 条加载链表在缺页的下一节点停下。没有跳过 DLL 基址，用了 3 个会话层。PID、进程名、低 48 位基址、名称和四个版本字段与固定基线一致。`extensive=true` 还没有语料差分。真实 32 位镜像和时间线还没有验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-verinfo.jsonl \
  --reference reference-windows-verinfo.json \
  --mapping docs/diff/windows.verinfo.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestProductVersion|TestExtensiveVersion|TestForwardList|TestVerInfoPluginRegistered|TestOfficialWindowsVerInfo' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.verinfo.VerInfo` 生成。当前保持 partial、accepted=false。
