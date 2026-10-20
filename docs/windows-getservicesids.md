# Windows 服务 SID

`windows.getservicesids` 对应固定基线的 `windows.getservicesids.GetServiceSIDs`。它为 SYSTEM hive 里不在锁定服务表中的服务计算 SID，不调用 Python、Volatility 或目标系统代码。

```sh
bin/gomem analyze windows.getservicesids --image memory.dmp --case ./case-001 --offline --format jsonl
```

只打开名称包含 `machine\system` 的 hive，比较不区分大小写。服务键先找 `CurrentControlSet\Services`，打不开再找 `ControlSet001\Services`。hive 打不开，或两个键都不存在，就跳过这个 hive。

锁定服务表有 461 个名称。子键名和表里的值完全相同就不输出。其余名称，包括空名称，都计算 SID。算法先做 Unicode 大写，再在每个字符后面加 U+0000，然后按 UTF-8 做 SHA1。取摘要前 20 字节，按小端拆成 5 个 DWORD，拼成 `S-1-5-80-...`。ASCII 名称和 UTF-16LE 的结果相同。读不到的子键跳过。摘要行不是服务。真实 32 位镜像和时间线还没有验收。

官方 Windows 10 19041 样本有 1 个 SYSTEM hive、189 行计算 SID，另有 161 个已知服务名被跳过。SID 和服务名与固定基线一致。

合成样本覆盖 `MyCustomSvc`、小写 `bits`、`É`、空名称，以及样本里的 `AarSvc_73fe2`。`BITS` 留在锁定表里，不计算。

```sh
python3 tools/diff_results.py \
  --native native-windows-getservicesids.jsonl \
  --reference reference-windows-getservicesids.json \
  --mapping docs/diff/windows.getservicesids.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/plugins ./internal/engine -run 'TestServiceSIDHashAndKnownNames|TestOfficialWindowsGetServiceSIDs' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.getservicesids.GetServiceSIDs` 生成。当前保持 partial、accepted=false。
