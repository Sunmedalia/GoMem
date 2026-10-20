# Windows SAM 哈希

`windows.hashdump` 对应固定基线的 `windows.registry.hashdump.Hashdump`。它从活动 hive 链表中取名称最后一段为 `SYSTEM` 和 `SAM` 的 hive，用 `ControlSet001\Control\Lsa` 下 `JD`、`Skew1`、`GBG`、`Data` 的键类数据还原 boot key，再解密 SAM 里的 LM/NT 哈希。没有调用 Python、Volatility 或目标系统代码。废弃入口 `windows.hashdump.Hashdump` 只是上游别名，不另建命令。

```sh
bin/gomem analyze windows.hashdump --image memory.dmp --case ./case-001 --offline --format jsonl
```

boot key 只读这四个键的 class cell。类数据按 UTF-16LE 拼成十六进制，再按 `8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7` 置换。class 读取停在单元格内部，短于声明长度就是错误，不会把后面的 bin 字节当成类数据。`SAM\Domains\Account` 的 `F` 值：修订 2 用 MD5 和 RC4，修订 3 用 AES-CBC，只保留前 16 字节。用户键 `V`：修订 1 用 MD5 和 RC4，修订 2 用 AES。NT 盐在 `nt_offset+8`，不是 `+4`。基线会忽略的修订或长度换成标准空哈希，LM 为 `aad3b435b51404eeaad3b435b51404ee`，NT 为 `31d6cfe0d16ae931b73c59d7e0c089c0`。找不到 hive、boot key 或用户记录时任务失败，并留下诊断；不会把空表当成成功。

合成样本用固定基线同一套算法生成密文。AES 修订的用户 `Ada`、RID 500，NT 为 `8846f7eaee8fb117ad06bdd830b7586c`，LM 为空哈希；盐放在 `+8`，`+4` 处是无关字节。RC4 的 `F` 修订 2 和用户哈希修订 1 也与同一组向量一致。缺 class cell 会点名 `JD` 并失败。

官方 Windows 10 19041 样本的 `JD` class 页不在内存里。内核和 Registry 进程读到的都是 nonpresent PTE。固定基线因此警告 hbootkey 无效并输出 0 行，任务仍算成功。本地结果是 0 条哈希、1 条诊断，任务失败。选定字段对照是 0 对 0，没有账户名或哈希可核对。这不是账户级验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-hashdump.jsonl \
  --reference reference-windows-hashdump.json \
  --mapping docs/diff/windows.hashdump.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsHashdump|TestOfficialWindowsHashdump' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.hashdump.Hashdump` 生成。当前保持 partial、accepted=false。32 位、其他真实修订、cachedump 和 LSA secret 都还没有做。
