# Windows LSA secret

`windows.lsadump` 对应固定基线的 `windows.registry.lsadump.Lsadump`。它从活动 hive 链表中取名称最后一段为 `SYSTEM` 和 `SECURITY` 的 hive，用与 `windows.hashdump` 相同的 boot key 解密 `Policy\Secrets` 下每个子键的 `CurrVal`。没有调用 Python、Volatility 或目标系统代码。废弃入口 `windows.lsadump.Lsadump` 只是上游别名，不另建命令。

```sh
bin/gomem analyze windows.lsadump --image memory.dmp --case ./case-001 --offline --format jsonl
```

Vista 及以后看符号表。`metadata.windows.pe` 同时有 major、minor、revision 时，major 大于等于 6 就是 Vista；否则符号或类型里有 `KdCopyDataBlock` 才走 Vista，没有则走更早的 DES。Vista 读 `Policy\PolEKList` 的第一个值。SHA-256 先吸收 boot key，再把偏移 28 到 60 的 32 字节吸收 1000 次。从偏移 60 起，每 16 字节用新的全零 IV 解密，块与块不链接。LSA key 是解密结果的第 68 到 100 字节。更早的系统读 `Policy\PolSecretEncryptionKey`：MD5 吸收 boot key，再把偏移 60 到 76 的盐吸收 1000 次，RC4 解密偏移 12 到 60，保留其中第 16 到 32 字节。

Vista 的每条 secret 用同一套独立 AES 块，密钥换成 LSA key。更早的系统从密文偏移 `0xC` 起做 SystemFunction005：DES 密钥窗口每次前进 7 字节，剩下不足 7 字节时下一次下标变成这个余数，而不是回到 0。解密后前 4 字节是小端长度，载荷从第 8 字节开始；长度超出缓冲区时截断到已解密的字节。最后一块不足 16 字节的 AES 输入直接失败，基线在这里会抛出 TypeError。

找不到 hive、boot key、LSA key、`Policy\Secrets` 或某条 CurrVal 时任务失败，并留下诊断。没有 CurrVal 的 secret 会记成这一条的错误；基线会跳过它。空 secret 列表也是失败，不会把空表当成成功。

合成样本用固定基线同一组类方法生成密文。Vista 路径解出 `NL$KM` 和带填充的 `MachinePassword`；XP/2003 路径解出 `DefaultPassword-XYZ`。缺 class cell 会点名 `JD` 并失败。

官方 Windows 10 19041 样本的 `JD` class 页不在内存里，和 `windows.hashdump` 是同一处 nonpresent PTE。固定基线因此没有 boot key，输出 0 行，任务仍算成功。本地结果是 0 条 secret、1 条诊断，任务失败。选定字段对照是 0 对 0。这不是 secret 级验收。

```sh
python3 tools/diff_results.py \
  --native native-windows-lsadump.jsonl \
  --reference reference-windows-lsadump.json \
  --mapping docs/diff/windows.lsadump.json
GOMEM_CORPUS_DIR="$PWD/.cache/corpus" go test ./internal/engine -run 'TestWindowsCredentialDumpsMissingSecurity|TestOfficialWindowsLsadump' -count=1
```

参考结果由锁定入口 `tools/reference.py --plugin windows.registry.lsadump.Lsadump` 生成。当前保持 partial、accepted=false。32 位和真实的 Vista 之前镜像还没有做对照。
