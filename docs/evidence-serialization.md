# 嵌套类型化证据的序列化

结构化证据可能包含嵌套的 `evidence.Value`：地址、声明长度、原始字节、空文本、false 布尔值和读取错误。这些值写入案件时是 Go 类型，读回后成为 JSON map。两种形态的字段顺序必须一致，否则未改动的证据也会无法通过行摘要验证。

`structure` 值在 JSON 序列化时先转换为规范的 JSON 对象，嵌套 map 按键排序；封存、SQLite 回读和报告导出使用同一表示。规范化与 Value 的 JSON 解码均使用 `json.Number`，普通 json.Unmarshal、SQLite 回读及带 UseNumber 的解码器都不会将结构中的整数转为 float64。地址及无损数字仍必须使用 Address/Number/Integer 类型的字符串表示；一般 JSON 消费方应对未类型化的数字使用 UseNumber。

顶层 bytes 的显式 `value:null` 在解码后保留为带类型的 nil 字节切片，重编码不会被 omitempty 丢掉。原本省略 value 的旧字节单元仍省略该字段，已有证据不被重写或重新封存。零字节捕获仍须结合 CapturedBytes、请求长度、读取状态与错误判断，null 本身不代表读取成功。

回归测试覆盖顶层及嵌套字节、null/省略/空 base64 三种形态、空字符串、false、读取错误、普通解码器下的 64 位无符号/有符号极值、数值指数和小数原文，以及多轮序列化前后 Verify 一致性。PEB 分诊的真实案件分页测试也会逐行核验读回的嵌套证据。已存储的证据不会被重写；旧开发构建中已产生摘要不一致的任务应保留原始记录，并用 `analyze --fresh` 生成可核验的新任务。
