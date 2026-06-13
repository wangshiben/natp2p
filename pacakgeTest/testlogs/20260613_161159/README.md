# 中继传输测试记录 — 2026-06-13 16:11

## 拓扑
- 中继服务器(公网): 38.0.0.1:9000  `mode=server`  (2H2G Debian12)
- 被叫端(本机): `mode=relayServer -size 4096`  nodeId=b7cccb0a...
- 主叫端(本机): `mode=client -size 4096`  → 经 relay 连接被叫端
- 本机出口 IP(relay 视角): 111.0.0.1

## 原始文件
- `relay_server.log`        中继服务器原始日志(含连接/转发/leg 状态)
- `callee_relayServer.log`  被叫端原始日志
- `caller_client.log`       主叫端原始日志

## 结果摘要
| 指标 | 主叫 | 被叫 |
|------|------|------|
| 收包 | 553 | 551 |
| duplicate_rx | 0 | 0 |
| parse_failures | 0 | 0 |
| missing_est(每流) | 0 | 0 |

零丢包、零重复、零解析失败。

## KCP/TCP 断连/重连排查结论
重点关注项: 连接过程中是否出现 KCP/TCP 断连后无法重连。

时间线(以 relay 日志为准):
- 16:16:16  被叫端 TCP 连入, 建 StreamGroup
- 16:16:37  主叫端连入, StreamOn 转发建立(forward=true)
- 16:16:37 → 16:18:18  约 100 秒稳定传输, **三方均无任何 leg 失败 / 重连 / backup 切换事件**
- 16:18:18  测试时间到, 程序主动 Close, 此时出现 TCP EOF

**结论: 本次测试全程未发生异常断连, 因此也没有触发重连流程。**
唯一的 TCP EOF 出现在测试结束瞬间, relay 日志明确标注 `ctxErr=context canceled`,
属于程序主动关闭(到点收尾), 非网络异常断连。

主叫端/被叫端日志中 `[DualStream]` 异常事件数均为 0。

## 说明: 本次为验证补充了重连结果日志
为能直接观察"断连后能否重连成功", 在 `networkFrameWork/DualStream.go` 的
`runReconnect` 中补充了重连结果日志(拨号失败 / attach 成功第N次 / 达上限彻底失败永久禁用)。
本次测试网络稳定未触发重连, 这些日志未被打印; 后续若出现真实断连, 可据此判断重连是否成功。
