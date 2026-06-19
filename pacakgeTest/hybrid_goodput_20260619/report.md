# ForwardHook 改为「净荷口径」验证报告（两轮真机）

> 日期：2026/06/19　拓扑脱敏：relay=10.10.0.1（server1），callee/server=10.10.0.2（server2），
> 重流 client=10.10.0.3（server3），本机轻流 client=10.10.0.4。
> 同目录 `runA/` `runB/` 为两轮完整原始日志（IP 已脱敏 RFC1918）。

## 0. 背景：为什么改

此前 `ForwardHookFunc` 统计的是 **带宽（throughput）**——relay 实际搬运的全部线上字节：
`FrameHeaderLength + len(Payload)`，且 **双向、含 ACK 帧、含重传帧**。
在丢包的 WAN 上它会显著高于应用层「成功送达的有效载荷」：
某轮 relay 记 ~39.56 MB 而应用层仅 ~11.7 MB（≈3.4×），用户据此判断「记录不对」。

经本地无重传对照确认其并非重复计数 bug（本地仅 ~1.08×，差额是帧头+ACK），
WAN 上的放大来自 **重传 + 双向 + 帧头 + ACK**。但用户期望 hook 贴近应用层净荷，故改口径。

## 1. 改动（`networkFrameWork/forward_hook.go` `onFrame`）

净荷口径（goodput）：
- **只累计 `FrameTypeData` 帧的 `len(Payload)`**；
- **不含帧头**（每帧 39B 头不计）；
- **跳过** `FrameTypeAck` / `FrameTypeRetransmit` / `FrameTypeFrameSizeChange`
  （ACK、重传、帧大小控制帧均不携带新业务净荷，重传是丢包重发的同一份数据）。

这样 relay 累计 ≈ 应用层 payload 总量。带宽口径仍可由 git 历史还原。
单测新增 `TestForwardHookCountsPayloadOnly`（验证仅数据帧计数、跳过 ACK/重传/控制帧、不含头），
其余既有 hook 单测随口径同步更新（阈值改按 payload）。

## 2. 拓扑与参数（两轮一致）

- relay（10.10.0.1，`mode=server`）：`-hookThresholdKB=512`（每 512KB 上报一次），ForwardHook 经
  `Cover().SetForwardHook` 自动注入到 server 的**每个** StreamGroup（共享 + 各重流独立 group）。
- callee（10.10.0.2，`mode=relayServer`）：`-size=14336 -duration=120 -floodDelay=3 -elephantMB=2`，
  共享 identity 跑 `EndpointFrameMux`，某共享流累计入站 >2MB 即判大象 → 注册独立 identity → 发迁移指令。
- 两 client（10.10.0.3 重流 / 10.10.0.4 轻流，`mode=client BNFS_FRAME_FOLLOWER=1`）：target 同一共享 nodeId，
  收到迁移指令则重连到独立 identity。
- 帧大小：MTU 1500 → 标准最优 1337 → 减 10% = **1204**（新逻辑，已去掉「验证最优值」硬编码）。

## 3. 两轮结果

两轮均：大象检测 → 迁移成功；ForwardHook 覆盖 **3 个 connId**（轻流共享 + 重流共享段 + 重流独连段）；
全程 **0 重复 / 0 解析失败**。

### Run A（`runA/`）

| 流 / 阶段 | connId | 上传 | 下载 |
|---|---|---|---|
| 轻流（10.10.0.4，共享，全程） | 679b9ebb | 911.88 KB | 911.88 KB |
| 重流共享段（10.10.0.3） | d356b74d | 2.06 MB | 2.13 MB |
| 重流独连段（迁移后） | 39c1bef1 | 3.02 MB | 3.09 MB |

- 应用层净荷（双向合计）= 1.78 + 4.19 + 6.11 ≈ **12.08 MB**
- relay ForwardHook 末条 = **12.51 MB**
- **比值 ≈ 1.04×**（迁移：`d356b74d` 累计入站 2.00 MB → 判大象 → 迁到独立 identity `e0806e06`）

### Run B（`runB/`）

| 流 / 阶段 | connId | 上传 | 下载 |
|---|---|---|---|
| 轻流（10.10.0.4，共享，全程） | 331df2f3 | 1.43 MB | 1.34 MB |
| 重流共享段（10.10.0.3） | e2f7483b | 2.07 MB | 2.23 MB |
| 重流独连段（迁移后） | cd52d189 | 455.94 KB | 498.68 KB |

- 应用层净荷（双向合计）= 2.77 + 4.30 + 0.93 ≈ **8.00 MB**
- relay ForwardHook 末条 = **8.51 MB**
- **比值 ≈ 1.06×**（迁移：`e2f7483b` 累计入站 2.07 MB → 判大象 → 迁到独立 identity `652e80b7`）

## 4. 结论

净荷口径下，relay ForwardHook 累计 ≈ **1.04–1.06× 应用层 payload 总量**（双向），
不再被重传/ACK/帧头放大（旧带宽口径在该 WAN 链路上是 1.5–3.4×）。
残差 ~4–6% 来自 **TLS 握手等 `FrameTypeData` 帧**（route 为空、应用层 TrafficMonitor 不统计，但仍是真实净荷转发）。
重流（含迁移后的独立 group）仍被 ForwardHook 完整统计——用户「重流必须被 ForwardHook 统计到」的约束保持成立。

> 旁注：另有一轮 90s 预热被 relay↔callee 腿 `connection reset by peer` 中途打断、重流未达阈值故未迁移，
> 但其 hook 6.00 MB vs 应用层 5.85 MB ≈ 1.03×，独立佐证了同一结论；正式结果以上面两轮干净测试为准。
> 本机单元测试套件中 `TestNewStreamGroup/TestNewTransportCover/TestNewTLSCrypto` 失败为环境因素
> （本机 9000 端口被 docker-proxy 占用），干净基线代码同样失败，非本次改动回归。
