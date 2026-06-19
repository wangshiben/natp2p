# 混合路线端到端验证报告（轻流复用 / 重流独连 + ForwardHook 统计）

> 日期：2026/06/19　拓扑脱敏：relay=10.10.0.1，server(callee)=10.10.0.2，重流 client=10.10.0.3，本机(轻流 client)=10.10.0.4
> 同目录原始日志：`relay.log` / `callee.log` / `server3_heavyclient.log` / `local_lightclient.log`（IP 已脱敏）。

## 1. 验证目标

混合路线：多个 client 经一个 relay 汇聚到一个 server，**轻流复用一条 server↔relay 连接**，
**重流（大象流）运行时检测后迁到独立连接**；且**所有流（含重流）都被 relay 的 `ForwardHookFunc` 统计到**。

## 2. 实现（机制正确，全部已落地）

- **帧头 connectionId**（`network/Frame.go`，定长头 37→39B）+ 出向源头打戳（`TcpStream.go`，取 `message.Header.ConnectionId`）。
- **relay 按帧头 connectionId 路由**（`FrameRouteRegistry.go` `pumpRelayToClients`）。
- **callee 帧级复用器** `EndpointFrameMux`（`networkFrameWork/EndpointFrameMux.go`，新）：单连接按 connectionId demux
  到每条逻辑连接独立 TcpStream/TLS/handler；单 FIFO 写者 + 非阻塞 dispatch。
- **运行时大象检测 + 重连迁移**（`pacakgeTest/relayServer.go`）：共享流累计入站超阈值 → 注册独立 identity（独立
  relay StreamGroup，不碰 relay 数据面）→ 发迁移指令 → client 重连到独立连接。
- **ForwardHook**：relay 经 `starter.Cover().SetForwardHook` 装，按 group 注入，**轻流 group 与各重流独立 group 同口径累计**。

## 3. 验证中发现并修复的关键缺陷

1. **多路复用 MessageId 撞号（致命，已修）**：各 per-conn 流 frameIdGen 都从 1 起，复用到一条连接后在 relay 的
   `DualFrameRelayEndpoint.collect` 里按 `{leg, msgId}` 撞号 → 两条流的帧被并成同一 logicalID 互相串台。
   现象：**单流永远正常、两流并发第二条必卡死**。修复：`incomingIDs` 改按 `{leg, connId, msgId}` 区分（`frame_adapter.go`）。
2. **ackIDs 不能带 connId（回归，已修）**：ACK 帧携带的是「回 ACK 一方的 t.connectionId」，与原数据帧业务 connId
   不一定相同（注册流 connId 为空）。曾误把 connId 也加进 `ackIDs` key → ACK 查不到 → 发送端永等确认 → 既有
   `TestRandomRelayClientInteraction` 挂死。修复：`ackIDs` 仍只按 `{leg, dstID}`（dstID 由 AllocMessageId 全 leg 唯一）。

## 4. 本地三进程（relay/callee/2 client 同机，均满发）

| 指标 | 结果 |
|---|---|
| 共享连接握手完成 | **2/2**（撞号修复后两流都能在一条连接上建连） |
| 判为大象 / 迁入完成 | **2 / 2**（两条满发流都被检测并迁到各自独立连接） |
| client1 独连吞吐 | 204.82 MB，`duplicate_rx=0 parse_failures=0` |
| client2 独连吞吐 | 200.99 MB，`duplicate_rx=0 parse_failures=0` |
| ForwardHook 覆盖 connId | **4**（2 条共享 connId + 2 条独立 connId） |

## 5. 三服务器真机（relay=10.10.0.1，callee=10.10.0.2，重流 client=10.10.0.3，本机=10.10.0.4），90s

| 指标 | 结果 |
|---|---|
| 共享连接握手完成 | **2/2**（两 client 都在一条 server↔relay 连接上建连，无握手期 HOL） |
| 重流 10.10.0.3 | 累计入站 1.12 MB **越阈值 → 判为大象 → 迁到独立 identity** → 独连压测 5.08/5.16 MB，`dup=0 parse=0` |
| 轻流 10.10.0.4 | 760 KB（< 1 MB 阈值）**未达大象 → 留在共享连接**，760/679 KB，`dup=0 parse=0` |
| ForwardHook | 触发 159 次，覆盖 **3 个 connId**（轻流共享 + 重流共享 + 重流独立），server 端累计转发 39.56 MB |

> 真机的吞吐不对称（10.10.0.3 链路快、本机家宽慢）天然演示了大象判别：**快流被判重→迁独连，慢流判轻→留共享**，
> 正是混合路线要的效果；两条流全程 0 重复 / 0 丢失。

## 6. ForwardHook 验证（按既定：只统计 server 端，不做 per-client 细分）

- relay 上一份 hook 配置自动注入到 server 的**每个** StreamGroup（共享 identity + 各重流独立 identity）。
- 日志 `[ForwardHook] +<bytes> (<frames>) connId=<...> | server端累计转发=<total>`：
  - 出现**多个不同 connId**（本地 4 个 / 真机 3 个）证明共享流与各独立重流 group **都被统计**；
  - `server端累计转发` 单调累加（本地 1.01 GB / 真机 39.56 MB），即 server 端全量。
- 本轮按约定**未触发 ErrorHook 停转发**那条路径（hook 恒返回 nil）。

## 7. 回归

- `go test ./network/ -race` ✅；`go test ./networkFrameWork/`（全量）✅ 185s（含曾被回归挂死、现已修复的
  `TestRandomRelayClientInteraction`）；`EndpointFrameMux` 单测 `-race` ✅。

## 8. 结论

混合路线 + ForwardHook 统计**端到端跑通且机制正确**：一条 server↔relay 连接多路复用轻流；大象流运行时检测后
迁到独立连接、独占带宽、消除单连接 HOL；**轻流与重流均被 ForwardHook 统计**（server 端全量、覆盖共享与各独立 group）；
全程 0 重复 / 0 丢失；无回归。

> 后续可选：① 更长时间真机 soak（本轮 90s/120s 已充分演示）；② 迁移阈值用现成吞吐自适应器口径自动整定；
> ③ ErrorHook 停转发路径在新架构下复刻验证（既有 hooktest Phase B 已验，本轮未重复）。
