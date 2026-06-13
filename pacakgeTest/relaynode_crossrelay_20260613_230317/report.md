# RelayNode 跨中继端到端验证报告

- 日期: 2026-06-13
- 时间戳目录: `20260613_230317`

## 目标

验证 `p2pnode/impl/relaynode` 的跨中继能力：本地节点1 经公网中继节点1 查找并连接到
注册在公网中继节点2 上的本地节点2，二者端到端进行 2-3 轮通信。

## 拓扑

```
本地节点1 (local1) ──register/connect──▶ 公网中继1 (relay1, 203.0.113.1:9000)
                                              ▲
                                              │ 控制链路 (FIND/FIND_RESP)
                                              ▼
本地节点2 (local2) ──register──▶ 公网中继2 (relay2, 198.51.100.1:9000) ──peer──▶ relay1
```

- relay1: 203.0.113.1:9000，NodeID `7395c719070515140475de6d03ecf7d9ed671e60924d596d6484293234508d4a`
- relay2: 198.51.100.1:9000，NodeID `3097a4cb56a0301ad1099bbc0c17fe022f907ff748a5fe1bf8f620a34df4be24`
  （relay2 启动时 `-peer 203.0.113.1:9000` 主动与 relay1 建立可重试控制链路）
- 两台公网服务器全程在 `/root/p2ptest` 下运行，root 用户、密钥登录。

## 验证流程（与需求一致）

1. relay1、relay2 启动，relay2 与 relay1 建立控制链路（relay1 日志 `控制链路已建立(被动)` + `relay邻居=1`）。
2. local2 注册到 relay2（relay2 日志 `托管NAT节点=1`），打印自身 NodeID，进入回显模式。
3. local1 注册到 relay1，请求连接 local2 的 NodeID：
   - relay1 本地未托管 local2 → `onMissingGroup` → 经控制链路向 relay2 发 FIND；
   - relay2 应答 `Hosts=true` + 自身地址；
   - relay1 裸字节级桥接：把 local1 的连接与「裸拨向 relay2、透传 local1 hello」的连接双向转发；
   - 端到端 TLS 握手在 local1↔local2 之间完成，relay 只搬运密文（relay1 日志 `跨中继桥接建立 ... leg=tcp`）。
4. local1 与 local2 进行 3 轮请求/响应通信。

## 结果：通过 ✓

独立 3 次运行（每次 local2 重新注册），每次 3/3 轮双向通信成功：

run1 (`local1_connect_run1.log`)：
```
已连接到 d2d61f782e916cb99793a0c6b9992a3469537d0ed7b0e29a9c8fb86edb32148e, 开始 3 轮通信
→ 第 0 轮 发送: hello-0      ← 第 0 轮 收到: echo:hello-0
→ 第 1 轮 发送: hello-1      ← 第 1 轮 收到: echo:hello-1
→ 第 2 轮 发送: hello-2      ← 第 2 轮 收到: echo:hello-2
通信完成: 成功 3/3 轮
```
local2 侧（`local2_listen_run1.log`）对应收到 hello-0/1/2 并回显 echo:*。
run2 / run3 同样 3/3 成功（见 `local1_connect_run2.log` / `local1_connect_run3.log`）。

## 原始日志清单

- `server1_relay1.log` — relay1（203.0.113.1）完整运行日志
- `server2_relay2.log` — relay2（198.51.100.1）完整运行日志
- `local1_connect_run{1,2,3}.log` — 本地节点1 三次连接 + 通信日志
- `local2_listen_run{1,2,3}.log` — 本地节点2 三次注册 + 回显日志

## 实现要点

- RelayNode（`p2pnode/impl/relaynode`）：接入 DHTable，**两张独立路由表** natNodes / relayNodes
  区分 Nat 节点与 Relay 节点；内嵌 relay 服务器；relay 间控制协议 HELLO/FIND/FIND_RESP；
  FIND 查不到目标返回错误。
- relay 间控制链路**可重试**：链路级指数退避重连 + 底层 DualStream leg 级重连。
- 跨中继数据面采用「裸字节级桥接」：relay 透明转发字节，不重写 MessageId / 不组包 / 不 ACK，
  local1↔local2 端到端可靠性自洽。
- 框架层调整（`networkFrameWork`）：`TransportCover` MissingGroupHandler / RegisterHook；
  `AcceptTcpStreamSync` 消除「模式切换前帧被组包」竞态；TCP 单 leg 注册避免双 leg failover 竞态；
  跨公网高延迟下调高 ACK 超时与重传上限（`initialAckTimeout` 600ms / `maxRetransmitAttempts` 6）。

## 备注

- 验证程序：`cmd/relaychat`（参考 `cmd/p2pchat`，flag 驱动 relay/listen/connect 模式）。
- 测试完成后将清理两台公网服务器 `/root/p2ptest` 下本次部署的文件（relaychat 二进制、start.sh、logs_* 目录）。
