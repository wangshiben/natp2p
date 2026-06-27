# 路线 B 实现方案：修复桥接层多 leg 处理，恢复 dual/KCP 吞吐

**方案时间**: 2026-06-27
**目标**: 恢复 Dial/Register 的 dual(KCP+TCP)，同时根治跨中继桥接的多 leg 竞态
**前置分析**: 见 `DUAL_LEG_RACE_ANALYSIS.md`

---

## 1. 关键认知（比初版分析更准确）

通读 `DualStream.go` 后，修正一处重要理解：

### 1.1 DualStream 不是"两条 leg 同时发同一份数据"

- **发送**：`sendOrder()` 默认 **KCP 为 primary、TCP 为 backup**。同一条逻辑消息**只在 primary 上发**，
  primary 写失败才 `handleLegFailure` 切到 backup（实时 failover）。**正常态只有一条 leg 在发。**
- **接收**：两条 leg 都跑 `startPump`，都可能收数据（兜底）。

### 1.2 这意味着竞态的真正形态

不是"KCP/TCP 稳定并发各发一半"，而是：
- **建连窗口**：dual 拨号时 KCP、TCP 先后到达 relay，两条 leg 都进 `findAndBridge`
- **failover 时刻**：primary KCP 失败切 TCP，`active` 在切换瞬间指向不确定
- **多 natNode 叠加**（用户指出的高发场景）：多个源节点各自 dual 拨号，
  relay 上多个 `CrossRelayBridge` 实例 + 每个内部双 leg，`active` 字段在并发下更易错乱

### 1.3 设计伏笔已存在

`StreamBridge.go:222` 注释明确写：
> "relay 桥接用它(LegTransport)来**确定性地只桥接源节点 send-preferred 的那条 leg**"

→ **路线 B 的正确形态早已设计好，只是单 leg 化时没接全**。

---

## 2. 路线 B 核心设计：只桥接 send-preferred(KCP) leg

### 2.1 原则

跨中继桥接对对端 relay 表现为**单条** peerConn。源端 dual 的两条 leg 中：
- **只把 send-preferred 的那条(默认 KCP)接入桥接数据面**
- **另一条(TCP backup)不参与桥接**：拨号到达 relay 后，若已有同 connID 桥接，直接关闭该 leg（现状已如此）
- 这样 `active` 永远只有一条 leg → 故障 A(回程投错 leg)根除
- KCP 作为数据面 → 恢复跨境高吞吐

### 2.2 与现状的差异

| 环节 | 现状(单 leg) | 路线 B |
|------|-------------|--------|
| Dial | `TryConnectTCPOnlyStream`(只拨 TCP) | `TryConnectTCPStream`(dual，KCP+TCP) |
| Register | `TryRegisterRelayStreamTCP` | `TryRegisterRelayStream`(dual) |
| 桥接接入的 leg | TCP（唯一） | **KCP**(send-preferred)，TCP 到达即关闭 |
| 数据面传输 | TCP(停等慢) | **KCP(ARQ+拥塞窗口，快)** |

### 2.3 为什么不是"两条 leg 都桥接 + 修 active"

理论上可以让桥接维护"每条 leg 独立的回程路由"，但：
- 跨中继对端是单 peerConn，**无法区分回程数据该给哪条 leg**（peerConn 不带 leg 标识）
- 要区分就得改 E2E 帧格式带 leg 标识 → 改动面过大、风险高
- **而 DualStream 正常态本就只用一条 leg 发** → 只桥接一条 leg 不损失正常吞吐
- 结论：**只桥接 send-preferred leg 是最小且正确的修复**

---

## 3. 具体改动点

### 改动 1：恢复 dual 拨号/注册
`p2pnode/impl/natnode/transport_impl.go`
```go
// Dial: TryConnectTCPOnlyStream → TryConnectTCPStream
// Register: TryRegisterRelayStreamTCP → TryRegisterRelayStream
```

### 改动 2：桥接只接入 send-preferred leg（关键）
`p2pnode/impl/relaynode/relay_node.go` 的 `findAndBridge`：
- 当前逻辑：第一条到达的 leg 建桥，后到的同 connID leg 直接 `Close`（442 行）
- **问题**：第一条到达的不一定是 KCP（KCP/TCP 到达顺序不定）。若 TCP 先到，会用 TCP 建桥，KCP 被关 → 又退回慢路径
- **修复**：用 `LegTransport(stream)` 判断，**优先用 KCP leg 建桥**：
  - KCP 先到：直接建桥
  - TCP 先到：暂存/短暂等待 KCP；若超时 KCP 未到则用 TCP 兜底（保证可用性）

### 改动 3：EOF 不误杀（故障 B）
`networkFrameWork/StreamBridge.go` `pumpPeerToLocal`/`pumpLocalToPeer`：
- 单 leg 桥接下，leg EOF 即连接结束，cancel 是合理的
- 但需确认：KCP 的正常 idle 不会被误判 EOF（KCP 有保活）

---

## 4. 风险与验证

### 4.1 风险点
1. **KCP/TCP 到达顺序**：findAndBridge 需正确"等到 KCP"，否则又用 TCP
2. **KCP 跨中继裸字节转发**：relay 退化为哑管道，KCP 的 UDP 包能否经 TCP-based peerConn 透传？
   —— **需重点验证**：peerConn 是 TCP，而 KCP leg 是 UDP，桥接处字节语义是否一致
3. **多 natNode 并发**：多个 bridge 实例的隔离性

### 4.2 验证计划（待用户确认复现拓扑）
1. 恢复 dual + 改桥接只接 KCP
2. 复现测试：双 relay + **多个 natNode 并发** + 大流量双向（用户指出的高发场景）
3. 抓数据：
   - 竞态是否消除（数据完整性、无错投/误杀）
   - dual/KCP 跨境带宽 vs 单 leg TCP 基线（预期大幅提升）

---

## 5. 待确认问题（需用户拍板）

1. **风险 4.1.2 是核心未知**：KCP leg 经裸字节 peerConn(TCP) 跨中继转发，
   UDP 语义能否正确透传？还是说 KCP leg 在跨中继时本就走不通，
   当初改单 leg 正是因为"KCP 跨中继转发不了"而非仅竞态？
   —— **这点我需要先验证，可能影响整个路线 B 可行性**

2. 复现测试拓扑：是否就是"双 relay + 多 natNode 并发 + 大流量"？

---

**下一步**：先验证 §5.1（KCP 能否跨中继桥接），这是路线 B 的可行性前提。
若 KCP 跨中继走不通，路线 B 需调整为"同 relay 用 dual/KCP，跨中继场景另想办法"。
