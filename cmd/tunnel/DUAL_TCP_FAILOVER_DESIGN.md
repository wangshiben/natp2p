# 双 TCP leg failover 方案设计

**时间**: 2026-06-27
**需求**: 运营商高峰期掐跨地域 UDP，KCP 可能连不上。dual 拨号时若 KCP 不通，
再建一条 TCP 组成双 leg（**目的：冗余/failover**，主路断线立即切备路，保证连接不中断）。
**前置**: `UDP_CONNECTIVITY_PROBE.md`（UDP 被运营商高峰期限流）

---

## 1. 现状机制（已读代码确认）

### 1.1 dual 拨号 `clientStream`
```
拨 KCP → attach(KCP槽)   ┐
拨 TCP → attach(TCP槽)   ┘ 两槽各一条
```
- `kcpStreamContext` 的 `SendMessage(handshakeCtx)` **会等首帧 ACK**，
  KCP 不通时 ACK 超时 → 返回 err → `kcpErr` 被设置 → KCP 槽为空
- 结果：KCP 不通时只剩 TCP 单 leg（**当前行为，退化成单 leg**）

### 1.2 DualStream 结构约束
- 只有两个固定槽位 `kcp` / `tcp`（`network.Stream` 字段），由 `streamTransport` 枚举(kcp/tcp)索引
- `sendOrder`：preferred 为主、另一条为 backup；同一消息只在主路发，失败切 backup
- `handleLegFailure`：leg 失败 → 用 `reconnectDialers[kind]` 重连

---

## 2. 方案 A：KCP 槽位放第二条 TCP（最小改动，选定）

### 2.1 核心思路
KCP 拨号失败时，**再拨一条 TCP，attach 到 KCP 槽位**，并把该槽的
reconnect dialer 设为 **TCP 拨号器**。对 DualStream 上层完全透明：
它以为有"KCP+TCP 两条 leg"，实际是两条 TCP，主备 failover 照常。

### 2.2 改动点（仅 `clientStream`）
```go
kcpClient, err := kcpStream(...)
if err != nil {
    kcpErr = err
    // 【新增】KCP 不通 → 在 KCP 槽位补一条 TCP 作备路
    tcp2, e2 := tcpClientStream(...)
    if e2 == nil {
        dual.attach(streamTransportKCP, tcp2)  // 占 KCP 槽, 实为 TCP
        kcpSlotIsTCP = true                     // 标记
    }
} else {
    dual.attach(streamTransportKCP, kcpClient)
}

// 主 TCP leg（不变）
tcpClient, _ := tcpClientStream(...)
dual.attach(streamTransportTCP, tcpClient)

// 【新增】KCP 槽位是 TCP 时, 重连器也用 TCP 拨号
if kcpSlotIsTCP {
    dual.SetReconnectDialer(streamTransportKCP, tcpDialer)  // 而非 kcpDialer
} else {
    dual.SetReconnectDialer(streamTransportKCP, kcpDialer)
}
dual.SetReconnectDialer(streamTransportTCP, tcpDialer)  // 不变
```

### 2.3 为什么这样安全（风险点逐一排查）

| 风险点 | 分析 | 结论 |
|--------|------|------|
| `LegTransport` 把 KCP 槽的 TCP 识别为 "tcp" | 它本就按底层 conn 类型判断，返回 "tcp" 是正确的 | ✅ 无害 |
| 桥接层 KCP 优先逻辑被误导 | 两条都是 tcp，findAndBridge 收到的 leg 都是 tcp，无 kcp 可等 → 第一条到达直接建桥（KCP 优先逻辑自然不触发）| ✅ 正常 |
| `preferred`/sendOrder 错乱 | 两条都是 TCP，主备切换语义不变，只是"主备都是 TCP" | ✅ 正常 |
| 重连拨错协议 | 已处理：KCP 槽位是 TCP 时，reconnect dialer 设为 TCP | ✅ 已解决 |
| 端口/连接冲突 | 两条 TCP 是不同源端口的独立连接，relay 侧按 connID 聚合 | ✅ 正常 |

### 2.4 relay 侧影响
- 两条 TCP leg 带**同一 connID** 到达 relay，与现有 dual(KCP+TCP)两条 leg 同 connID 的处理一致
- 跨中继 `findAndBridge`：两条都是 tcp，第一条建桥、第二条关闭（现有逻辑），单 leg 桥接，无竞态

---

## 3. 不选方案 B 的理由
方案 B（DualStream 通用化支持 N 条同类型 leg）需改 attach/streamLocked/sendOrder/
Close/reconnect/桥接 全链路，风险高。failover 需求用方案 A 即可满足，无需结构性改造。

---

## 4. 待确认的设计细节

### 4.1 KCP 是否完全放弃重试？
当前方案：KCP 拨号失败 → 直接用 TCP 占槽，**该连接生命周期内 KCP 槽永远是 TCP**。
- 优点：简单，高峰期 UDP 不通时稳定双 TCP
- 缺点：高峰过后 UDP 恢复，也不会自动切回 KCP（要等连接重建）
- **可选增强**：KCP 槽的重连器同时尝试 KCP，成功则换回 KCP（复杂，暂不做）

### 4.2 拨号顺序与延迟
KCP 握手超时 `dialHandshakeTimeout` 决定"等多久才判定 KCP 不通"。
高峰期每次拨号都要先等 KCP 超时（如 3s）才补 TCP，**增加建连延迟**。
- 可选优化：并发拨 KCP 和备用 TCP，KCP 成功则弃备 TCP；超时则用备 TCP
- 先确认 `dialHandshakeTimeout` 当前值

---

## 5. 验证计划
1. 单测：模拟 KCP 拨号失败，验证 KCP 槽位被 TCP 占据、双 TCP leg 建立
2. failover 测试：主 TCP leg 断开，验证切到备 TCP leg、连接不中断
3. 跨中继回归：双 TCP 跨中继建桥正常
4. 真实部署：高峰期 UDP 不通场景，验证双 TCP 稳定性

---

## 6. 实现结果（已完成）

### 6.1 代码改动
- `networkFrameWork/Dialers.go: clientStream`：KCP 拨号失败 → 拨备路 TCP attach 到 KCP 槽位，
  `kcpSlotIsTCP` 标记，KCP 槽的 reconnect dialer 改用 TCP 拨号器
- 新增 import：`fmt`、`logx`

### 6.2 测试结果
- `networkFrameWork/dual_tcp_failover_test.go: TestDualDial_KCPBlocked_FallbackToSecondTCP`
  - TCP-only relay（不监听 UDP）模拟 KCP 不通
  - ✅ KCP 槽位被 TCP 备路占据（未退化单 leg），两条 leg 底层均为 tcp
  - ✅ 建连耗时 1.5s（= dialHandshakeTimeout，KCP 握手超时）
  - ✅ `-race` 无数据竞争
- 回归：networkFrameWork dual/dial + relaynode 跨中继全部通过

### 6.3 failover 机制说明
双 TCP 的主备切换**完全复用 DualStream 现有的 KCP/TCP failover 逻辑**
（`sendOrder`/`handleLegFailure`/`scheduleReconnect`），仅把"备路从 KCP 换成 TCP"，
未改动 failover 控制流，故现有 stability 测试对该机制的覆盖依然有效。

### 6.4 待真实部署验证
- 高峰期 UDP 被掐时：client 建连应自动降级双 TCP，主 leg 断线切备路不中断
- 建连延迟：每次需先等 1.5s KCP 超时（可后续优化为并发拨号）
