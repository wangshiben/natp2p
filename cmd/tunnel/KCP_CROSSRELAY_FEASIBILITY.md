# KCP 跨中继可行性验证报告

**验证时间**: 2026-06-27
**目的**: 确认路线 B 的前提 —— KCP leg 经裸字节 peerConn 能否跨中继完整传输
**结论**: ✅ **KCP 跨中继可行**，但当前 `findAndBridge` 缺少 KCP 优先逻辑，跨境下有退回慢路径的风险

---

## 1. 验证方法

### 1.1 代码路径分析（先确认架构支持）

| 环节 | 发现 | 结论 |
|------|------|------|
| KCP stream 类型 | `kcpStreamContext` 用 `startTcpStream(...,conn)` 包装，conn 是 KCP 的 `net.Conn` | KCP/TCP 统一为 `TcpStream` 抽象 |
| 桥接取 leg | `SpliceLeg → TCPStreamOf(stream).RawConn()` 返回 `net.Conn` | KCP conn 实现 net.Conn，桥接可读写 |
| relay 监听 | `relayStarter.go` 同时 `net.Listen("tcp")` + `kcp.ListenWithOptions`(UDP) | relay 同时收 TCP 和 KCP |
| KCP 分发 | KCP listener accept 后同样走 `ListenTCPConnection` → `onMissingGroup` → `findAndBridge` | KCP/TCP 走完全相同的桥接路径 |

**架构层面：KCP 跨中继是支持的，桥接层对 KCP/TCP 是统一字节抽象。**

### 1.2 实测验证

新增测试 `cross_relay_dual_test.go: TestCrossRelay_DualLeg_LargeTransfer`：
- 临时把 `transport_impl.go` 改为 dual 拨号
- 拓扑：local1→relay1, local2→relay2, relay1↔relay2 控制链路
- local1 dual 拨号跨中继连 local2
- 双向传输 16 条 × 64KB = 1MB，校验 SHA256 完整性

---

## 2. 验证结果

### 2.1 KCP 跨中继传输成功 ✅

```
跨中继桥接建立: target=5ac44f32 via relay=...:19602 connId=bd5b543d leg=kcp
✅ dual 跨中继大流量传输成功: 16 条 × 64KB 双向, SHA256 全部一致
--- PASS: TestCrossRelay_DualLeg_LargeTransfer (2.20s)
```

- 桥接确实使用了 **KCP leg**（`leg=kcp`）
- 1MB 双向数据 SHA256 全部一致，**零损坏**
- KCP 的 UDP 字节流经裸字节 peerConn(TCP) 跨中继转发**完全正常**

### 2.2 暴露的问题：findAndBridge 无 KCP 优先逻辑 ⚠️

8 次重复测试，**8/8 都是 KCP 先到建桥**（本地环回下 KCP primary 几乎总先到）：
```
第1~8次: leg=kcp OK
统计: KCP建桥=8次, TCP建桥=0次, 失败=0次
```

**但这是本地环回的偶然**。检查 `findAndBridge`（relay_node.go:436-447）：
```go
// 同一 connID 可能有多条 leg 进入（dual 拨号）。只用第一条建桥, 其余关闭。
entry := n.localLegs[connID]
if entry != nil { stream.Close(); return nil }  // 后到的 leg 直接关闭
```
**完全是"第一条到达的 leg 建桥"，没有 KCP 优先判断**（`LegTransport` 只用于日志，line 480）。

**风险**：真实跨境网络下，KCP(UDP) 首包可能因丢包重传而晚于 TCP 到达。
此时会**用 TCP 建桥、关闭 KCP leg → 退回停等 TCP 慢路径**。本地测不出来，跨境会偶发。

### 2.3 失败时的连锁（故障 B 佐证）

日志中可见，建桥后另一条 leg 立即 EOF：
```
跨中继桥接建立: ... leg=kcp
TCP startPump NextMessage 失败: ... err=EOF
TCP leg 失败, 关闭并触发重连
```
当前因只桥接一条 leg、另一条被关，这个 EOF 是预期的（多余 leg 关闭）。
但若改为双 leg 桥接，EOF 误杀逻辑(故障 B)会被触发 —— 印证路线 B 改动 3 的必要性。

---

## 3. 结论与对路线 B 的影响

### 3.1 核心结论

✅ **KCP 跨中继可行** —— 当初改单 leg **不是因为 KCP 转发不了**，而是为规避双 leg 的 active 竞态（§竞态分析文档）。
这意味着**路线 B 完全可行**，KCP 能做跨中继数据面，恢复高吞吐。

### 3.2 路线 B 三个改动确认

| 改动 | 必要性 | 验证依据 |
|------|--------|---------|
| 改动1: transport_impl 恢复 dual | ✅ 必须 | dual 拨号才能产生 KCP leg |
| 改动2: findAndBridge 优先用 KCP 建桥 | ✅ **必须（本次新确认）** | 当前"第一条到达建桥"，跨境会偶发选 TCP |
| 改动3: EOF 不误杀 | ✅ 必须 | 日志见多余 leg EOF，双 leg 下会误杀 |

### 3.3 改动 2 的具体设计（细化）

`findAndBridge` 需保证用 KCP leg 建桥：
- **方案**：第一条 leg 到达时，若是 TCP，**短暂等待**（如 200~500ms）KCP leg；
  KCP 到则用 KCP 建桥、TCP 关闭；超时 KCP 未到才用 TCP 兜底（保证可用性）
- **依据**：`LegTransport(stream)` 已能返回 "kcp"/"tcp"，判断现成
- **权衡**：等待窗口增加首包延迟，但只影响建连一次，数据面用 KCP 的吞吐收益远大于此

---

## 4. 下一步

路线 B 可行性已确认，进入实现：
1. 改动 1：transport_impl 恢复 dual
2. 改动 2：findAndBridge 加 KCP 优先建桥逻辑
3. 改动 3：StreamBridge EOF 不误杀（若保留单 leg 桥接则无需，KCP 优先后仍是单 leg）
4. 回归测试：`TestCrossRelay_DualLeg_LargeTransfer` + 原有 `TestRelayNode_CrossRelayBridge`
5. 抓跨境实测带宽对比

**注**：本次验证用的测试文件 `cross_relay_dual_test.go` 保留，作为路线 B 的回归测试。
当前主线 `transport_impl.go` 已恢复单 leg（验证改动未污染主线）。
