# NATNode Dial 单leg vs 双leg —— 竞态机理分析与解决方案

**分析时间**: 2026-06-27
**触发问题**: 用户发现 `NATTransport.Dial` 被改成 TCP 单 leg，导致跨境隧道吞吐塌缩

---

## 1. 事实确认（git 溯源）

提交 **a6edc98**（`feat(relaynode): 实现 RelayNode 跨中继查找与桥接`，2026-06-13）把 Dial 改了：

```go
// 改之前（dual: KCP + TCP 双 leg）
func (t *NATTransport) Dial(...) {
    return networkFrameWork.TryConnectTCPStream(relayAddr, string(targetID), t.pubKeyHex)
}

// 改之后（TCP 单 leg）—— 当前状态
func (t *NATTransport) Dial(...) {
    return networkFrameWork.TryConnectTCPOnlyStream(relayAddr, string(targetID), t.pubKeyHex)
}
```

`Register` 同样从 `TryRegisterRelayStream`(dual) 改成 `TryRegisterRelayStreamTCP`(单 leg)。

---

## 2. 为什么慢（性能代价）

- **KCP** 走 UDP，自带 ARQ + 拥塞窗口，专为高丢包/高 RTT 链路的高吞吐设计
- 改成 **TCP 单 leg** 后，跨境链路退化为「单条 TCP + 上层 mux 停等」，吞吐被 RTT 锁死
- 实测：跨境隧道 0.013 MB/s（详见 BANDWIDTH_OPTIMIZATION.md）

---

## 3. 竞态机理（当初改单 leg 要规避的问题）

### 3.1 触发条件（三者同时成立）

1. client 用 **dual 拨号** → 产生 KCP + TCP **两条 leg**，共享**同一 connID**
2. client 与 server 落在**不同 relay** → 走 `CrossRelayBridge` 跨中继桥接
3. 有实际**双向数据**流动

### 3.2 缺陷位置：`networkFrameWork/StreamBridge.go` 的 `active` 字段

跨中继桥接的结构是「**多条 local leg ↔ 单条 peerConn**」：

```
client(dual)                relay1                      relay2        server
  KCP leg ──┐                                                          
  TCP leg ──┴──> [CrossRelayBridge] ──单条 peerConn──> relay2 ──────> server
```

桥接用**单个** `b.active` 字段记录"最近活跃的 leg"，回程(peer→local)写给它：

```go
// pumpLocalToPeer: 每条 leg 各跑一个，读到数据就抢着改 active
n, _ := localConn.Read(buf)
b.active = localConn          // ← KCP 和 TCP 两条 goroutine 互相覆盖

// pumpPeerToLocal: 回程取 active 决定写给谁
dst := b.active               // ← 可能是 KCP，也可能是 TCP，看上面谁最后写
dst.Write(buf[:n])
```

### 3.3 两个具体故障

**故障 A —— 回程投递到错误的 leg**
DualStream 的一条逻辑消息从 KCP leg 发出，但 `b.active` 可能已被 TCP leg 的活动覆盖，
回程响应被写到 TCP leg。client 的 DualStream 在它期待的 leg 上读不到 → **数据丢失/超时，时好时坏**。

**故障 B —— 一条 leg 的 EOF 误杀整个桥接**
```go
// pumpPeerToLocal / pumpLocalToPeer 里
if err != nil { b.cancel(); return }   // ← cancel 关掉整个 bridge
```
任意一条 leg 正常结束(EOF)就 `cancel()` 整个桥接，连累另一条还在用的 leg。

### 3.4 当初的「修复」= 回避

把 Dial 改单 leg → 只有一条 leg → `active` 不会被覆盖、不会被误杀 → 竞态消失。
**但根因（桥接层用单 active 字段处理多 leg）没解决，只是用「不再有多 leg」绕过了。**

---

## 4. 现状基线（已验证）

- 当前单 leg 跨中继单测 `TestRelayNode_CrossRelayBridge` **PASS**（2.11s）
- 日志确认：`跨中继桥接建立: ... leg=tcp`（单 leg）
- 但该测试只发 3 轮小 ping/pong，**不足以触发竞态**（竞态需 dual + 大流量）

---

## 5. 解决方案（两条路线对比）

### 路线 A：简单恢复 dual（不推荐单独使用）
- 改回 `TryConnectTCPStream` / `TryRegisterRelayStream`
- **风险**：§3 竞态原样重现（active 覆盖 + EOF 误杀都还在）

### 路线 B：修复桥接层多 leg 处理（推荐，根治）
核心思路：**桥接层不再用单个 `active` 字段，改为按 leg 独立维护回程路由**。

具体方向（待数据验证后细化）：
1. **回程路由按 connID+leg 区分**：peerConn 的回程数据应能区分属于哪条 leg，
   而不是盲投给"最近活跃"的那条。
   - 但注意：跨中继桥接对对端是「单条 TCP」，peerConn 本身不携带 leg 标识，
     这是难点 —— 可能需要 DualStream 层在 E2E 帧里带 leg 标识，或桥接只保留 send-preferred 单 leg。
2. **EOF 不误杀**：单条 leg EOF 只移除该 leg，仅当所有 leg 都关闭才 cancel 桥接。
3. **折中方案**：`LegTransport` 已存在（返回 "kcp"/"tcp"）。桥接可**确定性地只桥接 KCP leg**
   （send-preferred），TCP leg 仅作 failover 备份不参与数据面 —— 既得 KCP 吞吐，又避免双 leg 竞态。

### 路线 C：分场景（最实用）
- **单 relay 场景**（client/server 同 relay）：不走 CrossRelayBridge，无竞态 → **可直接用 dual**
- **跨中继场景**：用路线 B 修复
- 即：Dial 是否用 dual 可按"是否跨中继"动态决定（但拨号时未必预知，需进一步设计）

---

## 6. 下一步（按用户要求的流程）

1. ✅ **定位竞态出现场景**（本文档 §3）
2. ⏳ **写能复现竞态的测试**：恢复 dual + 改造 `TestRelayNode_CrossRelayBridge`
   加入大流量双向传输（如 1~5MB），让 KCP/TCP 双 leg 在 active 上产生竞争
3. ⏳ **抓实际数据**：复现竞态的失败现象（数据错乱/超时/桥接中断）+ dual 的带宽
4. ⏳ **基于数据定最终方案**（A/B/C 中选定 + 实现）

---

**当前结论**：用户判断正确 —— Dial 改单 leg 是吞吐塌缩的直接原因。但**不能简单改回 dual**，
因为桥接层 §3 的竞态会重现。正解是修复桥接层的多 leg 处理（路线 B/C），让 dual/KCP 在跨中继下也能稳定工作。
下一步先写复现测试抓数据。
