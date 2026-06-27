# 路线 B 实现报告：恢复 dual/KCP + KCP 优先建桥

**实现时间**: 2026-06-27
**状态**: ✅ 已实现并通过回归测试
**前置**: `DUAL_LEG_RACE_ANALYSIS.md`(竞态分析) / `SOLUTION_B_DESIGN.md`(设计) / `KCP_CROSSRELAY_FEASIBILITY.md`(可行性验证)

---

## 1. 实现的改动

### 改动 1：恢复 dual 拨号/注册
`p2pnode/impl/natnode/transport_impl.go`
```go
// Register: TryRegisterRelayStreamTCP → TryRegisterRelayStream (dual)
// Dial:     TryConnectTCPOnlyStream  → TryConnectTCPStream     (dual KCP+TCP)
```

### 改动 2：findAndBridge 确定性优先用 KCP leg 建桥（核心）
`p2pnode/impl/relaynode/relay_node.go`

`localBridgeEntry` 增加状态：
```go
type localBridgeEntry struct {
    bridge   *networkFrameWork.CrossRelayBridge
    bridged  bool          // 是否已建桥
    kcpReady chan struct{} // KCP leg 到达信号
}
```

`findAndBridge` 新逻辑（按到达 leg 类型分流）：
- **KCP 先到** → 立即 `doBridge` 建桥，`close(kcpReady)` 通知等待方
- **TCP 先到** → 不立即建桥，等待 `kcpWaitWindow`(400ms)：
  - 窗口内 KCP 到达 → KCP 建桥，本 TCP leg 关闭
  - 窗口超时 KCP 未到 → TCP 兜底建桥（保证可用性）
- **已建桥后到的 leg** → 一律关闭

### 改动 3：EOF 不误杀 —— 实测不需要
路线 B 仍是**单 leg 桥接**（只桥接 KCP，TCP 在 relay 入口即关闭，不进桥接）。
桥接内部 `active` 永远只有一条 leg，EOF 即真正结束，**故障 B 不会触发**。
这正是"只桥接 send-preferred leg"方案的优点：用最小改动同时解决故障 A 和 B。

---

## 2. 为什么这样能根治竞态

| 竞态 | 原因 | 路线 B 如何解决 |
|------|------|----------------|
| 故障 A：回程投错 leg | 桥接 `active` 被两条 leg 并发覆盖 | 只桥接一条(KCP)leg，`active` 恒定 |
| 故障 B：单 leg EOF 误杀桥接 | 两条 leg 共享桥接，一条 EOF cancel 全部 | 桥接内只有一条 leg，EOF 即正常结束 |

**关键洞察**：DualStream 正常态本就只用一条 leg 发数据（KCP primary / TCP backup），
所以"只桥接 KCP"不损失正常吞吐，反而消除了双 leg 在桥接层的竞争。

---

## 3. 回归测试结果

### 3.1 新增测试 `cross_relay_dual_test.go`
`TestCrossRelay_DualLeg_LargeTransfer`：双 relay + dual 拨号 + 1MB 双向传输 + SHA256 校验

| 项 | 结果 |
|----|------|
| 桥接使用的 leg | **KCP**（`leg=kcp`） |
| 建连耗时 | **2.6ms**（未触发 400ms 等待窗口，KCP 优先生效） |
| 1MB 双向数据完整性 | ✅ SHA256 全部一致 |
| 重复 5 次 | 5/5 KCP 建桥，全 PASS |
| `-race` 检测 | ✅ 无数据竞争 |

### 3.2 回归
| 包 | 结果 |
|----|------|
| `p2pnode/impl/relaynode` 全包 | ✅ PASS (82s) |
| `p2pnode/impl/natnode` 全包 | ✅ PASS |
| 原有 `TestRelayNode_CrossRelayBridge` | ✅ PASS |

### 3.3 已知无关失败
`networkFrameWork/TestTcpStreamSendMaxRetransmits` 在 60s 超时。
**经 git stash 在干净主线验证：该测试在无本次改动时同样超时**，
是预先存在的、与路线 B 无关的 TCP 重传测试问题。

---

## 4. 待验证（需真实跨境环境）

本地环回下 KCP 几乎总先到（dual 拨号 KCP 先发 hello），无法触发"TCP 先到等 KCP"路径。
需在真实跨境链路验证：
1. **TCP 先到 → 等待窗口 → KCP 建桥** 路径的实际触发与效果
2. **跨境带宽提升**：dual/KCP 跨中继 vs 单 leg TCP 基线（预期从 0.013 MB/s 大幅提升）
3. **400ms 窗口是否合适**：跨境 KCP 首包延迟分布

建议下一步：部署到 38(香港)/104 等真实节点，跑端到端隧道带宽对比测试。

---

## 5. 改动文件清单

| 文件 | 改动 |
|------|------|
| `p2pnode/impl/natnode/transport_impl.go` | Dial/Register 恢复 dual |
| `p2pnode/impl/relaynode/relay_node.go` | findAndBridge KCP 优先建桥 + doBridge 抽取 + localBridgeEntry 状态 |
| `p2pnode/impl/relaynode/cross_relay_dual_test.go` | 新增 dual 大流量回归测试 |

**未改动**：`networkFrameWork/`（Dialers.go 测试钩子已还原）、`StreamBridge.go`（单 leg 桥接无需改）。
