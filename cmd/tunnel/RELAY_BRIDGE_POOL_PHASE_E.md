# Relay↔Relay 连接池 — 阶段E 验证报告

> 配套设计文档：[RELAY_BRIDGE_POOL_DESIGN.md](./RELAY_BRIDGE_POOL_DESIGN.md)
> 阶段 A/B/C/D 已实现并提交，本文记录验证结论与真实部署清单。

---

## 1. 已完成的本地验证（可复现）

测试位于 `p2pnode/impl/relaynode/bridge_pool_test.go`，全部通过（含 `-race`）。

| 测试 | 验证点 | 结果 |
|------|--------|------|
| `TestBridgePool_Reuse` | 8 个并发 connID 复用同 1 条 physConn | ✅ 物理连接数=1 |
| `TestBridgePool_LeastLoaded` | least-loaded 分配基准（3 stream→ActiveStreams=3） | ✅ |
| `TestBridgePool_Reconnect` | physConn 断线后退避重连 | ✅ |
| `TestBridgePool_EndToEnd` | 池开 stream → 64KB echo SHA 一致 | ✅ |
| `TestBridgePool_ExpandOnConcurrency` | 56 并发达高水位→扩容至 2 条，不超 maxConns | ✅ |
| `TestBridgePool_NoExpandWhenIdle` | 低负载(3)不误扩容 | ✅ |
| `TestBridgePool_BurstDetector` | 滑动窗口内≥3 次→高峰态，窗口外退出 | ✅ |
| `TestBridgePool_BurstBatchTrim` | 高峰批量受 maxConns 封顶裁剪 | ✅ |
| `TestBridgePool_ReapIdle` | 4 条空闲→回收至保底 1 条 | ✅ |
| `TestBridgePool_ReapKeepsActive` | 有活跃会话的连接不被回收 | ✅ |
| `TestBridgePool_ChurnNoLeak` | 200 次开/关会话：物理连接峰值=1、goroutine 增长=0、SHA 全程一致 | ✅ |

**`ChurnNoLeak` 近似 Phase E 的核心担保**：大量短会话来去时，
- 物理连接数**不随会话数线性增长**（200 会话仍只 1 条物理连接）；
- **无 goroutine 泄漏**（增长 0）；
- 每次会话**端到端字节完整**（SHA256 一致）。

跨中继集成测试 `TestCrossRelay_DualLeg_LargeTransfer` 亦通过（池接入后端到端语义不变）。

---

## 2. 真实部署验证清单（需用户在跨服务器环境执行）

本地无法复现的部分：跨境真实链路、KCP 被阻断时的双 TCP 降级、长时窗口的扩缩容观察。
沿用既有拓扑（见 `SOLUTION_B_DEPLOY_VERIFY.md`）：

```
本地(大陆) → relay1(香港) → 跨中继桥接(连接池) → relay2(美国) → tunserver → http
```

### 2.1 功能正确性
- [ ] 跨中继隧道打通，HTTP 大文件(≥20MB)经隧道 SHA 一致。
- [ ] relay1 日志出现 `[bridge-pool] 新建连接池` 与 `物理连接已建立`。
- [ ] relay2 日志出现 `接受 bridge-mux 物理连接`（每对端 relay 仅少数几条，而非每会话一条）。

### 2.2 连接复用（池的核心收益）
- [ ] 并发发起多个跨中继会话，确认 relay1→relay2 的**物理 TCP 连接数远少于会话数**
      （`ss -tn | grep <relay2-ip>:<port>` 计数）。
- [ ] 对比改造前（每会话一条 TCP）：物理连接数应显著下降。

### 2.3 扩容 / 高峰
- [ ] 压测并发会话数 > `streamHighWatermark`(51)，确认物理连接按需扩容（日志 `扩容: ...新增 N 条`）。
- [ ] 突发负载下确认高峰态批量扩（日志 `burst=true`），且不超 `poolMaxConns`(8)。

### 2.4 收缩 / 无泄漏
- [ ] 负载回落后等待 `poolIdleTimeout`(60s)+`poolReapInterval`(15s)，
      确认空闲连接被回收（日志 `收缩: 回收 N 条`），保留 `minWarmConns`(1) 条。
- [ ] 长跑（≥30min 间歇负载）后 `ss` 连接数稳定、relay 进程 RSS/goroutine 不持续增长。

### 2.5 KCP 阻断降级（与池正交，回归确认）
- [ ] 大陆→香港 KCP(UDP) 不通时，client→relay1 走双 TCP；
      池化的 relay1→relay2 桥接（本身 TCP）正常承载，端到端不受影响。

---

## 3. 桥接来源校验（Phase E 发现 → 已实施软校验）

**原现状**：`acceptBridgeMux`（`relay_node.go`）接受**任何**带 `RelayBridgeMuxRoute`
首帧的连接，对端身份仅凭其自报的 `Header.NodeId`，**未校验是否为可信对端 relay**。

**风险**：与改造前的裸字节桥接信任模型一致，但**池化放大了影响**——一条被接受的物理连接
此后可多路复用承载任意数量会话。恶意一方若能连到 relay 的桥接端口，即可借一条物理连接
开大量逻辑会话。

**已实施（软校验，零行为变更）**：
- 新增 `RelayNode.knownRelayPeer(nodeID)`：遍历 `peerLinks`/`inboundLinks` 比对已知对端
  relay 的 `peerID`。
- `acceptBridgeMux` 对未在已知集合的来源记 `WARN` 但**仍放行**，避免误杀「控制链路尚未
  就绪时到达的桥接」。
- 验证：跨中继集成测试 `TestCrossRelay_DualLeg_LargeTransfer` 中 WARN **未触发**，
  证明合法跨中继路径的入口 relay NodeId 总在 host relay 的已知集合内——
  即升级为硬拒绝对合法路径是安全的。

**待用户决策的进一步收敛**：
1. 将软校验升级为**硬拒绝**（未知来源 `return error` 直接关闭连接）。
   已验证合法路径不受影响，只需把 `acceptBridgeMux` 的 WARN 分支改为返回错误。
2. 或对桥接握手帧增加基于 relay 身份私钥的签名校验（与控制链路一致的鉴权）。
3. 配合每对端 `poolMaxConns` 封顶（已有）限制单来源的物理连接占用。

> 硬拒绝触及信任边界，可能影响特殊拓扑（如尚未建控制链路即桥接），故保留为软校验默认，
> 升级开关留给用户。

---

## 4. 结论

- 连接池（阶段 A–D）**功能完整、本地验证充分**：复用、扩容（并发+发送压力）、
  高峰批量预扩、闲置收缩+保底，均有针对性测试覆盖且 `-race` 通过。
- **无连接/ goroutine 泄漏**（churn 测试担保），端到端语义不变（SHA 一致 + 跨中继集成测试通过）。
- 桥接来源软校验（§3）已实施且验证合法路径不触发 WARN；硬拒绝升级开关留给用户。
- 真实跨境链路验证（§2）需在用户的多服务器环境推进。
