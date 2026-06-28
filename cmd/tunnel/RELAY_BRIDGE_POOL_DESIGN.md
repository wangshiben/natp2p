# Relay↔Relay 多路复用连接池 — 设计方案

> 目标：把跨中继转发的"每会话新建裸 TCP"升级为"按对端 relay 维护的多路复用物理连接池"，
> 并定义扩容触发、扩容策略、高峰策略、收缩策略。

---

## 0. 决策摘要（已与你确认）

| 维度 | 决策 |
|------|------|
| 连接池形态 | **多路复用连接池**（一条物理连接用 stream-id 承载多路会话） |
| 扩容触发依据 | **并发 stream 数 + 发送压力（待发队列）** |
| 高峰策略 | **批量预扩**（检测到突发时成倍/批量加连接） |
| 收缩策略 | **闲置超时 + 保底**（空闲连接超时关闭，保留最少 N 条热连接） |

---

## 1. 现状与核心障碍（为什么必须先 mux 化）

跨 relay 转发当前是**裸字节单会话桥**（`networkFrameWork/StreamBridge.go`）：
- 每个会话（connID）`net.Dial("tcp4", addr)` 新建一条 TCP（`dialRawBridgeConn`，:188）。
- 拨通后**立即写一条 per-session hello 首帧**（含本次 connID + local1 公钥，:193-217）。
- 之后纯字节双向对拷（`pumpLocalToPeer`/`pumpPeerToLocal`），relay 完全透明、无帧边界。

**障碍**：一条 peerConn 与某次会话强绑定，复用它给新会话会让对端 relay 在旧字节流中间
收到新 hello → 协议错位。所以**裸字节连接天然不可池化**，必须引入"一条物理连接承载多路
会话"的复用层（multiplexing）。

项目已有可借鉴的 mux 实现：`cmd/tunnel/mux/`（session.go / stream.go / loop.go），
帧格式 `[1B type][4B streamID][payload]`，类型 OPEN/DATA/CLOSE。但它跑在
`p2pnode.Connection`（Message 语义）上，桥接用的是裸 `net.Conn`，需要一个适配/新实现。

---

## 2. 目标架构

```
                          relay-pair pool (key = hostAddr)
local1 ──leg(s)──► 入口relay ───────────────────────────────► 托管relay ──► local2
                      │   ┌──────────────────────────────┐       │
                      │   │ bridgePool[hostAddr]          │       │
                      │   │  ├─ physConn #1 (mux session) │       │
                      │   │  │   ├─ stream(connID-A)      │       │
                      │   │  │   ├─ stream(connID-B)      │       │
                      │   │  │   └─ ... 至多 maxStreams   │       │
                      │   │  ├─ physConn #2 (mux session) │       │
                      │   │  └─ ... 至多 maxConns         │       │
                      │   └──────────────────────────────┘       │
                      └─ 每个 connID 映射到一条 mux stream ───────┘
```

- **物理连接（physConn）**：一条 relay↔relay 的 TCP（仍可后续升级为 dual），承载一个 mux session。
- **逻辑会话（stream）**：每个跨中继 connID = 一条 mux stream，替代原来"一条独立 peerConn"。
- **池（pool）**：`map[hostAddr] -> *relayPeerPool`，每个 peerPool 管理到某对端 relay 的多条 physConn。

---

## 3. 复用协议设计（mux over bridge）

### 3.1 物理连接首帧（握手一次，连接级）
physConn 建立时只发**一次** relay-to-relay 握手帧（取代 per-session hello）：
```
RouteName = "/relay/bridge-mux"   (新增常量 RelayBridgeMuxRoute)
NodeId    = 本入口 relay 自身 ID
Payload   = 入口 relay 身份/版本信息
```
对端 relay 在 `onMissingGroup` 识别该 RouteName → 进入 mux-accept 模式，把这条物理连接
交给 mux server session，循环 `Accept()` 出逻辑 stream。

### 3.2 每会话 OPEN 帧（会话级）
入口 relay 为每个新 connID `OpenStream()`，OPEN 帧的 payload 携带**原 per-session hello 内容**：
```
OPEN.payload = encode(targetNodeId, connID, local1PubKey)
```
对端 relay `Accept()` 到 stream 后，解析 OPEN payload，拿到 (target, connID, pubKey)，
**在本地合成原来的 hello 首帧**，走它已有的 `StreamOn` 接入逻辑（即把 mux stream 当作
一条普通 client leg）。这样对端 relay 的下游（→ local2）逻辑零改动。

### 3.3 字节流
OPEN 之后，mux stream 的 DATA 帧 = local1↔local2 的端到端字节，relay 仍透明转发，
端到端 MessageId/ACK/分帧/去重不变（与现状一致）。

> 关键不变量：mux 层只多包一层 `[type][streamID]` 帧头，**不触碰** E2E 语义。

---

## 4. 连接池策略（核心）

每个 `relayPeerPool`（对应一个 hostAddr）维护：

```go
type relayPeerPool struct {
    hostAddr   string
    conns      []*physConn      // 当前物理连接
    // 指标
    // 每条 physConn 暴露: ActiveStreams() int, PendingBytes()/PendingFrames() int
}
```

### 4.1 扩容触发（并发数 + 发送压力）

对池内**每条** physConn 持续观察两个水位（取一个短周期采样，如 200ms）：

1. **并发水位**：`activeStreams >= streamHighWatermark`（默认 `maxStreamsPerConn * 0.8`，
   `maxStreamsPerConn` 默认 64）。
2. **发送压力水位**：mux session 的待发队列 `pendingFrames >= sendPressureThreshold`
   （默认 256 帧）或 `conn.Send` 出现阻塞（写超过 `sendBlockedMS`，默认 50ms 未返回）。

**扩容判定（针对整个 peerPool）**：当**所有现存 physConn 都达到上述任一高水位**且
`len(conns) < maxConns`（默认 8）→ 触发扩容（新开 physConn）。
（"所有连接都满"才扩容，避免少数热点连接误触发。）

```
扩容条件 = (∀ conn: conn.atHighWatermark()) && len(conns) < maxConns
```

新 connID 的 stream 分配：选 `activeStreams` 最少的 physConn（least-loaded）；
若都达上限且已 maxConns，则排队等待或复用最空的一条（软上限，保证可用性优先）。

### 4.2 高峰批量预扩

维护一个**高峰探测器**：滑动窗口（如 5s）内统计"扩容触发次数"或"水位持续超高时长"。

- 普通态：单次扩容只 +1 条 physConn。
- **高峰态**（窗口内扩容触发 ≥ `burstTriggerCount`，默认 3 次 / 或所有连接水位持续
  超高 ≥ `burstSustainMS`，默认 2s）：单次扩容改为**批量** +`burstBatchSize`（默认 +4，
  且不超过 maxConns 封顶）。
- 高峰态在水位回落（窗口内无触发）后自动退出，回到单条增长。

```
if 高峰探测命中:  add = min(burstBatchSize, maxConns-len(conns))
else:            add = min(1, maxConns-len(conns))
```

### 4.3 收缩策略（闲置超时 + 保底）

后台 reaper（周期 `reapInterval`，默认 15s）扫描每条 physConn：

- physConn `activeStreams == 0` 且**持续空闲** `idleTimeout`（默认 60s）→ 候选回收。
- **保底**：池内至少保留 `minWarmConns`（默认 1）条物理连接不回收（即便空闲），
  避免高峰间歇期频繁重建 + 重握手。
- 回收时优雅关闭：停止接新 stream → 等现有 stream 自然结束（已 0 活跃）→ 关闭 physConn →
  从 `conns` 移除。
- 封顶：`len(conns)` 永不超过 `maxConns`。

### 4.4 可调参数（集中常量，便于后续 tune）

```go
const (
    maxStreamsPerConn    = 64                  // 单连接最大并发 stream
    streamHighWatermark  = 51                  // = maxStreamsPerConn * 0.8
    sendPressureThreshold= 256                 // 待发帧阈值
    sendBlockedMS        = 50 * time.Millisecond
    maxConns             = 8                   // 单对端 relay 物理连接上限
    minWarmConns         = 1                   // 保底热连接数
    idleTimeout          = 60 * time.Second
    reapInterval         = 15 * time.Second
    // 高峰
    burstWindow          = 5 * time.Second
    burstTriggerCount    = 3
    burstSustainMS       = 2 * time.Second
    burstBatchSize       = 4
)
```

---

## 5. 落地分阶段（每阶段独立可测/可回滚）

### 阶段 A：bridge mux 复用协议（不含池策略，先打通多路复用）
- 新增 `networkFrameWork/bridge_mux.go`：在裸 `net.Conn` 上实现轻量 mux（移植
  `cmd/tunnel/mux` 帧格式到 net.Conn，或封装 net.Conn 为 p2pnode.Connection 复用现成 mux）。
- 新增握手常量 `RelayBridgeMuxRoute` 与 OPEN payload 编解码。
- 改 `dialRawBridgeConn` → 物理连接级握手一次；`CrossRelayBridge` 改为"在一条共享 physConn
  上 OpenStream"。
- 对端 relay `onMissingGroup` 增加 mux-accept 分支：识别 `RelayBridgeMuxRoute`，
  循环 Accept → 每 stream 合成 hello → 走现有 StreamOn。
- **验证**：单 physConn 承载多 connID，端到端文件传输 SHA 一致；跨中继测试（已有
  TestCrossRelay_DualLeg_LargeTransfer）通过。

### 阶段 B：连接池容器 + least-loaded 分配
- 新增 `p2pnode/impl/relaynode/bridge_pool.go`：`bridgePool map[hostAddr]*relayPeerPool`。
- `doBridge` 改为从 pool 取 stream（而非每次 NewCrossRelayBridge 拨号）。
- 生命周期范本沿用 `peerLink.manage`（退避重连、Close 级联）。
- **验证**：多 connID 复用同 physConn；连接数不随会话数线性增长。

### 阶段 C：扩容（并发数 + 发送压力水位）
- physConn 暴露 `ActiveStreams()` / `PendingFrames()` / 写阻塞探测。
- peerPool 实现 4.1 的扩容判定 + least-loaded 选连接。
- **验证**：单元测试模拟 N 个并发 stream，断言达水位时新开 physConn、未达不开。

### 阶段 D：高峰批量预扩 + 收缩 reaper
- 高峰探测器（滑动窗口）+ 批量扩容。
- 后台 reaper：闲置超时回收 + minWarmConns 保底 + maxConns 封顶。
- **验证**：突发负载断言批量扩；负载回落后断言收缩到 minWarmConns；封顶不超 maxConns。

### 阶段 E：真实部署验证
- 跨服务器（含 KCP 不通双 TCP 场景）验证连接池在真实链路下扩容/收缩、无连接泄漏、
  端到端数据完整。

---

## 6. 风险与注意

1. **端到端语义不能破坏**：mux 只加 `[type][streamID]` 帧头，E2E ACK/MessageId/去重不变。
   阶段 A 必须用现有跨中继测试守住这条不变量。
2. **dual leg 合并**：现状同 connID 的 KCP+TCP 两条 local leg 共享一条 peerConn
   （`SpliceLeg` 的 `started` 守护）。mux 化后应映射为**同一条 mux stream**
   （两条 local leg 写入同一 stream），保持现有 failover 行为。
3. **背压**：mux 单连接写串行化（`writeMu`），发送压力水位正是为此设计——避免一条物理连接
   被某个大流量 stream 堵死其他 stream。
4. **半关闭/错误传播**：一条 physConn 断开要让其上所有 stream 收到 CLOSE/EOF，
   并触发 pool 重建（不影响其他 physConn 上的会话）。
5. **ID 分配**：mux streamID 入口 relay 单侧分配（isClient=true，奇数 ID），对端只 Accept，
   沿用现成 mux 的约定避免冲突。
6. **未改动边界**：遵循项目约定，不动 `p2pnode/types.go` 既有接口语义（如需新方法走新文件/新接口）
   与 `p2pnode/router`。

---

## 7. 交付物清单

- `networkFrameWork/bridge_mux.go`（复用层）
- `networkFrameWork/StreamBridge.go`（改造为 mux stream 接入）
- `p2pnode/impl/relaynode/bridge_pool.go`（池 + 扩容/高峰/收缩）
- `p2pnode/impl/relaynode/relay_node.go`（doBridge 接池、onMissingGroup mux-accept 分支）
- `control_codec.go` 或新增：`RelayBridgeMuxRoute` 常量 + OPEN payload 编解码
- 单元测试：mux 复用、扩容水位、高峰批量、收缩保底
- 跨中继集成测试沿用并扩展
- 真实部署验证报告
