# DualStream N-leg 通用化实现方案

## 目标
把 DualStream 从"固定 kcp/tcp 两槽"重构为"支持 N 条 leg",从根上解决
双 TCP(或任意多条同类型 leg)在 relay 注册侧互相顶替的 bug,并为未来多 leg 并行预留能力。

## 修复的 bug
relay 侧 `detectStreamTransport` 对两条 TCP leg 都返回 `tcp`,第二条覆盖第一条
→ `context canceled` → 注册流重连风暴(真实部署已复现)。

---

## 核心设计:leg 键从"传输类型"升级为"唯一 leg ID"

保留 `streamTransport` 类型名(减少改动面),但**语义从"协议种类"变为"leg 唯一标识"**:
- 旧:只有 `"kcp"` / `"tcp"` 两个固定值
- 新:每条 leg 分配唯一 ID,如 `"kcp"`、`"tcp"`、`"tcp#2"`、`"kcp#2"`...

这样**所有以 streamTransport 为 map 键的结构无需改类型**:
`reconnectDialers` / `reconnectActive` / `adapters` / `incomingIDs(frameEndpointKey.kind)` / `ackIDs`。

### 每条 leg 的元数据
```go
type legEntry struct {
    id        streamTransport // 唯一 leg ID
    transport string          // 实际物理传输 "kcp"/"tcp"(用于日志、重连选协议)
    stream    network.Stream
}
```

---

## 数据结构改动(DualStream)

```go
// 旧:
//   kcp network.Stream
//   tcp network.Stream
//   preferred streamTransport
// 新:
legs      map[streamTransport]*legEntry  // 所有现役 leg
legOrder  []streamTransport              // 保持稳定的主备优先级顺序
preferred streamTransport                // 当前主 leg 的 ID
```

---

## 方法改造清单(DualStream.go,26 方法)

| 方法 | 改动 |
|------|------|
| `attach(kind, stream)` | map 写入而非 switch;若 kind 已存在存活 leg→生成新唯一 ID;维护 legOrder |
| `detach(kind, stream)` | map 删除;若删的是 preferred→选 legOrder 中下一条为 preferred |
| `streamLocked(kind)` | map 查找 |
| `HasStream(kind)` | map 查找 |
| `sendOrder()` | 返回 preferred leg + 下一条健康 leg 作 backup(遍历 legOrder) |
| `setPreferred/preferredTransport` | 基于 leg ID |
| `Close` | 遍历 legs map 全关 |
| `startPump/handleLegFailure` | 用 leg ID,日志用 legEntry.transport |
| `scheduleReconnect/runReconnect` | 用 leg ID;重连拨号用该 leg 的 transport 选 KCP/TCP 拨号器 |
| `SendMessage/SendMessageAsync` | sendOrder 返回值适配(已是 primary/backup 二元组,语义不变) |
| `NextMessage` | 不变(读 inbox) |

## 方法改造清单(frame_adapter.go,DualFrameRelayEndpoint)

| 方法 | 改动 |
|------|------|
| `adapters map[streamTransport]` | 键变唯一 leg ID,逻辑不变 |
| `AttachStream(kind,...)` | 接收 leg ID(由 DualStream attach 时传入) |
| `collect/isCurrent` | 用 leg ID;日志用 transport |
| `frameEndpointKey.kind` | 仍是 streamTransport(现为 leg ID),逻辑不变 |
| `chooseAdapterLocked(exclude)` | 遍历 adapters 选一条非 exclude 的,语义不变 |

---

## leg ID 分配策略

- client 拨号:KCP leg→`"kcp"`,TCP leg→`"tcp"`;KCP 失败补的 TCP→`"tcp"`(主),
  原 TCP→若 "tcp" 占用则 `"tcp#2"`
- relay attach:第一条→detect 得 "tcp"/"kcp";第二条同类→`detect + "#2"`
- 统一规则:`attach` 内若目标 ID 已被存活 leg 占用,追加 `#2/#3...` 直到唯一

这样 relay 收两条 TCP:leg1→"tcp",leg2→"tcp#2",两条独立共存,**不再互相顶替**。

---

## preferred / failover 语义(保持与现有一致)

- preferred = 当前主 leg ID;SendMessage 走 preferred,失败切 legOrder 中下一条
- 一条 leg 失败 → detach → 若是 preferred,preferred 切到下一条健康 leg
- 所有 leg 都失败 → Close
- **2 条 leg 时行为与现有 KCP/TCP 主备完全等价**(N-leg 是超集)

---

## 兼容性风险与对策

| 风险 | 对策 |
|------|------|
| 外部代码直接用 streamTransportKCP/TCP 常量 | 保留这两常量作为"首选 leg ID";检查所有引用点 |
| detectStreamTransport 仍返回 kcp/tcp | 保留,作为 attach 的"建议 ID",冲突时加后缀 |
| frameEndpointKey 跨 leg 的 ID 翻译 | 键含 leg ID,更细粒度,不会跨 leg 串号(反而更安全) |
| PreferTCP 语义 | 改为"切到任一 TCP 传输的 leg";检查调用方 |

---

## 验证计划
1. **单测**:
   - 扩展 `TestDualDial_KCPBlocked_FallbackToSecondTCP`:验证 relay 侧两条 TCP attach 得到
     两个独立 leg(id=tcp / tcp#2),无顶替
   - 新增 N-leg failover 单测:3 条 leg,逐条断开,验证主 leg 切换、连接不断
2. **回归**:networkFrameWork 全包(dual/stability/frame)+ relaynode 跨中继
3. **-race**:并发 attach/detach/send
4. **真实部署**:38/104,验证 server 双 TCP 注册不再重连风暴 + 20MB 传输 + failover
5. **报告**:真实部署验证报告

## 涉及文件
- `networkFrameWork/DualStream.go`(主重构)
- `networkFrameWork/frame_adapter.go`(adapters/collect 适配 leg ID)
- `networkFrameWork/Dialers.go`(leg ID 分配,client 侧已有双 TCP 逻辑适配)
- `networkFrameWork/dual_tcp_failover_test.go`(扩展)
- 检查所有 `streamTransportKCP`/`streamTransportTCP`/`detectStreamTransport` 引用点

## 实施顺序(分阶段,每阶段可编译可测)
1. 引入 legEntry + legs map,attach/detach/streamLocked/HasStream 改 map(保持 2 leg 行为)
2. sendOrder/preferred/reconnect 改 legOrder 遍历
3. frame_adapter adapters 改 leg ID
4. leg ID 唯一化分配(#2 后缀)+ relay 双 TCP 共存
5. 全量回归 + 真实部署
