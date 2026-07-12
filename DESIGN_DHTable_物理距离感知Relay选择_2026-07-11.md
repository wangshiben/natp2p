# DHTable 与物理网络质量感知的 Relay 选择设计

**状态**：阶段 0/1 已实现，阶段 2～4 待实施  
**日期**：2026-07-11  
**适用范围**：`DHTable/`、`p2pnode/impl/natnode/`、`p2pnode/impl/relaynode/`、`p2pnode/relayquery/`  
**核心目标**：避免“NodeID/XOR 逻辑距离很近，但真实网络距离很远”的 Relay 被 NAT 节点优先选中。

## 1. 背景

当前 NAT 节点向 Index 查询 Relay 列表后，会按自身 NodeID 与 Relay NodeID 的 XOR 距离升序排列，
然后逐个测试 TCP 端口是否可连接，选择第一个可达 Relay。

该方法只能回答两个问题：

1. Relay 在 DHT ID 空间中是否接近；
2. Relay 的 TCP 端口是否可连接。

它不能回答：

- NAT 到 Relay 的真实 RTT、抖动和超时率；
- Relay 是否长期稳定在线；
- Relay 是否处于过载状态；
- Relay 是否只对探测响应很快，但实际数据面质量很差。

NodeID 通常由公钥哈希产生，与机房、运营商、国家、ASN 和链路质量没有相关性。因此，XOR 最近的
节点完全可能位于物理网络的另一端。对于 CGNAT、跨运营商和跨境链路，这会让 NAT 节点从注册开始
就处于高延迟或弱网状态，并进一步放大 ACK 重传、连接保证金重扣和计费偏差。

## 2. 设计结论

采用“逻辑路由与物理选路分层”的设计：

```text
DHTable / KBucket
    负责：ID 空间覆盖、XOR 路由进展、稳定节点保留、替换缓存

RelaySelector
    负责：入口 Relay 的真实可达性、RTT、稳定时间、失败率和切换策略

RoutePolicy
    负责：跨 Relay 路由时，先保证 XOR 方向有进展，再从合格下一跳中选择网络质量更好的节点
```

不直接按 RTT 或“剩余 TTL”修改 KBucket 的结构顺序。对外需要按网络质量查看节点时，返回一个排序
后的只读投影，不改变桶内用于 LRU 淘汰的真实顺序。

用户提出的排序优先级保留为：

```text
1. RTT 延迟档位最低
2. 同一延迟档位中，连续稳定存活时间最长
```

不可达、握手失败、超时率过高或处于冷却期的节点会在上述排序之前被过滤。

## 3. 术语

### 3.1 Message TTL

`p2pnode.Message.TTL` 表示广播消息还能传播多少跳。它是 hop limit，不是时间，不能用于节点排序。

### 3.2 Route Entry TTL

路由条目在多久没有成功通信后进入可疑状态。本文使用 `StaleAfter` 表示，避免与消息 TTL 混淆。

### 3.3 RTT

NAT 或 Relay 从发出探测到收到对应响应的往返耗时。本文中“TTL 时间最短”统一解释为“实测 RTT
最短”。若原意是 Route Entry TTL，则它不能代表物理网络距离。

### 3.4 连续稳定存活时间

从最近一次被确认离线或控制链路中断之后，到当前持续在线的时间：

```text
StableAge = now - ContinuousHealthySince
```

它不是进程自报的 uptime。优先使用 Index 观察到的连续控制链路存活时间；NAT 还可以维护自己的
本地成功历史作为更可信的补充。

### 3.5 逻辑距离

节点 ID 的 XOR 距离，用于 DHT 路由和桶范围划分，与物理延迟无直接关系。

## 4. 当前实现盘点

### 4.1 DHTable

- KBucket 按本地节点与候选节点的 XOR 距离范围划分；
- `StoreNode` 使用切片维护桶内节点；
- 已存在节点再次加入或 `UpdateLastSeen` 时会移动到桶尾；
- 桶头代表最久未活跃节点，桶尾代表最新活跃节点；
- 桶满后新节点进入 replacement cache；
- `FindClosest` 会收集所有桶的节点，重新按“候选到目标”的 XOR 距离排序。

因此当前桶内已经具有 LRU 的顺序语义，不需要为了时间再全桶排序。

### 4.2 NAT Bootstrap

当前流程为：

```text
Index 返回 [{NodeID, Addr}]
        ↓
按 NAT NodeID 与 Relay NodeID 的 XOR 距离排序
        ↓
依次 TCP DialTimeout
        ↓
选择第一个可连接 Relay
```

TCP 探测只返回布尔值，没有保留连接耗时。Index 返回结构也没有稳定时间、能力或负载信息。

### 4.3 时间字段缺口

`DHTable.Node` 内部同时存在 `lastCalled` 和 `lastSeen`，但：

- `interfaces.Node` 没有暴露 `LastSeen()`；
- 生产通信路径没有系统性调用 `DHTTable.UpdateLastSeen`；
- `p2pnode.PeerInfo.LastSeen` 当前部分路径取自 `LastCalled()`；
- `LastCalled` 没有在真实心跳路径持续更新。

在补齐触达路径之前直接启用时间淘汰，会把健康节点错误标记为过期。

## 5. 目标与非目标

### 5.1 目标

1. NAT 初次注册优先选择真实网络质量更好的 Relay；
2. 在网络质量接近时优先选择长期稳定节点；
3. 保持 DHT XOR 路由正确性，不产生环路或失去远距离 ID 空间覆盖；
4. 避免短时网络抖动导致 Relay 频繁切换；
5. 避免探测风暴和恶意 Relay 通过单次快速响应骗取全部流量；
6. 与旧 Index/Relay/NAT 线格式向后兼容；
7. 支持灰度观察，不要求一次替换整个网络。

### 5.2 非目标

- 本设计不实现 IP 地理定位或强制地域调度；
- 不保证最低业务吞吐，RTT 只是网络质量的一部分；
- 不以 RTT 替代 DHT XOR 路由；
- 不在第一版实现全局最优多路径路由；
- 不允许 NAT 因为候选略快几毫秒就自动迁移现有业务连接。

## 6. 总体架构

```text
                         ┌─────────────────────────────┐
                         │ Index                       │
                         │ Relay registry              │
                         │ continuous-online metadata  │
                         └──────────────┬──────────────┘
                                        │ RelayQuery
                                        ▼
┌──────────────┐    candidate list    ┌──────────────────────┐
│ NAT Node     │─────────────────────▶│ RelaySelector        │
│              │                      │ staged probe         │
│ local history│◀────────────────────▶│ rank + hysteresis    │
└──────┬───────┘                      └──────────┬───────────┘
       │ selected relay                         │ probe
       ▼                                        ▼
┌──────────────┐                       ┌──────────────────────┐
│ registration │                       │ Relay probe endpoint │
│ business     │                       │ nonce echo + cert    │
└──────────────┘                       └──────────────────────┘

DHTable remains responsible for XOR buckets and route progress.
```

## 7. 数据结构

### 7.1 Index 返回的 Relay 信息

在现有 JSON 结构上追加可选字段：

```go
type Info struct {
    NodeID string `json:"node_id"`
    Addr   string `json:"addr"`

    ContinuousOnlineSince int64  `json:"continuous_online_since,omitempty"`
    LastControlSeen       int64  `json:"last_control_seen,omitempty"`
    CapacityClass         string `json:"capacity_class,omitempty"`
    LoadPermille          uint16 `json:"load_permille,omitempty"`
}
```

字段原则：

- `ContinuousOnlineSince` 必须由 Index 根据控制链路观察生成，不能采用 Relay 自报 uptime；
- `LastControlSeen` 用于排除 Index 已知的陈旧 Relay；
- `LoadPermille` 第一版只作为弱权重 tie-break，因为自报负载可能不可信；
- 新字段全部 `omitempty`，旧节点忽略未知字段，新 NAT 对缺失字段采用默认值。

### 7.2 NAT 本地探测结果

```go
type RelayProbeResult struct {
    NodeID              p2pnode.NodeID
    Address             string
    TCPConnectRTT       time.Duration
    HandshakeRTT        time.Duration
    MedianRTT           time.Duration
    Jitter              time.Duration
    Successes           int
    Attempts            int
    ConsecutiveFailures int
    ObservedAt          time.Time
    ErrorClass          ProbeErrorClass
}
```

`MedianRTT` 使用有效的应用层探测样本中位数。只有 TCP connect 成功、应用层 nonce 应答正确、Relay
证书和 NodeID 匹配的样本才算成功。

### 7.3 本地历史

```go
type RelayHistory struct {
    NodeID                 p2pnode.NodeID
    Address                string
    EWMARTT                time.Duration
    SuccessCount           uint64
    FailureCount           uint64
    ConsecutiveSuccess     uint32
    ConsecutiveFailure     uint32
    LocalHealthySince      time.Time
    LastSuccess            time.Time
    LastFailure            time.Time
    CooldownUntil          time.Time
}
```

第一版可以只保存在内存；稳定后可写入节点私钥同级的状态文件。状态文件不包含私钥，并采用原子替换写入。

### 7.4 DHT 桶条目

长期方案应让路由表持有健康元数据，避免一个 `Node` 同时进入多张路由表时共享时间状态：

```go
type bucketEntry struct {
    node                interfaces.Node
    lastSuccess         time.Time
    continuousSince     time.Time
    staleAfter          time.Time
    consecutiveFailures uint8
    state               entryState // healthy, suspect
}
```

桶内真实存储顺序继续是 LRU：头部最久未确认，尾部最近确认。网络质量排序通过复制条目后生成只读视图。

## 8. Relay 探测协议

### 8.1 为什么不能只测 TCP connect

TCP connect 只能证明端口开放，不能证明：

- 监听进程是期望的 Relay；
- Relay 事件循环能够及时响应；
- Admission/证书路径能够工作；
- TCP 后存在的代理没有把所有地址都快速接收后丢弃。

因此采用两阶段探测。

### 8.2 第一阶段：TCP 快速筛选

- 并发探测候选 Relay；
- 默认并发上限 `8`；
- 单次超时默认 `1500ms`，可以根据历史 P95 自适应；
- 记录 TCP connect RTT；
- 只用于快速剔除不可达地址。

### 8.3 第二阶段：应用层 Probe

新增轻量控制路由，例如：

```text
/relay/probe
```

请求：

```json
{
  "nonce": "random-128-bit",
  "client_time_unix_nano": 0,
  "expected_relay_id": "..."
}
```

响应：

```json
{
  "nonce": "same-value",
  "relay_id": "...",
  "index_sign": {}
}
```

NAT 只用本地单调时钟计算 RTT，不信任 Relay 返回的时间。响应必须：

- nonce 完全一致；
- Relay NodeID 与 Index 候选一致；
- indexSign 能通过本地缓存的 CA 公钥验签；
- 在探测超时内返回。

Probe 不创建业务连接、不扣连接保证金、不进入流量结算，但必须在 Relay 端做按 IP/NodeID 的速率限制。

### 8.4 采样

默认参数：

```text
TCP 快速探测：每个候选 1 次
应用层探测：通过第一阶段的候选每个 3 次
样本间隔：50～150ms 随机抖动
RTT：取成功样本中位数
成功门槛：至少 2/3 成功
```

若 Relay 数量很大：

1. 第一阶段并发 TCP 探测全部候选；
2. 按 TCP RTT 选前 `M=8`；
3. 再加入 `2` 个随机候选，防止永远没有机会发现 XOR 很远但物理很近的 Relay；
4. 只对这批候选做应用层三次采样。

## 9. 排序算法

### 9.1 资格过滤

候选必须满足：

```text
Address 非空
NodeID 合法
不是 Index 自身（除非进入最终回退）
Index 的 LastControlSeen 未过期
TCP 可达
应用层 Probe 至少 2/3 成功
证书与 NodeID 匹配
不处于本地 CooldownUntil
```

所有子 Relay 不合格时回退 Index，保持当前“总能上线”的语义。

### 9.2 RTT 延迟档位

不直接比较每一毫秒，而是先计算本轮最佳 RTT：

```text
bestRTT = min(candidate.MedianRTT)
bandWidth = max(10ms, bestRTT * 10%)
RTTBand(candidate) = floor((candidate.MedianRTT - bestRTT) / bandWidth)
```

示例：最佳 RTT 为 `40ms`，档宽为 `10ms`：

```text
40～49ms 进入第 0 档
50～59ms 进入第 1 档
60～69ms 进入第 2 档
```

这样 `40ms` 不会仅凭 1ms 优势永久压过稳定数月的 `41ms` Relay。

### 9.3 稳定时间

同 RTT 档位内使用：

```text
两侧都有记录：EffectiveStableAge = min(IndexStableAge, LocalStableAge)
只有一侧有记录：EffectiveStableAge = availableStableAge
两侧都无记录：EffectiveStableAge = 0
```

本地没有历史时只用 IndexStableAge，并把可信等级标为较低。Index 未提供时稳定时间为零，不阻止接入。

### 9.4 最终字典序

```text
1. RTTBand                         升序
2. EffectiveStableAge             降序
3. TimeoutRate                    升序
4. Jitter                         升序
5. LoadTier                       升序
6. EWMARTT                        升序
7. XOR(selfNodeID, relayNodeID)   升序
8. NodeID                         字典序，保证结果确定
```

前两项对应本次核心决策。XOR 只作为最后的确定性 tie-break，不再代表物理距离。

### 9.5 伪代码

```go
func SelectRelay(self NodeID, indexAddr string, infos []Info, probe Prober, history History) Selection {
    candidates := normalizeAndDeduplicate(infos)
    results := probe.InParallel(candidates, 8)
    eligible := filterEligible(results, history)
    if len(eligible) == 0 {
        return Selection{Address: indexAddr, Reason: "index-fallback"}
    }

    bestRTT := minimumMedianRTT(eligible)
    bandWidth := maxDuration(10*time.Millisecond, bestRTT/10)
    for candidate := range eligible {
        candidate.RTTBand = rttBand(candidate.MedianRTT, bestRTT, bandWidth)
        candidate.StableAge = effectiveStableAge(candidate, history)
        candidate.XORDistance = self.XOR(candidate.NodeID)
    }
    sort.SliceStable(eligible, relayLess)
    return Selection{Address: eligible[0].Address, Reason: explain(eligible[0])}
}
```

## 10. DHTable 桶策略

### 10.1 桶的结构顺序

外层桶始终按理论 XOR 距离范围排序：

```text
[SL0, EL0], [SL1, EL1], ...
```

禁止根据 RTT、Route Entry TTL 或稳定时间移动整个桶。否则会破坏范围连续性、桶分裂插入位置以及依赖
桶顺序的调用方语义。

### 10.2 桶内真实顺序

桶内保持 Kademlia 风格的 LRU：

```text
Head = 最久未成功确认
Tail = 最近成功确认
```

以下事件可以 Touch 节点：

- TLS/身份握手成功；
- DHT PONG/FIND_NODE 响应成功；
- Relay 控制链路收到合法消息；
- 业务 Send/Receive 成功；
- keepalive 收到端到端 ACK。

单纯收到未经认证的 UDP/TCP 字节或 Relay 自报心跳不能刷新时间。

### 10.3 Route Entry TTL 淘汰

建议第一版参数：

```text
Soft stale: 2 分钟无成功交互 → suspect + 主动探测
Probe timeout: 根据链路历史，默认 3 秒
Hard removal: 连续 2 次探测失败
Maintenance interval: 30 秒 + 0～10 秒随机抖动
```

维护时只检查桶头：

```text
if Head.lastSuccess 尚未达到 StaleAfter:
    结束本桶本轮检查
else:
    probe Head
    success → Touch 并移到 Tail
    failure → failures++
    failures >= 2 → Remove，并验证 replacement candidate 后补位
```

桶内已经按 LRU 排列，因此不需要每次维护执行 `sort.Slice`。

### 10.4 网络质量排序视图

如调试界面或选路模块需要查看“本桶内物理上更近的节点”，新增只读 API：

```go
RankedNodes(policy RankingPolicy) []interfaces.Node
```

它复制条目后排序，不改变 `Head/Tail` 和 replacement cache 语义。

## 11. 跨 Relay 下一跳策略

入口 Relay 选择与 DHT 路由不同。跨 Relay 寻址必须先保证 XOR 路由有进展：

```text
currentDistance = XOR(currentRelayID, targetID)
eligible next hop = XOR(candidateID, targetID) < currentDistance
```

只在有进展的候选中使用网络质量排序：

```text
1. 对目标的共同前缀进展更多
2. peer-link 健康
3. RTT 档位更低
4. 连续控制链路存活更久
5. 负载更低
6. XOR 距离
```

若 RTT 优先于“必须取得 XOR 进展”，可能在两个低延迟 Relay 间形成环路，或永远无法接近目标。

## 12. Relay 切换与迟滞

### 12.1 初次选择

NAT 启动时执行完整探测和排序，选择一个入口 Relay，并保持当前“唯一入口 Relay”拓扑。

### 12.2 重新选择触发条件

只在以下情况重新选择：

- 当前 Relay 注册失败或控制连接断开；
- 连续多次重连失败；
- 当前 Relay RTT 连续 3 个观察窗口超过历史基线 2 倍；
- 当前 Relay 被 Index 标记下线或证书失效；
- 运维显式要求重新调度。

不因一次慢探测主动迁移现有业务。

### 12.3 切换门槛

当前 Relay 尚可用时，新 Relay 必须同时满足：

```text
新 Relay 连续 3 次选择均胜出
新 Relay RTT 至少改善 20% 或降低一个完整 RTTBand
新 Relay 不处于冷却期
距上次主动切换超过 10 分钟
```

切换前需要考虑现有业务连接和保证金窗口。第一版建议“新连接使用新 Relay、旧连接自然结束”，不要
强制迁移活跃连接。

## 13. 安全设计

### 13.1 Sybil 与刷新占位

不能让新节点仅凭快速 Probe 或频繁 Touch 挤掉长期稳定节点。KBucket 满时仍保留稳定主列表，新节点
进入 replacement cache，只有主节点确认失效后才晋升。

### 13.2 快探测、慢数据攻击

恶意 Relay 可以让 `/relay/probe` 很快，却限制真实业务流量。缓解措施：

- 把实际注册耗时、业务 ACK RTT、断线率回灌本地 EWMA；
- 初次 Probe 只决定候选，实际会话质量持续修正历史；
- 业务失败会进入 cooldown；
- 后续可以加入小尺寸带宽探测，但第一版不主动制造额外流量。

### 13.3 虚假稳定时间

Relay 自报 uptime 只能作为展示信息，不能参与核心排序。稳定时间必须来自 Index 控制链路观察或 NAT
本地成功历史。

### 13.4 Probe DoS

Relay Probe 端点需要：

- 每源 IP 和 NodeID 令牌桶；
- 全局并发上限；
- 请求体大小上限；
- nonce 长度固定；
- 不分配业务 StreamGroup；
- 不访问 CA，不触发账本和保证金；
- 超载时快速返回 busy 或直接丢弃。

### 13.5 Index 元数据可信度

旧客户端会忽略新增字段。新客户端必须把 Index 元数据视为“候选建议”，真实可达性和 RTT仍由本地
探测决定。即使 Index 元数据陈旧，也只能影响排序，不能绕过 Relay 证书验证。

## 14. 性能与容量

设 Index 返回 `R` 个 Relay：

- 候选规范化：`O(R)`；
- 并发 TCP 探测：时间约为最慢一批超时，而不是 `R * timeout`；
- 排序：`O(R log R)`，通常远小于网络探测成本；
- KBucket 内只检查 LRU 头部，不新增全桶排序；
- K 通常很小，即使生成一次只读排序视图，`O(K log K)` 也可接受。

为避免大量 NAT 同时启动形成探测风暴：

- 探测任务加入随机抖动；
- NAT 本地缓存最近结果；
- Index 响应允许携带建议缓存时间；
- Relay 数量很大时只对 TCP 阶段筛出的前 M 个和少量随机候选做完整 Probe。

## 15. 可观测性

### 15.1 NAT 指标

```text
relay_selector_candidates_total
relay_selector_tcp_reachable
relay_selector_probe_success
relay_selector_probe_timeout
relay_selector_selected_rtt_ms
relay_selector_selected_stable_seconds
relay_selector_index_fallback_total
relay_selector_switch_total{reason}
relay_selector_suppressed_switch_total{reason}
```

### 15.2 Index/Relay 指标

```text
relay_continuous_online_seconds
relay_last_control_seen_seconds
relay_probe_requests_total
relay_probe_rejected_total{reason}
relay_probe_inflight
```

### 15.3 决策日志

每次选择记录有限、可解释的信息：

```text
[relay-select] candidates=4 eligible=3 selected=relayA
  rtt=42ms band=0 stable=72h loss=0 load=210/1000 xor_rank=3 reason="best-band,longest-stable"
```

日志不得记录私钥、完整证书或可用于重放的 nonce。

## 16. API 与文件改动建议

### 16.1 新文件

```text
p2pnode/impl/natnode/relay_selector.go
p2pnode/impl/natnode/relay_probe.go
p2pnode/impl/natnode/relay_history.go
p2pnode/impl/relaynode/probe_handler.go
DHTable/entry.go
DHTable/maintenance.go
```

### 16.2 修改文件

```text
p2pnode/relayquery/relayquery.go
    Info 增加向后兼容的可选稳定性字段

p2pnode/impl/natnode/bootstrap.go
    selectEntryRelay 从 reachable bool 改为 RelaySelector
    保留旧 XOR 策略作为回退和灰度开关

p2pnode/impl/relaynode/relay_node.go
    Index 维护 Relay 连续在线时间
    注册 ProbeRoute handler

DHTable/Buket.go
    节点与路由表健康元数据解耦
    保持 LRU，不按 RTT 修改真实顺序

interfaces/DHTTable.go
    增加 Touch/维护或只读排序视图接口
```

### 16.3 建议接口

```go
type RelayProber interface {
    Probe(ctx context.Context, info relayquery.Info) RelayProbeResult
}

type RelaySelector interface {
    Select(ctx context.Context, self p2pnode.NodeID, indexAddr string,
        infos []relayquery.Info) (RelaySelection, error)
}

type Clock interface {
    Now() time.Time
}
```

注入 `RelayProber` 与 `Clock`，避免单测依赖真实时间和公网。

## 17. 配置建议

```text
relay_selection_policy = xor | latency-stable
relay_probe_concurrency = 8
relay_probe_tcp_timeout = 1500ms
relay_probe_app_timeout = 2000ms
relay_probe_samples = 3
relay_probe_min_success = 2
relay_rtt_band_min = 10ms
relay_rtt_band_ratio = 0.10
relay_switch_improvement = 0.20
relay_switch_confirmations = 3
relay_switch_cooldown = 10m
dht_soft_stale = 2m
dht_remove_failures = 2
dht_maintenance_interval = 30s
```

第一版默认仍可使用 `xor`；在观察模式只计算 `latency-stable` 结果并记录差异，不真正改变选择。

## 18. 兼容与灰度

### 阶段 0：修正时间语义

- 明确 Message TTL、StaleAfter、RTT 命名；
- 路由表健康状态归属到表条目；
- 补齐成功通信路径的 Touch；
- 修复 `LastCalled/LastSeen` 混用；
- 补充竞态测试。

### 阶段 1：NAT 本地测量，不改协议

- 复用现有 Relay 列表；
- 并发记录 TCP connect RTT；
- 实现 RelaySelector 和 RTT 档位；
- 以 shadow 模式与 XOR 结果对比；
- 此阶段仍缺少应用层真实性和稳定时间，但能快速验证收益。

### 阶段 2：应用层 Probe 与 Index 稳定时间

- 扩展 `relayquery.Info`；
- 加入 ProbeRoute、证书绑定和限流；
- NAT 使用应用层 RTT 中位数；
- 正式启用 `latency-stable` 策略。

### 阶段 3：切换迟滞与本地历史

- 持久化 EWMA、失败率和本地稳定时间；
- 加入 cooldown 与主动切换阈值；
- 把实际业务质量回灌选择器。

### 阶段 4：跨 Relay 质量感知

- peer-link 记录 RTT/失败率；
- 下一跳必须取得 XOR 进展；
- 同等路由进展内按 RTT 档位和稳定时间选择；
- 验证无环路和跨 Relay 收敛。

## 19. 测试设计

### 19.1 RelaySelector 单元测试

1. XOR 最近但 RTT 最差，应选择 XOR 较远、RTT 更低的 Relay；
2. RTT 同档时选择连续稳定时间最长者；
3. RTT 不同档时稳定时间不能跨档反转结果；
4. 最佳 Relay 不可达时选择下一候选；
5. 所有子 Relay 不可达时回退 Index；
6. 重复地址和非法 NodeID 被过滤；
7. Probe 只有 1/3 成功时不合格；
8. 缺少新协议字段时仍可选择；
9. 完全同分时结果由 XOR/NodeID 确定，不随 map 顺序变化；
10. 并发探测不超过配置上限。

### 19.2 迟滞测试

1. 1ms 抖动不触发切换；
2. 只胜出一次不切换；
3. 连续三次改善 20% 后允许切换；
4. 冷却期内禁止再次主动切换；
5. 当前 Relay 失效时绕过改善门槛立即故障转移；
6. 新连接走新 Relay，旧连接不被强制关闭。

### 19.3 DHTable 测试

1. Touch 后节点移动到桶尾；
2. soft stale 后进入 suspect，不立即删除；
3. 探测成功恢复并移到桶尾；
4. 连续两次失败后删除并从 replacement cache 补位；
5. RTT 排序视图不改变 Head/Tail；
6. `FindClosest` 仍严格按目标 XOR 返回；
7. 桶范围顺序和分裂连续性不受网络质量字段影响；
8. fake clock 测试不使用真实 sleep；
9. `go test -race` 覆盖 Touch、维护、分裂和查询并发。

### 19.4 跨 Relay 属性测试

1. 每个下一跳到目标的 XOR 距离严格递减；
2. 任意拓扑中不能出现路由环；
3. 低 RTT 候选只有在满足路由进展时才被选择；
4. 最优低 RTT peer 断开时能选择另一个有进展 peer；
5. 旧版本 peer 缺少 RTT 元数据时仍可路由。

### 19.5 本机网络仿真

至少模拟三个 Relay：

```text
Relay A: XOR 最近，RTT 180ms，稳定 72h
Relay B: XOR 较远，RTT 35ms，稳定 24h
Relay C: XOR 最远，RTT 38ms，稳定 240h
```

预期 B/C 同属最低 RTT 档，选择稳定时间更长的 C。随后模拟 C 丢包或断开，验证选择 B，而不是回到
XOR 最近但物理最远的 A。

### 19.6 真实部署验收

沿用当前 server3 CA+Index、server4 Relay、本机 NAT 拓扑，并增加至少一个具有不同网络延迟的候选
Relay。仅两台公网服务器无法充分验证选择算法，因为 Index 与 Relay 角色固定且候选数不足。

验收记录：

- 每个候选三次 TCP/application RTT；
- RTT 中位数、抖动、超时率和稳定时间；
- XOR 排名与新策略排名；
- 最终选择理由；
- 注册耗时、业务握手耗时、文件传输吞吐；
- 弱网重传次数与计费差异；
- Relay 故障后的切换时间；
- 是否出现保证金重复扣费。

## 20. 验收标准

必须同时满足：

1. XOR 最近但 RTT 显著更差时，不再选择该 Relay；
2. RTT 位于同一档时稳定时间最长者胜出；
3. 所有候选不可达时仍能回退 Index；
4. 单次网络抖动不会触发 Relay 迁移；
5. 入口选择额外耗时在正常候选规模下不超过配置的总体 Bootstrap 预算；
6. Probe 不产生连接保证金和流量账单；
7. 新旧节点可以混合部署；
8. DHT `FindClosest`、桶范围和 replacement cache 行为不回归；
9. 跨 Relay 下一跳始终取得 XOR 进展；
10. 单元测试、集成测试和竞态测试通过；
11. 真机场景能给出可解释的选择日志；
12. 弱网测试中相对旧 XOR 策略不降低成功率。

## 21. 风险与权衡

| 风险 | 影响 | 缓解 |
|---|---|---|
| Bootstrap 多次探测增加上线时间 | 首次连接变慢 | 两阶段探测、并发上限、历史缓存 |
| 大量 NAT 同时探测 | Relay 瞬时压力 | 抖动、限流、Index 建议缓存时间 |
| RTT 低但吞吐差 | 选择错误 | 回灌业务 RTT/失败率，后续扩展小流量探测 |
| Relay 伪造 uptime/load | 排序被操纵 | 稳定时间由 Index 观察，负载只作弱权重 |
| RTT 抖动导致频繁切换 | 业务中断、重复保证金 | RTT 档位、连续确认、改善阈值、冷却期 |
| TTL 错误刷新 | 健康节点被淘汰 | 只在认证成功事件 Touch，过期后先探测 |
| RTT 排序破坏 DHT | 路由停滞或环路 | XOR 进展为硬条件，网络质量只在合格集合内排序 |
| 新字段与旧节点不兼容 | 灰度失败 | JSON 可选字段、旧 XOR 回退、shadow 模式 |

## 22. 最终决策建议

推荐批准以下方案：

1. 不将 RTT/Route TTL 写进 KBucket 的结构距离顺序；
2. KBucket 保持 XOR 分桶和 LRU 淘汰；
3. 新增独立 `RelaySelector`，入口选择采用“RTT 档位优先、同档稳定时间优先”；
4. NAT 自己测 RTT，Index 提供其观察到的连续在线时间；
5. 先做 shadow 模式验证，再切换默认策略；
6. 跨 Relay 选路必须先保证 XOR 严格进展，再比较物理网络质量；
7. 过期节点先探测、连续失败后才删除，不按单次 TTL 到期直接淘汰。

## 23. 2026-07-12 实机部署结果

server3 CA+Index、server4 Relay、本机 NAT Server/Client 的部署、RTT、自动选择、Relay 地址身份重绑定、
5MiB 文件完整性、计费观察和清理结果，见
`DHT_物理距离感知Relay_实机部署_报告_2026-07-12.md`。

结论为通过：当前线路 TCP 中位数 server3 `62.041ms`、server4 `48.909ms`，最终选择 server4；
实机发现并修复同一 Relay 地址重启换 NodeID 后旧 DHT 身份未清理的问题。仍需单独跟进单次 RTT 探针
抖动和最终样本中 `2.354x` 的唯一帧计量放大。

补充定向对照使用 `natServer2` 验证：其到 server3/serverN 的 XOR 距离以 `47...` 开头，到测试时
server4/serverX 的距离以 `81...` 开头；但 9 次 TCP connect 中位数分别为 `63.785ms` 和
`48.140ms`，真实 Bootstrap 最终选择 serverX，满足“逻辑近 N、物理近 X、最终采用 X”的预期。

该方案能够解决“逻辑距离近、物理距离远导致 NAT 天然进入弱网”的核心问题，同时保留 DHT 路由
正确性、KBucket 抗抖动能力和旧版本兼容性。

## 23. 第一版实现记录（2026-07-12）

本次完成阶段 0 和阶段 1，并把新策略设为 NAT Bootstrap 默认入口选择策略。没有把 RTT 或条目过期
时间写进 KBucket 的 XOR 范围，也没有改变 `FindClosest` 的逻辑距离语义。

### 23.1 DHTable 健康层

- `interfaces.Node` 补充 `LastSeen()`，展示与路由状态不再误用 `LastCalled()`；
- 每个 `StoreNode` 独立保存 `NodeHealth`：RTT、连续健康起点、最近成功、连续失败和 suspect 状态；
- `Touch` 只在调用方确认成功交互后刷新条目并移动到 LRU 尾部；
- `RankedNodes` 复制快照后按“healthy、RTT 档位、稳定时间、失败次数、原始 RTT、NodeID”排序，
  不改变真实 Head/Tail；
- `Maintain` 每桶每轮只检查头节点，默认 2 分钟 soft stale，探测成功 Touch，连续两次失败才删除；
- 主节点删除后，replacement candidate 必须先通过同一 Probe 才能晋升；
- 桶分裂会连同条目健康状态一起迁移，`FindClosest` 仍严格按目标 XOR 排序。

### 23.2 RelaySelector

NAT Bootstrap 默认执行并发 TCP connect RTT 探测：

```text
并发上限       8
单候选超时     1500ms
总体预算       5s
RTT 最小档宽   10ms
相对档宽       bestRTT * 10%
控制状态陈旧   2m
```

排序字典序为：RTTBand 升序、Index 连续在线时间降序、负载升序、原始 RTT 升序、XOR 升序、NodeID
升序。非法 NodeID、重复地址、Index 自身、TCP 不可达和控制状态陈旧的候选会被过滤；全部不可达时
回退 Index。设置 `BNFS_RELAY_SELECTION_POLICY=xor` 可立即恢复原“XOR 距离 + 串行可达性”策略。

### 23.3 Index 在线元数据

`relayquery.Info` 已以 `omitempty` 追加 `continuous_online_since`、`last_control_seen`、
`capacity_class` 和 `load_permille`，旧节点可以忽略。Index 通过已认证控制链路计数维护连续在线起点：
同一 Relay 仍有任一控制链路存活时不重置，全部断开后再次上线才重置。合法控制消息会刷新
`LastControlSeen`。关闭 Relay 时先释放 owner 锁再关闭 peer link，避免 link-down 回调反向取锁。

### 23.4 已完成验证

- RTT 同档时稳定 240h 的 38ms Relay 胜过稳定 24h 的 35ms Relay；
- 50ms Relay 即使稳定 240h，也不能跨档压过 30ms Relay；
- 缺少新字段的旧 Relay 仍可选择，完全同分由 XOR/NodeID 确定；
- 并发探测不会超过配置上限；不可达、陈旧、非法和重复候选按预期过滤；
- 排名视图不改变 LRU，维护使用假时钟且不依赖 sleep，连续失败与 replacement 验证通过；
- `FindClosest`、桶分裂、压力测试、NAT/Relay 回归和新增竞态测试通过。

### 23.5 尚未实现

本轮 TCP RTT 只能证明端口可连接，不能证明 Relay 身份、事件循环和数据面质量。阶段 2 的应用层
nonce Probe、证书绑定、Probe 限流和三次采样中位数仍未实现；阶段 3 的本地 EWMA/持久历史、切换
迟滞也未实现；跨 Relay 下一跳仍保持现有 XOR/FIND 机制，尚未接入质量感知。正式多 Relay 灰度前
必须完成这些阶段，不能把第一版 TCP connect RTT 表述成完整的抗恶意物理距离证明。
