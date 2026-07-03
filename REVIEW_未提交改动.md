# 待 Review:working tree 未提交改动

> 生成于 2026-06-28。本仓库 working tree 有 **三组互相独立** 的改动尚未提交。
> 用户保护传帧/ACK 层,**未经确认勿提交**。建议按组分别决策(留/退/分开提交)。

`git status` 概览:
```
 M cmd/tunnel/client/main.go        ┐
 M cmd/tunnel/mux/session.go        │ 组B 吞吐(实测无收益)
 M cmd/tunnel/mux/stream.go         │
 M cmd/tunnel/server/main.go        │
 M networkFrameWork/AckTracker.go   │
 M networkFrameWork/TcpStream.go    ┘
?? networkFrameWork/adaptive_timeout_test.go  (组B 的测试)

 M networkFrameWork/Dialers.go            ┐
 M networkFrameWork/DualStream.go         │ 组A 重连风暴修复(实测有效)
 M networkFrameWork/StreamBridge.go       │
 M p2pnode/impl/relaynode/relay_node.go   ┘

 M p2pnode/types.go   ┐ 组C 路由器(与隧道本次工作无关)
?? p2pnode/router/    ┘
```

---

## 组 A — 重连风暴修复 ✅ 实测有效,建议提交

**问题**:客户端双 TCP failover 保留了第二条 TCP leg 并给它注册了重连器;relay 端「一个 connID 一个桥接,多余 leg 直接 `Close()`」。客户端一重连、relay 一关闭 → 无限重连风暴(实测 170–220 次重连 / 912 次 NextMessage 失败)。

**修复是三处协同**(缺一不可,中途单独改任一处都引入了新 bug):

### A1. relay:多余 leg 改为 splice 并存,不再关闭
`p2pnode/impl/relaynode/relay_node.go` — `findAndBridge` 三个关闭点(已建桥后到 / KCP 已建桥唤醒 / 窗口超时)全部改为 `spliceFailoverLeg(...)`。新增 helper:
```go
func (n *RelayNode) spliceFailoverLeg(br *networkFrameWork.CrossRelayBridge, stream network.Stream, target, connID string) error {
    if br == nil { _ = stream.Close(); return nil }            // 极端竞态回退
    if err := br.SpliceLeg(stream); err != nil {
        logx.Warnf(...); _ = stream.Close(); return nil         // splice 失败回退
    }
    logx.Infof("[relaynode] failover leg 已并入桥接: ...")
    return nil
}
```
`CrossRelayBridge` 本就支持多条 local leg(`localConns/active/liveLegs`),此前从未用上。

### A2. standby 全程静默,心跳只跟 preferred leg
`networkFrameWork/Dialers.go` + `DualStream.go`。
- `tcpClientStreamContext` / `kcpStreamContext` 加可选 `noKeepAlive ...bool`;dual 模式所有 leg 用 `true` 创建 → 不自发 `keepLive`。
- 新增 `DualStream.startKeepAlive()`:900ms 经 `SendMessage` 发 `/ping`,只走当前 preferred leg。
- **为什么必须这样**:relay 桥接按「最近发字节的 leg」决定回程 active leg。若静默 standby 也发心跳,active 被翻到 standby,下一段下行数据被错路由到 standby,在 32KB 读边界把一帧劈成两半 → 两条 leg 同时解析失败 → 新风暴。心跳只走 preferred → active 稳定在数据 leg;failover 后 preferred 迁移、心跳自动跟随 → role-swap 安全。

### A3. SpliceLeg 不抢 active
`networkFrameWork/StreamBridge.go` — `b.active = localConn` 改为 `if b.active == nil { b.active = localConn }`。否则第二次 splice 把 active 设成静默 standby,握手响应被错路由劈裂 → tunnel=0(中途踩过这个回归)。

**真链实测**(5MB 整文件经隧道下载 vs 直连 SHA 逐字节对比):

| 指标 | 改前 | 改后 |
|------|------|------|
| TCP 重连/传输 | 170–220 | 0~1 |
| NextMessage 失败 | 912 | 0~1 |
| 5MB SHA | — | 一致 + 大小一致(5242880),多轮复现 |
| 隧道建立 | ✓ | ✓ |

残留「1 次」是握手窗口一次性事件,非持续循环。单测全过(networkFrameWork 78s、relaynode bridge 12s)。

**风险点请重点看**:`SpliceLeg` 的 active 语义改动是否对「单 leg 正常路径」无副作用;`spliceFailoverLeg` 的两处回退分支是否覆盖全部竞态。

---

## 组 B — 吞吐改动 ⚠️ 实测无收益,建议回退(或先搁置)

目标:跨境高 RTT 链路,把单 RTT 摊到的字节数放大(吞吐 ≈ chunk/RTT)。**不触碰传帧/ACK 核心逻辑**,只动两层:

### B1. maxChunk 32KB → 512KB(可配)
- `cmd/tunnel/mux/stream.go`:`const maxChunk = 32*1024` → `maxChunk := streamMaxChunk`。
- `cmd/tunnel/mux/session.go`:新增 `defaultMaxChunk = 512KB`、`resolveMaxChunk()`、env `TUNNEL_MAX_CHUNK`。

### B2. 数据泵 io.Copy → io.CopyBuffer(512KB)
- `cmd/tunnel/{client,server}/main.go`:裸 `io.Copy`(读上限钉死 32KB)→ `io.CopyBuffer` + `pumpBufSize()`(env `TUNNEL_PUMP_BUF`,默认 512KB)。
- **关键认知**:只调 maxChunk 没用——裸 `io.Copy` 每次最多喂 32KB 给 `mux.Write`,把单条消息钉死在 32KB。两处必须配套改。

### B3. waitAck「整消息硬截止」→「无进展超时」+ RTT 自适应
- `networkFrameWork/TcpStream.go`:新增 `srttMicros atomic.Int64`;`waitAck` 每当已确认帧数推进就 `timer.Reset(timeout)`(只有 timeout 内零进展才返回 `errAckTimeout`);新增 `adaptiveAckTimeout()`(`3×SRTT`,钳 `[300ms,5s]`)、`observeRTT()`(EWMA α=1/8,由 keepLive 往返采样)。
- `networkFrameWork/AckTracker.go`:新增 `ackedCount()`。
- **语义变化注意**:`initialAckTimeout=600ms` 从「整条消息硬截止」变成「无 RTT 样本时的无进展阈值缺省」。这是为放大 maxChunk 后的大消息兜底——大消息只要持续有 range ACK 就不误超时。**这一层最贴近你保护的传帧/ACK 逻辑,请重点 review 语义是否可接受。**
- 测试:`networkFrameWork/adaptive_timeout_test.go`(新增 3 个,-race 通过):无样本退回缺省 / 进展重置不误超时 / 真卡住仍超时触发重传。

**为什么建议回退**:真链 A/B 实测,组B(512K+自适应)比旧版 **慢约 20%**,且链路自身波动远大于该差异。当时 90KB/s 的瓶颈被确认是 **GFW 节流**(跨境 UDP/KCP 被限),不是协议停等。即「停等 ACK 是瓶颈」的假设被实测推翻——真正的收益来自组A。组B 没有数据支撑。

**决策选项**:
- (推荐)回退组B 6 个文件 + 删 `adaptive_timeout_test.go`,只留组A。
- 或:保留代码但默认值不变(maxChunk 退回 32KB,靠 env 才放大),把 B3 的自适应当作纯防御性改进单独评估。

回退命令(确认后再执行):
```
cd /root/natP2p
git checkout -- cmd/tunnel/client/main.go cmd/tunnel/mux/session.go \
  cmd/tunnel/mux/stream.go cmd/tunnel/server/main.go \
  networkFrameWork/AckTracker.go networkFrameWork/TcpStream.go
rm networkFrameWork/adaptive_timeout_test.go
```

---

## 组 C — 路由器 package ❓ 与本次隧道工作无关,需你确认归属

- `p2pnode/types.go`:`Message` 新增 `Code int` 字段(HTTP 语义状态码,默认 0)。
- `p2pnode/router/`(未跟踪新目录,日期 6/22):`router.go` / `tree.go` / `context.go` + 测试 + README,一个前缀树路由器。

这两项**不在** A/B 任何一组的讨论范围内,看起来是另一条线的工作(6/22,早于本次 6/27–28 的隧道调试)。我没动过它们,也不清楚是否就绪。**请确认**:是你已写好待提交的、还是半成品?要不要纳入提交、还是单独成一个 commit?

---

## 建议提交划分

1. **commit 1(组A)**:重连风暴修复 — 实测有效,可立即提交。
2. **组B**:回退或搁置(默认回退),不进 commit。
3. **commit 2(组C)**:路由器 — 待你确认归属后单独提交。

等你指示再动手:要我现在按上面回退组B 吗?组C 怎么处理?

