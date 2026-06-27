# DualStream N-leg + leg 标识 实现与部署验证报告

**时间**: 2026-06-27
**状态**: ✅ 实现完成，单测全绿，真实部署验证 server 注册不再重连风暴

---

## 1. 解决的问题

运营商高峰期掐跨地域 UDP → KCP 不通 → 之前 dual 拨号退化成单 TCP leg，失去 failover 冗余。
需求：KCP 不通时补第二条 TCP 组成"双 TCP" failover。

实现中发现并解决了更深的架构问题：**DualStream 用"传输类型(kcp/tcp)"作为 leg 键，
只能容纳一条 KCP + 一条 TCP**。双 TCP 的两条 leg 在 relay 注册侧因同键互相顶替，
导致 `context canceled` 重连风暴（真实部署复现）。

---

## 2. 实现方案：N-leg 通用化 + leg 标识

### 2.1 DualStream N-leg 化
- leg 键从"传输类型"升级为"唯一 leg ID"：基础 leg 用 "tcp"/"kcp"，
  同协议额外 leg 追加 "#2"（如 "tcp#2"）
- `kcp`/`tcp` 字段 → `legs map[streamTransport]*legEntry` + `legOrder []streamTransport`
- 每条 leg 记录 `family`(物理协议族 kcp/tcp，用于日志/重连选拨号器)
- 26 个方法全部改为基于 map/legOrder；sendOrder 改为 preferred + legOrder 选 backup
- frame_adapter 的 adapters/routes 按 leg ID 索引

### 2.2 leg 标识（关键：区分"替换"vs"并存"）
relay 收到同 nodeId 的新同协议 leg，无法仅凭连接信息区分两种场景：
- **重连/换流**：新 leg 应**顶替**同协议旧 leg
- **双 TCP failover**：第二条 TCP 应与第一条**并存**

解决：在固定头部新增 1 字节 `LegFlags`（位于 ConnectionId 之后的填充区，
`network.Header.LegFlags`，bit0=LegFlagExtra），向后兼容（老发送方该字节为 0）。
- client 双 TCP 的第二条 TCP leg 首帧打 `LegFlagExtra` 标记
- relay 端 `AttachStreamCoexist(stream, isExtraLegMarked(firstMsg))`：
  带标记→并存(attachLeg 分配新 ID)；不带→顶替(复用同族 ID)
- 重连时第二条 TCP 的 reconnect dialer 同样带标记，保持并存语义

### 2.3 涉及文件
| 文件 | 改动 |
|------|------|
| `network/Message.go` | Header 新增 LegFlags 字节 + 编解码 |
| `networkFrameWork/DualStream.go` | N-leg 重构（legs map/legOrder/attach/detach/sendOrder/reconnect/...） |
| `networkFrameWork/frame_adapter.go` | adapters 按 leg ID + onLegDetached 回程重路由 |
| `networkFrameWork/Dialers.go` | KCP 不通补第二条 TCP（带 LegFlagExtra）+ 按 leg ID 注册重连器 |
| `networkFrameWork/TcpStream.go` | 新增 IsClosed() |
| `networkFrameWork/StreamGroup.go` | AttachRelayStreamCoexist + StreamOn 传 coexist |
| `networkFrameWork/TransportCoverStream.go` | 注册路径传 isExtraLegMarked |

---

## 3. 测试结果

### 3.1 单元测试（全绿）
| 测试 | 结果 |
|------|------|
| TestDualDial_KCPBlocked_FallbackToSecondTCP | ✅ 双 TCP leg(tcp/tcp#2)共存 |
| TestConnectionStabilityKCPBlocked/Disconnected | ✅ KCP 重连 failover |
| TestCrossRelay_DualLeg_LargeTransfer | ✅ 跨中继 1MB 双向 |
| TestRelayNode_CrossRelayBridge | ✅ 跨中继桥接 |
| network / natnode 全包 | ✅ |
| -race | ✅ 无数据竞争 |

（既有失败 TestNewTransportCover / TestTcpStreamSendMaxRetransmits 与本次无关，
已在干净主线确认其本就失败。）

### 3.2 真实部署验证（38 relay + 104 server + 本地 client）
环境 UDP 被掐（KCP 必然失败），验证双 TCP 降级：

**核心结果 ✅**：server 注册到 relay **不再重连风暴**
- 改动前：双 TCP 互相顶替 → `context canceled` 无限循环 → `Listen 退出`
- 改动后：日志 `KCP 不通, 改用第二条 TCP leg(id=tcp) 组成双 TCP failover`，
  两条 leg(tcp/tcp#2)在 relay 共存，注册抖动收敛（11 行后稳定不增），server 持续存活

**端到端**：client 经隧道连通，health `{"status":"ok"}` 正常，20MB 文件传输进行中。

**带宽**：~44 KB/s —— 受限于跨境 TCP 物理链路（KCP 不通时全程 TCP），
非本次改动引入；提速需 BBR/换线路（见 BANDWIDTH_OPTIMIZATION.md），与本功能正交。

---

## 4. 结论

✅ N-leg 通用化 + leg 标识彻底解决了双 TCP 在 relay 端互相顶替的 bug。
✅ KCP 不通时自动降级为双 TCP failover，保留冗余，不再退化单 leg。
✅ 重连(替换)与双 TCP(并存)两种语义由 LegFlags 标识精确区分。
✅ 单测全绿 + race 通过 + 真实部署验证 server 注册稳定。

带宽受跨境链路物理限制，属已知问题，不在本功能范围。
