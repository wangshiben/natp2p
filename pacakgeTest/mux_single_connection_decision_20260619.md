# 单连接多路复用（n‑v‑1‑v‑1）：实现现状、HOL 实测、待拍板方案

> 日期：2026/06/19
> 主题：在 server↔relay **一条连接**上用 connectionId 多路复用多个 client，server 端控帧。
> 本文给出：已落地的实现、单连接多路复用暴露的队头阻塞（HOL）实测证据、"轻流/重流"判据、
> 以及三条可选路线的成本/收益，供拍板。
> 注：文中服务器 IP 已脱敏为 RFC1918 内网地址（relay=10.10.0.1 / server=10.10.0.2 / client2=10.10.0.3）。

---

## 1. 已实现（机制已验证正确，代码在工作区，未提交）

按"帧头加 connectionId、relay 按帧头路由、callee 帧级 demux、每连接独立 TLS/handler、server 控帧"
全部落地：

| 部件 | 文件 | 要点 |
|---|---|---|
| 帧线格式加 `ConnectionId` | `network/Frame.go` | 定长头 37→39 字节（加 `ConnIdLen(2)`），body = `ConnId+Payload`；`ParseToBytes/ParseFrame/ReadFrame` 同步改 |
| 出向源头打戳 | `networkFrameWork/TcpStream.go` | 数据帧取 `message.Header.ConnectionId`（权威，含 relay 经 `SendMessage` 转发首条消息的 pureForwarder 腿）；ACK/控制帧取 `t.connectionId` |
| relay 按帧头路由 | `networkFrameWork/FrameRouteRegistry.go` | `pumpRelayToClients` 用 `f.ConnectionId` 选目标 client，弃用解析首帧 payload；dual‑leg 三层 MessageId/failover 不动 |
| callee 帧级复用器 | `networkFrameWork/EndpointFrameMux.go`（新） | 两腿 pureForwarder+frameTap 取原始帧 → 按 `f.ConnectionId` demux → per‑conn `muxConn`（虚拟 net.Conn，非阻塞队列）→ `startTcpStream` 正常终结流；单写者 goroutine 出帧 |
| 每连接独立 TLS + handler | `pacakgeTest/relayServer.go` | 每个新 connectionId spawn 一个 goroutine：读 hello 推 nodeId → 独立 `NewTLSCrypto` → `TrafficMonitor` |
| 单端发起（server 控帧） | `TcpStream.go` | client 进程 `BNFS_FRAME_FOLLOWER=1` 不发起；callee per‑conn 流发起；pureForwarder 腿不发起 |

单测 `-race` 全绿（帧 round‑trip 带 connectionId；复用器双连接 demux）。

**机制被实测证明正确**：单条 client 经多路复用的单连接、用自己的 TLS，数据完全干净：
- 本机 relay/callee/client 三进程：单流 **323 MB / 0 重复 / 0 解析失败**。
- 真机（relay=10.10.0.1，server=10.10.0.2，本机=client）：单流 **2.27 MB / 0 重复 / 0 丢失**，TLS 正常、按 connectionId 路由正确。

---

## 2. 实测发现的根本问题：单连接多路复用的队头阻塞（HOL）

**现象**：两个 client 并发时，**第二个 client 始终卡在 TLS 握手**，本机与真机都复现。
callee 正确建了两条逻辑连接、读到两个 hello、为第二条发出握手 round‑1 且不断重传，但对端始终收不到。

**根因——线级 HOL**：两个 client 的流量复用在同一条 callee↔relay 物理连接上。client1 的 32‑worker 满发
在**收发两个方向**都主导了那条连接的字节流，client2 的握手字节物理上排在 client1 洪流之后。
真机上 client1 仅 ~45 KB/s 也照样把 client2 卡死 → **不是带宽饱和，是调度不公平**。

**两个复用点都需要公平，缺一不可**：
- 出向（callee→relay→各 client）：由 **callee 写者**决定谁的帧先上线。
- 入向（各 client→relay→callee）：relay 要把 N 条 client 腿并进同一条 callee 连接，由 **relay 转发器**
  （`pumpClientToRelay` 那组 goroutine 抢写）决定谁先上线。

已做的 callee 解耦（单 FIFO 写者 + 非阻塞 dispatch）只去掉了锁竞争，**没做轮询公平**，relay 侧未动 →
故仍复现饿死。

**两种性质不同的 HOL**（务必区分）：
- **(a) 调度不公平→饿死**（我们看到的）：可修。两个复用点都改 per‑connection **轮询调度**，轻流握手即可拿到公平份额、正常建立；修后两 client 都能跑，各拿 ~1/N。
- **(b) 单连接固有的 loss‑HOL + 单拥塞窗口**：修不掉。一条连接=一条有序字节流+一个拥塞窗口；丢一个包，
  KCP/TCP 重传期间所有流都卡一下，且 N 个流共享一个窗口**拿不到并行带宽**。这是 QUIC/HTTP3 用 per‑stream
  流控取代单 TCP 的根本原因。(a) 修好后 (b) 只是偶发延迟抖动，不会永久饿死。

---

## 3. "轻流 / 重流"怎么定义（决定走哪条路的关键）

不是看绝对字节，而是看**对共享连接的占用方式**：

- **重流**：出队长期非空（持续积压 backlog），永远有下一个包要发，把窗口一直占满。批量传输/同步/备份。
- **轻流**：发一阵就空闲——请求/响应、心跳、控制、偶发小数据，**主动让出车道**。

单车道公路类比：轻流=开一段就靠边停的车；重流=永不让道的卡车。一卡车+一辆车 → 车被堵（HOL）；
一堆间歇停的车 → 互相穿插不堵。

**轻重是相对的、看竞争的**，本质判据：
> 单流持续需求 ÷ 连接可用容量，外加占空比。
> 总需求 < 容量 → 谁都不饱和，全等效轻流；只有"总需求>容量 且 某流持续积压"时 HOL 才出现。

可测量信号：①占空比/队列深度（最直接）②速率占连接吞吐比例（持续 >10~20% 偏重）
③突发大小 vs BDP（带宽×时延积）④时延敏感性。

**实务做法——不预先分类，自动检测大象流**：所有流先上共享连接；持续监控每流积压/吞吐，
越阈值（明显是卡车）就**迁到独立连接**，老鼠流继续复用。**可直接复用现有帧大小自适应器按流测得的吞吐**
（`minHealthyThroughput`/30s 窗口那套）做判据，几乎零额外成本。

---

## 4. 三条路线（待拍板）

| 路 | 两流并发能否跑通 | 工作量 / 风险 | 局限 |
|---|---|---|---|
| **A. 两点公平调度** | 能（修好饿死） | callee 端容易；**relay 端要动 dual‑leg pump，风险高** | 仍共享一个拥塞窗口，重流拿不到并行带宽；loss‑HOL 仍在 |
| **C. 重流走独立连接（混合）** | 能，且重流各自满带宽 | 中等，**不碰 relay 最脆弱处** | 不再"严格一条连接"；连接数随重流数增 |
| **D. 降测试负载演示** | 能（不饱和就不饿死） | 很小 | 只验证功能，掩盖饱和下 HOL |

**路线 A 细化**：callee 写者改 per‑conn 轮询（我这边容易）；relay 把 N 条 client 腿并进 callee 连接处
也要轮询（动 `FrameRouteRegistry`/`frame_adapter`，碰最脆弱的 dual‑leg/dedup，风险高）。
建议若走 A，先只补 callee 侧、观察是否够轻流握手，再决定是否动 relay。

**路线 C 细化（业界标准 = 混合）**：控制/轻流复用一条连接；批量重流自动迁出到独立 server↔relay 连接。
用第 3 节的大象流检测触发迁移。最省心、最快、且回避 relay 风险；代价是放宽"严格一条连接"。

---

## 5. 我的推荐

取决于这条 server↔relay 上的真实流量画像：
- **主要是控制面/轻流**（小消息、RPC、心跳、偶发数据）：走 **A**，且**优先只做 callee 侧轮询**，
  尽量别动 relay pump。一条连接对大量轻流是净赢。
- **包含批量重流**（大文件/持续高吞吐）：走 **C 混合**。一条连接本质给不了并行带宽，对重流再公平也没用；
  重流独立连接最稳，且不碰 relay 最脆弱处。

倾向：业界普遍是**混合（C）**——轻流复用、重流独连。除非确认全是轻流，否则我倾向 C。

---

## 6. 待你拍板

1. **真实流量画像**：这条 server↔relay 上主要是轻流，还是会有打满链路的重流？
2. **路线**：A（两点公平，重连接受限）/ C（混合，重流独连）/ D（先降负载验证功能）/ 先不动。
3. 若走 A：是否接受先只改 callee 侧、暂不动 relay？若走 C：大象流迁移的阈值用现有吞吐自适应器的口径即可，是否认可？

> 代码现状：完整实现 + callee 解耦均在工作区，**未提交**。等你定方向再继续 / 提交。
