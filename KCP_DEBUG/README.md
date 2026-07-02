# KCP 连接回归排查报告

> 排查时间：2026-07-02
> 结论状态：**主根因已从代码层坐实**（非网络问题），附最兼容修复方案
> 排查方式：全程 git 提交历史比对 + kcp-go v5.6.72 源码语义核对；**不依赖单次网络实测**（KCP 跑在 UDP 上，运营商跨境 UDP 有时段性限流，单点实测会飘，只作旁证）
> 严谨性声明：本报告区分【已确证】与【存疑/待验证】。排查早期我曾用单次实测误判为"家庭 NAT 的 KCP UDP 回程不通"——**那是错的**，已推翻（见 §9）。我也曾把"批量写破坏 KCP 消息边界"当成致命根因写进初稿——**复核 kcp-go 源码后认为不成立**，已在 §4 更正。

---

## 0. 结论速览

**你的记忆准确：最开始 KCP 能传，某次重构后坏，且表现为"要频繁调 keepalive 时间和重试次数，越调越糟，最终彻底连不上"。**

根因**不是**网络 / 家庭 NAT / 运营商限 UDP，而是一个**代码层的协议设计问题**，在 `f8eb0c4`（2026-05-25 "重构协议部分，引入帧Frame，以及ACK超时重传策略"）一次引入：

> **在本就可靠有序的 KCP 之上，又叠了一层应用层 ARQ（帧级 ACK + 超时重传），并且把 keepalive 失败改成了直接 `failAndClose` 杀连接。**

KCP 自带 ARQ。"可靠叠可靠"本身只是低效；但叠加"keepalive 失败即杀连接"后，就形成一条**在真实链路（有 RTT/丢包）上必然触发、在 loopback（0 RTT 0 丢包）上永不触发**的死亡链：

```
真实链路丢包/RTT升高
  → KCP 底层恢复(重传)使一次往返的有效时延变长
  → 应用层帧 ACK 在 waitAck 超时内没回来 → 应用层也重传(冗余)
  → keepalive 也走这条 SendMessage，其 3s 预算被应用层指数退避吃满
  → keepalive 返回 error → failAndClose 杀掉 KCP leg
  → 每 900ms 一个 keepalive 周期都可能重复杀 → 永久重连churn = "连不上"
```

这条链**每一步都能在代码里指到行**（§3），且完美解释了"loopback 没问题、真机越来越连不上"和"要不停调 keepalive/重试"。

**修复首选**：**把存活探测从"app-ACK 是否准时"改成"收字节空闲 + 指数退避探测（连续 6 次无回帧才判死）"，并让可靠底层上的应用重传退让**（§6 方案 A），直击已确证根因、不砍任何 ACK、不动帧格式。KCP 开 stream 模式（方案 B）作为低风险防御加固可一并上。

---

## 1. 基线：KCP"最开始能用"的样子（a5171c3, 2026-04-26）

`a5171c3` 是"KCP 确认能传"的最后一个简单版本。它的 `TcpStream` 收发极简，**完全没有应用层 ARQ**：

```go
// 发：一次 Write 一个完整 message，写完即返回，不等任何 ACK
func (t *TcpStream) SendMessage(ctx, message) error {
    bytes, _ := message.ParseToBytes()
    _, err = t.connection.Write(bytes)
    return err
}
// 收：直接 ReadFull，靠 KCP 保证可靠有序
func (t *TcpStream) NextMessage() (*network.Message, error) {
    io.ReadFull(t.connection, headerRead)   // 头
    io.ReadFull(t.connection, payLoad)      // 体
}
// keepalive：失败不杀连接，下一轮再发
func (t *TcpStream) keepLive() {
    for { time.Sleep(5*time.Second); t.SendMessage(ctx, message) }  // 返回值都不看
}
```

关键点（这才是 KCP 的正确用法）：
- **无帧、无帧 ACK、无超时重传** → 完全依赖 KCP 自身可靠有序交付。
- keepalive 5s 一次，**失败也不杀连接** → 网络抖动能自愈。

`grep` 全历史确认：a5171c3 时 `waitAck` / `maxRetransmitAttempts` / `failAndClose` **一个都不存在**。

---

## 2. 转折点：f8eb0c4 引入应用层 ARQ（2026-05-25）

`f8eb0c4`（"重构协议部分，引入帧Frame，以及ACK超时重传策略"）：新增 `network/Frame.go`(+397)、重写 `TcpStream`(+629)，带来三个与 KCP 冲突的改动：

1. **帧拆分**：message 按 `DefaultMaxFramePayload`(1400) 拆成多帧。
2. **帧级 ACK + 超时重传**：`sendMessageWithMessageID` 写完帧后 `waitAck`，无进展超时则重传缺失帧，最多 `maxRetransmitAttempts` 次，耗尽返回 error。
3. **keepalive 失败 → `failAndClose` 杀连接**（基线不杀）。

这就是问题的引入点。下面逐行坐实它如何致命。

---

## 3. 已确证的死亡链（每步指到代码）

### 3.1 双重 ARQ

| 层 | 可靠机制 | 超时/重传 |
|---|---|---|
| KCP（UDP 之上，底层） | 自带 ARQ、序号、快重传 | `SetNoDelay(1,10,2,1)`，RTO ~30–100ms |
| 应用帧层（f8eb0c4 新叠） | 帧 ACK + tracker | `initialAckTimeout` 300→600ms，**指数退避** ×6 |

两层都在"等 ACK→超时→重传"。健康链路上应用层超时(600ms) > 一次往返，不触发，所以没事。**一旦真实链路丢包/RTT 升高**，KCP 底层恢复使有效往返时延变长 → 应用层 `waitAck` 先超时 → 触发**应用层重传**（`FrameTypeRetransmit` 帧再灌进 KCP 队列）→ KCP 又可靠传一遍 → 冗余重传拥塞 KCP 窗口 → 真 ACK 更晚 → 应用层更易超时 → **正反馈**。

代码位置：`TcpStream.sendMessageWithMessageID` 的 `for attempt` 重传循环 + `waitAck`。

### 3.2 keepalive 的 3s 预算被指数退避吃满 → 杀连接（"连不上"的直接机制）

```go
// keepLive(): 每 900ms 一次心跳，给 SendMessage 只有 3s 预算
heartbeatCtx, cancel := context.WithTimeout(t.streamCtx, 3*time.Second)
err := t.SendMessage(heartbeatCtx, &network.Message{Header:{RouteName:"/ping"...}})
if err != nil && ... { t.failAndClose(err); return }   // ← 失败直接杀 leg
```

应用层退避序列：600ms → 1200ms → 2400ms …。**两三次没进展就超过 3s**，`heartbeatCtx` 取消 → `SendMessage` 返回 error → `failAndClose` **杀掉 KCP leg**。之后每 900ms 一个 keepalive 周期都可能重复触发 → **永久重连 churn = 你说的"再也连不上"**。

对照基线：a5171c3 的 keepalive `for { sleep; SendMessage }` 连返回值都不看，**永不杀连接**。杀连接行为正是 f8eb0c4 引入的。

### 3.3 为什么 loopback 能过、真机崩

- **loopback / 进程内**：0 RTT、0 丢包。应用层 `waitAck` 永远在超时前拿到 ACK，双重 ARQ 从不触发冗余重传，keepalive 永远 <3s 成功 → **永不 failAndClose** → 一切正常。这就是为什么进程内测试始终"看起来没问题"。
- **真实链路**：有 RTT/丢包/乱序，3.1→3.2 的链被触发 → 连接被 keepalive 杀死 → churn。

这解释了你全部的观察，且**不依赖任何网络实测就能从代码推出**。

### 3.4 提交历史里"反复调参"的痕迹（旁证你的记忆）

- `f8eb0c4`：`initialAckTimeout = 300ms`
- `a6edc98`：改 `600ms`，注释原话 *"200ms导致连接不稳定，400ms性能提升但不如600ms，600ms是最佳平衡点"*
- `36d6b4c`：又改成"无进展重传"语义 + RTT 自适应
- keepalive 间隔：a5171c3 `5s` → `fa8e55c` 砍到 `900ms`

这些都是在给"第二层 ARQ 的超时"找一个能和"KCP 第一层 ARQ"勉强共存的值——**调参只能推迟雪崩，因为病根（双重 ARQ + keepalive 杀连接）没除**。你的记忆是准的。

---

## 3.5 更深一层的 root cause：一套 per-hop ARQ 把三个层的职责揉在了一起

> 你的两个纠正把病根逼到了更深一层：
> (a) **KCP 的 ARQ 不给上层任何"发送失败/对端已死"的回调或返回**（`UDPSession.Write` 只入队即返回，dead_link 要 ~20 次重传后才在下次读写暴露）——所以你在应用层加帧级 ACK 来探测存活/端到端可靠，**是正确且必须的，不能砍**。
> (b) 场景是**内网穿透**，中继只做字节 splice，跨 relay 多跳时单跳的 KCP/TCP 保证不了整条链路——所以**端到端确认也必须有**。

那问题就不是"多了一层 ACK"，而是**同一套 per-hop 帧 ACK 机制同时承担了三个本属于不同层的职责，并且无差别跑在每一跳上（含底层已可靠的直连跳）**：

| 职责 | 谁真正需要 | 现状 |
|---|---|---|
| **① 单跳可靠性**（重传丢的帧） | 没人——KCP/TCP 每跳都自带 ARQ | 应用层又重传一遍 = 冗余，且和 KCP RTO 抢跑 |
| **② 单跳存活探测**（连接/对端死没死） | 需要——KCP 无 failSend 回调，**加 ACK 是对的** | 但被实现成"3s 内没收到 app-ACK 就 `failAndClose`" |
| **③ 端到端可靠性**（跨 relay 多跳，中继只 splice 字节） | 需要——这是帧 ACK 的**正当理由** | 和 ①② 混在同一套 per-hop 机制里 |

**致命耦合**：把"单跳存活(②)"绑死在了"端到端 app-ACK 的到达时延"上。而 app-ACK 时延在跨境 KCP 上天然抖动——**一个 UDP 丢包 → KCP 等一个 RTO 才重传 → 这一帧的 ACK 就晚一个 RTO**。于是正常的 RTT 抖动被误判成"连接死了"，keepalive 就把一条好连接杀了；再叠上 ① 的冗余重传往已丢包的路径灌更多包 → 更多 KCP RTO → app-ACK 更晚 → 正反馈崩溃。

**为什么 TCP 跳没事、KCP 跳中招**：TCP 单层 ARQ、内核 RTO、无 app 重传抢跑，且直连 relay 的 RTT 稳，3s 撑得住；KCP 跨境有真实丢包，单个丢包就把 app-ACK 推迟一个 RTO，双重 ARQ 又互相加压，3s 预算被吃穿 → 杀连接 → churn。loopback 0 丢包永不触发。

**彻底修复的方向 = 把三个职责拆回各自的层**（见 §5 方案 A：这才是"彻底"，而非只调阈值）。

---

## 4. 关于"批量写破坏 KCP 消息边界"——我更正一个初稿里的过度结论

初稿里我曾把 `747f36f`（2026-06-18 批量写优化：多帧拼一个大 buffer 一次 Write）判为"破坏 KCP message 边界 → 彻底连不上"的致命第二步。**复核 kcp-go v5.6.72 源码后，我认为这个结论不成立，在此更正**：

- KCP 确实是 **message 模式**（全项目从未 `SetStreamMode(true)`）：一次 `Write` = 一条 KCP 消息，一次 `Read` 按 `frg==0` 边界返回整条。
- **但** `sess.go` 的 `UDPSession.Read` 有 `bufptr` 机制：当调用方 buffer 装不下整条消息时，KCP 把整条暂存 `s.buffer`、只拷走一部分、剩余留 `s.bufptr`，下次 `Read` 优先从 `bufptr` 排空。
- 因此"一次批量 Write 多帧 + 收端逐帧 `io.ReadFull`（精确请求字节数）"在 message 模式下**仍能正确逐字节排空**——`io.ReadFull` 从不过读，`bufptr` 保证连续字节跨多次 Read 对齐。**边界不会错乱。**

**我没能从代码坐实这条是 bug，因此不把它列为根因。** 它相关的一个**真实但存疑**的约束见下，作为防御性加固理由，不作定案。

### 【存疑，待验证】message 模式 255 分片上限

kcp-go `kcp.go` 的 `Send` 里：`count = ceil(len(buf)/mss)`，`if count > 255 { return -2 }`。message 模式下一次 `Write` 的 buffer 若 > 255×mss(≈350KB) 会失败。批量写在大消息/高发送窗口下**理论上**可能触及。但我**未验证** `UDPSession.Write` 是否会把大 buffer 自动分块、以及本项目实际单次 `writeFrames` 是否真会到 350KB。**列为待验证项，非定案根因。** 方案 B（stream 模式）可顺带消除此风险。

---

## 5. 修复方案（按"最兼容当前代码"排序）

> 目标：不推翻现有帧 / ACK / mux / relay 架构（那是为跨中继桥接、吞吐服务的，不能丢），只消除与 KCP 的语义冲突。

> 前提（你的两个纠正）：**应用层帧 ACK 必须保留**——KCP 无 failSend 回调，且跨 relay 端到端可靠只能靠它。所以修复不是"砍 ARQ"，而是**把 §3.5 的三个职责解耦**，让"存活探测"不再被"app-ACK 时延"误伤，让"单跳可靠性"交还给底层。

### 方案 A（首选，彻底，直击 §3.5 三职责耦合）：存活探测与 app-ACK 解耦 + 可靠底层退让重传

三处改动，对应拆开三个职责：

1. **② 存活探测改为"收字节空闲 + 指数退避探测"判活，与 app-ACK 解耦**（这是"彻底"的关键）：
   keepalive 不再"单次 `SendMessage` 超时就 `failAndClose`"。判死信号换成**"距上次从本 leg 收到对端任意帧（data / ACK / 对端 ping，任意类型）的空闲时长"**，配合**指数退避探测**：

   - **新增连接级 `lastRecvTime`（atomic）**：在 `readLoop` 每次 `ReadFrame` 成功后刷新一次。注意这**不是**现有的 `recvTracker.lastFrameTime`——后者是 per-message、组包完就 delete，只覆盖数据帧；`lastRecvTime` 是**连接级、覆盖一切入站帧**（含 ACK、对端心跳），才是真正的"对端还活着"信号。
   - **静默基线**：`lastRecvTime` 静默超过 `idleBaseline`（如 3s）→ 进入探测态，发第 1 个探测 ping。
   - **指数退避探测**：每发一个探测后，等待时长翻倍看 `lastRecvTime` 是否被任意入站帧刷新：
     ```
     探测1→等1s→探测2→等2s→探测3→等4s→探测4→等8s→探测5→等16s→探测6→等32s→判死
     ```
   - **判活（退出）**：任意一次等待期间收到对端任何帧 → `lastRecvTime` 刷新 → **立即退出探测态、退避清零**，连接判活。
   - **判死**：**连续 6 次探测（含各自退避窗口）都无任何回帧** → `failAndClose`。纯退避累计 `1+2+4+8+16+32 = 63s`——即"约 1 分钟持续静默且 6 次主动探测均石沉大海"才判这条 leg 死。
   - 效果：一个 UDP 丢包让某条 app-ACK 晚一个 RTO，**绝不**触发判死；只要链路上还有**任何**字节在动，连接恒活。真断网时对端什么都发不出 → `lastRecvTime` 冻结 → 6 次退避探测无响应 → 判死 → 交由 `DualStream.handleLegFailure`→`scheduleReconnect` 走既有重连（这条链不动）。
   - 位置：`TcpStream` 新增 `lastRecvTime` 字段 + `readLoop` 刷新（~3 行）；`TcpStream.keepLive()` 改成退避探测状态机（~20 行）。
   - **可调项**：`idleBaseline`(3s)、退避封顶（当前单次最长 32s）、探测次数（6）。若嫌真断网 63s 才 failover 偏久，可给单次等待封顶（如 ≤8s），则 6 次≈ `1+2+4+8+8+8=31s`——本报告先按你定的"6 次指数退避不同才判死"写，封顶留作后续调参。
2. **① 单跳可靠性交还底层：可靠底层上让应用重传退化为极少触发的兜底**：
   应用层帧重传的超时设成 **≫ 底层 RTO** 的量级（如 ≥ 5×SRTT 且有大下限），让它几乎不与 KCP 的快重传/RTO 抢跑。**帧 ACK 依然收发（③ 端到端确认要留），只是"因超时而主动重传"这个动作被推迟到"底层都救不回来"才发生。** 不是关闭 ACK，是让重传闭嘴。
   - 位置：`sendMessageWithMessageID` 重传循环 / `adaptiveAckTimeout`。
3. **③ 端到端确认保留不动**：帧 ACK 作为跨 relay 的端到端安全网继续存在，但它**无权杀单跳**（杀连接的权力交给 ①②）。

**为什么最兼容**：不动帧格式、不动 relay/mux/E2E 去重语义，不砍任何 ACK；只改"判死信号来源"和"重传触发阈值"。风险低、可用 `pacakgeTest` 真机验证。

### 方案 B（低风险防御加固，建议与 A 一起上）：KCP 开 stream 模式

在 4 处 KCP 会话创建后加一行 `SetStreamMode(true)`，让 KCP 语义 == TCP（无边界字节流）：
- `networkFrameWork/Dialers.go` `kcpStreamContext`（`SetNoDelay` 附近）
- `networkFrameWork/relayStarter.go` KCP accept 分支
- 其余 `kcp.DialWithOptions` / `kcp.ListenWithOptions` 处

**收益**：现有为 TCP 设计的"批量写 + 逐帧读"在 KCP 上语义完全一致；顺带消除 §4 的 255 分片上限风险与任何残余边界脆弱性。**注意**：B 不能替代 A（存活探测耦合与双重 ARQ 抢跑仍需 A 解决）。

---

## 5.5 ACK 带宽优化（内网穿透省服务器上行带宽）

> 场景：下行大文件时，反向 ACK 流量全压在 relay 上行带宽上。当前每个 ACK 是**独立帧**：`39B 定长头 + 最多 36B UUID connId + range 负载 ≈ 85B/条，且按 message 逐条回`。下行 N 条 message 就有 ~N 条 ACK 帧顶着 relay 上行。四招从大到小叠加，可把 ACK 带宽砍到接近零：

1. **Piggyback 搭车（最狠，零额外帧）**：帧头里的 **8 字节 `AckId` 字段目前闲置**（只被 FrameSizeChange 借用）。双向都有流量时，把"累积确认到 msgId N"写进反向 data 帧的 `AckId`，**完全不发独立 ACK 帧**。内网穿透多为双向流（HTTP 请求/响应、隧道回程），命中率高。
   - 位置：`writeFrames` 发 data 帧前填 `AckId` = 当前累积确认点；`handleData`/`handleAck` 读 data 帧的 `AckId` 顺带推进发送方 tracker。
2. **累积 ACK 取代逐条 range**：顺序到达（常态）时，回"已连续收到 ≤ msgId N"**一个数**即可，取代"每条 message 一个 range 列表"。只有出现空洞才退回 selective range。大幅减少 ACK 条数与每条负载。
3. **延迟合并 ACK（类 TCP delayed-ACK）**：收端开一个短窗口（~40ms），窗口内到达的多条 message 的确认**合并成一帧**发出，而不是每条立即回。`recvAckTimer`（现 250ms tick）已是现成载体，缩短并改成"合并待确认集合"即可。
4. **削 connId 开销**：回程 leg 确定时，ACK 帧不带 36B UUID connId（回程路由已知），或换成紧凑数字 id。ACK 又小又频，这项省得最直接。

**落地优先级**：`1(piggyback) > 3(延迟合并) > 2(累积) > 4(削 connId)`。piggyback 在双向流场景下几乎消灭独立 ACK 帧，收益最大且不改帧格式（`AckId` 字段现成）。**注意**：这些属于带宽优化，须在方案 A 落地、KCP 恢复稳定之后再上，避免和根因修复混在一起难以定位。

---

## 6. 建议落地顺序

1. **先上方案 A**（存活探测与 app-ACK 解耦 + 可靠底层退让重传）——直击 §3/§3.5 的"连不上"根因。这是"彻底"修复。
2. **同时上方案 B**（4 处 `SetStreamMode(true)`）——一行一处，低风险防御加固。
3. 用 `pacakgeTest/relayServer.go` 在**真实跨机链路**（非 loopback）验证 KCP 稳定传大文件；确认 keepalive 不再无故杀连接。
4. **稳定后再上 §5.5 的 ACK 带宽优化**（先 piggyback），单独验证省带宽效果。

---

## 7. 关键提交索引

| 提交 | 日期 | 作用 | 与本 bug 关系 |
|---|---|---|---|
| `a5171c3` | 04-26 | ping 心跳修正 | **KCP 能用的基线**（无应用层 ARQ、keepalive 不杀连接） |
| `f8eb0c4` | 05-25 | 引入帧 + ACK 超时重传 | **根因**：KCP 上叠第二层 ARQ + keepalive 失败杀连接 |
| `a6edc98` | 06-13 | 引入 AcceptTcpStreamSync | ackTimeout 300→600（调参痕迹，旁证） |
| `fa8e55c` | — | keepalive 间隔 5s→900ms | 调参痕迹（旁证） |
| `747f36f` | 06-18 | 批量写吞吐优化 | 初稿误判为致命，§4 已更正为"不成立/存疑" |
| `36d6b4c` | 06-28 | waitAck 进展重置 | 又一次与双重 ARQ 打架的调参 |

---

## 8. 确证程度总表（严谨甄别）

| 判断 | 程度 | 依据 |
|---|---|---|
| 根因在代码层、非网络 | **已确证** | 基线 a5171c3 无 ARQ 能用；f8eb0c4 引入后症状出现；机制纯代码可推 |
| f8eb0c4 双重 ARQ | **已确证** | KCP 自带 ARQ（源码）+ f8eb0c4 新增帧 ARQ（diff） |
| keepalive 失败杀连接是"连不上"直接机制 | **已确证** | 3s 预算 vs 指数退避序列（600/1200/2400…）纯算术；基线不杀、f8eb0c4 起杀 |
| loopback 过 / 真机崩 | **已确证**（机制层面） | 0-RTT 下 waitAck 永不超时、keepalive 永不失败 |
| 批量写破坏 message 边界 | **不成立** | `sess.go` bufptr + `io.ReadFull` 精确读，能正确排空（§4 更正） |
| 255 分片上限触发 | **存疑/待验证** | 源码有此限制，但未验证 UDPSession.Write 分块行为与实际 buffer 大小 |
| 具体"哪一次提交彻底连不上" | **无法从代码单点断言** | 症状 RTT/丢包敏感；确证的是 f8eb0c4 引入了必崩机制，触发阈值随链路变化 |

---

## 9. 我在排查中犯过的错误（诚实记录）

1. **早期误判为"家庭 NAT 的 KCP UDP 回程本质不通"**：基于单次网络实测 + loopback 能过的假象，方向完全错。是你的线索（"最开始能用、改代码后坏、要反复调 keepalive"）把方向拉回代码层。此后本报告结论全部基于提交历史 + kcp-go 源码，不依赖易飘的网络实测。
2. **初稿把"批量写破坏 KCP 消息边界"当致命根因**：复核 `sess.go` 的 `bufptr` 排空机制后判定不成立，已在 §4 更正、并从修复主线降级为防御性加固（方案 B）。

主根因（f8eb0c4 双重 ARQ + keepalive 杀连接）的证据链是纯代码可复核的，独立于网络环境。
