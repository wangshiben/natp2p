# 跨 relay 通信吞吐诊断与优化方案

> 复现问题:跨 relay 传输仅 **0.19 MB/s**,预期 ≥1 MB/s。
> 本报告用变量控制实验定位瓶颈,给出分层优化方案。

---

## 1. 测试拓扑与关键前提

```
本机 tunserver ──上行──> 129 relay ──下行──> 本机 tunclient
  (读本地httpserver)                          (回给本地curl)
```

**两个必须先讲清的前提**(否则数字会误导):

1. **caller/callee 都在本机** → 同一份字节要**先上行到 129、再下行回本机**,跨境走 **2 趟**。
2. **KCP 没穿透,走的是双 TCP**(见上一份跨relay报告):本机移动网络 UDP 回程被运营商 NAT 丢弃。所以底层是 **TCP + 应用层端到端 ACK**。

---

## 2. 网络层基线(绕过所有应用代码)

| 指标 | 实测 | 说明 |
|---|---|---|
| RTT 本机↔129 | **~96ms** | 跨境正常 |
| 原始 TCP 上行(→129) | **1.85 MB/s** | SSH dd,单流 |
| 原始 TCP 下行(129→) | **0.66 MB/s** | SSH dd,单流 ← **瓶颈方向** |

**关键洞察**:下行 0.66 MB/s ≈ `64KB / 96ms` = **单条 TCP 被带宽时延积(BDP)卡住**。
96ms RTT 下,单 TCP 连接若窗口 ~64KB,吞吐上限就是 ~0.66 MB/s。**这是单条 TCP 腿的物理天花板。**

---

## 3. 应用层瓶颈定位(变量控制实验)

同一 20MB 传输,只改一个旋钮:

| 实验 | send_window | chunk | pump_buf | 吞吐 |
|---|---|---|---|---|
| 基线 | 8 | 64KB | 512KB | **0.201 MB/s** |
| 加窗口 | **64** | 64KB | 512KB | 0.188 MB/s |
| 加 chunk | 32 | **128KB** | 512KB | 0.212 MB/s |
| 全拉满 | 32 | 64KB | **4MB** | 0.203 MB/s |

**结论:吞吐对窗口/chunk/pump 全免疫,恒定 ~0.2 MB/s → 有效在途深度恒为 1(停等)。**

### 根因:`io.CopyBuffer` 的"读一次→写一次→阻塞等 ACK"循环

数据泵结构(`cmd/tunnel/server|client/main.go`):
```go
io.CopyBuffer(dst, src, make([]byte, 512KB))
// 每轮: n = src.Read(buf);  dst.Write(buf[:n])
```

- `src.Read` 从 loopback HTTP 连接**每次只返回 ~32-64KB**(TCP 有多少给多少,不受缓冲大小约束——这正是 pump=4MB 也没用的原因)。
- 每次 `Stream.Write` 只拿到 ~1 个 chunk → `Stream.Write` 内部 fan-out 只有 1 个 goroutine。
- `Stream.Write` 结尾 `wg.Wait()` **阻塞到这 1 个 chunk 的端到端 ACK 回来**,才返回、才做下一次 Read。

```go
// cmd/tunnel/mux/stream.go  Stream.Write
for len(p) > 0 { ... go sendData(seq, chunk) ... }  // fan-out
wg.Wait()   // ← 阻塞到全部 chunk 的端到端 ACK,单流退化成停等
```

发送窗口(`sendWindow`,容量8)只在**多条并发 stream** 时有用;单文件下载 = 单条 stream,永远只有 1 个在途。

### 停等代价 = 双程跨境往返

```
0.203 MB/s ÷ 64KB ≈ 3.2 条/秒 ≈ 每条 310ms
端到端 ACK 路径:去(本机→relay→本机) + ACK回(本机→relay→本机) ≈ 4×96ms ≈ 384ms
```
实测 310ms 与理论 384ms 同量级,**确认停等 + 双程跨境**。

---

## 4. 瓶颈分层总结

| 层 | 瓶颈 | 当前上限 | 打破手段 |
|---|---|---|---|
| **L1 应用层** | 单流 `Write` 停等深度=1 | ~0.2 MB/s | **流水线化 Write(下方方案A)** |
| **L2 单TCP腿** | BDP:64KB窗口×96ms | ~0.66 MB/s | 大 socket 缓冲 / 多腿条带化 |
| **L3 底层协议** | TCP(KCP未穿透) | — | 修复 UDP 回程让 KCP 生效 |

**现状被 L1 卡死在 0.2**,连 L2 的 0.66 都没摸到。**先解 L1,吞吐应跳到 ~0.66;要过 1MB/s 需再叠 L2/L3。**

---

## 5. 优化方案(按性价比排序)

### 方案A:流水线化单流发送 —— 解 L1【最高优先级,预期 0.2→0.66 MB/s】

**问题**:`Stream.Write` 每次 `wg.Wait()` 等全部 ACK 才返回,把 CopyBuffer 的读节奏和 ACK RTT 死锁在一起。

**改法**:让 `Stream.Write` **不等 ACK 就返回**,只在**在途窗口满**时才背压。改成滚动窗口:
```go
// 伪代码:Stream.Write 推 chunk 进窗口即返回,不等 ACK
for len(p) > 0 {
    chunk := next(p)
    s.sess.sendWindow <- struct{}{}      // 满则阻塞(背压),否则立即过
    go func() {
        defer func(){ <-s.sess.sendWindow }()
        s.sess.sendData(id, seq, chunk)  // 内部等 ACK,但不挡住 Write 返回
    }()
}
// 不在这里 wg.Wait();关闭时才 drain
```
效果:连续多次 `Write` 可让 **W=8 条消息同时在途**,深度 1→8。
理论上限 `8×64KB / 0.384s ≈ 1.33 MB/s`,但会先撞上 L2 的 0.66 单腿天花板 → **实际预期 ~0.66 MB/s**。
风险:需保证错误传播(某 chunk 失败要让后续 Write/Close 感知)、关闭时正确 drain 在途 chunk。

### 方案B:提升单 TCP 腿窗口 —— 解 L2【预期 0.66→1.5+ MB/s】

单腿 BDP 受 socket 缓冲限制。给 relay 腿显式设大缓冲:
```go
tcpConn.SetReadBuffer(4 << 20)   // 4MB
tcpConn.SetWriteBuffer(4 << 20)
```
并确认内核 `net.ipv4.tcp_rmem/wmem` 上限够大。96ms RTT 下要跑满 2MB/s,窗口需 ~200KB,4MB 缓冲足够。
配合方案A 后,单腿有望到 1.5-2 MB/s。

### 方案C:多腿条带化(bridge striping)—— 解 L2【聚合突破单腿天花板】

代码库已有条带化基建(git log 里的 F3 `LogicalConn` 拆多 TCP 并行、`-bridge-width`)。
把跨境流量拆到 **N 条并行 TCP 腿**,聚合吞吐 ≈ N × 单腿。这是绕过单 TCP BDP 最稳的路子(下载器多线程同理)。
建议:确认 `-bridge-width` 在当前隧道路径生效,压测 width=2/4 的聚合吞吐。

### 方案D:修复 KCP 穿透 —— 解 L3【跨境最优,但当前 UDP 被安全组挡死】

KCP 自带大窗口 + 前向纠错,跨境高丢包链路远优于 TCP。但**当前 KCP 根本建立不起来**,详见 §7。

---

## 7. 【专项】KCP 能不能提速?—— 先测能否建立,再论提速

> 用户诉求:优先看 KCP 能否提速,不能再考虑 TCP。
> 结论:**当前测不了 KCP 提速,因为 UDP 被腾讯云安全组挡死,KCP 握手 100% 失败,永远回退双 TCP。且即便通了,单流吞吐也会被 §3 的应用层停等卡在同一水平。**

### 7.1 KCP 建立失败(网络层,非代码)

在**两台云服务器之间**(193 跑 client/server,relay=129)复测,KCP 仍失败:
- tunclient 日志:`KCP 不通, 补第二条 TCP leg 组成双 TCP failover`
- relay(129) 日志:`ListenKCPConnection error: timeout`

原始 UDP 可达性判定(绕过所有应用代码,纯 python UDP echo):

| 测试 | 结果 |
|---|---|
| TCP:9000 云对云(193→129) | ✅ 通(relay 注册在用) |
| TCP:19999 云对云(任意端口) | ❌ 超时 |
| UDP:9000 云对云(193→129,echo) | ❌ echo **没收到任何包** |
| UDP:19999 双向(193↔129,echo) | ❌ 双向都没收到 |
| UDP:9000 本机(移动网络)→129 | ❌ 超时 |

**判定链**:
1. TCP:19999 不通 + TCP:9000 通 → 安全组按**端口白名单**放行(只开 22/9000)。
2. 129 主机防火墙 `YJ-FIREWALL-INPUT` 是纯 IP 黑名单(74 条,193 不在内),**不分协议、无 UDP 规则** → 主机防火墙排除。
3. UDP:9000 的 echo **收不到任何包** → 包在到达主机前就被丢 → **腾讯云安全组只放行了 TCP:9000,没放行 UDP:9000**。

> 纠正之前一处误判:上次说"KCP Write 成功=包到达 relay"是错的。UDP `send()` 本地永远成功(fire-and-forget),不代表送达。这次 echo 实测证明**包根本没到**。

### 7.2 修复:放行 UDP,才能测 KCP(需你在控制台操作)

**这是配置问题,不是代码问题,我改不了,需要你操作:**

1. **腾讯云控制台 → 两台服务器(129/193)的安全组 → 入站规则 → 放行 `UDP:9000`**(来源按需:测试可先 `0.0.0.0/0`,生产收紧到对端 IP)。
2. 若客户端在**家宽/机房**(非移动 CGNAT),UDP 回程通,则真机也能跑 KCP;**移动 4G/5G 的 CGNAT 通常挡 UDP 入站回程**,那种网络 KCP 天生跑不起来,只能靠 TCP。

放行后我可立即复测 KCP 单流吞吐(任务已挂起待验证)。

### 7.3 但即便 KCP 通了,单流也不会更快(代码层已证实)

KCP 和 TCP **共用同一套应用层发送/ACK 代码**:
```go
// Dialers.go  kcpStreamContext 和 TCP 拨号都走:
res := startTcpStream(originalNodeId, connectionId, conn)  // conn 是 KCP 或 TCP
```
→ 同一个 `TcpStream.SendMessage / waitAck`,§3 的**单流停等(深度=1)对 KCP/TCP 完全一致**。
KCP 唯一优势在**丢包链路**(自带 FEC/快重传,底层恢复快),但:
- **不解决单流停等** → 单流吞吐仍 ~0.2 MB/s。
- 只有先做**方案A(流水线化 Write)**,KCP 的大窗口优势才发挥得出来。

**所以正确顺序其实是:方案A(应用层流水线)是地基,KCP/TCP 都受益;KCP 是在方案A 之上、丢包链路才额外加分的选项——不是替代方案A 的捷径。**

---

## 8. 对"优先 KCP"诉求的直接回答

1. **KCP 现在提不了速,因为它建立不起来** —— 腾讯云安全组没放行 UDP:9000。请先放行(§7.2)。
2. **即便放行、KCP 建立成功,单流吞吐仍会是 ~0.2 MB/s** —— 因为瓶颈在应用层单流停等(§3),KCP/TCP 同源同病。
3. **真正的提速地基是方案A(流水线化 Write)**,KCP 和 TCP 都靠它才能突破 0.2。KCP 只在此之上、跨境丢包时比 TCP 多一层优势。
4. 建议:**先放行 UDP → 我复测确认 KCP 单流确实 ~0.2(证实判断)→ 再做方案A → 方案A 之上对比 KCP vs TCP 的真实收益**,用数据决定跨境到底用哪个传输层。

---

## 6. 建议执行顺序

1. **先做方案A**(流水线化 Write)—— 改动集中在 `mux/stream.go`,预期立竿见影 0.2→0.66,验证 L1 判断。
2. **再叠方案B**(TCP 大缓冲)—— 几行改动,预期 →1.5+ MB/s,达成 >1MB/s 目标。
3. **需要更高**:方案C 多腿条带化聚合。
4. **方案D(KCP)** 需换网络环境单独验证,与前三者正交。

> 注:方案A 涉及发送语义改动(不再逐 Write 等 ACK),需补单测覆盖"错误传播 + 关闭 drain",避免丢数据。建议我先在 worktree 里实现方案A+B 并压测,拿到真实数字再决定是否上条带化。
