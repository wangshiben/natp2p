# 跨 Relay 通信测试报告（真实链路）

> 测试时间：2026-07-02
> 拓扑：natClient + natServer **均在本机**；relayServer=**129.0.0.1**（server3），indexServer=**193.0.0.1**（server4），两台国内云服务器。
> 结论：**端到端通信成功、连接稳定、20MB×3 完整性校验全部通过**。
> **重要限定**：本次真实链路上 **KCP(UDP) 未能穿透**，隧道实际走 **双 TCP failover**。因此本报告确证的是「跨 relay 端到端可靠 + 方案A 在 TCP leg 上无误杀」，**KCP-over-真实链路 未被覆盖**（原因是本机所在网络的 UDP 回程被运营商 NAT 阻断，与本次代码改动无关）。详见 §4。

---

## 1. 拓扑与部署

```
                        indexServer (193.0.0.1:9000)
                              ▲ 注册/bootstrap
                              │
本机 natClient ──隧道──▶ relayServer (129.0.0.1:9000) ◀──注册── 本机 natServer
  (tunclient:18888)         (中继转发)                              (tunserver→httpfileserver:15173)
```

| 组件 | 位置 | 进程 | 状态 |
|---|---|---|---|
| indexServer | 193.0.0.1 (server4) | `nodeserver -mode index -listen :9000` | ✅ 就绪，nodeId=cb33e4ab1bcdc4ba |
| relayServer | 129.0.0.1 (server3) | `nodeserver -mode relay -index 193.0.0.1:9000` | ✅ 就绪并注册到 index，nodeId=51061038e22fd1f0 |
| httpfileserver | 本机 | 20MB 源站 :15173 | ✅ |
| natServer (tunserver) | 本机 | `-relay 129… -index 193…` | ✅ nodeId=ccd9503437c66fda |
| natClient (tunclient) | 本机 | `-target <server> -relay 129… -index 193…` | ✅ 隧道已建立 |

控制链路：relay(129) ↔ index(193) 双向控制链路建立成功（日志 `控制链路已建立`、`已注册到 index`）。

## 2. 执行

远端（一次性）：
```bash
# 193: index
nodeserver -mode index -listen :9000 -public 193.0.0.1:9000
# 129: relay 注册到 193
nodeserver -mode relay -listen :9000 -public 129.0.0.1:9000 -index 193.0.0.1:9000
```
本机：`httpfileserver` + `tunserver` + `tunclient`（relay=129，index=193），经隧道 `curl` 拉取 20MB 文件三次。

## 3. 结果

### 3.1 连通
| 步骤 | 结果 |
|---|---|
| index(193) 启动 + UDP/TCP :9000 监听 | ✅ |
| relay(129) 启动并注册到 index | ✅ 控制链路双向建立 |
| natServer 经 relay 注册 | ✅ nodeId=ccd9503437c66fda |
| natClient 建立隧道 | ✅ `已建立隧道连接` |
| health（经隧道跨 relay） | ✅ `{"status":"ok"}` |

### 3.2 20MB 文件传输（跨 relay，三次）
| 迭代 | HTTP | 大小 | 耗时 | 吞吐 | SHA256 |
|---|---|---|---|---|---|
| 1 | 200 | 20,971,520 | 101.77 s | 0.19 MB/s | ✅ 一致 |
| 2 | 200 | 20,971,520 | 102.50 s | 0.19 MB/s | ✅ 一致 |
| 3 | 200 | 20,971,520 | 104.26 s | 0.19 MB/s | ✅ 一致 |

源站 SHA256 = `d8d30193b09352c7892b853fec49747e6c011c55147e8cda4b3d30d56193f728`，三次下载全部逐字节一致。跨 relay 端到端历时约 5 分钟连续传输，逻辑连接全程未中断。

### 3.3 方案A 在真实链路上的表现（TCP leg）
- 全程 **无 `keepLive 判死` / `unreachable`（存活探测误杀）**。
- 仅一次 `TCP leg 失败, 关闭并触发重连`（14:07:27），并 `TCP 重连成功 第1次尝试` 立即恢复 —— 属正常的单 leg 抖动自愈，逻辑连接未断、传输未受影响。
- 说明：方案A 的「指数退避 6 次探测判死 + 应用重传对可靠底层退让」在真实跨境链路上**不误杀、不雪崩**，与设计一致（在 TCP leg 上得到验证）。

## 4. 关键限定：KCP(UDP) 未穿透，本次走双 TCP（诚实记录）

### 4.1 现象
- 本机 tunclient 日志：`[Dialers] KCP 不通, 补第二条 TCP leg 组成双 TCP failover`。
- relay(129) 日志：测试时段内**只有 `AcceptTcpStream 成功`**（来自本机 egress `111.0.0.3`），KCP 侧持续 `ListenKCPConnection error: timeout: connection closed`。
- 原始 KCP 探测（本机→129:9000，绕过所有应用逻辑，直接 `kcp.DialWithOptions` + Write/Read）：**Write 成功、Read 10/10 全部 timeout**。

### 4.2 原因（网络层，非代码）
- 本机 egress 为**中国移动 IPv6（`2409:8a02:…`）+ IPv4 CGNAT（`111.0.0.3`）**的移动/运营商 NAT 环境。
- TCP 能经 IPv4 CGNAT 建连（有连接状态、回程可穿）；**KCP 的 UDP 回程被运营商 NAT 丢弃**（无连接状态、UDP 入站被过滤）——即经典的「家庭/运营商 NAT UDP 回程不通」。
- relay 侧 UDP:9000 监听正常（`ss -ulnp` 有 fd）、出站 UDP 能到达 relay（Write 成功），**唯独 relay→本机 的 UDP 回包到不了**。
- **这与本次 keepalive/ARQ 改动无关**：任何应用层超时/重传策略都无法让被运营商丢弃的 UDP 包穿透。

### 4.3 影响
- ✅ 已确证：跨 relay 端到端可靠、完整性、稳定性（TCP 路径 + 方案A 在 TCP leg 无误杀）。
- ⚠️ 未覆盖：**KCP-over-真实链路** 的存活探测/双重 ARQ 修复效果。方案A 对 KCP 的价值（跨境 KCP 丢包下不误杀、不雪崩）本次**无法在此客户端网络证实**——因为 KCP 根本没跑起来。
- 吞吐 0.19 MB/s 低，是**双 TCP failover 经单条跨境中继**的结果（且 TCP 跨境 + 加密 + 组帧 + relay 转发），非 KCP 路径、也非方案A 的性能特征。

### 4.4 要真正验证 KCP-over-真实链路，需满足其一
1. 换一个 **UDP 回程可通** 的客户端网络（有公网 IP 或宽松 NAT 的机房/家宽），再跑同一套；
2. 或在**两台云服务器之间**（如 129 作 client 侧、193 作 server 侧，彼此云网络 UDP 互通）跑 natClient/natServer，relay 用第三台——把「客户端」从受限的移动 NAT 挪开。

## 5. 与本机报告的关系
- 《本机测试报告》：loopback 全栈，功能/完整性/无误杀/吞吐基线（~18 MB/s）通过。
- 本报告：真实跨 relay（index/relay 在国内云）端到端通过，方案A 在真实 TCP leg 上无误杀；KCP 因客户端网络 UDP 受限未穿透。
- **两份都无法单独证实「KCP 在真实链路上的方案A 修复效果」**——loopback 无丢包不触发，真实链路 KCP 未穿透。这是当前测试环境（移动 NAT 客户端）的客观限制，已如实记录，建议按 §4.4 补测。

## 6. 复现命令（备查）
```bash
# 远端
ssh server4 'nodeserver -mode index -listen :9000 -public 193.0.0.1:9000'
ssh server3 'nodeserver -mode relay -listen :9000 -public 129.0.0.1:9000 -index 193.0.0.1:9000'
# 本机（relay=129 index=193）
httpfileserver -port 15173 -size 20
tunserver  -target 127.0.0.1:15173 -relay 129.0.0.1:9000 -index 193.0.0.1:9000
tunclient  -target <serverNodeID> -listen 127.0.0.1:18888 -relay 129.0.0.1:9000 -index 193.0.0.1:9000
curl -o /dev/null http://127.0.0.1:18888/file
# 定位 KCP UDP 是否穿透（绕过应用层）
kcp.DialWithOptions("129.0.0.1:9000") → Write ok / Read timeout ⇒ UDP 回程被阻断
```
