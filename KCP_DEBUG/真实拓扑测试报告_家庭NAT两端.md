# 跨中继隧道吞吐测试报告（正确拓扑：client + natserver 均在本机）

> 测试日期：2026-07-04（修订版）
> 分支：`feat/pipeline`（对应远端 `dev_local`）
> **本报告纠正此前 `优化后测试报告_方案AE.md` 的拓扑错误，以此版为准。**

---

## 0. 为什么有这份修订

此前的报告把 **client 和 relay1 放在同一台机（server3，走 loopback）、natserver 和 relay2 放在同一台机（server4，走 loopback）**，导致真正的跨区链路只有 relay1↔relay2 一段，client/natserver 那两跳全是零 RTT 的假链路。那批数据（868 / 1163 / 2543 KB/s）**不代表真实端到端吞吐**。

本报告采用正确拓扑：**client 和 natserver 都在本机（家庭 NAT 后），两个 relay 才是云服务器**。

---

## 1. 结论速览

```
本机(client) ──1条conn──▶ relay1(server3) ◀──KCP桥互联──▶ relay2(server4) ──1条conn──▶ 本机(natserver) ──▶ httpfile
      └────── 家庭NAT上行 ──────┘                                           └────── 家庭NAT下行 ──────┘
```

| 配置 | 1MB 探测 | 50MB 下载 | SHA |
|---|---|---|---|
| 默认（家庭两跳含 KCP） | 17 KB/s | 超时跑不完 | — |
| **`BNFS_DISABLE_KCP=1`（本机两端纯 TCP）** | 301 KB/s | **229 KB/s** | ✅ 一致 |

- **家庭 NAT 两跳必须禁用 KCP**：本机在中国移动 CGNAT 后，KCP 的 UDP 回程建不起来，默认走 KCP 会陷入重传风暴，吞吐塌到 17 KB/s、50MB 根本跑不完。
- 禁 KCP 走纯 TCP 后稳定在 **229 KB/s**，50MB 完整传输、SHA256 一致。
- 云↔云那段桥接（relay1↔relay2）走 KCP 正常（UDP 在云间可达），日志已确认。

---

## 2. 测试环境

| 项 | 值 |
|---|---|
| client + natserver + httpfile | **本机**（家庭移动网络，公网出口 IPv6 `2409:…`，IPv4 为 CGNAT） |
| relay1（client 侧入口 / index / 桥接拨号方） | server3（`129.0.0.1:9010`，`BNFS_BRIDGE_KCP=1`） |
| relay2（natserver 侧出口） | server4（`193.0.0.1:9000`） |
| 测试文件 | 50 MB（本机 httpfileserver，SHA256=`7c1e31c9…`） |

**本机裸带宽基准（scp，不经隧道）**：

| 方向 | 速率 |
|---|---|
| 上行（本机→server3） | 2,695 KB/s |
| 下行（server3→本机） | 575 KB/s ← **物理瓶颈，链路严重不对称** |

---

## 3. 数据流与瓶颈分析

50MB 文件的真实路径：

```
httpfile(本机) → natserver(本机) →[家庭上行]→ relay2(云) →[云KCP桥]→ relay1(云) →[家庭下行]→ client(本机)
```

- 数据先从本机上行到云（natserver→relay2），再从云下行回本机（relay1→client）——**双穿家庭 NAT，且串行**。
- 端到端上限受限于**家庭下行 575 KB/s**（下行段是瓶颈）。
- 实测 229 KB/s ≈ 下行上限的 **40%**。差距来自：双穿 NAT、上下行串行、隧道加解密/协议开销、移动链路间歇抖动（多次 50MB 下载在 150–233 KB/s 波动，偶尔跑不完）。

---

## 4. 三条腿的传输层选择（关键）

| 腿 | 链路 | 传输层 | 原因 |
|---|---|---|---|
| client → relay1 | 家庭上行 | **纯 TCP** | 家庭 CGNAT 下 KCP 的 UDP 回程建不起来 |
| relay1 ↔ relay2 | 云 ↔ 云 | **KCP 桥** | 云间 UDP 可达，KCP 正常，日志确认 |
| relay2 → natserver | 家庭下行 | **纯 TCP** | 同 client 侧，CGNAT UDP 回程不通 |

> 本机两端用 `BNFS_DISABLE_KCP=1` 强制纯 TCP。默认（含 KCP）时，每次发送先卡满 KCP 握手/重传超时才 fallback，吞吐塌到 17 KB/s。

---

## 5. 对优化方案的重新评估

- **方案A（accumCopy）代码本身有效、默认开启、无回归**（本机 loopback 曾测 32 MB/s，SHA 一致）。但在**家庭 NAT 端到端**场景，瓶颈是**家庭下行带宽 + 双穿 NAT**，不是应用层停等，所以提速不明显。
- **方案E（bridge-KCP）** 只对 **relay1↔relay2 云↔云那段**有效（那段 UDP 通）。它无法改善家庭 NAT 两跳（那两跳被迫纯 TCP）。
- 结论：在这个真实拓扑下，**吞吐天花板由家庭链路（尤其下行 575 KB/s）决定**，两个应用层/传输层优化能贡献的空间有限。若要显著提速，方向应是家庭链路本身（换网络/加带宽），或减少双穿 NAT 的串行开销。

---

## 6. 开关

| 开关 | 本场景取值 | 作用 |
|---|---|---|
| `BNFS_DISABLE_KCP` | 本机两端设 `1` | 家庭 NAT 下强制纯 TCP，避免 KCP 回程不通导致的卡死 |
| `BNFS_BRIDGE_KCP` | relay1 设 `1` | 云↔云桥接走 KCP |
| `TUNNEL_COALESCE_MS` | 默认 2 | 方案A 聚合窗口 |

---

## 7. 复现要点（踩过的坑）

- 本机 5173 端口被占用（sandbox 进程），httpfile 改用 5273。
- 家庭移动链路下载间歇卡顿，50MB 需放宽 curl `--max-time` 到 ~400s 才能稳定跑完取 SHA。
- 裸下行首测 55 KB/s 是超时截断假象，干净测（5MB 不截断）为 575 KB/s。
