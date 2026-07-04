# 跨中继隧道吞吐优化测试报告（方案A + 方案E）

> 测试日期：2026-07-04
> 分支：`feat/pipeline`（对应远端 `dev_local`）
> 优化提交：`perf(tunnel): 应用层 accumCopy + bridge-mux 可选 KCP`

---

## 1. 结论速览

境内两台云服务器，跨中继隧道下载 50MB 文件，逐步叠加两项优化后的实测吞吐：

| 档位 | 吞吐 | 相对基线 | SHA |
|---|---|---|---|
| **真基线**（优化前二进制，纯 `io.CopyBuffer` + TCP 桥） | 866–870 KB/s | 1.0× | ✅ |
| **+ 方案A**（应用层 `accumCopy` + TCP 桥） | 1161–1165 KB/s | **≈1.34×** | ✅ |
| **+ 方案A+E**（`accumCopy` + KCP 桥） | 2404–2655 KB/s | **≈2.8–3.1×** | ✅ |

- 三档下载文件 SHA256 全部与源文件一致（`8b5f731e…`），无数据损坏。
- **方案A 单独即让隧道稳定突破 1MB/s**；叠加方案E（桥接换 KCP）再翻约一倍。
- 两项优化正交、可独立开关，均已通过本机 loopback + 境内真链路验证。

---

## 2. 测试环境

| 项 | 值 |
|---|---|
| ingress relay / index / client 侧 | server3（公网 `129.0.0.1`，4 核） |
| egress relay / tunserver 侧 | server4（公网 `193.0.0.1`，2 核） |
| 链路 RTT（server3↔server4） | **31.46 ms**（min/avg/max 31.42/31.46/31.54，0% 丢包） |
| 测试文件 | 50 MB（httpfileserver 生成，SHA256=`8b5f731e965510b334…`） |
| 测量方式 | `curl -w '%{speed_download}'`，每档 3 次，`--max-time` 保护 |

**拓扑（数据流）**：

```
 client(server3) ──▶ relay1/index(server3:9010, loopback) ──▶ relay2(server4:9000) ──▶ tunserver(server4) ──▶ httpfile(:5173)
                     └─ client→relay1 为本机 loopback ─┘   └──── 跨区 31ms，桥接物理连接 ────┘
```

> 关键：`client→relay1` 是**本机 loopback（零 RTT）**，真正的跨区延迟全在 **relay1→relay2 的桥接物理连接**上。因此桥接层的传输协议（方案E）才是跨区吞吐的决定因素。

---

## 3. 两项优化说明

### 方案A —— 应用层 `accumCopy`（默认开启）

**问题**：原 `pipe` 用 `io.CopyBuffer`，每次 `Read` 只从源 TCP 拿回一个分段（~16KB）就 `Write` 给 mux，导致每条 mux 消息只激活 1 个并发发送、在途深度≈1，退化成停等，吞吐受限于 `payload/RTT`。

**改法**：朝 mux 写的方向改用 `accumCopy` —— 单次阻塞读拿到首段后，在 `coalesceWindow`（默认 2ms，`TUNNEL_COALESCE_MS` 可调）短窗内**贪婪 drain** 源上已就绪字节、填满 pumpBuf（512KB）再一次 `Write`，使每条 mux 消息激活 W 个并发发送（在途深度 1→W）。

- **不使用裸 `io.ReadFull`**（否则小请求如 HTTP GET 会干等填满缓冲而死锁）；首段到、短窗内无更多数据即刻 flush。
- 反方向（源为 mux stream，发端已聚合）仍用 `io.CopyBuffer`。
- 源不支持 `SetReadDeadline` 时自动回退 `io.CopyBuffer`。

### 方案E —— bridge-mux 可选 KCP（`BNFS_BRIDGE_KCP=1` 开启）

**问题**：跨中继桥接的物理连接原写死 `net.Dial("tcp4")`，跨区高 RTT 下 TCP 队头阻塞限制吞吐。

**改法**：`DialBridgeMuxSession` 拨号按 `BNFS_BRIDGE_KCP=1` 分支走 KCP（`kcp.DialWithOptions` + NoDelay/MTU/窗口调参，与 client→relay 一致）。**接受侧零改动**——框架本就在同一地址监听 UDP，TCP/KCP 两种连接进同一条 accept 路径。默认仍 TCP 兜底。开关设在 ingress relay（拨号方）即可。

---

## 4. 逐档实测数据

### 4.1 真基线（优化前二进制，无 accumCopy，TCP 桥）

> 用优化提交的父提交 `2449fbc` 构建的旧二进制，排除任何二进制差异。

| 次 | 用时 | 速率 |
|---|---|---|
| 1 | 60.55 s | 865,944 B/s |
| 2 | 60.28 s | 869,807 B/s |
| 3 | 60.34 s | 868,906 B/s |

**均值 ≈ 868 KB/s**，SHA=`8b5f731e…` ✅

### 4.2 方案A（accumCopy 默认 2ms，TCP 桥）

| 次 | 用时 | 速率 |
|---|---|---|
| 1 | 74.44 s | 704,266 B/s（首跑预热） |
| 2 | 45.14 s | 1,161,589 B/s |
| 3 | 44.97 s | 1,165,761 B/s |

**稳定后 ≈ 1163 KB/s**，桥接确认走 TCP（0 条 KCP 日志），SHA ✅

### 4.3 方案A+E（accumCopy + KCP 桥）

| 次 | 用时 | 速率 |
|---|---|---|
| 1 | 21.81 s | 2,404,028 B/s |
| 2 | 20.39 s | 2,571,351 B/s |
| 3 | 19.75 s | 2,655,031 B/s |

**均值 ≈ 2543 KB/s**，日志确认 `桥接物理连接走 KCP: addr=193.0.0.1:9000`，SHA ✅

---

## 5. 验证与回归

- **本机 loopback**（localsim 全套 5 进程，20MB）：32.5 MB/s，SHA 一致，health/checksum 小请求正常（证明 accumCopy 无死锁）。带 `BNFS_BRIDGE_KCP=1` 同样通过（无回归）。
- **relaynode 单元测试**：全绿（约 52s）。
- **networkFrameWork / nodeserver 构建**：绿。

---

## 6. 开关与调参

| 开关 | 默认 | 作用 |
|---|---|---|
| `TUNNEL_COALESCE_MS` | 2 | 方案A 贪婪 drain 短窗（ms）；越大聚合越足、小请求延迟越高；设 0 近似退回旧行为 |
| `BNFS_BRIDGE_KCP` | 未设=TCP | 设 `1` 时 ingress relay 桥接拨号走 KCP，消除跨区 TCP 队头阻塞 |

> 方案A 默认开启、无需配置；方案E 需在 ingress relay 显式 `BNFS_BRIDGE_KCP=1`，默认 TCP 兜底，极端限 UDP 环境不受影响。

---

## 7. 后续空间

当前 A+E ≈ 2.5 MB/s（曾测得峰值 3.2 MB/s，跨区链路状态波动）。相对基线约 3×，但距裸链路（此前测裸 TCP ~10 MB/s）仍有余量。下一层候选瓶颈：mux 发送窗口 W、KCP 窗口大小、单流并发条数。建议后续单独针对 W / KCP 窗口做对照测量。
