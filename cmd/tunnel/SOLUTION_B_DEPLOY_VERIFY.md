# 路线 B 跨境部署验证报告

**验证时间**: 2026-06-27
**拓扑**: 跨中继(本地→relay1→跨中继→relay2→tunserver→HTTP)
**结论**: ⚠️ **路线 B 代码逻辑正确，但在大陆→香港链路上无法发挥 KCP 优势——KCP(UDP)被跨境网络阻断，且桥接 peerConn 本身就是 TCP**

---

## 1. 部署拓扑

```
本地(大陆 111.0.0.2)   38(香港,relay1)      104(美国,relay2+tunserver+http)
       │                        │                        │
       │ ① client连relay1(TCP)  │                        │
       ├───────────────────────>│                        │
       │                        │ ② relay2主动连relay1    │
       │                        │<───────────────────────┤ (控制链路✓)
       │ ③ 连tunserver(跨中继)   │   relay1→relay2 peerConn │
       │   relay1 FIND relay2 ──→├───────────────────────>│
       │                        │                        │
       │ ④ HTTP 20MB: 本地←relay1←relay2←tunserver←http(104)
```

- relay1 = 38:9000(香港，nodeserver index 模式)
- relay2 = 104:9001(美国，注册到 relay1，控制链路建立成功)
- tunserver = 104，注册到本机 relay2
- httpserver = 104:5173，20MB 文件
- client = 本地(大陆)，连 relay1

---

## 2. 关键发现

### 2.1 跨中继隧道全线打通 ✅
- client `已建立隧道连接`，health 经隧道返回 `{"status":"ok"}`
- 两个 relay 控制链路成功建立、互相登记
- 路线 B 的 dual 拨号 + KCP 优先建桥逻辑**正确运行**（日志可见等待窗口生效）

### 2.2 决定性发现：大陆→香港 KCP(UDP) 不通 ❌

relay1(38) 接入日志显示，client(大陆 111.0.0.2)到 relay1 的连接：
```
remote=111.0.0.2:12796 → nodeId=d51ea34a (client注册)
remote=111.0.0.2:12797 → nodeId=7a18236b (连tunserver)
```
**两条都是 TCP 连接，没有任何 KCP(UDP)连接到达 relay1。**

把 `kcpWaitWindow` 从 400ms **调大到 5s 重测，KCP leg 仍未到达**：
```
18:26:59 KCP leg 未在 5s 内到达, TCP 兜底建桥: ... leg=tcp
```
→ 不是窗口太短的问题，而是**大陆→香港的 UDP 包被跨境网络阻断/丢弃**（国际出口对 UDP 的常见 QoS 限制）。这正是当初改单 leg 的深层原因之一。

### 2.3 第二个发现：桥接 peerConn 本身就是 TCP

`networkFrameWork/StreamBridge.go: dialRawBridgeConn`:
```go
conn, err := net.Dial("tcp4", addr)  // relay1→relay2 桥接连接写死 TCP
```
即**即使 client→relay1 的 KCP 能用，relay1→relay2 这段跨中继桥接也是 TCP**，
KCP 无法贯穿整条跨中继路径。当前架构下 KCP 只存在于「单跳 natnode↔relay」，
跨中继的 relay 间转发是裸字节 TCP。

---

## 3. 带宽数据

| 场景 | 带宽 | 说明 |
|------|------|------|
| 之前单 relay 单 leg(TCP) | 0.013 MB/s | 旧基线 |
| 本次跨中继(dual，实际 TCP 兜底) | 0.079 MB/s | 20MB 未传完(180s 仅 14.9MB) |
| 裸 HTTP + BBR(38直连) | 1.672 MB/s | 物理上限参考 |

注：0.079 vs 0.013 的差异主要来自**拓扑与路由不同**（本次 104→38→本地，且 38 已开 BBR），
**不能归因于路线 B**——因为本次实际走的仍是 TCP（KCP 没生效）。

---

## 4. 结论：路线 B 的真实价值与局限

### 4.1 路线 B 代码是正确的
- dual 拨号、KCP 优先建桥、TCP 兜底、单 leg 桥接消除竞态 —— 逻辑都按设计运行
- 本地环回/机房内（UDP 通的环境）能正确选 KCP（见单测 `TestCrossRelay_DualLeg_LargeTransfer`）

### 4.2 但在本场景无法提速，两个原因
1. **大陆→香港 UDP 被阻断** → client→relay1 这跳 KCP 用不了，只能 TCP 兜底
2. **桥接 peerConn 写死 TCP** → 即使首跳 KCP 可用，relay 间转发仍是 TCP

→ **整条跨境路径实际全程 TCP，KCP 完全没参与，路线 B 对跨境带宽无贡献。**

---

## 5. 真正的优化方向（修正后）

| 方向 | 可行性 | 说明 |
|------|--------|------|
| **桥接 peerConn 改用 KCP** | ⭐⭐⭐ | 改 `dialRawBridgeConn` 用 KCP 拨号；relay 间(38↔104 机房级)UDP 通，KCP 能在太平洋段发挥拥塞控制优势 |
| **TCP 层 BBR**（当前最有效） | ⭐⭐⭐ | 既然全程 TCP，给所有 relay 机器开 BBR 是最直接的提速（已验证单跳 27 倍） |
| client→relay1 改善 | ⭐ | 大陆→香港 UDP 受限，KCP 难用；可考虑换 UDP 不被限的线路或保持 TCP+BBR |
| mux 滑动窗口 | ⭐⭐ | 解决停等，与传输层正交 |

### 5.1 重点建议
路线 B 对「UDP 可达」的链路（如 relay 间、海外节点间）有效；
但大陆出境的客户端首跳，KCP 往往不可用。**当前最高性价比仍是：所有 relay 开 BBR + 桥接 peerConn 改 KCP（针对 relay 间 UDP 可达段）**。

---

## 6. 代码状态
- `kcpWaitWindow` 已恢复 400ms
- 路线 B 改动保留（逻辑正确，对 UDP 可达场景有效）
- 远程/本地测试进程已全部清理

**下一步建议**：改造 `dialRawBridgeConn` 用 KCP 拨号（让 relay 间走 KCP），
再在 38↔104 这种 UDP 可达的机房级链路上验证带宽提升。
