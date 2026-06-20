# index / bootstrap 续写 — 三机真机测试报告

> 日期: 2026/06/20　分支: dev_local
> 拓扑脱敏: server1=10.10.0.1(香港/index), server2=10.10.0.2(国外/relay), server3=10.10.0.3(callee)
> 原始日志见 `raw_logs/`(公网 IP 已在本报告脱敏, 日志保留真实内容)。

## 目标

验证本次续写的四项新能力(node 层启动/注册编排):
1. RelayNode 启动后自动向 index 注册成为邻居。
2. NatNode 启动时向 index 查询 relay 列表, 按 XOR 距离就近选 relay 注册。
3. 目标 relay 不可达时回退次近(直至回退 index)。
4. index 启动入口(无上级的 RelayNode) + 两个 main 接线。

## 真机网络条件(实测)

| 链路 | 9000 端口可达性 |
|------|----------------|
| server1 ↔ server2 | ✔ 双向可达 |
| server1 ↔ server3 | ✔ 双向可达 |
| **server2 ↔ server3** | ✘ **不可达**(i/o timeout) |
| 本机/server3 → server2 | ✘ 不可达(server2 在国外, 需 server1 香港做 SSH 跳板部署) |

`server2↔server3 不可达`是天然条件, 正好触发「不可达→回退」分支。
部署: server2 经 `ssh -J root@server1` 跳板 + 本机密钥登录(server1 自身密钥无 server2 凭证)。

## 角色编排

- server1: `relaychat -mode index -listen 0.0.0.0:9000 -public <s1>:9000`
- server2: `relaychat -mode relay -listen 0.0.0.0:9000 -public <s2>:9000 -index <s1>:9000`
- server3: `relaychat -mode listen -index <s1>:9000`(callee)
- client: 起在 server1 上(唯一能到达 server2:9000 的位置), `-mode connect -index <s1>:9000 -target <callee>`

## 结果

### ✅ 四项新能力全部真机验证通过

1. **relay→index 注册** ✔ — server2 relay 启动即与 index 建控制链路, index 状态打印
   `relay邻居=1 [relay邻居] id=931ba35e… addr=<s2>:9000`。重启 index 后 server2 经 peerLink
   重试自动重新注册(relay邻居 恢复 1), 证明链路级重连有效。
2. **natnode 查询 index 拿 relay 列表** ✔ — 两端日志均
   `[natnode] index <s1>:9000 返回 2 个 relay`。
3. **就近可达 relay 选择** ✔ — server1 上的 client(可达 server2)
   `[natnode] 选定就近可达的子 relay 作为入口: <s2>:9000`, 并在 server2 上登记为托管 NAT 节点。
4. **不可达→回退 index** ✔ — server3 callee
   `relay <s2>:9000 不可达: i/o timeout` → `无可达子 relay, 回退注册到 index: <s1>:9000`。
   这正是「目标 relay 不可达切次近(此处无次近→回退 index)」的真机复现。
5. **跨中继 FIND + 桥接建立** ✔ — server2 relay 经控制链路 FIND 到 index(托管 callee), 建桥:
   `[relaynode] 跨中继桥接建立: target=8743aba3… via relay=<s1>:9000 leg=tcp`。
6. **本地转发数据面 3/3 轮** ✔ — 两个都回退到 index 的 natnode(server3 callee + server3 client),
   经 index 本地转发: `通信完成: 成功 3/3 轮`(echo:localfwd-0/1/2)。

### ✅ 跨中继桥接端到端数据轮 — 已定位根因并修复, 真机 3/3 轮通过

client(server1)→server2(relay)→[桥接回]→index(托管 callee)→callee(server3) 这条
**非对称双 relay 桥接**路径, 此前端到端 TLS 握手失败:
```
callee: 握手失败: TLS 握手失败: wrong Salt format: 期望 "salt|sign", 收到 1 段 (payloadLen=130)
```

**根因(已用真机帧级日志定位)**: callee 在 TLS 握手里收到了**两份公钥**, 把后续 salt 帧顶到了
错误的读取位置。帧级证据(在 server2 桥接腿抓到, 解出帧头):
```
msgId=1 ftype=2(Retransmit) payloadLen=384  ← 客户端首帧(routing-hello/公钥)的【重传】
msgId=2 ftype=0(Data)       payloadLen=384  ← TLS 握手公钥
msgId=3 ftype=0(Data)       payloadLen=383  ← salt
```
入口 relay(server2)在 `AcceptTcpStreamSync` 同步读走客户端首帧用于路由, 再改发自己合成的
hello 给对端 relay —— 客户端这条**首帧根本不会到达真正的 callee**, 故端到端 ACK 永远回不来。
桥接路径当时**故意不在本地 ACK 首帧**(注释原话「首包 ACK 由对端真正的 nat 节点端到端回来」,
此前提对桥接不成立)。客户端 `recvAckTimer` 超时(`recvAckIdleTimeout=1s`)后**重传首帧**,
该重传帧经裸字节 splice 透传到 callee, 成为**第二份公钥**, 握手错位。

**为何进程内单测一直绿**: 进程内握手 <1s 完成, 重传定时器(1s)从不触发; 唯有跨公网高延迟
(双跨洲)路径才稳定复现。

**修复**(`networkFrameWork/TransportCoverStream.go`, isBridge 分支): 在把流交给桥接 handler 前
调用 `stream.AckFirstMessage()` 本地补发首帧 ACK。该首帧已被入口 relay 消费用于路由, 本地 ACK
语义正确; 首帧之后的真实 TLS 负载仍由对端 callee 端到端 ACK, 不受影响。

**修复后真机验证**(client@server1→server2→桥接→index 托管 callee@server3):
```
[natnode] 选定就近可达的子 relay 作为入口: <s2>:9000
正在跨中继连接 target 99d425ef… → 已连接
通信完成: 成功 3/3 轮 (echo:bridgefix-0/1/2)
```
callee 侧帧序列恢复正常(公钥仅一份): `hello(130) → 公钥(130) → salt(129) → metadata(187)`,
SetCryptoSuite 成功, 无 "wrong Salt format"。

## 结论

本次续写的 index/relay 注册 + natnode bootstrap 就近选择 + 不可达回退 四项能力, 三机真机
全部验证通过。跨中继桥接路径(非对称双 relay)此前的端到端 TLS 首包错位已**定位根因(桥接路径
未本地 ACK 首帧 → 客户端重传 → callee 收到双份公钥)并修复**, 修复后真机 3/3 轮通过。

进程内单测(含 -race): relayquery 编解码 / natnode bootstrap 选择 / relaynode 跨中继集成
(`TestRelayNode_CrossRelayBridge` 2.1s, `TestRelayNode_FindMiss` 2.1s) 全绿。
natnode 进程内通信测试(`TestNATNode_ThreeNodeDiscovery` 等)的本机超时是预存 KCP 调度环境问题
(见记忆 natnode-inprocess-tests-flaky, 干净树同样复现), 非本次回归。
