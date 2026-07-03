# BUG: 公网客户端注册腿双TCP竞争导致隧道无法建立

> 记录于 2026-06-29。feat/pipeline 分支。待修复(用户将清空上下文后处理)。
> 严重性:高 — 任何经**公网**(非 localhost)连接 relay 的客户端都无法建立隧道。

## 现象

server4(193.0.0.1,大陆,距 HK 仅 10ms RTT)作为 tunclient 接入 natp2p,
**隧道始终建立不起来**(tunnel=0),即使 relay 全新重启也 100% 复现。

客户端(server4)日志特征:
```
本节点 ID: 3239e1bf...
目标节点:  6b006632...
使用指定 relay: 38.0.0.1:9000
正在连接目标节点 ...
[Dialers] KCP 不通, 改用第二条 TCP leg(id=tcp) 组成双 TCP failover: target=6b006632 connId=4379...  ← 拨【目标tunserver】
[Dialers] KCP 不通, 改用第二条 TCP leg(id=tcp) 组成双 TCP failover: target=3239e1bf connId=       ← 拨【自己的注册腿】(connId 空)
[DualStream] TCP startPump NextMessage 失败: nodeId=3239e1bf connId= leg=tcp err=EOF
[DualStream] TCP leg 失败, 关闭并触发重连: nodeId=3239e1bf connId=
Listen 退出: stream closed   ← 注册腿失败导致整个 Listen() 退出,客户端重试,循环
```

relay1(server1, index 模式)日志特征(关键):
```
[relay] 新连接: remote=193.0.0.1:38516
[relay] AcceptTcpStream 成功: nodeId=3239e1bf connId=        ← 注册腿第1条
[relay] 新建 StreamGroup: nodeId=3239e1bf
[relaynode] 本地托管的 NAT 节点登记到 natNodes: 3239e1bf 来源=193.0.0.1:38516
[relay] 新连接: remote=193.0.0.1:38536
[relay] AcceptTcpStream 成功: nodeId=3239e1bf connId=        ← 注册腿第2条(双TCP failover)
[relay] 附加 relay leg 到已有 StreamGroup: nodeId=3239e1bf
[FrameRelay] TCP NextFrame 失败: nodeId=3239e1bf connId= isCurrent=false err=stream closed  ← 第1条腿被顶掉
... 之后两条腿都 EOF, "关闭(relay 端不重连)"
```

## 根因分析(初判,待修复者确认)

**这是「客户端注册腿(control/registration leg, connId 空)」的双 TCP failover 与 relay
StreamGroup 的竞争**,与已修复的「数据腿」重连风暴(组A, commit aa1fe9b)是**同类问题、
不同代码路径**:
- 组A 修的是**数据腿**桥接:`relaynode.findAndBridge` / `CrossRelayBridge.SpliceLeg`
  (connId 非空的业务连接)。
- 本 bug 在**注册腿**:`TransportCoverStream.go:193-224`(connId 空的注册流)
  → `StreamGroup.AttachRelayStreamCoexist`(StreamGroup.go:107)
  → `DualStream.AttachStreamCoexist`,`coexist` 参数 = `isExtraLegMarked(message)`。

客户端的 `clientStream`(Dialers.go)为注册腿也开了双 TCP failover。第二条注册腿到达
relay1 时走 `附加 relay leg 到已有 StreamGroup` 分支(TransportCoverStream.go:217-218),
调 `AttachRelayStreamCoexist(stream, isExtraLegMarked(message))`。**怀疑第二条注册腿
没有打 legExtraMarker 标记**(或 coexist 逻辑未对注册腿生效)→ `AttachStreamCoexist`
顶替而非并存 → 第一条注册腿被关闭(`isCurrent=false ... stream closed`)→ 客户端
`Listen()` 收到 stream closed 退出 → 整个客户端循环重试,隧道永远建不起来。

## 为什么之前没暴露(关键)

- **今早能跑通的是 HK-本地客户端**(server1 上起 client,`-relay 127.0.0.1:9000`,localhost)。
  localhost 上双 TCP 两条注册腿几乎同时到达,时序竞争窗口极小,第二条 attach 时第一条
  可能尚未完成 StartListen,侥幸不触发顶替;或 RTT≈0 使两条腿状态稳定。
- **server4 经公网连 relay1(10ms RTT)**,两条注册腿到达有可观时间差,
  第一条已 `新建 StreamGroup` + StartListen 跑起来,第二条到达时顶掉它 → 必现。
- 即:**RTT 越大越容易触发**。这解释了为何 localhost/同机测试一直没暴露,
  而真实公网客户端 100% 复现。

## 复现方法

环境(SSH 别名见 [[deploy-servers]],server4 见下):
- server1(HK, 38.0.0.1):relay1,`nodeserver -mode index -listen 0.0.0.0:9000 -bridge-width 1`
- server2(US, 104.0.0.1):relay2 `-mode relay -listen 0.0.0.0:9001 -public 104.0.0.1:9001 -index 38.0.0.1:9000` + tunserver + python http :5173(20MB)
- server4(大陆, 193.0.0.1):tunclient,`-relay 38.0.0.1:9000`(公网,10ms RTT)

步骤:
1. 全新启动 relay1、relay2(确认 nodeserver 计数各=1、relay2 控制链路=1)。
   注意:本环境 `pkill -f` 对部分进程无效,需 `pgrep -f nodeserver` 拿 PID 后 `kill -9`。
2. server2 起 tunserver(`/tmp/rl_srv20b.sh`)+ python http :5173。
3. server4 起 tunclient 指向公网 relay1:
   `tunclient -target <tunserver_id> -relay 38.0.0.1:9000 -listen 127.0.0.1:8888`
   (脚本:`/tmp/s4_cli.sh`)
4. 观察:客户端 `Listen 退出: stream closed` 循环,tunnel=0,100% 复现。
5. 对照:同样的 relay,HK-本地客户端(`/tmp/hk_cli.sh`,`-relay 127.0.0.1:9000`)能建立隧道
   (今早 5MB/20MB A/B 均通)→ 证明是公网/高RTT 触发的注册腿竞争,非 relay 本身坏。

测试二进制(均 v1_head/v2_groupb/v3_pipeline 三套):
server4:/tmp/tunclient_v*,server2:/tmp/tunserver_v*。

## 涉及源码(修复入口)

- `networkFrameWork/TransportCoverStream.go:193-224` — 注册流(connId 空)attach 分支,
  第二条腿走 `AttachRelayStreamCoexist(stream, isExtraLegMarked(message))`。
- `networkFrameWork/StreamGroup.go:107` `AttachRelayStreamCoexist` → `DualStream.AttachStreamCoexist`。
- `networkFrameWork/Dialers.go:212-280` `clientStream`(dual 模式)— **已确认的关键点见下**。
- `networkFrameWork/frame_adapter.go:284-288` — `isCurrent=false` 时的 NextFrame 失败日志(现象观测点)。

### 已确认:clientStream 里两条注册腿只有一条打了 legExtraMarker

`clientStream`(Dialers.go,isDefault=true)在 **KCP 不通**时(server4 正是 KCP 不通)产生两条 TCP 注册腿:
- **第一条**:`tcp2`(Dialers.go:247-249)— `extraFirst` 经 `markExtraLeg(extraFirst)`,**打了标记 ✓**。
- **第二条**:`tcpClient`(Dialers.go:267)— 用原始 `FirstMessage`,**没打 markExtraLeg ✗**。

两条都 attach 到同一注册 StreamGroup。当**未打标记的第二条 `tcpClient` 到达 relay1**时,
`isExtraLegMarked(message)=false` → `AttachRelayStreamCoexist(stream, false)` → coexist=false
→ `DualStream.AttachStreamCoexist` 顶替而非并存 → 先到的腿被关闭(`isCurrent=false ... stream closed`)
→ 客户端 `Listen()` 退出。

注:数据腿路径(extraTCPDialer, Dialers.go:236-240)对第二条 TCP 一律 `markExtraLeg(fm)`,
所以数据腿不犯此病;**注册腿的 line 267 这条漏打了标记**,是最可疑的直接病灶。

## 修复方向(供参考,待修复者判断)

1. **(最可能)** Dialers.go:267 的 `tcpClient` 注册腿也打 `markExtraLeg`(与数据腿对称),
   使 relay 侧 coexist=true 并存。但需注意:两条腿若都打标记,要确认 relay 侧
   `AttachStreamCoexist` 在「两条都 extra」时的并存语义正确(谁是 primary)。
2. 或 relay 侧 `AttachRelayStreamCoexist`(注册腿路径,TransportCoverStream.go:218)
   **对注册腿强制 coexist=true**(注册腿天然该 failover 冗余并存,不该互相顶替)。
   这个改动面更小、更聚焦注册腿语义,可能比改客户端更稳妥。
3. 修复后验证:server4 经公网建立隧道成功 + 20MB 下载 SHA_OK + reconnect≈0;
   且 HK-本地客户端、server3 跨境不回归。

## 关联

- 数据腿同类问题修复:[[tunnel-reconnect-storm-rootcause]](组A,findAndBridge/SpliceLeg)。
- 流水线/方案A 上下文:[[tunnel-pipeline-window]]。
- 服务器/带宽数据:[[deploy-servers]] + 本会话带宽实测(见下文 memory)。
