# 混合路线实现方案（轻流复用 / 重流独连）+ ForwardHook 统计保证

> 日期：2026/06/19　承接 `mux_single_connection_decision_20260619.md` 第 4 节"路线 C 混合"。
> 决策已定：轻流复用一条 server↔relay 连接，重流走独立连接。新增硬约束：重流必须被
> `ForwardHookFunc` 统计到，并在验证报告里顺带验 ForwardHook。

---

## 0. 关键实现事实（决定方案形状）

1. **relay 把同一 group 的所有 client 都走 preferred callee leg**（`pumpClientToRelay`→共享 `relayFrame`→preferred；
   多余 leg 仅 failover）。⇒ 给同一 nodeId 的 group **加 callee leg 不能隔离重流带宽**。
2. **真正隔离两条路**：
   - (甲) relay 改造：按 connectionId 把指定 client 路由到专用 callee leg —— **动最脆弱的 dual-leg pump，风险高**。
   - (乙) **重流用单独 identity（keypair）注册 → relay 自然建一个独立 StreamGroup → 独立 pump → 带宽隔离，
     不碰 relay**。✅ 采用乙。
3. **ForwardHook 按 StreamGroup 注入**（`TransportCover.SetForwardHook` → 每个新建 group 都 `SetForwardHook`，
   见 `TransportCoverStream.go:158`）。⇒ 重流的独立 group **自动被同一 hook 配置统计**，与轻流 group 同口径。
   ForwardHook 统计重流 = **天然满足**（重流照样过 relay，且每个 group 都挂 hook）。
4. 测试 relay 走 `NewRelayStarter`，可经 `starter.Cover().SetForwardHook(cfg)` 装 hook（`relayStarter.go:88` `Cover()`）。

---

## 1. 架构

- **轻流**：callee 注册一个"共享 identity S"，其上跑 `EndpointFrameMux`（已实现），N 个轻流复用这一条 callee↔relay 连接。
- **重流**：每个重流由 callee 用"专用 identity D_i（独立 keypair）"注册 → relay 建独立 group_i → 该重流独占 callee↔relay 连接，
  跑原始 1:1 终结流（不复用、不 HOL）。重流 client 直接 target D_i 的 nodeId。
- **relay 不改**：S 和各 D_i 都是普通注册 → 各自独立 group + 独立 pump + 各挂同一份 ForwardHook 配置。
- **ForwardHook**：在 relay 上经 `Cover().SetForwardHook` 装一次，**自动覆盖 S 与所有 D_i**，轻流重流同口径累计。

---

## 2. "重流"如何判定（唯一待拍板的 fork）

- **(A) 上游显式声明（upfront，推荐先做）**：flow 建立时即知重轻（测试用 `-heavy` flag；真实场景由 RouteName/应用 hint）。
  重流从一开始就 target 专用 identity。**无需运行时迁移**，最简单、最稳，足以验证机制 + ForwardHook。
- **(B) 运行时大象流检测 + 迁移（完整自适应，后续）**：所有流先上共享 S；callee 用现有帧大小自适应器按流测吞吐，
  越阈值即判为大象 → 发控制消息让该 client **重连**到新 D_i（detect-and-reconnect，非热迁移，简单可靠）。
  工作量大（控制协议 + 动态注册 + client 重连），建议二期。

> 本期建议走 **(A)**：先把"轻流复用 + 重流独连 + ForwardHook 全覆盖"跑通验证；(B) 的大象检测复用
> 现成吞吐口径，留作二期增量。

---

## 3. 改动清单（按 (A)）

1. **`pacakgeTest/relayServer.go`**
   - relay（`Server`/`mode=server`）：装 ForwardHook —— `starter.Cover().SetForwardHook(cfg)`，cfg 的 `ThresholdBytes`
     设小值（如 256KB）、`Hook` 打印累计 `ForwardStats`、`ErrorHook` 打印错误。用于验证 hook 在轻流/重流两类 group 上都触发。
   - callee（`mode=relayServer`）：
     - 默认注册"共享 identity"跑 `EndpointFrameMux`（轻流）。
     - 新增 `-heavyIdentities N`：再注册 N 个独立 identity，各跑原始 1:1 终结流（重流），各自打印 nodeId。
   - client（`mode=client`）：保持 follower；`-targetId` 指向共享或某专用 identity 即可（由编排决定轻/重）。
2. **无框架层改动**：relay / StreamGroup / frame_adapter 不动；ForwardHook 复用现成链路。
3. **（二期 B 才需要）** 控制消息 + 动态注册 + client 重连 + 大象检测。

---

## 4. 验证（含 ForwardHook）

真机：relay=server1，callee=server2，重流 client=server3 + 本机其一，轻流 client=本机其余。
- **轻流**：≥2 个 client target 共享 identity → 经 `EndpointFrameMux` 复用一条连接（一条注册连接 + 多 client leg）。
- **重流**：1~2 个 client 各 target 一个专用 identity → 各自独立 group / 独立连接 → 不互相 HOL、各自满吞吐。
- **ForwardHook 验证**：relay 日志显示 hook 在**共享 group 与每个专用 group 上都按阈值触发**、`ForwardStats`
  累计字节随转发增长；两个方向（client_to_relay / relay_to_clients）都计。可加一轮 `ErrorHook` 触发（hook 返回 error →
  该方向转发停 → 对端超时）复刻既有 hooktest 的 Phase B。
- 判读：轻流复用连接成立、重流独连不被轻/重互相饿死、`0 重复/0 解析失败`、ForwardHook 全覆盖且口径正确。
- 抓完整原始日志（relay/callee/各 client）+ 写报告；server IP 脱敏 RFC1918。

---

## 5. 已拍板（2026/06/19）

1. **重流判定 = (B) 运行时大象流检测 + 重连迁移**。
2. **ForwardHook 验证 = 只统计 server 端（callee 各 group）的转发流量**；client 端不做 per-client 细分；
   只验累计/覆盖，**不做** ErrorHook 停转发那一轮。
3. **认可"重流独立 identity 注册 = 独立 group（不碰 relay）"**。

## 6. 落地设计（B，全部落在 `pacakgeTest/relayServer.go`，不动框架层）

**relay（mode=server）**：`starter.Cover().SetForwardHook(cfg)`。cfg.ThresholdBytes 设小值（如 512KB），
Hook 打印该 group 累计 `ForwardStats`（含 direction）。每个 group（共享 S + 各重流 D_i）自动各挂一份 →
server 端总流量 = 各 group 累计之和。ErrorHook 仅打印、不返回 error（不停转发）。

**callee（mode=relayServer）**：
- 注册共享 identity S → `EndpointFrameMux` → 每 connectionId 一个 `serveMuxConn` handler（轻流默认路径）。
- **大象检测**：`serveMuxConn` 内周期采样本流入站速率（TrafficMonitor 的 Rx 速率 / 现有吞吐口径）；
  持续 > 阈值（如 >Xs 内 >Y KB/s）判为大象。
- **迁移发起**：判为大象后 callee：① 用**新 keypair** `TryRegisterRelayStream` 注册专用 identity D_i，
  起一个原始 1:1 终结 handler 等待迁入；② 通过该轻流给 client 发**迁移指令**消息
  （`RouteName="/test/migrate"`，payload=D_i 的 nodeId）；③ 停掉这条共享轻流。
- 专用 group D_i 由 relay 自然新建 → 独立 pump → 独立 ForwardHook 累计（重流被统计）。

**client（mode=client）**：TrafficMonitor 的 receiver 检到 `RouteName=="/test/migrate"` 的消息 →
停当前 TrafficMonitor → 用 payload 里的 nodeId 重新 `ConnectNodeWithTargetRelay` → 重启 TrafficMonitor
（迁到专用连接，独占带宽，不再与轻流 HOL）。

**验证**：relay=server1，callee=server2，client=server3 + 本机。先都上共享 S；其中一个发满（大象）→
被检测 → 迁到专用 identity → 独占连接吞吐恢复，另一条轻流不再被饿死。ForwardHook 日志显示
S 与 D_i 两个 group 都在累计。抓全日志 + 报告，IP 脱敏。
