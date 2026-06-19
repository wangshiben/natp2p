# RelayNode 转发 Hook 端到端验证报告

- 日期: 2026-06-19
- 时间戳目录: `hooktest_20260619_083532`

## 目标（对应需求 1）

在 `p2pnode/impl/relaynode` 中新增转发 hook 功能：

- relayNode 每转发帧累计到指定大小（阈值），就自动调用一次 hook；
- hook 返回 `nil` 才继续转发；
- hook 返回 `error` 则执行 errorHook（**结构体参数** `ForwardErrorInfo` 传递错误上下文），并**停止该方向的转发**。

## 拓扑（三服务器，与需求规划一致）

```
caller (server2, 172.20.118.47) ──register/connect──▶ relayServer (server1, 10.146.83.21:9000)
                                                              ▲  转发 hook 在此触发
                                                              │  跨中继桥接
                                                              ▼
echo-server (server3, 192.168.66.213) ──register──▶ relayServer (server1)
```

- server1 (`10.146.83.21`)：充当 relayServer，启用转发 hook。
- server2 (`172.20.118.47`)：client 端（connect 模式），跨中继向 server3 发送多轮数据。
- server3 (`192.168.66.213`)：server 端（listen 模式），回显收到的每条消息。
- server2 与 server3 之间无法直连，全部流量经 server1 中继 —— 正好驱动 relay 的转发 hook。

> 注：真实公网 IP 已在所有日志中以随机内网 IP 替换。

## 新增的类型与 API

定义在 `networkFrameWork/forward_hook.go`，并在 `p2pnode/impl/relaynode/forward_hook.go` 中以类型别名导出：

```go
// 每转发到指定大小时调用；返回 nil 继续转发，返回 error 触发 ErrorHook 并停止该方向转发。
type ForwardHookFunc func(ctx context.Context, stats *ForwardStats) error

// errorHook 用结构体参数传递错误上下文。
type ForwardErrorInfo struct {
    Stats     *ForwardStats // 触发错误时的转发统计
    Err       error         // hook 返回的错误
    Direction string        // 转发方向: "client_to_relay" / "relay_to_clients"
}
type ForwardErrorHookFunc func(ctx context.Context, errorInfo *ForwardErrorInfo)

type ForwardStats struct {
    TotalBytes  int64          // 自上次 hook 以来累计转发字节数
    TotalFrames int64          // 自上次 hook 以来转发帧数
    LastFrame   *network.Frame // 最后一个转发的帧（只读）
}

type ForwardHookConfig struct {
    ThresholdBytes int64                // 触发 hook 的累计字节阈值
    Hook           ForwardHookFunc
    ErrorHook      ForwardErrorHookFunc
}
```

配置入口：`RelayNode.SetForwardHook(config *ForwardHookConfig)`（须在 `Start()` 前调用）。
配置下沉链路：`RelayNode → TransportCover.SetForwardHook → 新建 StreamGroup.SetForwardHook →
pumpClientToRelay / pumpRelayToClients`，在两个方向的 frame pump 中按帧累计、达阈值调用 hook。

## 验证流程与结果：通过 ✓

### Phase A —— 成功路径（hook 始终返回 nil）

参数：`-threshold 131072`（128KB 触发一次）、`-failat 0`（永不失败）；client 发 50 轮 × 14336 字节。

- server1 relay 日志 `server1_relay_phaseA.log`：hook 每累计约 131KB 触发一次，全部返回 nil，转发不中断。
  ```
  [HOOK #3] 本次累计转发 131280 字节 / 166 帧, 累计总转发 394470 字节
  ...
  [HOOK #14] 本次累计转发 131689 字节 / 143 帧, 累计总转发 1841897 字节
  ```
- server2 client 日志 `server2_connect_phaseA.log`：
  ```
  已连接到 c2fcb74c...443c, 开始 50 轮通信 (每轮 14336 字节)
  → 已完成 50/50 轮
  通信完成: 成功 50/50 轮, 共发送约 716800 字节
  ```
- 结论：hook 返回 nil → 转发持续进行，端到端 50/50 轮全部成功。

### Phase B —— 错误路径（第 3 次 hook 返回 error，触发 errorHook）

参数：`-threshold 131072`、`-failat 3`（第 3 次 hook 调用主动返回 error）。

- server1 relay 日志 `server1_relay_phaseB.log`：
  ```
  [HOOK #1] 本次累计转发 131902 字节 / 171 帧, 累计总转发 131902 字节
  [HOOK #2] 本次累计转发 131180 字节 / 159 帧, 累计总转发 263082 字节
  [HOOK #3] 本次累计转发 131280 字节 / 166 帧, 累计总转发 394362 字节
  [ERROR-HOOK] 转发被终止!
      方向(Direction): client_to_relay
      错误(Err): 模拟业务拒绝: 第3次hook主动返回error(已转发394362字节)
      触发时统计(Stats): 字节=131280 帧数=166
  ```
- server2 client 日志 `server2_connect_phaseB.log`：转发停止后客户端无法继续，
  ```
  → 已完成 10/50 轮
  第 12 轮发送失败: send message: max retransmits exceeded
  通信完成: 成功 12/50 轮, 共发送约 172032 字节
  ```
- 结论：hook 返回 error → errorHook 被调用并收到完整结构体参数（Direction / Err / Stats）→
  该方向转发停止 → 客户端后续发送因得不到中继转发而超时。**符合需求预期**。

## 单元测试

`networkFrameWork/forward_hook_test.go` 4 项全部通过（`go test ./networkFrameWork/ -run TestForwardHook -v`）：

- `TestForwardHookTriggersOnThreshold` —— 累计达阈值触发一次。
- `TestForwardHookErrorTriggersErrorHook` —— hook 返回 error 触发 errorHook 并返回停止信号、结构体参数正确。
- `TestForwardHookNilConfigNoop` —— 未配置时不影响转发。
- `TestForwardHookAccumulatesAcrossFrames` —— 多帧累计与阈值后重置正确（9 帧触发 3 次）。

## 原始日志清单

- `server1_relay_phaseA.log` / `server1_relay_phaseB.log` —— relay（server1）成功/错误两阶段日志。
- `server2_connect_phaseA.log` / `server2_connect_phaseB.log` —— client（server2）两阶段日志。
- `server3_listen_phaseA.log` / `server3_listen_phaseB.log` —— echo-server（server3）两阶段日志。

## 验证程序

`cmd/hooktest/main.go`（三模式：relay / listen / connect，flag 驱动），与 `cmd/relaychat` 风格一致。
