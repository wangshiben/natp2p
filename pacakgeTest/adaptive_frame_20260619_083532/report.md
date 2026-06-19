# 动态自适应帧大小 跨中继吞吐验证报告

- 日期: 2026-06-19
- 时间戳目录: `adaptive_frame_20260619_083532`

## 目标（对应需求 2）

按需求 1 规划的三服务器网络拓扑，重新测试此前修改的「30 秒间隔动态自适应帧大小」程序
（`network/FrameSizeAdaptor.go` + `network/FrameSizeMTU.go` + `networkFrameWork/TcpStream.go`），
验证在真实跨公网中继链路上：

- 帧大小变更同步协议（`FrameTypeFrameSizeChange`）双向确认正常；
- 动态自适应（800→1400 字节范围、防振荡）正常工作；
- 长时间双向打流无重复包、无解析失败、无加密错误、无连接断开。

## 拓扑（三服务器，与需求一致）

```
caller (server2, 172.20.118.47) ──┐
                                   ├──▶ relayServer (server1, 10.146.83.21:9000) ──▶ 双向中继转发
echo/callee (server3, 192.168.66.213) ──┘
```

- server1 (`10.146.83.21`)：relayServer（`-mode server`）。
- server2 (`172.20.118.47`)：caller（`-mode client`），32 sender worker 同步流水线打流。
- server3 (`192.168.66.213`)：callee（`-mode relayServer`），注册后双向打流 + 回流。
- server2↔server3 无法直连，全部流量经 server1 中继。测试时长 100 秒。

> 注：真实公网 IP 已在所有日志中以随机内网 IP 替换。server1↔server2 RTT≈194ms（高延迟公网链路）。

## 结果：通过 ✓

### caller 侧（server2，`server2_caller.log`）

```
🏆 峰值上传: 356.20 KB/s
🏆 峰值下载: 313.46 KB/s
📈 总上传: 6.50 MB (467 个包)
📈 总下载: 6.83 MB (491 个包)
🔎 Trace: unique_rx=496 duplicate_rx=0 parse_failures=0
```

### callee 侧（server3，`server3_callee.log`）

```
🏆 峰值上传: 270.71 KB/s
🏆 峰值下载: 398.95 KB/s
📈 总上传: 6.71 MB (482 个包)
📈 总下载: 6.85 MB (492 个包)
🔎 Trace: unique_rx=492 duplicate_rx=0 parse_failures=0
```

### 动态自适应帧大小

两端帧从 800 字节起步，按「连续 2 次同方向才调整」的防振荡策略增大，并通过帧大小变更
确认协议双向同步成功：

```
[FrameAdaptor] 准备 增大 帧( 800 -> 864 ), 等待下次确认（防振荡 1 /2）
[FrameAdaptor] 吞吐稳定, 请求 增大 帧:  800 -> 864  (当前: 285 KB/s, 上次: 291 KB/s)
[TcpStream] 收到帧大小变更确认: newSize=864 confirmed=true
[FrameAdaptor] ✅ 帧大小变更已同步:  800 -> 864
[FrameAdaptor] 准备 增大 帧( 864 -> 933 ), 等待下次确认（防振荡 1 /2）
```

MTU 检测：两端 eth0 MTU=1500，按策略使用验证最优值 1400 作为帧大小上限。

## 结论

- **0 重复包、0 解析失败**：跨中继 1-hop 重写 + 帧大小动态变更同步过程中帧边界未错位，无加密错误。
- 双向各传输约 6.5–6.85 MB，峰值上/下行 270–399 KB/s，全程无连接断开。
- 帧大小变更同步协议在真实高延迟（RTT≈194ms）公网链路上正常确认，自适应增大生效。
- 与此前进程内/本地验证一致，在三服务器真实拓扑下复测通过。

## 原始日志清单

- `server1_relay.log` —— relayServer（server1）运行日志。
- `server2_caller.log` —— caller（server2）打流 + 实时速率 + 最终报告 + 帧自适应事件。
- `server3_callee.log` —— callee（server3）注册 + 打流 + 最终报告 + 帧自适应事件。

## 验证程序

`pacakgeTest/relayServer.go`（三模式：server / relayServer / client，`TrafficMonitor` 统计 + trace 去重）。
