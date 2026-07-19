# 随机 Client→Server 并发稳定性测试报告

## 结论

默认规模为 7 个 Relay、13 个 NatServer 和 6 个 NatClient。六个随机 Client
均经桥接 Relay 接入，并从完整的 13 个 NatServer 池独立、有放回地选择目标。

修复前轮次共记录 1614/1620 条成功传输。4 条握手失败和 2 条数据停滞均已
定位到代码级根因并修复。首个修复后轮次完成 372/372 条正确传输、0 fail，
但因 watcher 状态跨代混读被误判为
`FAILED / failure_watcher_status_invalid`，因此没有续算为 12 小时结果。

单快照读取修复后，替代轮次完整运行 43200 秒并以
`COMPLETED / duration_complete` 结束。最终 2632/2632 条传输成功、0 fail、
0 校验错误，累计约 386 GiB；资源、覆盖、容器连续性和 watcher 终态门禁
全部通过。本报告只保留脱敏汇总。

## 拓扑与并发模型

- `relay02`–`relay05` 属于 `control_partition_a`。
- `relay06`–`relay07` 属于 `control_partition_b`。
- `relay01` 同时连接两个分区，作为应用层桥接 Relay。
- 6 个 NatClient 各有独立 worker，不按分区缩小 13 个 Server 的随机池。
- 全局在途槽约束 Server 重启、Client 握手、文件传输和记录收尾。
- 同一个 Server 使用独立锁，避免多个 worker 同时替换单会话 `tunserver`。
- 每次传输随机选择 `100`–`200 MiB`，并验证字节数与 SHA-256。
- 两条并发传输各限速 5 MiB/s，总上限为 10 MiB/s。

这里的随机性是任意 Client 从完整 Server 池选择目标，而不是随机选择入口
Relay。强制场景 2 仍单独验证入口 Relay 消失后的迁移，不与随机负载入口
混用。Dashboard 记录 Client 命名空间中实际建立的 Relay 对端，不根据目标
Server 分区推断。

## 早期配置缺陷

早期轮次中，一个随机 Client 错误沿用强制迁移场景的非桥接入口，无法访问
另一分区中的目标 Server。相同目标经桥接入口可正常完成传输，证明问题不在
目标服务、文件或校验逻辑。当前配置将所有随机负载入口统一为桥接 Relay，
并增加生成后约束校验。

## 冷启动门禁

`while read` 从 Server 池逐项处理服务时，循环内的 Compose exec 曾继承
外层标准输入并吞掉后续服务项，使部分 Server 没有完成预期重启。相关 helper
现显式从 `/dev/null` 读取，mock 回归确认池内项目全部执行。

随后发现冷启动探测已消费目标 Server 的唯一隧道，但对应 `server-fresh`
标记没有清除。随机 worker 因而把已使用实例误判为 fresh。现在仅在冷启动
传输成功后消费标记；状态更新失败会直接记为 profile setup failure。

## 失败原因与拓扑

修复前的 6 条失败如下。记录编号取代真实时间和运行标识：

| 记录 | Client→Relay→Relay→Server | 分区 | 传输状态 | 分类 |
|---|---|---|---|---|
| 1 | `natclient03 → relay01 → relay03 → natserver03` | A | `rc=2`，0 B | 握手/身份首帧解析失败 |
| 2 | `natclient03 → relay01 → relay06 → natserver09` | B | `rc=2`，0 B | 握手/身份首帧解析失败 |
| 3 | `natclient04 → relay01 → relay04 → natserver12` | A | 部分数据后超时 | 数据路径停滞 |
| 4 | `natclient01 → relay01 → relay06 → natserver09` | B | 部分数据后超时 | 数据路径停滞 |
| 5 | `natclient03 → relay01 → relay06 → natserver09` | B | `rc=2`，0 B | 握手/身份首帧解析失败 |
| 6 | `natclient06 → relay01 → relay06 → natserver09` | B | `rc=2`，0 B | 握手/身份首帧解析失败 |

4 条 `rc=2` 都在等待十六进制公钥首帧时读到非协议字符，且没有发起文件
请求。确定性回归确认 Relay 在 Server ACK 公钥前过早 ACK Client，随后发送
的 Noise hello 越过公钥。现在同一逻辑连接的业务 leg 共享首帧 gate，只有
Server ACK 后才放行 Client，并对首帧重传去重。

2 条在途失败都已建立 Noise/E2E 会话，随后 KCP 重连超时并只收到部分数据。
根因是 KCP accept 串行等待半开首帧造成队头阻塞，同时初始 KCP 未建立却
保留 Resume 拨号器，持续放大积压。accept 已改为有界并发；初始 KCP 失败后
只保留健康 TCP 恢复路径。

A、B 两个分区都出现失败，且同一桥接 Relay 还承载了大量正确传输，因此
报告和网页只把该 Relay 标记为共同路径，不作单点根因断言。

## 跨 Relay Resume

修复后的强制迁移场景又捕获一处回归：新 Relay 曾把未知 `Resume` 的公钥
模板重送进已启用 E2E record 的 Server 会话，并在 ACK 超时后写入永久
tombstone。现在所有业务 `Resume` 只恢复路由和物理 leg，不重发公钥；
临时恢复失败允许重试。bridge-mux OPEN 以向后兼容的可选字段透传
`Resume|Extra`，单路与条带化路径均有确定性测试。

## Watcher 误报与修复

watcher 通过临时文件加原子 `rename` 发布整代状态。runner 原先为读取多个
字段重复打开该文件，可能把相邻两代的 size 与 offset 混在一起，误判为
`failure_watcher_status_invalid`。该轮业务传输和资源均正常，停止是误报
后的清理结果。

runner 现在只打开状态文件一次，在同一快照内校验 schema、必需字段和重复
键；终态追平检查复用同一份快照。原子替换压力回归、watcher Node 测试和
failure-watcher gate 均通过。

## Dashboard 验收

Dashboard 在本机 `8911` 提供页面、`/healthz` 和 `/api/status`。页面
为每个逻辑 Client 固定渲染卡片，并只保留有限最近完成记录。展示内容包括：

- 实际入口 Relay、随机目标 NatServer、传输字节数和平均有效载荷带宽；
- SHA-256 校验状态，但不返回完整 SHA-256；
- 分区、桥接 Relay、逻辑可达性矩阵和资源阈值；
- worker 脱敏存活状态，不公开 PID 或进程启动时间；
- fail 的原因分类、四跳路径、共享网络和传输进度。

API 已剔除完整传输 ID、SHA-256、NodeID、网络子网、宿主地址和进程身份。
Dashboard 使用独立进程组；runner 因 fail 进入终态并清理 Compose 后，证据页
仍持续可访问，直到显式 `stop` 或下一次 `start` 安全回收。

## 回归与终态

完整本机部署回归使用：

```bash
bash scripts/local-deploy-test.sh
```

三个强制场景全部通过：

| 场景 | 结果 |
|---|---|
| 网络分区与桥接 Relay | PASS |
| 入口 Relay 中途消失并迁移 | PASS |
| KCP 路径失效后 TCP 接管 | PASS |

最终稳定性轮次满足：

- 完整运行 43200 秒并进入 `COMPLETED / duration_complete`；
- 2632/2632 条传输正确，失败和校验错误均为 0；
- 6 个 Client 均覆盖 13 个 Server 及三类目标路径；
- 所有资源样本低于 `55% / 40% / 40%` 阈值；
- 核心容器身份连续、无重启，终态清理完成；
- watcher 追平、无告警，Dashboard 保留脱敏终态。

## 已知边界

- Server 目标随机，但入口 Relay 当前固定为桥接 Relay。
- 一条传输中途切换 Relay 时，当前单条记录不能表达多段入口路径。
- 带宽是应用层有效载荷带宽，不等于 Relay 计费字节或物理链路带宽。
- 6 个 worker 是独立随机请求源；资源门禁下最多两条大传输同时在途。

报告不包含真实 IP/域名、Token、私钥、完整 NodeID/哈希、运行 ID、精确
时间、宿主规格、原始日志或本机绝对路径。
