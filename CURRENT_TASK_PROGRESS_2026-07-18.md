# 当前任务与进度说明（已完成）

## 当前任务

在降低稳定性集群规模后完成 12 小时随机 Client→Server 长稳测试，并保证：

- 集群规模为 7 个 Relay、13 个 NatServer、6 个 NatClient；
- 资源阈值为 CPU 55%、内存 40%、磁盘 40%；
- 总传输限速为 10 MiB/s；
- Index、CA Web、Relay 持续运行，NAT 节点参与随机并发传输；
- Dashboard 监听本机 `8911`，页面和 API 均使用脱敏数据；
- 正式长稳前完整通过三个强制本机部署场景。

## 最终状态

- 修复前轮次累计 1614/1620 条成功传输，6 条失败均已定位并修复。
- 首个修复后轮次完成 372/372 条正确传输、0 fail，但因 watcher 状态跨代混读被误判为 `failure_watcher_status_invalid`，不计入最终 12 小时。
- watcher 单快照读取修复后，替代轮次完整运行 43200 秒，并进入 `COMPLETED / duration_complete`。
- 最终 2632/2632 条传输成功、0 fail、0 校验错误，累计约 386 GiB。
- 6 个 Client 均覆盖全部 13 个 Server，并覆盖 A、B 和 bridge 三类目标路径。
- 全部资源样本低于 CPU/内存/磁盘强停阈值，核心容器身份连续且重启数为 0。
- watcher 追平全部传输记录，无历史或新增失败、无告警、`lastError=null`。
- Compose 正常清理后，Dashboard 页面与 API 仍保留并展示脱敏终态。

## 失败诊断与拓扑

修复前轮次的 6 条失败已从 `transfers.tsv`、脱敏 Client/Server 快照、
`server-pool.tsv` 和 Compose 控制网络恢复逻辑路径：

| 记录 | 脱敏逻辑路径 | 分区 | 结果 | 诊断 |
|---|---|---|---|---|
| 1 | `natclient03 → relay01 → relay03 → natserver03` | A | `rc=2`，0 B | 握手首帧公钥解析读到非协议字符，Client 未在就绪窗口完成 |
| 2 | `natclient03 → relay01 → relay06 → natserver09` | B | `rc=2`，0 B | 同一首帧解析特征，未进入数据请求 |
| 3 | `natclient04 → relay01 → relay04 → natserver12` | A | 部分数据后超时 | E2E 已建立后数据路径停滞；KCP 重连超时为关联证据 |
| 4 | `natclient01 → relay01 → relay06 → natserver09` | B | 部分数据后超时 | E2E 已建立后数据路径停滞；未完成校验 |
| 5 | `natclient03 → relay01 → relay06 → natserver09` | B | `rc=2`，0 B | 同一首帧解析特征，未进入数据请求 |
| 6 | `natclient06 → relay01 → relay06 → natserver09` | B | `rc=2`，0 B | 同一首帧解析特征；身份/连接代次边界异常 |

4 条握手失败源于 Relay 过早确认 Client 首帧；2 条数据停滞源于 KCP accept
队头阻塞与陈旧 Resume 重连的共同放大。所有失败都经过桥接 `relay01`，
但同一入口同时承载大量成功传输，因此它是共同路径而不是单点根因。

Dashboard 的 `/api/status` 返回 `failureAnalysis`，包含四跳路径、A/B
分区、每段共享网络、传输进度、原因层级和脱敏证据。失败详情只保留有限
最近记录，摘要独立累计；API 不返回完整 SHA-256、传输 ID、NodeID、网络
子网、PID 或进程启动时间。

## 已修复的根因

### 业务首帧 ACK 与顺序门控

Relay 曾在目标 Server 真正收到业务公钥前先 ACK Client，随后发送的 Noise
hello 可能越过公钥。现在同一逻辑连接的并发业务 leg 共享首帧 gate；只有
Server ACK 公钥后才 ACK Client，并对首帧重传去重。

### KCP accept 队头阻塞与陈旧重连

KCP accept 曾串行等待半开连接首帧，一条坏连接会阻塞后续健康连接；初始
KCP 从未建立时仍保留 Resume 拨号器，持续制造无效恢复请求。TCP/KCP accept
现使用有界并发；初始 KCP 失败后删除对应拨号器，仅保留健康 TCP 恢复路径。

### 跨 Relay Resume

新 Relay 曾把未知 `Resume` 的公钥模板再次送入已启用 E2E record 的 Server
会话，导致 ACK 超时和永久 tombstone。现在业务 `Resume` 只重建路由与物理
leg，不重发公钥；临时 setup/resource-missing 失败不写 tombstone。
bridge-mux OPEN 以向后兼容的可选字段透传 `Resume|Extra`。

### Watcher 状态快照跨代混读

watcher 使用临时文件加原子 `rename` 发布状态。runner 原先连续多次打开
状态文件读取不同字段，可能把相邻两代的 size/offset 拼成不可能的组合。
现在 runner 单次打开、校验并解析完整快照，终态追平检查复用同一份结果；
并发原子替换回归确认不会再形成混合状态。

### 注册代次隔离

同一 NatServer 身份冷重启时，新注册 leg 曾附加到旧 `StreamGroup`，使旧
adapter 的未确认帧被重放到新进程。现在每次逻辑注册生成新的会话代次；
Relay 只允许同代 leg 共用 `StreamGroup`，不同代 fresh 注册原子替换旧组，
并保留有界退役代次与业务连接 tombstone，拒绝延迟旧 leg 回切。

### 长稳冷启动门禁

`while read` 循环内的 Compose exec 曾继承并消费外层标准输入，使后续
NatServer 未被处理。相关调用现从 `/dev/null` 读取。冷启动传输成功后还会
消费对应 `server-fresh` 标记；标记更新失败直接记为 profile setup failure。

## 已完成修改

- 注册代次字段、序列化、同代附加和不同代原子替换；
- 退役代次、连接 tombstone 与有界状态清理；
- E2E record 认证、去重、重放窗口和降级保护；
- 首帧 ACK gate、Resume 路由恢复与 bridge-mux LegFlags；
- TCP/KCP accept 有界并发与无效 KCP 拨号器清理；
- Frame route、adapter replay/cache 和 bridge 生命周期清理；
- 冷启动标准输入隔离、fresh 标记消费与资源门禁；
- failure watcher、Dashboard 失败分析与单快照状态门禁；
- 原始运行证据目录从 Git 跟踪中移除并加入忽略规则。

## 已完成验证

- 全仓 `go test -vet=off ./...` 通过。
- 关键 Resume/gate/slot 回归在 `-race -count=10` 下通过。
- watcher Node 测试、failure-watcher gate、Dashboard 生命周期回归通过。
- watcher 原子换代压力回归连续通过，相关 Shell 脚本 `bash -n` 通过。
- 标准输入 mock 回归确认池内全部项目均被处理。
- 完整默认命令 `bash scripts/local-deploy-test.sh` 的三个强制场景全部 PASS。
- 12 小时替代轮次满足传输、覆盖、资源、容器连续性、watcher 与 Dashboard
  全部门禁。

## 验收注意事项

- `start` 的退出码不是启动成功判据；应联合检查 `phase=RUNNING`、资源守卫和节点计数。
- `/healthz` 只说明监控进程存活，不能替代业务状态验收。
- 终态必须同时核对 phase、传输记录、资源样本、容器连续性和 watcher 游标。
- 跟踪文档不得包含真实 IP、域名、Token、私钥、完整 NodeID/哈希、运行 ID、
  精确宿主规格、原始日志或本机绝对路径。
