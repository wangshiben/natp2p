# 双签计费与恶意节点长稳任务进度（2026-07-20）

## 任务目标

本轮在既有 NAT/Relay P2P 稳定性框架上完成以下工作：

1. 以 `W = 1 MiB` 为计费窗口，引入 Relay 首签、NatServer 本地证据核对联签、CA 权威增量结算；
2. Index/CA 不可达时，将双方已签凭证逐次写入 Relay 本地 `waitSubmit`，每次队列扩容和移除都持久化，恢复通信后按通道顺序提交；
3. 防范恶意 Relay 的用量虚增、额外扣款、费率覆盖、凭证篡改和重放，以及恶意 NatServer 的旧水位、同序分叉、拒签和身份伪造；
4. 将恶意节点随机行为、生产队列恢复、失败原因和拓扑状态接入 12 小时长稳及 Dashboard，任何漏防都标记 FAIL；
5. 完成全量回归、三个强制本机部署场景、短时长稳、脱敏提交，再启动新的 12 小时轮次并持续监控。

## 当前结论

- 最终代码已通过 180 秒 `smoke + enforce` 严格短测；新的正式 12 小时 `full + enforce` 轮次已从零启动并进入 `RUNNING`，未满 43,200 秒前不计为通过；
- 已确认上一正式轮次的 CPU 超限不是 5 MiB/s 限速失效或传统死循环，而是临时 NAT 身份退出后 Relay 侧 KCP 注册组没有 EOF/超时回收，残留会话继续参与 KCP 10 ms 调度和路由清扫；框架现以单扫描器回收持续静默 90 秒的注册组，并同步删除 Relay 托管索引；
- 双签协议、生产 `waitSubmit`、CA 事务账本和主要恶意行为防线已经实现；
- 隔离容器级 NatServer/Relay fixture、真实 Go 组件探针和宿主侧车均已接入 FAIL gate；
- Dashboard 已新增 `malicious-natserver` 与 `malicious-relay` 独立卡片，明确展示其真实正常分区接入、隔离计费 fixture、随机恶意行为、对应防范措施和最近攻击裁决；
- Relay、网络框架、全仓回归、最终代码状态的完整本机部署三场景、此前 600 秒短测和最新 180 秒持续恶意事件短测均已通过；
- 当前没有确定性测试阻断，Dashboard 正监听 `0.0.0.0:8911` 并展示正式轮次；回环、本机非回环地址和既有 FRP 公网入口均已对当前页面、`/healthz` 与 `/api/status` 实测返回 200。必须完整运行 43,200 秒及通过终态证据门禁才能宣称验收完成。

## 已完成实现

### 双签凭证

- NatServer 为每条可计费 E2E Record 分配 Session、单调序号和明文字节数，计费字段进入认证数据；
- Relay 只接受完整、唯一、连续且身份有效的 Record，并生成绑定以下内容的 canonical 凭证：
  - 上一张 MutualVoucher ID；
  - 累计唯一字节；
  - 最后一条 Record ID 与序号；
  - RecordSet 摘要；
  - NatServer、Relay、Session、方向和固定分账策略；
- NatServer 仅在本地 Record 序列计算出的下一个窗口边界联签，拒绝 Relay 提前按小额快照刷凭证；
- CA 同时验证双方签名、证书、前驱链、累计水位和策略，按累计值计算 Relay 95%、CA 5% 的权威增量；
- 同一凭证重放返回零增量；同序不同内容、旧水位、错误前驱和篡改签名均拒绝或冻结通道；
- 旧 `/reserve`、`/settle` 单方扣款接口已停用并返回 `410 Gone`。

### Session 恢复与防回滚

- NatServer 区分已 Seal 但发送结果未知的 staged Record 和发送成功的 confirmed Record；
- Relay 的恢复水位必须由 Relay 私钥签名，并绑定随机 challenge、Session、双方身份、累计值、最后 Record、序号和 RecordSet；
- confirmed 用量不得回滚；只有精确命中本地证据的 ambiguous staged 尾量可以按 Relay 签名水位对齐；
- 同一旧 Session 换到新地址时同样必须先精确核对签名水位，不能借换地址读取 NatServer 未公开的本地快照；
- NatServer 的 Ready 证明进一步绑定 Relay 水位、preexisting/reset 决定和恢复凭证 ID，避免控制响应字段被替换；
- 双签响应丢失时，NatServer 返回最后一张双方已签凭证；Relay 先写入 `waitSubmit`，再推进 Session，避免永久僵死和凭证分叉；
- 证据快照滚动有界，同时保留 confirmed、最后双签和待签阈值所需边界。

### `waitSubmit` 与 CA 不可达

- Relay 在取得双方签名后先将凭证、付款方公钥和证书写入哈希链 WAL；
- 每次入队和出队均 append、flush、`fsync`，明确断尾可恢复，完整 frame 损坏则 fail-closed；
- 同一付款通道严格按前驱顺序提交，不同付款方可公平推进；
- 欠费和可重试 CA 故障保留凭证，CA 恢复后继续提交；终态错误冻结对应通道；
- 队列增加每付款方项目数和字节数配额，单一恶意 NatServer 填满自己的配额不会 poison 整个 Relay；
- CA 账本使用事务 WAL 和原子快照提交余额、Relay 收益、CA 收益与通道水位。

### 恶意节点验证

长稳环境包含三层互补验证：

1. 宿主侧车覆盖签名、凭证、结算、重放和离线队列编排；
2. 真实 Go 组件探针直接执行生产 `billingvoucher`、`billingqueue` 及相关验证逻辑；
3. Compose 中运行隔离的 `malicious-natserver` 与 `malicious-relay` fixture：
   - 各自持有独立临时私钥和 CA 证书；
   - 无宿主端口、丢弃 capability、只读根文件系统；
   - 通过真实容器 HTTP/CA 网络随机重复执行 9 类负向协议用例；
   - 覆盖虚增、重放、费率覆盖、窗口越界、双签篡改、旧水位、同序分叉、拒签和身份伪造；
   - 任一意外接受、余额异常、覆盖不足、状态畸形、停止或心跳过期都进入 FAIL。

容器 fixture 验证容器调度、独立身份、双方 HTTP 协作和生产 CA 端点，但不实例化完整 P2P Payload Socket。Dashboard 会明确展示该边界，完整 Socket/状态机仍由真实部署门禁和 Go 组件测试覆盖。

随机恶意行为与生产防线核对表：

| 行为 | 攻击方式 | 防范与代码入口 |
| --- | --- | --- |
| `relay_usage_inflation` | Relay 将累计唯一字节数抬高后请求 Nat 联签 | Nat 仅认可本地 E2E Record 快照中的累计量、末条 Record ID/序号和集合摘要，且必须命中确定性阈值；不一致不签名：`p2pnode/impl/natnode/billing_meter.go` 的 `natBillingMeter.cosign` |
| `relay_request_replay` | 重复提交同一双方签名凭证 | Relay WAL 按 voucher ID 拒绝队内重复；CA 按 voucher ID 返回幂等结果，重放强制 `Delta=0`、Relay 收益增量为 0：`billingqueue/queue.go` 的 `Queue.enqueue`、`cmd/caserver/main.go` 的 `ledger.settleVoucher` |
| `relay_fee_override` | Relay 篡改费率/分账策略摘要 | 凭证绑定不可变 policy digest；生产策略固定唯一字节计量、1 MiB 窗口和累计 95/5 Relay/CA 分账：`billingvoucher/policy.go` 的 `CurrentPolicyDigest`、`CurrentPolicyCumulativeTotals` |
| `relay_window_overrun` | 单个 sequence 申领超过 1 MiB | 凭证主体校验 sequence ceiling，前后凭证差值也不得超过 1 MiB：`billingvoucher/voucher.go` 的 `VoucherBody.Validate`、`ValidateSuccessor` |
| `nat_stale_watermark` | Nat 使用不增长的累计水位或旧 Record 序号 | successor 必须严格递增 sequence、累计唯一字节、末 Record 序号和 Record 集合摘要，并正确引用前驱：`billingvoucher/voucher.go` 的 `ValidateSuccessor` |
| `nat_same_sequence_fork` | Nat 对同一 sequence 生成不同凭证主体 | Nat 本地拒绝同序不同 body；CA 检出同序不同 body ID 后持久化冻结通道，后续结算 fail-closed：`p2pnode/impl/natnode/billing_meter.go` 的 `natBillingMeter.cosign`、`cmd/caserver/main.go` 的 `ledger.settleVoucher` |
| `nat_signature_refusal` | Nat 拒绝付款方签名，Relay 尝试单签结算 | `MutualVoucher` 强制付款方与 Relay 两份 P-256 ECDSA 签名均有效，缺签无法构造/验证：`billingvoucher/signature.go` 的 `MutualVoucher.Verify` 与 `billingvoucher/voucher.go` 的 `NewMutualVoucher` |
| `relay_voucher_tamper` | 联签后修改 LastRecordID 或 RecordSetDigest | 双方签名覆盖 canonical body，body 包含末 Record ID/序号、RecordSetDigest、policy 和水位；任一字段变化使签名失效：`billingvoucher/voucher.go` 的 `VoucherBody.CanonicalBytes`、`billingvoucher/signature.go` 的 `verifyBodySignature` |
| `index_disconnect_backlog_recovery` | CA/Index 断连时累积 backlog，再重启 Relay 并尝试乱序或重复恢复 | 入队/出队 frame 均写入、flush、`fsync`；重放校验同通道 FIFO 和重复 ID，明确断尾可恢复、完整损坏 fail-closed：`billingqueue/queue.go` 的 `Queue.enqueue`、`RemoveChannelHead`、`appendFrame` 及 WAL replay |
| `nat_identity_forgery` | 使用恶意私钥签名，却套用已签发 Nat 身份/证书 | 同时核对证书 CA 签名、证书角色、SubjectPubKey、派生 NodeID、声明 NodeID 和实际验签公钥：`cmd/billing-adversary-node/main.go` 的 `attackerNode.verifyPayerProposal`、`admission/cert.go` 的 `Verify` |

宿主侧车在 `test/local-chaos/monitor/billing-adversary.mjs` 中完成初始全覆盖后随机选择场景；真实 Go 组件探针入口为 `test/local-chaos/billingadversary/probe.go`；容器角色目录及随机循环位于 `cmd/billing-adversary-node/main.go`。任何恶意候选被接受、余额/账本发生非预期变化、覆盖不足或探针失活都会令长稳门禁失败。

### 真实混合恶意拓扑与异常迁移

- 初始硬编码真实链路为 `正常 mixed-path-probe → 恶意 Relay → 正常 relay03 → 恶意 NatServer`：恶意 NatServer 确实注册在正常 Relay，`relay03` 通过 `nodeserver -peer` 主动维持到恶意 Relay 的控制邻居，链路不再是两个恶意 fixture 互相模拟；
- 混合探针通过真实 `tunclient/tunserver` 下载 1 MiB Payload，并逐次核对字节数与 SHA-256；计费 HTTP fixture 仍保持隔离，Dashboard 会明确区分两类证据；
- 每一个新 NatServer 类恶意事件都会隔离当前恶意 NatServer，再让恶意 NatServer 与正常探针协同切到一个随机正常 `relay03..relay07`；每一个新 Relay 类恶意事件都会隔离恶意 Relay，再将其控制邻居切到另一个随机正常 Relay；两类迁移均持续发生而非只处理首次事件，并禁止回选当前及上一次 Relay，避免递归两跳、旧注册竞态和迁移回跳；
- 恶意 NatServer 每次跨 Relay 恢复都由宿主控制器生成新的 P-256 网络身份、通过私有 enrollment 凭据申请证书并充值，避免同一身份回到旧 Relay 时绕过或降低旧计费尾项的 fail-closed 校验；Dashboard 仍只聚合为逻辑节点 `malicious-natserver`，不公开身份材料；
- 恶意 Relay 恢复时主动回连 `relay03`，用于打破正常 Relay 旧 DualStream 半开时无法及时重拨的恢复僵局；初始方向仍由正常 Relay 主动接入恶意 Relay；
- `test/local-chaos/mixed-path-controller.mjs` 的 `pendingTriggers` 按序消费每个未处理事件，`migrateForTrigger`、`startMaliciousRelay` 和 `mixedPathNodes` 实现真实进程切换；`createSerialHeartbeatPublisher` 每 2 秒独立发布一次串行原子快照，迁移长等待不会再被误判为控制器失活；
- 正常终止先写入 `mixed-adversary-path.drain`，控制器完成当前迁移、停止接收新事件并发布 `drain_complete=1` 后才执行终态门禁；终态要求 `generation >= 9`、9/9 行为均已接入正常分区、全部迁移证据闭合且 violation 为 0；
- Dashboard 后端 `test/local-chaos/monitor/server.mjs` 的 `buildMixedPathLinks` 输出真实混合路径和正常 Relay→恶意 Relay 控制边；前端 `test/local-chaos/monitor/index.html` 的 `normalizeTopology`、`renderTopologyGraph` 与 `renderMixedPathTransferCard` 同步展示恶意节点、随机 Relay 切换及迁移后 SHA-256。

### 管理面与 Dashboard

- CA `/issue` 使用 Relay、NatServer、NatClient 三种角色隔离的 enrollment Bearer；申请角色必须匹配凭据角色；
- `/credit` 使用独立 admin Bearer，恶意 fixture 不持有 enrollment 或 admin 凭据；
- 凭据只通过权限受限的本地文件传入，不进入命令行、Compose 文档、Dashboard 或 Git；
- Dashboard 默认只监听 `127.0.0.1`，远程监听必须显式开启并由外层网络策略保护；
- runner 持续检查 Dashboard `/api/status` 的 HTTP、JSON 和业务状态，超过宽限期即 FAIL，不再只检查 PID；
- 每轮使用唯一运行目录，避免同秒重启复用旧状态；
- 页面展示生产计费门禁、容器 fixture、Go 组件探针、watcher、失败原因和脱敏拓扑。
- 页面为两个隔离恶意节点分别展示固定逻辑服务名、容器运行/健康状态、重启次数、探针执行与覆盖，以及最近一次已阻断或漏防裁决；
- Dashboard API 仅按白名单输出上述字段，不暴露容器 ID、地址、NodeID、密钥、PID、私有路径或原始运行标识；`RUNNING` 阶段缺节点、重启、非健康、覆盖不全或探针失败都会使状态探测 fail-closed。

### 真实生产队列门禁

启动长稳前必须执行以下真实 Compose 流程：

1. 暂停真实 CA；
2. 通过真实 NatServer→Relay 数据链形成至少三张双方已签生产 backlog；
3. 冻结生产者并确认队列深度和 WAL 连续稳定；
4. 记录只读摘要后强制终止真实 Relay；
5. 验证崩溃期间 WAL 未丢失、未变化；
6. 恢复 Relay 和 CA，确认队列归零；
7. 严格核对付款方扣款、Relay 收益、CA 收益及 95/5 分账；
8. 重建业务链并再次完成真实传输，证明恢复后数据路径仍可用。

## 阶段性测试结果

已通过：

- `billingcontrol`、`billingqueue`、`billingrecord`、`billingvoucher`；
- Nat 计费与恢复测试；
- confirmed 防回滚、旧 Session 新地址核对、Ready 状态签名、丢失联签响应恢复；
- 确定性阈值联签和付款方队列配额；
- CA 鉴权与凭据隔离测试；
- Dashboard 安全/脱敏、唯一 run ID、连续 API 探测；
- 容器 fixture 9/9 初始覆盖、心跳和 fail-closed 聚合测试；
- production billing gate 和 billing adversary gate 的定向 Shell/Node 测试。

2026-07-20 最新复核已通过：

- Relay 包全量测试约 44 秒完成，网络框架包约 153 秒完成，不再复现包级超时；
- `go test -vet=off -count=1 -timeout=15m ./...` 全仓通过；
- 计费、CA、Nat、Relay 的定向 `-race` 通过，网络框架单轮复跑及连续三轮 `-race`（约 460 秒）通过；首个探索性并行调用曾出现一次未复现的非零结果，正式长稳期间继续观察相关网络生命周期；
- 44 个 Node/Dashboard 测试、Dashboard 生命周期、billing adversary/production gate 及其他长稳 Shell 门禁通过；
- 完整默认 `bash scripts/local-deploy-test.sh` 三个强制场景全部通过；
- 300 秒 Compose 短时长稳以 `COMPLETED / duration_complete` 结束，生产计费门禁 `PASSED`，恶意侧车覆盖 9/9、失败 0，容器 fixture 覆盖 9/9、失败 0，20 次随机传输全部成功；
- `git diff --check`、Shell 语法和关键 Node 脚本语法检查通过。

2026-07-21 真实混合拓扑复核已通过：

- 300 秒 `smoke + enforce` Compose 轮次以 `COMPLETED / duration_complete` 结束；混合路径完成两类异常触发的 2 次随机 Relay 迁移，24 次 1 MiB 探测全部 SHA-256 PASS、失败 0；
- 18 次正常 NAT Client 随机传输全部成功，覆盖 6/6 Client 和 8 个 NatServer，总传输量 2,509 MiB，失败及 SHA-256 错误均为 0；
- 宿主随机恶意侧车执行 30 次并覆盖 9 类行为，容器门禁快照执行 51 次并覆盖 9/9，二者 violation 均为 0；宿主侧车本轮随机计数为用量虚增 5、请求重放 3、费率覆盖 3、窗口越界 3、凭证篡改 5、旧水位 3、同序分叉 3、拒签 3、离线队列恢复 2；
- 完整默认 `bash scripts/local-deploy-test.sh` 再次通过三个强制场景：分区仅桥接 Relay 可达、传输中入口 Relay 消失后迁移、传输中 KCP 黑洞后 TCP 接管；
- Dashboard 确认监听 `0.0.0.0:8911`，本机非回环页面/API 与既有 129.* FRP TCP 入口的页面、`/healthz`、`/api/status` 均返回 200；不在文档中记录完整公网映射。

2026-07-21 最新迁移与排空竞态复核已通过：

- `random-transfer-deadline.test.sh`、混合路径控制器 4 个单测、Shell 语法和 `git diff --check` 全部通过；
- 场景 2 的 300 秒 `smoke + enforce` 回归以 `COMPLETED / duration_complete` 结束，15/15 次随机传输成功、覆盖 6/6 Client、SHA-256 错误 0；
- 混合路径完成两次不回跳的随机 Relay 迁移，25 次 1 MiB SHA-256 探测全部 PASS；宿主随机恶意检查 31/31 被阻断、覆盖 9/9，容器探针执行 53 次、覆盖 9/9、失败 0；
- 完整默认 `bash scripts/local-deploy-test.sh` 在最终代码状态再次通过三个强制场景，排空阶段未再出现 `random_worker_identity_invalid`。

本次完善过程中出现并已处理的非安全漏防事件：

- `mixed_path_heartbeat_stale`：迁移过程最长等待 45–60 秒，而旧实现只在主循环末尾刷新；改为独立 2 秒串行心跳后，迁移期心跳年龄稳定在 0–2 秒；
- `mixed_path_process_start_timeout`：心跳修复后暴露出恶意 Relay 重启时 `relay03` 旧控制流半开、未触发重拨；恢复进程增加到 `relay03` 的主动控制连接后，两类迁移均通过；
- 正式轮次一次启动尝试在场景 2 中首次迁移 `relay03 → relay06` 后，第二次随机回选了初始 `relay03`，碰到尚未清理完的旧 NatServer 注册并以 `mixed_path_process_start_timeout` fail-closed；Relay 选择现排除当前和上一次节点，回跳回归测试已补充，该未跑满轮次不计为 12 小时通过；
- 场景 2 的 300 秒定向回归随后完成 `relay03 → relay04 → relay06` 两次前向迁移，混合探测与 16 笔随机传输均无失败，但终态排空恰逢 worker 进程组在“存活检查”和“身份检查”之间正常退出，被误报 `random_worker_identity_invalid`；排空逻辑现对该消失竞态重新核对一次，仍存活的身份异常继续 fail-closed；
- 一次 180 秒单并发试跑的 9 笔传输全部正确，但随机竞争未轮到 `natclient03`，覆盖门禁按设计拒绝；使用既有 300 秒基线后覆盖 6/6，未降低验收标准；
- 一次仅用于诊断的 6 并发试跑把单流预算降为 1 MiB/s，193 MiB 样本在 180 秒截止时传完约 179 MiB 并以 `rc=28` fail-closed；正式配置恢复单并发 10 MiB/s，该记录不作为网络或安全通过证据。

正式长稳中的已处理事件：

- 前一轮在约 7 分钟时由 fail-closed 门禁终止，报码为 `billing_container_probe_security_violation`；证据显示 `nat_same_sequence_fork` 的一次“漏防”发生在恶意候选提交之前：诚实基线访问 CA 瞬时返回 502，余额和账本均未变化，因此属于基线可用性故障被 fixture 误分类，不是分叉凭证被接受；
- 容器 fixture 现对基线传输错误、502/503/504 和 CA 5xx 最多重试 3 次；首次结算结果未知时，仅接受 CA 明确返回 `Replayed=true` 且 `Delta=0` 的幂等重放；付款不足、非重试型拒绝、恶意候选被接受或账务变化仍立即 fail-closed；
- 失败码已拆分为 `nat_attack_baseline_unavailable` 与真正的基线拒绝，并增加 502 后成功、未知结果后幂等重放、付款拒绝不重试、连续瞬时故障最终 fail-closed 的回归测试；修复后相关 Go `-race`、Dashboard/容器探针测试和 `git diff --check` 通过；
- 因前一轮未跑满 43,200 秒，未计为稳定性通过；当前正式轮次从零重新计时。

2026-07-21 正常分区混合拓扑严格门禁复核：

- 控制器状态现明确记录恶意 NatServer 注册到正常 `relay03..relay07`、对应 `control_partition_a/b`、正常 Relay03 到恶意 Relay 的真实 `control-hello`、当前混合路径和证据依据；
- 每次迁移必须同时记录恶意事件 `contained=true`、受影响进程隔离成功、随机正常 Relay 接管、迁移后路径仍同时包含正常分区与恶意节点，以及真实 1 MiB Payload SHA-256 PASS；终态 Shell 门禁要求最近两次迁移全部满足上述条件；
- Dashboard 拓扑 API 已实测输出正常 Relay→恶意 NatServer 的真实 Payload 边和正常 Relay03→恶意 Relay 的控制边；恶意↔恶意 HTTP/CA fixture 继续单独标注为隔离计费证据，不再作为 P2P 拓扑证据；
- 全页浏览器截图复核发现隔离 fixture 的恶意↔恶意虚线仍曾混入 SVG 主拓扑；现已从主拓扑移除，仅保留在独立恶意行为证据区，同时前端根据实时 attachment 补画正常 Relay→恶意 NatServer 和正常 Relay→恶意 Relay，并增加“主拓扑不存在恶意↔恶意边”的回归断言；
- NAT Client 随机传输区域和恶意节点卡片现显示真实正常分区接入、异常阻断/隔离、随机 Relay 迁移、迁移后 SHA-256，以及随机恶意行为对应的防范措施；
- 最终代码前的 600 秒 `smoke + enforce` 轮次以 `COMPLETED / duration_complete` 结束：31/31 次随机传输成功、覆盖 6/6 Client、失败 0；混合路径 43 次探测全部通过，两次迁移分别进入正常分区 A/B，且 containment 证据 2/2；宿主恶意检查 50/50 被阻断，容器检查 91 次、覆盖 9/9、失败 0；
- 51 个 Node/Dashboard 测试（含正常分区混合边和拒绝恶意↔恶意主拓扑边的断言）、Dashboard 生命周期、混合路径 Shell 门禁、相关 Go 普通及 `-race` 回归均通过；最终代码状态再次执行默认 `bash scripts/local-deploy-test.sh`，三个强制场景全部 PASS；
- 启动正式轮次时捕获并修复两个瞬时状态问题：Dashboard 在合法 `MIGRATING` 窗口不再因被隔离端点短暂停止而误报；恶意容器只有完成本角色 4/4 或 5/5 初始覆盖后才从 `STARTING` 进入 `RUNNING`，避免首个事件后短暂发布“RUNNING 但覆盖不完整”；此前未跑满轮次均不计 12 小时结果。

当前正式长稳：

- 最新 180 秒 `smoke + enforce` 轮次以 `COMPLETED / duration_complete` 结束：37/37 个持续随机恶意事件均在正常分区完成隔离和随机 Relay 接管，覆盖 9/9 行为，containment violation 为 0；
- 该轮完成 50 次真实 1 MiB 混合路径探测，全部 SHA-256 PASS；10/10 次 NAT Client 随机大文件传输成功，失败 0；恶意 NatServer 和恶意 Relay 均实际接入正常 A/B 控制分区，主拓扑中不存在恶意节点互连边；
- 控制器终态为 `generation=37`、`drain_complete=1`；NatServer 身份轮换解决了重复回到旧 Relay 时旧计费尾项触发 fail-closed 而无法重置的问题，未放宽任何计费安全校验；
- Node/Dashboard 测试现为 53/53，通过全部 13 个相关 Shell 门禁；`go test -vet=off -count=1 -timeout=15m ./...` 全仓通过，最终代码状态的默认 `bash scripts/local-deploy-test.sh` 三个强制场景全部 PASS；
- 正式 12 小时 `random + full + enforce` 长稳已从零启动并进入 `RUNNING`，本轮随机选中 KCP→TCP 故障切换场景；Dashboard 固定使用外部可访问的 `0.0.0.0:8911`，随机负载保持单并发和 10 MiB/s 总预算；
- 启动门禁为 `PASSED / verified`，6/6 随机 Client worker 健康；启动观察期间正常分区恶意处置已从 `generation=10` 持续增长到 25，25/25 次隔离、随机 Relay 接管和迁移后 SHA-256 均通过，覆盖 9/9、violation 为 0，证明页面不再只保留最初两条正常分区阻断；
- 当前主拓扑 API 仅包含正常 Relay→恶意 NatServer、正常 Relay→恶意 Relay 及 CA admission 边，恶意↔恶意边为 0；NAT Client 区域同步展示最近 20 条真实正常分区随机恶意行为、处置路径、防范措施和迁移后探测；
- 当前轮次的回环、本机非回环页面、`/healthz`、`/api/status` 以及既有 FRP TCP 映射均返回 200；本文件不记录完整公网入口或映射端口；
- 任何此前失败、主动停止或仅运行 180/300/600 秒的轮次均不计 12 小时结果；正式轮次必须完整运行 43,200 秒，并同时满足 `phase=COMPLETED`、`outcome=COMPLETED`、`detail=duration_complete`。

2026-07-22 失败修复、资源降载与新正式轮次：

- KCP→TCP 正式轮次曾出现 TCP 已完成 Relay 重连、但旧 UDP/KCP leg 仍被保留为 preferred，导致回程首包停滞；`networkFrameWork/DualStream.go` 的 `runReconnect` 现仅在新 leg 完整拨号并 attach 成功后提升该 leg，TCP 与后续 KCP 的双向重新提升均有普通及 `-race` 回归；
- 另一正式轮次在高频恶意迁移期间被误判为 `mixed_path_normal_partition_attachment_invalid`：controller 的状态文件虽然原子替换，旧 Shell 门禁却逐字段重复打开文件，可能把不同代次拼成一个从未存在的状态；`test/local-chaos/mixed-path-gate.sh` 现一次只读取一个不可变快照，并增加检查过程中发生原子换代的确定性回归及连续压力复跑；
- 10 MiB/s 单流轮次最终由真实资源门禁以 `RESOURCE_LIMIT / resource_threshold_exceeded` 终止，项目 CPU 达 55.53%，其清理产生的在途 `rc=28` 不计作独立网络根因；框架默认聚合预算已降为 5 MiB/s，README 与 CLI 帮助同步更新；
- 当前全新 12 小时 `random + full + enforce` 轮次显式使用 `max_inflight=1`、`workload_limit_mibps=5`、`per_transfer_limit_mibps=5`，随机选中 NAT 路径故障转移场景，已通过启动门禁并保持 `RUNNING`；Dashboard 继续监听 `0.0.0.0:8911`，既有 129.* FRP 映射不在文档记录完整地址；
- 进入 `RUNNING` 后已完成立即基线加每 180 秒一次、持续 3,600 秒的 21/21 次观察：106/106 笔 100–200 MiB 随机传输与 SHA-256 全部正确，6/6 Client worker 始终健康，failure watcher 告警/失败均为 0；
- 同一小时内混合恶意处置 generation 从 14 增长到 506，宿主随机恶意检查增长到 257，容器真实组件检查增长到 507，9/9 行为覆盖、violation 0；每个采样的主拓扑均有 3–4 条正常分区↔恶意节点边且恶意↔恶意边为 0，迁移后 1 MiB 探测全部 SHA-256 PASS；
- 该小时共采集 467 个资源样本，项目宿主 CPU 平均 24.33%、峰值 36.11%，项目内存峰值 11.33%，磁盘门禁峰值 19%，非 `OK` 样本为 0；21 次本机非回环页面/健康/API 与 21 次 FRP 页面/健康/API 均返回 200；
- 上述一小时观察通过不等于 12 小时通过；当前轮次必须继续完整运行 43,200 秒，任何旧失败轮次、资源超限轮次或主动停止轮次均不合并计时。

2026-07-22 KCP 注册组泄漏修复与再次重启：

- 对上一轮 `RESOURCE_LIMIT` 证据按时间轴关联后，累计创建 5,629 个注册组而仅观察到 3,636 次清理，约有 1,969 个高置信孤儿 KCP 注册会话；残留组数与项目 CPU 的相关系数为 0.993，最终项目宿主 CPU 达 55.19%、主机 CPU 达 67.01%。每条残留 KCP 会话继续参加约 10 ms 一次的协议调度，并保留 frame route 清扫器，因此表现为生命周期泄漏驱动的活锁式调度风暴，而不是某个无阻塞 `for` 循环；
- `TcpStream.LatestReceiveTime` 与 `DualStream.LatestReceiveTime` 现提供物理 leg 最近收帧时间；`TransportCover` 只运行一个共享扫描器，默认每 5 秒检查一次，注册组所有现役物理 leg 持续静默 90 秒后关闭。扫描器在组表清空后自行退出，不会为每个恶意身份增加一套 ticker/goroutine；
- 回收前会再次读取最新活跃时间，避免扫描快照后刚恢复的连接被误杀；退出删除继续使用 `StreamGroup` 指针 compare-delete，旧代次退出不能删除新代次，并只在确认当前组退出后触发 `SetUnregisterHook`；
- `RelayNode.onUnregister` 同步删除 `natNodes` 和 `hostedNatAddr`。账户及 durable 双签队列不作无条件强删，避免把尚未结算的安全状态当成缓存回收；它们没有每身份周期调度，不是本次 CPU 风暴来源；
- 新增静默组回收、持续活跃不误杀、旧代次不注销替换组、所有物理 leg 取最新活跃时间、256 个突发身份全部回收且共享扫描器停止、Relay 托管索引删除回归；定向 `-race`、`networkFrameWork` 与 `relaynode` 包全测均通过；
- 最终代码再次运行完整 `bash scripts/local-deploy-test.sh`，分区仅桥接 Relay 可达、入口 Relay 传输中消失后迁移、KCP 黑洞后 TCP 接管三个强制场景全部 PASS；
- 正式 12 小时 `random + full + enforce` 已重新从零进入 `RUNNING`，本轮随机选中 KCP→TCP 故障切换，显式保持 `max_inflight=1`、总预算和单流上限均为 5 MiB/s；启动门禁、9/9 恶意行为覆盖、混合正常分区接入和资源门禁均为健康；
- Dashboard 当前监听 `0.0.0.0:8911`，回环、本机非回环页面/API 和既有 129.* FRP 页面、`/healthz`、`/api/status` 已再次实测全部返回 200；
- 首小时 3 分钟周期审计已由 `test/local-chaos/first-hour-audit.sh` 启动，首个样本 PASS；共需 21 个样本覆盖到第 60 分钟，逐次核对 runner 身份、资源日志、failure watcher、宿主/容器恶意门禁、真实混合路径与传输记录。该审计通过仍不替代完整 43,200 秒终态。

2026-07-22 最近完整一小时手工活锁趋势审计：

- 正式轮次已连续运行超过 1 小时 44 分钟，自动首小时审计先以 21/21 PASS 结束；随后对截至审计时点的最近完整 60 分钟重新读取原始资源表、7 个 Relay 容器日志、传输表和恶意事件表，未复用审计脚本的 PASS 结论；
- 456 个资源样本全部为 `OK`。项目宿主 CPU 平均 20.48%、峰值 30.26%，线性回归斜率为 -0.94 个百分点/小时，CPU 与时间相关系数 -0.053；主机 CPU 平均 36.57%、峰值 46.69%，斜率 +0.17 个百分点/小时、与时间相关系数 0.013。四个 15 分钟桶的项目 CPU 平均值依次为 20.85%、20.85%、20.04%、20.20%，没有逼近此前 55%/67% 终止点的单调趋势；
- 同一小时四个 15 分钟桶的 `创建 − 注册代次替换 − 注销` 分别为 `+1、+1、0、-2`，合计正好为 0；期间新建 694 个组、原子替换并关闭旧代次 321 个、注销 373 个、其中静默超时回收 350 个。全轮日志估算现役组为 31 个，符合固定 NAT 与混合路径活动拓扑的数量级，不再随恶意身份代次增长；
- 项目内存平均 9.78%、峰值 9.89%，斜率 +0.107 个百分点/小时，折合约 33.7 MiB/小时，仍需在 12 小时终态复核；当前 7 个 Relay 合计仅约 164 MiB、单个 6–33 MiB，而 13 个持续提供 100–200 MiB 文件的 NatServer 合计约 2.85 GiB，因此该小幅增长更符合文件服务工作集/页缓存升温，不符合孤儿 Relay/KCP 会话的 CPU 调度泄漏形态；
- 该小时完成 106 笔、合计 15,934 MiB 的随机大文件传输，覆盖 6/6 Client 和 13/13 Server，返回码失败 0、SHA-256 错误 0；failure watcher 新失败 0，资源终止表只有表头，Relay 日志未发现 panic、fatal、deadlock 或异常 keepalive 判死；
- 同一小时随机执行 239 次恶意事件，9 类行为均出现且 239/239 为 `CONTAINED`：断联队列恢复 18、同序分叉 32、拒签 30、旧水位 20、费率覆盖 14、请求重放 33、用量虚增 32、凭证篡改 29、窗口越界 31；混合路径保持正常分区接入、9/9 覆盖、probe failure 0、network violation 0；
- 本机非回环和既有 129.* FRP 的页面、`/healthz`、`/api/status` 在手工审计终点再次全部返回 200。结论是当前没有残留活锁趋势，但内存小斜率和完整 43,200 秒终态仍继续 fail-closed 监控，不能以这一小时替代 12 小时验收。

## 下一步

1. 等待首小时审计完成 21/21 个样本并汇总 CPU/内存趋势、随机恶意行为与处置结果；持续监控 transfer FAIL、恶意行为 violation、生产队列、watcher/sidecar/Dashboard 心跳和核心容器连续性；
2. 等待完整 43,200 秒运行结束，核对 `COMPLETED / duration_complete`、传输、资源、核心容器、watcher 游标、生产计费门禁、Go 组件探针和 9/9 容器覆盖；
3. 更新本文件的正式终态，做提交前脱敏扫描，只显式暂存任务文件，排除私钥、token、运行目录、日志、账本和用户文件 `0`；
4. 仅在用户明确要求时提交代码。

## 验收边界

- `start` 返回成功不等于长稳已启动，必须看到 phase 进入 `RUNNING`；
- `/healthz` 或容器 PID 存活不能替代业务状态、覆盖率和心跳验收；
- 容器 fixture 必须同时满足 9/9 覆盖、0 violation 和新鲜心跳；
- 正式终态必须同时核对 phase、传输记录、资源样本、容器连续性、watcher 游标和所有计费门禁；
- 本文件不记录真实服务器地址、测试环境地址、token、私钥、完整 NodeID/哈希、运行 ID、宿主规格或原始日志路径。
