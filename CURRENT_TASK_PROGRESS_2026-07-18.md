# 当前任务与进度说明（截至 2026-07-20，进行中）

## 当前任务

在上一轮 12 小时随机 Client→Server 长稳通过的基础上，完成安全计费协议、
恶意节点防护验证和新一轮 12 小时稳定性测试，并保证：

- 集群规模为 7 个 Relay、13 个 NatServer、6 个 NatClient；
- 资源阈值为 CPU 55%、内存 40%、磁盘 40%；
- 总传输限速为 10 MiB/s；
- Index、CA Web、Relay 持续运行，NAT 节点参与随机并发传输；
- 计费采用 `W = 1 MiB` 累计窗口、Relay/NatServer 双签凭证和 CA 权威增量结算；
- Index/CA 不可达时，Relay 将双签凭证逐次持久化到生产 `waitSubmit` WAL，恢复后按序提交；
- 12 小时测试持续随机注入恶意 Relay、恶意 NatServer 和 Index 断连行为，漏防立即标记 FAIL；
- Dashboard 监听本机 `8911`，页面和 API 均使用脱敏数据；
- 正式长稳前通过真实 Compose `waitSubmit` 恢复门禁，并完整通过三个强制本机部署场景。

## 当前状态

- 安全计费主链、生产 `waitSubmit`、CA 事务账本、消息 holdback、双方状态证明和丢失联签响应恢复已实现；
- 恶意行为侧车、真实 Go 组件探针及两个隔离容器 fixture 已接入 FAIL gate 与 Dashboard；两个容器通过真实容器 HTTP/CA 网络随机重复执行 9 类负向协议用例；
- 真实 Compose 恢复门禁已实现为“暂停 CA、形成生产 backlog、冻结生产者、强杀 Relay、核验 WAL、恢复并重新传输”，但尚待本轮最终环境实跑签收；
- CA 的 `/issue` 已使用角色隔离的 enrollment Bearer，`/credit` 使用独立 admin Bearer；负向 fixture 不持有管理凭据；
- Dashboard 默认仅监听 `127.0.0.1`，runner 会持续验证 `/api/status`，不再只检查页面进程 PID；
- 计费核心、Nat 和队列定向回归已通过；Relay 全包回归当前出现超时，正在定位具体挂起用例；
- 本轮全仓回归、完整默认本机部署三场景和新一轮 12 小时长稳尚未完成；
- 在这些门禁全部通过并启动新轮次前，本文件不把本轮任务标记为完成。

## 本轮已实现

### `W = 1 MiB` 双签计费

- NatServer 为发送记录分配 Session、单调序号和明文字节数，并把计费字段纳入 E2E AAD；
- Relay 只累计完整、唯一且通过结构校验的 Record，达到窗口边界后先签 canonical 账单；
- 账单绑定上一张双方凭证、累计唯一字节、最后 Record、RecordSet 摘要、身份、方向和固定策略；
- NatServer 依据本地快照核对并联签；CA 同时验证双方签名、双方证书和全部通道不变量；
- CA 的实现比“只验证 NatServer 签名”更保守，不接受 Relay 单方报数，也不允许调用方覆盖费率。

### 生产 `waitSubmit` 与 CA 账本

- Relay 在取得双方签名后，先把凭证、付款方公钥和证书写入哈希链 WAL；每次入队、出队均同步落盘；
- 崩溃产生的明确断尾可恢复，完整 frame 损坏则 fail-closed；压缩采用原子替换；
- 同一通道保持前驱 FIFO，不同付款方可公平推进；欠费、证书续签和终态冻结不会破坏其他通道；
- CA 使用事务 WAL 和周期快照原子提交余额、分账、通道水位与裁决；重放只产生零增量；
- 旧 `/reserve`、`/settle` 单方扣款入口已退役并返回 `410 Gone`。

### 恶意节点与会话安全

- 完整消息在计费验账前不释放 Data/Retransmit 帧；握手前导有白名单、阶段和资源上限；
- 计费控制流要求 NatServer 对 Relay 随机挑战、Session 和双方身份做私钥持有证明；
- 同序分叉、虚增用量、篡改 Record、错误签名、旧水位、凭证重放和费率覆盖均有明确拒绝或幂等结果；
- Relay 不再因水位不一致无条件轮换 Session。只有无 pending、无 blocked，且全部状态已由最后凭证覆盖的 Session 才能轮换；
- 无凭证尾量、凭证后的未签尾量、pending-only 和 blocked 状态均 fail-closed，防止恶意 NatServer 反复重置 Session 套取不足一个窗口的免费流量。

### 本轮新增的恢复与资源隔离加固

- NatServer 将已 Seal 但发送结果未知的记录标为 staged，将发送成功的最高序号标为 confirmed；Relay 的签名水位只能回滚 staged，不能回滚任何 confirmed 用量；
- Relay 的水位证明绑定随机 challenge、Session、双方身份、累计字节、最后 Record、序号和 RecordSet；NatServer 的 Ready 签名进一步绑定该水位、恢复决定和恢复凭证 ID；
- 同一 Session 即使从新地址重连，也必须提交与本地状态精确一致的 Relay 签名水位，不能借换地址读取 NatServer 尚未公开的快照；
- 双签响应在网络中丢失时，NatServer 返回最后一张双方已签凭证；Relay 先将其写入生产 `waitSubmit`，再恢复 Session 水位，避免永久僵死或分叉；
- NatServer 只联签由本地 Record 序列确定的下一个窗口边界，拒绝 Relay 提前按小额快照刷凭证；证据快照滚动有界，同时保留 confirmed、最近双签和待签边界；
- `waitSubmit` 增加每付款方项目数和字节数配额；单一恶意 NatServer 触发配额只阻断自己的通道，不再 poison 整个 Relay 流水线。

### 管理面与监控加固

- CA enrollment token 按 Relay、NatServer、NatClient 三种角色隔离，申请角色必须和 token 角色一致；充值使用单独 admin token；
- token 只存在于权限为 `0600` 的测试私有目录和容器内文件，不进入命令行、Compose 文档、Dashboard API 或提交内容；
- 每次启动使用不可复用的唯一运行目录，避免同秒重启继承旧 sentinel/status；
- runner 对 Dashboard `/api/status` 做持续 HTTP 与 JSON 状态检查，超过宽限期即写入明确 FAIL；
- production gate 在计算 WAL 摘要前先冻结真实生产者，Relay 恢复并清空队列后还必须重建业务链路并完成一次真实传输。

### 测试深度说明

- 恶意行为侧车使用本地 CA 签发、与生产身份隔离的模拟 NatServer/Relay 逻辑身份，验证签名与结算 API 的拒绝、幂等和余额不变量；
- Compose 额外运行 `malicious-natserver` 与 `malicious-relay` 两个无宿主端口、去 capability、只读根文件系统的隔离 fixture；两者各持独立临时私钥和 CA 证书，经真实容器网络执行虚增、重放、费率覆盖、窗口越界、双签篡改、旧水位、同序分叉、拒签和身份伪造；
- 容器 fixture 任一意外接受、余额异常、覆盖不足、状态畸形、停止或心跳过期都会进入 FAIL；场景初始全覆盖后继续按确定性随机序列运行；
- 容器 fixture 覆盖真实容器调度、独立身份、双方 HTTP 交互和生产 CA 结算端点，但不实例化完整 P2P Payload Socket，也不替代生产 Nat billing meter/Relay pipeline 的 Go 组件探针；Dashboard 明确展示该边界；
- 侧车中的离线队列模型用于验证攻击编排和状态机，不等同于生产 Relay Go `waitSubmit` 恢复证明；
- 真实 Compose 启动门禁会暂停实际 CA、形成真实双签 backlog、冻结生产者并重启实际 Relay、验证 WAL 恢复，再恢复 CA 并核对队列清空、95/5 分账和恢复后真实传输；
- 真实门禁未通过时不得启动或宣称新一轮 12 小时长稳有效。

## 上一轮 12 小时长稳基线（历史终态）

以下结果属于引入本轮安全计费和恶意节点门禁之前的上一轮传输稳定性测试，
仅作为回归基线，不能替代本轮验收：

- 修复前轮次累计 1614/1620 条成功传输，6 条失败均已定位并修复。
- 首个修复后轮次完成 372/372 条正确传输、0 fail，但因 watcher 状态跨代混读被误判为 `failure_watcher_status_invalid`，不计入最终 12 小时。
- watcher 单快照读取修复后，替代轮次完整运行 43200 秒，并进入 `COMPLETED / duration_complete`。
- 最终 2632/2632 条传输成功、0 fail、0 校验错误，累计约 386 GiB。
- 6 个 Client 均覆盖全部 13 个 Server，并覆盖 A、B 和 bridge 三类目标路径。
- 全部资源样本低于 CPU/内存/磁盘强停阈值，核心容器身份连续且重启数为 0。
- watcher 追平全部传输记录，无历史或新增失败、无告警、`lastError=null`。
- Compose 正常清理后，Dashboard 页面与 API 仍保留并展示脱敏终态。

## 上一轮失败诊断与拓扑

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
子网、PID、容器 ID、运行目录或原始证据路径。

## 上一轮已修复的传输根因

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

## 上一轮传输稳定性修改

- 注册代次字段、序列化、同代附加和不同代原子替换；
- 退役代次、连接 tombstone 与有界状态清理；
- E2E record 认证、去重、重放窗口和降级保护；
- 首帧 ACK gate、Resume 路由恢复与 bridge-mux LegFlags；
- TCP/KCP accept 有界并发与无效 KCP 拨号器清理；
- Frame route、adapter replay/cache 和 bridge 生命周期清理；
- 冷启动标准输入隔离、fresh 标记消费与资源门禁；
- failure watcher、Dashboard 失败分析与单快照状态门禁；
- 原始运行证据目录从 Git 跟踪中移除并加入忽略规则。

## 上一轮已完成验证

- 全仓 `go test -vet=off ./...` 通过。
- 关键 Resume/gate/slot 回归在 `-race -count=10` 下通过。
- watcher Node 测试、failure-watcher gate、Dashboard 生命周期回归通过。
- watcher 原子换代压力回归连续通过，相关 Shell 脚本 `bash -n` 通过。
- 标准输入 mock 回归确认池内全部项目均被处理。
- 完整默认命令 `bash scripts/local-deploy-test.sh` 的三个强制场景全部 PASS。
- 12 小时替代轮次满足传输、覆盖、资源、容器连续性、watcher 与 Dashboard
  全部门禁。

## 本轮阶段性验证

- `billingcontrol`、`billingqueue`、`billingrecord`、`billingvoucher` 和 Nat 计费回归已通过；新增 confirmed 防回滚、新地址旧 Session、Ready 状态签名、丢失联签恢复、阈值门控和付款方队列配额均有定向测试；
- CA 鉴权、Dashboard 连续探测、唯一 run ID、production gate 一致性窗口和恢复后传输的定向 Go/Node/Shell 测试已通过；
- 9 类隔离容器协议负向用例、9 类侧车/组件覆盖、Dashboard 严格脱敏和 Compose 凭据隔离测试已阶段性通过；
- Relay 全包测试当前在 10 分钟包级超时结束，尚未得到具体失败断言；该项必须定位并通过后才能进入本机部署验收；
- 阶段性结果将在真实 Compose 门禁合入后统一复跑，不能替代最终全仓与本机部署验收。

## 本轮待完成

1. 定位并修复 Relay 全包测试超时，再执行计费链、网络链和容器 fixture 的定向 `-race`；
2. 执行全仓 Go、Node、Shell、Dashboard、CA 鉴权和两个 billing gate 回归；
3. 在本轮实际 Compose 环境签收生产 `waitSubmit` 断连、Relay 强杀、CA 恢复、严格 95/5 对账和恢复后传输；
4. 运行完整默认 `bash scripts/local-deploy-test.sh`，三个强制场景必须全部 PASS；
5. 执行短时长稳，确认 `VERIFYING_BILLING → RUNNING`、生产门禁、两类恶意探针、watcher、Dashboard 和核心容器全部健康；
6. 扫描并排除私钥、token、原始日志、运行目录、完整标识符和其他环境证据后提交，且绝不暂存用户文件 `0`；
7. 启动启用恶意行为强制门禁的新一轮 12 小时长稳；
8. 持续监控 transfer FAIL、容器/组件恶意行为漏防、watcher/sidecar/Dashboard 心跳和核心容器连续性，出现异常立即分析和报告。

## 验收注意事项

- `start` 的退出码不是启动成功判据；应联合检查 `phase=RUNNING`、资源守卫和节点计数。
- `/healthz` 只说明监控进程存活，不能替代业务状态验收。
- 容器 fixture 的 `RUNNING` 必须同时满足 9/9 初始覆盖、0 violation 和新鲜心跳，不能只看容器 PID/healthcheck。
- 终态必须同时核对 phase、传输记录、资源样本、容器连续性和 watcher 游标。
- 恶意侧车 PASS 不能替代真实生产 Relay `waitSubmit` 恢复门禁。
- 跟踪文档不得包含真实 IP、域名、Token、私钥、完整 NodeID/哈希、运行 ID、
  精确宿主规格、原始日志或本机绝对路径。
