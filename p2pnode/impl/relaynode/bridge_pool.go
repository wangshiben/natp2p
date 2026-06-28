package relaynode

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/networkFrameWork"
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// =============================================================================
// relayPeerPool —— 到一个对端 relay 的多路复用物理连接池
//
// 设计要点（见 cmd/tunnel/RELAY_BRIDGE_POOL_DESIGN.md Phase B）：
//   - 按 hostAddr（对端 relay 可路由地址）做 key，每个对端一个池。
//   - 池内维护多条 physConn（MuxSession），每条 physConn 承载多路会话（OpenStream）。
//   - least-loaded 选连接：新会话选 ActiveStreams() 最小的 physConn。
//   - Phase B 只做「单连接 + 手动扩容接口」，扩容水位/高峰/收缩在 Phase C/D。
// =============================================================================

var (
	errPoolClosed    = errors.New("bridge pool: closed")
	errNoHealthyConn = errors.New("bridge pool: no healthy connection")
)

// relayPeerPool 管理到一个对端 relay 的所有 mux 物理连接。
type relayPeerPool struct {
	hostAddr     string
	selfNodeID   string // 本 relay NodeId（拨号握手时作 Header.NodeId）
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	conns        []*physConn
	closed       bool
	minWarmConns int // 最少保持的热连接数（Phase B 固定 1，Phase D 可调）

	// 高峰探测（Phase D §4.2）：记录滑动窗口内的扩容触发时刻。
	expandEvents []time.Time

	// F4 吞吐驱动的条带化宽度推荐：
	lastWroteBytes int64 // 上轮采样的累计写出字节（算增量用）
	recWidth       int   // 当前推荐的新逻辑连接宽度（吞吐档位）
}

// physConn 是一条 relay↔relay 的物理 mux 连接（含重连）。
type physConn struct {
	pool    *relayPeerPool
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	sess    *networkFrameWork.MuxSession
	closed  bool
	backoff time.Duration // 当前退避时长

	// idleSince 是该连接最近一次「活跃会话归零」的时刻（Phase D 收缩判定）。
	// 零值表示尚未进入空闲（或当前有活跃会话）。
	idleSince time.Time
}

// 重连退避参数（沿用 peerLink 范本：nextBackoff 在 peer_link.go，上限 peerLinkRedialMax）。
const (
	physConnRedialInitial = 500 * time.Millisecond
)

// 连接池扩容策略参数（Phase C，见 RELAY_BRIDGE_POOL_DESIGN.md §4.1/§4.4）。
const (
	// maxStreamsPerConn 单条物理连接承载的最大并发逻辑会话数（软上限）。
	maxStreamsPerConn = 64
	// streamHighWatermark 并发水位 = maxStreamsPerConn * 0.8，达到即视为该连接「并发吃紧」。
	streamHighWatermark = 51
	// sendPressureThreshold 发送压力水位：mux 待发帧数达到即视为该连接「发送吃紧」。
	sendPressureThreshold = 256
	// poolMaxConns 单对端 relay 的物理连接数上限。
	poolMaxConns = 8
	// poolSampleInterval 扩容采样周期：每隔该时长检查一次各 physConn 水位。
	poolSampleInterval = 200 * time.Millisecond
	// contentionBytesThreshold 多流写竞争阈值：单条物理连接写队列积压字节达到即视为
	// 流间队头阻塞（模式 A 摊散信号）。64KB ≈ 两个 32KB 满块在排队。
	contentionBytesThreshold = 64 * 1024
	// widthThroughputStep 吞吐→宽度档位步长：每达到该 字节/秒 给推荐宽度 +1 条 leg。
	// 1MB/s 一档：单 TCP 跨境常受限于此量级，超过即考虑拆多 TCP 并行。
	widthThroughputStep = 1024 * 1024
)

// 高峰批量预扩参数（Phase D §4.2）。
const (
	// burstWindow 高峰探测滑动窗口（统计窗口内扩容触发次数）。
	burstWindow = 5 * time.Second
	// burstTriggerCount 窗口内扩容触发 ≥ 该次数 → 进入高峰态（批量扩容）。
	burstTriggerCount = 3
	// burstBatchSize 高峰态单次扩容增量（普通态每次 +1，高峰态每次 +N）。
	burstBatchSize = 4
)

// 收缩 reaper 参数（Phase D §4.3）。
const (
	// poolReapInterval reaper 扫描周期（检查空闲连接回收）。
	poolReapInterval = 15 * time.Second
	// poolIdleTimeout 物理连接空闲（ActiveStreams==0）超过该时长 → 候选回收。
	poolIdleTimeout = 60 * time.Second
)

// atHighWatermark 报告该物理连接是否达到任一高水位（并发数 或 发送压力）。
// 无健康 session 视为「不占用扩容信号」(false)：它由 manage() 负责重连，不应触发扩容。
func (pc *physConn) atHighWatermark() bool {
	pc.mu.Lock()
	sess := pc.sess
	pc.mu.Unlock()
	if sess == nil || sess.IsClosed() {
		return false
	}
	if sess.ActiveStreams() >= streamHighWatermark {
		return true
	}
	if sess.PendingFrames() >= sendPressureThreshold {
		return true
	}
	return false
}

// contended 报告该连接是否处于「多流写竞争」状态（模式 A 摊散信号）：
// 同一条 TCP 上有 ≥2 条活跃会话且写队列积压字节超过阈值，说明这些流在串行写路径上
// 互相阻塞（队头阻塞），应把它们摊散到更多物理连接以并行各自的 cwnd。
func (pc *physConn) contended() bool {
	pc.mu.Lock()
	sess := pc.sess
	pc.mu.Unlock()
	if sess == nil || sess.IsClosed() {
		return false
	}
	return sess.ActiveStreams() >= 2 && sess.PendingBytes() >= contentionBytesThreshold
}

// liveConns 返回当前有健康 session 的物理连接快照（持锁外用）。
func (p *relayPeerPool) liveConns() []*physConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	live := make([]*physConn, 0, len(p.conns))
	for _, pc := range p.conns {
		pc.mu.Lock()
		sess := pc.sess
		pc.mu.Unlock()
		if sess != nil && !sess.IsClosed() {
			live = append(live, pc)
		}
	}
	return live
}

// connCount 返回池内物理连接总数（含正在重连的）。
func (p *relayPeerPool) connCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

// autoscale 是扩容采样循环（Phase C）：周期性检查水位，满足条件则 +1 物理连接。
//
// 扩容判定（针对整个池，§4.1）：
//   - 存在 ≥1 条健康连接，且「所有健康连接都达到高水位」(避免少数热点误触发)；
//   - 且当前连接总数 < poolMaxConns。
// 满足则新增 1 条 physConn（高峰批量预扩在 Phase D 接管单次增量）。
func (p *relayPeerPool) autoscale() {
	ticker := time.NewTicker(poolSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.maybeExpand()
			p.sampleThroughput()
		}
	}
}

// sampleThroughput 采样本池到对端 relay 的聚合写吞吐（基于各 session WroteBytes 增量），
// 据此更新 recWidth（推荐的新逻辑连接条带化宽度）。
//
// 思路：跨境高 BDP 链路上，单条逻辑连接挤在一条 TCP 受单 cwnd 限制；当观察到该对端持续
// 高吞吐（说明有大流量需求），就建议新逻辑连接用更宽的条带（拆到多条 TCP 并行各自 cwnd）。
// 仅影响后续新建的逻辑连接（不对存量连接做有风险的 mid-flow resplice）。
func (p *relayPeerPool) sampleThroughput() {
	p.mu.Lock()
	conns := make([]*physConn, len(p.conns))
	copy(conns, p.conns)
	p.mu.Unlock()

	var total int64
	for _, pc := range conns {
		pc.mu.Lock()
		sess := pc.sess
		pc.mu.Unlock()
		if sess != nil && !sess.IsClosed() {
			total += sess.WroteBytes()
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	prev := p.lastWroteBytes
	p.lastWroteBytes = total
	if prev == 0 {
		return // 首次采样无增量基准
	}
	delta := total - prev
	if delta < 0 {
		delta = 0
	}
	// delta 是一个采样周期(poolSampleInterval)内写出的字节数 → 估算 bytes/s。
	bytesPerSec := float64(delta) * float64(time.Second) / float64(poolSampleInterval)

	// 按吞吐档位推荐宽度：每 widthThroughputStep 字节/秒 +1 条 leg，封顶 poolMaxConns。
	rec := 1 + int(bytesPerSec/widthThroughputStep)
	if rec < 1 {
		rec = 1
	}
	if rec > poolMaxConns {
		rec = poolMaxConns
	}
	p.recWidth = rec
}

// recommendedWidth 返回当前推荐的新逻辑连接条带化宽度（吞吐驱动，见 sampleThroughput）。
func (p *relayPeerPool) recommendedWidth() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recWidth < 1 {
		return 1
	}
	return p.recWidth
}

// maybeExpand 执行一次扩容判定与（必要时）扩容。返回是否实际扩容。
//
// Phase D：扩容量受高峰探测影响——普通态每次 +1；高峰态（burstWindow 内扩容触发
// ≥ burstTriggerCount 次）每次批量 +burstBatchSize，均不超过 poolMaxConns 封顶。
func (p *relayPeerPool) maybeExpand() bool {
	live := p.liveConns()
	if len(live) == 0 {
		return false // 无健康连接：交给 manage() 重连，不在此扩容。
	}
	// 扩容信号有两类，满足其一即扩（均要求所有健康连接同时命中，避免少数热点误触发）：
	//   1. 高水位：并发会话数或发送帧压力达上限（Phase C，应对会话数暴涨）。
	//   2. 写竞争：多流挤一条 TCP 且写队列积压（F2 模式 A，应对吞吐受队头阻塞）。
	allHigh := true
	allContended := true
	for _, pc := range live {
		if !pc.atHighWatermark() {
			allHigh = false
		}
		if !pc.contended() {
			allContended = false
		}
	}
	if !allHigh && !allContended {
		return false
	}
	reason := "高水位"
	if !allHigh {
		reason = "写竞争(模式A摊散)"
	}
	// 触发扩容 → 记录事件并按高峰态决定批量大小。
	p.mu.Lock()
	if p.closed || len(p.conns) >= poolMaxConns {
		p.mu.Unlock()
		return false
	}
	now := time.Now()
	p.recordExpandEventLocked(now)
	batch := 1
	if p.inBurstLocked(now) {
		batch = burstBatchSize
	}
	room := poolMaxConns - len(p.conns)
	if batch > room {
		batch = room
	}
	p.mu.Unlock()
	if batch <= 0 {
		return false
	}
	for i := 0; i < batch; i++ {
		p.addPhysConn()
	}
	logx.Infof("[bridge-pool] 扩容: peer=%s 触发=%s → 新增 %d 条物理连接 (now=%d/%d, burst=%v)",
		p.hostAddr, reason, batch, p.connCount(), poolMaxConns, batch > 1)
	return true
}

// recordExpandEventLocked 记录一次扩容触发时刻并裁剪滑动窗口外的旧事件（持 p.mu）。
func (p *relayPeerPool) recordExpandEventLocked(now time.Time) {
	cutoff := now.Add(-burstWindow)
	kept := p.expandEvents[:0]
	for _, t := range p.expandEvents {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	p.expandEvents = append(kept, now)
}

// inBurstLocked 报告当前是否处于高峰态：滑动窗口内扩容触发次数 ≥ burstTriggerCount（持 p.mu）。
func (p *relayPeerPool) inBurstLocked(now time.Time) bool {
	cutoff := now.Add(-burstWindow)
	count := 0
	for _, t := range p.expandEvents {
		if t.After(cutoff) {
			count++
		}
	}
	return count >= burstTriggerCount
}

// reap 是收缩循环（Phase D §4.3）：周期扫描，回收长时间空闲的物理连接，
// 但池内至少保留 minWarmConns 条热连接，且永不超过 poolMaxConns。
func (p *relayPeerPool) reap() {
	ticker := time.NewTicker(poolReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.reapOnce(time.Now())
		}
	}
}

// reapOnce 执行一次空闲回收扫描。now 参数便于测试注入时间。
func (p *relayPeerPool) reapOnce(now time.Time) {
	var toClose []*physConn
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	// 刷新各连接的空闲状态（活跃→清零起点；归零→记录起点）。
	for _, pc := range p.conns {
		pc.refreshIdle(now)
	}
	// 保底：回收后池内连接数不得低于 minWarmConns。
	// budget 是本轮最多可回收的数量。
	budget := len(p.conns) - p.minWarmConns
	survivors := make([]*physConn, 0, len(p.conns))
	for _, pc := range p.conns {
		if budget > 0 && pc.idleExpired(now) {
			toClose = append(toClose, pc)
			budget--
			continue
		}
		survivors = append(survivors, pc)
	}
	p.conns = survivors
	remaining := len(p.conns)
	p.mu.Unlock()
	for _, pc := range toClose {
		pc.close()
	}
	if len(toClose) > 0 {
		logx.Infof("[bridge-pool] 收缩: peer=%s 回收 %d 条空闲物理连接 (剩余=%d, 保底=%d)",
			p.hostAddr, len(toClose), remaining, p.minWarmConns)
	}
}

// refreshIdle 更新连接空闲起点：有活跃会话→清零；无活跃会话→首次记录 now（持 p.mu 由调用方保证）。
func (pc *physConn) refreshIdle(now time.Time) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	sess := pc.sess
	if sess == nil || sess.IsClosed() {
		// 无健康会话：不在收缩范畴（manage 负责），清空闲标记。
		pc.idleSince = time.Time{}
		return
	}
	if sess.ActiveStreams() > 0 {
		pc.idleSince = time.Time{} // 有活跃会话，重置空闲计时。
		return
	}
	if pc.idleSince.IsZero() {
		pc.idleSince = now // 首次归零，开始计时。
	}
}

// idleExpired 报告连接是否已空闲超过 poolIdleTimeout（持 p.mu 由调用方保证）。
func (pc *physConn) idleExpired(now time.Time) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	sess := pc.sess
	if sess == nil || sess.IsClosed() {
		return false // 重连中，不回收。
	}
	if sess.ActiveStreams() > 0 || pc.idleSince.IsZero() {
		return false
	}
	return now.Sub(pc.idleSince) >= poolIdleTimeout
}


// newRelayPeerPool 创建到 hostAddr 的连接池，立即启动 minWarmConns 条物理连接。
func newRelayPeerPool(parent context.Context, hostAddr, selfNodeID string, minWarmConns int) *relayPeerPool {
	ctx, cancel := context.WithCancel(parent)
	p := &relayPeerPool{
		hostAddr:     hostAddr,
		selfNodeID:   selfNodeID,
		ctx:          ctx,
		cancel:       cancel,
		minWarmConns: minWarmConns,
	}
	// Phase B：启动时只建 minWarmConns 条（暂定 1），扩容接口留给 Phase C。
	for i := 0; i < minWarmConns; i++ {
		p.addPhysConn()
	}
	// Phase C：后台扩容采样循环（并发数 + 发送压力水位）。
	go p.autoscale()
	// Phase D：后台收缩 reaper（闲置超时回收 + minWarmConns 保底）。
	go p.reap()
	return p
}

// addPhysConn 新增一条物理连接到池（带退避重连）。
func (p *relayPeerPool) addPhysConn() *physConn {
	ctx, cancel := context.WithCancel(p.ctx)
	pc := &physConn{
		pool:    p,
		ctx:     ctx,
		cancel:  cancel,
		backoff: physConnRedialInitial,
	}
	p.mu.Lock()
	p.conns = append(p.conns, pc)
	p.mu.Unlock()
	go pc.manage()
	return pc
}

// OpenStream 在池内选一条物理连接上开一条逻辑会话。
//
// F2（模式 A 摊散调度）：选连接综合「写压力(pendingBytes)」与「并发会话数」打分，
// 把新逻辑连接摊到最空闲的物理连接，规避把多条流挤在同一条 TCP 导致的写串行队头阻塞。
// 不同逻辑连接因此天然分散到多条独立 cwnd 的 TCP，聚合带宽更高。
func (p *relayPeerPool) OpenStream(connID, targetNodeID, originPubKey string) (*networkFrameWork.MuxStream, error) {
	best := p.pickLeastLoaded()
	if best == nil {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return nil, errPoolClosed
		}
		return nil, errNoHealthyConn
	}
	best.mu.Lock()
	sess := best.sess
	best.mu.Unlock()
	if sess == nil || sess.IsClosed() {
		return nil, errNoHealthyConn
	}
	return sess.OpenStream(connID, targetNodeID, originPubKey)
}

// pickLeastLoaded 返回综合负载最小的健康物理连接（模式 A 摊散核心）。
// 负载分以 pendingBytes 为主（写压力直接反映队头阻塞风险），ActiveStreams 为次（平手打散）。
func (p *relayPeerPool) pickLeastLoaded() *physConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	var best *physConn
	var bestPending int64 = 1<<63 - 1
	bestStreams := int(^uint(0) >> 1)
	for _, pc := range p.conns {
		pc.mu.Lock()
		sess := pc.sess
		pc.mu.Unlock()
		if sess == nil || sess.IsClosed() {
			continue
		}
		pending := sess.PendingBytes()
		streams := sess.ActiveStreams()
		if pending < bestPending || (pending == bestPending && streams < bestStreams) {
			bestPending = pending
			bestStreams = streams
			best = pc
		}
	}
	return best
}

// OpenLogicalConn 在池内开一条逻辑连接（逻辑/物理 N:M 抽象的入口）。
// width = 该逻辑连接要用的物理 leg 数：
//   - width<=1：单 leg（模式 A 退化 / 默认），等价 OpenStream 包一层 LogicalConn。
//   - width>1：条带化（模式 B，F3 启用），在 width 条不同 physConn 上各开一条 leg，
//     组装成条带化逻辑连接（出站轮转分片+序号，入站重排）。
func (p *relayPeerPool) OpenLogicalConn(connID, targetNodeID, originPubKey string, width int) (*networkFrameWork.LogicalConn, error) {
	if width < 1 {
		width = 1
	}
	if width == 1 {
		st, err := p.OpenStream(connID, targetNodeID, originPubKey)
		if err != nil {
			return nil, err
		}
		return networkFrameWork.NewSingleLegConn(st), nil
	}
	// width>1：在 width 条不同 physConn 上各开一条 leg（F3 条带化）。
	// 受池容量约束，实际可能低于期望 width（池 < width 或健康连接不足）。
	// 先选出目标 physConn，确定实际 legCount，再各自 OpenStreamLeg 带正确 legIndex/legCount。
	targets := make([]*physConn, 0, width)
	used := make(map[*physConn]bool, width)
	for i := 0; i < width; i++ {
		pc := p.pickLeastLoadedExcluding(used)
		if pc == nil {
			break
		}
		used[pc] = true
		targets = append(targets, pc)
	}
	if len(targets) == 0 {
		return nil, errNoHealthyConn
	}
	legCount := len(targets)
	legs := make([]*networkFrameWork.MuxStream, 0, legCount)
	for idx, pc := range targets {
		pc.mu.Lock()
		sess := pc.sess
		pc.mu.Unlock()
		if sess == nil || sess.IsClosed() {
			continue
		}
		// 每条 leg 用同 connID + (legIndex, legCount)，对端据此归并为一条条带化逻辑连接。
		st, err := sess.OpenStreamLeg(connID, targetNodeID, originPubKey, idx, legCount)
		if err != nil {
			continue
		}
		legs = append(legs, st)
	}
	if len(legs) == 0 {
		return nil, errNoHealthyConn
	}
	if len(legs) == 1 {
		return networkFrameWork.NewSingleLegConn(legs[0]), nil
	}
	return networkFrameWork.NewStripedConn(connID, legs), nil
}

// pickLeastLoadedExcluding 返回负载最小的健康物理连接，排除 used 中已选的。
// 用于条带化时在不同 physConn 上开多 leg（避免多 leg 挤一条 TCP 失去并行收益）。
func (p *relayPeerPool) pickLeastLoadedExcluding(used map[*physConn]bool) *physConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	var best *physConn
	var bestPending int64 = 1<<63 - 1
	bestStreams := int(^uint(0) >> 1)
	for _, pc := range p.conns {
		if used[pc] {
			continue
		}
		pc.mu.Lock()
		sess := pc.sess
		pc.mu.Unlock()
		if sess == nil || sess.IsClosed() {
			continue
		}
		pending := sess.PendingBytes()
		streams := sess.ActiveStreams()
		if pending < bestPending || (pending == bestPending && streams < bestStreams) {
			bestPending = pending
			bestStreams = streams
			best = pc
		}
	}
	return best
}

// Close 关闭池及其所有物理连接。
func (p *relayPeerPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	p.cancel()
	for _, pc := range conns {
		pc.close()
	}
	return nil
}

// manage 是 physConn 的重连循环（沿用 peerLink.manage 范本）。
func (pc *physConn) manage() {
	for {
		select {
		case <-pc.ctx.Done():
			return
		default:
		}
		sess, err := networkFrameWork.DialBridgeMuxSession(pc.ctx, pc.pool.hostAddr, pc.pool.selfNodeID)
		if err != nil {
			logx.Warnf("[bridge-pool] 拨向 %s 失败, %v 后重试: %v", pc.pool.hostAddr, pc.backoff, err)
			if !pc.sleep(pc.backoff) {
				return
			}
			pc.backoff = nextBackoff(pc.backoff)
			continue
		}
		pc.mu.Lock()
		pc.sess = sess
		pc.mu.Unlock()
		pc.backoff = physConnRedialInitial // 成功后重置退避
		logx.Infof("[bridge-pool] 物理连接已建立: peer=%s", pc.pool.hostAddr)
		// 阻塞直到 sess 断开（sess.Context().Done()）或 pc 被关闭。
		select {
		case <-sess.Context().Done():
			logx.Infof("[bridge-pool] 物理连接断开: peer=%s", pc.pool.hostAddr)
			pc.mu.Lock()
			pc.sess = nil
			pc.mu.Unlock()
			if !pc.sleep(pc.backoff) {
				return
			}
			pc.backoff = nextBackoff(pc.backoff)
		case <-pc.ctx.Done():
			_ = sess.Close()
			return
		}
	}
}

func (pc *physConn) sleep(d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-pc.ctx.Done():
		return false
	}
}

func (pc *physConn) close() {
	pc.cancel()
	pc.mu.Lock()
	sess := pc.sess
	pc.sess = nil
	pc.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
}

// =============================================================================
// RelayNode 侧：池查找/创建 + 跨中继会话开启
// =============================================================================

// bridgeMinWarmConns 是每个对端 relay 池保底保持的热连接数（Phase D 可调）。
const bridgeMinWarmConns = 1

// poolFor 返回到 hostAddr 的连接池，不存在则惰性创建。
// 若显式强制了 bridgeWidth>1，则用它作为 minWarm floor，预热足够的物理连接让条带化能真正
// 摊到多条独立 TCP（单条逻辑连接不会自发产生跨流竞争来触发扩容）。
func (n *RelayNode) poolFor(hostAddr string) *relayPeerPool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if pool := n.bridgePools[hostAddr]; pool != nil {
		return pool
	}
	minWarm := bridgeMinWarmConns
	if w := int(n.bridgeWidth.Load()); w > minWarm {
		if w > poolMaxConns {
			w = poolMaxConns
		}
		minWarm = w
	}
	pool := newRelayPeerPool(n.ctx, hostAddr, n.idStr(), minWarm)
	n.bridgePools[hostAddr] = pool
	logx.Infof("[bridge-pool] 新建连接池: peer=%s minWarm=%d", hostAddr, minWarm)
	return pool
}

// openBridgeStream 通过池向 hostAddr 开一条跨中继逻辑会话。
// 池内物理连接可能正在(重)拨号尚未就绪，这里给一个短重试窗口等待首条连接建立。
//
// F1/F3 改造：返回 *LogicalConn（仍实现 net.Conn），桥接调用端透明（只认 net.Conn）。
// width 取自 RelayNode.bridgeWidth（F4 动态调整；默认 1=非条带化）。
func (n *RelayNode) openBridgeStream(hostAddr, targetNodeID, originPubKey, connID string) (net.Conn, error) {
	pool := n.poolFor(hostAddr)
	// width 决策：bridgeWidth>0 为显式强制（测试/配置）；==0 为自动（吞吐驱动推荐）。
	width := int(n.bridgeWidth.Load())
	if width < 1 {
		width = pool.recommendedWidth()
	}
	deadline := time.Now().Add(bridgeOpenTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lc, err := pool.OpenLogicalConn(connID, targetNodeID, originPubKey, width)
		if err == nil {
			return lc, nil
		}
		lastErr = err
		if err == errPoolClosed {
			return nil, err
		}
		// 物理连接尚未就绪（errNoHealthyConn）：短暂等待重试。
		select {
		case <-time.After(bridgeOpenRetryInterval):
		case <-n.ctx.Done():
			return nil, n.ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errNoHealthyConn
	}
	return nil, lastErr
}

// SetBridgeWidth 设置桥接出站条带化宽度（每条逻辑连接用几条物理 leg）。
// 1=非条带化（模式 A）；>1=条带化（模式 B）。F4 据流量动态调整；测试/配置可显式设定。
func (n *RelayNode) SetBridgeWidth(w int) {
	if w < 1 {
		w = 1
	}
	n.bridgeWidth.Store(int32(w))
}

// closeBridgePools 关闭所有跨中继连接池（RelayNode.Close 调用）。
func (n *RelayNode) closeBridgePools() {
	n.mu.Lock()
	pools := make([]*relayPeerPool, 0, len(n.bridgePools))
	for _, p := range n.bridgePools {
		pools = append(pools, p)
	}
	n.bridgePools = make(map[string]*relayPeerPool)
	n.mu.Unlock()
	for _, p := range pools {
		_ = p.Close()
	}
}

const (
	// bridgeOpenTimeout 等待池内物理连接就绪并开出会话的总超时。
	bridgeOpenTimeout = 5 * time.Second
	// bridgeOpenRetryInterval 物理连接尚未就绪时的重试间隔。
	bridgeOpenRetryInterval = 100 * time.Millisecond
)
