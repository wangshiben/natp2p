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
		}
	}
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
	for _, pc := range live {
		if !pc.atHighWatermark() {
			return false // 只要有一条还没满，就不扩容。
		}
	}
	// 所有健康连接都达高水位 → 记录触发事件并按高峰态决定批量大小。
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
	logx.Infof("[bridge-pool] 扩容: peer=%s 所有连接达高水位 → 新增 %d 条物理连接 (now=%d/%d, burst=%v)",
		p.hostAddr, batch, p.connCount(), poolMaxConns, batch > 1)
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

// OpenStream 在池内选一条 least-loaded 物理连接上开一条逻辑会话。
// Phase B：只用第一条 conn；Phase C 扩容后选 ActiveStreams 最小的。
func (p *relayPeerPool) OpenStream(connID, targetNodeID, originPubKey string) (*networkFrameWork.MuxStream, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errPoolClosed
	}
	var best *physConn
	minActive := int(^uint(0) >> 1) // max int
	for _, pc := range p.conns {
		pc.mu.Lock()
		sess := pc.sess
		pc.mu.Unlock()
		if sess == nil || sess.IsClosed() {
			continue
		}
		active := sess.ActiveStreams()
		if active < minActive {
			minActive = active
			best = pc
		}
	}
	p.mu.Unlock()
	if best == nil {
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

// OpenLogicalConn 在池内开一条逻辑连接（逻辑/物理 N:M 抽象的入口）。
// width = 该逻辑连接要用的物理 leg 数：
//   - width<=1：单 leg（模式 A 退化 / 默认），等价 OpenStream 包一层 LogicalConn。
//   - width>1：条带化（模式 B），在 width 条不同 physConn 上各开一条 leg（F3 启用分片收发）。
//
// F1：width 恒按 1 处理（上层暂只传 1）；F3/F4 再启用 >1 的多 leg 装配。
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
	// width>1 的多 leg 装配在 F3 接入；当前退化为单 leg，保证行为安全。
	st, err := p.OpenStream(connID, targetNodeID, originPubKey)
	if err != nil {
		return nil, err
	}
	return networkFrameWork.NewSingleLegConn(st), nil
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
func (n *RelayNode) poolFor(hostAddr string) *relayPeerPool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if pool := n.bridgePools[hostAddr]; pool != nil {
		return pool
	}
	pool := newRelayPeerPool(n.ctx, hostAddr, n.idStr(), bridgeMinWarmConns)
	n.bridgePools[hostAddr] = pool
	logx.Infof("[bridge-pool] 新建连接池: peer=%s minWarm=%d", hostAddr, bridgeMinWarmConns)
	return pool
}

// openBridgeStream 通过池向 hostAddr 开一条跨中继逻辑会话。
// 池内物理连接可能正在(重)拨号尚未就绪，这里给一个短重试窗口等待首条连接建立。
//
// F1 改造：返回 *LogicalConn（仍实现 net.Conn），桥接调用端透明（只认 net.Conn）。
func (n *RelayNode) openBridgeStream(hostAddr, targetNodeID, originPubKey, connID string) (net.Conn, error) {
	pool := n.poolFor(hostAddr)
	deadline := time.Now().Add(bridgeOpenTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lc, err := pool.OpenLogicalConn(connID, targetNodeID, originPubKey, 1) // F1: width=1
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
