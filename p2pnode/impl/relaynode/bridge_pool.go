package relaynode

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/networkFrameWork"
	"context"
	"errors"
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
	// 所有健康连接都达高水位 → 在 maxConns 封顶内扩容。
	p.mu.Lock()
	if p.closed || len(p.conns) >= poolMaxConns {
		p.mu.Unlock()
		return false
	}
	p.mu.Unlock()
	p.addPhysConn()
	logx.Infof("[bridge-pool] 扩容: peer=%s 所有连接达高水位 → 新增物理连接 (now=%d/%d)",
		p.hostAddr, p.connCount(), poolMaxConns)
	return true
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
func (n *RelayNode) openBridgeStream(hostAddr, targetNodeID, originPubKey, connID string) (*networkFrameWork.MuxStream, error) {
	pool := n.poolFor(hostAddr)
	deadline := time.Now().Add(bridgeOpenTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		st, err := pool.OpenStream(connID, targetNodeID, originPubKey)
		if err == nil {
			return st, nil
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
