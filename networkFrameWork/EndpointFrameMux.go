package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// EndpointFrameMux 是 callee（被中继端点）侧的「单条物理连接 → 多逻辑连接」帧级复用器。
//
// 背景：n‑v‑1‑v‑1 拓扑下，多条 client 经一个 relay 汇聚到一个 server，server↔relay 维持
// 一条连接。这条连接上的每一帧都自带 ConnectionId（见 network.Frame）。本复用器：
//   - 把注册得到的 DualStream 两条 leg 置为 pureForwarder 并接 frameTap，读出**原始帧**
//     （不做 relay 那套 logicalID 重写——那是面向「纯转发」的，会破坏「既终结又发起」的端点语义）；
//   - 按 frame.ConnectionId 把帧 demux 到每条逻辑连接各自的缓冲（muxConn）；
//   - 每见到一个新 ConnectionId，回调 onNew 让上层 spawn 一个 handler goroutine，
//     在该 muxConn 上跑一条**正常的** TcpStream（独立 assembler / crypto / ACK / 帧大小自适应）。
//
// 出方向：per‑conn 流写出的帧（已自带 ConnectionId 戳）经 muxConn.Write 还原后，写到当前
// preferred leg，写失败回退到另一条 leg。多条逻辑连接并发写共享物理连接，由 writeMu 串行化整帧。
type EndpointFrameMux struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dual       *DualStream
	adapters   []*TcpFrameAdapter // 每条底层 leg 一个（KCP / TCP）
	adapterSet map[*TcpStream]struct{}

	// outCh + 单写者 goroutine：所有逻辑连接的出帧按入队顺序 FIFO 写出（按到达公平），
	// 写者在阻塞的 conn.Write 上等待时不持有任何调用方共享的锁，故一条流的慢写不会
	// 卡住别的流的握手写——这是避免单连接多路复用 head-of-line 阻塞的关键。
	outCh     chan *network.Frame
	controlCh chan *network.Frame

	mu                     sync.Mutex
	conns                  map[string]*muxConn
	inbound                map[muxFrameKey]muxInboundRoute
	outbound               map[muxFrameKey]*muxOutboundRoute
	billingGenerations     map[muxFrameKey]*muxBillingGenerationRoute
	retired                map[string]time.Time
	kcpGoodput             map[streamTransport]*frameRelayGoodputState
	kcpCooldown            time.Time
	lastQualityMaintenance time.Time
	outboundFrames         int
	startOnce              sync.Once
	controlBurst           int

	// onNew 在首次见到某 ConnectionId 时被调用（持锁外），上层据此 spawn per‑conn handler。
	onNew func(connId string, conn net.Conn)
}

type EndpointFrameMuxSnapshot struct {
	DataQueueDepth       int
	DataQueueCapacity    int
	ControlQueueDepth    int
	ControlQueueCapacity int
}

// NewEndpointFrameMux 在已注册的 relay 流（应为 *DualStream）上构造复用器。
// onNew 每条新逻辑连接回调一次，参数 conn 即喂给该连接的虚拟 net.Conn。
// 必须在任何 client 业务帧到达前调用（注册成功后立即调用），否则会漏掉先到的帧。
func NewEndpointFrameMux(stream network.Stream, onNew func(connId string, conn net.Conn)) (*EndpointFrameMux, error) {
	dual := ensureDualStream(stream)
	if dual == nil {
		return nil, errors.New("endpoint frame mux requires dual stream carrier")
	}
	ctx, cancel := context.WithCancel(dual.ctx)
	m := &EndpointFrameMux{
		ctx:                ctx,
		cancel:             cancel,
		dual:               dual,
		adapterSet:         make(map[*TcpStream]struct{}),
		conns:              make(map[string]*muxConn),
		inbound:            make(map[muxFrameKey]muxInboundRoute),
		outbound:           make(map[muxFrameKey]*muxOutboundRoute),
		billingGenerations: make(map[muxFrameKey]*muxBillingGenerationRoute),
		retired:            make(map[string]time.Time),
		kcpGoodput:         make(map[streamTransport]*frameRelayGoodputState),
		onNew:              onNew,
		outCh:              make(chan *network.Frame, endpointMuxDataQueueCapacity),
		controlCh:          make(chan *network.Frame, 1024),
	}

	if len(m.attachCurrentLegs()) == 0 {
		cancel()
		return nil, errors.New("endpoint frame mux: no tcp leg available")
	}
	return m, nil
}

// Start 启动单写者 goroutine 与每条 leg 的读循环（demux）。非阻塞。
func (m *EndpointFrameMux) Start() {
	m.startOnce.Do(func() {
		go m.writeLoop()
		m.attachCurrentLegs()
		for _, adapter := range m.snapshotAdapters() {
			go m.readLeg(adapter)
		}
		go m.watchLegs()
	})
}

// Done 在承载注册流关闭或 Close 被调用后关闭。
func (m *EndpointFrameMux) Done() <-chan struct{} { return m.ctx.Done() }

func (m *EndpointFrameMux) Snapshot() EndpointFrameMuxSnapshot {
	if m == nil {
		return EndpointFrameMuxSnapshot{}
	}
	return EndpointFrameMuxSnapshot{
		DataQueueDepth:       len(m.outCh),
		DataQueueCapacity:    cap(m.outCh),
		ControlQueueDepth:    len(m.controlCh),
		ControlQueueCapacity: cap(m.controlCh),
	}
}

// writeLoop 是唯一的出帧写者：按入队顺序把帧写到 preferred leg（失败回退另一条）。
// 阻塞的 conn.Write 只卡住本 goroutine，不持有任何调用方共享的锁，故不会让一条流的
// 慢写饿死别的流——出帧按到达顺序公平写出。
func (m *EndpointFrameMux) writeLoop() {
	for {
		frame, ok := m.nextOutboundFrame()
		if !ok {
			return
		}
		m.writeFrame(frame)
	}
}

func (m *EndpointFrameMux) nextOutboundFrame() (*network.Frame, bool) {
	var frame *network.Frame
	// 控制流量优先于批量数据，但在有界突发后强制轮到数据，避免密集 ACK 饿死负载队列。
	if m.controlBurst < endpointMuxMaxControlBurst {
		select {
		case frame = <-m.controlCh:
			m.controlBurst++
			return frame, true
		default:
		}
	} else {
		select {
		case frame = <-m.outCh:
			m.controlBurst = 0
			return frame, true
		default:
			m.controlBurst = 0
		}
	}
	select {
	case <-m.ctx.Done():
		return nil, false
	case frame = <-m.controlCh:
		m.controlBurst++
	case frame = <-m.outCh:
		m.controlBurst = 0
	}
	return frame, true
}

func (m *EndpointFrameMux) writeFrame(frame *network.Frame) {
	if m.outboundBillingGenerationStale(frame, time.Now()) {
		return
	}
	adapters, routeKey, routed := m.orderedAdaptersForFrame(frame)
	for _, adapter := range adapters {
		if err := adapter.HandleFrame(m.ctx, frame); err != nil {
			if routed {
				m.forgetInboundRoute(routeKey, adapter)
			}
			continue
		}
		if routed {
			m.completeInboundRoute(routeKey, adapter, frame)
		}
		m.observeOutboundFrame(adapter, frame, time.Now())
		return
	}
}

// Close 关闭复用器并取消所有 per‑conn muxConn。
func (m *EndpointFrameMux) Close() {
	m.cancel()
	m.mu.Lock()
	for _, c := range m.conns {
		c.Close()
	}
	m.conns = make(map[string]*muxConn)
	m.inbound = make(map[muxFrameKey]muxInboundRoute)
	m.outbound = make(map[muxFrameKey]*muxOutboundRoute)
	m.billingGenerations = make(map[muxFrameKey]*muxBillingGenerationRoute)
	m.retired = make(map[string]time.Time)
	m.kcpGoodput = make(map[streamTransport]*frameRelayGoodputState)
	m.outboundFrames = 0
	m.mu.Unlock()
}

// CloseConnection 只回收一个逻辑会话，不影响其它 connectionID 或注册载体。
func (m *EndpointFrameMux) CloseConnection(connID string) {
	if m.removeConn(connID) {
		m.writeControl(&network.Frame{
			FrameType:    network.FrameTypeConnectionClose,
			ConnectionId: connID,
		})
	}
}

func (m *EndpointFrameMux) watchLegs() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		}
		m.maintainCarrierQuality(time.Now())
		for _, adapter := range m.attachCurrentLegs() {
			go m.readLeg(adapter)
		}
	}
}

// attachCurrentLegs 将 carrier 新出现的重连 leg 纳入帧解复用；返回本次新增的适配器。
func (m *EndpointFrameMux) attachCurrentLegs() []*TcpFrameAdapter {
	legs := m.dual.legStreams()
	added := make([]*TcpFrameAdapter, 0, len(legs))
	for _, leg := range legs {
		tcp := tcpStreamFromStream(leg)
		if tcp == nil || tcp.IsClosed() {
			continue
		}

		m.mu.Lock()
		_, exists := m.adapterSet[tcp]
		m.mu.Unlock()
		if exists {
			continue
		}

		tcp.SetPureForwarder(true)
		adapter := NewTcpFrameAdapter(tcp)
		if adapter == nil {
			continue
		}

		m.mu.Lock()
		if _, exists := m.adapterSet[tcp]; !exists {
			m.adapterSet[tcp] = struct{}{}
			m.adapters = append(m.adapters, adapter)
			added = append(added, adapter)
		}
		m.mu.Unlock()
	}
	return added
}

func (m *EndpointFrameMux) snapshotAdapters() []*TcpFrameAdapter {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*TcpFrameAdapter(nil), m.adapters...)
}

func (m *EndpointFrameMux) readLeg(a *TcpFrameAdapter) {
	defer m.removeAdapter(a)
	for {
		f, err := a.NextFrame(m.ctx)
		if err != nil {
			return
		}
		m.dispatchFromAdapter(a, f)
	}
}

func (m *EndpointFrameMux) removeAdapter(expected *TcpFrameAdapter) {
	if expected == nil {
		return
	}
	m.mu.Lock()
	delete(m.adapterSet, expected.stream)
	for index, adapter := range m.adapters {
		if adapter == expected {
			m.adapters = append(m.adapters[:index], m.adapters[index+1:]...)
			break
		}
	}
	for key, route := range m.inbound {
		if route.adapter == expected {
			delete(m.inbound, key)
		}
	}
	m.mu.Unlock()
}

// dispatch 把一帧按 ConnectionId 投递到对应逻辑连接的缓冲；新连接先回调 onNew。
func (m *EndpointFrameMux) dispatch(f *network.Frame) {
	m.dispatchFromAdapter(nil, f)
}

func (m *EndpointFrameMux) dispatchFromAdapter(adapter *TcpFrameAdapter, f *network.Frame) {
	connId := f.ConnectionId
	if connId == "" {
		// carrier 自身的保活 ACK 不属于任何逻辑会话，正常静默消费；其它无归属帧保留告警。
		if f.FrameType == network.FrameTypeAck {
			return
		}
		logx.Warnf("[EndpointMux] 丢弃无 connectionId 的帧: msgId=%d seq=%d type=%d", f.MessageId, f.SeqId, f.FrameType)
		return
	}
	m.mu.Lock()
	now := time.Now()
	if f.FrameType == network.FrameTypeAck {
		m.observeOutboundAckLocked(f, now)
		m.observeBillingGenerationAckLocked(f, now)
	}
	if m.isRetiredLocked(connId, now) {
		m.mu.Unlock()
		return
	}
	c := m.conns[connId]
	if c == nil && f.FrameType != network.FrameTypeData && f.FrameType != network.FrameTypeRetransmit {
		m.mu.Unlock()
		return
	}
	if adapter != nil && (f.FrameType == network.FrameTypeData || f.FrameType == network.FrameTypeRetransmit) {
		if m.inbound == nil {
			m.inbound = make(map[muxFrameKey]muxInboundRoute)
		}
		m.inbound[muxFrameKey{connectionID: connId, messageID: f.MessageId}] = muxInboundRoute{
			adapter: adapter,
			total:   f.TotalFrames,
		}
	}
	isNew := c == nil
	if isNew {
		c = newMuxConnWithContext(connId, m.writeSharedContext)
		m.conns[connId] = c
	}
	m.mu.Unlock()

	if isNew {
		logx.Infof("[EndpointMux] 新逻辑连接: connId=%s", connId)
		m.onNew(connId, c)
	}

	bs, err := f.ParseToBytes()
	if err != nil {
		logx.Errorf("[EndpointMux] 帧序列化失败 connId=%s: %v", connId, err)
		return
	}
	// push 永不阻塞 readLeg：一条逻辑连接消费慢只会让它自己的队列增长（满则丢最旧、
	// 靠端到端重传补回），绝不卡住别的连接的入站帧。这是读侧避免 HOL 的关键。
	c.push(bs)
}

// removeConn 在某逻辑连接结束时清理。供 per‑conn handler defer 调用，避免 map 泄漏。
func (m *EndpointFrameMux) removeConn(connId string) bool {
	m.mu.Lock()
	c := m.conns[connId]
	delete(m.conns, connId)
	m.retireLocked(connId, time.Now())
	for key := range m.inbound {
		if key.connectionID == connId {
			delete(m.inbound, key)
		}
	}
	for key := range m.outbound {
		if key.connectionID == connId {
			m.removeOutboundRouteLocked(key)
		}
	}
	for key := range m.billingGenerations {
		if key.connectionID == connId {
			delete(m.billingGenerations, key)
		}
	}
	m.mu.Unlock()
	if c != nil {
		c.Close()
	}
	return c != nil
}

const (
	endpointMuxTombstoneTTL        = 10 * time.Minute
	endpointMuxTombstoneLimit      = 4096
	endpointMuxDataQueueCapacity   = 64
	endpointMuxMaxControlBurst     = 32
	endpointMuxKeepAliveMaxPayload = network.HeaderLength + 512
)

func (m *EndpointFrameMux) isRetiredLocked(connID string, now time.Time) bool {
	expiresAt, exists := m.retired[connID]
	if !exists {
		return false
	}
	if now.Before(expiresAt) {
		return true
	}
	delete(m.retired, connID)
	return false
}

func (m *EndpointFrameMux) retireLocked(connID string, now time.Time) {
	if connID == "" {
		return
	}
	if m.retired == nil {
		m.retired = make(map[string]time.Time)
	}
	if expiresAt, exists := m.retired[connID]; exists && now.Before(expiresAt) {
		return
	}
	if len(m.retired) >= endpointMuxTombstoneLimit {
		var oldestID string
		var oldestExpiry time.Time
		for retiredID, expiresAt := range m.retired {
			if !now.Before(expiresAt) {
				delete(m.retired, retiredID)
				continue
			}
			if oldestID == "" || expiresAt.Before(oldestExpiry) {
				oldestID = retiredID
				oldestExpiry = expiresAt
			}
		}
		if len(m.retired) >= endpointMuxTombstoneLimit {
			delete(m.retired, oldestID)
		}
	}
	m.retired[connID] = now.Add(endpointMuxTombstoneTTL)
}

// writeShared 把一帧交给单写者 goroutine（入队即返回，除非队列满才施加公平背压）。
// 不在调用方持锁、不在调用方阻塞于 conn.Write，故一条流的慢写不会卡住别的流。
func (m *EndpointFrameMux) writeShared(f *network.Frame) error {
	return m.writeSharedContext(context.Background(), f)
}

func (m *EndpointFrameMux) writeSharedContext(ctx context.Context, f *network.Frame) error {
	if ctx == nil {
		ctx = context.Background()
	}
	queue := m.outCh
	if endpointMuxControlFrame(f) {
		queue = m.controlCh
	}
	if queue == nil {
		return errors.New("endpoint mux queue unavailable")
	}
	if err := m.trackOutboundBillingGeneration(f, time.Now()); err != nil {
		return err
	}
	select {
	case queue <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-m.ctx.Done():
		return errors.New("endpoint mux closed")
	}
}

func endpointMuxControlFrame(frame *network.Frame) bool {
	if frame == nil {
		return false
	}
	switch frame.FrameType {
	case network.FrameTypeAck, network.FrameTypeFrameSizeChange, network.FrameTypeConnectionClose:
		return true
	case network.FrameTypeData, network.FrameTypeRetransmit:
		if frame.SeqId != 0 || frame.TotalFrames != 1 ||
			len(frame.Payload) < network.HeaderLength || len(frame.Payload) > endpointMuxKeepAliveMaxPayload {
			return false
		}
		header, err := network.ParseHeader(frame.Payload[:network.HeaderLength])
		return err == nil && header.RouteName == KeepAliveRoute
	default:
		return false
	}
}

func (m *EndpointFrameMux) writeControl(frame *network.Frame) {
	if m.controlCh == nil {
		return
	}
	select {
	case m.controlCh <- frame:
	case <-m.ctx.Done():
	}
}

// orderedAdapters 返回按 preferred 协议优先排序的 leg 适配器。
func (m *EndpointFrameMux) orderedAdapters() []*TcpFrameAdapter {
	adapters := m.snapshotAdapters()
	if m.dual == nil {
		return adapters
	}
	preferred := m.dual.preferredTransport()
	m.mu.Lock()
	kcpCoolingDown := time.Now().Before(m.kcpCooldown)
	m.mu.Unlock()
	ordered := make([]*TcpFrameAdapter, 0, len(adapters))
	var rest []*TcpFrameAdapter
	for _, a := range adapters {
		kind := transportOfStream(a.stream)
		if kcpCoolingDown && legFamily(preferred) == streamTransportKCP && legFamily(kind) == streamTransportTCP {
			ordered = append(ordered, a)
		} else if kind == preferred && !(kcpCoolingDown && legFamily(kind) == streamTransportKCP) {
			ordered = append(ordered, a)
		} else {
			rest = append(rest, a)
		}
	}
	return append(ordered, rest...)
}

type muxFrameKey struct {
	connectionID string
	messageID    uint64
}

type muxInboundRoute struct {
	adapter *TcpFrameAdapter
	total   uint32
}

type muxOutboundRoute struct {
	kind         streamTransport
	total        uint32
	payloadBySeq map[uint32]int
	sentBytes    int64
	ackedBytes   int64
	ackProgress  frameAckProgress
	lastActive   time.Time
}

type muxBillingGenerationRoute struct {
	generation uint64
	total      uint32
	lastActive time.Time
}

const (
	endpointMuxFramePayload             = 32 * 1024
	endpointMuxQualityRouteTTL          = 2 * time.Minute
	endpointMuxQualityMaxRoutes         = 8192
	endpointMuxBillingGenerationLimit   = 8192
	endpointMuxQualityMaxFramesPerRoute = 32768
	endpointMuxQualityMaxTrackedFrames  = 262144
)

func (m *EndpointFrameMux) observeOutboundFrame(adapter *TcpFrameAdapter, frame *network.Frame, now time.Time) {
	if adapter == nil || frame == nil || frame.ConnectionId == "" ||
		(frame.FrameType != network.FrameTypeData && frame.FrameType != network.FrameTypeRetransmit) {
		return
	}
	kind := transportOfStream(adapter.stream)
	if legFamily(kind) != streamTransportKCP || frame.TotalFrames == 0 ||
		frame.SeqId >= frame.TotalFrames || frame.TotalFrames > endpointMuxQualityMaxFramesPerRoute {
		return
	}
	key := muxFrameKey{connectionID: frame.ConnectionId, messageID: frame.MessageId}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.outbound == nil {
		m.outbound = make(map[muxFrameKey]*muxOutboundRoute)
	}
	route := m.outbound[key]
	if route == nil {
		if len(m.outbound) >= endpointMuxQualityMaxRoutes {
			m.sweepOutboundLocked(now)
		}
		if len(m.outbound) >= endpointMuxQualityMaxRoutes ||
			m.outboundFrames >= endpointMuxQualityMaxTrackedFrames {
			return
		}
		route = &muxOutboundRoute{
			kind:         kind,
			total:        frame.TotalFrames,
			payloadBySeq: make(map[uint32]int),
			lastActive:   now,
		}
		m.outbound[key] = route
	}
	if route.total != frame.TotalFrames || route.kind != kind {
		m.removeOutboundRouteLocked(key)
		return
	}
	route.lastActive = now
	if _, exists := route.payloadBySeq[frame.SeqId]; exists {
		return
	}
	if len(route.payloadBySeq) >= endpointMuxQualityMaxFramesPerRoute ||
		m.outboundFrames >= endpointMuxQualityMaxTrackedFrames {
		m.removeOutboundRouteLocked(key)
		return
	}
	payloadBytes := len(frame.Payload)
	route.payloadBySeq[frame.SeqId] = payloadBytes
	route.sentBytes += int64(payloadBytes)
	m.outboundFrames++
	state := m.carrierGoodputStateLocked(kind, now)
	state.windowSent += int64(payloadBytes)
	state.outstanding += int64(payloadBytes)
}

func (m *EndpointFrameMux) observeOutboundAckLocked(frame *network.Frame, now time.Time) {
	if frame == nil || frame.ConnectionId == "" {
		return
	}
	key := muxFrameKey{connectionID: frame.ConnectionId, messageID: frame.MessageId}
	route := m.outbound[key]
	if route == nil {
		return
	}
	route.lastActive = now
	if delta, _, valid := acknowledgeFramePayload(
		frame,
		route.total,
		&route.ackProgress,
		func(sequence uint32) (int, bool) {
			size, exists := route.payloadBySeq[sequence]
			return size, exists
		},
	); valid && delta > 0 {
		route.ackedBytes += delta
		state := m.carrierGoodputStateLocked(route.kind, now)
		state.windowAcked += delta
		state.outstanding -= delta
		if state.outstanding < 0 {
			state.outstanding = 0
		}
	}
	if isFullFrameAck(frame, route.total) {
		m.removeOutboundRouteLocked(key)
	}
}

func muxAckPayloadBytes(frame *network.Frame, expectedTotal uint32, payloadBySeq map[uint32]int) (int64, bool) {
	payloadBytes, _, valid := acknowledgeFramePayload(
		frame,
		expectedTotal,
		&frameAckProgress{},
		func(sequence uint32) (int, bool) {
			size, exists := payloadBySeq[sequence]
			return size, exists
		},
	)
	return payloadBytes, valid
}

func (m *EndpointFrameMux) carrierGoodputStateLocked(kind streamTransport, now time.Time) *frameRelayGoodputState {
	if m.kcpGoodput == nil {
		m.kcpGoodput = make(map[streamTransport]*frameRelayGoodputState)
	}
	state := m.kcpGoodput[kind]
	if state == nil {
		state = &frameRelayGoodputState{windowStarted: now}
		m.kcpGoodput[kind] = state
	}
	return state
}

func (m *EndpointFrameMux) maintainCarrierQuality(now time.Time) {
	if m.dual == nil {
		return
	}
	m.mu.Lock()
	if !m.lastQualityMaintenance.IsZero() && now.Sub(m.lastQualityMaintenance) < frameRelaySweepInterval {
		m.mu.Unlock()
		return
	}
	m.lastQualityMaintenance = now
	m.sweepOutboundLocked(now)
	m.sweepBillingGenerationsLocked(now)
	decisions := m.evaluateCarrierGoodputLocked(now)
	if len(decisions) > 0 {
		m.kcpCooldown = now.Add(frameRelayGoodputCooldown)
	}
	m.mu.Unlock()

	for _, decision := range decisions {
		m.dual.setPreferred(streamTransportTCP)
		logx.Warnf("[EndpointMux] KCP carrier 确认吞吐连续低于阈值, 切换 TCP: goodput=%dB/s threshold=%dB/s sent=%d acked=%d window=%s cooldown=%s",
			decision.goodput, defaultKCPGoodputBytesPerSecond, decision.sent, decision.acked,
			decision.elapsed, frameRelayGoodputCooldown)
	}
}

func (m *EndpointFrameMux) trackOutboundBillingGeneration(frame *network.Frame, now time.Time) error {
	if m == nil || m.dual == nil || frame == nil || frame.ConnectionId == "" ||
		(frame.FrameType != network.FrameTypeData && frame.FrameType != network.FrameTypeRetransmit) {
		return nil
	}
	key := muxFrameKey{connectionID: frame.ConnectionId, messageID: frame.MessageId}
	generation := m.dual.relayGeneration.Load()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.billingGenerations == nil {
		m.billingGenerations = make(map[muxFrameKey]*muxBillingGenerationRoute)
	}
	if route := m.billingGenerations[key]; route != nil {
		if route.generation != generation {
			return ErrRelayChangedDuringSend
		}
		route.lastActive = now
		return nil
	}
	if frame.FrameType != network.FrameTypeData || frame.SeqId != 0 ||
		len(frame.Payload) < network.HeaderLength {
		return nil
	}
	header, err := network.ParseHeader(frame.Payload[:network.HeaderLength])
	if err != nil || header.BillingSequence == 0 {
		return nil
	}
	if len(m.billingGenerations) >= endpointMuxBillingGenerationLimit {
		m.sweepBillingGenerationsLocked(now)
	}
	if len(m.billingGenerations) >= endpointMuxBillingGenerationLimit {
		return errors.New("endpoint mux billing generation capacity exceeded")
	}
	m.billingGenerations[key] = &muxBillingGenerationRoute{
		generation: generation,
		total:      frame.TotalFrames,
		lastActive: now,
	}
	return nil
}

func (m *EndpointFrameMux) outboundBillingGenerationStale(frame *network.Frame, now time.Time) bool {
	if m == nil || m.dual == nil || frame == nil || frame.ConnectionId == "" ||
		(frame.FrameType != network.FrameTypeData && frame.FrameType != network.FrameTypeRetransmit) {
		return false
	}
	key := muxFrameKey{connectionID: frame.ConnectionId, messageID: frame.MessageId}
	m.mu.Lock()
	defer m.mu.Unlock()
	route := m.billingGenerations[key]
	if route == nil {
		return false
	}
	route.lastActive = now
	return route.generation != m.dual.relayGeneration.Load()
}

func (m *EndpointFrameMux) observeBillingGenerationAckLocked(frame *network.Frame, now time.Time) {
	if frame == nil || frame.ConnectionId == "" {
		return
	}
	key := muxFrameKey{connectionID: frame.ConnectionId, messageID: frame.MessageId}
	route := m.billingGenerations[key]
	if route == nil {
		return
	}
	route.lastActive = now
	if isFullFrameAck(frame, route.total) {
		delete(m.billingGenerations, key)
	}
}

func (m *EndpointFrameMux) sweepBillingGenerationsLocked(now time.Time) {
	for key, route := range m.billingGenerations {
		if route == nil || now.Sub(route.lastActive) >= endpointMuxQualityRouteTTL {
			delete(m.billingGenerations, key)
		}
	}
}

func (m *EndpointFrameMux) evaluateCarrierGoodputLocked(now time.Time) []frameRelayGoodputDecision {
	if now.Before(m.kcpCooldown) {
		return nil
	}
	policy := defaultKCPSendQualityPolicy()
	decisions := make([]frameRelayGoodputDecision, 0)
	for kind, state := range m.kcpGoodput {
		if state == nil || state.windowStarted.IsZero() || now.Before(state.windowStarted) {
			continue
		}
		elapsed := now.Sub(state.windowStarted)
		if elapsed < frameRelayGoodputWindow {
			continue
		}
		sent := state.windowSent
		acked := state.windowAcked
		outstanding := state.outstanding
		state.windowStarted = now
		state.windowSent = 0
		state.windowAcked = 0
		if sent < int64(policy.minimumPayloadBytes) {
			if outstanding < int64(policy.minimumPayloadBytes) || acked >= sent {
				state.lowWindowStreak = 0
			}
			continue
		}
		if outstanding < int64(policy.minimumPayloadBytes) || acked >= sent {
			state.lowWindowStreak = 0
			continue
		}
		goodput := int64(float64(acked) / elapsed.Seconds())
		if goodput >= policy.minimumGoodputBytesPerSec {
			state.lowWindowStreak = 0
			continue
		}
		state.lowWindowStreak++
		if state.lowWindowStreak < frameRelaySlowRouteThreshold {
			continue
		}
		decisions = append(decisions, frameRelayGoodputDecision{
			kcpKind: kind,
			tcpKind: streamTransportTCP,
			sent:    sent,
			acked:   acked,
			elapsed: elapsed,
			goodput: goodput,
		})
		delete(m.kcpGoodput, kind)
	}
	return decisions
}

func (m *EndpointFrameMux) sweepOutboundLocked(now time.Time) {
	for key, route := range m.outbound {
		if route == nil || now.Sub(route.lastActive) >= endpointMuxQualityRouteTTL {
			m.removeOutboundRouteLocked(key)
		}
	}
}

func (m *EndpointFrameMux) removeOutboundRouteLocked(key muxFrameKey) {
	route := m.outbound[key]
	if route == nil {
		delete(m.outbound, key)
		return
	}
	m.outboundFrames -= len(route.payloadBySeq)
	if m.outboundFrames < 0 {
		m.outboundFrames = 0
	}
	if outstanding := route.sentBytes - route.ackedBytes; outstanding > 0 {
		if state := m.kcpGoodput[route.kind]; state != nil {
			state.outstanding -= outstanding
			if state.outstanding < 0 {
				state.outstanding = 0
			}
		}
	}
	delete(m.outbound, key)
}

func (m *EndpointFrameMux) orderedAdaptersForFrame(frame *network.Frame) ([]*TcpFrameAdapter, muxFrameKey, bool) {
	ordered := m.orderedAdapters()
	if frame == nil || frame.FrameType != network.FrameTypeAck || frame.ConnectionId == "" {
		return ordered, muxFrameKey{}, false
	}
	key := muxFrameKey{connectionID: frame.ConnectionId, messageID: frame.MessageId}
	m.mu.Lock()
	route, exists := m.inbound[key]
	m.mu.Unlock()
	if !exists || route.adapter == nil {
		return ordered, key, false
	}
	for index, adapter := range ordered {
		if adapter != route.adapter {
			continue
		}
		if index > 0 {
			copy(ordered[1:index+1], ordered[:index])
			ordered[0] = adapter
		}
		return ordered[:1], key, true
	}
	m.forgetInboundRoute(key, route.adapter)
	return nil, key, true
}

func (m *EndpointFrameMux) forgetInboundRoute(key muxFrameKey, expected *TcpFrameAdapter) {
	m.mu.Lock()
	if route, exists := m.inbound[key]; exists && route.adapter == expected {
		delete(m.inbound, key)
	}
	m.mu.Unlock()
}

func (m *EndpointFrameMux) completeInboundRoute(key muxFrameKey, expected *TcpFrameAdapter, frame *network.Frame) {
	m.mu.Lock()
	if route, exists := m.inbound[key]; exists && route.adapter == expected && isFullFrameAck(frame, route.total) {
		delete(m.inbound, key)
	}
	m.mu.Unlock()
}

// transportOfStream 判断某 TcpStream 属于哪种协议 leg（按底层连接 RemoteAddr 网络类型）。
func transportOfStream(t *TcpStream) streamTransport {
	if t == nil || t.connection == nil {
		return streamTransportUnknown
	}
	if addr := t.connection.RemoteAddr(); addr != nil {
		switch addr.Network() {
		case "tcp", "tcp4", "tcp6":
			return streamTransportTCP
		default:
			return streamTransportKCP
		}
	}
	return streamTransportUnknown
}

// =============================================================================
// muxConn：per‑conn 虚拟 net.Conn。
//   Read  —— 从本连接缓冲（incoming）取序列化帧字节，喂给 per‑conn TcpStream 的 ReadFrame。
//   Write —— per‑conn TcpStream 写出的（可能多帧拼接的）字节，逐帧还原后经 writeFn 写到共享连接。
// 这就是用户要的「缓冲区」：按 connectionId 分隔，避免跨连接错误消费。
// =============================================================================

// muxConnMaxQueue 是单条逻辑连接入站帧的最大缓冲帧数；超过则丢最旧（端到端重传补回），
// 避免某条流的慢消费拖垮内存。正常负载远不会触及。
const muxConnMaxQueue = 8192

type muxConn struct {
	connId  string
	writeFn func(context.Context, *network.Frame) error

	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte // demux 推入的「整帧」序列化字节，先进先出
	rem    []byte   // 上一帧未被 Read 取完的剩余字节
	closed bool

	closeCh            chan struct{}
	closeOnce          sync.Once
	writeMu            sync.Mutex
	writeDeadline      time.Time
	writeGeneration    uint64
	activeWriteCancels map[uint64]context.CancelFunc
}

func newMuxConn(connId string, writeFn func(*network.Frame) error) *muxConn {
	return newMuxConnWithContext(connId, func(_ context.Context, frame *network.Frame) error {
		return writeFn(frame)
	})
}

func newMuxConnWithContext(connId string, writeFn func(context.Context, *network.Frame) error) *muxConn {
	c := &muxConn{
		connId:  connId,
		writeFn: writeFn,
		closeCh: make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// push 把一整帧字节追加到队列（永不阻塞调用方）。队列超上限则丢最旧。
func (c *muxConn) push(b []byte) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if len(c.queue) >= muxConnMaxQueue {
		c.queue = c.queue[1:]
		logx.Warnf("[EndpointMux] connId=%s 入站队列超限, 丢最旧帧(靠重传补回)", c.connId)
	}
	c.queue = append(c.queue, b)
	c.mu.Unlock()
	c.cond.Signal()
}

func (c *muxConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	for len(c.rem) == 0 {
		for len(c.queue) == 0 && !c.closed {
			c.cond.Wait()
		}
		if len(c.queue) == 0 && c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		c.rem = c.queue[0]
		c.queue = c.queue[1:]
	}
	n := copy(p, c.rem)
	c.rem = c.rem[n:]
	c.mu.Unlock()
	return n, nil
}

func (c *muxConn) Write(p []byte) (int, error) {
	select {
	case <-c.closeCh:
		return 0, io.ErrClosedPipe
	default:
	}
	// p 可能包含多帧拼接（TcpStream.writeFrames 会把整批帧并成一次 Write）。
	// 逐帧 ReadFrame 还原（每帧自描述长度），再交给 writeFn 写共享连接。
	r := bytes.NewReader(p)
	for r.Len() > 0 {
		f, err := network.ReadFrame(r)
		if err != nil {
			return 0, err
		}
		if err := c.writeFrameContext(f); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *muxConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.writeMu.Lock()
		for generation, cancel := range c.activeWriteCancels {
			cancel()
			delete(c.activeWriteCancels, generation)
		}
		c.writeMu.Unlock()
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.cond.Broadcast()
	})
	return nil
}

func (c *muxConn) LocalAddr() net.Addr               { return muxAddr(c.connId) }
func (c *muxConn) RemoteAddr() net.Addr              { return muxAddr(c.connId) }
func (c *muxConn) SetDeadline(t time.Time) error     { return nil }
func (c *muxConn) SetReadDeadline(t time.Time) error { return nil }
func (c *muxConn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	c.writeDeadline = t
	c.writeGeneration++
	for _, cancel := range c.activeWriteCancels {
		cancel()
	}
	c.writeMu.Unlock()
	return nil
}

func (c *muxConn) beginWriteContext() (context.Context, context.CancelFunc, uint64) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeGeneration++
	generation := c.writeGeneration
	var ctx context.Context
	var cancel context.CancelFunc
	if c.writeDeadline.IsZero() {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithDeadline(context.Background(), c.writeDeadline)
	}
	if c.activeWriteCancels == nil {
		c.activeWriteCancels = make(map[uint64]context.CancelFunc)
	}
	c.activeWriteCancels[generation] = cancel
	return ctx, cancel, generation
}

func (c *muxConn) finishWriteContext(cancel context.CancelFunc, generation uint64) {
	c.writeMu.Lock()
	delete(c.activeWriteCancels, generation)
	c.writeMu.Unlock()
	cancel()
}

func (c *muxConn) writeStateChanged(generation uint64) (bool, time.Time) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeGeneration != generation, c.writeDeadline
}

func (c *muxConn) writeFrameContext(frame *network.Frame) error {
	for {
		ctx, cancel, generation := c.beginWriteContext()
		err := c.writeFn(ctx, frame)
		c.finishWriteContext(cancel, generation)
		if err == nil {
			return nil
		}
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		changed, deadline := c.writeStateChanged(generation)
		select {
		case <-c.closeCh:
			return io.ErrClosedPipe
		default:
		}
		if !changed {
			return err
		}
		if deadline.IsZero() || time.Now().Before(deadline) {
			continue
		}
		return context.DeadlineExceeded
	}
}

// muxAddr 标识不受物理 MTU 限制的进程内虚拟连接。
type muxAddr string

func (a muxAddr) Network() string { return "mux" }
func (a muxAddr) String() string  { return string(a) }
