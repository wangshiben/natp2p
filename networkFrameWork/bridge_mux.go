package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// bridge mux —— relay↔relay 物理连接上的轻量多路复用层
//
// 设计要点（见 RELAY_BRIDGE_POOL_DESIGN.md）：
//   - 一条 relay↔relay 的物理 net.Conn 承载多路跨中继会话（每个 connID 一条 mux stream）。
//   - 复用 network.Frame 作为 mux 外层信封：用 network.ReadFrame 精确分帧、绝不过读。
//       * 外层 Frame.ConnectionId = mux streamID（= 跨中继业务 connID）
//       * 外层 Frame.FrameType    = mux 控制类型（OPEN / DATA / CLOSE，专用值）
//       * 外层 Frame.Payload      = 内层 E2E 原始字节（对 mux 层完全透明）
//   - MuxStream 实现 net.Conn，使桥接两端现有逻辑（裸字节泵 / ListenTCPConnection）
//     几乎零改动即可接入。
//
// relay↔relay 物理链路上只跑 mux 帧，因此这里的 FrameType 取值与业务 FrameType
// 命名空间互不影响（同一条物理连接不会混跑两类帧）。
// =============================================================================

const (
	// muxFrameOpen：入口 relay 通知对端"开一条新逻辑会话"。
	// Payload 携带 OPEN 元信息（target nodeId + local1 公钥），ConnectionId = streamID。
	muxFrameOpen uint8 = 200
	// muxFrameData：会话字节。Payload = E2E 原始字节，ConnectionId = streamID。
	muxFrameData uint8 = 201
	// muxFrameClose：会话结束。ConnectionId = streamID。
	muxFrameClose uint8 = 202
)

var (
	errMuxClosed     = errors.New("bridge mux: session closed")
	errMuxStreamGone = errors.New("bridge mux: stream closed")
)

// muxOpenInfo 是 OPEN 帧 Payload 的解码结果。
// 线格式（与 dialRawBridgeConn 原 hello 等价）：targetNodeId 与 originPubKey 用 '\n' 分隔。
type muxOpenInfo struct {
	targetNodeID string
	originPubKey string
}

func encodeMuxOpen(targetNodeID, originPubKey string) []byte {
	return []byte(targetNodeID + "\n" + originPubKey)
}

func decodeMuxOpen(payload []byte) muxOpenInfo {
	s := string(payload)
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return muxOpenInfo{targetNodeID: s[:i], originPubKey: s[i+1:]}
		}
	}
	return muxOpenInfo{targetNodeID: s}
}

// MuxSession 在一条物理 net.Conn 上多路复用若干 MuxStream。
//
// 入口侧（isClient=true）调用 OpenStream 主动开会话；
// 对端侧（isClient=false）通过 Accept 收取对端开的会话。
type MuxSession struct {
	conn   net.Conn
	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex // 串行化对底层 conn 的写

	mu       sync.Mutex
	streams  map[string]*MuxStream
	accept   chan *MuxStream
	closed   bool
	isClient bool

	// 指标（供连接池扩容判定）
	activeStreams int64 // 当前活跃 stream 数
	pendingFrames int64 // 进入写串行队列但尚未写出的帧数（发送压力近似）
}

// NewMuxSession 在 conn 上建立 mux 会话并启动读循环。
// parent 取消或底层 conn 断开时会话整体关闭。
func NewMuxSession(parent context.Context, conn net.Conn, isClient bool) *MuxSession {
	ctx, cancel := context.WithCancel(parent)
	s := &MuxSession{
		conn:     conn,
		ctx:      ctx,
		cancel:   cancel,
		streams:  make(map[string]*MuxStream),
		accept:   make(chan *MuxStream, 32),
		isClient: isClient,
	}
	go s.readLoop()
	return s
}

// Context 暴露会话上下文（连接池可据此感知会话死亡）。
func (s *MuxSession) Context() context.Context { return s.ctx }

// ActiveStreams 返回当前活跃 stream 数（扩容并发水位）。
func (s *MuxSession) ActiveStreams() int { return int(atomic.LoadInt64(&s.activeStreams)) }

// PendingFrames 返回排队待写的帧数近似值（扩容发送压力水位）。
func (s *MuxSession) PendingFrames() int { return int(atomic.LoadInt64(&s.pendingFrames)) }

// IsClosed 报告会话是否已关闭。
func (s *MuxSession) IsClosed() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

// OpenStream 开一条新逻辑会话（入口侧）。streamID 用业务 connID，
// open 元信息（targetNodeID + 公钥）随 OPEN 帧发往对端，供对端合成 hello 接入下游。
func (s *MuxSession) OpenStream(streamID, targetNodeID, originPubKey string) (*MuxStream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errMuxClosed
	}
	if _, exists := s.streams[streamID]; exists {
		s.mu.Unlock()
		return nil, errors.New("bridge mux: duplicate streamID " + streamID)
	}
	st := newMuxStream(s, streamID)
	s.streams[streamID] = st
	s.mu.Unlock()
	atomic.AddInt64(&s.activeStreams, 1)

	if err := s.writeFrame(muxFrameOpen, streamID, encodeMuxOpen(targetNodeID, originPubKey)); err != nil {
		s.dropStream(streamID)
		return nil, err
	}
	return st, nil
}

// Accept 取对端开的下一条会话（对端侧），会话关闭返回 errMuxClosed。
func (s *MuxSession) Accept() (*MuxStream, error) {
	select {
	case st, ok := <-s.accept:
		if !ok {
			return nil, errMuxClosed
		}
		return st, nil
	case <-s.ctx.Done():
		return nil, errMuxClosed
	}
}

// Close 关闭会话与其上所有 stream，并关闭底层 conn。
func (s *MuxSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	streams := make([]*MuxStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[string]*MuxStream)
	close(s.accept)
	s.mu.Unlock()

	s.cancel()
	for _, st := range streams {
		st.closeLocal()
	}
	return s.conn.Close()
}

// readLoop 从物理连接精确读 mux 帧并分派。会话生命周期与读循环绑定。
func (s *MuxSession) readLoop() {
	defer s.Close()
	for {
		frame, err := network.ReadFrame(s.conn)
		if err != nil {
			if err != io.EOF {
				logx.Debugf("[bridge-mux] readLoop 结束: %v", err)
			}
			return
		}
		streamID := frame.ConnectionId
		switch frame.FrameType {
		case muxFrameOpen:
			s.handleOpen(streamID, frame.Payload)
		case muxFrameData:
			s.mu.Lock()
			st := s.streams[streamID]
			s.mu.Unlock()
			if st != nil {
				st.deliver(frame.Payload)
			}
		case muxFrameClose:
			s.dropStream(streamID)
		default:
			// 物理链路上不应出现非 mux 帧，忽略。
		}
	}
}

// handleOpen 注册对端开的 stream 并投递到 Accept 队列。
func (s *MuxSession) handleOpen(streamID string, openPayload []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if _, exists := s.streams[streamID]; exists {
		s.mu.Unlock()
		return
	}
	st := newMuxStream(s, streamID)
	st.openInfo = decodeMuxOpen(openPayload)
	s.streams[streamID] = st
	s.mu.Unlock()
	atomic.AddInt64(&s.activeStreams, 1)

	select {
	case s.accept <- st:
	case <-s.ctx.Done():
	}
}

// dropStream 从表中移除并本地关闭一条 stream（对端 CLOSE 或本地 Close 调用）。
func (s *MuxSession) dropStream(streamID string) {
	s.mu.Lock()
	st := s.streams[streamID]
	if st != nil {
		delete(s.streams, streamID)
	}
	s.mu.Unlock()
	if st != nil {
		atomic.AddInt64(&s.activeStreams, -1)
		st.closeLocal()
	}
}

// writeFrame 把一帧 mux 帧串行写入底层 conn。pendingFrames 近似反映写压力。
func (s *MuxSession) writeFrame(typ uint8, streamID string, payload []byte) error {
	frame := &network.Frame{
		FrameType:    typ,
		ConnectionId: streamID,
		Payload:      payload,
	}
	bs, err := frame.ParseToBytes()
	if err != nil {
		return err
	}
	atomic.AddInt64(&s.pendingFrames, 1)
	s.writeMu.Lock()
	defer func() {
		s.writeMu.Unlock()
		atomic.AddInt64(&s.pendingFrames, -1)
	}()
	select {
	case <-s.ctx.Done():
		return errMuxClosed
	default:
	}
	if _, err := s.conn.Write(bs); err != nil {
		return err
	}
	return nil
}

// =============================================================================
// MuxStream —— 一条逻辑会话，实现 net.Conn，使桥接两端零改动接入。
// =============================================================================

// MuxStream 是 MuxSession 上的一条逻辑字节流，实现 net.Conn。
type MuxStream struct {
	sess     *MuxSession
	id       string
	openInfo muxOpenInfo // 仅对端 Accept 出的 stream 有意义

	mu       sync.Mutex
	buf      []byte
	dataCh   chan struct{}
	closed   bool
	closedCh chan struct{}
	once     sync.Once
}

func newMuxStream(sess *MuxSession, id string) *MuxStream {
	return &MuxStream{
		sess:     sess,
		id:       id,
		dataCh:   make(chan struct{}, 1),
		closedCh: make(chan struct{}),
	}
}

// OpenInfo 返回对端开此 stream 时携带的元信息（target nodeId + 公钥）。
func (st *MuxStream) OpenInfo() muxOpenInfo { return st.openInfo }

// StreamID 返回该逻辑会话 ID（= 业务 connID）。
func (st *MuxStream) StreamID() string { return st.id }

// deliver 追加入站字节并唤醒阻塞的 Read。
func (st *MuxStream) deliver(data []byte) {
	if len(data) == 0 {
		return
	}
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	st.buf = append(st.buf, data...)
	st.mu.Unlock()
	select {
	case st.dataCh <- struct{}{}:
	default:
	}
}

// Read 实现 io.Reader：阻塞直到有数据或 stream 关闭（缓冲耗尽后返回 io.EOF）。
func (st *MuxStream) Read(p []byte) (int, error) {
	for {
		st.mu.Lock()
		if len(st.buf) > 0 {
			n := copy(p, st.buf)
			st.buf = st.buf[n:]
			st.mu.Unlock()
			return n, nil
		}
		closed := st.closed
		st.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		select {
		case <-st.dataCh:
		case <-st.closedCh:
		case <-st.sess.ctx.Done():
			return 0, io.EOF
		}
	}
}

// Write 实现 io.Writer：大写入切成多帧 DATA。
func (st *MuxStream) Write(p []byte) (int, error) {
	const maxChunk = 32 * 1024
	st.mu.Lock()
	closed := st.closed
	st.mu.Unlock()
	if closed {
		return 0, errMuxStreamGone
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		if err := st.sess.writeFrame(muxFrameData, st.id, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Close 发 CLOSE 帧并本地拆除 stream。
func (st *MuxStream) Close() error {
	st.mu.Lock()
	already := st.closed
	st.mu.Unlock()
	if !already {
		_ = st.sess.writeFrame(muxFrameClose, st.id, nil)
	}
	st.sess.dropStream(st.id)
	st.closeLocal()
	return nil
}

// closeLocal 不发帧地标记关闭（对端 CLOSE 或会话死亡时用）。
func (st *MuxStream) closeLocal() {
	st.once.Do(func() {
		st.mu.Lock()
		st.closed = true
		st.mu.Unlock()
		close(st.closedCh)
		select {
		case st.dataCh <- struct{}{}:
		default:
		}
	})
}

// --- net.Conn 其余方法：mux stream 之上无独立地址/截止时间语义，给出安全占位 ---

type bridgeMuxAddr struct{ id string }

func (a bridgeMuxAddr) Network() string { return "bridge-mux" }
func (a bridgeMuxAddr) String() string  { return "bridge-mux:" + a.id }

func (st *MuxStream) LocalAddr() net.Addr  { return bridgeMuxAddr{id: st.id} }
func (st *MuxStream) RemoteAddr() net.Addr { return bridgeMuxAddr{id: st.id} }

// SetDeadline / SetReadDeadline / SetWriteDeadline：mux stream 由 Read/Write 内部
// 通过会话 ctx 与 closedCh 控制生命周期，不支持独立 deadline，返回 nil 不报错以兼容
// 调用 net.Conn 通用接口的代码路径。
func (st *MuxStream) SetDeadline(t time.Time) error      { return nil }
func (st *MuxStream) SetReadDeadline(t time.Time) error  { return nil }
func (st *MuxStream) SetWriteDeadline(t time.Time) error { return nil }

// =============================================================================
// 物理连接级握手 + 两端接入辅助
// =============================================================================

// muxHandshakeRoute 是 relay↔relay 多路复用物理连接的握手 RouteName。
// 与 relaynode.RelayBridgeMuxRoute 同值；在本包内重复定义以避免反向依赖 relaynode 包。
const muxHandshakeRoute = "/relay/bridge-mux"

// DialBridgeMuxSession 裸拨一条到对端 relay 的物理 TCP 连接，发送一次物理连接级握手，
// 然后在其上建立 client 侧 MuxSession。之后用 session.OpenStream(connID,...) 开多路会话。
//
//	selfNodeID 入口 relay 自身 NodeId（握手帧 Header.NodeId）。
func DialBridgeMuxSession(parent context.Context, addr, selfNodeID string) (*MuxSession, error) {
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(2 * 1024 * 1024)
		_ = tcpConn.SetWriteBuffer(2 * 1024 * 1024)
	}
	// 物理连接级握手：一条普通 Message 首帧，RouteName 标记 mux 桥接物理连接。
	header := &network.Header{
		RouteName:     muxHandshakeRoute,
		NodeId:        selfNodeID,
		NodeIdVersion: 1,
	}
	msg := &network.Message{Header: header, Payload: []byte(selfNodeID)}
	frames, err := msg.ToFrames(1)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	for _, f := range frames {
		bs, err := f.ParseToBytes()
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := conn.Write(bs); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return NewMuxSession(parent, conn, true), nil
}

// AcceptBridgeMuxStream 在对端 relay 侧把一条 MuxStream 转换成"看起来像普通 client 首帧接入"
// 的 net.Conn：在 stream 字节前预置一条合成 hello 帧（Header.NodeId=target,
// Payload=local1 公钥, ConnectionId=connID），之后透传 stream 的 E2E 字节。
// 返回的 net.Conn 可直接交给 TransportCover.ListenTCPConnection，复用全部下游接入逻辑。
func AcceptBridgeMuxStream(st *MuxStream) (net.Conn, error) {
	info := st.OpenInfo()
	header := &network.Header{
		RouteName:    "",
		NodeId:       info.targetNodeID,
		NodeIdVersion: 1,
		ConnectionId: st.StreamID(),
	}
	msg := &network.Message{Header: header, Payload: []byte(info.originPubKey)}
	frames, err := msg.ToFrames(1)
	if err != nil {
		return nil, err
	}
	var prefix []byte
	for _, f := range frames {
		bs, err := f.ParseToBytes()
		if err != nil {
			return nil, err
		}
		prefix = append(prefix, bs...)
	}
	return &prefixConn{Conn: st, prefix: prefix}, nil
}

// prefixConn 在底层 net.Conn 的读取流前注入一段预置字节（合成 hello 帧），
// 写入与生命周期透传给底层 conn。
type prefixConn struct {
	net.Conn
	mu     sync.Mutex
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	p.mu.Lock()
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		p.mu.Unlock()
		return n, nil
	}
	p.mu.Unlock()
	return p.Conn.Read(b)
}
