package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
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
// 线格式（'\n' 分隔，向后兼容）：targetNodeId \n originPubKey [\n legIndex \n legCount [\n legFlags]]
// 老格式只有前两段或前四段，解码时 legCount 缺省=1、legFlags 缺省=0。
type muxOpenInfo struct {
	targetNodeID string
	originPubKey string
	legIndex     int // 条带化时本 leg 在逻辑连接内的序号（0-based）
	legCount     int // 条带化时逻辑连接的总 leg 数；1 表示非条带化
	legFlags     uint8
}

func encodeMuxOpen(targetNodeID, originPubKey string, legFlags ...uint8) []byte {
	return encodeMuxOpenLeg(targetNodeID, originPubKey, 0, 1, legFlags...)
}

// encodeMuxOpenLeg 编码带条带化元信息的 OPEN payload。
func encodeMuxOpenLeg(targetNodeID, originPubKey string, legIndex, legCount int, legFlags ...uint8) []byte {
	flags := optionalLegFlags(legFlags)
	if legCount <= 1 && flags == 0 {
		// 单 leg：保持老格式（两段），与老对端完全兼容。
		return []byte(targetNodeID + "\n" + originPubKey)
	}
	if legCount <= 1 {
		legIndex = 0
		legCount = 1
	}
	payload := targetNodeID + "\n" + originPubKey + "\n" +
		itoa(legIndex) + "\n" + itoa(legCount)
	if flags != 0 {
		payload += "\n" + itoa(int(flags))
	}
	return []byte(payload)
}

func optionalLegFlags(flags []uint8) uint8 {
	if len(flags) == 0 {
		return 0
	}
	return flags[0]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func decodeMuxOpen(payload []byte) muxOpenInfo {
	s := string(payload)
	parts := splitN(s, '\n', 5)
	info := muxOpenInfo{legIndex: 0, legCount: 1}
	if len(parts) > 0 {
		info.targetNodeID = parts[0]
	}
	if len(parts) > 1 {
		info.originPubKey = parts[1]
	}
	if len(parts) > 3 {
		info.legIndex = atoi(parts[2])
		if c := atoi(parts[3]); c > 0 {
			info.legCount = c
		}
	}
	if len(parts) > 4 {
		if flags := atoi(parts[4]); flags >= 0 && flags <= int(^uint8(0)) {
			info.legFlags = uint8(flags)
		}
	}
	return info
}

// splitN 按 sep 分割 s 为至多 n 段（最后一段保留剩余所有，含 sep）。
func splitN(s string, sep byte, n int) []string {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
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

	// 指标（供连接池扩容/调度判定）
	activeStreams int64 // 当前活跃 stream 数
	pendingFrames int64 // 进入写串行队列但尚未写出的帧数（发送压力近似）
	pendingBytes  int64 // 进入写串行队列但尚未写出的字节数（写压力, 调度用, 比帧数更准）
	wroteBytes    int64 // 累计已写出字节数（吞吐近似, 调度可据增量估算热度）
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

// PendingBytes 返回排队待写但尚未写出的字节数（写压力, 调度选 leg 用，比帧数更准）。
func (s *MuxSession) PendingBytes() int64 { return atomic.LoadInt64(&s.pendingBytes) }

// WroteBytes 返回累计已写出字节数（吞吐近似，调度可据采样增量估算连接热度）。
func (s *MuxSession) WroteBytes() int64 { return atomic.LoadInt64(&s.wroteBytes) }

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
func (s *MuxSession) OpenStream(streamID, targetNodeID, originPubKey string, legFlags ...uint8) (*MuxStream, error) {
	return s.OpenStreamLeg(streamID, targetNodeID, originPubKey, 0, 1, legFlags...)
}

// OpenStreamLeg 开一条带条带化元信息的逻辑会话 leg。
// legCount>1 时，对端据 (streamID, legIndex, legCount) 把多条 mux 会话归并为一条条带化逻辑连接。
func (s *MuxSession) OpenStreamLeg(streamID, targetNodeID, originPubKey string, legIndex, legCount int, legFlags ...uint8) (*MuxStream, error) {
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

	if err := s.writeFrame(muxFrameOpen, streamID, encodeMuxOpenLeg(targetNodeID, originPubKey, legIndex, legCount, legFlags...)); err != nil {
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
				st.deliverSeq(frame.MessageId, frame.Payload)
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
	return s.writeFrameSeq(typ, streamID, 0, payload)
}

// writeFrameSeq 同 writeFrame，但额外携带逻辑连接级序号 seq（写入 Frame.MessageId）。
// 条带化（F3）下，单条逻辑连接的字节被拆到多条物理 leg 发送，接收端据 seq 按序重组。
// 非条带化路径 seq=0，对端忽略无害（老对端同样忽略 MessageId，向后兼容）。
func (s *MuxSession) writeFrameSeq(typ uint8, streamID string, seq uint64, payload []byte) error {
	frame := &network.Frame{
		MessageId:    seq,
		FrameType:    typ,
		ConnectionId: streamID,
		Payload:      payload,
	}
	bs, err := frame.ParseToBytes()
	if err != nil {
		return err
	}
	atomic.AddInt64(&s.pendingFrames, 1)
	atomic.AddInt64(&s.pendingBytes, int64(len(bs)))
	s.writeMu.Lock()
	defer func() {
		s.writeMu.Unlock()
		atomic.AddInt64(&s.pendingFrames, -1)
		atomic.AddInt64(&s.pendingBytes, -int64(len(bs)))
	}()
	select {
	case <-s.ctx.Done():
		return errMuxClosed
	default:
	}
	if _, err := s.conn.Write(bs); err != nil {
		return err
	}
	atomic.AddInt64(&s.wroteBytes, int64(len(bs)))
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
	// deliverHook 非 nil 时，入站字节交给它（条带化 LogicalConn 的重排器）而非本地 buf。
	deliverHook func(seq uint64, data []byte)
	// hookPending 暂存「hook 设置之前」就到达的条带化分片(seq,data)。
	// 条带化归并(collectStripedLeg)需聚齐 M 条 leg 才 attach hook，但 leg0 可能在其余 leg
	// 完成 OPEN 之前就收到 DATA 帧（如握手首帧）。这些早到分片若直接落入 st.buf 就对
	// 重排器不可见 → 永久丢失 → 重排器卡在 seq 缺口、握手挂死。改为先暂存，attach 时回放。
	hookPending []pendingSeqChunk
}

// pendingSeqChunk 是 hook attach 前暂存的一个带序号分片。
type pendingSeqChunk struct {
	seq  uint64
	data []byte
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

// TargetNodeID/OriginPubKey 暴露对端 OPEN 元信息（接入侧条带化归并用）。
func (st *MuxStream) TargetNodeID() string { return st.openInfo.targetNodeID }
func (st *MuxStream) OriginPubKey() string { return st.openInfo.originPubKey }

// LegIndex/LegCount 返回条带化元信息（对端 Accept 出的 leg 有意义）。
// LegCount<=1 表示非条带化（单 leg）。
func (st *MuxStream) LegIndex() int { return st.openInfo.legIndex }
func (st *MuxStream) LegCount() int {
	if st.openInfo.legCount <= 0 {
		return 1
	}
	return st.openInfo.legCount
}

// LegFlags 返回入口业务首帧携带的 leg 标志位。
func (st *MuxStream) LegFlags() uint8 { return st.openInfo.legFlags }

// StreamID 返回该逻辑会话 ID（= 业务 connID）。
func (st *MuxStream) StreamID() string { return st.id }

// deliver 追加入站字节并唤醒阻塞的 Read（无序号路径）。
func (st *MuxStream) deliver(data []byte) {
	st.deliverSeq(0, data)
}

// deliverSeq 投递带逻辑连接级序号的入站字节。
// 若设置了 deliverHook（条带化 LogicalConn 注册），则交给 hook 做重排；否则按原路追加到本地缓冲。
func (st *MuxStream) deliverSeq(seq uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	st.mu.Lock()
	hook := st.deliverHook
	closed := st.closed
	striped := st.openInfo.legCount > 1
	if closed {
		st.mu.Unlock()
		return
	}
	if hook == nil && striped {
		// 条带化 leg 但 hook 尚未 attach（其余 leg 还没聚齐）：暂存早到分片，等 attach 回放。
		// 复制一份：底层读缓冲会被复用。
		cp := make([]byte, len(data))
		copy(cp, data)
		st.hookPending = append(st.hookPending, pendingSeqChunk{seq: seq, data: cp})
		st.mu.Unlock()
		return
	}
	st.mu.Unlock()
	if hook != nil {
		// 条带化：交给 LogicalConn 的重排器（自带其内部缓冲与唤醒）。
		hook(seq, data)
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

// setDeliverHook 让上层（条带化 LogicalConn）接管该 leg 的入站投递。
// attach 时把「hook 设置前」暂存的早到分片按到达顺序回放给 hook，消除条带化归并竞态丢帧。
func (st *MuxStream) setDeliverHook(h func(seq uint64, data []byte)) {
	st.mu.Lock()
	st.deliverHook = h
	pending := st.hookPending
	st.hookPending = nil
	st.mu.Unlock()
	for _, pc := range pending {
		h(pc.seq, pc.data)
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

// writeChunkSeq 把单个分片以给定逻辑连接级序号 seq 发出（条带化 LogicalConn 用）。
// 调用方负责分片不超过 maxChunk 并保证 seq 在该逻辑连接内连续递增。
func (st *MuxStream) writeChunkSeq(seq uint64, chunk []byte) error {
	st.mu.Lock()
	closed := st.closed
	st.mu.Unlock()
	if closed {
		return errMuxStreamGone
	}
	return st.sess.writeFrameSeq(muxFrameData, st.id, seq, chunk)
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

// bridgeUseKCP 报告跨中继桥接物理连接是否走 KCP(可靠 UDP)而非 TCP。
// 默认 TCP;设 BNFS_BRIDGE_KCP=1 改走 KCP,消除跨区 TCP 队头阻塞。egress relay 的
// 框架 KCP listener(relayStarter.go)本就监听同一 addr 的 UDP,接受侧无需改动。
func bridgeUseKCP() bool {
	return os.Getenv("BNFS_BRIDGE_KCP") == "1"
}

// DialBridgeMuxSession 裸拨一条到对端 relay 的物理连接(TCP 或 KCP,见 bridgeUseKCP)，
// 发送一次物理连接级握手，然后在其上建立 client 侧 MuxSession。
// 之后用 session.OpenStream(connID,...) 开多路会话。
//
//	selfNodeID 入口 relay 自身 NodeId（握手帧 Header.NodeId）。
func DialBridgeMuxSession(parent context.Context, addr, selfNodeID string) (*MuxSession, error) {
	var conn net.Conn
	if bridgeUseKCP() {
		// KCP 拨号:与 client→relay 的 kcpStreamContext / relayStarter accept 侧调参一致。
		kconn, err := kcp.DialWithOptions(addr, nil, 1, 1)
		if err != nil {
			return nil, err
		}
		kconn.SetNoDelay(1, 10, 2, 1)
		kconn.SetMtu(1400)
		kconn.SetWriteBuffer(4 * 1024 * 1024)
		kconn.SetWindowSize(256, 1024)
		conn = kconn
		logx.Infof("[bridge-mux] 桥接物理连接走 KCP: addr=%s self=%.16s", addr, selfNodeID)
	} else {
		tconn, err := net.Dial("tcp4", addr)
		if err != nil {
			return nil, err
		}
		if tcpConn, ok := tconn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetReadBuffer(2 * 1024 * 1024)
			_ = tcpConn.SetWriteBuffer(2 * 1024 * 1024)
		}
		conn = tconn
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
	prefix, err := buildHelloPrefix(st.OpenInfo(), st.StreamID())
	if err != nil {
		return nil, err
	}
	return &prefixConn{Conn: st, prefix: prefix}, nil
}

// AcceptBridgeMuxLogicalConn 同 AcceptBridgeMuxStream，但接入侧承载体是一条条带化
// LogicalConn（M 条 leg 已归并）。targetNodeID/originPubKey 取自归并时任一 leg 的 OpenInfo
// （见 MuxStream.TargetNodeID/OriginPubKey）。
func AcceptBridgeMuxLogicalConn(lc *LogicalConn, targetNodeID, originPubKey string, legFlags ...uint8) (net.Conn, error) {
	prefix, err := buildHelloPrefix(muxOpenInfo{
		targetNodeID: targetNodeID,
		originPubKey: originPubKey,
		legFlags:     optionalLegFlags(legFlags),
	}, lc.LogicalID())
	if err != nil {
		return nil, err
	}
	return &prefixConn{Conn: lc, prefix: prefix}, nil
}

// buildHelloPrefix 构造对端下游接入所需的合成 hello 首帧字节。
func buildHelloPrefix(info muxOpenInfo, connID string) ([]byte, error) {
	header := &network.Header{
		RouteName:     "",
		NodeId:        info.targetNodeID,
		NodeIdVersion: 1,
		ConnectionId:  connID,
		LegFlags:      info.legFlags,
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
	return prefix, nil
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
