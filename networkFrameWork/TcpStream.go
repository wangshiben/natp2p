package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/xtaci/kcp-go/v5"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	initialAckTimeout     = 300 * time.Millisecond
	maxRetransmitAttempts = 3
	ackBatchThreshold     = 100
	recvAckIdleTimeout    = time.Second
	recvAckTickInterval   = 250 * time.Millisecond
	inboxBufferSize       = 64
)

var errAckTimeout = errors.New("ack timeout")

// TcpStream : 可完全到达的流对象
type TcpStream struct {
	nodeId       string
	connection   net.Conn
	sendLock     sync.Mutex
	connectionId string
	crypto       network.EncrypSuite
	frameIdGen   network.FrameIdGenerator
	assembler    *network.FrameAssembler

	streamCtx    context.Context
	streamCancel context.CancelFunc

	inboxCh chan *network.Message

	pendingMu sync.Mutex
	pending   map[uint64]*ackTracker

	recvMu       sync.Mutex
	recvTrackers map[uint64]*recvTracker

	deliveredMu sync.Mutex
	delivered   map[uint64]bool

	// frameTap 是 relay 数据面的"帧旁路通道"。
	// 当 relay 通过 SetFrameTap 安装一个通道后，readLoop 收到的每一帧 Data/Retransmit
	// 在进入正常重组路径前，会非阻塞地复制一份投递到这里，供 FrameRelayEndpoint 消费。
	// frameTapMu 保护 frameTap 字段本身的并发读写（安装 / 卸载 / 读取）。
	// 通道缓冲满则丢弃，不会阻塞 readLoop 主流程。
	frameTapMu     sync.RWMutex
	frameTap       chan *network.Frame
	frameRelayMode atomic.Bool

	fatalMu   sync.Mutex
	fatalErr  error
	closeOnce sync.Once
}

type ackTracker struct {
	total uint32
	mu    sync.Mutex
	acked map[uint32]bool
	ch    chan struct{}
}

func newAckTracker(total uint32) *ackTracker {
	return &ackTracker{
		total: total,
		acked: make(map[uint32]bool, total),
		ch:    make(chan struct{}, 1),
	}
}

func (a *ackTracker) update(ranges []network.AckRange) {
	a.mu.Lock()
	for _, r := range ranges {
		for s := r.Start; s <= r.End; s++ {
			a.acked[s] = true
		}
	}
	a.mu.Unlock()
	a.signal()
}

func (a *ackTracker) complete() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return uint32(len(a.acked)) >= a.total
}

func (a *ackTracker) missing() []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]uint32, 0)
	for s := uint32(0); s < a.total; s++ {
		if !a.acked[s] {
			out = append(out, s)
		}
	}
	return out
}

func (a *ackTracker) signal() {
	select {
	case a.ch <- struct{}{}:
	default:
	}
}

type recvTracker struct {
	total          uint32
	framesSinceAck int
	lastFrameTime  time.Time
}

func startTcpStream(nodeId, connectionId string, conn net.Conn) *TcpStream {
	ctx, cancel := context.WithCancel(context.Background())
	t := &TcpStream{
		nodeId:       nodeId,
		connection:   conn,
		connectionId: connectionId,
		assembler:    network.NewFrameAssembler(),
		streamCtx:    ctx,
		streamCancel: cancel,
		inboxCh:      make(chan *network.Message, inboxBufferSize),
		pending:      make(map[uint64]*ackTracker),
		recvTrackers: make(map[uint64]*recvTracker),
		delivered:    make(map[uint64]bool),
	}
	go t.readLoop()
	go t.recvAckTimer()
	return t
}

func NewTCPStream(nodeId, connectionId string, conn net.Conn) *TcpStream {
	return startTcpStream(nodeId, connectionId, conn)
}

// AcceptTcpStream 服务端从已建立的连接上等首条消息：先启动一个空 TcpStream，
// 由读循环消费首帧后从 inbox 拿到完整 Message，再以 payload 中的公钥推导对端 nodeId。
// 返回的 Stream 已携带 ACK/重传机制，可直接用于后续收发。
func AcceptTcpStream(conn net.Conn) (*TcpStream, *network.Message, error) {
	t := startTcpStream("", "", conn)
	msg, err := t.NextMessage(context.Background())
	if err != nil {
		t.Close()
		return nil, nil, err
	}
	hash := sha256.Sum256(msg.Payload)
	t.nodeId = hex.EncodeToString(hash[:])
	t.connectionId = msg.Header.ConnectionId
	return t, msg, nil
}

const (
	tcpMode = "tcp"
	udpMode = "udp"
)
const KeepAliveRoute = "/ping"

func (t *TcpStream) Close() error {
	t.failAndClose(errors.New("stream closed"))
	return nil
}

func (t *TcpStream) Connection() net.Conn {
	return t.connection
}

func (t *TcpStream) keepLive() {
	header := &network.Header{
		RouteName:     KeepAliveRoute,
		NodeId:        t.nodeId,
		NodeIdVersion: 1,
		ConnectionId:  "",
	}
	message := &network.Message{Header: header}
	for {
		select {
		case <-t.streamCtx.Done():
			return
		case <-time.After(5 * time.Second):
			_ = t.SendMessage(context.Background(), message)
		}
	}
}

func (t *TcpStream) NextMessage(ctx context.Context) (*network.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.streamCtx.Done():
		return nil, t.streamErr()
	case msg := <-t.inboxCh:
		return msg, nil
	}
}

// SendMessage 阻塞式发送：分帧发出后等待 ACK 覆盖到所有 SeqId，否则按指数退避重传，
// 总共最多 maxRetransmitAttempts 次。在等待期间响应 ctx 取消、stream 关闭、
// 收到坏帧的连接级错误。
func (t *TcpStream) SendMessage(ctx context.Context, message *network.Message) error {
	if err := t.fatal(); err != nil {
		return err
	}
	if t.crypto != nil {
		encrypted, err := t.crypto.Encrypt(message.Payload)
		if err != nil {
			return err
		}
		message.Payload = encrypted
	}
	messageId := t.frameIdGen.Next()
	frames, err := message.ToFrames(messageId)
	if err != nil {
		return err
	}
	total := uint32(len(frames))
	tracker := newAckTracker(total)
	t.pendingMu.Lock()
	t.pending[messageId] = tracker
	t.pendingMu.Unlock()
	defer func() {
		t.pendingMu.Lock()
		delete(t.pending, messageId)
		t.pendingMu.Unlock()
	}()

	if err := t.writeFrames(frames); err != nil {
		return err
	}

	timeout := initialAckTimeout
	for attempt := 0; ; attempt++ {
		err := t.waitAck(ctx, tracker, timeout)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errAckTimeout) {
			return err
		}
		if tracker.complete() {
			return nil
		}
		if attempt >= maxRetransmitAttempts {
			return errors.New("send message: max retransmits exceeded")
		}
		missing := tracker.missing()
		retrans := make([]*network.Frame, 0, len(missing))
		for _, seq := range missing {
			cp := *frames[seq]
			cp.FrameType = network.FrameTypeRetransmit
			retrans = append(retrans, &cp)
		}
		if err := t.writeFrames(retrans); err != nil {
			return err
		}
		timeout *= 2
	}
}

func (t *TcpStream) waitAck(ctx context.Context, tracker *ackTracker, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.streamCtx.Done():
			return t.streamErr()
		case <-tracker.ch:
			if tracker.complete() {
				return nil
			}
		case <-timer.C:
			return errAckTimeout
		}
	}
}

func (t *TcpStream) writeFrames(frames []*network.Frame) error {
	t.sendLock.Lock()
	defer t.sendLock.Unlock()
	for _, f := range frames {
		bs, err := f.ParseToBytes()
		if err != nil {
			return err
		}
		if _, err := t.connection.Write(bs); err != nil {
			return err
		}
	}
	return nil
}

func (t *TcpStream) writeFrame(f *network.Frame) error {
	bs, err := f.ParseToBytes()
	if err != nil {
		return err
	}
	t.sendLock.Lock()
	defer t.sendLock.Unlock()
	_, err = t.connection.Write(bs)
	return err
}

func (t *TcpStream) NodeId() string       { return t.nodeId }
func (t *TcpStream) ConnectionId() string { return t.connectionId }
func (t *TcpStream) SetCryptoSuite(suite network.EncrypSuite) {
	t.crypto = suite
}

// SetFrameTap 安装/替换帧旁路通道。
//
// 参数 ch：调用方持有的接收通道；从此 readLoop 收到的每一帧 Data/Retransmit
// 在进入 FrameAssembler 之前都会被非阻塞地复制一份投递到这里（满则丢弃）。
// 传 nil 等同于卸载。
//
// 必须在该流开始接收业务数据帧之前调用，否则 relay 会错过先到的帧。
// 一般由 NewTcpFrameAdapter 在构造期调用一次。
func (t *TcpStream) SetFrameTap(ch chan *network.Frame) {
	t.frameTapMu.Lock()
	t.frameTap = ch
	t.frameTapMu.Unlock()
}

func (t *TcpStream) SetFrameRelayMode(enabled bool) {
	t.frameRelayMode.Store(enabled)
}

func (t *TcpStream) getFrameTap() chan *network.Frame {
	t.frameTapMu.RLock()
	ch := t.frameTap
	t.frameTapMu.RUnlock()
	return ch
}

// NextFrame 从帧旁路通道（frameTap）取下一帧 Data/Retransmit 原始帧。
//
// 仅供 relay 的 frame pump 使用，不改变 network.Stream 的 Message 语义；
// 应用层调用方应继续使用 NextMessage。
//
// 参数：
//
//	ctx  调用方的取消上下文。group 关闭、relay leg 异常等都通过 ctx 触发返回。
//
// 退出条件（任一即返回）：
//   - ctx 被取消（返回 ctx.Err()）
//   - 底层流被关闭（返回 streamErr()）
//   - 旁路通道有可取的帧（返回该帧, nil）
//
// 注意：若调用前未通过 SetFrameTap 安装旁路通道，则会永久阻塞直到 ctx / 流关闭。
func (t *TcpStream) NextFrame(ctx context.Context) (*network.Frame, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.streamCtx.Done():
		return nil, t.streamErr()
	case f := <-t.getFrameTap():
		return f, nil
	}
}

// HandleFrame 把一帧原始数据写到底层连接，供 relay 把帧从一条 leg 桥接到另一条 leg。
//
// 参数：
//
//	ctx    保留入参以便未来扩展（当前实现实际写入是阻塞 IO，不消费 ctx）。
//	frame  待写出的原始帧。调用方通常已经把 frame.MessageId 改写为目标 leg 的新 ID。
//
// 行为：
//   - 若底层流已被标记 fatal（连接出错 / 已关闭），立即返回错误。
//   - 否则按帧二进制格式序列化并写入底层 net.Conn，写入持锁串行化。
//
// 注意：本方法跳过加密 / 分帧 / ACK 跟踪，是 relay 数据面专用。
// 应用层调用方应继续使用 SendMessage。
func (t *TcpStream) HandleFrame(ctx context.Context, frame *network.Frame) error {
	if err := t.fatal(); err != nil {
		return err
	}
	return t.writeFrame(frame)
}

// WriteFrame 是 HandleFrame 的同步等价形式，不接受 ctx；
// 保留用于不需要 ctx 语义的内部转发场景。语义与 HandleFrame 一致：
// 跳过加密 / 分帧 / ACK 跟踪，把整帧原样写到底层连接。
func (t *TcpStream) WriteFrame(f *network.Frame) error {
	if err := t.fatal(); err != nil {
		return err
	}
	return t.writeFrame(f)
}

// AllocMessageId 在本流的 frameIdGen 上分配一个全局唯一（在该流命名空间内）的 MessageId。
//
// relay 用途：每当 frame pump 在源 leg 上看到一个新的 srcMessageId，
// 必须在目标 leg 上调用本方法拿一个 dstMessageId，并把同一条消息后续所有帧都
// 改写为该 dstMessageId。这样源/目标两侧的 MessageId 命名空间相互隔离，
// 不会与目标 leg 自己 SendMessage 时生成的 MessageId 冲突。
func (t *TcpStream) AllocMessageId() uint64 {
	return t.frameIdGen.Next()
}

// SetIdentity 在握手阶段把流绑定到一个明确的对端身份。
//
// 参数：
//
//	nodeId        对端 NodeId（一般由对端公钥 SHA256 派生）。
//	connectionId  本流所代表的业务连接 ID；relay 注册流通常为空。
//
// 使用场景：服务端 AcceptTcpStream 时只能拿到 IP/Port，需要等首条消息（含公钥）
// 到达后才知道对端是谁；relay 客户端注册成功后也要在这里把流绑定到具体身份。
// 不加锁的原因：调用发生在握手阶段，此时 readLoop 仍在运行但 nodeId/connectionId
// 还没被任何并发读取者使用，串行赋值即可。
func (t *TcpStream) SetIdentity(nodeId, connectionId string) {
	t.nodeId = nodeId
	t.connectionId = connectionId
}

func (t *TcpStream) readLoop() {
	for {
		frame, err := network.ReadFrame(t.connection)
		if err != nil {
			t.failAndClose(err)
			return
		}
		if err := t.handleFrame(frame); err != nil {
			t.failAndClose(err)
			return
		}
	}
}

func (t *TcpStream) handleFrame(f *network.Frame) error {
	switch f.FrameType {
	case network.FrameTypeAck:
		return t.handleAck(f)
	case network.FrameTypeData, network.FrameTypeRetransmit:
		return t.handleData(f)
	default:
		return errors.New("unknown frame type")
	}
}

func (t *TcpStream) handleAck(f *network.Frame) error {
	ranges, err := network.DecodeAckRanges(f.Payload)
	if err != nil {
		return err
	}
	t.pendingMu.Lock()
	tr, ok := t.pending[f.MessageId]
	t.pendingMu.Unlock()
	if !ok {
		return nil
	}
	tr.update(ranges)
	return nil
}

func (t *TcpStream) handleData(f *network.Frame) error {
	if tap := t.getFrameTap(); tap != nil {
		select {
		case tap <- f:
		default:
		}
	}

	t.deliveredMu.Lock()
	if t.delivered[f.MessageId] {
		t.deliveredMu.Unlock()
		return t.sendAck(f.MessageId, f.TotalFrames, network.FullAckRange(f.TotalFrames))
	}
	t.deliveredMu.Unlock()

	msg, err := t.assembler.Add(f)
	if err != nil {
		return err
	}
	t.recvMu.Lock()
	rt, ok := t.recvTrackers[f.MessageId]
	if !ok {
		rt = &recvTracker{total: f.TotalFrames, lastFrameTime: time.Now()}
		t.recvTrackers[f.MessageId] = rt
	} else {
		rt.lastFrameTime = time.Now()
	}
	rt.framesSinceAck++
	framesSinceAck := rt.framesSinceAck
	t.recvMu.Unlock()

	if msg != nil {
		t.recvMu.Lock()
		delete(t.recvTrackers, f.MessageId)
		t.recvMu.Unlock()
		t.deliveredMu.Lock()
		t.delivered[f.MessageId] = true
		t.deliveredMu.Unlock()
		if err := t.sendAck(f.MessageId, f.TotalFrames, network.FullAckRange(f.TotalFrames)); err != nil {
			return err
		}
		if t.crypto != nil {
			decrypted, err := t.crypto.Decrypt(msg.Payload)
			if err != nil {
				return err
			}
			msg.Payload = decrypted
		}
		if t.frameRelayMode.Load() {
			return nil
		}
		select {
		case t.inboxCh <- msg:
		case <-t.streamCtx.Done():
			return t.streamErr()
		}
		return nil
	}
	if framesSinceAck >= ackBatchThreshold {
		ranges, total, ok := t.assembler.Snapshot(f.MessageId)
		if !ok {
			return nil
		}
		t.recvMu.Lock()
		if rt, ok := t.recvTrackers[f.MessageId]; ok {
			rt.framesSinceAck = 0
		}
		t.recvMu.Unlock()
		if err := t.sendAck(f.MessageId, total, ranges); err != nil {
			return err
		}
	}
	return nil
}

func (t *TcpStream) recvAckTimer() {
	ticker := time.NewTicker(recvAckTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.streamCtx.Done():
			return
		case now := <-ticker.C:
			var due []uint64
			t.recvMu.Lock()
			for id, rt := range t.recvTrackers {
				if now.Sub(rt.lastFrameTime) >= recvAckIdleTimeout {
					due = append(due, id)
					rt.framesSinceAck = 0
					rt.lastFrameTime = now
				}
			}
			t.recvMu.Unlock()
			for _, id := range due {
				ranges, total, ok := t.assembler.Snapshot(id)
				if !ok {
					continue
				}
				if err := t.sendAck(id, total, ranges); err != nil {
					t.failAndClose(err)
					return
				}
			}
		}
	}
}

func (t *TcpStream) sendAck(messageId uint64, total uint32, ranges []network.AckRange) error {
	f, err := network.BuildAckFrame(messageId, total, ranges)
	if err != nil {
		return err
	}
	return t.writeFrame(f)
}

func (t *TcpStream) failAndClose(err error) {
	t.closeOnce.Do(func() {
		t.fatalMu.Lock()
		if t.fatalErr == nil {
			t.fatalErr = err
		}
		t.fatalMu.Unlock()
		t.streamCancel()
		t.connection.Close()
		t.pendingMu.Lock()
		for _, tr := range t.pending {
			tr.signal()
		}
		t.pendingMu.Unlock()
	})
}

func (t *TcpStream) streamErr() error {
	t.fatalMu.Lock()
	defer t.fatalMu.Unlock()
	if t.fatalErr != nil {
		return t.fatalErr
	}
	return errors.New("stream closed")
}

func (t *TcpStream) fatal() error {
	t.fatalMu.Lock()
	defer t.fatalMu.Unlock()
	return t.fatalErr
}

func TryConnectTCPStream(addr, targetNodeId, originalPubkeyHex string) (network.Stream, string, error) {
	connectionId := uuid.New().String()
	header := &network.Header{
		RouteName:     "",
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	stream, err := clientStream(body, addr, targetNodeId, connectionId, true)
	return stream, connectionId, err
}

func TryRegisterRelayStream(pubKey, relayAddress string) (network.Stream, error) {
	hash := sha256.Sum256([]byte(pubKey))
	originalNodeId := hex.EncodeToString(hash[:])

	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  "",
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(pubKey),
	}
	return clientStream(body, relayAddress, originalNodeId, "", true)
}

// TryRegisterStream : nat后设备注册Stream
// 参数:
//
//	addr: 要连接的中转服务器地址
//	originalPubkeyHex: 自己的公钥
//	streamMode: 可选: tcp/udp，默认udp，若无法连接，则使用tcp
//	targetNodeId: 目标节点的nodeId(如果不是短时连接某一特定节点，则此项可不填)
//
// 返回值:
//
//	network.Stream: 流对象
//	string: 流的connectionId(当targetNodeId不为空时有)
//	error: 错误信息
func TryRegisterStream(addr, originalPubkeyHex, targetNodeId, streamMode string) (network.Stream, string, error) {
	hash := sha256.Sum256([]byte(originalPubkeyHex))
	originalNodeId := hex.EncodeToString(hash[:])
	connectionId := ""
	if len(targetNodeId) != 0 {
		connectionId = uuid.New().String()
	}
	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	if streamMode == udpMode {
		stream, err := clientStream(body, addr, originalNodeId, connectionId, true)
		if err != nil {
			return nil, "", err
		}
		return stream, connectionId, nil
	} else if streamMode == tcpMode {
		stream, err := clientStream(body, addr, originalNodeId, connectionId, false)
		if err != nil {
			return nil, "", err
		}
		return stream, connectionId, nil
	}
	return nil, "", errors.New("wrong stream mode")
}

func clientStream(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string, isDefault bool) (network.Stream, error) {
	if isDefault {
		stream, err := kcpStream(FirstMessage, tcpAddr, originalNodeId, connectionId)
		if err == nil {
			return stream, err
		}
	}

	conn, err := net.Dial("tcp4", tcpAddr)
	if err != nil {
		return nil, err
	}
	res := startTcpStream(originalNodeId, connectionId, conn)
	if err := res.SendMessage(context.Background(), FirstMessage); err != nil {
		conn.Close()
		return nil, err
	}
	go res.keepLive()
	return res, nil
}

func kcpStream(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string) (network.Stream, error) {
	conn, err := kcp.DialWithOptions(tcpAddr, nil, 1, 1)
	if err != nil {
		return nil, err
	}
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetMtu(1000)
	conn.SetWriteBuffer(4 * 1024 * 1024)
	conn.SetWindowSize(128, 512)

	res := startTcpStream(originalNodeId, connectionId, conn)
	if err := res.SendMessage(context.Background(), FirstMessage); err != nil {
		conn.Close()
		return nil, err
	}
	go res.keepLive()
	return res, nil
}
