package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	initialAckTimeout      = 300 * time.Millisecond
	maxRetransmitAttempts  = 3
	ackBatchThreshold      = 100
	recvAckIdleTimeout     = time.Second
	recvAckTickInterval    = 250 * time.Millisecond
	inboxBufferSize        = 64
	e2eDeliveredCacheLimit = 65536
)

const KeepAliveRoute = "/ping"

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

	e2eDeliveredMu    sync.Mutex
	e2eDelivered      map[string]struct{}
	e2eDeliveredOrder []string

	// frameTapMu / frameTap：本流的「帧旁路通道」。
	//   非 nil 时，readLoop 收到的每一帧（数据帧 + 在 pure forwarder 模式下也包括 ACK 帧）
	//   都会复制一份送进 tap，供 relay frame pump 消费。
	//   普通模式下 tap 仅作观察用途，会非阻塞丢弃；relay/pure 模式下保证可靠投递。
	frameTapMu sync.RWMutex
	frameTap   chan *network.Frame

	// frameRelayMode：把本流的「完整 Message 重组结果」从 inboxCh 旁路出去（不再投到业务层），
	//   仅作为 frame 的来源被 relay 使用。它单独控制 inbox 行为，不改变 ACK / 组包 / 重传。
	frameRelayMode atomic.Bool

	// pureForwarder：把本流彻底变成 frame router。详见 SetPureForwarder 注释。
	//   只有挂在 relay DualFrameRelayEndpoint 上的 leg 才会开启它；
	//   应用端的 client / relayServer 流始终保持 false，仍跑完整的 ACK / 重传 / 组包逻辑。
	pureForwarder atomic.Bool

	fatalMu   sync.Mutex
	fatalErr  error
	closeOnce sync.Once
}

// startTcpStream 在已经建好的连接上开 readLoop 与 recvAckTimer，
// 是 NewTCPStream / AcceptTcpStream / 拨号入口共享的内部构造路径。
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
		e2eDelivered: make(map[string]struct{}),
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

// =============================================================================
// 基础属性 / 生命周期
// =============================================================================

func (t *TcpStream) NodeId() string       { return t.nodeId }
func (t *TcpStream) ConnectionId() string { return t.connectionId }
func (t *TcpStream) SetCryptoSuite(suite network.EncrypSuite) {
	t.crypto = suite
}

func (t *TcpStream) Close() error {
	t.failAndClose(errors.New("stream closed"))
	return nil
}

func (t *TcpStream) Connection() net.Conn {
	return t.connection
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

func (t *TcpStream) keepLive() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.streamCtx.Done():
			return
		case <-ticker.C:
			heartbeatCtx, cancel := context.WithTimeout(t.streamCtx, 3*time.Second)
			err := t.SendMessage(heartbeatCtx, &network.Message{
				Header: &network.Header{
					RouteName:     KeepAliveRoute,
					NodeId:        t.nodeId,
					NodeIdVersion: 1,
					ConnectionId:  t.connectionId,
				},
			})
			cancel()
			if err != nil && t.streamCtx.Err() == nil && !isContextError(err) {
				t.failAndClose(err)
				return
			}
		}
	}
}

// =============================================================================
// 应用层收发：NextMessage / SendMessage / 重传
// =============================================================================

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
	return t.sendMessageWithMessageID(ctx, message, nil)
}

func (t *TcpStream) sendMessageWithMessageID(ctx context.Context, message *network.Message, messageID []byte) error {
	if err := t.fatal(); err != nil {
		return err
	}
	if t.crypto != nil {
		if suite, ok := t.crypto.(network.MessageIdentitySuite); ok {
			encrypted, _, err := suite.EncryptWithMessageID(message.Payload, messageID)
			if err != nil {
				return err
			}
			message.Payload = encrypted
		} else {
			encrypted, err := t.crypto.Encrypt(message.Payload)
			if err != nil {
				return err
			}
			message.Payload = encrypted
		}
	}
	messageId := t.frameIdGen.Next()
	frames, err := message.ToFrames(messageId)
	if err != nil {
		return err
	}
	if t.pureForwarder.Load() {
		// pure forwarder leg：写完帧就返回。不建 pending、不等 ACK、不重传，
		// 因为 ACK 由对端真正的接收者直接回到原始发送者，跟本 leg 无关。
		return t.writeFrames(frames)
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
			t.failAndClose(err)
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
	if _, err := t.connection.Write(bs); err != nil {
		t.failAndClose(err)
		return err
	}
	return nil
}

// =============================================================================
// relay 数据面：frame tap / pure forwarder / HandleFrame / NextFrame
// =============================================================================

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

// SetPureForwarder 把本流切成「纯转发器」。
//
// 仅 relay 内部的 leg 会开启它。开启后该 leg 在协议上彻底变成一个 frame router：
//   - handleData：只把原始数据帧投到 frameTap，不组包、不维护 recvTrackers/delivered、不发 ACK；
//   - handleAck：不在本地消费 ACK，而是把 ACK 帧也投到 frameTap，交给 relay pump 透传给对端；
//   - recvAckTimer：直接退出，不再补发 ACK；
//   - SendMessage：写完帧就返回，不建 pending、不等 ACK、不重传。
//
// 这样 client 与 relayServer 之间是真正的端到端 ACK，relay 不再代替任何一方应答，
// 避免「relay 抢先 ACK 导致发送端虚高、背压压在 relay 内部缓冲」的问题。
func (t *TcpStream) SetPureForwarder(enabled bool) {
	t.pureForwarder.Store(enabled)
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

// =============================================================================
// 入站方向：readLoop / handleAck / handleData / recvAckTimer
// =============================================================================

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
	// pure forwarder：本 leg 不消费 ACK，把整帧透传到 frameTap，
	// 让 relay frame pump 把它送回真正的发送方。
	if t.pureForwarder.Load() {
		if tap := t.getFrameTap(); tap != nil {
			select {
			case tap <- f:
			case <-t.streamCtx.Done():
				return t.streamErr()
			}
		}
		return nil
	}
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

func isKeepAliveFrame(f *network.Frame) bool {
	if f == nil || f.SeqId != 0 || len(f.Payload) < network.HeaderLength {
		return false
	}
	h, err := network.ParseHeader(f.Payload[:network.HeaderLength])
	if err != nil {
		return false
	}
	return h.RouteName == KeepAliveRoute
}

func (t *TcpStream) handleData(f *network.Frame) error {
	localKeepAlive := t.pureForwarder.Load() && isKeepAliveFrame(f)
	// frameTap 投递：
	//   - relay 模式 / pure forwarder 模式：必须可靠投递（阻塞等容量），不能丢帧，否则 relay 会断流；
	//   - 但 pure forwarder 上的 KeepAliveRoute 仍是链路本地保活，不进 frameTap、由本 leg 自己 ACK；
	//   - 普通模式：只是给观察者用的旁路，可以非阻塞丢弃。
	if tap := t.getFrameTap(); tap != nil && !localKeepAlive {
		if t.frameRelayMode.Load() || t.pureForwarder.Load() {
			select {
			case tap <- f:
			case <-t.streamCtx.Done():
				return t.streamErr()
			}
		} else {
			select {
			case tap <- f:
			default:
			}
		}
	}

	// pure forwarder：业务数据帧不组包、不维护接收追踪、不发 ACK；
	// 但链路本地 KeepAliveRoute 仍要留在本 leg 内部消费，否则对端 keepalive 永远收不到 ACK。
	if t.pureForwarder.Load() && !localKeepAlive {
		return nil
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
			if identitySuite, ok := t.crypto.(network.MessageIdentitySuite); ok {
				decrypted, messageID, hasMessageID, err := identitySuite.DecryptWithMessageID(msg.Payload)
				if err != nil {
					return err
				}
				msg.Payload = decrypted
				if hasMessageID && t.seenOrRecordE2EMessage(messageID) {
					return nil
				}
			} else {
				decrypted, err := t.crypto.Decrypt(msg.Payload)
				if err != nil {
					return err
				}
				msg.Payload = decrypted
			}
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
			// pure forwarder leg 不组包、也不维护 recvTrackers，
			// idle 补 ACK 这件事完全没有意义，直接退出 timer goroutine。
			if t.pureForwarder.Load() {
				return
			}
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

// =============================================================================
// 错误传播 / e2e 去重
// =============================================================================

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

// seenOrRecordE2EMessage 判断这条端到端 messageID 是否已经派发过。
//
//	已经见过 -> 返回 true，调用方应跳过该消息（避免 relay failover 引起的重复完整消息再次投递）。
//	新的    -> 返回 false 并记录；记录数超过 e2eDeliveredCacheLimit 时按 FIFO 淘汰最旧条目。
func (t *TcpStream) seenOrRecordE2EMessage(messageID []byte) bool {
	if len(messageID) == 0 {
		return false
	}
	key := string(messageID)
	t.e2eDeliveredMu.Lock()
	defer t.e2eDeliveredMu.Unlock()
	if _, ok := t.e2eDelivered[key]; ok {
		return true
	}
	t.e2eDelivered[key] = struct{}{}
	t.e2eDeliveredOrder = append(t.e2eDeliveredOrder, key)
	if len(t.e2eDeliveredOrder) > e2eDeliveredCacheLimit {
		oldest := t.e2eDeliveredOrder[0]
		copy(t.e2eDeliveredOrder, t.e2eDeliveredOrder[1:])
		t.e2eDeliveredOrder = t.e2eDeliveredOrder[:len(t.e2eDeliveredOrder)-1]
		delete(t.e2eDelivered, oldest)
	}
	return false
}
