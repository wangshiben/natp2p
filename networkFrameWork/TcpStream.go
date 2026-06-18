package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// initialAckTimeout 是首次等待 ACK 的超时。取值要容忍跨公网 / 多跳中继的 RTT
	// （local↔relay1↔relay2↔local 往返可达数百毫秒并带抖动）, 过小会触发不必要的重传甚至握手失败。
	initialAckTimeout = 600 * time.Millisecond
	// maxRetransmitAttempts 是单条消息的最大重传次数。配合指数退避, 给跨公网高延迟链路足够的送达窗口。
	maxRetransmitAttempts  = 6
	ackBatchThreshold      = 100
	recvAckIdleTimeout     = time.Second
	recvAckTickInterval    = 250 * time.Millisecond
	inboxBufferSize        = 64
	e2eDeliveredCacheLimit = 65536
)

const KeepAliveRoute = "/ping"

// pendingInboxMessage 是 inboxCh 上传递的内部消息结构。
// 当帧重组完成时若 crypto 尚未安装（典型场景：TLS 握手与对端首条加密消息抵达存在竞态），
// 就把 needDecrypt=true 的原始密文挂进队列，由 NextMessage 在被读取时再用当时的 crypto 解密。
type pendingInboxMessage struct {
	msg         *network.Message
	needDecrypt bool // true 表示 Payload 为密文，等读取时再解密
	cipherIsE2E bool // true 表示密文带 E2E 信封（需用 DecryptWithMessageID 并去重）
}

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

	inboxCh chan *pendingInboxMessage

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

	// firstMsgID / firstMsgTotalFrames 记录 AcceptTcpStreamSync 同步读到的首条消息标识,
	// 供调用方在确定流模式后用 AckFirstMessage 补发首包 ACK。
	firstMsgID          uint64
	firstMsgTotalFrames uint32
}

// startTcpStream 在已经建好的连接上开 readLoop 与 recvAckTimer，
// 是 NewTCPStream / AcceptTcpStream / 拨号入口共享的内部构造路径。
func startTcpStream(nodeId, connectionId string, conn net.Conn) *TcpStream {
	t := newTcpStream(nodeId, connectionId, conn)
	t.startLoops()
	return t
}

// newTcpStream 仅构造 TcpStream, 不启动 readLoop / recvAckTimer。
// 用于需要在启动读循环之前先确定流模式（如 relay 桥接先切 pure forwarder）的场景。
func newTcpStream(nodeId, connectionId string, conn net.Conn) *TcpStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &TcpStream{
		nodeId:       nodeId,
		connection:   conn,
		connectionId: connectionId,
		assembler:    network.NewFrameAssembler(),
		streamCtx:    ctx,
		streamCancel: cancel,
		inboxCh:      make(chan *pendingInboxMessage, inboxBufferSize),
		pending:      make(map[uint64]*ackTracker),
		recvTrackers: make(map[uint64]*recvTracker),
		delivered:    make(map[uint64]bool),
		e2eDelivered: make(map[string]struct{}),
	}
}

// startLoops 启动 readLoop 与 recvAckTimer。每个流只应调用一次。
func (t *TcpStream) startLoops() {
	go t.readLoop()
	go t.recvAckTimer()
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

// AcceptTcpStreamSync 同步读取首条消息后返回, 但**不**启动 readLoop / recvAckTimer。
//
// 与 AcceptTcpStream 的区别：首条消息通过直接同步读帧获得, 期间没有后台读循环,
// 因此首条消息之后到达的帧不会被提前组包进 inbox。调用方据首条消息决定流模式
// （如 relay 桥接需要先 SetPureForwarder + 装 frameTap）, 再调用 StartLoops() 启动读循环,
// 从而消除「模式切换前若干帧已被当作 Message 组包」的竞态。
func AcceptTcpStreamSync(conn net.Conn) (*TcpStream, *network.Message, error) {
	t := newTcpStream("", "", conn)
	msg, msgID, totalFrames, err := t.readFirstMessageSync()
	if err != nil {
		t.Close()
		return nil, nil, err
	}
	t.firstMsgID = msgID
	t.firstMsgTotalFrames = totalFrames
	hash := sha256.Sum256(msg.Payload)
	t.nodeId = hex.EncodeToString(hash[:])
	t.connectionId = msg.Header.ConnectionId
	return t, msg, nil
}

// AckFirstMessage 给同步读到的首条消息回 ACK。
// 普通（非裸字节桥接）路径在 StartLoops 前调用, 以补回 readFirstMessageSync 未发的首包 ACK。
func (t *TcpStream) AckFirstMessage() error {
	if t.firstMsgTotalFrames == 0 {
		return nil
	}
	return t.sendAck(t.firstMsgID, t.firstMsgTotalFrames, network.FullAckRange(t.firstMsgTotalFrames))
}

// StartLoops 是 startLoops 的导出别名, 供 AcceptTcpStreamSync 的调用方在确定流模式后启动读循环。
func (t *TcpStream) StartLoops() { t.startLoops() }

// RawConn 返回底层 net.Conn, 供裸字节级桥接（relay 透明转发）直接 io.Copy 使用。
// 仅当未启动 readLoop（如 AcceptTcpStreamSync 之后未 StartLoops）时, 裸读才不会与 readLoop 抢字节。
func (t *TcpStream) RawConn() net.Conn { return t.connection }

// readFirstMessageSync 直接在连接上同步读帧, 直到组装出第一条完整 Message。
// 不经过 readLoop / inbox, 也不发 ACK（由调用方决定是否 ACK）。
// 返回首条消息及其 messageId / totalFrames（供调用方按需 ACK）。
func (t *TcpStream) readFirstMessageSync() (*network.Message, uint64, uint32, error) {
	for {
		frame, err := network.ReadFrame(t.connection)
		if err != nil {
			return nil, 0, 0, err
		}
		if frame.FrameType == network.FrameTypeAck {
			continue
		}
		msg, err := t.assembler.Add(frame)
		if err != nil {
			return nil, 0, 0, err
		}
		if msg != nil {
			t.deliveredMu.Lock()
			t.delivered[frame.MessageId] = true
			t.deliveredMu.Unlock()
			return msg, frame.MessageId, frame.TotalFrames, nil
		}
	}
}

// =============================================================================
// 基础属性 / 生命周期
// =============================================================================

func (t *TcpStream) NodeId() string       { return t.nodeId }
func (t *TcpStream) ConnectionId() string { return t.connectionId }
func (t *TcpStream) SetCryptoSuite(suite network.EncrypSuite) {
	log.Printf("[TcpStream] SetCryptoSuite: nodeId=%.16s connId=%s suite=%T", t.nodeId, t.connectionId, suite)
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
	connType := "TCP"
	if t.connection != nil && t.connection.RemoteAddr().Network() != "tcp" {
		connType = "KCP"
	}
	ticker := time.NewTicker(900 * time.Millisecond)
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
				log.Printf("[%s] keepLive 心跳失败, 关闭连接: nodeId=%.16s connId=%s err=%v",
					connType, t.nodeId, t.connectionId, err)
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
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.streamCtx.Done():
			return nil, t.streamErr()
		case pending := <-t.inboxCh:
			if pending == nil || pending.msg == nil {
				continue
			}
			msg := pending.msg
			// 若重组时尚未装 crypto，本消息保留密文，现在按当下 crypto 解密。
			// 解决 TLS 握手与对端加密首条消息抵达的竞态。
			if pending.needDecrypt && t.crypto != nil {
				if identitySuite, ok := t.crypto.(network.MessageIdentitySuite); ok {
					decrypted, messageID, hasMessageID, err := identitySuite.DecryptWithMessageID(msg.Payload)
					if err != nil {
						// 解密失败可能是这条消息本身就是握手期的明文（无信封），
						// 不视为致命错误，原样投递给上层。
						previewLen := len(msg.Payload)
						if previewLen > 32 {
							previewLen = 32
						}
						log.Printf("[TcpStream] NextMessage 延迟解密失败(E2E), 原样投递: nodeId=%.16s connId=%s payloadLen=%d hexPreview=%x err=%v",
							t.nodeId, t.connectionId, len(msg.Payload), msg.Payload[:previewLen], err)
						return msg, nil
					}
					msg.Payload = decrypted
					if hasMessageID && t.seenOrRecordE2EMessage(messageID) {
						// 是重复 E2E 消息，跳过继续读下一条。
						continue
					}
				} else {
					decrypted, err := t.crypto.Decrypt(msg.Payload)
					if err != nil {
						previewLen := len(msg.Payload)
						if previewLen > 32 {
							previewLen = 32
						}
						log.Printf("[TcpStream] NextMessage 延迟解密失败(plain), 原样投递: nodeId=%.16s connId=%s payloadLen=%d hexPreview=%x err=%v",
							t.nodeId, t.connectionId, len(msg.Payload), msg.Payload[:previewLen], err)
						return msg, nil
					}
					msg.Payload = decrypted
				}
			}
			return msg, nil
		}
	}
}

// SendMessage 阻塞式发送：分帧发出后等待 ACK 覆盖到所有 SeqId，否则按指数退避重传，
// 总共最多 maxRetransmitAttempts 次。在等待期间响应 ctx 取消、stream 关闭、
// 收到坏帧的连接级错误。
func (t *TcpStream) SendMessage(ctx context.Context, message *network.Message) error {
	return t.sendMessageWithMessageID(ctx, message, nil)
}

// SendMessageAsync 异步发送消息，立即返回。发送结果通过回调通知。
// 如果 callback 为 nil，行为退化为同步阻塞（等价于 SendMessage）。
func (t *TcpStream) SendMessageAsync(ctx context.Context, message *network.Message, callback network.MessageResultCallback) error {
	if callback == nil {
		// 兼容模式：同步发送
		return t.SendMessage(ctx, message)
	}

	// 异步模式：立即返回，后台发送
	go func() {
		err := t.SendMessage(ctx, message)

		// 生成消息标识
		msgID := ""
		if message.Header != nil && len(message.Header.ConnectionId) >= 8 {
			msgID = message.Header.ConnectionId[:8]
			if len(message.Header.NodeId) >= 8 {
				msgID += "-" + message.Header.NodeId[:8]
			}
		}

		// 确定传输协议
		transport := "TCP"
		if t.connection != nil && t.connection.RemoteAddr().Network() != "tcp" {
			transport = "KCP"
		}

		result := network.MessageResult{
			MessageID:     msgID,
			Success:       err == nil,
			Error:         err,
			Attempts:      1, // SendMessage内部已处理重传
			UsedTransport: transport,
		}

		callback(result)
	}()

	return nil
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

	// 批量写入优化：把所有帧序列化到一个缓冲区，一次 Write 发出
	// 减少 syscall 次数，大幅提升吞吐
	if len(frames) == 0 {
		return nil
	}

	// 预估总大小
	totalSize := 0
	for _, f := range frames {
		totalSize += network.FrameHeaderLength + len(f.Payload)
	}

	buf := make([]byte, 0, totalSize)
	for _, f := range frames {
		bs, err := f.ParseToBytes()
		if err != nil {
			return err
		}
		buf = append(buf, bs...)
	}

	if _, err := t.connection.Write(buf); err != nil {
		t.failAndClose(err)
		return err
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
		// 关键修改：解密延迟到 NextMessage 读取时再做。
		// 这是为了消除 TLS 握手期间的竞态——对端可能在我方 SetCryptoSuite 之前
		// 就发来加密消息，按"重组时立刻解密"会因 t.crypto==nil 而原样推入 inbox，
		// 等读取时是密文。改在 NextMessage 时按当下 t.crypto 解密，可彻底消除竞态。
		// 但 frameRelayMode 走纯转发不入 inbox，与解密无关，照旧返回。
		if t.frameRelayMode.Load() {
			return nil
		}
		// 仅在我方还没装 crypto 时延迟解密；已装则立刻解密 + E2E 去重，行为不变。
		needDecrypt := false
		cipherIsE2E := false
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
		} else {
			// crypto 还没装 → Payload 可能是 TLS 握手的明文（如 saltSign），
			// 也可能是对端抢跑发来的密文。无法在此区分，统一打 needDecrypt 标记，
			// 由 NextMessage 在读取时按当下 crypto 决定是否解密。
			needDecrypt = true
			cipherIsE2E = true // 假设若需解密则是 E2E 信封；非信封 aesGCMDecrypt 也能识别
			previewLen := len(msg.Payload)
			if previewLen > 32 {
				previewLen = 32
			}
			log.Printf("[TcpStream] handleData 入 inbox 时 crypto=nil, 标记 needDecrypt: nodeId=%.16s connId=%s route=%s payloadLen=%d hexPreview=%x",
				t.nodeId, t.connectionId, msg.Header.RouteName, len(msg.Payload), msg.Payload[:previewLen])
		}
		select {
		case t.inboxCh <- &pendingInboxMessage{msg: msg, needDecrypt: needDecrypt, cipherIsE2E: cipherIsE2E}:
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
