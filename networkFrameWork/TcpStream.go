package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// initialAckTimeout 是「无进展」重传阈值的下限/缺省值（尚无 RTT 样本时用）。
	// 注意语义：waitAck 测「距上次 ACK 进展多久」，而非「整条消息必须在此内完成」——
	// 只要还在收到新的 range ACK（有进展）就不超时。
	// —— 与底层 ARQ 解耦（见 KCP_DEBUG/README.md 方案A ①）——
	// 底层 KCP/TCP 自带可靠 ARQ（RTO 数十~数百 ms）。应用层重传只应作「底层都救不回来」
	// 的兜底，绝不能与底层 RTO 抢跑（否则冗余重传拥塞底层窗口 → app-ACK 更晚 → 雪崩）。
	// 故把无进展阈值放宽到 ≫ 底层 RTO（下限 800ms），底层可靠交付时 ACK 持续进展、计时器
	// 不断重置，应用层重传几乎永不触发；仅当底层长时间零进展（真卡死）才补发。
	// 真正的判死交给 keepLive 存活探测（~63s）与 KCP 自身 dead_link，此处只是次级兜底。
	initialAckTimeout = 800 * time.Millisecond
	// ackProgressRTTMultiple：无进展阈值 = 该倍数 × SRTT。放宽到 4×，给底层 ARQ 恢复余量。
	ackProgressRTTMultiple = 4
	// minAckTimeout / maxAckTimeout：自适应无进展阈值的钳位区间。下限 800ms（≫ 底层 RTO），
	// 上限 8s；重传退避也钳在 maxAckTimeout，使整条消息重传耗尽有界（见 sendMessageWithMessageID）。
	minAckTimeout = 800 * time.Millisecond
	maxAckTimeout = 8 * time.Second
	// 逻辑 mux 流共享一条 NatServer→Relay carrier。高并发时即使链路完全健康，
	// 单条消息也可能在共享发送队列中等待数秒；沿用物理流 800ms 的初始阈值会在
	// 100 路场景下把排队误判成丢包并触发重传放大。mux 流使用更宽的无进展窗口，
	// 真正的断链仍由 keepalive 和调用方 context 有界回收。
	muxInitialAckTimeout = 8 * time.Second
	muxMinAckTimeout     = 8 * time.Second
	muxMaxAckTimeout     = 30 * time.Second
	// maxRetransmitAttempts 是单条消息的最大重传次数。配合指数退避, 给跨公网高延迟链路足够的送达窗口。
	maxRetransmitAttempts = 6
	ackBatchThreshold     = 100
	recvAckIdleTimeout    = time.Second
	recvAckTickInterval   = 250 * time.Millisecond
	inboxBufferSize       = 64

	// —— 存活探测（liveness）：判死信号从「app-ACK 是否准时」解耦为「收字节空闲 + 指数退避探测」——
	// 见 KCP_DEBUG/README.md §3.5 / 方案A。KCP 无 failSend 回调、跨境 KCP 单个丢包会让某条
	// app-ACK 晚一个 RTO，故绝不能用「单条 ping 的 ACK 是否准时」判死（会把抖动误判成断链）。
	// 改为：距上次收到对端【任意帧】静默超过 keepAliveIdleBaseline 才开始主动探测；探测按指数退避，
	// 连续 keepAliveMaxProbes 次都收不到任何回帧才判死。期间收到任意入站帧立即判活、退避清零。
	keepAliveIdleBaseline = 3 * time.Second // 静默多久后开始主动探测
	keepAliveProbeBase    = 1 * time.Second // 首次探测后的等待，其后每次翻倍(1,2,4,8,16,32)
	keepAliveMaxProbes    = 6               // 连续这么多次探测无任何回帧才判死
	keepAliveProbeTimeout = 3 * time.Second // 单个探测 SendMessage 的发送预算（仅发，不据其超时判死）
)

const KeepAliveRoute = "/ping"

type streamKeepAlivePolicy struct {
	idleBaseline time.Duration
	probeBase    time.Duration
	maxProbes    int
	probeTimeout time.Duration
}

func defaultStreamKeepAlivePolicy() streamKeepAlivePolicy {
	return streamKeepAlivePolicy{
		idleBaseline: keepAliveIdleBaseline,
		probeBase:    keepAliveProbeBase,
		maxProbes:    keepAliveMaxProbes,
		probeTimeout: keepAliveProbeTimeout,
	}
}

func (p streamKeepAlivePolicy) normalized() streamKeepAlivePolicy {
	defaults := defaultStreamKeepAlivePolicy()
	if p.idleBaseline <= 0 {
		p.idleBaseline = defaults.idleBaseline
	}
	if p.probeBase <= 0 {
		p.probeBase = defaults.probeBase
	}
	if p.maxProbes <= 0 {
		p.maxProbes = defaults.maxProbes
	}
	if p.probeTimeout <= 0 {
		p.probeTimeout = defaults.probeTimeout
	}
	return p
}

// pendingInboxMessage 是 inboxCh 上传递的内部消息结构。
// 当帧重组完成时若 crypto 尚未安装（典型场景：Noise 握手与对端首条加密消息抵达存在竞态），
// 就把 needDecrypt=true 的原始密文挂进队列，由 NextMessage 在被读取时再用当时的 crypto 解密。
type pendingInboxMessage struct {
	msg         *network.Message
	needDecrypt bool // true 表示 Payload 为密文，等读取时再解密
	cipherIsE2E bool // true 表示密文带 E2E 信封（需用 DecryptWithMessageID 并去重）
}

// TcpStream : 可完全到达的流对象
type TcpStream struct {
	// nodeId / connectionId 用原子指针保护：握手期 keepLive 心跳(900ms tick)与帧打戳等
	// 后台 goroutine 会并发读，而 SetIdentity / Accept 路径会在后台 goroutine 启动后才写入，
	// 早前用裸 string 串行赋值导致 -race 报数据竞争（读: keepLive，写: SetIdentity）。
	// 一律经 setNodeId/getNodeId、setConnectionId/getConnectionId 访问，禁止直接读写字段。
	nodeId       atomic.Pointer[string]
	connection   net.Conn
	sendLock     sync.Mutex
	connectionId atomic.Pointer[string]
	// crypto 同样用原子指针：握手期 SetCryptoSuite 写，readLoop/handleData 与发送路径并发读。
	// 原子 Load/Store 既消除字段本身的竞争，又建立 happens-before —— 保证读到的 EncrypSuite
	// 是「构造完成」的（否则 readLoop 可能读到尚未初始化完成的 E2E 会话）。
	// 经 getCrypto/setCrypto 访问，禁止直接读写。
	crypto           atomic.Pointer[network.EncrypSuite]
	recordObserverMu sync.RWMutex
	recordObserver   network.OutboundRecordObserver
	frameIdGen       network.FrameIdGenerator
	assembler        *network.FrameAssembler

	streamCtx    context.Context
	streamCancel context.CancelFunc

	inboxCh chan *pendingInboxMessage

	pendingMu sync.Mutex
	pending   map[uint64]*ackTracker

	recvMu       sync.Mutex
	recvTrackers map[uint64]*recvTracker

	deliveredMu sync.Mutex
	delivered   map[uint64]bool

	e2eDeliveredMu sync.Mutex
	e2eReplay      e2eReplayWindow

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

	fatalMu       sync.Mutex
	fatalErr      error
	closeOnce     sync.Once
	keepAliveOnce sync.Once

	// firstMsgID / firstMsgTotalFrames 记录 AcceptTcpStreamSync 同步读到的首条消息标识,
	// 供调用方在确定流模式后用 AckFirstMessage 补发首包 ACK。
	firstMsgID          uint64
	firstMsgTotalFrames uint32
	firstMsgAcked       atomic.Bool

	// frameSizeAdaptor 动态帧大小自适应器（可选，nil时使用固定DefaultMaxFramePayload）
	frameSizeAdaptor *network.FrameSizeAdaptor

	// frameSizeChangeMu 保护帧大小变更的同步过程
	frameSizeChangeMu   sync.Mutex
	frameSizeChangeAcks map[int]chan bool // newSize -> ack channel

	// srttMicros 是本流平滑 RTT 估计（微秒，EWMA），由 keepLive 心跳的 SendMessage 往返采样。
	// 0 表示尚无样本。waitAck 用它把「无进展超时阈值」按链路实际 RTT 自适应，
	// 取代固定 600ms —— 高 RTT 链路给更大预算，避免大消息/高延迟下误判超时触发雪崩重传。
	srttMicros atomic.Int64

	// lastRecvMicros 是本 leg 上「最近一次从对端收到任意帧」的时刻（UnixMicro，atomic）。
	// 由 readLoop 每次 ReadFrame 成功后刷新（覆盖 data/ACK/对端心跳一切入站帧）。
	// 这是存活探测的判活信号——只要对端还在发任何字节，连接即活；与「我发的某条 app-ACK
	// 是否准时回来」彻底解耦。区别于 recvTracker.lastFrameTime（那是 per-message、只覆盖
	// 数据帧、组包完即删）。见 KCP_DEBUG/README.md 方案A。
	lastRecvMicros atomic.Int64

	testAckDelayNanos  atomic.Int64
	testDataFrameDelay time.Duration
	testLogRetransmit  bool
	keepAlivePolicy    streamKeepAlivePolicy
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

	// 启用KCP优化的渐进式帧大小自适应器
	// 策略：从800字节开始，每30秒根据实际吞吐调整
	adaptor := network.NewKCPFrameSizeAdaptor()
	virtualMux := conn != nil && conn.RemoteAddr() != nil && conn.RemoteAddr().Network() == "mux"

	// 根据连接的MTU自动设置最大帧大小
	if adaptor != nil && virtualMux {
		adaptor.SetMaxFrameSize(endpointMuxFramePayload)
		adaptor.SetFrameSize(endpointMuxFramePayload)
	} else if adaptor != nil && conn != nil {
		maxFrameSize := network.DetectMaxFrameSize(conn)
		adaptor.SetMaxFrameSize(maxFrameSize)
	}

	t := &TcpStream{
		connection:          conn,
		assembler:           network.NewFrameAssembler(),
		streamCtx:           ctx,
		streamCancel:        cancel,
		inboxCh:             make(chan *pendingInboxMessage, inboxBufferSize),
		pending:             make(map[uint64]*ackTracker),
		recvTrackers:        make(map[uint64]*recvTracker),
		delivered:           make(map[uint64]bool),
		frameSizeAdaptor:    adaptor,
		frameSizeChangeAcks: make(map[int]chan bool),
		testDataFrameDelay:  testDurationFromEnv("BNFS_TEST_DATA_FRAME_DELAY"),
		testLogRetransmit:   testBoolFromEnv("BNFS_TEST_LOG_RETRANSMIT"),
		keepAlivePolicy:     defaultStreamKeepAlivePolicy(),
	}
	t.testAckDelayNanos.Store(int64(testDurationFromEnv("BNFS_TEST_ACK_DELAY")))
	// 身份字段经原子指针存储（见字段注释），构造期串行设置，之后任何并发读写都走原子。
	t.setNodeId(nodeId)
	t.setConnectionId(connectionId)
	// 初始化存活时间戳为「现在」，避免新流一建立就被存活探测误判为静默。
	t.lastRecvMicros.Store(time.Now().UnixMicro())

	// 设置帧大小变更同步回调。
	//
	// 单端发起（single-initiator）：只有 initiator 端才安装回调、才会主动发
	// FrameTypeFrameSizeChange 请求；follower 端不装回调，永远只应用+ACK 对端请求，
	// 自己绝不发起。通过环境变量 BNFS_FRAME_FOLLOWER 把整个进程标记为 follower
	// （测试中 client 进程设此变量，server/callee 进程不设 → 由 server 掌控帧大小）。
	// relay 的 pureForwarder leg 另由 SetPureForwarder 卸载回调，亦不发起。
	if adaptor != nil && !virtualMux && !frameSizeFollowerProcess() {
		adaptor.SetFrameSizeChangeCallback(t.requestFrameSizeChange)
	}

	return t
}

// frameSizeFollowerProcess 报告本进程是否被标记为帧大小 follower。
// BNFS_FRAME_FOLLOWER ∈ {1,true,yes} 时为 true：本进程任何流都不主动发起帧大小变更。
func frameSizeFollowerProcess() bool {
	switch os.Getenv("BNFS_FRAME_FOLLOWER") {
	case "1", "true", "yes", "TRUE", "YES":
		return true
	default:
		return false
	}
}

func testDurationFromEnv(name string) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0
	}
	return duration
}

func testBoolFromEnv(name string) bool {
	switch os.Getenv(name) {
	case "1", "true", "yes", "TRUE", "YES":
		return true
	default:
		return false
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
	t.setNodeId(hex.EncodeToString(hash[:]))
	t.setConnectionId(msg.Header.ConnectionId)
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
	t.setNodeId(hex.EncodeToString(hash[:]))
	t.setConnectionId(msg.Header.ConnectionId)
	return t, msg, nil
}

// AckFirstMessage 给同步读到的首条消息回 ACK。
// 同步接入路径在 StartLoops 前调用，以补回 readFirstMessageSync 未发的首包 ACK。
func (t *TcpStream) AckFirstMessage() error {
	if t.firstMsgTotalFrames == 0 {
		return nil
	}
	if err := t.sendAck(t.firstMsgID, t.firstMsgTotalFrames, network.FullAckRange(t.firstMsgTotalFrames)); err != nil {
		return err
	}
	t.firstMsgAcked.Store(true)
	return nil
}

// StartLoops 是 startLoops 的导出别名, 供 AcceptTcpStreamSync 的调用方在确定流模式后启动读循环。
func (t *TcpStream) StartLoops() { t.startLoops() }

// RawConn 返回底层 net.Conn，供传输识别和生命周期管理使用。
// 仅当未启动 readLoop 时才允许调用方直接读取，避免与 readLoop 争用字节流。
func (t *TcpStream) RawConn() net.Conn { return t.connection }

// IsClosed 报告该流是否已关闭（streamCtx 已取消）。
// 供 DualStream 判断同协议族旧 leg 是否仍存活，从而决定"替换旧 leg"还是"并存新 leg"。
func (t *TcpStream) IsClosed() bool {
	select {
	case <-t.streamCtx.Done():
		return true
	default:
		return false
	}
}

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

func (t *TcpStream) NodeId() string       { return t.getNodeId() }
func (t *TcpStream) ConnectionId() string { return t.getConnectionId() }

// LatestReceiveTime 返回本物理 leg 最近一次收到对端任意帧的时间。
// Relay 用它被动回收已经失去对端、但底层 KCP 会话迟迟不返回 EOF 的注册流。
func (t *TcpStream) LatestReceiveTime() time.Time {
	micros := t.lastRecvMicros.Load()
	if micros <= 0 {
		return time.Time{}
	}
	return time.UnixMicro(micros)
}

// getNodeId / setNodeId / getConnectionId / setConnectionId 原子访问身份字段。
// nil 指针（从未 set）视为空串。所有读写点必须经这四个方法，不得直接碰字段，否则 -race 会报竞争。
func (t *TcpStream) getNodeId() string {
	if p := t.nodeId.Load(); p != nil {
		return *p
	}
	return ""
}
func (t *TcpStream) setNodeId(s string) { t.nodeId.Store(&s) }
func (t *TcpStream) getConnectionId() string {
	if p := t.connectionId.Load(); p != nil {
		return *p
	}
	return ""
}
func (t *TcpStream) setConnectionId(s string) { t.connectionId.Store(&s) }

func (t *TcpStream) SetCryptoSuite(suite network.EncrypSuite) {
	logx.Debugf("[TcpStream] SetCryptoSuite: nodeId=%.16s connId=%s suite=%T", t.getNodeId(), t.getConnectionId(), suite)
	if suite == nil {
		if t.getCrypto() != nil {
			t.failAndClose(errors.New("TcpStream: refusing to remove an established E2E suite"))
		}
		return
	}
	installed := suite
	if !t.crypto.CompareAndSwap(nil, &installed) {
		t.failAndClose(errors.New("TcpStream: refusing to replace an established E2E suite"))
	}
}

// getCrypto / setCrypto 原子访问加密套件。从未 set（nil 指针）或显式 set 为 nil 时返回 nil。
func (t *TcpStream) getCrypto() network.EncrypSuite {
	if p := t.crypto.Load(); p != nil {
		return *p
	}
	return nil
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
// 该写入发生在握手阶段，但此时 keepLive 心跳 goroutine 已启动并会并发读 nodeId/connectionId，
// 故经原子指针 set（曾误以为「无并发读取者、串行赋值即可」，导致 -race 报竞争）。
func (t *TcpStream) SetIdentity(nodeId, connectionId string) {
	t.setNodeId(nodeId)
	t.setConnectionId(connectionId)
}

// keepLive 存活维护 + 判死。
//
// 判死信号已从「单条 ping 的 app-ACK 是否准时」解耦为「收字节空闲 + 指数退避探测」
// （见 KCP_DEBUG/README.md §3.5 / 方案A）。核心：只要本 leg 上还在收到对端【任意帧】
// （由 readLoop 刷新 lastRecvMicros），连接即活；跨境 KCP 单个丢包让某条 app-ACK 晚一个
// RTO，绝不会被误判为断链。只有「持续静默 + 连续 keepAliveMaxProbes 次主动探测都收不到
// 任何回帧」才 failAndClose，交由 DualStream.handleLegFailure→scheduleReconnect 走既有重连。
//
// 状态机（判活以 lastRecvMicros 是否被刷新为准，与本次探测 ACK 是否准时无关）：
//
//	非探测态：每 keepAliveIdleBaseline 轮询；若期间收到过帧（lastRecv 距今 < 基线）则继续等；
//	          静默超基线 → 进入探测态。
//	探测态：记录探测前的 lastRecv 快照 → 发探测 ping → 等 backoff(1,2,4,8,16,32s) →
//	        若 lastRecv 被刷新（收到任意帧）→ 判活、退出探测态、退避清零；
//	        否则 probeCount++；连续 keepAliveMaxProbes 次都没刷新 → 判死。
func (t *TcpStream) keepLive() {
	policy := t.keepAlivePolicy.normalized()
	connType := "TCP"
	if t.connection != nil && t.connection.RemoteAddr() != nil {
		switch t.connection.RemoteAddr().Network() {
		case "tcp", "tcp4", "tcp6":
			connType = "TCP"
		case "mux":
			connType = "MUX"
		default:
			connType = "KCP"
		}
	}
	idleSince := func() time.Duration {
		last := t.lastRecvMicros.Load()
		if last <= 0 {
			return 0
		}
		return time.Since(time.UnixMicro(last))
	}
	sleep := func(d time.Duration) bool {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-t.streamCtx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	hasPendingSends := func() bool {
		t.pendingMu.Lock()
		pending := len(t.pending) != 0
		t.pendingMu.Unlock()
		return pending
	}

	for {
		// 正在等待业务消息 ACK 时，业务发送自己的无进展超时与重传状态机
		// 才是连接存活性的权威判断。此时再并发发送 keepalive，会和业务帧争用
		// 同一逻辑流的写锁/Relay 路由，并可能在高并发慢流中把健康连接误杀。
		if hasPendingSends() {
			if !sleep(policy.idleBaseline) {
				return
			}
			continue
		}

		// —— 非探测态：等到静默超过基线才开始探测 ——
		if d := idleSince(); d < policy.idleBaseline {
			if !sleep(policy.idleBaseline - d) {
				return
			}
			continue
		}

		// —— 探测态：指数退避连续探测 ——
		probeCount := 0
		backoff := policy.probeBase
		alive := false
		for probeCount < policy.maxProbes {
			// 探测期间若应用启动了业务发送，立即把判活权交回业务 ACK
			// 状态机，避免保活与真实流量形成重传/写锁争用。
			if hasPendingSends() {
				alive = true
				break
			}
			before := t.lastRecvMicros.Load() // 探测前的收帧快照

			heartbeatCtx, cancel := context.WithTimeout(t.streamCtx, policy.probeTimeout)
			start := time.Now()
			err := t.SendMessage(heartbeatCtx, &network.Message{
				Header: &network.Header{
					RouteName:     KeepAliveRoute,
					NodeId:        t.getNodeId(),
					NodeIdVersion: 1,
					ConnectionId:  t.getConnectionId(),
				},
			})
			cancel()
			if err == nil {
				// 探测成功往返：有效 RTT 样本 + 对端活着。
				t.observeRTT(time.Since(start))
			}
			if t.streamCtx.Err() != nil {
				return
			}

			// 等一个退避窗口，看这期间是否收到对端【任意帧】（判活的唯一依据）。
			if !sleep(backoff) {
				return
			}
			if t.lastRecvMicros.Load() != before {
				alive = true // 收到任意入站帧 → 判活
				break
			}
			probeCount++
			if backoff < 32*time.Second {
				backoff *= 2
			}
		}
		if alive {
			continue // 退避清零，回非探测态
		}
		if hasPendingSends() {
			continue
		}
		// 连续 keepAliveMaxProbes 次探测窗口内都没收到任何帧 → 判死。
		logx.Warnf("[%s] keepLive 判死: 连续 %d 次指数退避探测均无任何回帧, 关闭 leg: nodeId=%.16s connId=%s",
			connType, policy.maxProbes, t.getNodeId(), t.getConnectionId())
		t.failAndClose(errors.New("keepalive: peer unreachable after exponential-backoff probes"))
		return
	}
}

// StartKeepAlive starts logical-stream liveness detection once. Relay carrier
// streams intentionally do not call this because DualStream owns their leg
// lifecycle; persistent service sessions call it after the Noise handshake.
func (t *TcpStream) StartKeepAlive() {
	t.keepAliveOnce.Do(func() {
		go t.keepLive()
	})
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
			// 解决 Noise 握手与对端加密首条消息抵达的竞态。
			crypto := t.getCrypto()
			if pending.needDecrypt && crypto != nil {
				messageID, authenticated, err := network.OpenMessagePayload(crypto, msg)
				if err != nil {
					failure := fmt.Errorf("TcpStream E2E record rejected: %w", err)
					t.failAndClose(failure)
					return nil, failure
				}
				if authenticated {
					duplicate, replayErr := t.seenOrRecordE2EMessage(messageID)
					if replayErr != nil {
						failure := fmt.Errorf("TcpStream E2E replay state rejected: %w", replayErr)
						t.failAndClose(failure)
						return nil, failure
					}
					if duplicate {
						continue
					}
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

func (t *TcpStream) SendMessageAwaitAck(ctx context.Context, message *network.Message) error {
	return t.sendMessageWithAckMode(ctx, message, nil, true, nil)
}

func (t *TcpStream) SendMessageWithInitialWrite(
	ctx context.Context,
	message *network.Message,
	onInitialWrite func(),
) error {
	return t.sendMessageWithAckMode(ctx, message, nil, false, onInitialWrite)
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
	return t.sendMessageWithAckMode(ctx, message, messageID, false, nil)
}

func (t *TcpStream) sendMessageWithAckMode(
	ctx context.Context,
	message *network.Message,
	messageID []byte,
	awaitAckInPureMode bool,
	onInitialWrite func(),
) error {
	if err := t.fatal(); err != nil {
		return err
	}
	message = cloneMessage(message)
	if message == nil {
		return errors.New("send message: message is nil")
	}
	if crypto := t.getCrypto(); crypto != nil {
		sealedMessageID, err := network.SealMessagePayload(crypto, message, messageID)
		if err != nil {
			return err
		}
		if message.Header != nil && message.Header.BillingSequence != 0 {
			t.recordObserverMu.RLock()
			observer := t.recordObserver
			t.recordObserverMu.RUnlock()
			if observer != nil {
				if err := observer(cloneMessage(message), append([]byte(nil), sealedMessageID...)); err != nil {
					return fmt.Errorf("TcpStream billing record rejected: %w", err)
				}
			}
		}
	} else if message.Header != nil && message.Header.BillingSequence != 0 {
		return errors.New("TcpStream billing record requires E2E encryption")
	}
	messageId := t.frameIdGen.Next()

	// 动态获取帧大小
	frameSize := network.DefaultMaxFramePayload
	if t.frameSizeAdaptor != nil {
		frameSize = t.frameSizeAdaptor.GetFrameSize()
	}

	// 使用动态帧大小切分
	frames, err := message.SplitToFrames(messageId, frameSize)
	if err != nil {
		return err
	}
	// 源头打戳：从 message（一个完整业务消息）切出的数据帧带上业务 connectionId，
	// 供 relay 按帧头路由、callee 帧级 demux。
	// connectionId 取自 message 头（权威）——这点很关键：relay 转发 client 首条消息时走
	// group.relayStream.SendMessage（callee leg 是 pureForwarder），那条 leg 的 t.connectionId
	// 是 relay 自己的、并非 client 的；只有取 message.Header.ConnectionId 才能把 client 的
	// connectionId 正确带到 callee。后续帧走 frame pump 的 HandleFrame（不经此处），verbatim 透传。
	connId := t.getConnectionId()
	if message.Header != nil && message.Header.ConnectionId != "" {
		connId = message.Header.ConnectionId
	}
	for _, f := range frames {
		f.ConnectionId = connId
	}
	if t.pureForwarder.Load() && !awaitAckInPureMode {
		// pure forwarder leg：写完帧就返回。不建 pending、不等 ACK、不重传，
		// 因为 ACK 由对端真正的接收者直接回到原始发送者，跟本 leg 无关。
		if err := t.writeFramesContext(ctx, frames); err != nil {
			return err
		}
		if onInitialWrite != nil {
			onInitialWrite()
		}
		return nil
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

	ackStartedAt := time.Now()
	if err := t.writeFrames(frames); err != nil {
		return err
	}
	if onInitialWrite != nil {
		onInitialWrite()
	}

	// 无进展重传阈值按实测 RTT 自适应（无样本时退回 initialAckTimeout）。
	timeout := t.adaptiveAckTimeout()
	for attempt := 0; ; attempt++ {
		err := t.waitAck(ctx, tracker, timeout)
		if err == nil {
			t.observeRTT(time.Since(ackStartedAt))
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
		if t.testLogRetransmit {
			var retransmitBytes int
			for _, frame := range retrans {
				retransmitBytes += len(frame.Payload)
			}
			logx.Infof("[retransmit-test] node=%.16s conn=%s frames=%d bytes=%d attempt=%d",
				t.getNodeId(), t.getConnectionId(), len(retrans), retransmitBytes, attempt+1)
		}
		if err := t.writeFrames(retrans); err != nil {
			return err
		}
		// 退避但钳在 maxAckTimeout，使重传耗尽总时长有界（不与底层 RTO 抢跑、也不会退避到分钟级）。
		timeout *= 2
		_, _, maximum := t.ackTimeoutBounds()
		if timeout > maximum {
			timeout = maximum
		}
	}
}

func (t *TcpStream) SetOutboundRecordObserver(observer network.OutboundRecordObserver) {
	t.recordObserverMu.Lock()
	t.recordObserver = observer
	t.recordObserverMu.Unlock()
}

// waitAck 等待 tracker 收齐 ACK。语义为「无进展超时」：timeout 是「距上次 ACK 进展」的
// 最长容忍时间，而非整条消息的硬截止。每当对端 ACK 推进了已确认帧数（有进展）就重置计时器，
// 因此一条大消息只要持续有 range ACK 回来就不会误判超时；只有真正卡住（timeout 内零进展）
// 才返回 errAckTimeout 触发重传缺失帧。这样放大 maxChunk / 高 RTT 链路不再雪崩。
func (t *TcpStream) waitAck(ctx context.Context, tracker *ackTracker, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	lastProgress := tracker.ackedCount()
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
			if cur := tracker.ackedCount(); cur > lastProgress {
				// 有进展：重置无进展计时器。
				lastProgress = cur
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(timeout)
			}
		case <-timer.C:
			return errAckTimeout
		}
	}
}

func (t *TcpStream) ackTimeoutBounds() (initial, minimum, maximum time.Duration) {
	if t != nil && t.connection != nil && t.connection.RemoteAddr() != nil &&
		t.connection.RemoteAddr().Network() == "mux" {
		return muxInitialAckTimeout, muxMinAckTimeout, muxMaxAckTimeout
	}
	return initialAckTimeout, minAckTimeout, maxAckTimeout
}

// adaptiveAckTimeout 返回当前「无进展」重传阈值：有 RTT 样本时为 ackProgressRTTMultiple×SRTT
// （钳在当前传输类型的 [minimum, maximum]）；无样本时退回 initial。
// 物理 TCP/KCP 保持原来的 800ms..8s；共享 carrier 上的 mux 逻辑流使用 8s..30s，
// 避免把公平排队时延误判成丢包。
func (t *TcpStream) adaptiveAckTimeout() time.Duration {
	initial, minimum, maximum := t.ackTimeoutBounds()
	srtt := t.srttMicros.Load()
	if srtt <= 0 {
		return initial
	}
	to := time.Duration(srtt) * time.Microsecond * ackProgressRTTMultiple
	if to < minimum {
		return minimum
	}
	if to > maximum {
		return maximum
	}
	return to
}

// observeRTT 用一次往返样本更新 SRTT（EWMA，α=1/8，与 TCP 经验一致）。
func (t *TcpStream) observeRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	us := sample.Microseconds()
	prev := t.srttMicros.Load()
	if prev <= 0 {
		t.srttMicros.Store(us)
		return
	}
	// srtt = 7/8*srtt + 1/8*sample
	t.srttMicros.Store((prev*7 + us) / 8)
}

func (t *TcpStream) writeFrames(frames []*network.Frame) error {
	return t.writeFramesContext(context.Background(), frames)
}

func (t *TcpStream) writeFramesContext(ctx context.Context, frames []*network.Frame) error {
	if len(frames) == 0 {
		return nil
	}
	if ctx == nil {
		return errors.New("write frames: nil context")
	}
	if t.testDataFrameDelay > 0 {
		encoded := make([][]byte, len(frames))
		for index, frame := range frames {
			serialized, err := frame.AppendTo(nil)
			if err != nil {
				return fmt.Errorf("encode frame %d: %w", index, err)
			}
			encoded[index] = serialized
		}

		t.sendLock.Lock()
		defer t.sendLock.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		totalBytes := 0
		for index, frame := range frames {
			if err := t.writeBytesLockedContext(ctx, encoded[index]); err != nil {
				return err
			}
			totalBytes += len(encoded[index])
			if frame.FrameType == network.FrameTypeData || frame.FrameType == network.FrameTypeRetransmit {
				time.Sleep(t.testDataFrameDelay)
			}
		}
		if t.frameSizeAdaptor != nil {
			t.frameSizeAdaptor.RecordBytesSent(totalBytes)
		}
		return nil
	}

	totalSize := 0
	for index, frame := range frames {
		size, err := frame.WireSize()
		if err != nil {
			return fmt.Errorf("encode frame %d: %w", index, err)
		}
		if totalSize > int(^uint(0)>>1)-size {
			return errors.New("encode frames: batch too large")
		}
		totalSize += size
	}

	buf := make([]byte, 0, totalSize)
	for index, frame := range frames {
		var err error
		buf, err = frame.AppendTo(buf)
		if err != nil {
			return fmt.Errorf("encode frame %d: %w", index, err)
		}
	}

	t.sendLock.Lock()
	defer t.sendLock.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.writeBytesLockedContext(ctx, buf); err != nil {
		return err
	}

	// 记录发送字节数到自适应器（用于吞吐量计算）
	if t.frameSizeAdaptor != nil {
		t.frameSizeAdaptor.RecordBytesSent(len(buf))
	}

	return nil
}

func (t *TcpStream) writeFrame(f *network.Frame) error {
	bs, err := f.AppendTo(nil)
	if err != nil {
		return err
	}
	t.sendLock.Lock()
	defer t.sendLock.Unlock()
	if delay := time.Duration(t.testAckDelayNanos.Load()); f.FrameType == network.FrameTypeAck && delay > 0 {
		time.Sleep(delay)
	}
	return t.writeBytesLocked(bs)
}

func (t *TcpStream) setTestAckDelay(delay time.Duration) {
	t.testAckDelayNanos.Store(int64(delay))
}

func (t *TcpStream) writeBytesLocked(buf []byte) error {
	return t.writeBytesLockedContext(context.Background(), buf)
}

func (t *TcpStream) writeBytesLockedContext(ctx context.Context, buf []byte) error {
	if ctx == nil {
		return errors.New("write bytes: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := t.connection.SetWriteDeadline(deadline); err != nil {
			t.failAndClose(err)
			return err
		}
		defer func() { _ = t.connection.SetWriteDeadline(time.Time{}) }()
	}
	written, err := t.connection.Write(buf)
	if err == nil && written != len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
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
	// 转发腿绝不参与帧大小决策：卸载自适应回调，避免 relay 在 server↔relay 这一跳上
	// 与 server 抢着发起帧大小变更（破坏「由 server 端掌控帧大小」）。
	if enabled && t.frameSizeAdaptor != nil {
		t.frameSizeAdaptor.SetFrameSizeChangeCallback(nil)
	}
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

// HandleFrameBatch 按输入顺序把一批帧编码到同一缓冲区，并在一次持锁 Write 中写完。
// 空批次是 no-op；nil context 或批次中的 nil Frame 会返回错误且不会写入任何字节。
func (t *TcpStream) HandleFrameBatch(ctx context.Context, frames []*network.Frame) error {
	if err := t.fatal(); err != nil {
		return err
	}
	if ctx == nil {
		return errors.New("handle frame batch: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.writeFramesContext(ctx, frames)
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
		// 刷新存活时间戳：收到对端【任意帧】即证明连接活着（存活探测判活信号，见 keepLive）。
		t.lastRecvMicros.Store(time.Now().UnixMicro())
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
	case network.FrameTypeFrameSizeChange:
		// 区分请求和确认：SeqId=0是请求，SeqId=1是确认ACK
		if f.SeqId == 0 {
			t.handleFrameSizeChangeRequest(f)
		} else {
			t.handleFrameSizeChangeAck(f)
		}
		return nil
	default:
		return errors.New("unknown frame type")
	}
}

func (t *TcpStream) handleAck(f *network.Frame) error {
	t.pendingMu.Lock()
	tracker, pending := t.pending[f.MessageId]
	t.pendingMu.Unlock()
	if pending {
		ranges, err := network.DecodeAckRanges(f.Payload)
		if err != nil {
			return err
		}
		tracker.update(ranges)
		return nil
	}
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
	if t.pureForwarder.Load() && t.firstMsgAcked.Load() && f.MessageId == t.firstMsgID &&
		f.ConnectionId == t.getConnectionId() {
		return t.sendAck(f.MessageId, f.TotalFrames, network.FullAckRange(f.TotalFrames))
	}
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
		// 这是为了消除 Noise 握手期间的竞态——对端可能在我方 SetCryptoSuite 之前
		// 就发来加密消息，按"重组时立刻解密"会因 t.crypto==nil 而原样推入 inbox，
		// 等读取时是密文。改在 NextMessage 时按当下 t.crypto 解密，可彻底消除竞态。
		// 但 frameRelayMode 走纯转发不入 inbox，与解密无关，照旧返回。
		if t.frameRelayMode.Load() {
			return nil
		}
		// 仅在我方还没装 crypto 时延迟解密；已装则立刻解密 + E2E 去重，行为不变。
		needDecrypt := false
		cipherIsE2E := false
		if crypto := t.getCrypto(); crypto != nil {
			messageID, authenticated, err := network.OpenMessagePayload(crypto, msg)
			if err != nil {
				return err
			}
			if authenticated {
				duplicate, replayErr := t.seenOrRecordE2EMessage(messageID)
				if replayErr != nil {
					return replayErr
				}
				if duplicate {
					return nil
				}
			}
		} else {
			// crypto 还没装 → Payload 可能是版本化 Noise 握手帧，
			// 也可能是对端抢跑发来的密文。无法在此区分，统一打 needDecrypt 标记，
			// 由 NextMessage 在读取时按当下 crypto 决定是否解密。
			needDecrypt = true
			cipherIsE2E = true // 假设若需解密则是 E2E 信封；非信封 aesGCMDecrypt 也能识别
			previewLen := len(msg.Payload)
			if previewLen > 32 {
				previewLen = 32
			}
			logx.Debugf("[TcpStream] handleData 入 inbox 时 crypto=nil, 标记 needDecrypt: nodeId=%.16s connId=%s msgId=%d route=%s payloadLen=%d hexPreview=%x",
				t.getNodeId(), t.getConnectionId(), f.MessageId, msg.Header.RouteName, len(msg.Payload), msg.Payload[:previewLen])
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
	f.ConnectionId = t.getConnectionId() // 源头打戳：ACK 也带本流 connectionId，relay 按帧头回程
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
// 滑动窗口会永久拒绝落在窗口水位之前的旧序号，避免有界 FIFO 淘汰后重新接受历史 Record。
func (t *TcpStream) seenOrRecordE2EMessage(messageID []byte) (bool, error) {
	t.e2eDeliveredMu.Lock()
	defer t.e2eDeliveredMu.Unlock()
	return t.e2eReplay.observe(messageID)
}

// 这些方法添加到 TcpStream 中

// =============================================================================
// 帧大小动态调整同步机制
// =============================================================================

// requestFrameSizeChange 请求改变帧大小，等待对端确认
// 返回true表示对端已确认，可以应用新帧大小
func (t *TcpStream) requestFrameSizeChange(newSize int) bool {
	t.frameSizeChangeMu.Lock()
	ackCh := make(chan bool, 1)
	t.frameSizeChangeAcks[newSize] = ackCh
	t.frameSizeChangeMu.Unlock()

	frame := &network.Frame{
		MessageId:    0,
		SeqId:        0,
		TotalFrames:  1,
		AckId:        uint64(newSize),
		FrameType:    network.FrameTypeFrameSizeChange,
		ConnectionId: t.getConnectionId(),
		Payload:      nil,
	}

	if err := t.writeFrame(frame); err != nil {
		logx.Errorf("[TcpStream] 发送帧大小变更请求失败: newSize=%d err=%v", newSize, err)
		t.frameSizeChangeMu.Lock()
		delete(t.frameSizeChangeAcks, newSize)
		t.frameSizeChangeMu.Unlock()
		return false
	}

	select {
	case confirmed := <-ackCh:
		t.frameSizeChangeMu.Lock()
		delete(t.frameSizeChangeAcks, newSize)
		t.frameSizeChangeMu.Unlock()
		return confirmed
	case <-time.After(3 * time.Second):
		logx.Warnf("[TcpStream] 帧大小变更确认超时: newSize=%d", newSize)
		t.frameSizeChangeMu.Lock()
		delete(t.frameSizeChangeAcks, newSize)
		t.frameSizeChangeMu.Unlock()
		return false
	case <-t.streamCtx.Done():
		return false
	}
}

func (t *TcpStream) handleFrameSizeChangeRequest(frame *network.Frame) {
	newSize := int(frame.AckId)
	currentSize := network.DefaultMaxFramePayload
	if t.frameSizeAdaptor != nil {
		currentSize = t.frameSizeAdaptor.GetFrameSize()
	}

	logx.Debugf("[TcpStream] 收到帧大小变更请求: %d -> %d", currentSize, newSize)

	if newSize < 500 || newSize > 2800 {
		logx.Warnf("[TcpStream] 拒绝不合理的帧大小: %d", newSize)
		t.sendFrameSizeChangeAck(newSize, false)
		return
	}

	if err := t.sendFrameSizeChangeAck(newSize, true); err != nil {
		logx.Errorf("[TcpStream] 发送帧大小变更确认失败: %v", err)
		return
	}

	if t.frameSizeAdaptor != nil {
		t.frameSizeAdaptor.SetFrameSize(newSize)
		logx.Debugf("[TcpStream] ✅ 已应用对端请求的帧大小: %d", newSize)
	}
}

func (t *TcpStream) handleFrameSizeChangeAck(frame *network.Frame) {
	newSize := int(frame.AckId)
	confirmed := frame.SeqId == 1

	logx.Debugf("[TcpStream] 收到帧大小变更确认: newSize=%d confirmed=%v", newSize, confirmed)

	t.frameSizeChangeMu.Lock()
	if ch, ok := t.frameSizeChangeAcks[newSize]; ok {
		select {
		case ch <- confirmed:
		default:
		}
	}
	t.frameSizeChangeMu.Unlock()
}

func (t *TcpStream) sendFrameSizeChangeAck(newSize int, confirmed bool) error {
	seqId := uint32(0)
	if confirmed {
		seqId = 1
	}

	frame := &network.Frame{
		MessageId:    0,
		SeqId:        seqId,
		TotalFrames:  1,
		AckId:        uint64(newSize),
		FrameType:    network.FrameTypeFrameSizeChange,
		ConnectionId: t.getConnectionId(),
		Payload:      nil,
	}

	return t.writeFrame(frame)
}
