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
	ctx      context.Context
	cancel   context.CancelFunc
	dual     *DualStream
	adapters []*TcpFrameAdapter // 每条底层 leg 一个（KCP / TCP）

	// outCh + 单写者 goroutine：所有逻辑连接的出帧按入队顺序 FIFO 写出（按到达公平），
	// 写者在阻塞的 conn.Write 上等待时不持有任何调用方共享的锁，故一条流的慢写不会
	// 卡住别的流的握手写——这是避免单连接多路复用 head-of-line 阻塞的关键。
	outCh chan *network.Frame

	mu    sync.Mutex
	conns map[string]*muxConn

	// onNew 在首次见到某 ConnectionId 时被调用（持锁外），上层据此 spawn per‑conn handler。
	onNew func(connId string, conn net.Conn)
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
		ctx:    ctx,
		cancel: cancel,
		dual:   dual,
		conns:  make(map[string]*muxConn),
		onNew:  onNew,
		outCh:  make(chan *network.Frame, 1024),
	}

	// 把当前已 attach 的每条 leg 接成原始帧适配器。
	legs := dual.legStreams()
	for _, leg := range legs {
		if leg == nil {
			continue
		}
		tcp := tcpStreamFromStream(leg)
		if tcp == nil {
			continue
		}
		tcp.SetPureForwarder(true) // 只 tap 原始帧、不本地组包/ACK；同时卸载帧大小回调（复用腿不发起）
		adapter := NewTcpFrameAdapter(tcp)
		if adapter == nil {
			continue
		}
		m.adapters = append(m.adapters, adapter)
	}
	if len(m.adapters) == 0 {
		cancel()
		return nil, errors.New("endpoint frame mux: no tcp leg available")
	}
	return m, nil
}

// Start 启动单写者 goroutine 与每条 leg 的读循环（demux）。非阻塞。
func (m *EndpointFrameMux) Start() {
	go m.writeLoop()
	for _, a := range m.adapters {
		go m.readLeg(a)
	}
}

// writeLoop 是唯一的出帧写者：按入队顺序把帧写到 preferred leg（失败回退另一条）。
// 阻塞的 conn.Write 只卡住本 goroutine，不持有任何调用方共享的锁，故不会让一条流的
// 慢写饿死别的流——出帧按到达顺序公平写出。
func (m *EndpointFrameMux) writeLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case f := <-m.outCh:
			ordered := m.orderedAdapters()
			for _, a := range ordered {
				if err := a.HandleFrame(m.ctx, f); err != nil {
					continue
				}
				break
			}
		}
	}
}

// Close 关闭复用器并取消所有 per‑conn muxConn。
func (m *EndpointFrameMux) Close() {
	m.cancel()
	m.mu.Lock()
	for _, c := range m.conns {
		c.Close()
	}
	m.mu.Unlock()
}

func (m *EndpointFrameMux) readLeg(a *TcpFrameAdapter) {
	for {
		f, err := a.NextFrame(m.ctx)
		if err != nil {
			return
		}
		m.dispatch(f)
	}
}

// dispatch 把一帧按 ConnectionId 投递到对应逻辑连接的缓冲；新连接先回调 onNew。
func (m *EndpointFrameMux) dispatch(f *network.Frame) {
	connId := f.ConnectionId
	if connId == "" {
		// 没有 connectionId 无法归属——理论上 callee 收到的业务帧都带戳，留日志兜底。
		logx.Warnf("[EndpointMux] 丢弃无 connectionId 的帧: msgId=%d seq=%d type=%d", f.MessageId, f.SeqId, f.FrameType)
		return
	}
	m.mu.Lock()
	c := m.conns[connId]
	isNew := c == nil
	if isNew {
		c = newMuxConn(connId, m.writeShared)
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
func (m *EndpointFrameMux) removeConn(connId string) {
	m.mu.Lock()
	c := m.conns[connId]
	delete(m.conns, connId)
	m.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// writeShared 把一帧交给单写者 goroutine（入队即返回，除非队列满才施加公平背压）。
// 不在调用方持锁、不在调用方阻塞于 conn.Write，故一条流的慢写不会卡住别的流。
func (m *EndpointFrameMux) writeShared(f *network.Frame) error {
	select {
	case m.outCh <- f:
		return nil
	case <-m.ctx.Done():
		return errors.New("endpoint mux closed")
	}
}

// orderedAdapters 返回按 preferred 协议优先排序的 leg 适配器。
func (m *EndpointFrameMux) orderedAdapters() []*TcpFrameAdapter {
	preferred := m.dual.preferredTransport()
	ordered := make([]*TcpFrameAdapter, 0, len(m.adapters))
	var rest []*TcpFrameAdapter
	for _, a := range m.adapters {
		if transportOfStream(a.stream) == preferred {
			ordered = append(ordered, a)
		} else {
			rest = append(rest, a)
		}
	}
	return append(ordered, rest...)
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
	writeFn func(*network.Frame) error

	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte // demux 推入的「整帧」序列化字节，先进先出
	rem    []byte   // 上一帧未被 Read 取完的剩余字节
	closed bool

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newMuxConn(connId string, writeFn func(*network.Frame) error) *muxConn {
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
		if err := c.writeFn(f); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *muxConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.cond.Broadcast()
	})
	return nil
}

func (c *muxConn) LocalAddr() net.Addr                { return muxAddr(c.connId) }
func (c *muxConn) RemoteAddr() net.Addr               { return muxAddr(c.connId) }
func (c *muxConn) SetDeadline(t time.Time) error      { return nil }
func (c *muxConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *muxConn) SetWriteDeadline(t time.Time) error { return nil }

// muxAddr 是一个非 *net.TCPAddr 的占位地址；这样 DetectMaxFrameSize 会回退到默认上限（1400），
// 不会去匹配本机网卡 MTU（per‑conn 虚拟连接没有真实网卡）。
type muxAddr string

func (a muxAddr) Network() string { return "mux" }
func (a muxAddr) String() string  { return string(a) }
