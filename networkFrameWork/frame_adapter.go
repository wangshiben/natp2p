package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"errors"
	"sort"
	"sync"
)

// FrameRelayEndpoint 是 relay 数据面专用的"逐帧桥接"接口。
//
// 设计动机：
//   - network.Stream 接口面向应用层，暴露的是完整的 Message 收发语义（NextMessage / SendMessage），
//     内部会做分帧、重组、加解密、ACK / 重传。
//   - 但 relay（公网中转节点）只是把字节从一条 TCP 连接搬到另一条 TCP 连接，
//     如果先在 relay 把所有帧重组成完整 Message 再转发，就会出现 head-of-line blocking：
//     单条大 Message 的一个帧丢了，会把同一连接上其它消息全部卡死。
//   - 所以 relay 需要一种"只看 Frame、不看 Message"的接口，把 Data/Retransmit 帧从源 leg
//     拿出来，改写 MessageId 后写到目标 leg 即可，ACK 仍由各 leg 内部独立维护。
//
// 该接口只在 relay 内部使用，应用层 / TLS 握手 / 客户端 ClientStream 仍走 network.Stream。
type FrameRelayEndpoint interface {
	// NextFrame 从底层流的"帧旁路通道"取下一帧 Data/Retransmit 原始帧。
	// 不会返回 ACK 帧（ACK 仍由 TcpStream 自己处理），不会做重组。
	// ctx 用于在 relay 关闭 / 整组取消时及时退出阻塞读取。
	NextFrame(ctx context.Context) (*network.Frame, error)

	// HandleFrame 把一帧原始数据写到底层连接。供 relay frame pump 把"从源 leg 取出的帧"
	// 改写 MessageId 后投递到目标 leg。
	// 注意：本方法绕过加密 / 分帧 / ACK 跟踪，调用方必须保证 frame 已是合法二进制结构。
	HandleFrame(ctx context.Context, frame *network.Frame) error

	// AllocMessageId 在目标 leg 上分配一个全新的 MessageId。
	// relay 必须为每条跨 leg 的消息重写 MessageId，避免与目标 leg 自己 SendMessage 时
	// 生成的 MessageId 冲突（两边的 frameIdGen 是相互独立的命名空间）。
	AllocMessageId() uint64

	// NodeId 返回该 leg 对端的 NodeId（公钥派生）。relay 用它定位会话归属。
	NodeId() string

	// ConnectionId 返回该 leg 当前绑定的业务 ConnectionId。
	// 对 relay 注册 leg 而言通常为空；对 client 连接 leg 是该业务连接的 uuid。
	ConnectionId() string

	// Close 关闭底层连接，释放该 leg 占用的资源。
	Close() error
}

// TcpFrameAdapter 是 FrameRelayEndpoint 在 *TcpStream 之上的默认实现。
//
// 职责：
//   - 在构造时给 TcpStream 安装一个"帧旁路通道"（frameTap），让 readLoop 在收到
//     Data/Retransmit 帧时除了走正常的重组路径外，再非阻塞地把该帧投递一份到本通道。
//   - 把 FrameRelayEndpoint 的所有方法直接代理到底层 TcpStream 对应方法上。
//
// 字段说明：
//
//	stream  底层被包装的 TcpStream；所有读写最终都落到它身上。
//	frames  本适配器持有的旁路通道，缓冲 64 帧，供 relay pump 通过 NextFrame 消费。
//	        通道所有权在构造期通过 stream.SetFrameTap 转交给 TcpStream，由它写入。
type TcpFrameAdapter struct {
	stream *TcpStream
	frames chan *network.Frame
}

// NewTcpFrameAdapter 创建并安装一个帧旁路适配器。
//
// 参数：
//
//	stream 必须是已经在 readLoop 中正常工作的 *TcpStream。
//	       如果传入 nil，返回 nil（调用方必须显式判空）；这样 relay 在底层不是 *TcpStream
//	       时（比如未来扩展的 KCP / UDP 流）可以安全地走老的 message 转发路径。
//
// 行为：
//   - 创建一个带缓冲（64）的 *network.Frame 通道。
//   - 调用 stream.SetFrameTap 把通道写入端交给 TcpStream，从此 readLoop 收到的
//     Data/Retransmit 帧会非阻塞地投一份到此通道；通道满则丢弃（relay 不影响主重组路径）。
//   - 必须在该流开始接收正式数据帧前调用，否则 relay 会错过先到的帧。
func NewTcpFrameAdapter(stream *TcpStream) *TcpFrameAdapter {
	if stream == nil {
		return nil
	}
	// 若该流已装有 frameTap（例如 relay 在启动读循环前用 PrepareBridgeLeg 提前装好以缓冲握手帧）,
	// 复用同一通道, 避免替换通道导致已缓冲的帧丢失。
	if existing := stream.getFrameTap(); existing != nil {
		stream.SetFrameRelayMode(true)
		return &TcpFrameAdapter{stream: stream, frames: existing}
	}
	ch := make(chan *network.Frame, 4096)
	stream.SetFrameTap(ch)
	stream.SetFrameRelayMode(true)
	return &TcpFrameAdapter{stream: stream, frames: ch}
}

// NextFrame 从底层 TcpStream 的 frameTap 通道取下一帧。
// 阻塞直到：取到一帧 / ctx 被取消 / 底层流关闭。
func (a *TcpFrameAdapter) NextFrame(ctx context.Context) (*network.Frame, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.stream.streamCtx.Done():
		return nil, a.stream.streamErr()
	case f := <-a.frames:
		return f, nil
	}
}

// HandleFrame 把一帧原始数据写到底层 TCP 连接。
// 调用方（relay frame pump）通常已经把 frame.MessageId 改写为目标 leg 的新 ID。
func (a *TcpFrameAdapter) HandleFrame(ctx context.Context, frame *network.Frame) error {
	return a.stream.HandleFrame(ctx, frame)
}

// AllocMessageId 透传到底层流的 frameIdGen，分配目标 leg 上唯一的 MessageId。
func (a *TcpFrameAdapter) AllocMessageId() uint64 {
	return a.stream.AllocMessageId()
}

// NodeId 返回底层流当前绑定的对端 NodeId。
func (a *TcpFrameAdapter) NodeId() string {
	return a.stream.NodeId()
}

// ConnectionId 返回底层流当前绑定的业务 ConnectionId。
func (a *TcpFrameAdapter) ConnectionId() string {
	return a.stream.ConnectionId()
}

// Close 关闭底层流（同时会终止 readLoop 与所有挂起的 ACK 等待）。
func (a *TcpFrameAdapter) Close() error {
	return a.stream.Close()
}

// ===========================================================================
// relay 帧路由的「三层 MessageId 模型」（理解下面代码的前提）
//
// 一条业务消息在公网 relay 上会经过两条不同的底层 leg（来源 leg、目标 leg），
// 每条 leg 都是一个独立的 TcpStream，各自有自己的 frameIdGen，MessageId 互不相通。
// 为了让 relay 既能转发数据帧、又能把对端回来的 ACK 帧正确送回发送方，这里引入三种 ID：
//
//  1. transport MessageId（来源侧）：源 leg 上这条消息原本的 MessageId。
//     不同 leg / 不同连接可能撞车（都从 1 开始），所以不能直接拿来跨 leg 用。
//
//  2. logicalID：relay 内部为「某条来源消息流」分配的稳定逻辑 ID。
//     由 logicalGen 统一生成，全 endpoint 唯一。它是 relay pump 在 NextFrame 里
//     看到的 frame.MessageId，也是 routes map 的 key。
//     同一条来源消息（含它后续所有数据帧、以及对端回来的 ACK）始终复用同一个 logicalID。
//
//  3. dstID（目标侧）：在目标 leg 上为这条消息新分配的 MessageId。
//     真正写到目标连接上的 frame.MessageId 用的是它。
//
// 映射关系：
//   - incomingIDs: {来源 leg kind, 该 leg 上 remote 发送的数据帧 MessageId} -> logicalID
//     （入站数据方向：把对端发来的 Data/Retransmit 的 transport MessageId 翻译成 relay 内部 logicalID）
//   - ackIDs:      {目标 leg kind, relay 写出去时分配的 dstID} -> logicalID
//     （ACK 回程方向：把对端基于 dstID 回来的 ACK 翻译回同一个 logicalID）
//   - routes:      logicalID -> dualFrameRoute（出站方向：决定写到哪条目标 leg、用哪个 dstID）
//
// 关键点：同一条底层 leg 上，双方各自的 frameIdGen 都可能从 1 开始，因此「对端主动发来的数据帧 ID」
// 与「relay 写出去后等待 ACK 的 dstID」在数值上完全可能撞车。ACK 回程若继续复用 incomingIDs，
// 就会把『对端回的 ACK(id=1)』和『对端主动发来的数据(id=1)』混成同一条 logicalID。
// 所以 ACK 回程必须单独走 ackIDs，不能与 remote->relay 的入站数据映射共用一张表。
// ===========================================================================

// dualRelayFrame 暂未使用，保留作为未来「带来源标记的帧」扩展位。
type dualRelayFrame struct {
	kind  streamTransport
	frame *network.Frame
}

// frameEndpointKey 是 incomingIDs / ackIDs 的 key：某条具体 leg（kind）上、某条业务连接（connId）的一个 transport MessageId。
// 用 kind 区分 TCP/KCP 两条 leg 的独立命名空间；用 connId 区分**同一条物理连接上多路复用的多条逻辑连接**——
// callee 把 N 条 per-conn 流复用到一条 server↔relay 连接时，各 per-conn 流的 frameIdGen 都从 1 开始、
// MessageId 会撞车，必须带 connId 才能把它们区分开（否则两条流的 msgId=1 会被并成同一条 logicalID 而互相串台）。
type frameEndpointKey struct {
	kind      streamTransport
	connId    string
	messageID uint64
}

// dualFrameRoute 描述「一条 logicalID 当前应该写到哪条目标 leg」。
//
//	kind         当前选用的目标 leg 协议（TCP / KCP）。
//	endpoint     当前目标 leg 的适配器，HandleFrame 真正写它。
//	dstID        在目标 leg 上为这条消息分配的 MessageId（写出去的 frame 用它）。
//	totalFrames  这条消息一共多少帧，用于判断是否收齐。
//	framesBySeq  已经见过的数据帧缓存（按 SeqId）。leg failover 时要把它们
//	             按序重放到 backup leg，避免目标侧拿到半条消息无法重组。
type dualFrameRoute struct {
	kind        streamTransport
	connId      string // 该 logicalID 所属业务连接，failover 重绑 ackIDs 时需要
	endpoint    *TcpFrameAdapter
	dstID       uint64
	totalFrames uint32
	framesBySeq map[uint32]*network.Frame
}

// DualFrameRelayEndpoint 把 DualStream 内部的 TCP/KCP 两条 leg 聚合成一个 FrameRelayEndpoint。
// relay 的 frame pump 只面对这个接口；具体写到 TCP 还是 KCP、某条 leg 失败后是否重放，
// 都在这里处理。
//
// 字段说明：
//
//	stream       被聚合的 DualStream（提供 ctx、leg 选择、failover/重连）。
//	adapters     当前每条协议 leg 对应的帧适配器（kind -> adapter）。
//	incoming     入站汇聚通道：collect() 把各 leg 读到的原始帧改写成 logicalID 后投到这里，
//	             relay pump 通过 NextFrame 消费。
//	incomingIDs  {leg kind, 该 leg 上 remote 数据帧 MessageId} -> logicalID 的映射。
//	ackIDs       {leg kind, relay 写到该 leg 的 dstID} -> logicalID 的 ACK 回程映射。
//	logicalGen   logicalID / dstID 的统一生成器（保证全 endpoint 唯一，避免两套计数器撞号）。
//	routes       logicalID -> dualFrameRoute，出站方向的路由表。
type DualFrameRelayEndpoint struct {
	stream *DualStream

	mu          sync.Mutex
	adapters    map[streamTransport]*TcpFrameAdapter
	incoming    chan *network.Frame
	incomingIDs map[frameEndpointKey]uint64
	ackIDs      map[frameEndpointKey]uint64
	logicalGen  network.FrameIdGenerator
	routes      map[uint64]*dualFrameRoute
}

func NewDualFrameRelayEndpoint(stream *DualStream) *DualFrameRelayEndpoint {
	if stream == nil {
		return nil
	}
	return &DualFrameRelayEndpoint{
		stream:      stream,
		adapters:    make(map[streamTransport]*TcpFrameAdapter),
		incoming:    make(chan *network.Frame, 1024),
		incomingIDs: make(map[frameEndpointKey]uint64),
		ackIDs:      make(map[frameEndpointKey]uint64),
		routes:      make(map[uint64]*dualFrameRoute),
	}
}

// AttachStream 把 DualStream 的一条底层 leg 接入 frame relay 数据面。
//
// 关键动作：
//   - NewTcpFrameAdapter 给该 leg 装上帧旁路通道（frameTap），并切到 relay 模式。
//   - SetPureForwarder(true) 把该 leg 变成「纯转发器」：不再本地组包、不再本地发 ACK、
//     SendMessage 也不等 ACK。这样 client 与 relayServer 之间是端到端 ACK，relay 只搬帧。
//   - 启动 collect goroutine，持续把该 leg 读到的原始帧汇聚到 incoming 通道。
func (e *DualFrameRelayEndpoint) AttachStream(kind streamTransport, stream network.Stream) error {
	if kind == streamTransportUnknown || stream == nil {
		return errors.New("invalid frame relay stream")
	}
	tcp := tcpStreamFromStream(stream)
	if tcp == nil {
		return errors.New("frame relay requires tcp stream carrier")
	}
	adapter := NewTcpFrameAdapter(tcp)
	tcp.SetPureForwarder(true)
	e.mu.Lock()
	e.adapters[kind] = adapter
	e.mu.Unlock()
	go e.collect(kind, adapter)
	return nil
}

// collect 是入站方向的汇聚循环：不断从某条 leg 的适配器读原始帧，
// 把帧的 transport MessageId 翻译成 relay 内部 logicalID，再投递到 incoming 通道，
// 供 relay pump 的 NextFrame 消费。
//
// 注意：这里收到的可能是数据帧，也可能是「对端回来的 ACK 帧」（pure forwarder 模式下
// ACK 也会进入 frameTap）。两者的翻译规则不同：
//   - Data/Retransmit：用 incomingIDs（remote 主动发来的 transport MessageId -> logicalID）
//   - ACK：            用 ackIDs（relay 之前写出去的 dstID -> logicalID）
//
// 这样可以避免同一条 leg 上「对端主动发来的数据 id=1」和「对端回给 relay 的 ACK(id=1)」
// 数值撞车，被误翻译成同一条 logicalID。
//
// 同时，第一次见到某个 logicalID 时，在 routes 里登记「这条 logicalID 来自哪条 leg、
// 原始 MessageId 是多少」。这样当反方向需要把帧/ACK 写回这条来源 leg 时，HandleFrame
// 能直接命中已存在的 route，而不会误判成一条全新消息再分配新 dstID。
func (e *DualFrameRelayEndpoint) collect(kind streamTransport, adapter *TcpFrameAdapter) {
	kindStr := transportName(legFamily(kind))
	for {
		f, err := adapter.NextFrame(e.stream.ctx)
		if err != nil {
			isCurrent := e.isCurrent(kind, adapter)
			ctxErr := e.stream.ctx.Err()
			logx.Warnf("[FrameRelay] %s NextFrame 失败: nodeId=%.16s connId=%s isCurrent=%v ctxErr=%v err=%v",
				kindStr, e.stream.NodeId(), e.stream.ConnectionId(), isCurrent, ctxErr, err)
			if ctxErr == nil && isCurrent {
				e.stream.handleLegFailure(kind, adapter.stream)
			}
			return
		}
		out := cloneFrame(f)
		// transport MessageId -> logicalID：
		//   - 入站数据帧按 incomingIDs/incomingMessageID 绑定；
		//   - ACK 帧按 ackIDs 反查，避免和对端主动发来的数据帧编号撞车；
		//   - 未绑定 ACK 没有对应的 relay route，直接丢弃，不能落到 incomingIDs 污染后续数据帧。
		logicalID, ok := e.resolveIncomingMessageID(kind, f)
		if !ok {
			continue
		}
		out.MessageId = logicalID
		e.mu.Lock()
		// 为这条来源 logicalID 建立「回写路由」：日后要把帧写回此来源 leg 时，
		// dstID 就用它原本的 transport MessageId，原样还回去。
		if e.routes[logicalID] == nil {
			e.routes[logicalID] = &dualFrameRoute{
				kind:        kind,
				connId:      f.ConnectionId,
				endpoint:    adapter,
				dstID:       f.MessageId,
				totalFrames: f.TotalFrames,
				framesBySeq: make(map[uint32]*network.Frame),
			}
		}
		e.mu.Unlock()
		select {
		case <-e.stream.ctx.Done():
			return
		case e.incoming <- out:
		}
	}
}

func (e *DualFrameRelayEndpoint) isCurrent(kind streamTransport, adapter *TcpFrameAdapter) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.adapters[kind] == adapter
}

// incomingMessageID 把「某条 leg 上 remote 主动发来的数据帧 MessageId」翻译成稳定的 logicalID。
// 第一次见到就分配一个新的 logicalID 并记下来；之后同一来源消息的所有数据帧
// 都会拿到同一个 logicalID。
func (e *DualFrameRelayEndpoint) incomingMessageID(kind streamTransport, connId string, messageID uint64) uint64 {
	key := frameEndpointKey{kind: kind, connId: connId, messageID: messageID}
	e.mu.Lock()
	defer e.mu.Unlock()
	if id, ok := e.incomingIDs[key]; ok {
		return id
	}
	id := e.logicalGen.Next()
	e.incomingIDs[key] = id
	return id
}

// ackMessageID 把「某条 leg 上对端回给 relay 的 ACK(dstID)」翻译回原 logicalID。
// **不按 connId 区分**：dstID 由目标 leg 的 AllocMessageId 分配、全 leg 唯一，本就不撞车；
// 而 ACK 帧携带的是「回 ACK 那一方的 t.connectionId」，与原数据帧的业务 connId 不一定相同
// （例如注册流 connId 为空），按 connId 查会查不到 → ACK 丢失 → 发送端永远等不到确认。
func (e *DualFrameRelayEndpoint) ackMessageID(kind streamTransport, messageID uint64) (uint64, bool) {
	key := frameEndpointKey{kind: kind, messageID: messageID}
	e.mu.Lock()
	defer e.mu.Unlock()
	id, ok := e.ackIDs[key]
	return id, ok
}

func (e *DualFrameRelayEndpoint) resolveIncomingMessageID(kind streamTransport, frame *network.Frame) (uint64, bool) {
	if frame != nil && frame.FrameType == network.FrameTypeAck {
		// ACK 回程按 dstID（唯一）查，不带 connId（见 ackMessageID 说明）。
		id, ok := e.ackMessageID(kind, frame.MessageId)
		return id, ok
	}
	// 入站数据按 {kind, connId, msgId} 区分：多路复用时各流 msgId 从 1 起会撞车，靠 connId 区分。
	return e.incomingMessageID(kind, frame.ConnectionId, frame.MessageId), true
}

// bindAckMessageID 显式登记 {leg kind, dstID} -> logicalID（dstID 唯一, 不带 connId）。
func (e *DualFrameRelayEndpoint) bindAckMessageID(kind streamTransport, transportMessageID uint64, logicalID uint64) {
	key := frameEndpointKey{kind: kind, messageID: transportMessageID}
	e.mu.Lock()
	e.ackIDs[key] = logicalID
	e.mu.Unlock()
}

// NextFrame 供 relay pump 消费入站汇聚帧（已是 logicalID 视角）。
func (e *DualFrameRelayEndpoint) NextFrame(ctx context.Context) (*network.Frame, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.stream.ctx.Done():
		return nil, errors.New("stream closed")
	case f := <-e.incoming:
		return f, nil
	}
}

// HandleFrame 是出站方向：relay pump 把一帧（MessageId 已是 logicalID）交给本端点写出。
//
// 流程：
//  1. 用 logicalID 查 routes：
//     - 命中（常见）：说明这条消息的目标 leg / dstID 已确定，直接复用。
//     collect 在入站时已为「来源 logicalID」建好回写 route；反方向的数据/ACK 都走这里。
//     - 未命中：这是一条新发起的出站消息，选一条可用 leg、分配新的 dstID 建 route，
//     并把 {目标 leg kind, dstID} -> logicalID 也写进 incomingIDs，
//     这样对端基于 dstID 回来的 ACK 能在 collect 里翻译回同一个 logicalID（闭环）。
//  2. 缓存该帧（按 SeqId），供 leg failover 时重放。
//  3. 把帧 MessageId 改写成 dstID，写到目标 leg。
//  4. 写失败则走 replayRoute：换 backup leg 并把已缓存帧整条重放。
func (e *DualFrameRelayEndpoint) HandleFrame(ctx context.Context, frame *network.Frame) error {
	logicalID := frame.MessageId
	cached := cloneFrame(frame)
	e.mu.Lock()
	route := e.routes[logicalID]
	if route == nil {
		kind, adapter := e.chooseAdapterLocked(streamTransportUnknown)
		if adapter == nil {
			e.mu.Unlock()
			return errors.New("stream closed")
		}
		route = &dualFrameRoute{
			kind:        kind,
			connId:      frame.ConnectionId,
			endpoint:    adapter,
			dstID:       adapter.AllocMessageId(),
			totalFrames: frame.TotalFrames,
			framesBySeq: make(map[uint32]*network.Frame),
		}
		e.routes[logicalID] = route
		// 闭环：目标 leg 用 dstID(唯一) 回来的 ACK，要能翻译回这个 logicalID。不带 connId（见 ackMessageID）。
		e.ackIDs[frameEndpointKey{kind: kind, messageID: route.dstID}] = logicalID
	}
	route.framesBySeq[frame.SeqId] = cached
	endpoint := route.endpoint
	dstID := route.dstID
	e.mu.Unlock()

	out := cloneFrame(frame)
	out.MessageId = dstID
	if err := endpoint.HandleFrame(ctx, out); err != nil {
		kindStr := transportName(legFamily(route.kind))
		logx.Warnf("[FrameRelay] %s HandleFrame 写入失败, 触发 replayRoute: nodeId=%.16s connId=%s err=%v",
			kindStr, e.stream.NodeId(), e.stream.ConnectionId(), err)
		return e.replayRoute(ctx, logicalID, route.kind, endpoint)
	}
	return nil
}

// replayRoute 在当前目标 leg 写失败时调用：
//   - 关闭/摘除失败 leg 并触发其重连；
//   - 选一条 backup leg，给这条 logicalID 重新分配 dstID（并刷新 dstID->logicalID 闭环）；
//   - 把已缓存的所有帧按 SeqId 顺序重放到 backup leg，保证目标侧拿到的是完整消息，
//     而不是「前半段在旧 leg、后半段在新 leg」的拼不起来的半条消息。
// onLegDetached 在 DualStream 摘除一条 leg 时调用：删除该 leg 的 adapter，
// 并把所有绑定到它的回写路由主动切到一条存活 leg（无存活 leg 则保留，待新 leg attach）。
// 这样即便没有写失败触发 replayRoute，回程也能主动避开已摘除的死 leg。
func (e *DualFrameRelayEndpoint) onLegDetached(id streamTransport) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.adapters, id)
	for logicalID, route := range e.routes {
		if route == nil || route.kind != id {
			continue
		}
		kind, adapter := e.chooseAdapterLocked(id)
		if adapter == nil {
			continue
		}
		route.kind = kind
		route.endpoint = adapter
		route.dstID = adapter.AllocMessageId()
		e.ackIDs[frameEndpointKey{kind: kind, messageID: route.dstID}] = logicalID
	}
}

func (e *DualFrameRelayEndpoint) replayRoute(ctx context.Context, logicalID uint64, failedKind streamTransport, failedEndpoint *TcpFrameAdapter) error {
	// 仅当 failedEndpoint 仍是该 kind 的现役 adapter 时才触发 leg 失败，
	// 否则说明 leg 已被新 adapter 替换，写到旧 endpoint 失败属于"路由陈旧"，
	// 不应再次 handleLegFailure（避免与正常重连流程产生级联）。
	if e.isCurrent(failedKind, failedEndpoint) {
		e.stream.handleLegFailure(failedKind, failedEndpoint.stream)
	}

	e.mu.Lock()
	if e.adapters[failedKind] == failedEndpoint {
		delete(e.adapters, failedKind)
	}
	route := e.routes[logicalID]
	if route == nil {
		e.mu.Unlock()
		return errors.New("stream closed")
	}
	kind, adapter := e.chooseAdapterLocked(failedKind)
	if adapter == nil {
		e.mu.Unlock()
		return errors.New("stream closed")
	}
	route.kind = kind
	route.endpoint = adapter
	route.dstID = adapter.AllocMessageId()
	e.ackIDs[frameEndpointKey{kind: kind, messageID: route.dstID}] = logicalID
	frames := orderedFrames(route.framesBySeq)
	dstID := route.dstID
	e.mu.Unlock()

	for _, f := range frames {
		out := cloneFrame(f)
		out.MessageId = dstID
		if err := adapter.HandleFrame(ctx, out); err != nil {
			e.stream.handleLegFailure(kind, adapter.stream)
			return err
		}
	}
	e.finishRouteIfComplete(logicalID)
	return nil
}

// chooseAdapterLocked 选一条可用 leg：优先 DualStream 当前的 preferred 协议，
// 否则在 TCP/KCP 里挑一条非 exclude 的现役 leg。exclude 用于 failover 时排除刚失败的 leg。
// 调用方必须已持有 e.mu。
func (e *DualFrameRelayEndpoint) chooseAdapterLocked(exclude streamTransport) (streamTransport, *TcpFrameAdapter) {
	preferred := e.stream.preferredTransport()
	if preferred != exclude {
		if adapter := e.adapters[preferred]; adapter != nil {
			return preferred, adapter
		}
	}
	// 按 DualStream.legOrder 的稳定顺序遍历适配器（含 "tcp#2" 等额外同协议 leg），
	// 选第一条非 exclude/preferred 的。用稳定顺序而非 map 随机序，避免回程 leg 抖动。
	for _, id := range e.stream.legIDOrder() {
		if id == exclude || id == preferred {
			continue
		}
		if adapter := e.adapters[id]; adapter != nil {
			return id, adapter
		}
	}
	return streamTransportUnknown, nil
}

func (e *DualFrameRelayEndpoint) finishRouteIfComplete(logicalID uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	route := e.routes[logicalID]
	if route != nil && route.totalFrames > 0 && len(route.framesBySeq) >= int(route.totalFrames) {
		delete(e.routes, logicalID)
	}
}

func (e *DualFrameRelayEndpoint) AllocMessageId() uint64 {
	return e.logicalGen.Next()
}

func (e *DualFrameRelayEndpoint) NodeId() string {
	return e.stream.NodeId()
}

func (e *DualFrameRelayEndpoint) ConnectionId() string {
	return e.stream.ConnectionId()
}

func (e *DualFrameRelayEndpoint) Close() error {
	return e.stream.Close()
}

func cloneFrame(f *network.Frame) *network.Frame {
	if f == nil {
		return nil
	}
	out := *f
	out.Payload = append([]byte(nil), f.Payload...)
	return &out
}

func orderedFrames(frames map[uint32]*network.Frame) []*network.Frame {
	seqs := make([]int, 0, len(frames))
	for seq := range frames {
		seqs = append(seqs, int(seq))
	}
	sort.Ints(seqs)
	out := make([]*network.Frame, 0, len(seqs))
	for _, seq := range seqs {
		out = append(out, frames[uint32(seq)])
	}
	return out
}
