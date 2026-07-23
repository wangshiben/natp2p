package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	defaultFrameRelayMaxCachedBytes      int64 = 64 << 20
	defaultFrameRelayMaxRouteCachedBytes int64 = 16 << 20
	defaultFrameRelayMaxRoutes                 = 8192
	defaultRelayBatchMaxFrames                 = 32
	defaultRelayBatchMaxBytes                  = 32 << 10
	frameRelayRouteTTL                         = 2 * time.Minute
	frameRelayCompletedRouteTTL                = 90 * time.Second
	frameRelaySweepInterval                    = 250 * time.Millisecond
	frameRelaySlowRouteThreshold               = 2
)

var errFrameRelayReplayCacheUnavailable = errors.New("frame relay replay cache unavailable")
var errFrameRelayLegDetached = errors.New("frame relay leg detached during attach")

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
// 该接口只在 relay 内部使用，应用层 / Noise 握手 / 客户端 ClientStream 仍走 network.Stream。
type FrameRelayEndpoint interface {
	// NextFrame 从底层流的"帧旁路通道"取下一帧原始帧。
	// pure-forwarder 模式会同时返回 Data/Retransmit 与 ACK，且不会做重组。
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

// frameBatchSource/frameBatchSink 是 relay 数据面的可选快速路径。实现方仍须保持
// FrameRelayEndpoint 的同步完成语义；不支持批处理的 endpoint 由 pump 自动退化为单帧。
type frameBatchSource interface {
	NextFrameBatch(ctx context.Context, maxFrames, maxBytes int) ([]*network.Frame, error)
}

type frameBatchSink interface {
	HandleFrameBatch(ctx context.Context, frames []*network.Frame) error
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
//	frames  本适配器持有的旁路通道，缓冲 4096 帧，供 relay pump 通过 NextFrame 消费。
//	        通道所有权在构造期通过 stream.SetFrameTap 转交给 TcpStream，由它写入。
type TcpFrameAdapter struct {
	stream  *TcpStream
	frames  chan *network.Frame
	readMu  sync.Mutex
	pending *network.Frame
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
//   - 创建一个带缓冲（4096）的 *network.Frame 通道。
//   - 调用 stream.SetFrameTap 把通道写入端交给 TcpStream；relay 模式可靠投递业务帧，
//     缓冲满时向底层读取施加背压，避免静默丢帧。
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
	a.readMu.Lock()
	defer a.readMu.Unlock()
	if a.pending != nil {
		frame := a.pending
		a.pending = nil
		return frame, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.stream.streamCtx.Done():
		return nil, a.stream.streamErr()
	case frame := <-a.frames:
		if frame == nil {
			return nil, errors.New("frame relay: nil input frame")
		}
		return frame, nil
	}
}

// NextFrameBatch 阻塞取得首帧后，仅排空已经到达的帧，不等待凑批。
func (a *TcpFrameAdapter) NextFrameBatch(ctx context.Context, maxFrames, maxBytes int) ([]*network.Frame, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	return pullFrameBatch(ctx, a.stream.streamCtx.Done(), a.stream.streamErr, a.frames, &a.pending, maxFrames, maxBytes)
}

// HandleFrame 把一帧原始数据写到底层 TCP 连接。
// 调用方（relay frame pump）通常已经把 frame.MessageId 改写为目标 leg 的新 ID。
func (a *TcpFrameAdapter) HandleFrame(ctx context.Context, frame *network.Frame) error {
	return a.stream.HandleFrame(ctx, frame)
}

func (a *TcpFrameAdapter) HandleFrameBatch(ctx context.Context, frames []*network.Frame) error {
	return a.stream.HandleFrameBatch(ctx, frames)
}

func pullFrameBatch(
	ctx context.Context,
	streamDone <-chan struct{},
	streamErr func() error,
	input <-chan *network.Frame,
	pending **network.Frame,
	maxFrames, maxBytes int,
) ([]*network.Frame, error) {
	if maxFrames <= 0 {
		maxFrames = defaultRelayBatchMaxFrames
	}
	if maxBytes <= 0 {
		maxBytes = int(^uint(0) >> 1)
	}

	var first *network.Frame
	if *pending != nil {
		first = *pending
		*pending = nil
	} else {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-streamDone:
			return nil, streamErr()
		case first = <-input:
		}
	}
	if first == nil {
		return nil, errors.New("frame relay: nil input frame")
	}
	firstSize, err := first.WireSize()
	if err != nil {
		return nil, err
	}
	batchCapacity := len(input) + 1
	if batchCapacity > maxFrames {
		batchCapacity = maxFrames
	}
	frames := make([]*network.Frame, 1, batchCapacity)
	frames[0] = first
	totalBytes := firstSize
	if maxFrames == 1 || totalBytes >= maxBytes {
		return frames, nil
	}

	for len(frames) < maxFrames {
		select {
		case frame := <-input:
			if frame == nil {
				return nil, errors.New("frame relay: nil input frame")
			}
			size, sizeErr := frame.WireSize()
			if sizeErr != nil {
				return nil, sizeErr
			}
			if totalBytes > maxBytes-size {
				*pending = frame
				return frames, nil
			}
			frames = append(frames, frame)
			totalBytes += size
		default:
			return frames, nil
		}
	}
	return frames, nil
}

func nextEndpointFrameBatch(ctx context.Context, endpoint FrameRelayEndpoint) ([]*network.Frame, error) {
	if source, ok := endpoint.(frameBatchSource); ok {
		return source.NextFrameBatch(ctx, defaultRelayBatchMaxFrames, defaultRelayBatchMaxBytes)
	}
	frame, err := endpoint.NextFrame(ctx)
	if err != nil {
		return nil, err
	}
	return []*network.Frame{frame}, nil
}

func writeEndpointFrameBatch(ctx context.Context, endpoint FrameRelayEndpoint, frames []*network.Frame) error {
	if len(frames) == 0 {
		return nil
	}
	if len(frames) > 1 {
		if sink, ok := endpoint.(frameBatchSink); ok {
			return sink.HandleFrameBatch(ctx, frames)
		}
	}
	for _, frame := range frames {
		if err := endpoint.HandleFrame(ctx, frame); err != nil {
			return err
		}
	}
	return nil
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

type adapterReplayJob struct {
	logicalID  uint64
	generation uint64
	adapter    *TcpFrameAdapter
	dstID      uint64
	frames     []*network.Frame
}

type frameRelayQualityReplayJob struct {
	logicalID  uint64
	generation uint64
	kind       streamTransport
	adapter    *TcpFrameAdapter
	dstID      uint64
	frames     []*network.Frame
}

// frameEndpointKey 是 incomingIDs / ackIDs 的 key：某条具体 leg（kind）上、某条业务连接（connId）的一个 transport MessageId。
// 用 kind 区分 TCP/KCP 两条 leg 的独立命名空间；用 connId 区分**同一条物理连接上多路复用的多条逻辑连接**——
// callee 把 N 条 per-conn 流复用到一条 server↔relay 连接时，各 per-conn 流的 frameIdGen 都从 1 开始、
// MessageId 会撞车，必须带 connId 才能把它们区分开（否则两条流的 msgId=1 会被并成同一条 logicalID 而互相串台）。
type frameEndpointKey struct {
	kind      streamTransport
	adapter   *TcpFrameAdapter
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
	kind         streamTransport
	connId       string // 该 logicalID 所属业务连接，failover 重绑 ackIDs 时需要
	endpoint     *TcpFrameAdapter
	dstID        uint64
	totalFrames  uint32
	framesBySeq  map[uint32]*network.Frame
	sourceKey    *frameEndpointKey
	ackKeys      map[frameEndpointKey]struct{}
	cachedBytes  int64
	payloadBytes int64
	ackedFrames  uint64
	lastAckAt    time.Time
	createdAt    time.Time
	lastActive   time.Time
	completedAt  time.Time
	generation   uint64
	replayOff    bool
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

	mu            sync.Mutex
	readMu        sync.Mutex
	adapters      map[streamTransport]*TcpFrameAdapter
	incoming      chan *network.Frame
	pending       *network.Frame
	incomingIDs   map[frameEndpointKey]uint64
	ackIDs        map[frameEndpointKey]uint64
	logicalGen    network.FrameIdGenerator
	routes        map[uint64]*dualFrameRoute
	slowKCPRoutes map[streamTransport]int
	cachedBytes   int64
	maxBytes      int64
	maxRouteBytes int64
	maxRoutes     int
	closed        bool
}

func NewDualFrameRelayEndpoint(stream *DualStream) *DualFrameRelayEndpoint {
	if stream == nil {
		return nil
	}
	endpoint := &DualFrameRelayEndpoint{
		stream:        stream,
		adapters:      make(map[streamTransport]*TcpFrameAdapter),
		incoming:      make(chan *network.Frame, 1024),
		incomingIDs:   make(map[frameEndpointKey]uint64),
		ackIDs:        make(map[frameEndpointKey]uint64),
		routes:        make(map[uint64]*dualFrameRoute),
		slowKCPRoutes: make(map[streamTransport]int),
		maxBytes:      defaultFrameRelayMaxCachedBytes,
		maxRouteBytes: defaultFrameRelayMaxRouteCachedBytes,
		maxRoutes:     defaultFrameRelayMaxRoutes,
	}
	go endpoint.reapRoutes()
	return endpoint
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
	if !e.stream.isCurrentLeg(kind, stream) {
		return errFrameRelayLegDetached
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("frame relay endpoint closed")
	}
	if current := e.adapters[kind]; current != nil && current.stream == tcp {
		e.mu.Unlock()
		if !e.stream.isCurrentLeg(kind, stream) {
			e.onLegDetached(kind, stream)
			return errFrameRelayLegDetached
		}
		return nil
	}
	e.mu.Unlock()

	adapter := NewTcpFrameAdapter(tcp)
	tcp.SetPureForwarder(true)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("frame relay endpoint closed")
	}
	if current := e.adapters[kind]; current != nil && current.stream == tcp {
		e.mu.Unlock()
		if !e.stream.isCurrentLeg(kind, stream) {
			e.onLegDetached(kind, stream)
			return errFrameRelayLegDetached
		}
		return nil
	}
	previous := e.adapters[kind]
	e.adapters[kind] = adapter
	previousAdapters := make([]*TcpFrameAdapter, 0, 1)
	if previous != nil {
		previousAdapters = append(previousAdapters, previous)
	} else {
		seen := make(map[*TcpFrameAdapter]struct{})
		for _, route := range e.routes {
			if route == nil || route.kind != kind || route.endpoint == nil || route.endpoint == adapter {
				continue
			}
			if _, ok := seen[route.endpoint]; ok {
				continue
			}
			seen[route.endpoint] = struct{}{}
			previousAdapters = append(previousAdapters, route.endpoint)
		}
	}
	jobs := make([]adapterReplayJob, 0)
	for _, previousAdapter := range previousAdapters {
		jobs = append(jobs, e.replaceAdapterLocked(kind, previousAdapter, adapter, time.Now())...)
	}
	e.mu.Unlock()
	go e.collect(kind, adapter)
	for _, job := range jobs {
		for _, frame := range job.frames {
			e.mu.Lock()
			current := e.routes[job.logicalID]
			valid := !e.closed && e.adapters[kind] == job.adapter && current != nil &&
				current.endpoint == job.adapter && current.generation == job.generation && current.completedAt.IsZero()
			e.mu.Unlock()
			if !valid {
				break
			}
			out := cloneFrame(frame)
			out.MessageId = job.dstID
			if err := job.adapter.HandleFrame(e.stream.ctx, out); err != nil {
				if e.isCurrent(kind, job.adapter) {
					e.stream.handleLegFailure(kind, job.adapter.stream)
				}
				return err
			}
		}
	}
	if !e.stream.isCurrentLeg(kind, stream) {
		e.onLegDetached(kind, stream)
		return errFrameRelayLegDetached
	}
	return nil
}

func (e *DualFrameRelayEndpoint) replaceAdapterLocked(kind streamTransport, previous, replacement *TcpFrameAdapter, now time.Time) []adapterReplayJob {
	if previous == nil || previous == replacement {
		return nil
	}
	jobs := make([]adapterReplayJob, 0)
	for logicalID, route := range e.routes {
		if route == nil {
			delete(e.routes, logicalID)
			continue
		}
		e.dropAdapterAckKeysLocked(route, previous)
		fromPrevious := route.sourceKey != nil && route.sourceKey.adapter == previous
		toPrevious := route.endpoint == previous
		if fromPrevious || (toPrevious && !route.completedAt.IsZero()) {
			e.removeRouteLocked(logicalID)
			continue
		}
		if !toPrevious {
			continue
		}
		route.kind = kind
		route.endpoint = replacement
		route.dstID = replacement.AllocMessageId()
		route.generation++
		route.lastActive = now
		e.bindAckKeyLocked(logicalID, route, kind, replacement, route.dstID)
		if !route.replayOff {
			jobs = append(jobs, adapterReplayJob{
				logicalID:  logicalID,
				generation: route.generation,
				adapter:    replacement,
				dstID:      route.dstID,
				frames:     orderedFrames(route.framesBySeq),
			})
		}
	}
	e.dropAdapterIndexesLocked(previous)
	return jobs
}

func (e *DualFrameRelayEndpoint) dropAdapterAckKeysLocked(route *dualFrameRoute, adapter *TcpFrameAdapter) {
	if route == nil || adapter == nil {
		return
	}
	for key := range route.ackKeys {
		if key.adapter != adapter {
			continue
		}
		delete(route.ackKeys, key)
		delete(e.ackIDs, key)
	}
}

func (e *DualFrameRelayEndpoint) dropAdapterIndexesLocked(adapter *TcpFrameAdapter) {
	if adapter == nil {
		return
	}
	for key := range e.incomingIDs {
		if key.adapter == adapter {
			delete(e.incomingIDs, key)
		}
	}
	for key := range e.ackIDs {
		if key.adapter == adapter {
			delete(e.ackIDs, key)
		}
	}
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
		e.mu.Lock()
		if e.closed || e.adapters[kind] != adapter {
			e.mu.Unlock()
			return
		}
		now := time.Now()
		logicalID, route, resolveErr := e.resolveIncomingFrameLocked(kind, adapter, f, now)
		preferred := streamTransportUnknown
		if resolveErr == nil && route != nil && isFullFrameAck(f, route.totalFrames) {
			preferred = e.completeRouteLocked(route, now)
		}
		e.mu.Unlock()
		if preferred != streamTransportUnknown {
			e.stream.setPreferred(preferred)
		}
		if resolveErr != nil {
			logx.Errorf("[FrameRelay] %s 入站帧状态无效, 关闭逻辑流: nodeId=%.16s connId=%s err=%v",
				kindStr, e.stream.NodeId(), e.stream.ConnectionId(), resolveErr)
			_ = e.stream.Close()
			return
		}
		if route == nil {
			continue
		}
		out := cloneFrame(f)
		out.MessageId = logicalID
		select {
		case <-e.stream.ctx.Done():
			return
		case e.incoming <- out:
		}
	}
}

func (e *DualFrameRelayEndpoint) resolveIncomingFrameLocked(kind streamTransport, adapter *TcpFrameAdapter, frame *network.Frame, now time.Time) (uint64, *dualFrameRoute, error) {
	if frame == nil {
		return 0, nil, errors.New("nil frame")
	}
	if frame.FrameType == network.FrameTypeAck {
		key := frameEndpointKey{kind: kind, adapter: adapter, messageID: frame.MessageId}
		logicalID, ok := e.ackIDs[key]
		if !ok {
			return 0, nil, nil
		}
		route := e.routes[logicalID]
		if route == nil {
			delete(e.ackIDs, key)
			return 0, nil, nil
		}
		route.lastActive = now
		e.observeAckProgressLocked(route, frame, now)
		return logicalID, route, nil
	}
	if frame.FrameType != network.FrameTypeData && frame.FrameType != network.FrameTypeRetransmit {
		return 0, nil, nil
	}
	if frame.TotalFrames == 0 || frame.SeqId >= frame.TotalFrames {
		return 0, nil, errors.New("invalid data frame sequence")
	}

	key := frameEndpointKey{kind: kind, adapter: adapter, connId: frame.ConnectionId, messageID: frame.MessageId}
	if logicalID, ok := e.incomingIDs[key]; ok {
		route := e.routes[logicalID]
		if route != nil {
			if route.totalFrames != frame.TotalFrames {
				return 0, nil, errors.New("frames disagree on TotalFrames for relay route")
			}
			route.lastActive = now
			return logicalID, route, nil
		}
		delete(e.incomingIDs, key)
	}
	if !e.ensureRouteSlotLocked(now) {
		return 0, nil, fmt.Errorf("frame relay route limit exceeded: %d", e.maxRoutes)
	}
	logicalID := e.logicalGen.Next()
	sourceKey := key
	route := &dualFrameRoute{
		kind:        kind,
		connId:      frame.ConnectionId,
		endpoint:    adapter,
		dstID:       frame.MessageId,
		totalFrames: frame.TotalFrames,
		framesBySeq: make(map[uint32]*network.Frame),
		sourceKey:   &sourceKey,
		createdAt:   now,
		lastActive:  now,
	}
	e.incomingIDs[key] = logicalID
	e.routes[logicalID] = route
	return logicalID, route, nil
}

func (e *DualFrameRelayEndpoint) isCurrent(kind streamTransport, adapter *TcpFrameAdapter) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.closed && e.adapters[kind] == adapter
}

// NextFrame 供 relay pump 消费入站汇聚帧（已是 logicalID 视角）。
func (e *DualFrameRelayEndpoint) NextFrame(ctx context.Context) (*network.Frame, error) {
	e.readMu.Lock()
	defer e.readMu.Unlock()
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil, errors.New("frame relay endpoint closed")
	}
	if e.pending != nil {
		frame := e.pending
		e.pending = nil
		return frame, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.stream.ctx.Done():
		return nil, errors.New("stream closed")
	case frame := <-e.incoming:
		if frame == nil {
			return nil, errors.New("frame relay: nil input frame")
		}
		return frame, nil
	}
}

func (e *DualFrameRelayEndpoint) NextFrameBatch(ctx context.Context, maxFrames, maxBytes int) ([]*network.Frame, error) {
	e.readMu.Lock()
	defer e.readMu.Unlock()
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil, errors.New("frame relay endpoint closed")
	}
	return pullFrameBatch(ctx, e.stream.ctx.Done(), func() error {
		return errors.New("stream closed")
	}, e.incoming, &e.pending, maxFrames, maxBytes)
}

// HandleFrame 是出站方向：relay pump 把一帧（MessageId 已是 logicalID）交给本端点写出。
//
// 流程：
//  1. 用 logicalID 查 routes：
//     - 命中（常见）：说明这条消息的目标 leg / dstID 已确定，直接复用。
//     collect 在入站时已为「来源 logicalID」建好回写 route；反方向的数据/ACK 都走这里。
//     - 未命中：这是一条新发起的出站消息，选一条可用 leg、分配新的 dstID 建 route，
//     并把 {目标 adapter, leg kind, dstID} -> logicalID 写进 ackIDs，
//     这样对端基于 dstID 回来的 ACK 能在 collect 里翻译回同一个 logicalID（闭环）。
//  2. 缓存该帧（按 SeqId），供 leg failover 时重放。
//  3. 把帧 MessageId 改写成 dstID，写到目标 leg。
//  4. 写失败则走 replayRoute：换 backup leg 并把已缓存帧整条重放。
func (e *DualFrameRelayEndpoint) HandleFrame(ctx context.Context, frame *network.Frame) error {
	return e.handleFrameRun(ctx, []*network.Frame{frame})
}

// HandleFrameBatch 保持输入 FIFO，仅合并连续且属于同一 logical message 的数据帧。
// ACK/控制帧始终单独写出，避免被大数据批次拖延。
func (e *DualFrameRelayEndpoint) HandleFrameBatch(ctx context.Context, frames []*network.Frame) error {
	for start := 0; start < len(frames); {
		first := frames[start]
		if first == nil {
			return errors.New("frame relay: nil frame")
		}
		end := start + 1
		if isRelayBatchDataFrame(first) {
			for end < len(frames) && sameRelayFrameRun(first, frames[end]) {
				end++
			}
		}
		if err := e.handleFrameRun(ctx, frames[start:end]); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func isRelayBatchDataFrame(frame *network.Frame) bool {
	return frame != nil && (frame.FrameType == network.FrameTypeData || frame.FrameType == network.FrameTypeRetransmit)
}

func sameRelayFrameRun(first, next *network.Frame) bool {
	return isRelayBatchDataFrame(next) && first.MessageId == next.MessageId &&
		first.ConnectionId == next.ConnectionId && first.TotalFrames == next.TotalFrames
}

func (e *DualFrameRelayEndpoint) handleFrameRun(ctx context.Context, frames []*network.Frame) error {
	if len(frames) == 0 {
		return nil
	}
	frame := frames[0]
	if frame == nil {
		return errors.New("frame relay: nil frame")
	}
	logicalID := frame.MessageId
	for _, candidate := range frames {
		if candidate == nil {
			return errors.New("frame relay: nil frame")
		}
		if candidate.MessageId != logicalID || candidate.ConnectionId != frame.ConnectionId || candidate.TotalFrames != frame.TotalFrames {
			return errors.New("frame relay: mixed message batch")
		}
		if len(frames) > 1 && !isRelayBatchDataFrame(candidate) {
			return errors.New("frame relay: control frame in data batch")
		}
		if isRelayBatchDataFrame(candidate) && (candidate.TotalFrames == 0 || candidate.SeqId >= candidate.TotalFrames) {
			return errors.New("frame relay: invalid data frame sequence")
		}
	}

	now := time.Now()
	replayDisabledNow := false
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("frame relay endpoint closed")
	}
	route := e.routes[logicalID]
	if route == nil {
		if frame.FrameType == network.FrameTypeAck {
			e.mu.Unlock()
			return nil
		}
		if frame.FrameType != network.FrameTypeData && frame.FrameType != network.FrameTypeRetransmit {
			e.mu.Unlock()
			return errors.New("frame relay: unsupported frame type")
		}
		if frame.TotalFrames == 0 || frame.SeqId >= frame.TotalFrames {
			e.mu.Unlock()
			return errors.New("frame relay: invalid data frame sequence")
		}
		if !e.ensureRouteSlotLocked(now) {
			e.mu.Unlock()
			return fmt.Errorf("frame relay route limit exceeded: %d", e.maxRoutes)
		}
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
			ackKeys:     make(map[frameEndpointKey]struct{}),
			createdAt:   now,
			lastActive:  now,
			generation:  1,
		}
		e.routes[logicalID] = route
		e.bindAckKeyLocked(logicalID, route, kind, adapter, route.dstID)
	} else if route.totalFrames != frame.TotalFrames && frame.TotalFrames != 0 {
		e.mu.Unlock()
		return errors.New("frame relay: TotalFrames changed for existing route")
	}
	route.lastActive = now
	if route.completedAt.IsZero() {
		for _, candidate := range frames {
			if e.cacheFrameLocked(route, candidate) {
				replayDisabledNow = true
			}
		}
	}
	kind := route.kind
	endpoint := route.endpoint
	dstID := route.dstID
	generation := route.generation
	e.mu.Unlock()
	if replayDisabledNow {
		logx.Warnf("[FrameRelay] 重放缓存达到上限, 健康链路继续直通但本消息不再支持 leg 重放: nodeId=%.16s connId=%s logicalID=%d",
			e.stream.NodeId(), e.stream.ConnectionId(), logicalID)
	}

	outputs := make([]*network.Frame, len(frames))
	for index, candidate := range frames {
		out := *candidate
		out.MessageId = dstID
		outputs[index] = &out
	}
	if err := writeEndpointFrameBatch(ctx, endpoint, outputs); err != nil {
		kindStr := transportName(legFamily(kind))
		logx.Warnf("[FrameRelay] %s HandleFrame 写入失败, 触发 replayRoute: nodeId=%.16s connId=%s err=%v",
			kindStr, e.stream.NodeId(), e.stream.ConnectionId(), err)
		return e.replayRoute(ctx, logicalID, kind, endpoint, generation)
	}
	if isFullFrameAck(frame, route.totalFrames) {
		preferred := streamTransportUnknown
		e.mu.Lock()
		if current := e.routes[logicalID]; current == route && current.generation == generation {
			preferred = e.completeRouteLocked(current, time.Now())
		}
		e.mu.Unlock()
		if preferred != streamTransportUnknown {
			e.stream.setPreferred(preferred)
		}
	}
	return nil
}

func (e *DualFrameRelayEndpoint) bindAckKeyLocked(logicalID uint64, route *dualFrameRoute, kind streamTransport, adapter *TcpFrameAdapter, dstID uint64) {
	key := frameEndpointKey{kind: kind, adapter: adapter, messageID: dstID}
	e.ackIDs[key] = logicalID
	if route.ackKeys == nil {
		route.ackKeys = make(map[frameEndpointKey]struct{})
	}
	route.ackKeys[key] = struct{}{}
}

func (e *DualFrameRelayEndpoint) cacheFrameLocked(route *dualFrameRoute, frame *network.Frame) bool {
	if route == nil || frame == nil || route.replayOff {
		return false
	}
	if existing := route.framesBySeq[frame.SeqId]; existing != nil {
		if frame.FrameType != network.FrameTypeAck {
			return false
		}
		size := cachedFrameBytes(existing)
		route.cachedBytes -= size
		e.cachedBytes -= size
		delete(route.framesBySeq, frame.SeqId)
	}
	size := cachedFrameBytes(frame)
	if route.cachedBytes+size > e.maxRouteBytes || e.cachedBytes+size > e.maxBytes {
		payloadBytes := route.payloadBytes
		e.releaseRouteFramesLocked(route)
		route.payloadBytes = payloadBytes
		route.replayOff = true
		return true
	}
	if route.framesBySeq == nil {
		route.framesBySeq = make(map[uint32]*network.Frame)
	}
	route.framesBySeq[frame.SeqId] = cloneFrame(frame)
	route.cachedBytes += size
	e.cachedBytes += size
	if frame.FrameType == network.FrameTypeData || frame.FrameType == network.FrameTypeRetransmit {
		route.payloadBytes += int64(len(frame.Payload))
	}
	return false
}

func cachedFrameBytes(frame *network.Frame) int64 {
	if frame == nil {
		return 0
	}
	return int64(network.FrameHeaderLength + len(frame.ConnectionId) + len(frame.Payload) + 128)
}

// replayRoute 在当前目标 leg 写失败时调用：
//   - 关闭/摘除失败 leg 并触发其重连；
//   - 选一条 backup leg，给这条 logicalID 重新分配 dstID（并刷新 dstID->logicalID 闭环）；
//   - 把已缓存的所有帧按 SeqId 顺序重放到 backup leg，保证目标侧拿到的是完整消息，
//     而不是「前半段在旧 leg、后半段在新 leg」的拼不起来的半条消息。
//
// onLegDetached 在 DualStream 摘除一条 leg 时调用：删除该 leg 的 adapter，
// 并把所有绑定到它的回写路由主动切到一条存活 leg（无存活 leg 则保留，待新 leg attach）。
// 这样即便没有写失败触发 replayRoute，回程也能主动避开已摘除的死 leg。
func (e *DualFrameRelayEndpoint) onLegDetached(id streamTransport, stream network.Stream) {
	detachedStream := tcpStreamFromStream(stream)
	if detachedStream == nil {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	failedAdapter := e.adapters[id]
	if failedAdapter == nil || failedAdapter.stream != detachedStream {
		e.mu.Unlock()
		return
	}
	delete(e.adapters, id)
	type replayJob struct {
		kind    streamTransport
		adapter *TcpFrameAdapter
		frames  []*network.Frame
		dstID   uint64
	}
	jobs := make([]replayJob, 0)
	for logicalID, route := range e.routes {
		if route == nil {
			delete(e.routes, logicalID)
			continue
		}
		e.dropAdapterAckKeysLocked(route, failedAdapter)
		if route.kind != id || route.endpoint != failedAdapter {
			continue
		}
		if route.sourceKey != nil || !route.completedAt.IsZero() {
			e.removeRouteLocked(logicalID)
			continue
		}
		if route.replayOff {
			e.removeRouteLocked(logicalID)
			continue
		}
		kind, adapter := e.chooseAdapterLocked(id)
		if adapter == nil {
			continue
		}
		route.kind = kind
		route.endpoint = adapter
		route.dstID = adapter.AllocMessageId()
		route.generation++
		route.lastActive = time.Now()
		e.bindAckKeyLocked(logicalID, route, kind, adapter, route.dstID)
		jobs = append(jobs, replayJob{
			kind:    kind,
			adapter: adapter,
			frames:  orderedFrames(route.framesBySeq),
			dstID:   route.dstID,
		})
	}
	e.dropAdapterIndexesLocked(failedAdapter)
	e.mu.Unlock()

	for _, job := range jobs {
		for _, frame := range job.frames {
			out := cloneFrame(frame)
			out.MessageId = job.dstID
			if err := job.adapter.HandleFrame(e.stream.ctx, out); err != nil {
				e.stream.handleLegFailure(job.kind, job.adapter.stream)
				break
			}
		}
	}
}

func (e *DualFrameRelayEndpoint) replayRoute(ctx context.Context, logicalID uint64, failedKind streamTransport, failedEndpoint *TcpFrameAdapter, failedGeneration uint64) error {
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
	if route.generation != failedGeneration || route.endpoint != failedEndpoint {
		e.mu.Unlock()
		return nil
	}
	if route.replayOff {
		e.mu.Unlock()
		return errFrameRelayReplayCacheUnavailable
	}
	if !route.completedAt.IsZero() {
		e.mu.Unlock()
		return nil
	}
	kind := streamTransportUnknown
	adapter := e.adapters[failedKind]
	if adapter != nil && adapter != failedEndpoint {
		kind = failedKind
	} else {
		kind, adapter = e.chooseAdapterLocked(failedKind)
	}
	if adapter == nil {
		e.mu.Unlock()
		return errors.New("stream closed")
	}
	route.kind = kind
	route.endpoint = adapter
	route.dstID = adapter.AllocMessageId()
	route.generation++
	route.lastActive = time.Now()
	e.bindAckKeyLocked(logicalID, route, kind, adapter, route.dstID)
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

func (e *DualFrameRelayEndpoint) ensureRouteSlotLocked(now time.Time) bool {
	if e.maxRoutes <= 0 {
		return false
	}
	if len(e.routes) < e.maxRoutes {
		return true
	}
	e.sweepExpiredLocked(now)
	for len(e.routes) >= e.maxRoutes {
		var oldestID uint64
		var oldest time.Time
		for logicalID, route := range e.routes {
			if route == nil || route.completedAt.IsZero() {
				continue
			}
			if oldestID == 0 || route.completedAt.Before(oldest) {
				oldestID = logicalID
				oldest = route.completedAt
			}
		}
		if oldestID == 0 {
			return false
		}
		e.removeRouteLocked(oldestID)
	}
	return true
}

func (e *DualFrameRelayEndpoint) prepareQualityReplayLocked(now time.Time) ([]frameRelayQualityReplayJob, uint64) {
	if e.closed || e.stream == nil {
		return nil, 0
	}
	tcpKind := streamTransportUnknown
	var tcpAdapter *TcpFrameAdapter
	for _, id := range e.stream.legIDOrder() {
		if legFamily(id) == streamTransportTCP && e.adapters[id] != nil {
			tcpKind = id
			tcpAdapter = e.adapters[id]
			break
		}
	}
	if tcpAdapter == nil {
		return nil, 0
	}

	jobs := make([]frameRelayQualityReplayJob, 0)
	for logicalID, route := range e.routes {
		if route == nil || route.sourceKey != nil || !route.completedAt.IsZero() ||
			legFamily(route.kind) != streamTransportKCP || route.createdAt.IsZero() || now.Before(route.createdAt) {
			continue
		}
		budget, eligible := frameRelayRouteQualityBudget(route.payloadBytes)
		if !eligible {
			continue
		}
		progressAt := route.createdAt
		if route.lastAckAt.After(progressAt) {
			progressAt = route.lastAckAt
		}
		if now.Sub(progressAt) < budget {
			continue
		}
		if route.replayOff || len(route.framesBySeq) == 0 {
			return nil, logicalID
		}

		kcpKind := route.kind
		route.kind = tcpKind
		route.endpoint = tcpAdapter
		route.dstID = tcpAdapter.AllocMessageId()
		route.generation++
		route.lastActive = now
		e.bindAckKeyLocked(logicalID, route, tcpKind, tcpAdapter, route.dstID)
		delete(e.slowKCPRoutes, kcpKind)
		jobs = append(jobs, frameRelayQualityReplayJob{
			logicalID:  logicalID,
			generation: route.generation,
			kind:       tcpKind,
			adapter:    tcpAdapter,
			dstID:      route.dstID,
			frames:     orderedFrames(route.framesBySeq),
		})
	}
	return jobs, 0
}

func frameRelayRouteQualityBudget(payloadBytes int64) (time.Duration, bool) {
	if payloadBytes <= 0 {
		return 0, false
	}
	maximumInt := int64(^uint(0) >> 1)
	if payloadBytes > maximumInt {
		payloadBytes = maximumInt
	}
	return defaultKCPSendQualityPolicy().budget(int(payloadBytes))
}

func (e *DualFrameRelayEndpoint) writeQualityReplayJob(ctx context.Context, job frameRelayQualityReplayJob) error {
	for _, frame := range job.frames {
		e.mu.Lock()
		current := e.routes[job.logicalID]
		valid := !e.closed && e.adapters[job.kind] == job.adapter && current != nil &&
			current.endpoint == job.adapter && current.generation == job.generation && current.completedAt.IsZero()
		e.mu.Unlock()
		if !valid {
			return nil
		}
		out := cloneFrame(frame)
		out.MessageId = job.dstID
		if err := job.adapter.HandleFrame(ctx, out); err != nil {
			return err
		}
	}
	return nil
}

func (e *DualFrameRelayEndpoint) maintainRoutes(now time.Time) {
	e.mu.Lock()
	jobs, unavailableLogicalID := e.prepareQualityReplayLocked(now)
	if unavailableLogicalID != 0 {
		e.closed = true
		e.adapters = make(map[streamTransport]*TcpFrameAdapter)
		e.clearRoutesLocked()
		e.mu.Unlock()
		logx.Errorf("[FrameRelay] KCP route 质量超时但重放缓存不可用, fail-closed: nodeId=%.16s connId=%s logicalID=%d",
			e.stream.NodeId(), e.stream.ConnectionId(), unavailableLogicalID)
		_ = e.stream.Close()
		return
	}
	e.sweepExpiredLocked(now)
	e.mu.Unlock()

	for _, job := range jobs {
		e.stream.setPreferred(job.kind)
		logx.Warnf("[FrameRelay] KCP route ACK 无进展超过质量预算, 改绑 TCP 并重放: nodeId=%.16s connId=%s logicalID=%d frames=%d",
			e.stream.NodeId(), e.stream.ConnectionId(), job.logicalID, len(job.frames))
		if err := e.writeQualityReplayJob(e.stream.ctx, job); err != nil {
			logx.Warnf("[FrameRelay] TCP 质量重放失败, 进入常规 leg failover: nodeId=%.16s connId=%s logicalID=%d err=%v",
				e.stream.NodeId(), e.stream.ConnectionId(), job.logicalID, err)
			_ = e.replayRoute(e.stream.ctx, job.logicalID, job.kind, job.adapter, job.generation)
		}
	}
}

func (e *DualFrameRelayEndpoint) completeRouteLocked(route *dualFrameRoute, now time.Time) streamTransport {
	if route == nil {
		return streamTransportUnknown
	}
	preferred := streamTransportUnknown
	if route.completedAt.IsZero() {
		preferred = e.observeCompletedRouteLocked(route, now)
		route.completedAt = now
	}
	e.releaseRouteFramesLocked(route)
	route.lastActive = now
	return preferred
}

func (e *DualFrameRelayEndpoint) observeCompletedRouteLocked(route *dualFrameRoute, now time.Time) streamTransport {
	if route.sourceKey != nil || legFamily(route.kind) != streamTransportKCP ||
		route.createdAt.IsZero() || now.Before(route.createdAt) {
		return streamTransportUnknown
	}
	budget, eligible := defaultKCPSendQualityPolicy().budget(int(route.payloadBytes))
	if !eligible {
		return streamTransportUnknown
	}
	if now.Sub(route.createdAt) < budget {
		delete(e.slowKCPRoutes, route.kind)
		return streamTransportUnknown
	}
	if e.slowKCPRoutes == nil {
		e.slowKCPRoutes = make(map[streamTransport]int)
	}
	e.slowKCPRoutes[route.kind]++
	if e.slowKCPRoutes[route.kind] < frameRelaySlowRouteThreshold {
		return streamTransportUnknown
	}
	if e.stream == nil {
		return streamTransportUnknown
	}
	for _, id := range e.stream.legIDOrder() {
		if legFamily(id) == streamTransportTCP && e.adapters[id] != nil {
			delete(e.slowKCPRoutes, route.kind)
			return id
		}
	}
	return streamTransportUnknown
}

func (e *DualFrameRelayEndpoint) releaseRouteFramesLocked(route *dualFrameRoute) {
	if route == nil {
		return
	}
	e.cachedBytes -= route.cachedBytes
	if e.cachedBytes < 0 {
		e.cachedBytes = 0
	}
	route.cachedBytes = 0
	route.payloadBytes = 0
	route.framesBySeq = nil
}

func (e *DualFrameRelayEndpoint) removeRouteLocked(logicalID uint64) {
	route := e.routes[logicalID]
	if route == nil {
		return
	}
	e.releaseRouteFramesLocked(route)
	if route.sourceKey != nil && e.incomingIDs[*route.sourceKey] == logicalID {
		delete(e.incomingIDs, *route.sourceKey)
	}
	for key := range route.ackKeys {
		if e.ackIDs[key] == logicalID {
			delete(e.ackIDs, key)
		}
	}
	delete(e.routes, logicalID)
}

func (e *DualFrameRelayEndpoint) sweepExpiredLocked(now time.Time) {
	for logicalID, route := range e.routes {
		if route == nil {
			delete(e.routes, logicalID)
			continue
		}
		if !route.completedAt.IsZero() {
			if now.Sub(route.lastActive) >= frameRelayCompletedRouteTTL {
				e.removeRouteLocked(logicalID)
			}
			continue
		}
		lastActive := route.lastActive
		if lastActive.IsZero() {
			lastActive = route.createdAt
		}
		if !lastActive.IsZero() && now.Sub(lastActive) >= frameRelayRouteTTL {
			e.removeRouteLocked(logicalID)
		}
	}
}

func (e *DualFrameRelayEndpoint) reapRoutes() {
	ticker := time.NewTicker(frameRelaySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.stream.ctx.Done():
			e.mu.Lock()
			e.closed = true
			e.adapters = make(map[streamTransport]*TcpFrameAdapter)
			e.clearRoutesLocked()
			e.mu.Unlock()
			return
		case now := <-ticker.C:
			e.maintainRoutes(now)
		}
	}
}

func (e *DualFrameRelayEndpoint) clearRoutesLocked() {
	for logicalID := range e.routes {
		e.removeRouteLocked(logicalID)
	}
	e.incomingIDs = make(map[frameEndpointKey]uint64)
	e.ackIDs = make(map[frameEndpointKey]uint64)
	e.slowKCPRoutes = make(map[streamTransport]int)
	e.cachedBytes = 0
}

func isFullFrameAck(frame *network.Frame, expectedTotal uint32) bool {
	if frame == nil || frame.FrameType != network.FrameTypeAck || expectedTotal == 0 || frame.TotalFrames != expectedTotal {
		return false
	}
	ranges, err := network.DecodeAckRanges(frame.Payload)
	if err != nil || len(ranges) == 0 {
		return false
	}
	cursor := uint64(0)
	total := uint64(expectedTotal)
	for _, ackRange := range ranges {
		start := uint64(ackRange.Start)
		end := uint64(ackRange.End)
		if start > end || end >= total || start > cursor {
			return false
		}
		if end >= cursor {
			cursor = end + 1
		}
	}
	return cursor == total
}

func (e *DualFrameRelayEndpoint) observeAckProgressLocked(route *dualFrameRoute, frame *network.Frame, now time.Time) {
	covered, valid := frameAckCoverage(frame, route.totalFrames)
	if !valid || covered <= route.ackedFrames {
		return
	}
	route.ackedFrames = covered
	route.lastAckAt = now
}

func frameAckCoverage(frame *network.Frame, expectedTotal uint32) (uint64, bool) {
	if frame == nil || frame.FrameType != network.FrameTypeAck || expectedTotal == 0 || frame.TotalFrames != expectedTotal {
		return 0, false
	}
	ranges, err := network.DecodeAckRanges(frame.Payload)
	if err != nil || len(ranges) == 0 {
		return 0, false
	}
	total := uint64(expectedTotal)
	var covered uint64
	var cursor uint64
	var previousStart uint64
	for index, ackRange := range ranges {
		start := uint64(ackRange.Start)
		end := uint64(ackRange.End)
		if start > end || end >= total || (index > 0 && start < previousStart) {
			return 0, false
		}
		previousStart = start
		if end < cursor {
			continue
		}
		if start < cursor {
			start = cursor
		}
		covered += end - start + 1
		cursor = end + 1
	}
	return covered, true
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
	e.mu.Lock()
	e.closed = true
	e.adapters = make(map[streamTransport]*TcpFrameAdapter)
	e.clearRoutesLocked()
	e.mu.Unlock()
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
