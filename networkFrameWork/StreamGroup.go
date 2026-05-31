package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"fmt"
	"sync"
)

// StreamGroup 负责管理多个Stream。
//
// 一个 group 在公网 relay 节点上对应"某个被中继的节点（设备1）"：
//   - relayStream: 与设备1之间已建立的那条注册流（用 Message 语义读取首条消息分类，
//     之后由 frame pump 直接搬运原始帧）。
//   - relayFrame:  在 relayStream 是 *TcpStream 时构造出的 FrameRelayEndpoint 适配器；
//     公网中转的数据面只通过它收发 Frame，不再做 Message 重组。
//   - connectionMap: 所有挂到该 group 上的"客户端 leg"。key = ConnectionId，
//     每个 client（设备2 ...）连进来时由 StreamOn() 注册。
//
// 字段说明：
//
//	beforeConnectionHook  StreamOn 时执行的握手钩子（预留给 SSL 握手等）。
//	lock                  保护 connectionMap 的并发读写。
//	ctx / cancelFunc      group 生命周期，组关闭时所有 frame pump 立即返回。
//	nodeId                该 group 代表的对端 NodeId（即设备1）。
type StreamGroup struct {
	relayStream           network.Stream
	relayFrame            FrameRelayEndpoint
	relayFramePumpStarted bool
	connectionMap         map[string]*connectionResource
	frameRoutes           *frameRouteRegistry
	beforeConnectionHook  BeforeStreamOnHook
	lock                  sync.Mutex
	cancelFunc            context.CancelFunc
	ctx                   context.Context
	nodeId                string
}

type connectionResource struct {
	stream             network.Stream
	frame              FrameRelayEndpoint
	ctx                context.Context
	flag               context.CancelFunc
	messageLoopStarted bool
	framePumpStarted   bool
}

func (c *connectionResource) Close() {
	c.flag()
	c.stream.Close()
}

func (c *connectionResource) ListenStream(ctx context.Context) (*network.Message, error) {
	message, err := c.stream.NextMessage(ctx)
	if err != nil {
		return nil, err
	}
	return message, nil
}

func defaultHookfunc(ClientStream, ServerStream network.Stream, FirstMessage *network.Message) error {
	return nil
}

// BeforeStreamOnHook 预留给SSL套件
type BeforeStreamOnHook func(ClientStream, ServerStream network.Stream, FirstMessage *network.Message) error

// frameRouteEntry 描述一条从源 leg 到目标 leg 的路由：
//
//	dest   目标 leg 的 FrameRelayEndpoint，用于把帧写出去。
//	dstID  在目标 leg 上为这一条逻辑消息预分配的新 MessageId。
//	       同一条消息的所有后续帧都复用此 dstID，确保目标侧能正确重组。
type frameRouteEntry struct {
	dest  FrameRelayEndpoint
	dstID uint64
}

// clientRouteKey 是 client 侧路由表的复合 key。
// 之所以要带 connectionID：同一个 StreamGroup 下挂着多个 client leg，
// 每个 client 的 MessageId 都从小数开始，单看 MessageId 会互相撞车，
// 必须用「哪个 client + 它的 MessageId」才能唯一定位一条路由。
type clientRouteKey struct {
	connectionID string
	messageID    uint64
}

// frameRouteRegistry 是「一个 StreamGroup 内、relay 与所有 client leg 之间」的双向路由表。
//
// pumpRelayToClients（relay->client）与 pumpClientToRelay（client->relay）共享同一份 registry，
// 这样一个方向建立的映射，反方向的 ACK 帧能复用，不会被当成新消息另起炉灶：
//
//	relaySide   key = relay leg 上的 MessageId        -> 转发到某个 client leg 的 entry
//	clientSide  key = {client connectionID, MessageId} -> 转发到 relay leg 的 entry
//
// 举例（client 发数据、relayServer 回 ACK）：
//   - client->relay：在 clientSide 记 {connID, srcMsgId}->relay(dstID)，
//     同时在 relaySide 记 dstID->client(srcMsgId) 作为反向回程。
//   - relayServer 的 ACK 经 relay leg 进来时，pumpRelayToClients 用 relaySide[ackMsgId]
//     就能直接查到「该回哪个 client、用哪个原始 MessageId」。
type frameRouteRegistry struct {
	mu         sync.Mutex
	relaySide  map[uint64]*frameRouteEntry
	clientSide map[clientRouteKey]*frameRouteEntry
}

func newFrameRouteRegistry() *frameRouteRegistry {
	return &frameRouteRegistry{
		relaySide:  make(map[uint64]*frameRouteEntry),
		clientSide: make(map[clientRouteKey]*frameRouteEntry),
	}
}

func (r *frameRouteRegistry) relayGet(messageID uint64) *frameRouteEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.relaySide[messageID]
}

func (r *frameRouteRegistry) relaySet(messageID uint64, entry *frameRouteEntry) {
	r.mu.Lock()
	r.relaySide[messageID] = entry
	r.mu.Unlock()
}

func (r *frameRouteRegistry) clientGet(connectionID string, messageID uint64) *frameRouteEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clientSide[clientRouteKey{connectionID: connectionID, messageID: messageID}]
}

func (r *frameRouteRegistry) clientSet(connectionID string, messageID uint64, entry *frameRouteEntry) {
	r.mu.Lock()
	r.clientSide[clientRouteKey{connectionID: connectionID, messageID: messageID}] = entry
	r.mu.Unlock()
}

// newFrameRouteEntry 在第一次见到某个新 srcMessageId 时调用。
// 立即在目标 leg 上 AllocMessageId，使整条消息后续所有帧都映射到这个新 ID。
func newFrameRouteEntry(dest FrameRelayEndpoint) *frameRouteEntry {
	return &frameRouteEntry{dest: dest, dstID: dest.AllocMessageId()}
}

// parseFrameHeader 仅在 frame 是某条消息的首帧（SeqId == 0）时尝试解析其 Message Header。
//
// 返回 (Header, true) 表示这是一条业务首帧，relay 可以基于 Header.ConnectionId 决定路由；
// 返回 (nil, false) 的几种情况：
//   - frame == nil
//   - SeqId != 0：非首帧，relay 应该按已有映射跟随转发，无需再解析
//   - Payload 长度不足以容纳 Header
//   - Header 解析失败
//   - Header.RouteName == KeepAliveRoute：心跳包，不进入 relay 数据面
func parseFrameHeader(f *network.Frame) (*network.Header, bool) {
	if f == nil || f.SeqId != 0 || len(f.Payload) < network.HeaderLength {
		return nil, false
	}
	h, err := network.ParseHeader(f.Payload[:network.HeaderLength])
	if err != nil {
		return nil, false
	}
	if h.RouteName == KeepAliveRoute {
		return nil, false
	}
	return h, true
}

// pumpRelayToClients 是 relay->client 方向的 frame pump。
//
// 帧来源：relay leg（设备1 那侧）。帧去向：根据业务 ConnectionId 找到对应 client leg。
// 在 pure forwarder 模式下，这里搬运的既有数据帧，也有「设备1 回给 client 的 ACK 帧」。
//
// 路由复用 routes（与 pumpClientToRelay 共享）：
//   - relayGet(f.MessageId) 命中：说明这条 relay 侧 MessageId 已经有目标 client leg
//     （要么是设备1 主动发的数据流首帧建立的，要么是 client->relay 方向登记的反向回程）。
//   - 未命中：必须是数据流首帧（SeqId==0 且能解析出 Header），用 Header.ConnectionId
//     找到目标 client leg，分配 dstID 建正向映射，并登记反向回程（client 的 ACK 用得上）。
//
// 找不到目标 client（还没连上 / 已断开）就丢弃该帧。写失败则退出 pump。
func pumpRelayToClients(ctx context.Context, relay FrameRelayEndpoint, lookup func(string) FrameRelayEndpoint, routes *frameRouteRegistry) {
	for {
		f, err := relay.NextFrame(ctx)
		if err != nil {
			return
		}

		entry := routes.relayGet(f.MessageId)
		if entry == nil {
			// relay 侧第一次见到这个 MessageId：只接受能解析出业务 Header 的数据首帧。
			h, ok := parseFrameHeader(f)
			if !ok {
				continue
			}
			dst := lookup(h.ConnectionId)
			if dst == nil {
				continue
			}
			entry = newFrameRouteEntry(dst)
			// 正向：relay 的这个 MessageId -> 目标 client(dstID)。
			routes.relaySet(f.MessageId, entry)
			// 反向回程：client 用 dstID 回的 ACK -> 写回 relay leg 的原始 MessageId。
			routes.clientSet(dst.ConnectionId(), entry.dstID, &frameRouteEntry{dest: relay, dstID: f.MessageId})
		}

		out := *f
		out.MessageId = entry.dstID
		if err := entry.dest.HandleFrame(ctx, &out); err != nil {
			return
		}
	}
}

// pumpClientToRelay 是 client->relay 方向的 frame pump。
//
// 帧来源：某条 client leg（设备2）。帧去向：固定为本 group 的 relay leg（设备1）。
// pure forwarder 模式下，这里既转发 client 发的数据帧，也转发「client 回给设备1 的 ACK 帧」。
//
// 路由复用 routes（与 pumpRelayToClients 共享，用 connectionID 区分不同 client）：
//   - clientGet({connID, f.MessageId}) 命中：复用已有映射（含 relay->client 方向登记的反向回程）。
//   - 未命中：必须是数据首帧（SeqId==0），在 relay leg 上分配 dstID 建正向映射，
//     并登记反向回程（relayServer 的 ACK 用 dstID 回来时，能查回这个 client）。
//
// 写失败则退出 pump。
func pumpClientToRelay(ctx context.Context, client FrameRelayEndpoint, relay FrameRelayEndpoint, routes *frameRouteRegistry) {
	for {
		f, err := client.NextFrame(ctx)
		if err != nil {
			return
		}

		entry := routes.clientGet(client.ConnectionId(), f.MessageId)
		if entry == nil {
			if f.SeqId != 0 {
				continue
			}
			entry = newFrameRouteEntry(relay)
			// 正向：client 的这个 MessageId -> relay leg(dstID)。
			routes.clientSet(client.ConnectionId(), f.MessageId, entry)
			// 反向回程：relay 用 dstID 回的 ACK -> 写回该 client 的原始 MessageId。
			routes.relaySet(entry.dstID, &frameRouteEntry{dest: client, dstID: f.MessageId})
		}

		out := *f
		out.MessageId = entry.dstID
		if err := entry.dest.HandleFrame(ctx, &out); err != nil {
			return
		}
	}
}

func (s *StreamGroup) AttachRelayStream(stream network.Stream) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	dual := ensureDualStream(s.relayStream)
	s.relayStream = dual
	if err := dual.AttachStream(stream); err != nil {
		return err
	}
	if s.relayFrame == nil {
		s.relayFrame = dual.EnableFrameRelay()
	}
	return nil
}

// StreamOn 把新接入的 client leg 挂到指定 ConnectionId 对应的逻辑流上。
// 返回值 forwardFirstMessage 表示这是不是该逻辑连接的第一条底层 leg；
// 只有第一条 leg 的首包需要继续转发给 relay 端，后续 leg 只做挂载，不重复转发首包。
func (s *StreamGroup) StreamOn(stream network.Stream, FirstMessage *network.Message) (forwardFirstMessage bool, err error) {
	connectionId := FirstMessage.Header.ConnectionId
	if len(connectionId) == 0 {
		return false, errors.New("connectionId is empty")
	}

	s.lock.Lock()
	resource := s.connectionMap[connectionId]
	if resource != nil {
		dual := ensureDualStream(resource.stream)
		resource.stream = dual
		s.lock.Unlock()
		if err := dual.AttachStream(stream); err != nil {
			return false, err
		}
		if resource.frame == nil {
			resource.frame = dual.EnableFrameRelay()
		}
		return false, nil
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	logicalStream := ensureDualStream(stream)
	resource = &connectionResource{
		stream: logicalStream,
		ctx:    ctx,
		flag:   cancelFunc,
		frame:  logicalStream.EnableFrameRelay(),
	}
	s.connectionMap[connectionId] = resource
	s.lock.Unlock()

	err = s.beforeConnectionHook(logicalStream, s.relayStream, FirstMessage)
	if err != nil {
		s.CloseTargetConnection(connectionId)
		return true, err
	}

	if resource.frame != nil && s.relayFrame != nil {
		s.startFramePump(connectionId, resource)
	} else {
		s.startConnectionLoop(connectionId, resource)
	}
	return true, nil
}

func (s *StreamGroup) startFramePump(connectionId string, resource *connectionResource) {
	s.lock.Lock()
	if resource.framePumpStarted {
		s.lock.Unlock()
		return
	}
	resource.framePumpStarted = true
	ctx := resource.ctx
	frame := resource.frame
	relayFrame := s.relayFrame
	s.lock.Unlock()
	if frame == nil || relayFrame == nil {
		return
	}
	go pumpClientToRelay(ctx, frame, relayFrame, s.frameRoutes)
}

func (s *StreamGroup) startConnectionLoop(connectionId string, resource *connectionResource) {
	s.lock.Lock()
	if resource.messageLoopStarted {
		s.lock.Unlock()
		return
	}
	resource.messageLoopStarted = true
	ctx := resource.ctx
	s.lock.Unlock()

	go func(c *connectionResource, connectionId string, ctx context.Context) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("%v", err)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				message, err := c.ListenStream(ctx)
				if err != nil {
					s.CloseTargetConnection(connectionId)
					return
				}
				if message.Header.RouteName == KeepAliveRoute {
					continue
				}
				if err := s.relayStream.SendMessage(ctx, message); err != nil {
					s.CloseTargetConnection(connectionId)
					return
				}
			}
		}
	}(resource, connectionId, ctx)
}

func (s *StreamGroup) StartListen() {
	if s.relayFrame != nil {
		pumpRelayToClients(s.ctx, s.relayFrame, func(connID string) FrameRelayEndpoint {
			s.lock.Lock()
			defer s.lock.Unlock()
			resource := s.connectionMap[connID]
			if resource == nil {
				return nil
			}
			return resource.frame
		}, s.frameRoutes)
		return
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			message, err := s.relayStream.NextMessage(s.ctx)
			if err != nil {
				return
			}
			if message.Header.RouteName == KeepAliveRoute {
				continue
			}
			s.lock.Lock()
			resource := s.connectionMap[message.Header.ConnectionId]
			s.lock.Unlock()
			if resource == nil {
				continue
			}
			if err := resource.stream.SendMessage(s.ctx, message); err != nil {
				s.CloseTargetConnection(message.Header.ConnectionId)
			}
		}
	}
}

func NewStreamGroup(relayStream network.Stream, beforeConnectionHook BeforeStreamOnHook) *StreamGroup {
	ctx, cancelFunc := context.WithCancel(context.Background())
	logicalRelayStream := ensureDualStream(relayStream)
	return &StreamGroup{
		relayStream:          logicalRelayStream,
		relayFrame:           logicalRelayStream.EnableFrameRelay(),
		connectionMap:        make(map[string]*connectionResource),
		frameRoutes:          newFrameRouteRegistry(),
		beforeConnectionHook: beforeConnectionHook,
		ctx:                  ctx,
		cancelFunc:           cancelFunc,
		nodeId:               logicalRelayStream.NodeId(),
	}
}

// CloseTargetConnection 强制关闭挂在本 group 上的某条 client leg。
//
// 参数：
//
//	connectionId  目标 client leg 的业务连接 ID（StreamOn 时注册的那个）。
//
// 行为：从 connectionMap 中删除该条目，然后调用 connectionResource.Close()
// （触发 ctx 取消，关闭底层 stream，所有 pump / message loop 立即退出）。
// 若 connectionId 不存在或已被关闭，返回相应错误。
func (s *StreamGroup) CloseTargetConnection(connectionId string) error {

	s.lock.Lock()
	defer s.lock.Unlock()
	c := s.connectionMap[connectionId]
	if c == nil {
		return errors.New("connectionId not exist or it's already closed")
	}
	delete(s.connectionMap, connectionId)
	c.Close()
	return nil
}
