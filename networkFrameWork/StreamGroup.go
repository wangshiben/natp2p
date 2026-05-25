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
	// 负责处理node的连接等信息
	relayStream          network.Stream
	relayFrame           FrameRelayEndpoint
	connectionMap        map[string]*connectionResource // 此Stream目前保持会话的所有clientStream
	beforeConnectionHook BeforeStreamOnHook
	lock                 sync.Mutex
	cancelFunc           context.CancelFunc
	ctx                  context.Context
	nodeId               string
}

// connectionResource 表示挂在某个 StreamGroup 上的"一条 client leg"。
//
//	stream  client 端的应用层 Stream（用于控制面消息，如握手首包、keepalive）。
//	frame   仅在 stream 是 *TcpStream 时存在，是 relay 数据面 frame pump 的端点。
//	flag    取消该 leg 上后台 goroutine（消息循环 / frame pump）的钩子。
type connectionResource struct {
	stream network.Stream
	frame  FrameRelayEndpoint
	flag   context.CancelFunc
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

// pumpRelayToClients 是 relay→client 方向的 frame pump。
//
// 场景：公网 relay 收到了来自"被中继节点"（设备1）的一帧，需要根据帧内业务头里的
// ConnectionId 决定要发给哪一个挂在本 group 上的 client leg（设备2 / 设备3 / ...）。
//
// 参数：
//
//	ctx     pump 生命周期；group 关闭或 relay leg 被关闭时取消，循环立即返回。
//	relay   relay leg 的 FrameRelayEndpoint（由 *TcpStream 适配而来），即帧的来源。
//	lookup  动态查询函数：传入业务 ConnectionId，返回对应 client leg 的 FrameRelayEndpoint；
//	        若未找到（client 还没连上来 / 已断开），返回 nil 表示"丢弃这一帧"。
//	        必须由调用方负责加锁保护 connectionMap 的并发访问。
//
// 行为：
//  1. 死循环 NextFrame，直到 ctx 取消或底层流出错。
//  2. 维护 srcMessageId -> frameRouteEntry 的映射 entries：
//     - 第一次见到某个 srcMessageId 时，要求当前帧是首帧（SeqId == 0）且能解析出 Header；
//     用 Header.ConnectionId 经 lookup 找到目标 leg；目标 leg 不存在则丢弃整帧。
//     - 找到后通过 newFrameRouteEntry 在目标 leg 上 AllocMessageId，建立映射。
//  3. 复制一份 frame，把 MessageId 改写为 entry.dstID，调用目标 leg 的 HandleFrame。
//  4. 若目标 leg 写入失败，删掉该映射并退出 pump（通常意味着目标连接已断）。
//
// mu 保护 entries map 的并发访问；当前实现是单 goroutine 循环，但写入失败分支会
// 在持锁后立即退出，留出锁是为了未来可能的并发扩展。
func pumpRelayToClients(ctx context.Context, relay FrameRelayEndpoint, lookup func(string) FrameRelayEndpoint) {
	var mu sync.Mutex
	entries := make(map[uint64]*frameRouteEntry)

	for {
		f, err := relay.NextFrame(ctx)
		if err != nil {
			return
		}

		mu.Lock()
		entry, ok := entries[f.MessageId]
		if !ok {
			h, ok := parseFrameHeader(f)
			if !ok {
				mu.Unlock()
				continue
			}
			dst := lookup(h.ConnectionId)
			if dst == nil {
				mu.Unlock()
				continue
			}
			entry = newFrameRouteEntry(dst)
			entries[f.MessageId] = entry
		}
		mu.Unlock()

		out := *f
		out.MessageId = entry.dstID
		if err := entry.dest.HandleFrame(ctx, &out); err != nil {
			mu.Lock()
			delete(entries, f.MessageId)
			mu.Unlock()
			return
		}
	}
}

// pumpClientToRelay 是 client→relay 方向的 frame pump。
//
// 场景：公网 relay 收到了某个 client leg（设备2）发来的一帧，要转发给该 group
// 对应的"被中继节点"（设备1）的 relay leg。
//
// 与 pumpRelayToClients 的差别：
//   - 目标是固定的（就是 group.relayFrame），不需要 lookup。
//   - 不需要解析业务 Header；只要见到新的 srcMessageId 且当前帧是首帧（SeqId == 0），
//     就在 relay leg 上 AllocMessageId 建立映射，后续帧跟随。
//   - 非首帧但又没建立映射的，直接丢弃（属于不完整 / 乱序进来的尾帧）。
//
// 参数：
//
//	ctx     pump 生命周期，client leg 关闭或 group ctx 取消时退出。
//	client  client leg 的 FrameRelayEndpoint（帧来源）。
//	relay   relay leg 的 FrameRelayEndpoint（帧去向，固定）。
func pumpClientToRelay(ctx context.Context, client FrameRelayEndpoint, relay FrameRelayEndpoint) {
	var mu sync.Mutex
	entries := make(map[uint64]*frameRouteEntry)

	for {
		f, err := client.NextFrame(ctx)
		if err != nil {
			return
		}

		mu.Lock()
		entry, ok := entries[f.MessageId]
		if !ok {
			if f.SeqId != 0 {
				mu.Unlock()
				continue
			}
			entry = newFrameRouteEntry(relay)
			entries[f.MessageId] = entry
		}
		mu.Unlock()

		out := *f
		out.MessageId = entry.dstID
		if err := entry.dest.HandleFrame(ctx, &out); err != nil {
			mu.Lock()
			delete(entries, f.MessageId)
			mu.Unlock()
			return
		}
	}
}

// StreamOn 当有一个新 client Stream 要挂到本 group 上时调用。
//
// 调用方：通常是 TransportCover.ListenTCPConnection — 它读到一个非空 ConnectionId 的
// 首条消息（来自设备2）后，找到对应 group（设备1 的 group），把这条 client 流挂进来。
//
// 参数：
//
//	stream         新接入的 client leg；其底层若是 *TcpStream，会被包装成 FrameRelayEndpoint。
//	FirstMessage   client 发来的首条业务消息；必须携带 ConnectionId（一般 Payload 为空，
//	               用作业务连接握手），ConnectionId 为空则直接返回错误。
//
// 行为：
//  1. 用 FirstMessage.Header.ConnectionId 作为 key，把 client leg 注册到 connectionMap。
//  2. 调用 beforeConnectionHook（预留给 SSL/TLS 等握手）。失败则关闭这条 client leg，
//     但首条消息的转发仍按原逻辑执行（保持兼容）。
//  3. 如果 stream 与 relayStream 都是 *TcpStream，构造 client leg 的 FrameRelayEndpoint，
//     启动 client→relay 方向的 frame pump（pumpClientToRelay），后续数据面全部走帧桥接。
//  4. 否则降级回旧的 message-loop 路径：起一个 goroutine 循环 NextMessage，过滤心跳，
//     把消息整包转发到 relayStream。出错时清理本 leg。
func (s *StreamGroup) StreamOn(stream network.Stream, FirstMessage *network.Message) error {
	s.lock.Lock()
	connectionId := FirstMessage.Header.ConnectionId
	ctx, cancelFunc := context.WithCancel(context.Background())
	c := &connectionResource{
		stream: stream,
		flag:   cancelFunc,
	}
	if len(connectionId) == 0 {
		s.lock.Unlock()
		return errors.New("connectionId is empty")
	}
	s.connectionMap[connectionId] = c
	s.lock.Unlock()

	err := s.beforeConnectionHook(stream, s.relayStream, FirstMessage)
	if err != nil {
		s.CloseTargetConnection(connectionId)
	}

	if t, ok := stream.(*TcpStream); ok {
		c.frame = NewTcpFrameAdapter(t)
	}

	if c.frame != nil && s.relayFrame != nil {
		go pumpClientToRelay(ctx, c.frame, s.relayFrame)
		return err
	}

	go func(c *connectionResource, connectionId string, ctx context.Context) {
		defer func() {
			err := recover()
			if err != nil {
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
				err = s.relayStream.SendMessage(ctx, message)
				if err != nil {
					s.CloseTargetConnection(connectionId)
				}
			}
		}
	}(c, FirstMessage.Header.ConnectionId, ctx)
	return err
}

// StartListen 启动该 group 的 relay 侧消费循环。
//
// 两种模式（互斥）：
//
//  1. frame 模式（relayFrame != nil，即 relay 底层是 *TcpStream）：
//     启动 pumpRelayToClients，把来自设备1 的所有原始帧按 ConnectionId 分发到对应 client leg。
//     lookup 闭包在持锁状态下从 connectionMap 取出对应 client 的 frame 适配器；
//     未找到则返回 nil，pump 会丢弃该帧。
//
//  2. message 模式（兜底，例如未来 KCP/UDP 不实现 FrameRelayEndpoint 时）：
//     循环 NextMessage，过滤心跳，按 ConnectionId 找到 client 流后整条 SendMessage 转发。
//     这条路径在帧桥接生效后基本不会被走到，仅作兼容。
//
// 调用方一般是 RelayStarter 在 group 注册成功后立即起一个 goroutine 跑这个函数。
func (s *StreamGroup) StartListen() {
	if s.relayFrame != nil {
		pumpRelayToClients(s.ctx, s.relayFrame, func(connID string) FrameRelayEndpoint {
			s.lock.Lock()
			defer s.lock.Unlock()
			res := s.connectionMap[connID]
			if res == nil {
				return nil
			}
			return res.frame
		})
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
			resource.stream.SendMessage(s.ctx, message)
		}
	}
}

// NewStreamGroup 构造一个 StreamGroup。
//
// 参数：
//
//	relayStream           已经握手成功的"被中继节点"那条注册流（设备1 ↔ 公网 relay）。
//	                      若其底层是 *TcpStream，会立即包装成 FrameRelayEndpoint，
//	                      启用 frame 模式数据面；否则降级为 message-loop 模式。
//	beforeConnectionHook  每个 client leg 挂上来时的握手钩子（预留给 SSL 套件）。
//	                      传 nil 是非法的，调用方应使用 defaultHookfunc 占位。
func NewStreamGroup(relayStream network.Stream, beforeConnectionHook BeforeStreamOnHook) *StreamGroup {
	ctx, cancelFunc := context.WithCancel(context.Background())
	s := &StreamGroup{
		relayStream:          relayStream,
		connectionMap:        make(map[string]*connectionResource),
		beforeConnectionHook: beforeConnectionHook,
		ctx:                  ctx,
		cancelFunc:           cancelFunc,
	}
	if rt, ok := relayStream.(*TcpStream); ok {
		s.relayFrame = NewTcpFrameAdapter(rt)
	}
	return s
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
