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
	forwardHookConfig     *ForwardHookConfig // 转发 hook 配置（可选）
	lock                  sync.Mutex
	cancelFunc            context.CancelFunc
	ctx                   context.Context
	nodeId                string
}

// connectionResource 表示「挂在 group 上的某条业务连接」全部相关资源。
//
//	stream             该 client leg 的 network.Stream（通常是 *DualStream）。
//	frame              对应的 FrameRelayEndpoint，frame pump 走它。
//	ctx / flag         本 connection 的生命周期 ctx 与取消函数。
//	messageLoopStarted 是否已经启动 message loop（fallback 路径）。
//	framePumpStarted   是否已经启动 frame pump（默认路径）。
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

// NewStreamGroup 用一条已建立的 relay 注册流构造 StreamGroup。
// 内部把 relayStream 升级成 *DualStream 并启用 frame relay 适配器，
// 后续所有 client leg 都会挂到这个 group 上、共享同一份 frameRoutes。
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

// SetForwardHook 设置转发 hook 配置。
// 必须在 frame pump 启动前调用（即在任何 StreamOn 调用之前）。
func (s *StreamGroup) SetForwardHook(config *ForwardHookConfig) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.forwardHookConfig = config
}

// AttachRelayStream 把另一条同 nodeId 的 relay leg 挂到本 group 的 relayStream 上。
// 用于 relay 端在 KCP / TCP 双 leg 场景下补齐第二条 leg。
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

// startFramePump 是默认数据面：client leg -> relay leg 的帧搬运。
// frame 与 relayFrame 都就绪时启动一次，避免重复 goroutine。
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
	hookConfig := s.forwardHookConfig
	s.lock.Unlock()
	if frame == nil || relayFrame == nil {
		return
	}
	go pumpClientToRelay(ctx, frame, relayFrame, s.frameRoutes, hookConfig)
}

// startConnectionLoop 是 fallback 路径：当 frame relay 不可用时用 Message 语义中转。
// 只在没有任何 frame 适配器时才会进来。
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

// StartListen 是 relay leg 一侧的 frame pump 入口。
//   - 优先：用 relayFrame + 共享 frameRoutes 跑 frame 转发，整条 group 共享一份路由表；
//   - fallback：relayFrame 为空时才退化到 Message 转发循环。
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
		}, s.frameRoutes, s.forwardHookConfig)
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
