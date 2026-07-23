package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
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
	registrationSessionID string
	knownConnectionIDs    map[string]struct{}
	closedConnectionIDs   map[string]struct{}
	dormantConnectionIDs  []string
	dormantFailedIDs      []string
	closeOnce             sync.Once
}

var ErrBusinessConnectionLimit = errors.New("stream group business connection limit reached")

var ErrBusinessConnectionInitializationFailed = errors.New("business connection initialization failed")

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
	setupReady         chan struct{}
	setupErr           error
	firstReady         chan struct{}
	firstReadyOnce     sync.Once
	firstMessage       *network.Message
	firstForward       bool
	resume             bool
	firstErr           error
	closeOnce          sync.Once
}

func (c *connectionResource) Close() {
	c.closeOnce.Do(func() {
		c.flag()
		_ = c.stream.Close()
	})
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
	return newStreamGroupWithRelaySlot(relayStream, beforeConnectionHook, false)
}

func newStreamGroupWithRelaySlot(relayStream network.Stream, beforeConnectionHook BeforeStreamOnHook, extra bool) *StreamGroup {
	return newStreamGroupWithRelaySession(relayStream, beforeConnectionHook, extra, "")
}

func newStreamGroupWithRelaySession(relayStream network.Stream, beforeConnectionHook BeforeStreamOnHook, extra bool, sessionID string) *StreamGroup {
	ctx, cancelFunc := context.WithCancel(context.Background())
	logicalRelayStream := relaySlotDualStream(relayStream, extra)
	return &StreamGroup{
		relayStream:           logicalRelayStream,
		relayFrame:            logicalRelayStream.EnableFrameRelay(),
		connectionMap:         make(map[string]*connectionResource),
		frameRoutes:           newFrameRouteRegistry(),
		beforeConnectionHook:  beforeConnectionHook,
		ctx:                   ctx,
		cancelFunc:            cancelFunc,
		nodeId:                logicalRelayStream.NodeId(),
		registrationSessionID: sessionID,
		knownConnectionIDs:    make(map[string]struct{}),
		closedConnectionIDs:   make(map[string]struct{}),
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
// AttachRelayStreamCoexist 同 AttachRelayStream，但 coexist=true 时使用稳定备用 slot
// （用于 client 双 TCP failover 的额外 leg，首帧带 legExtraMarker）。
func (s *StreamGroup) AttachRelayStreamCoexist(stream network.Stream, coexist bool) error {
	return s.attachRelayStreamCoexist(stream, coexist, false)
}

func (s *StreamGroup) attachRelayStreamCoexist(stream network.Stream, coexist, resume bool) error {
	s.lock.Lock()
	if s.isClosed() {
		s.lock.Unlock()
		return errors.New("stream group closed")
	}
	dual := ensureDualStream(s.relayStream)
	s.relayStream = dual
	needsRelayFrame := s.relayFrame == nil
	s.lock.Unlock()

	if err := dual.attachStreamCoexist(stream, coexist, resume); err != nil {
		return err
	}
	// 双 TCP 的 normal/extra 可能乱序到达。每次 TCP 挂载后都检查 exact
	// tcp + tcp#2 slot，只有两者齐备才能确认本次 KCP 握手已降级；否则保留
	// 仍可能有效的 KCP，避免 extra 先到时过早切断正常注册。
	if detectStreamTransport(stream) == streamTransportTCP {
		if retired := dual.retireStaleKCPWhenDualTCPReady(); retired > 0 {
			logx.Infof("[relay] 双 TCP 注册确认 KCP 不可用, 淘汰 %d 条旧 KCP leg: nodeId=%.16s",
				retired, dual.NodeId())
		}
	}
	if needsRelayFrame {
		frame := dual.EnableFrameRelay()
		s.lock.Lock()
		if !s.isClosed() && s.relayFrame == nil {
			s.relayFrame = frame
		}
		s.lock.Unlock()
	}
	return nil
}

func (s *StreamGroup) AttachRelayStream(stream network.Stream) error {
	return s.AttachRelayStreamCoexist(stream, false)
}

// StreamOn 把新接入的 client leg 挂到指定 ConnectionId 对应的逻辑流上。
// 返回值 forwardFirstMessage 表示首包是否需要继续转发给 relay 端：只有 fresh
// non-resume ConnectionId 才转发。Resume 只重建 Relay 路由并挂载物理 leg；它携带的
// payload 是建连时的公钥模板，不能再次送入已经启用 E2E record 的 Server 会话。
func (s *StreamGroup) StreamOn(stream network.Stream, FirstMessage *network.Message) (forwardFirstMessage bool, err error) {
	connectionId := FirstMessage.Header.ConnectionId
	if len(connectionId) == 0 {
		return false, errors.New("connectionId is empty")
	}

	s.lock.Lock()
	if s.isClosed() {
		s.lock.Unlock()
		return false, errors.New("stream group closed")
	}
	if _, initializationFailed := s.closedConnectionIDs[connectionId]; initializationFailed {
		if isResumeLegMarked(FirstMessage) {
			s.lock.Unlock()
			return false, fmt.Errorf("%w: connectionId=%s", ErrBusinessConnectionInitializationFailed, connectionId)
		}
		delete(s.closedConnectionIDs, connectionId)
	}
	resource := s.connectionMap[connectionId]
	if resource != nil {
		dual := ensureDualStream(resource.stream)
		resource.stream = dual
		s.lock.Unlock()
		if err := dual.attachStreamCoexist(stream, isExtraLegMarked(FirstMessage), isResumeLegMarked(FirstMessage)); err != nil {
			return false, err
		}
		if resource.frame == nil {
			resource.frame = dual.EnableFrameRelay()
		}
		return false, nil
	}
	if len(s.connectionMap) >= retiredBusinessConnectionLimit {
		s.lock.Unlock()
		return false, ErrBusinessConnectionLimit
	}
	resume := isResumeLegMarked(FirstMessage)
	forwardFirstMessage = !resume
	if s.knownConnectionIDs == nil {
		s.knownConnectionIDs = make(map[string]struct{})
	}
	addBoundedKnownConnectionID(s.knownConnectionIDs, s.connectionMap, connectionId)

	ctx, cancelFunc := context.WithCancel(s.ctx)
	logicalStream := relaySlotDualStream(stream, isExtraLegMarked(FirstMessage))
	resource = &connectionResource{
		stream:       logicalStream,
		ctx:          ctx,
		flag:         cancelFunc,
		frame:        logicalStream.EnableFrameRelay(),
		setupReady:   make(chan struct{}),
		firstReady:   make(chan struct{}),
		firstMessage: cloneMessage(FirstMessage),
		firstForward: forwardFirstMessage,
		resume:       resume,
	}
	s.connectionMap[connectionId] = resource
	s.lock.Unlock()

	err = s.beforeConnectionHook(logicalStream, s.relayStream, FirstMessage)
	if err != nil {
		resource.setupErr = err
		close(resource.setupReady)
		s.failBusinessConnectionInitialization(connectionId, resource)
		return true, err
	}

	if resource.frame != nil && s.relayFrame != nil {
		s.startFramePump(connectionId, resource)
	} else {
		s.startConnectionLoop(connectionId, resource)
	}
	close(resource.setupReady)
	return forwardFirstMessage, nil
}

func (s *StreamGroup) AwaitFirstMessage(connectionID string) error {
	s.lock.Lock()
	resource := s.connectionMap[connectionID]
	relayStream := s.relayStream
	s.lock.Unlock()
	if resource == nil {
		s.failBusinessConnectionInitialization(connectionID, nil)
		return errors.New("business connection resource not found")
	}
	select {
	case <-resource.ctx.Done():
		s.failBusinessConnectionInitialization(connectionID, resource)
		return resource.ctx.Err()
	case <-resource.setupReady:
	}
	if resource.setupErr != nil {
		s.failBusinessConnectionInitialization(connectionID, resource)
		return resource.setupErr
	}
	resource.firstReadyOnce.Do(func() {
		defer close(resource.firstReady)
		if !resource.firstForward {
			resource.firstMessage = nil
			return
		}
		sender, ok := relayStream.(interface {
			SendMessageAwaitAck(context.Context, *network.Message) error
		})
		if !ok {
			resource.firstErr = errors.New("relay stream does not support acknowledged first-message forwarding")
			s.failBusinessConnectionInitialization(connectionID, resource)
			return
		}
		ctx, cancel := context.WithTimeout(resource.ctx, dialHandshakeTimeout)
		defer cancel()
		resource.firstErr = sender.SendMessageAwaitAck(ctx, resource.firstMessage)
		resource.firstMessage = nil
		if resource.firstErr != nil {
			s.failBusinessConnectionInitialization(connectionID, resource)
		}
	})
	<-resource.firstReady
	return resource.firstErr
}

func relaySlotDualStream(stream network.Stream, extra bool) *DualStream {
	if !extra || stream == nil || detectStreamTransport(stream) == streamTransportUnknown {
		return ensureDualStream(stream)
	}
	dual := newDualStream(stream.NodeId(), stream.ConnectionId())
	if err := dual.AttachStreamCoexist(stream, true); err == nil {
		return dual
	}
	dual.cancel()
	return ensureDualStream(stream)
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
	go func() {
		pumpClientToRelay(ctx, frame, relayFrame, s.frameRoutes, hookConfig, s.nodeId)
		s.closeTargetConnectionIfMatch(connectionId, resource)
	}()
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
					s.closeTargetConnectionIfMatch(connectionId, c)
					return
				}
				if message.Header.RouteName == KeepAliveRoute {
					continue
				}
				if err := s.relayStream.SendMessage(ctx, message); err != nil {
					s.closeTargetConnectionIfMatch(connectionId, c)
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
	defer s.Close()
	if s.relayFrame != nil {
		pumpRelayToClients(s.ctx, s.relayFrame, func(connID string) FrameRelayEndpoint {
			s.lock.Lock()
			defer s.lock.Unlock()
			resource := s.connectionMap[connID]
			if resource == nil {
				return nil
			}
			return resource.frame
		}, s.frameRoutes, s.forwardHookConfig, s.nodeId, func(connID string, endpoint FrameRelayEndpoint) {
			s.closeTargetConnectionByFrame(connID, endpoint)
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
			if err := resource.stream.SendMessage(s.ctx, message); err != nil {
				s.CloseTargetConnection(message.Header.ConnectionId)
			}
		}
	}
}

func (s *StreamGroup) latestRelayReceiveTime() time.Time {
	s.lock.Lock()
	relayStream := s.relayStream
	s.lock.Unlock()
	activity, ok := relayStream.(interface{ LatestReceiveTime() time.Time })
	if !ok {
		return time.Time{}
	}
	return activity.LatestReceiveTime()
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
	return s.closeTargetConnection(connectionId, nil, nil, true)
}

func (s *StreamGroup) closeTargetConnectionIfMatch(connectionId string, expected *connectionResource) {
	_ = s.closeTargetConnection(connectionId, expected, nil, false)
}

func (s *StreamGroup) closeTargetConnectionByFrame(connectionId string, expected FrameRelayEndpoint) {
	_ = s.closeTargetConnection(connectionId, nil, expected, false)
}

func (s *StreamGroup) failBusinessConnectionInitialization(connectionId string, expected *connectionResource) {
	s.lock.Lock()
	current := s.connectionMap[connectionId]
	if current != nil && current != expected {
		s.lock.Unlock()
		return
	}
	failedResource := current
	if failedResource == nil {
		failedResource = expected
	}
	// 只有真正的新建连接初始化失败才封存 ConnectionId。Resume 是已建立逻辑会话的
	// 临时物理恢复尝试；把一次迁移窗口失败写成 tombstone 会永久阻断后续合法重试。
	if failedResource != nil && !failedResource.resume {
		if s.closedConnectionIDs == nil {
			s.closedConnectionIDs = make(map[string]struct{})
		}
		addBoundedConnectionID(s.closedConnectionIDs, connectionId)
	}
	if current != nil {
		delete(s.connectionMap, connectionId)
		s.frameRoutes.purgeConnection(connectionId)
		if s.forwardHookConfig != nil {
			s.forwardHookConfig.ensureRetransmitCache().forgetConnection(s.nodeId, connectionId)
			s.forwardHookConfig.forgetHeldConnection(s.nodeId, connectionId)
		}
	}
	s.lock.Unlock()
	if current != nil {
		current.Close()
	} else if expected != nil {
		expected.Close()
	}
}

func (s *StreamGroup) closeTargetConnection(connectionId string, expectedResource *connectionResource, expectedFrame FrameRelayEndpoint, missingIsError bool) error {
	s.lock.Lock()
	c := s.connectionMap[connectionId]
	if c == nil {
		s.lock.Unlock()
		if missingIsError {
			return errors.New("connectionId not exist or it's already closed")
		}
		return nil
	}
	if expectedResource != nil && c != expectedResource {
		s.lock.Unlock()
		return nil
	}
	if expectedFrame != nil && c.frame != expectedFrame {
		s.lock.Unlock()
		return nil
	}
	delete(s.connectionMap, connectionId)
	s.frameRoutes.purgeConnection(connectionId)
	if s.forwardHookConfig != nil {
		s.forwardHookConfig.ensureRetransmitCache().forgetConnection(s.nodeId, connectionId)
		s.forwardHookConfig.forgetHeldConnection(s.nodeId, connectionId)
	}
	s.lock.Unlock()
	c.Close()
	return nil
}

func (s *StreamGroup) isClosed() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

func (s *StreamGroup) stopAndSnapshotConnectionIDs() []string {
	s.cancelFunc()
	return s.snapshotConnectionIDs()
}

func (s *StreamGroup) snapshotConnectionIDs() []string {
	s.lock.Lock()
	if s.dormantConnectionIDs != nil {
		connectionIDs := append([]string(nil), s.dormantConnectionIDs...)
		s.lock.Unlock()
		return connectionIDs
	}
	connectionIDs := s.snapshotConnectionIDsLocked()
	s.lock.Unlock()
	return connectionIDs
}

func (s *StreamGroup) snapshotConnectionIDsLocked() []string {
	connectionIDs := make([]string, 0, min(retiredBusinessConnectionLimit,
		len(s.connectionMap)+len(s.knownConnectionIDs)+len(s.closedConnectionIDs)))
	seen := make(map[string]struct{}, cap(connectionIDs))
	appendConnectionID := func(connectionID string) {
		if connectionID == "" || len(connectionIDs) >= retiredBusinessConnectionLimit {
			return
		}
		if _, exists := seen[connectionID]; exists {
			return
		}
		seen[connectionID] = struct{}{}
		connectionIDs = append(connectionIDs, connectionID)
	}
	for connectionID := range s.connectionMap {
		appendConnectionID(connectionID)
	}
	for connectionID := range s.closedConnectionIDs {
		appendConnectionID(connectionID)
	}
	for connectionID := range s.knownConnectionIDs {
		appendConnectionID(connectionID)
	}
	return connectionIDs
}

func (s *StreamGroup) snapshotInitializationFailedConnectionIDs() []string {
	s.lock.Lock()
	if s.dormantFailedIDs != nil {
		connectionIDs := append([]string(nil), s.dormantFailedIDs...)
		s.lock.Unlock()
		return connectionIDs
	}
	connectionIDs := s.snapshotInitializationFailedConnectionIDsLocked()
	s.lock.Unlock()
	return connectionIDs
}

func (s *StreamGroup) snapshotInitializationFailedConnectionIDsLocked() []string {
	connectionIDs := make([]string, 0, len(s.closedConnectionIDs))
	for connectionID := range s.closedConnectionIDs {
		connectionIDs = append(connectionIDs, connectionID)
	}
	return connectionIDs
}

func (s *StreamGroup) inheritConnectionIDs(connectionIDs []string) {
	s.lock.Lock()
	if s.knownConnectionIDs == nil {
		s.knownConnectionIDs = make(map[string]struct{})
	}
	for _, connectionID := range connectionIDs {
		addBoundedConnectionID(s.knownConnectionIDs, connectionID)
	}
	s.lock.Unlock()
}

func (s *StreamGroup) inheritInitializationFailedConnectionIDs(connectionIDs []string) {
	s.lock.Lock()
	if s.closedConnectionIDs == nil {
		s.closedConnectionIDs = make(map[string]struct{})
	}
	for _, connectionID := range connectionIDs {
		addBoundedConnectionID(s.closedConnectionIDs, connectionID)
	}
	s.lock.Unlock()
}

func addBoundedConnectionID(connectionIDs map[string]struct{}, connectionID string) {
	if connectionID == "" {
		return
	}
	if _, exists := connectionIDs[connectionID]; exists {
		return
	}
	if len(connectionIDs) >= retiredBusinessConnectionLimit {
		for existingConnectionID := range connectionIDs {
			delete(connectionIDs, existingConnectionID)
			break
		}
	}
	connectionIDs[connectionID] = struct{}{}
}

func addBoundedKnownConnectionID(connectionIDs map[string]struct{}, activeConnections map[string]*connectionResource, connectionID string) {
	if connectionID == "" {
		return
	}
	if _, exists := connectionIDs[connectionID]; exists {
		return
	}
	if len(connectionIDs) >= retiredBusinessConnectionLimit {
		removed := false
		for existingConnectionID := range connectionIDs {
			if activeConnections[existingConnectionID] == nil {
				delete(connectionIDs, existingConnectionID)
				removed = true
				break
			}
		}
		if !removed {
			return
		}
	}
	connectionIDs[connectionID] = struct{}{}
}

func (s *StreamGroup) Close() {
	s.closeOnce.Do(func() {
		s.cancelFunc()
		s.lock.Lock()
		resources := make(map[string]*connectionResource, len(s.connectionMap))
		for connectionID, resource := range s.connectionMap {
			resources[connectionID] = resource
		}
		s.dormantConnectionIDs = s.snapshotConnectionIDsLocked()
		s.dormantFailedIDs = s.snapshotInitializationFailedConnectionIDsLocked()
		s.connectionMap = make(map[string]*connectionResource)
		s.knownConnectionIDs = make(map[string]struct{})
		s.closedConnectionIDs = make(map[string]struct{})
		s.frameRoutes.clear()
		if s.forwardHookConfig != nil {
			cache := s.forwardHookConfig.ensureRetransmitCache()
			for connectionID := range resources {
				cache.forgetConnection(s.nodeId, connectionID)
				s.forwardHookConfig.forgetHeldConnection(s.nodeId, connectionID)
			}
		}
		relayStream := s.relayStream
		s.lock.Unlock()

		if relayStream != nil {
			_ = relayStream.Close()
		}
		for _, resource := range resources {
			resource.Close()
		}
	})
}
