package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func dialRegistrationSession(identity *relayTestIdentity, relayAddr, sessionID string, flags uint8) (network.Stream, error) {
	message := &network.Message{
		Header: &network.Header{
			NodeId:        identity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  "",
			LegFlags:      flags,
			LegSessionId:  sessionID,
		},
		Payload: []byte(identity.publicKey),
	}
	return clientStream(message, relayAddr, identity.nodeID, "", false)
}

func waitForRegistrationSession(t *testing.T, cover *TransportCover, nodeID, sessionID string) *StreamGroup {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cover.lock.Lock()
		group := cover.StreamGroup[nodeID]
		cover.lock.Unlock()
		if group != nil && !group.isClosed() && group.registrationSessionID == sessionID {
			return group
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待注册代次超时: nodeId=%.16s session=%s", nodeID, sessionID)
	return nil
}

func waitForRegistrationSessionExit(t *testing.T, cover *TransportCover, nodeID string, group *StreamGroup) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cover.lock.Lock()
		current := cover.StreamGroup[nodeID]
		cover.lock.Unlock()
		if current != group && group.isClosed() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待注册代次退出超时: nodeId=%.16s session=%s", nodeID, group.registrationSessionID)
}

func dialBusinessSession(identity *relayTestIdentity, relayAddr, targetNodeID, connectionID string, flags uint8) (network.Stream, error) {
	message := &network.Message{
		Header: &network.Header{
			NodeId:        targetNodeID,
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
			LegFlags:      flags,
		},
		Payload: []byte(identity.publicKey),
	}
	return clientStream(message, relayAddr, targetNodeID, connectionID, false)
}

func waitForBusinessResource(t *testing.T, group *StreamGroup, connectionID string) *connectionResource {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		group.lock.Lock()
		resource := group.connectionMap[connectionID]
		group.lock.Unlock()
		if resource != nil {
			return resource
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待业务连接资源超时: connId=%s", connectionID)
	return nil
}

func waitForStreamClosure(t *testing.T, stream network.Stream) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if stream == nil || streamIsClosed(stream) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("被拒绝的旧代次 stream 未及时关闭")
}

func expectNoBusinessMessage(t *testing.T, stream network.Stream, timeout time.Duration) {
	t.Helper()
	message, err := nextNonKeepAliveMessage(context.Background(), stream, timeout)
	if !errors.Is(err, context.DeadlineExceeded) {
		if message == nil {
			t.Fatalf("等待无业务消息时返回非超时错误: %v", err)
		}
		prefix := message.Payload
		if len(prefix) > 32 {
			prefix = prefix[:32]
		}
		t.Fatalf("新注册代次收到旧业务帧: connId=%s payloadPrefix=%q err=%v",
			message.Header.ConnectionId, prefix, err)
	}
}

func TestRelayRegistrationColdRestartDoesNotReplayPriorSessionFrames(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	serverIdentity, err := newRelayTestIdentity("cold-restart-incarnation-server")
	if err != nil {
		t.Fatalf("创建 server 身份失败: %v", err)
	}
	firstGeneration, err := TryRegisterRelayStream(serverIdentity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("第一代注册失败: %v", err)
	}
	defer firstGeneration.Close()
	firstSlots := waitForRelayTCPStableSlots(t, cover, serverIdentity.nodeID, nil)

	cover.lock.Lock()
	oldGroup := cover.StreamGroup[serverIdentity.nodeID]
	cover.lock.Unlock()
	if oldGroup == nil || oldGroup.registrationSessionID == "" {
		t.Fatal("第一代注册未建立带会话 ID 的 StreamGroup")
	}
	oldEndpoint, ok := oldGroup.relayFrame.(*DualFrameRelayEndpoint)
	if !ok {
		t.Fatalf("第一代 relay endpoint 类型错误: %T", oldGroup.relayFrame)
	}

	oldClientIdentity, err := newRelayTestIdentity("cold-restart-old-client")
	if err != nil {
		t.Fatalf("创建旧 client 身份失败: %v", err)
	}
	oldClient, oldConnectionID, err := TryConnectTCPStream(relayAddr, serverIdentity.nodeID, oldClientIdentity.publicKey)
	if err != nil {
		t.Fatalf("旧业务连接失败: %v", err)
	}
	defer oldClient.Close()
	firstMessage, err := nextNonKeepAliveMessage(context.Background(), firstGeneration, 3*time.Second)
	if err != nil {
		t.Fatalf("第一代未收到旧业务首帧: %v", err)
	}
	if string(firstMessage.Payload) != oldClientIdentity.publicKey {
		t.Fatalf("旧业务首帧错误: got=%q", firstMessage.Payload)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		oldGroup.lock.Lock()
		_, known := oldGroup.knownConnectionIDs[oldConnectionID]
		oldGroup.lock.Unlock()
		if known {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	oldGroup.lock.Lock()
	_, knownOldConnection := oldGroup.knownConnectionIDs[oldConnectionID]
	oldGroup.lock.Unlock()
	if !knownOldConnection {
		t.Fatal("旧业务 ConnectionId 未进入第一代生命周期集合")
	}

	logicalID := oldEndpoint.AllocMessageId()
	staleMessage := &network.Message{
		Header: &network.Header{
			NodeId:        serverIdentity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  oldConnectionID,
		},
		Payload: []byte("Noise-old-incarnation"),
	}
	frames, err := staleMessage.ToFrames(logicalID)
	if err != nil {
		t.Fatalf("构造旧 Noise sentinel 帧失败: %v", err)
	}
	for _, frame := range frames {
		frame.ConnectionId = oldConnectionID
	}

	oldEndpoint.mu.Lock()
	oldAdapter := oldEndpoint.adapters[streamTransportTCP]
	if oldAdapter == nil {
		oldEndpoint.mu.Unlock()
		t.Fatal("第一代 normal TCP adapter 不存在")
	}
	now := time.Now()
	route := &dualFrameRoute{
		kind:        streamTransportTCP,
		connId:      oldConnectionID,
		endpoint:    oldAdapter,
		dstID:       oldAdapter.AllocMessageId(),
		totalFrames: uint32(len(frames)),
		framesBySeq: make(map[uint32]*network.Frame),
		ackKeys:     make(map[frameEndpointKey]struct{}),
		createdAt:   now,
		lastActive:  now,
		generation:  1,
	}
	oldEndpoint.routes[logicalID] = route
	oldEndpoint.bindAckKeyLocked(logicalID, route, route.kind, oldAdapter, route.dstID)
	cacheDisabled := false
	for _, frame := range frames {
		cacheDisabled = oldEndpoint.cacheFrameLocked(route, frame) || cacheDisabled
	}
	cachedBytes := oldEndpoint.cachedBytes
	oldEndpoint.mu.Unlock()
	if cacheDisabled || cachedBytes == 0 {
		t.Fatalf("旧 Noise sentinel 未进入 active replay cache: disabled=%v bytes=%d", cacheDisabled, cachedBytes)
	}

	secondGeneration, err := TryRegisterRelayStream(serverIdentity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("第二代冷启动注册失败: %v", err)
	}
	defer secondGeneration.Close()
	excluded := make(map[network.Stream]struct{}, len(firstSlots))
	for _, stream := range firstSlots {
		excluded[stream] = struct{}{}
	}
	waitForRelayTCPStableSlots(t, cover, serverIdentity.nodeID, excluded)

	cover.lock.Lock()
	newGroup := cover.StreamGroup[serverIdentity.nodeID]
	tombstone, hasTombstone := cover.retiredBusinessConnections[serverIdentity.nodeID][oldConnectionID]
	cover.lock.Unlock()
	if newGroup == nil || newGroup == oldGroup {
		t.Fatal("冷启动没有原子替换整个 StreamGroup")
	}
	if newGroup.registrationSessionID == "" || newGroup.registrationSessionID == oldGroup.registrationSessionID {
		t.Fatal("第二代注册会话 ID 未更新")
	}
	if !hasTombstone || tombstone.registrationSessionID != oldGroup.registrationSessionID {
		t.Fatal("旧业务 ConnectionId 未绑定到退役服务端代次")
	}

	expectNoBusinessMessage(t, secondGeneration, 250*time.Millisecond)

	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		oldEndpoint.mu.Lock()
		cleared := oldEndpoint.closed && len(oldEndpoint.routes) == 0 && oldEndpoint.cachedBytes == 0
		oldEndpoint.mu.Unlock()
		if cleared {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	oldEndpoint.mu.Lock()
	oldEndpointCleared := oldEndpoint.closed && len(oldEndpoint.routes) == 0 && oldEndpoint.cachedBytes == 0
	oldEndpoint.mu.Unlock()
	oldGroup.lock.Lock()
	oldResources := len(oldGroup.connectionMap)
	oldKnownConnections := len(oldGroup.knownConnectionIDs)
	oldGroup.lock.Unlock()
	oldGroup.frameRoutes.mu.Lock()
	oldOuterRoutes := oldGroup.frameRoutes.pairCount
	oldGroup.frameRoutes.mu.Unlock()
	if !oldEndpointCleared || oldResources != 0 || oldKnownConnections != 0 || oldOuterRoutes != 0 {
		t.Fatalf("旧代资源未完整清理: endpoint=%v resources=%d known=%d outerRoutes=%d",
			oldEndpointCleared, oldResources, oldKnownConnections, oldOuterRoutes)
	}

	resumeMessage := &network.Message{
		Header: &network.Header{
			NodeId:        serverIdentity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  oldConnectionID,
			LegFlags:      network.LegFlagResume,
		},
		Payload: []byte(oldClientIdentity.publicKey),
	}
	staleResume, _ := clientStream(resumeMessage, relayAddr, serverIdentity.nodeID, oldConnectionID, false)
	if staleResume != nil {
		defer staleResume.Close()
		waitForStreamClosure(t, staleResume)
	}
	newGroup.lock.Lock()
	_, staleResourceCreated := newGroup.connectionMap[oldConnectionID]
	newGroup.lock.Unlock()
	if staleResourceCreated {
		t.Fatal("旧业务 Resume 在新服务端代次中重建了 connectionResource")
	}
	expectNoBusinessMessage(t, secondGeneration, 150*time.Millisecond)

	newClientIdentity, err := newRelayTestIdentity("cold-restart-new-client")
	if err != nil {
		t.Fatalf("创建新 client 身份失败: %v", err)
	}
	newClient, _, err := TryConnectTCPStream(relayAddr, serverIdentity.nodeID, newClientIdentity.publicKey)
	if err != nil {
		t.Fatalf("新代业务连接失败: %v", err)
	}
	defer newClient.Close()
	newFirstMessage, err := nextNonKeepAliveMessage(context.Background(), secondGeneration, 3*time.Second)
	if err != nil {
		t.Fatalf("第二代未收到新业务首帧: %v", err)
	}
	if got := string(newFirstMessage.Payload); got != newClientIdentity.publicKey {
		t.Fatalf("第二代业务首帧错误: got=%q want=%q", got, newClientIdentity.publicKey)
	}
}

func TestRelayRegistrationRetiredSessionCannotSwitchBack(t *testing.T) {
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	identity, err := newRelayTestIdentity("retired-registration-session")
	if err != nil {
		t.Fatalf("创建注册身份失败: %v", err)
	}
	sessionA := uuid.New().String()
	sessionB := uuid.New().String()
	first, err := dialRegistrationSession(identity, relayAddr, sessionA, 0)
	if err != nil {
		t.Fatalf("注册 A 失败: %v", err)
	}
	groupA := waitForRegistrationSession(t, cover, identity.nodeID, sessionA)
	if err := first.Close(); err != nil {
		t.Fatalf("关闭注册 A 失败: %v", err)
	}
	waitForRegistrationSessionExit(t, cover, identity.nodeID, groupA)

	second, err := dialRegistrationSession(identity, relayAddr, sessionB, 0)
	if err != nil {
		t.Fatalf("注册 B 失败: %v", err)
	}
	defer second.Close()
	groupB := waitForRegistrationSession(t, cover, identity.nodeID, sessionB)
	if groupA == groupB || !groupA.isClosed() {
		t.Fatal("A→B 未替换并关闭旧注册组")
	}

	lateLegs := []struct {
		name  string
		flags uint8
	}{
		{name: "normal"},
		{name: "extra", flags: network.LegFlagExtra},
		{name: "resume", flags: network.LegFlagResume},
		{name: "extra-resume", flags: network.LegFlagExtra | network.LegFlagResume},
	}
	for _, lateLeg := range lateLegs {
		t.Run(lateLeg.name, func(t *testing.T) {
			stream, _ := dialRegistrationSession(identity, relayAddr, sessionA, lateLeg.flags)
			if stream != nil {
				defer stream.Close()
				waitForStreamClosure(t, stream)
			}
		})
	}

	cover.lock.Lock()
	current := cover.StreamGroup[identity.nodeID]
	retired := cover.isRegistrationSessionRetiredLocked(identity.nodeID, sessionA, time.Now())
	cover.lock.Unlock()
	if current != groupB || current.registrationSessionID != sessionB {
		t.Fatal("延迟 A leg 将现役 B 注册组切回旧代次")
	}
	if !retired {
		t.Fatal("A 注册代次没有保留 retired tombstone")
	}
}

func TestBusinessResumeAllowedWithinGenerationAndRejectedAfterRestart(t *testing.T) {
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	serverIdentity, err := newRelayTestIdentity("business-resume-generation-server")
	if err != nil {
		t.Fatalf("创建 server 身份失败: %v", err)
	}
	clientIdentity, err := newRelayTestIdentity("business-resume-generation-client")
	if err != nil {
		t.Fatalf("创建 client 身份失败: %v", err)
	}
	sessionA := uuid.New().String()
	sessionB := uuid.New().String()
	connectionID := uuid.New().String()

	serverA, err := dialRegistrationSession(serverIdentity, relayAddr, sessionA, 0)
	if err != nil {
		t.Fatalf("注册服务端 A 失败: %v", err)
	}
	groupA := waitForRegistrationSession(t, cover, serverIdentity.nodeID, sessionA)

	clientA, err := dialBusinessSession(clientIdentity, relayAddr, serverIdentity.nodeID, connectionID, 0)
	if err != nil {
		t.Fatalf("建立 A 代业务连接失败: %v", err)
	}
	defer clientA.Close()
	firstMessage, err := nextNonKeepAliveMessage(context.Background(), serverA, 3*time.Second)
	if err != nil {
		t.Fatalf("A 代未收到业务首帧: %v", err)
	}
	if firstMessage.Header.ConnectionId != connectionID || string(firstMessage.Payload) != clientIdentity.publicKey {
		t.Fatalf("A 代业务首帧错误: connId=%s payload=%q", firstMessage.Header.ConnectionId, firstMessage.Payload)
	}
	waitForBusinessResource(t, groupA, connectionID)

	if err := serverA.Close(); err != nil {
		t.Fatalf("模拟 A 注册链路退出失败: %v", err)
	}
	waitForRegistrationSessionExit(t, cover, serverIdentity.nodeID, groupA)

	serverAResume, err := dialRegistrationSession(serverIdentity, relayAddr, sessionA, network.LegFlagResume)
	if err != nil {
		t.Fatalf("同代服务端 Resume 被拒绝: %v", err)
	}
	groupAResume := waitForRegistrationSession(t, cover, serverIdentity.nodeID, sessionA)
	if groupAResume == groupA {
		t.Fatal("已关闭的 A group 未由同代 Resume 重建")
	}

	clientAResume, err := dialBusinessSession(clientIdentity, relayAddr, serverIdentity.nodeID, connectionID, network.LegFlagResume)
	if err != nil {
		t.Fatalf("同服务端代次的业务 Resume 被拒绝: %v", err)
	}
	defer clientAResume.Close()
	waitForBusinessResource(t, groupAResume, connectionID)
	expectNoBusinessMessage(t, serverAResume, 150*time.Millisecond)

	if err := serverAResume.Close(); err != nil {
		t.Fatalf("关闭恢复后的 A 注册链路失败: %v", err)
	}
	waitForRegistrationSessionExit(t, cover, serverIdentity.nodeID, groupAResume)

	serverB, err := dialRegistrationSession(serverIdentity, relayAddr, sessionB, 0)
	if err != nil {
		t.Fatalf("注册冷重启服务端 B 失败: %v", err)
	}
	defer serverB.Close()
	groupB := waitForRegistrationSession(t, cover, serverIdentity.nodeID, sessionB)

	cover.lock.Lock()
	tombstone, hasTombstone := cover.retiredBusinessConnections[serverIdentity.nodeID][connectionID]
	cover.lock.Unlock()
	if !hasTombstone || tombstone.registrationSessionID != sessionA {
		t.Fatal("A 自然退出后旧业务 ConnectionId 未保留代次 tombstone")
	}

	staleLegs := []struct {
		name  string
		flags uint8
	}{
		{name: "normal"},
		{name: "extra", flags: network.LegFlagExtra},
		{name: "resume", flags: network.LegFlagResume},
		{name: "extra-resume", flags: network.LegFlagExtra | network.LegFlagResume},
	}
	for _, staleLeg := range staleLegs {
		t.Run(staleLeg.name, func(t *testing.T) {
			stream, _ := dialBusinessSession(clientIdentity, relayAddr, serverIdentity.nodeID, connectionID, staleLeg.flags)
			if stream != nil {
				defer stream.Close()
				waitForStreamClosure(t, stream)
			}
		})
	}
	groupB.lock.Lock()
	_, staleResourceCreated := groupB.connectionMap[connectionID]
	groupB.lock.Unlock()
	if staleResourceCreated {
		t.Fatal("A 代业务 Resume 在 B 代重建了 connectionResource")
	}
	expectNoBusinessMessage(t, serverB, 150*time.Millisecond)
}

func TestDormantRegistrationAllowsDifferentSessionResume(t *testing.T) {
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	identity, err := newRelayTestIdentity("dormant-different-resume")
	if err != nil {
		t.Fatalf("创建注册身份失败: %v", err)
	}
	sessionA := uuid.New().String()
	sessionB := uuid.New().String()
	first, err := dialRegistrationSession(identity, relayAddr, sessionA, 0)
	if err != nil {
		t.Fatalf("注册 A 失败: %v", err)
	}
	groupA := waitForRegistrationSession(t, cover, identity.nodeID, sessionA)
	if err := first.Close(); err != nil {
		t.Fatalf("关闭注册 A 失败: %v", err)
	}
	waitForRegistrationSessionExit(t, cover, identity.nodeID, groupA)

	second, err := dialRegistrationSession(identity, relayAddr, sessionB, network.LegFlagResume)
	if err != nil {
		t.Fatalf("dormant A 后不同代次 Resume B 不应被拒绝: %v", err)
	}
	defer second.Close()
	groupB := waitForRegistrationSession(t, cover, identity.nodeID, sessionB)
	cover.lock.Lock()
	retiredA := cover.isRegistrationSessionRetiredLocked(identity.nodeID, sessionA, time.Now())
	cover.lock.Unlock()
	if groupB == groupA || !retiredA {
		t.Fatal("不同代次 Resume B 未接管并退役 dormant A")
	}
}

func TestStreamGroupRejectsBusinessConnectionBeyondGenerationLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	group := &StreamGroup{
		connectionMap:       make(map[string]*connectionResource, retiredBusinessConnectionLimit),
		knownConnectionIDs:  make(map[string]struct{}, retiredBusinessConnectionLimit),
		closedConnectionIDs: make(map[string]struct{}),
		ctx:                 ctx,
		cancelFunc:          cancel,
	}
	for index := 0; index < retiredBusinessConnectionLimit; index++ {
		connectionID := uuid.New().String()
		group.connectionMap[connectionID] = &connectionResource{}
		group.knownConnectionIDs[connectionID] = struct{}{}
	}

	forward, err := group.StreamOn(nil, &network.Message{Header: &network.Header{ConnectionId: uuid.New().String()}})
	if forward || !errors.Is(err, ErrBusinessConnectionLimit) {
		t.Fatalf("超出业务连接代次上限应明确拒绝: forward=%v err=%v", forward, err)
	}
	if len(group.connectionMap) != retiredBusinessConnectionLimit ||
		len(group.knownConnectionIDs) != retiredBusinessConnectionLimit {
		t.Fatal("拒绝超限业务连接时改写了现役代次集合")
	}
}

func TestStreamGroupGenerationSnapshotPrioritizesActiveConnections(t *testing.T) {
	activeConnectionID := uuid.New().String()
	group := &StreamGroup{
		connectionMap: map[string]*connectionResource{
			activeConnectionID: {},
		},
		knownConnectionIDs:  make(map[string]struct{}, retiredBusinessConnectionLimit),
		closedConnectionIDs: make(map[string]struct{}, retiredBusinessConnectionLimit),
	}
	group.knownConnectionIDs[activeConnectionID] = struct{}{}
	for index := 1; index < retiredBusinessConnectionLimit; index++ {
		group.knownConnectionIDs[uuid.New().String()] = struct{}{}
	}
	for index := 0; index < retiredBusinessConnectionLimit; index++ {
		group.closedConnectionIDs[uuid.New().String()] = struct{}{}
	}

	newHistoryID := uuid.New().String()
	addBoundedKnownConnectionID(group.knownConnectionIDs, group.connectionMap, newHistoryID)
	if _, retained := group.knownConnectionIDs[activeConnectionID]; !retained {
		t.Fatal("knownConnectionIDs 淘汰了仍活跃的 ConnectionId")
	}
	if _, added := group.knownConnectionIDs[newHistoryID]; !added {
		t.Fatal("knownConnectionIDs 有可淘汰历史项时未记录新 ConnectionId")
	}

	connectionIDs := group.snapshotConnectionIDs()
	if len(connectionIDs) != retiredBusinessConnectionLimit {
		t.Fatalf("代次快照未按上限截断: got=%d want=%d", len(connectionIDs), retiredBusinessConnectionLimit)
	}
	for _, connectionID := range connectionIDs {
		if connectionID == activeConnectionID {
			return
		}
	}
	t.Fatal("代次快照在历史记录超限时遗漏活跃 ConnectionId")
}
