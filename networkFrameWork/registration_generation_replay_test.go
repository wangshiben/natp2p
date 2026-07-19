package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"testing"
	"time"
)

func TestRelayRegistrationGenerationQuarantinesCachedNoiseSentinel(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	identity, err := newRelayTestIdentity("cached-noise-generation-boundary")
	if err != nil {
		t.Fatalf("创建注册身份失败: %v", err)
	}
	oldRegistration, err := TryRegisterRelayStream(identity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("旧代注册失败: %v", err)
	}
	defer oldRegistration.Close()
	oldSlots := waitForRelayTCPStableSlots(t, cover, identity.nodeID, nil)

	cover.lock.RLock()
	oldGroup := cover.StreamGroup[identity.nodeID]
	cover.lock.RUnlock()
	if oldGroup == nil || oldGroup.registrationSessionID == "" {
		t.Fatal("旧代注册组没有 registration session ID")
	}
	oldEndpoint, ok := oldGroup.relayFrame.(*DualFrameRelayEndpoint)
	if !ok {
		t.Fatalf("旧代 relay endpoint 类型错误: %T", oldGroup.relayFrame)
	}

	const staleConnectionID = "00000000-0000-0000-0000-000000000103"
	const stalePayload = "Noise-old-generation-sentinel"
	logicalID := oldEndpoint.AllocMessageId()
	staleMessage := &network.Message{
		Header: &network.Header{
			NodeId:        identity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  staleConnectionID,
		},
		Payload: []byte(stalePayload),
	}
	frames, err := staleMessage.ToFrames(logicalID)
	if err != nil {
		t.Fatalf("构造旧代 Noise sentinel 帧失败: %v", err)
	}
	for _, frame := range frames {
		frame.ConnectionId = staleConnectionID
	}
	reassembled, err := network.AssembleFrames(frames)
	if err != nil {
		t.Fatalf("Noise sentinel 不是合法可重组消息: %v", err)
	}
	if string(reassembled.Payload) != stalePayload {
		t.Fatalf("Noise sentinel 重组载荷错误: got=%q want=%q", reassembled.Payload, stalePayload)
	}

	oldEndpoint.mu.Lock()
	oldAdapter := oldEndpoint.adapters[streamTransportTCP]
	if oldAdapter == nil {
		oldEndpoint.mu.Unlock()
		t.Fatal("旧代 normal TCP adapter 不存在")
	}
	now := time.Now()
	route := &dualFrameRoute{
		kind:        streamTransportTCP,
		connId:      staleConnectionID,
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
	for _, frame := range frames {
		if oldEndpoint.cacheFrameLocked(route, frame) {
			oldEndpoint.mu.Unlock()
			t.Fatal("旧代 Noise sentinel 意外超过 replay cache 上限")
		}
	}
	cachedBytes := route.cachedBytes
	oldEndpoint.mu.Unlock()
	if cachedBytes == 0 {
		t.Fatal("旧代 Noise sentinel 未进入 active replay cache")
	}

	newRegistration, err := TryRegisterRelayStream(identity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("冷重启新代注册失败: %v", err)
	}
	defer newRegistration.Close()
	excluded := make(map[network.Stream]struct{}, len(oldSlots))
	for _, stream := range oldSlots {
		excluded[stream] = struct{}{}
	}
	waitForRelayTCPStableSlots(t, cover, identity.nodeID, excluded)

	cover.lock.RLock()
	newGroup := cover.StreamGroup[identity.nodeID]
	cover.lock.RUnlock()
	if newGroup == nil || newGroup == oldGroup {
		t.Fatal("冷重启新代复用了旧 StreamGroup")
	}
	if newGroup.registrationSessionID == "" || newGroup.registrationSessionID == oldGroup.registrationSessionID {
		t.Fatal("冷重启新代没有独立 registration session ID")
	}
	newEndpoint, ok := newGroup.relayFrame.(*DualFrameRelayEndpoint)
	if !ok || newEndpoint == oldEndpoint {
		t.Fatalf("冷重启新代没有独立 relay endpoint: %T", newGroup.relayFrame)
	}

	message, err := nextNonKeepAliveMessage(context.Background(), newRegistration, 250*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		if message == nil {
			t.Fatalf("新代等待旧帧时返回非超时错误: %v", err)
		}
		t.Fatalf("新代收到旧 adapter replay: connId=%s payload=%q err=%v",
			message.Header.ConnectionId, message.Payload, err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		oldEndpoint.mu.Lock()
		cleared := oldEndpoint.closed && len(oldEndpoint.routes) == 0 && oldEndpoint.cachedBytes == 0
		oldEndpoint.mu.Unlock()
		if cleared {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	oldEndpoint.mu.Lock()
	defer oldEndpoint.mu.Unlock()
	t.Fatalf("旧代 endpoint 未清空: closed=%v routes=%d cachedBytes=%d",
		oldEndpoint.closed, len(oldEndpoint.routes), oldEndpoint.cachedBytes)
}
