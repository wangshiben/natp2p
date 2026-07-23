package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleCarrier struct {
	nodeID       string
	connectionID string
	frames       chan *network.Frame
	done         chan struct{}
	nextStarted  chan struct{}
	nextOnce     sync.Once
	closeOnce    sync.Once
	frameID      atomic.Uint64
	failWrites   bool
	handledMu    sync.Mutex
	handled      []*network.Frame
}

func newLifecycleCarrier(nodeID, connectionID string) *lifecycleCarrier {
	return &lifecycleCarrier{
		nodeID:       nodeID,
		connectionID: connectionID,
		frames:       make(chan *network.Frame, 16),
		done:         make(chan struct{}),
		nextStarted:  make(chan struct{}),
	}
}

func (c *lifecycleCarrier) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *lifecycleCarrier) NextMessage(ctx context.Context) (*network.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, errors.New("closed")
	}
}

func (c *lifecycleCarrier) SendMessage(ctx context.Context, _ *network.Message) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return errors.New("closed")
	default:
		return nil
	}
}

func (c *lifecycleCarrier) SendMessageAsync(ctx context.Context, message *network.Message, callback network.MessageResultCallback) error {
	err := c.SendMessage(ctx, message)
	if callback != nil {
		callback(network.MessageResult{Success: err == nil, Error: err})
	}
	return err
}

func (c *lifecycleCarrier) NodeId() string       { return c.nodeID }
func (c *lifecycleCarrier) ConnectionId() string { return c.connectionID }
func (c *lifecycleCarrier) SetCryptoSuite(network.EncrypSuite) {
}

func (c *lifecycleCarrier) NextFrame(ctx context.Context) (*network.Frame, error) {
	c.nextOnce.Do(func() { close(c.nextStarted) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, errors.New("closed")
	case frame := <-c.frames:
		return frame, nil
	}
}

func (c *lifecycleCarrier) HandleFrame(ctx context.Context, frame *network.Frame) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return errors.New("closed")
	default:
	}
	if c.failWrites {
		return errors.New("injected write failure")
	}
	copyFrame := cloneFrame(frame)
	c.handledMu.Lock()
	c.handled = append(c.handled, copyFrame)
	c.handledMu.Unlock()
	return nil
}

func (c *lifecycleCarrier) AllocMessageId() uint64 { return c.frameID.Add(1) }

func (c *lifecycleCarrier) handledCount() int {
	c.handledMu.Lock()
	defer c.handledMu.Unlock()
	return len(c.handled)
}

func newLifecycleGroup(relay *lifecycleCarrier) *StreamGroup {
	ctx, cancel := context.WithCancel(context.Background())
	return &StreamGroup{
		relayStream:          relay,
		relayFrame:           relay,
		connectionMap:        make(map[string]*connectionResource),
		frameRoutes:          newFrameRouteRegistry(),
		beforeConnectionHook: defaultHookfunc,
		ctx:                  ctx,
		cancelFunc:           cancel,
		nodeId:               relay.NodeId(),
	}
}

func newLifecycleResource(group *StreamGroup, carrier *lifecycleCarrier) *connectionResource {
	ctx, cancel := context.WithCancel(group.ctx)
	return &connectionResource{stream: carrier, frame: carrier, ctx: ctx, flag: cancel}
}

func bindLifecyclePair(routes *frameRouteRegistry, relayID uint64, connectionID string, clientID uint64, relayDest, clientDest FrameRelayEndpoint) *frameRouteEntry {
	return bindLifecyclePairWithTotal(routes, relayID, connectionID, clientID, 1, relayDest, clientDest)
}

func bindLifecyclePairWithTotal(routes *frameRouteRegistry, relayID uint64, connectionID string, clientID uint64, totalFrames uint32, relayDest, clientDest FrameRelayEndpoint) *frameRouteEntry {
	pair, ok := routes.bindPair(
		relayID,
		&frameRouteEntry{dest: clientDest, dstID: clientID},
		clientRouteKey{connectionID: connectionID, messageID: clientID},
		&frameRouteEntry{dest: relayDest, dstID: relayID},
		totalFrames,
	)
	if !ok {
		return nil
	}
	return pair.relayEntry
}

func waitLifecycleCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func TestFrameRouteRegistryTombstoneTTLAndHardLimit(t *testing.T) {
	clock := time.Unix(100, 0)
	routes := newFrameRouteRegistryWithLimits(90*time.Second, 2)
	routes.now = func() time.Time { return clock }
	relay := newLifecycleCarrier("relay", "")
	client := newLifecycleCarrier("client", "conn-a")

	first := bindLifecyclePair(routes, 1, "conn-a", 11, relay, client)
	routes.complete(first)
	if !first.pair.completed || routes.pairCount != 1 {
		t.Fatalf("full ACK 后应保留一条 tombstone pair: completed=%v pairs=%d", first.pair.completed, routes.pairCount)
	}

	clock = clock.Add(60 * time.Second)
	if got := routes.relayGet(1); got != first {
		t.Fatal("TTL 内 tombstone 应继续命中原 route")
	}
	clock = clock.Add(40 * time.Second)
	if routes.pairCount != 1 {
		t.Fatal("访问 tombstone 应刷新滑动 TTL")
	}
	clock = clock.Add(51 * time.Second)
	if got := routes.relayGet(1); got != nil {
		t.Fatal("滑动 TTL 到期后 route 应回收")
	}
	if routes.pairCount != 0 || len(routes.relaySide) != 0 || len(routes.clientSide) != 0 {
		t.Fatalf("TTL 回收必须成对清空: pairs=%d relay=%d client=%d", routes.pairCount, len(routes.relaySide), len(routes.clientSide))
	}

	second := bindLifecyclePair(routes, 2, "conn-a", 12, relay, client)
	clock = clock.Add(time.Second)
	third := bindLifecyclePair(routes, 3, "conn-a", 13, relay, client)
	clock = clock.Add(time.Second)
	if rejected := bindLifecyclePair(routes, 4, "conn-a", 14, relay, client); rejected != nil {
		t.Fatal("硬上限不能淘汰仍在传输的 active pair")
	}
	if routes.pairCount != 2 || len(routes.relaySide) != 2 || len(routes.clientSide) != 2 {
		t.Fatalf("硬上限必须约束成对映射: pairs=%d relay=%d client=%d", routes.pairCount, len(routes.relaySide), len(routes.clientSide))
	}
	if routes.relayGet(2) != second || routes.relayGet(3) != third || routes.relayGet(4) != nil {
		t.Fatal("达到硬上限时必须保留所有 active pair 并拒绝新 pair")
	}
	routes.complete(second)
	if fourth := bindLifecyclePair(routes, 4, "conn-a", 14, relay, client); fourth == nil {
		t.Fatal("存在 completed tombstone 时应允许淘汰后创建新 pair")
	}
	if routes.relayGet(2) != nil || routes.relayGet(3) != third || routes.relayGet(4) == nil {
		t.Fatal("超过硬上限时只能淘汰 completed tombstone")
	}
}

func TestFrameRouteRegistryActivePairSurvivesLegacyTTLsAndContinues(t *testing.T) {
	clock := time.Unix(500, 0)
	routes := newFrameRouteRegistryWithLimits(90*time.Second, 4)
	routes.now = func() time.Time { return clock }
	relay := newLifecycleCarrier("relay", "")
	client := newLifecycleCarrier("client", "conn-active")

	relayEntry := bindLifecyclePairWithTotal(routes, 71, "conn-active", 81, 3, relay, client)
	if relayEntry == nil || relayEntry.pair == nil {
		t.Fatal("failed to bind active route pair")
	}
	clientEntry := relayEntry.pair.clientEntry
	clock = clock.Add(3 * time.Minute)

	if got := routes.relayGet(71); got != relayEntry {
		t.Fatalf("active relay route expired across legacy TTLs: got=%p want=%p", got, relayEntry)
	}
	if got := routes.clientGet("conn-active", 81); got != clientEntry {
		t.Fatalf("active client route expired across legacy TTLs: got=%p want=%p", got, clientEntry)
	}
	pair, ok := routes.bindPair(
		71,
		&frameRouteEntry{dest: client, dstID: 81},
		clientRouteKey{connectionID: "conn-active", messageID: 81},
		&frameRouteEntry{dest: relay, dstID: 71},
		3,
	)
	if !ok || pair != relayEntry.pair {
		t.Fatalf("active route could not continue after legacy TTLs: pair=%p want=%p ok=%v", pair, relayEntry.pair, ok)
	}
	if routes.pairCount != 1 || pair.completed {
		t.Fatalf("active route state changed after continuation: pairs=%d completed=%v", routes.pairCount, pair.completed)
	}
}

func TestFrameRouteRegistryRejectsOneSidedKeyCollision(t *testing.T) {
	routes := newFrameRouteRegistryWithLimits(time.Minute, 4)
	relay := newLifecycleCarrier("relay", "")
	client := newLifecycleCarrier("client", "conn-a")
	first := bindLifecyclePair(routes, 1, "conn-a", 11, relay, client)
	if first == nil {
		t.Fatal("failed to bind initial pair")
	}

	if pair, ok := routes.bindPair(2, &frameRouteEntry{dest: client, dstID: 11}, clientRouteKey{connectionID: "conn-a", messageID: 11}, &frameRouteEntry{dest: relay, dstID: 2}, 1); ok || pair != nil {
		t.Fatal("client-side key collision must be rejected")
	}
	if pair, ok := routes.bindPair(1, &frameRouteEntry{dest: client, dstID: 12}, clientRouteKey{connectionID: "conn-a", messageID: 12}, &frameRouteEntry{dest: relay, dstID: 1}, 1); ok || pair != nil {
		t.Fatal("relay-side key collision must be rejected")
	}
	if routes.pairCount != 1 || routes.relayGet(1) != first || routes.clientGet("conn-a", 11) != first.pair.clientEntry {
		t.Fatal("rejected collision changed the original bidirectional pair")
	}
}

func TestFrameRouteRegistryPurgeConnectionAndRetainCompletedMapping(t *testing.T) {
	routes := newFrameRouteRegistry()
	relay := newLifecycleCarrier("relay", "")
	clientA := newLifecycleCarrier("client-a", "conn-a")
	clientB := newLifecycleCarrier("client-b", "conn-b")

	entry := bindLifecyclePair(routes, 1, "conn-a", 11, relay, clientA)
	routes.complete(entry)
	if got := routes.clientGet("conn-a", 11); got == nil || got.dstID != 1 {
		t.Fatal("completed tombstone 必须保留原 ID 映射供非首帧重传")
	}
	bindLifecyclePair(routes, 2, "conn-a", 12, relay, clientA)
	bindLifecyclePair(routes, 3, "conn-b", 13, relay, clientB)

	routes.purgeConnection("conn-a")
	if routes.pairCount != 1 || routes.clientGet("conn-a", 11) != nil || routes.clientGet("conn-a", 12) != nil {
		t.Fatalf("conn-a 应被完整清理: pairs=%d", routes.pairCount)
	}
	if routes.relayGet(1) != nil || routes.relayGet(2) != nil || routes.relayGet(3) == nil {
		t.Fatal("按连接清理必须删除对应 relay 反向映射且不影响其它连接")
	}
}

func TestFrameRoutePumpFullAckMarksTombstone(t *testing.T) {
	routes := newFrameRouteRegistry()
	relay := newLifecycleCarrier("relay", "")
	client := newLifecycleCarrier("client", "conn-a")
	entry := bindLifecyclePairWithTotal(routes, 1, "conn-a", 11, 3, relay, client)
	wrongTotal, err := network.BuildAckFrame(1, 1, network.FullAckRange(1))
	if err != nil {
		t.Fatal(err)
	}
	wrongTotal.ConnectionId = "conn-a"
	ack, err := network.BuildAckFrame(1, 3, network.FullAckRange(3))
	if err != nil {
		t.Fatal(err)
	}
	ack.ConnectionId = "conn-a"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pumpRelayToClients(ctx, relay, func(string) FrameRelayEndpoint { return client }, routes, nil, "relay", nil)
	relay.frames <- wrongTotal
	waitLifecycleCondition(t, time.Second, func() bool { return client.handledCount() == 1 })
	if entry.pair.completed {
		t.Fatal("TotalFrames 不匹配的 ACK 不得完成 pair")
	}
	relay.frames <- ack
	waitLifecycleCondition(t, time.Second, func() bool {
		routes.mu.Lock()
		defer routes.mu.Unlock()
		return entry.pair.completed
	})
	if client.handledCount() != 2 || routes.relayGet(1) == nil || routes.clientGet("conn-a", 11) == nil {
		t.Fatal("full ACK 应完成 pair 但保留双向 tombstone")
	}
}

func TestStreamGroupExpectedCleanupCannotDeleteReplacement(t *testing.T) {
	relay := newLifecycleCarrier("relay", "")
	group := newLifecycleGroup(relay)
	defer group.Close()
	oldClient := newLifecycleCarrier("old-client", "same-conn")
	newClient := newLifecycleCarrier("new-client", "same-conn")
	oldResource := newLifecycleResource(group, oldClient)
	newResource := newLifecycleResource(group, newClient)

	group.lock.Lock()
	group.connectionMap["same-conn"] = oldResource
	group.lock.Unlock()

	group.lock.Lock()
	group.connectionMap["same-conn"] = newResource
	group.lock.Unlock()
	group.closeTargetConnectionIfMatch("same-conn", oldResource)
	group.lock.Lock()
	got := group.connectionMap["same-conn"]
	group.lock.Unlock()
	if got != newResource {
		t.Fatal("old pump 退出不得删除同 connectionID 的新 resource")
	}
}

func TestStreamGroupFramePumpExitRemovesResourceAndRoutes(t *testing.T) {
	relay := newLifecycleCarrier("relay", "")
	group := newLifecycleGroup(relay)
	defer group.Close()
	client := newLifecycleCarrier("client", "conn-a")
	resource := newLifecycleResource(group, client)
	group.connectionMap["conn-a"] = resource
	bindLifecyclePair(group.frameRoutes, 1, "conn-a", 11, relay, client)
	group.startFramePump("conn-a", resource)
	select {
	case <-client.nextStarted:
	case <-time.After(time.Second):
		t.Fatal("client frame pump did not start")
	}
	_ = client.Close()
	waitLifecycleCondition(t, time.Second, func() bool {
		group.lock.Lock()
		defer group.lock.Unlock()
		return group.connectionMap["conn-a"] == nil
	})
	group.frameRoutes.mu.Lock()
	pairs := group.frameRoutes.pairCount
	group.frameRoutes.mu.Unlock()
	if pairs != 0 {
		t.Fatalf("frame pump 退出后应清理该连接 routes, got %d", pairs)
	}
}

func TestStreamGroupClientWriteFailureDoesNotStopOtherClients(t *testing.T) {
	relay := newLifecycleCarrier("relay", "")
	group := newLifecycleGroup(relay)
	clientA := newLifecycleCarrier("client-a", "conn-a")
	clientA.failWrites = true
	clientB := newLifecycleCarrier("client-b", "conn-b")
	resourceA := newLifecycleResource(group, clientA)
	resourceB := newLifecycleResource(group, clientB)
	group.connectionMap["conn-a"] = resourceA
	group.connectionMap["conn-b"] = resourceB
	bindLifecyclePair(group.frameRoutes, 1, "conn-a", 11, relay, clientA)
	bindLifecyclePair(group.frameRoutes, 2, "conn-b", 12, relay, clientB)

	finished := make(chan struct{})
	go func() {
		group.StartListen()
		close(finished)
	}()
	select {
	case <-relay.nextStarted:
	case <-time.After(time.Second):
		t.Fatal("relay frame pump did not start")
	}
	relay.frames <- &network.Frame{MessageId: 1, SeqId: 0, TotalFrames: 1, FrameType: network.FrameTypeData, ConnectionId: "conn-a"}
	relay.frames <- &network.Frame{MessageId: 2, SeqId: 0, TotalFrames: 1, FrameType: network.FrameTypeData, ConnectionId: "conn-b"}

	waitLifecycleCondition(t, time.Second, func() bool { return clientB.handledCount() == 1 })
	group.lock.Lock()
	_, hasA := group.connectionMap["conn-a"]
	_, hasB := group.connectionMap["conn-b"]
	group.lock.Unlock()
	if hasA || !hasB {
		t.Fatalf("失败 client 应单独移除且健康 client 保留: hasA=%v hasB=%v", hasA, hasB)
	}

	_ = relay.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("group did not exit after relay closed")
	}
}

func TestTransportCoverGroupExitCompareDelete(t *testing.T) {
	cover := NewTransportCover()
	oldRelay := newLifecycleCarrier("hosted-node", "")
	oldGroup := newLifecycleGroup(oldRelay)
	cover.StreamGroup["hosted-node"] = oldGroup

	finished := make(chan struct{})
	go func() {
		cover.listenGroup("hosted-node", oldGroup)
		close(finished)
	}()
	select {
	case <-oldRelay.nextStarted:
	case <-time.After(time.Second):
		t.Fatal("old group listener did not start")
	}

	newRelay := newLifecycleCarrier("hosted-node", "")
	newGroup := newLifecycleGroup(newRelay)
	cover.lock.Lock()
	cover.StreamGroup["hosted-node"] = newGroup
	cover.lock.Unlock()
	_ = oldRelay.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("old group listener did not exit")
	}
	cover.lock.RLock()
	got := cover.StreamGroup["hosted-node"]
	cover.lock.RUnlock()
	if got != newGroup {
		t.Fatal("old group compare-delete must not remove replacement group")
	}
	newGroup.Close()

	standaloneRelay := newLifecycleCarrier("standalone-node", "")
	standaloneGroup := newLifecycleGroup(standaloneRelay)
	cover.lock.Lock()
	cover.StreamGroup["standalone-node"] = standaloneGroup
	cover.lock.Unlock()
	go cover.listenGroup("standalone-node", standaloneGroup)
	select {
	case <-standaloneRelay.nextStarted:
	case <-time.After(time.Second):
		t.Fatal("standalone group listener did not start")
	}
	_ = standaloneRelay.Close()
	waitLifecycleCondition(t, time.Second, func() bool { return !cover.HasGroup("standalone-node") })
}

func TestDualStreamRejectsAttachAfterClose(t *testing.T) {
	dual := newDualStreamWithPump("closed-node", "closed-connection", false)
	if err := dual.Close(); err != nil {
		t.Fatal(err)
	}
	carrier := newLifecycleCarrier("client", "closed-connection")
	defer carrier.Close()
	if err := dual.attachWithID(streamTransportTCP, streamTransportTCP, carrier); err == nil {
		t.Fatal("closed DualStream accepted a new leg")
	}
	dual.mu.RLock()
	legCount := len(dual.legs)
	dual.mu.RUnlock()
	if legCount != 0 {
		t.Fatalf("closed DualStream retained %d legs", legCount)
	}
}
