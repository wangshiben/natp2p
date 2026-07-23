package networkFrameWork

import (
	"context"
	"errors"
	"testing"
	"time"

	"bnfs_p2p/network"
)

func newFrameAdapterCacheTestEndpoint() *DualFrameRelayEndpoint {
	return &DualFrameRelayEndpoint{
		adapters:      make(map[streamTransport]*TcpFrameAdapter),
		incoming:      make(chan *network.Frame, 16),
		incomingIDs:   make(map[frameEndpointKey]uint64),
		ackIDs:        make(map[frameEndpointKey]uint64),
		routes:        make(map[uint64]*dualFrameRoute),
		maxBytes:      defaultFrameRelayMaxCachedBytes,
		maxRouteBytes: defaultFrameRelayMaxRouteCachedBytes,
		maxRoutes:     defaultFrameRelayMaxRoutes,
	}
}

func mustFrameAdapterAck(t *testing.T, messageID uint64, total uint32, ranges []network.AckRange) *network.Frame {
	t.Helper()
	frame, err := network.BuildAckFrame(messageID, total, ranges)
	if err != nil {
		t.Fatalf("build ACK: %v", err)
	}
	return frame
}

func applyFrameAdapterAck(endpoint *DualFrameRelayEndpoint, kind streamTransport, adapter *TcpFrameAdapter, frame *network.Frame, now time.Time) (uint64, *dualFrameRoute, error) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	logicalID, route, err := endpoint.resolveIncomingFrameLocked(kind, adapter, frame, now)
	if err == nil && route != nil && isFullFrameAck(frame, route.totalFrames) {
		endpoint.completeRouteLocked(route, now)
	}
	return logicalID, route, err
}

func TestIsFullFrameAck(t *testing.T) {
	full := mustFrameAdapterAck(t, 1, 3, network.FullAckRange(3))
	split := mustFrameAdapterAck(t, 1, 3, []network.AckRange{{Start: 0, End: 0}, {Start: 1, End: 2}})
	overlap := mustFrameAdapterAck(t, 1, 3, []network.AckRange{{Start: 0, End: 1}, {Start: 1, End: 2}})
	partial := mustFrameAdapterAck(t, 1, 3, []network.AckRange{{Start: 0, End: 1}})
	gap := mustFrameAdapterAck(t, 1, 3, []network.AckRange{{Start: 0, End: 0}, {Start: 2, End: 2}})
	reversed := mustFrameAdapterAck(t, 1, 3, []network.AckRange{{Start: 1, End: 0}})
	outOfRange := mustFrameAdapterAck(t, 1, 3, []network.AckRange{{Start: 0, End: 3}})
	wrongOrder := mustFrameAdapterAck(t, 1, 3, []network.AckRange{{Start: 1, End: 2}, {Start: 0, End: 0}})
	empty := mustFrameAdapterAck(t, 1, 3, nil)

	tests := []struct {
		name          string
		frame         *network.Frame
		expectedTotal uint32
		want          bool
	}{
		{name: "nil", frame: nil, expectedTotal: 3},
		{name: "not ACK", frame: &network.Frame{FrameType: network.FrameTypeData, TotalFrames: 3, Payload: full.Payload}, expectedTotal: 3},
		{name: "zero expected total", frame: full, expectedTotal: 0},
		{name: "total mismatch", frame: full, expectedTotal: 4},
		{name: "malformed payload", frame: &network.Frame{FrameType: network.FrameTypeAck, TotalFrames: 3, Payload: []byte{1}}, expectedTotal: 3},
		{name: "empty ranges", frame: empty, expectedTotal: 3},
		{name: "partial", frame: partial, expectedTotal: 3},
		{name: "gap", frame: gap, expectedTotal: 3},
		{name: "reversed", frame: reversed, expectedTotal: 3},
		{name: "out of range", frame: outOfRange, expectedTotal: 3},
		{name: "wrong order", frame: wrongOrder, expectedTotal: 3},
		{name: "single full range", frame: full, expectedTotal: 3, want: true},
		{name: "split full ranges", frame: split, expectedTotal: 3, want: true},
		{name: "overlapping full ranges", frame: overlap, expectedTotal: 3, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isFullFrameAck(test.frame, test.expectedTotal); got != test.want {
				t.Fatalf("isFullFrameAck() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDualFrameRelayEndpointAckCompletionReleasesCache(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	adapter := &TcpFrameAdapter{}
	const logicalID uint64 = 7
	const destinationID uint64 = 41
	now := time.Unix(1_700_000_000, 0)
	route := &dualFrameRoute{
		kind:        streamTransportTCP,
		endpoint:    adapter,
		dstID:       destinationID,
		totalFrames: 3,
		framesBySeq: make(map[uint32]*network.Frame),
		ackKeys:     make(map[frameEndpointKey]struct{}),
		createdAt:   now,
		lastActive:  now,
		generation:  1,
	}
	endpoint.routes[logicalID] = route
	endpoint.bindAckKeyLocked(logicalID, route, streamTransportTCP, adapter, destinationID)
	for sequence := uint32(0); sequence < route.totalFrames; sequence++ {
		frame := &network.Frame{
			MessageId:    logicalID,
			SeqId:        sequence,
			TotalFrames:  route.totalFrames,
			FrameType:    network.FrameTypeData,
			ConnectionId: "ack-release",
			Payload:      make([]byte, 256),
		}
		if endpoint.cacheFrameLocked(route, frame) {
			t.Fatal("cache unexpectedly disabled below the configured limit")
		}
	}
	before := endpoint.cachedBytes
	if before == 0 || route.cachedBytes != before || len(route.framesBySeq) != 3 {
		t.Fatalf("unexpected initial cache state: endpoint=%d route=%d frames=%d", endpoint.cachedBytes, route.cachedBytes, len(route.framesBySeq))
	}

	partial := mustFrameAdapterAck(t, destinationID, route.totalFrames, []network.AckRange{{Start: 0, End: 1}})
	gotID, gotRoute, err := applyFrameAdapterAck(endpoint, streamTransportTCP, adapter, partial, now.Add(time.Second))
	if err != nil || gotID != logicalID || gotRoute != route {
		t.Fatalf("resolve partial ACK: logicalID=%d route=%p err=%v", gotID, gotRoute, err)
	}
	if endpoint.cachedBytes != before || route.cachedBytes != before || len(route.framesBySeq) != 3 || !route.completedAt.IsZero() {
		t.Fatalf("partial ACK released replay state: endpoint=%d route=%d frames=%d completed=%v", endpoint.cachedBytes, route.cachedBytes, len(route.framesBySeq), route.completedAt)
	}

	completedAt := now.Add(2 * time.Second)
	full := mustFrameAdapterAck(t, destinationID, route.totalFrames, network.FullAckRange(route.totalFrames))
	gotID, gotRoute, err = applyFrameAdapterAck(endpoint, streamTransportTCP, adapter, full, completedAt)
	if err != nil || gotID != logicalID || gotRoute != route {
		t.Fatalf("resolve full ACK: logicalID=%d route=%p err=%v", gotID, gotRoute, err)
	}
	if endpoint.cachedBytes != 0 || route.cachedBytes != 0 || route.framesBySeq != nil {
		t.Fatalf("full ACK did not release replay cache: endpoint=%d route=%d frames=%v", endpoint.cachedBytes, route.cachedBytes, route.framesBySeq)
	}
	if !route.completedAt.Equal(completedAt) {
		t.Fatalf("completedAt=%v, want %v", route.completedAt, completedAt)
	}
	if len(endpoint.routes) != 1 || len(endpoint.ackIDs) != 1 {
		t.Fatalf("full ACK must retain a lightweight tombstone: routes=%d ackIDs=%d", len(endpoint.routes), len(endpoint.ackIDs))
	}

	gotID, gotRoute, err = applyFrameAdapterAck(endpoint, streamTransportTCP, adapter, full, completedAt.Add(time.Second))
	if err != nil || gotID != logicalID || gotRoute != route {
		t.Fatalf("completed tombstone did not resolve repeated ACK: logicalID=%d route=%p err=%v", gotID, gotRoute, err)
	}
	if endpoint.cachedBytes != 0 || route.cachedBytes != 0 || route.framesBySeq != nil {
		t.Fatal("repeated ACK recreated replay cache")
	}
}

func TestDualFrameRelayEndpointSweepExpiredRemovesIndexes(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	adapter := &TcpFrameAdapter{}
	now := time.Unix(1_700_100_000, 0)

	addRoute := func(logicalID, sourceID, destinationID uint64, lastActive, completedAt time.Time) *dualFrameRoute {
		sourceKey := frameEndpointKey{kind: streamTransportTCP, adapter: adapter, connId: "ttl-conn", messageID: sourceID}
		route := &dualFrameRoute{
			kind:        streamTransportTCP,
			connId:      sourceKey.connId,
			endpoint:    adapter,
			dstID:       destinationID,
			totalFrames: 1,
			framesBySeq: make(map[uint32]*network.Frame),
			sourceKey:   &sourceKey,
			ackKeys:     make(map[frameEndpointKey]struct{}),
			createdAt:   lastActive,
			lastActive:  lastActive,
			completedAt: completedAt,
			generation:  1,
		}
		endpoint.routes[logicalID] = route
		endpoint.incomingIDs[sourceKey] = logicalID
		endpoint.bindAckKeyLocked(logicalID, route, streamTransportTCP, adapter, destinationID)
		if endpoint.cacheFrameLocked(route, &network.Frame{
			MessageId:    logicalID,
			TotalFrames:  1,
			FrameType:    network.FrameTypeData,
			ConnectionId: sourceKey.connId,
			Payload:      make([]byte, 64),
		}) {
			t.Fatal("cache unexpectedly disabled while constructing TTL fixture")
		}
		return route
	}

	expiredActive := addRoute(1, 101, 201, now.Add(-frameRelayRouteTTL-time.Second), time.Time{})
	expiredCompletedAt := now.Add(-frameRelayCompletedRouteTTL - time.Second)
	expiredCompleted := addRoute(2, 102, 202, expiredCompletedAt, expiredCompletedAt)
	fresh := addRoute(3, 103, 203, now.Add(-time.Second), time.Time{})
	freshBytes := fresh.cachedBytes

	endpoint.sweepExpiredLocked(now)
	if len(endpoint.routes) != 1 || endpoint.routes[3] != fresh {
		t.Fatalf("unexpected routes after sweep: %#v", endpoint.routes)
	}
	if len(endpoint.incomingIDs) != 1 || len(endpoint.ackIDs) != 1 {
		t.Fatalf("expired indexes were not removed together: incoming=%d ack=%d", len(endpoint.incomingIDs), len(endpoint.ackIDs))
	}
	if endpoint.cachedBytes != freshBytes {
		t.Fatalf("cachedBytes=%d, want fresh route bytes %d", endpoint.cachedBytes, freshBytes)
	}
	if expiredActive.framesBySeq != nil || expiredCompleted.framesBySeq != nil {
		t.Fatal("expired routes retained frame payloads")
	}

	endpoint.sweepExpiredLocked(now.Add(frameRelayRouteTTL))
	if len(endpoint.routes) != 0 || len(endpoint.incomingIDs) != 0 || len(endpoint.ackIDs) != 0 || endpoint.cachedBytes != 0 {
		t.Fatalf("final TTL sweep did not clear all state: routes=%d incoming=%d ack=%d bytes=%d", len(endpoint.routes), len(endpoint.incomingIDs), len(endpoint.ackIDs), endpoint.cachedBytes)
	}
}

func TestDualFrameRelayEndpointActiveRouteRefreshesIdleTTL(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	adapter := &TcpFrameAdapter{stream: &TcpStream{}}
	now := time.Unix(1_700_150_000, 0)
	first := &network.Frame{
		MessageId:    91,
		SeqId:        0,
		TotalFrames:  2,
		FrameType:    network.FrameTypeData,
		ConnectionId: "active-route",
	}

	endpoint.mu.Lock()
	logicalID, route, err := endpoint.resolveIncomingFrameLocked(streamTransportTCP, adapter, first, now)
	endpoint.mu.Unlock()
	if err != nil || route == nil {
		t.Fatalf("resolve first active frame: logicalID=%d route=%p err=%v", logicalID, route, err)
	}

	continuedAt := now.Add(frameRelayRouteTTL - time.Second)
	second := cloneFrame(first)
	second.SeqId = 1
	endpoint.mu.Lock()
	endpoint.sweepExpiredLocked(continuedAt)
	continuedID, continuedRoute, continueErr := endpoint.resolveIncomingFrameLocked(streamTransportTCP, adapter, second, continuedAt)
	endpoint.mu.Unlock()
	if continueErr != nil {
		t.Fatalf("continue active route before idle TTL: %v", continueErr)
	}
	if continuedID != logicalID || continuedRoute != route {
		t.Fatalf("active route was recreated before idle TTL: logicalID=%d/%d route=%p/%p", continuedID, logicalID, continuedRoute, route)
	}
	if !route.completedAt.IsZero() || !route.lastActive.Equal(continuedAt) {
		t.Fatalf("continued active route has invalid state: completed=%v lastActive=%v", route.completedAt, route.lastActive)
	}

	endpoint.mu.Lock()
	endpoint.sweepExpiredLocked(continuedAt.Add(frameRelayRouteTTL - time.Second))
	stillActive := endpoint.routes[logicalID] == route
	endpoint.sweepExpiredLocked(continuedAt.Add(frameRelayRouteTTL))
	expired := endpoint.routes[logicalID] == nil
	endpoint.mu.Unlock()
	if !stillActive || !expired {
		t.Fatalf("idle TTL lifecycle invalid: active-before-deadline=%v expired-at-deadline=%v", stillActive, expired)
	}
}

func TestDualFrameRelayEndpointCacheLimitDisablesReplay(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	adapter := &TcpFrameAdapter{}
	const logicalID uint64 = 19
	first := &network.Frame{
		MessageId:    logicalID,
		SeqId:        0,
		TotalFrames:  2,
		FrameType:    network.FrameTypeData,
		ConnectionId: "limited-cache",
		Payload:      make([]byte, 128),
	}
	limit := cachedFrameBytes(first)
	endpoint.maxBytes = limit
	endpoint.maxRouteBytes = limit
	route := &dualFrameRoute{
		kind:        streamTransportTCP,
		endpoint:    adapter,
		totalFrames: 2,
		framesBySeq: make(map[uint32]*network.Frame),
		createdAt:   time.Now(),
		lastActive:  time.Now(),
		generation:  3,
	}
	endpoint.routes[logicalID] = route

	if endpoint.cacheFrameLocked(route, first) {
		t.Fatal("first frame at the exact limit disabled replay")
	}
	if endpoint.cachedBytes != limit || route.cachedBytes != limit || endpoint.cachedBytes > endpoint.maxBytes {
		t.Fatalf("unexpected cache usage at limit: endpoint=%d route=%d limit=%d", endpoint.cachedBytes, route.cachedBytes, limit)
	}
	second := cloneFrame(first)
	second.SeqId = 1
	if !endpoint.cacheFrameLocked(route, second) {
		t.Fatal("frame exceeding the hard limit did not disable replay")
	}
	if !route.replayOff || endpoint.cachedBytes != 0 || route.cachedBytes != 0 || route.framesBySeq != nil {
		t.Fatalf("hard-limit fallback retained partial replay state: replayOff=%v endpoint=%d route=%d frames=%v", route.replayOff, endpoint.cachedBytes, route.cachedBytes, route.framesBySeq)
	}
	if endpoint.cacheFrameLocked(route, first) || endpoint.cachedBytes != 0 {
		t.Fatal("replay-disabled route accepted new cached frames")
	}

	err := endpoint.replayRoute(context.Background(), logicalID, streamTransportTCP, adapter, route.generation)
	if !errors.Is(err, errFrameRelayReplayCacheUnavailable) {
		t.Fatalf("replayRoute error=%v, want %v", err, errFrameRelayReplayCacheUnavailable)
	}
}

func TestDualFrameRelayEndpointAdapterIncarnationSeparatesIDs(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	oldAdapter := &TcpFrameAdapter{}
	newAdapter := &TcpFrameAdapter{}
	now := time.Unix(1_700_200_000, 0)
	frame := &network.Frame{
		MessageId:    1,
		TotalFrames:  1,
		FrameType:    network.FrameTypeData,
		ConnectionId: "same-connection",
		Payload:      []byte("payload"),
	}

	endpoint.mu.Lock()
	oldLogicalID, oldRoute, err := endpoint.resolveIncomingFrameLocked(streamTransportTCP, oldAdapter, frame, now)
	if err != nil {
		endpoint.mu.Unlock()
		t.Fatalf("resolve old adapter: %v", err)
	}
	repeatedLogicalID, repeatedRoute, err := endpoint.resolveIncomingFrameLocked(streamTransportTCP, oldAdapter, frame, now.Add(time.Second))
	if err != nil {
		endpoint.mu.Unlock()
		t.Fatalf("resolve repeated old adapter frame: %v", err)
	}
	newLogicalID, newRoute, err := endpoint.resolveIncomingFrameLocked(streamTransportTCP, newAdapter, frame, now.Add(2*time.Second))
	if err != nil {
		endpoint.mu.Unlock()
		t.Fatalf("resolve new adapter: %v", err)
	}
	if oldLogicalID != repeatedLogicalID || oldRoute != repeatedRoute {
		endpoint.mu.Unlock()
		t.Fatal("same adapter incarnation did not reuse its logical route")
	}
	if oldLogicalID == newLogicalID || oldRoute == newRoute {
		endpoint.mu.Unlock()
		t.Fatal("new adapter incarnation reused an old logical route")
	}

	endpoint.bindAckKeyLocked(oldLogicalID, oldRoute, streamTransportTCP, oldAdapter, 55)
	endpoint.bindAckKeyLocked(newLogicalID, newRoute, streamTransportTCP, newAdapter, 55)
	ack := &network.Frame{MessageId: 55, TotalFrames: 1, FrameType: network.FrameTypeAck}
	resolvedOldID, resolvedOldRoute, err := endpoint.resolveIncomingFrameLocked(streamTransportTCP, oldAdapter, ack, now.Add(3*time.Second))
	if err != nil {
		endpoint.mu.Unlock()
		t.Fatalf("resolve old adapter ACK: %v", err)
	}
	resolvedNewID, resolvedNewRoute, err := endpoint.resolveIncomingFrameLocked(streamTransportTCP, newAdapter, ack, now.Add(3*time.Second))
	endpoint.mu.Unlock()
	if err != nil {
		t.Fatalf("resolve new adapter ACK: %v", err)
	}
	if resolvedOldID != oldLogicalID || resolvedOldRoute != oldRoute {
		t.Fatalf("old ACK resolved to logicalID=%d route=%p", resolvedOldID, resolvedOldRoute)
	}
	if resolvedNewID != newLogicalID || resolvedNewRoute != newRoute {
		t.Fatalf("new ACK resolved to logicalID=%d route=%p", resolvedNewID, resolvedNewRoute)
	}
	if len(endpoint.incomingIDs) != 2 || len(endpoint.ackIDs) != 2 || len(endpoint.routes) != 2 {
		t.Fatalf("incarnation indexes unexpectedly collided: incoming=%d ack=%d routes=%d", len(endpoint.incomingIDs), len(endpoint.ackIDs), len(endpoint.routes))
	}
}

func TestDualFrameRelayEndpointAdapterReplacementRebindsAndReleases(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	oldAdapter := &TcpFrameAdapter{stream: &TcpStream{}}
	newAdapter := &TcpFrameAdapter{stream: &TcpStream{}}
	endpoint.adapters[streamTransportTCP] = oldAdapter
	now := time.Unix(1_700_250_000, 0)

	sourceFrame := &network.Frame{
		MessageId:    10,
		TotalFrames:  1,
		FrameType:    network.FrameTypeData,
		ConnectionId: "replacement-source",
	}
	sourceID, _, err := endpoint.resolveIncomingFrameLocked(streamTransportTCP, oldAdapter, sourceFrame, now)
	if err != nil {
		t.Fatalf("resolve source route: %v", err)
	}

	const outboundID uint64 = 100
	outbound := &dualFrameRoute{
		kind:        streamTransportTCP,
		endpoint:    oldAdapter,
		dstID:       20,
		totalFrames: 2,
		framesBySeq: make(map[uint32]*network.Frame),
		ackKeys:     make(map[frameEndpointKey]struct{}),
		createdAt:   now,
		lastActive:  now,
		generation:  1,
	}
	endpoint.routes[outboundID] = outbound
	endpoint.bindAckKeyLocked(outboundID, outbound, streamTransportTCP, oldAdapter, outbound.dstID)
	for sequence := uint32(0); sequence < outbound.totalFrames; sequence++ {
		if endpoint.cacheFrameLocked(outbound, &network.Frame{
			MessageId:    outboundID,
			SeqId:        sequence,
			TotalFrames:  outbound.totalFrames,
			FrameType:    network.FrameTypeData,
			ConnectionId: "replacement-outbound",
			Payload:      make([]byte, 128),
		}) {
			t.Fatal("replacement fixture unexpectedly disabled replay")
		}
	}

	const completedID uint64 = 200
	completed := &dualFrameRoute{
		kind:        streamTransportTCP,
		endpoint:    oldAdapter,
		dstID:       30,
		totalFrames: 1,
		ackKeys:     make(map[frameEndpointKey]struct{}),
		createdAt:   now,
		lastActive:  now,
		completedAt: now,
		generation:  1,
	}
	endpoint.routes[completedID] = completed
	endpoint.bindAckKeyLocked(completedID, completed, streamTransportTCP, oldAdapter, completed.dstID)

	endpoint.adapters[streamTransportTCP] = newAdapter
	jobs := endpoint.replaceAdapterLocked(streamTransportTCP, oldAdapter, newAdapter, now.Add(time.Second))
	if len(jobs) != 1 || jobs[0].logicalID != outboundID || len(jobs[0].frames) != 2 {
		t.Fatalf("unexpected replacement jobs: %#v", jobs)
	}
	if endpoint.routes[sourceID] != nil || endpoint.routes[completedID] != nil {
		t.Fatal("replacement retained old source/completed routes")
	}
	if endpoint.routes[outboundID] != outbound || outbound.endpoint != newAdapter || outbound.generation != 2 {
		t.Fatal("active outbound route was not rebound to the new adapter")
	}
	if len(outbound.ackKeys) != 1 {
		t.Fatalf("replacement retained stale ACK keys: %d", len(outbound.ackKeys))
	}
	for key := range endpoint.incomingIDs {
		if key.adapter == oldAdapter {
			t.Fatal("replacement retained old incoming adapter index")
		}
	}
	for key := range endpoint.ackIDs {
		if key.adapter == oldAdapter {
			t.Fatal("replacement retained old ACK adapter index")
		}
	}

	full := mustFrameAdapterAck(t, outbound.dstID, outbound.totalFrames, network.FullAckRange(outbound.totalFrames))
	resolvedID, resolvedRoute, err := applyFrameAdapterAck(endpoint, streamTransportTCP, newAdapter, full, now.Add(2*time.Second))
	if err != nil || resolvedID != outboundID || resolvedRoute != outbound {
		t.Fatalf("resolve replacement ACK: logicalID=%d route=%p err=%v", resolvedID, resolvedRoute, err)
	}
	if endpoint.cachedBytes != 0 || outbound.cachedBytes != 0 || outbound.framesBySeq != nil {
		t.Fatal("replacement ACK did not release replay payload")
	}
}

func TestDualFrameRelayEndpointThousandAckedMessagesReleaseCache(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	endpoint.maxRoutes = 1_100
	adapter := &TcpFrameAdapter{}
	now := time.Unix(1_700_300_000, 0)
	const messageCount = 1_000

	for messageIndex := 1; messageIndex <= messageCount; messageIndex++ {
		logicalID := uint64(messageIndex)
		destinationID := uint64(10_000 + messageIndex)
		route := &dualFrameRoute{
			kind:        streamTransportTCP,
			endpoint:    adapter,
			dstID:       destinationID,
			totalFrames: 1,
			framesBySeq: make(map[uint32]*network.Frame),
			ackKeys:     make(map[frameEndpointKey]struct{}),
			createdAt:   now,
			lastActive:  now,
			generation:  1,
		}
		endpoint.routes[logicalID] = route
		endpoint.bindAckKeyLocked(logicalID, route, streamTransportTCP, adapter, destinationID)
		frame := &network.Frame{
			MessageId:    logicalID,
			TotalFrames:  1,
			FrameType:    network.FrameTypeData,
			ConnectionId: "long-transfer",
			Payload:      make([]byte, 1_024),
		}
		if endpoint.cacheFrameLocked(route, frame) {
			t.Fatalf("message %d unexpectedly disabled replay", messageIndex)
		}
		if endpoint.cachedBytes == 0 {
			t.Fatalf("message %d was not cached before ACK", messageIndex)
		}

		now = now.Add(time.Microsecond)
		ack := mustFrameAdapterAck(t, destinationID, 1, network.FullAckRange(1))
		resolvedID, resolvedRoute, err := applyFrameAdapterAck(endpoint, streamTransportTCP, adapter, ack, now)
		if err != nil || resolvedID != logicalID || resolvedRoute != route {
			t.Fatalf("message %d ACK resolution: logicalID=%d route=%p err=%v", messageIndex, resolvedID, resolvedRoute, err)
		}
		if endpoint.cachedBytes != 0 || route.cachedBytes != 0 || route.framesBySeq != nil {
			t.Fatalf("message %d retained replay bytes: endpoint=%d route=%d frames=%v", messageIndex, endpoint.cachedBytes, route.cachedBytes, route.framesBySeq)
		}
	}

	if len(endpoint.routes) != messageCount || len(endpoint.ackIDs) != messageCount {
		t.Fatalf("unexpected tombstone count: routes=%d ack=%d", len(endpoint.routes), len(endpoint.ackIDs))
	}
	endpoint.sweepExpiredLocked(now.Add(frameRelayCompletedRouteTTL))
	if endpoint.cachedBytes != 0 || len(endpoint.routes) != 0 || len(endpoint.ackIDs) != 0 || len(endpoint.incomingIDs) != 0 {
		t.Fatalf("expired long-transfer state not cleared: bytes=%d routes=%d ack=%d incoming=%d", endpoint.cachedBytes, len(endpoint.routes), len(endpoint.ackIDs), len(endpoint.incomingIDs))
	}
}

func TestDualFrameRelayEndpointClosedRejectsNewState(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	endpoint.closed = true
	endpoint.incoming <- &network.Frame{MessageId: 1, TotalFrames: 1, FrameType: network.FrameTypeData}

	if frame, err := endpoint.NextFrame(context.Background()); err == nil || frame != nil {
		t.Fatalf("closed NextFrame = (%v, %v), want error", frame, err)
	}
	if err := endpoint.HandleFrame(context.Background(), &network.Frame{MessageId: 1, TotalFrames: 1, FrameType: network.FrameTypeData}); err == nil {
		t.Fatal("closed HandleFrame accepted a new route")
	}
	if len(endpoint.routes) != 0 || len(endpoint.incomingIDs) != 0 || len(endpoint.ackIDs) != 0 || endpoint.cachedBytes != 0 {
		t.Fatalf("closed endpoint retained state: routes=%d incoming=%d ack=%d bytes=%d", len(endpoint.routes), len(endpoint.incomingIDs), len(endpoint.ackIDs), endpoint.cachedBytes)
	}
}

func TestDualFrameRelayEndpointDetachRemovesReplayDisabledRoute(t *testing.T) {
	endpoint := newFrameAdapterCacheTestEndpoint()
	oldAdapter := &TcpFrameAdapter{stream: &TcpStream{}}
	endpoint.adapters[streamTransportTCP] = oldAdapter
	endpoint.routes[1] = &dualFrameRoute{
		kind:        streamTransportTCP,
		endpoint:    oldAdapter,
		totalFrames: 2,
		ackKeys:     make(map[frameEndpointKey]struct{}),
		createdAt:   time.Now(),
		lastActive:  time.Now(),
		generation:  1,
		replayOff:   true,
	}

	endpoint.onLegDetached(streamTransportTCP, oldAdapter.stream)
	if len(endpoint.routes) != 0 || len(endpoint.adapters) != 0 || len(endpoint.ackIDs) != 0 || endpoint.cachedBytes != 0 {
		t.Fatalf("detach retained replay-disabled state: routes=%d adapters=%d ack=%d bytes=%d", len(endpoint.routes), len(endpoint.adapters), len(endpoint.ackIDs), endpoint.cachedBytes)
	}
}
