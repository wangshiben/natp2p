package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type idleLifecycleCarrier struct {
	*lifecycleCarrier
	lastReceiveMicros atomic.Int64
	unhealthy         atomic.Bool
}

func newIdleLifecycleCarrier(nodeID string) *idleLifecycleCarrier {
	carrier := &idleLifecycleCarrier{lifecycleCarrier: newLifecycleCarrier(nodeID, "")}
	carrier.touch()
	return carrier
}

func (c *idleLifecycleCarrier) touch() {
	c.lastReceiveMicros.Store(time.Now().UnixMicro())
}

func (c *idleLifecycleCarrier) LatestReceiveTime() time.Time {
	return time.UnixMicro(c.lastReceiveMicros.Load())
}

func (c *idleLifecycleCarrier) IsClosed() bool {
	return c.unhealthy.Load()
}

func newIdleLifecycleGroup(relay *idleLifecycleCarrier) *StreamGroup {
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

func TestTransportCoverReapsSilentRegistrationGroup(t *testing.T) {
	cover := NewTransportCover()
	cover.SetRegistrationIdlePolicy(40*time.Millisecond, 5*time.Millisecond)
	relay := newIdleLifecycleCarrier("silent-registration")
	relay.unhealthy.Store(true)
	group := newIdleLifecycleGroup(relay)
	cover.StreamGroup[group.nodeId] = group
	unregistered := make(chan string, 1)
	cover.SetUnregisterHook(func(nodeID string) { unregistered <- nodeID })
	go cover.listenGroup(group.nodeId, group)

	waitLifecycleCondition(t, time.Second, func() bool { return !cover.HasGroup(group.nodeId) })
	select {
	case nodeID := <-unregistered:
		if nodeID != group.nodeId {
			t.Fatalf("unregistered node = %q, want %q", nodeID, group.nodeId)
		}
	case <-time.After(time.Second):
		t.Fatal("silent registration cleanup did not invoke unregister hook")
	}
}

func TestTransportCoverReapsOpenDualRegistrationAfterReceiveStops(t *testing.T) {
	cover := NewTransportCover()
	cover.SetRegistrationIdlePolicy(40*time.Millisecond, 5*time.Millisecond)
	relay := newIdleLifecycleCarrier("stale-open-registration")
	relay.lastReceiveMicros.Store(time.Now().Add(-time.Second).UnixMicro())
	dual := newDualStreamWithPump(relay.NodeId(), "", false)
	dual.legs[streamTransportKCP] = &legEntry{
		id: streamTransportKCP, family: streamTransportKCP, stream: relay,
	}
	dual.legOrder = []streamTransport{streamTransportKCP}
	dual.preferred = streamTransportKCP
	group := newIdleLifecycleGroup(relay)
	group.relayStream = dual
	cover.StreamGroup[group.nodeId] = group
	unregistered := make(chan string, 1)
	cover.SetUnregisterHook(func(nodeID string) { unregistered <- nodeID })
	go cover.listenGroup(group.nodeId, group)

	waitLifecycleCondition(t, time.Second, func() bool { return !cover.HasGroup(group.nodeId) })
	select {
	case nodeID := <-unregistered:
		if nodeID != group.nodeId {
			t.Fatalf("unregistered node = %q, want %q", nodeID, group.nodeId)
		}
	case <-time.After(time.Second):
		t.Fatal("stale open dual registration did not invoke unregister hook")
	}
}

func TestTransportCoverKeepsLiveSilentRegistrationAndAcceptsBusiness(t *testing.T) {
	cover := NewTransportCover()
	cover.SetRegistrationIdlePolicy(40*time.Millisecond, 5*time.Millisecond)
	relay := newRelaySlotTestTCPStream(t, "live-silent-registration")
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	cover.StreamGroup[group.nodeId] = group
	go cover.listenGroup(group.nodeId, group)

	time.Sleep(120 * time.Millisecond)
	if !cover.HasGroup(group.nodeId) {
		t.Fatal("live registration was reaped solely because it remained silent")
	}

	client := newRelaySlotTestTCPStream(t, "business-client")
	SetStreamIdentity(client, "business-client", "business-after-idle")
	first := &network.Message{Header: &network.Header{
		NodeId:       group.nodeId,
		ConnectionId: client.ConnectionId(),
	}}
	if _, err := group.StreamOn(client, first); err != nil {
		t.Fatalf("business connection after registration idle timeout failed: %v", err)
	}
	group.Close()
	waitLifecycleCondition(t, time.Second, func() bool { return !cover.HasGroup(group.nodeId) })
}

func TestTransportCoverDoesNotReapActiveRegistrationGroup(t *testing.T) {
	cover := NewTransportCover()
	cover.SetRegistrationIdlePolicy(45*time.Millisecond, 5*time.Millisecond)
	relay := newIdleLifecycleCarrier("active-registration")
	group := newIdleLifecycleGroup(relay)
	cover.StreamGroup[group.nodeId] = group
	go cover.listenGroup(group.nodeId, group)

	deadline := time.Now().Add(180 * time.Millisecond)
	for time.Now().Before(deadline) {
		relay.touch()
		time.Sleep(10 * time.Millisecond)
	}
	if !cover.HasGroup(group.nodeId) {
		t.Fatal("active registration group was reaped")
	}
	group.Close()
	waitLifecycleCondition(t, time.Second, func() bool { return !cover.HasGroup(group.nodeId) })
}

func TestTransportCoverUnregisterHookCannotRemoveReplacement(t *testing.T) {
	cover := NewTransportCover()
	cover.SetRegistrationIdlePolicy(0, 0)
	unregistered := make(chan string, 2)
	cover.SetUnregisterHook(func(nodeID string) { unregistered <- nodeID })

	oldRelay := newIdleLifecycleCarrier("replacement-registration")
	oldGroup := newIdleLifecycleGroup(oldRelay)
	cover.StreamGroup[oldGroup.nodeId] = oldGroup
	go cover.listenGroup(oldGroup.nodeId, oldGroup)
	<-oldRelay.nextStarted

	newRelay := newIdleLifecycleCarrier(oldGroup.nodeId)
	newGroup := newIdleLifecycleGroup(newRelay)
	cover.lock.Lock()
	cover.StreamGroup[newGroup.nodeId] = newGroup
	cover.lock.Unlock()
	go cover.listenGroup(newGroup.nodeId, newGroup)
	<-newRelay.nextStarted
	oldGroup.Close()
	time.Sleep(30 * time.Millisecond)
	select {
	case nodeID := <-unregistered:
		t.Fatalf("old generation invoked unregister hook for %q", nodeID)
	default:
	}
	if !cover.HasGroup(newGroup.nodeId) {
		t.Fatal("old generation removed replacement group")
	}

	newGroup.Close()
	select {
	case nodeID := <-unregistered:
		if nodeID != newGroup.nodeId {
			t.Fatalf("replacement unregister node = %q", nodeID)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement group did not invoke unregister hook")
	}
}

func TestTransportCoverBlockingUnregisterHookDoesNotBlockBusinessRegistry(t *testing.T) {
	cover := NewTransportCover()
	cover.SetRegistrationIdlePolicy(0, 0)
	hookStarted := make(chan struct{})
	releaseHook := make(chan struct{})
	var started sync.Once
	cover.SetUnregisterHook(func(string) {
		started.Do(func() { close(hookStarted) })
		<-releaseHook
	})

	relay := newIdleLifecycleCarrier("blocking-unregister")
	group := newIdleLifecycleGroup(relay)
	cover.lock.Lock()
	cover.StreamGroup[group.nodeId] = group
	cover.lock.Unlock()
	go cover.listenGroup(group.nodeId, group)
	<-relay.nextStarted
	group.Close()
	select {
	case <-hookStarted:
	case <-time.After(time.Second):
		t.Fatal("blocking unregister hook did not start")
	}

	// HasGroup uses the same registry lock as the business StreamOn lookup. A blocking
	// control-plane hook must not retain that lock and globally stall new sessions.
	lookupDone := make(chan bool, 1)
	go func() { lookupDone <- cover.HasGroup("unrelated-business-target") }()
	select {
	case <-lookupDone:
	case <-time.After(100 * time.Millisecond):
		close(releaseHook)
		t.Fatal("blocking unregister hook retained the TransportCover registry lock")
	}
	close(releaseHook)
}

func TestDualStreamLatestReceiveTimeUsesNewestPhysicalLeg(t *testing.T) {
	older := newIdleLifecycleCarrier("dual-activity")
	newer := newIdleLifecycleCarrier("dual-activity")
	olderTime := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	newerTime := time.Now().Add(-time.Second).Truncate(time.Microsecond)
	older.lastReceiveMicros.Store(olderTime.UnixMicro())
	newer.lastReceiveMicros.Store(newerTime.UnixMicro())

	dual := newDualStreamWithPump("dual-activity", "", false)
	dual.legs[streamTransportKCP] = &legEntry{id: streamTransportKCP, family: streamTransportKCP, stream: older}
	dual.legs[streamTransportTCP] = &legEntry{id: streamTransportTCP, family: streamTransportTCP, stream: newer}
	dual.legOrder = []streamTransport{streamTransportKCP, streamTransportTCP}
	t.Cleanup(func() { _ = dual.Close() })

	if got := dual.LatestReceiveTime(); !got.Equal(newerTime) {
		t.Fatalf("latest receive = %s, want %s", got, newerTime)
	}
}

func TestDualStreamStaleRequiresOrphanedKCP(t *testing.T) {
	kcp := newIdleLifecycleCarrier("orphaned-kcp")
	kcp.lastReceiveMicros.Store(time.Now().Add(-3 * time.Second).UnixMicro())
	dual := newDualStreamWithPump(kcp.NodeId(), "", false)
	dual.legs[streamTransportKCP] = &legEntry{id: streamTransportKCP, family: streamTransportKCP, stream: kcp}
	dual.legOrder = []streamTransport{streamTransportKCP}
	t.Cleanup(func() { _ = dual.Close() })

	if !dual.isStale(2 * time.Second) {
		t.Fatal("orphaned KCP stream with no recent receive was not classified as stale")
	}
	tcp := newIdleLifecycleCarrier("orphaned-kcp")
	tcp.lastReceiveMicros.Store(time.Now().Add(-3 * time.Second).UnixMicro())
	dual.legs[streamTransportTCP] = &legEntry{id: streamTransportTCP, family: streamTransportTCP, stream: tcp}
	dual.legOrder = append(dual.legOrder, streamTransportTCP)
	if dual.isStale(2 * time.Second) {
		t.Fatal("open TCP backup did not protect a silent KCP carrier")
	}
	tcp.unhealthy.Store(true)
	if !dual.isStale(2 * time.Second) {
		t.Fatal("closed TCP backup kept an orphaned KCP carrier alive")
	}
}

func TestTransportCoverBurstRegistrationsAreFullyReaped(t *testing.T) {
	const groupCount = 256
	cover := NewTransportCover()
	cover.SetRegistrationIdlePolicy(30*time.Millisecond, 3*time.Millisecond)
	var unregistered atomic.Int64
	cover.SetUnregisterHook(func(string) { unregistered.Add(1) })

	for index := 0; index < groupCount; index++ {
		relay := newIdleLifecycleCarrier(fmt.Sprintf("burst-registration-%03d", index))
		relay.unhealthy.Store(true)
		group := newIdleLifecycleGroup(relay)
		cover.lock.Lock()
		cover.StreamGroup[group.nodeId] = group
		cover.lock.Unlock()
		go cover.listenGroup(group.nodeId, group)
	}

	waitLifecycleCondition(t, 3*time.Second, func() bool {
		cover.lock.RLock()
		groupTotal := len(cover.StreamGroup)
		cover.lock.RUnlock()
		return groupTotal == 0 && unregistered.Load() == groupCount
	})
	waitLifecycleCondition(t, time.Second, func() bool {
		cover.lock.RLock()
		running := cover.idleSweeperRunning
		cover.lock.RUnlock()
		return !running
	})
}
