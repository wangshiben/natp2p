package networkFrameWork

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type idleLifecycleCarrier struct {
	*lifecycleCarrier
	lastReceiveMicros atomic.Int64
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

func TestTransportCoverBurstRegistrationsAreFullyReaped(t *testing.T) {
	const groupCount = 256
	cover := NewTransportCover()
	cover.SetRegistrationIdlePolicy(30*time.Millisecond, 3*time.Millisecond)
	var unregistered atomic.Int64
	cover.SetUnregisterHook(func(string) { unregistered.Add(1) })

	for index := 0; index < groupCount; index++ {
		relay := newIdleLifecycleCarrier(fmt.Sprintf("burst-registration-%03d", index))
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
