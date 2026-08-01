package relaynode

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"bnfs_p2p/p2pnode/impl/natnode"
)

func signedHostRouteForTest(t *testing.T, origin *RelayNode, target string) hostRouteWire {
	t.Helper()
	now := time.Now()
	route := hostRouteWire{
		Target: target, RelayID: origin.idStr(), RelayPublicKey: origin.pubKeyHex(),
		Addr: origin.getAddr(), Incarnation: "test-incarnation", Sequence: 1,
		IssuedAt: now.UnixNano(), LeaseUntil: now.Add(hostRouteLease).UnixNano(), Active: true,
		Path: []string{origin.idStr()},
	}
	signature, err := signHostRoute(origin.privKey, route)
	if err != nil {
		t.Fatalf("sign host route: %v", err)
	}
	route.Signature = signature
	return route
}

func TestHostRouteRejectsTamperedOriginAnnouncement(t *testing.T) {
	origin, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9001")
	if err != nil {
		t.Fatalf("create origin Relay: %v", err)
	}
	defer origin.Close()
	receiver, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9002")
	if err != nil {
		t.Fatalf("create receiver Relay: %v", err)
	}
	defer receiver.Close()

	route := signedHostRouteForTest(t, origin, strings.Repeat("a", 64))
	if accepted, _ := receiver.acceptHostRoute(origin.idStr(), route); !accepted {
		t.Fatal("valid signed host route was rejected")
	}
	tampered := cloneHostRoute(route)
	tampered.Sequence++
	if accepted, _ := receiver.acceptHostRoute(origin.idStr(), tampered); accepted {
		t.Fatal("tampered host route was accepted")
	}
}

func TestHostRouteTransitRequiresMultipleOriginRelays(t *testing.T) {
	originOne, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9011")
	if err != nil {
		t.Fatalf("create first origin Relay: %v", err)
	}
	defer originOne.Close()
	originTwo, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9012")
	if err != nil {
		t.Fatalf("create second origin Relay: %v", err)
	}
	defer originTwo.Close()
	receiver, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9013")
	if err != nil {
		t.Fatalf("create receiver Relay: %v", err)
	}
	defer receiver.Close()
	target := strings.Repeat("1", 64)

	if accepted, becameMultipath := receiver.acceptHostRoute(originOne.idStr(), signedHostRouteForTest(t, originOne, target)); !accepted || becameMultipath {
		t.Fatalf("first route result: accepted=%t becameMultipath=%t", accepted, becameMultipath)
	}
	if receiver.hostRouteTransitEnabled(target) {
		t.Fatal("single-origin target was exposed for multi-hop transit")
	}
	if routes := receiver.hostRouteSnapshot(time.Now()); len(routes) != 0 {
		t.Fatalf("single-origin learned routes in sync snapshot=%d, want 0", len(routes))
	}

	if accepted, becameMultipath := receiver.acceptHostRoute(originTwo.idStr(), signedHostRouteForTest(t, originTwo, target)); !accepted || !becameMultipath {
		t.Fatalf("second route result: accepted=%t becameMultipath=%t", accepted, becameMultipath)
	}
	if !receiver.hostRouteTransitEnabled(target) {
		t.Fatal("multi-origin target was not exposed for multi-hop transit")
	}
	if routes := receiver.hostRouteSnapshot(time.Now()); len(routes) != 2 {
		t.Fatalf("multi-origin learned routes in sync snapshot=%d, want 2", len(routes))
	}
}

func TestHostWithdrawalOnlyRemovesSendingNeighborRoute(t *testing.T) {
	receiver, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9003")
	if err != nil {
		t.Fatalf("create receiver Relay: %v", err)
	}
	defer receiver.Close()
	target := strings.Repeat("b", 64)
	relayA := strings.Repeat("c", 64)
	relayB := strings.Repeat("d", 64)
	receiver.mu.Lock()
	receiver.hostRoutes[target] = map[string]hostRouteRecord{
		relayA: {wire: hostRouteWire{Target: target, RelayID: relayA, Active: true}, via: "neighbor-a"},
		relayB: {wire: hostRouteWire{Target: target, RelayID: relayB, Active: true}, via: "neighbor-b"},
	}
	receiver.mu.Unlock()
	link := &peerLink{peerID: "neighbor-a"}
	receiver.receiveHostWithdrawals(link, []hostRouteKey{{Target: target, RelayID: relayB}})
	receiver.mu.RLock()
	_, relayAExists := receiver.hostRoutes[target][relayA]
	_, relayBExists := receiver.hostRoutes[target][relayB]
	receiver.mu.RUnlock()
	if !relayAExists || !relayBExists {
		t.Fatal("neighbor withdrawal removed a route learned from another peer")
	}
	receiver.receiveHostWithdrawals(link, []hostRouteKey{{Target: target, RelayID: relayA}})
	receiver.mu.RLock()
	_, relayAExists = receiver.hostRoutes[target][relayA]
	_, relayBExists = receiver.hostRoutes[target][relayB]
	receiver.mu.RUnlock()
	if relayAExists || !relayBExists {
		t.Fatal("neighbor withdrawal did not remove exactly its own route")
	}
}

func TestHostWithdrawalRejectsNonCanonicalNodeIDs(t *testing.T) {
	receiver, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9004")
	if err != nil {
		t.Fatalf("create receiver Relay: %v", err)
	}
	defer receiver.Close()
	target := strings.Repeat("e", 64)
	relayID := strings.Repeat("f", 64)
	receiver.mu.Lock()
	receiver.hostRoutes[target] = map[string]hostRouteRecord{
		relayID: {wire: hostRouteWire{Target: target, RelayID: relayID, Active: true}, via: "neighbor-a"},
	}
	receiver.mu.Unlock()
	link := &peerLink{peerID: "neighbor-a"}
	receiver.receiveHostWithdrawals(link, []hostRouteKey{
		{Target: "not-a-node-id", RelayID: relayID},
		{Target: target, RelayID: "not-a-relay-id"},
	})
	receiver.mu.RLock()
	_, exists := receiver.hostRoutes[target][relayID]
	receiver.mu.RUnlock()
	if !exists {
		t.Fatal("non-canonical withdrawal removed a valid route")
	}
}

func TestBlockedHostRouteBroadcastDoesNotDelaySuccessorNatRegistration(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	relayAddr := reserveMultiRelayTestAddr(t)
	relay := startRelay(t, relayAddr, relayAddr)
	defer relay.Close()

	blocked := make(chan struct{})
	release := make(chan struct{})
	var started sync.Once
	linkCtx, linkCancel := context.WithCancel(relay.ctx)
	defer linkCancel()
	blockedLink := &peerLink{
		owner: relay, outbound: true, peerID: strings.Repeat("f", 64),
		ctx: linkCtx, cancel: linkCancel,
	}
	relay.mu.Lock()
	relay.hostRouteBroadcastSend = func(ctx context.Context, _ *peerLink, _ *controlMessage) error {
		started.Do(func() { close(blocked) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}
	relay.inboundLinks = append(relay.inboundLinks, blockedLink)
	relay.mu.Unlock()

	first, err := natnode.NewNATNode(nil, relayAddr)
	if err != nil {
		t.Fatalf("create first NAT node: %v", err)
	}
	defer first.Close()
	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	firstResult := make(chan error, 1)
	go func() { firstResult <- first.Listen(firstCtx, relayAddr) }()

	select {
	case <-blocked:
	case err := <-firstResult:
		t.Fatalf("first NAT registration exited before route broadcast blocked: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("first host-route broadcast did not reach the blocked control link")
	}

	second, err := natnode.NewNATNode(nil, relayAddr)
	if err != nil {
		t.Fatalf("create successor NAT node: %v", err)
	}
	defer second.Close()
	secondCtx, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	secondResult := make(chan error, 1)
	startedAt := time.Now()
	go func() { secondResult <- second.Listen(secondCtx, relayAddr) }()

	deadline := time.NewTimer(1200 * time.Millisecond)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !relay.starter.Cover().HasGroup(string(second.ID())) {
		select {
		case err := <-secondResult:
			t.Fatalf("successor NAT registration exited: %v", err)
		case <-deadline.C:
			t.Fatalf("successor NAT registration was blocked by route broadcast for %v", time.Since(startedAt))
		case <-ticker.C:
		}
	}
	if elapsed := time.Since(startedAt); elapsed >= 1200*time.Millisecond {
		t.Fatalf("successor NAT registration took %v, want <1.2s", elapsed)
	}
	close(release)
}

func TestHostRouteBroadcastQueuePreservesLocalRouteGenerationOrder(t *testing.T) {
	relay, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9005")
	if err != nil {
		t.Fatalf("create Relay: %v", err)
	}
	defer relay.Close()

	linkCtx, linkCancel := context.WithCancel(relay.ctx)
	defer linkCancel()
	blockedLink := &peerLink{
		owner: relay, outbound: true, peerID: strings.Repeat("e", 64),
		ctx: linkCtx, cancel: linkCancel,
	}
	delivered := make(chan []bool, 2)
	relay.mu.Lock()
	relay.hostRouteBroadcastSend = func(_ context.Context, _ *peerLink, message *controlMessage) error {
		states := make([]bool, 0, len(message.Routes))
		for _, route := range message.Routes {
			states = append(states, route.Active)
		}
		delivered <- states
		return nil
	}
	relay.inboundLinks = append(relay.inboundLinks, blockedLink)
	relay.mu.Unlock()

	target := strings.Repeat("d", 64)
	relay.publishLocalHostRoute(target, false)
	relay.publishLocalHostRoute(target, true)
	states := make([]bool, 0, 2)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(states) < 2 {
		select {
		case batch := <-delivered:
			states = append(states, batch...)
		case <-deadline.C:
			t.Fatalf("queued route generations=%v, want [false true]", states)
		}
	}
	if len(states) != 2 || states[0] || !states[1] {
		t.Fatalf("route generation order=%v, want [false true]", states)
	}
}
