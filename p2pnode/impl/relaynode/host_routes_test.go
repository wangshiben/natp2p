package relaynode

import (
	"strings"
	"testing"
	"time"
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
