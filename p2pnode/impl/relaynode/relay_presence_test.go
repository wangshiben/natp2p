package relaynode

import (
	"bnfs_p2p/DHTable"
	"context"
	"fmt"
	"testing"
	"time"
)

func TestRelayNodeCloseWithTrackedPeerDoesNotDeadlock(t *testing.T) {
	node, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	defer node.cancel()
	peerID := fmt.Sprintf("%064x", 42)
	node.relayNodes.AddNode(DHTable.NewNodeFromPeerID(peerID))
	node.relayLinkUp(peerID)

	linkContext, cancel := context.WithCancel(node.ctx)
	link := &peerLink{
		owner: node, addr: "127.0.0.1:9001", outbound: true,
		peerID: peerID, countedUp: true, ctx: linkContext, cancel: cancel,
	}
	node.mu.Lock()
	node.peerLinks[link.addr] = link
	node.mu.Unlock()

	done := make(chan struct{})
	go func() {
		node.closePeerLinks()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RelayNode.Close 与 relayLinkDown 发生锁死")
	}
}

func TestRelayPresenceResetsContinuousTimeAfterAllLinksDown(t *testing.T) {
	node, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	defer node.cancel()
	peerID := fmt.Sprintf("%064x", 43)
	node.relayNodes.AddNode(DHTable.NewNodeFromPeerID(peerID))
	node.relayLinkUp(peerID)
	first := node.relayPresence(peerID).ContinuousOnlineSince
	node.relayLinkUp(peerID)
	node.relayLinkDown(peerID)
	if node.relayPresence(peerID).ContinuousOnlineSince != first {
		t.Fatal("仍有活动控制链路时不应重置连续在线时间")
	}
	node.relayLinkDown(peerID)

	node.mu.Lock()
	node.relayOnlineSince[peerID] = time.Unix(first-10, 0)
	node.mu.Unlock()
	node.relayLinkUp(peerID)
	if got := node.relayPresence(peerID).ContinuousOnlineSince; got <= first-10 {
		t.Fatalf("全部链路断开后重新上线应重置连续在线时间: old=%d new=%d", first-10, got)
	}

	node.closePeerLinks()
}

func TestRelayAddressReassignmentRemovesStaleIdentity(t *testing.T) {
	node, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	defer node.cancel()
	oldPeerID := fmt.Sprintf("%064x", 44)
	newPeerID := fmt.Sprintf("%064x", 45)
	peerAddr := "192.0.2.44:9000"

	node.onPeerHello(oldPeerID, peerAddr, "")
	node.relayLinkUp(oldPeerID)
	node.onPeerHello(newPeerID, peerAddr, "")

	neighbors := node.RelayNeighbors()
	if len(neighbors) != 1 || string(neighbors[0].ID) != newPeerID {
		t.Fatalf("同一 Relay 地址重新绑定后应只保留新身份: %+v", neighbors)
	}
	node.mu.RLock()
	_, oldAddressExists := node.peerIDToAddr[oldPeerID]
	_, oldPresenceExists := node.relayOnlineSince[oldPeerID]
	node.mu.RUnlock()
	if oldAddressExists || oldPresenceExists {
		t.Fatal("旧 Relay 身份的地址或在线状态未清理")
	}
}
