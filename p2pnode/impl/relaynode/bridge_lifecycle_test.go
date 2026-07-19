package relaynode

import (
	"bnfs_p2p/networkFrameWork"
	"context"
	"testing"
	"time"
)

func TestReleaseLocalBridgeWhenDoneRemovesOnlyMatchingEntry(t *testing.T) {
	tests := []struct {
		name        string
		replace     bool
		wantPresent bool
	}{
		{name: "completed entry", wantPresent: false},
		{name: "replacement entry", replace: true, wantPresent: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bridgeContext, cancelBridge := context.WithCancel(context.Background())
			bridge := networkFrameWork.NewCrossRelayBridge(bridgeContext, "peer", "target", "origin", "connection")
			entry := &localBridgeEntry{bridge: bridge, bridged: true, kcpReady: make(chan struct{})}
			node := &RelayNode{localLegs: map[string]*localBridgeEntry{"connection": entry}}
			done := make(chan struct{})
			go func() {
				node.releaseLocalBridgeWhenDone("connection", entry, bridge)
				close(done)
			}()

			var replacement *localBridgeEntry
			if test.replace {
				replacement = &localBridgeEntry{kcpReady: make(chan struct{})}
				node.localLegs["connection"] = replacement
			}
			cancelBridge()

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("bridge completion cleanup did not finish")
			}
			node.mu.RLock()
			current, present := node.localLegs["connection"]
			node.mu.RUnlock()
			if present != test.wantPresent {
				t.Fatalf("entry presence = %v, want %v", present, test.wantPresent)
			}
			if test.wantPresent && current != replacement {
				t.Fatal("old bridge cleanup removed or replaced the new entry")
			}
		})
	}
}
