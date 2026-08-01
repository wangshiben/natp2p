package natnode

import (
	"bnfs_p2p/networkFrameWork"
	"testing"
)

func TestFixedRelayDialPolicyKeepsDirectAddressAndReconnectGate(t *testing.T) {
	gate := networkFrameWork.NewHTTPReconnectGate("http://127.0.0.1:18912", "test-token")
	policy := fixedRelayDialPolicy{address: "relay.test:9000", gate: gate, role: "natserver"}

	target, err := policy.CurrentRelay()
	if err != nil {
		t.Fatalf("CurrentRelay: %v", err)
	}
	if target.Address != "relay.test:9000" || target.Generation != 0 {
		t.Fatalf("direct relay target = %+v", target)
	}
	if policy.ReconnectGate() != gate {
		t.Fatal("fixed direct relay policy lost reconnect gate")
	}
	if policy.ReconnectRole() != "natserver" {
		t.Fatalf("reconnect role = %q", policy.ReconnectRole())
	}
}
