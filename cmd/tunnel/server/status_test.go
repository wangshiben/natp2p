package main

import (
	"bnfs_p2p/p2pnode/impl/natnode"

	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteServiceListenerStatusRedactsIdentifiers(t *testing.T) {
	file := filepath.Join(t.TempDir(), "private", "service-listener.json")
	snapshot := natnode.ServiceListenerSnapshot{
		RelayAddress:      "relay03:9000",
		CarrierConnected:  true,
		CarrierGeneration: 2,
		ActiveSessions:    1,
		MaxSessions:       8,
		AcceptQueueDepth:  1,
		AcceptQueue:       8,
		AcceptedTotal:     7,
		RejectedTotal:     2,
		Carriers: []natnode.ServiceCarrierSnapshot{
			{RelayAddress: "relay02:9000", Connected: true, CarrierGeneration: 4, ActiveSessions: 0},
			{RelayAddress: "relay03:9000", Connected: true, CarrierGeneration: 2, ActiveSessions: 1},
		},
		Sessions: []natnode.ServiceSessionSnapshot{{
			ConnectionID: "12345678-1234-1234-1234-123456789abc",
			PeerID:       "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			RelayAddress: "relay03:9000",
		}},
	}
	if err := writeServiceListenerStatus(file, "natserver03", "0123456789abcdef0123456789abcdef", snapshot); err != nil {
		t.Fatalf("write status: %v", err)
	}
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	var status serviceListenerStatus
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.NodeID != "0123456789abcdef" || len(status.Sessions) != 1 ||
		status.Sessions[0].ConnectionID != "12345678" || status.Sessions[0].PeerID != "abcdef0123456789" {
		t.Fatalf("status identifiers were not redacted: %+v", status)
	}
	if status.ActiveSessions != 1 || status.AcceptedTotal != 7 || status.RejectedTotal != 2 {
		t.Fatalf("status counters changed: %+v", status)
	}
	if len(status.Carriers) != 2 || status.Sessions[0].RelayAddress != "relay03:9000" {
		t.Fatalf("multi-Relay status was not preserved: %+v", status)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat status: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("status mode = %o, want 600", info.Mode().Perm())
	}
}

func TestSplitRelayAddressesDeduplicatesInOrder(t *testing.T) {
	got := splitRelayAddresses(" relay02:9000,relay01:9000,relay02:9000,,relay03:9000 ")
	want := []string{"relay02:9000", "relay01:9000", "relay03:9000"}
	if len(got) != len(want) {
		t.Fatalf("relay count=%d, want %d: %v", len(got), len(want), got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("relay[%d]=%q, want %q", index, got[index], want[index])
		}
	}
}
