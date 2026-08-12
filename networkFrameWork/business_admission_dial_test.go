package networkFrameWork

import (
	"bnfs_p2p/network"
	"testing"
)

type recordingBusinessAdmissionPolicy struct {
	calls int
}

func (*recordingBusinessAdmissionPolicy) CurrentRelay() (RelayDialTarget, error) {
	return RelayDialTarget{Address: "relay.test:9000"}, nil
}

func (*recordingBusinessAdmissionPolicy) ReportRelayDialResult(RelayDialTarget, error) {}

func (policy *recordingBusinessAdmissionPolicy) BuildBusinessAdmissionPayload(
	targetNodeID, connectionID, legSessionID, entryRelayID string,
) ([]byte, error) {
	policy.calls++
	return []byte(targetNodeID + ":" + connectionID + ":" + legSessionID + ":" + entryRelayID), nil
}

func TestRefreshBusinessAdmissionPayloadPreservesRegistrationEnvelope(t *testing.T) {
	policy := &recordingBusinessAdmissionPolicy{}
	message := &network.Message{
		Header:  &network.Header{NodeId: "server", LegSessionId: "registration-generation"},
		Payload: []byte(`{"pk":"server-public-key","is":"server-certificate"}`),
	}
	originalPayload := string(message.Payload)
	if err := refreshBusinessAdmissionPayload(policy, message, "relay02:9000"); err != nil {
		t.Fatal(err)
	}
	if policy.calls != 0 {
		t.Fatalf("business admission provider called %d time(s) for registration reconnect", policy.calls)
	}
	if string(message.Payload) != originalPayload {
		t.Fatalf("registration envelope changed to %q", message.Payload)
	}
}

func TestRefreshBusinessAdmissionPayloadRenewsBusinessProof(t *testing.T) {
	policy := &recordingBusinessAdmissionPolicy{}
	message := &network.Message{
		Header: &network.Header{
			NodeId: "server", ConnectionId: "connection", LegSessionId: "dial-generation",
		},
		Payload: []byte("expired-proof"),
	}
	if err := refreshBusinessAdmissionPayload(policy, message, "relay02:9000"); err != nil {
		t.Fatal(err)
	}
	if policy.calls != 1 {
		t.Fatalf("business admission provider called %d time(s), want 1", policy.calls)
	}
	want := "server:connection:dial-generation:relay02:9000"
	if string(message.Payload) != want || message.Header.PayLoadLength != uint(len(want)) {
		t.Fatalf("business proof = %q length=%d, want %q length=%d",
			message.Payload, message.Header.PayLoadLength, want, len(want))
	}
}
