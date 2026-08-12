package admission

import (
	"testing"
	"time"
)

func TestDenyDecisionSignatureBindsRelayRequestAndScope(t *testing.T) {
	privateKey, err := GenerateCAKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	decision, err := SignDenyDecision(privateKey, DenyDecision{
		ErrorCode: "billing_key_revoked", ScopeType: "billing_key", ScopeID: "key-1",
		RelayID: "relay-1", RequestID: "request-1", EffectiveAt: now.Unix(), IssuedAt: now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDenyDecision(&privateKey.PublicKey, decision, "relay-1", "request-1", now); err != nil {
		t.Fatalf("valid deny decision rejected: %v", err)
	}
	tampered := *decision
	tampered.ScopeID = "key-2"
	if err := VerifyDenyDecision(&privateKey.PublicKey, &tampered, "relay-1", "request-1", now); err == nil {
		t.Fatal("tampered deny scope was accepted")
	}
	if err := VerifyDenyDecision(&privateKey.PublicKey, decision, "relay-2", "request-1", now); err == nil {
		t.Fatal("deny decision was replayed to a different relay")
	}
}
