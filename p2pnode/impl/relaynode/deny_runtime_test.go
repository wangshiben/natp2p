package relaynode

import (
	"bnfs_p2p/admission"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyDenyDecisionRequiresTrustedSignature(t *testing.T) {
	caPrivateKey, err := admission.GenerateCAKey()
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	publicKeyPEM, err := admission.MarshalCAPublicKeyPEM(&caPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier := admission.NewCAClient("")
	if err := verifier.SetPubKeyPEM(publicKeyPEM); err != nil {
		t.Fatal(err)
	}
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Verifier: verifier})

	decision, err := admission.SignDenyDecision(caPrivateKey, admission.DenyDecision{
		ErrorCode: "billing_key_revoked", ScopeType: "billing_key", ScopeID: "key-1",
		RelayID: relay.idStr(), RequestID: "request-1", EffectiveAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.applyDenyDecision(decision); err != nil {
		t.Fatalf("trusted deny decision rejected: %v", err)
	}
	if _, ok := relay.businessDeniedScopes["billing_key:key-1"]; !ok {
		t.Fatal("trusted deny decision did not update local deny scope")
	}

	tampered := *decision
	tampered.ScopeID = "key-2"
	if err := relay.applyDenyDecision(&tampered); err == nil {
		t.Fatal("tampered deny decision was accepted")
	}
	if _, ok := relay.businessDeniedScopes["billing_key:key-2"]; ok {
		t.Fatal("tampered deny decision polluted local deny scopes")
	}
}

func TestApplyDenyDecisionDoesNotUpdateMemoryWhenPersistenceFails(t *testing.T) {
	caPrivateKey, err := admission.GenerateCAKey()
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	publicKeyPEM, err := admission.MarshalCAPublicKeyPEM(&caPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier := admission.NewCAClient("")
	if err := verifier.SetPubKeyPEM(publicKeyPEM); err != nil {
		t.Fatal(err)
	}
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Verifier: verifier})
	invalidStatePath := filepath.Join(t.TempDir(), "state-directory")
	if err := os.Mkdir(invalidStatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	relay.mu.Lock()
	relay.revocationControl = &relayRevocationControl{
		node: relay, client: verifier, path: invalidStatePath,
		state: persistedRevocationState{Version: revocationStateVersion, RelayID: relay.idStr()},
	}
	relay.mu.Unlock()
	decision, err := admission.SignDenyDecision(caPrivateKey, admission.DenyDecision{
		ErrorCode: "billing_key_revoked", ScopeType: "billing_key", ScopeID: "key-persist-failure",
		RelayID: relay.idStr(), RequestID: "request-persist-failure", EffectiveAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.applyDenyDecision(decision); err == nil {
		t.Fatal("deny decision unexpectedly succeeded with an unwritable state target")
	}
	relay.businessAdmissionMu.Lock()
	_, denied := relay.businessDeniedScopes["billing_key:key-persist-failure"]
	relay.businessAdmissionMu.Unlock()
	if denied {
		t.Fatal("failed durable deny write polluted the in-memory deny set")
	}
}

func TestProductionRevocationStalenessRejectsNewAdmission(t *testing.T) {
	relay, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Profile: SecurityProfileProduction})
	relay.mu.Lock()
	relay.revocationControl = &relayRevocationControl{node: relay, lastSuccessful: time.Now().Add(-revocationFreshnessLimit - time.Second)}
	relay.mu.Unlock()
	if err := relay.onRegisterVerify("client-node", nil, "192.0.2.1:1234"); err == nil {
		t.Fatal("stale production revocation state accepted a new registration")
	}
}

func TestValidateAdmissionProductionCannotDegrade(t *testing.T) {
	if err := ValidateAdmissionConfig(&AdmissionConfig{Profile: SecurityProfileProduction, Mode: AdmissionWarn}, "relay"); err == nil {
		t.Fatal("production warn mode was accepted")
	}
	if err := ValidateAdmissionConfig(&AdmissionConfig{Profile: SecurityProfileProduction, Mode: AdmissionEnforce}, "relay"); err == nil {
		t.Fatal("production missing certificate/verifier was accepted")
	}
	if err := ValidateAdmissionConfig(&AdmissionConfig{Profile: SecurityProfileDevelopment, Mode: AdmissionOff}, "relay"); err != nil {
		t.Fatalf("development off mode rejected: %v", err)
	}
}
