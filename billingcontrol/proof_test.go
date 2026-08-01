package billingcontrol

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
)

func TestReadyProofBindsChallengeAndIdentities(t *testing.T) {
	payerKey := generateIdentity(t)
	relayKey := generateIdentity(t)
	payerPublicKey := hex.EncodeToString(payerKey.PublicKey().Bytes())
	relayPublicKey := hex.EncodeToString(relayKey.PublicKey().Bytes())
	payerID, err := IdentityIDFromPublicKeyHex(payerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	relayID, err := IdentityIDFromPublicKeyHex(relayPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	binding := ProofBinding{
		Challenge: challenge,
		SessionID: testIdentifier("session"),
		PayerID:   payerID,
		RelayID:   relayID,
	}
	proof, err := SignReadyProof(payerKey, binding)
	if err != nil {
		t.Fatalf("sign ready proof: %v", err)
	}
	if err := VerifyReadyProof(payerPublicKey, binding, proof); err != nil {
		t.Fatalf("verify ready proof: %v", err)
	}
	if _, err := parseCanonicalProof(proof, true); err != nil {
		t.Fatalf("proof is not canonical low-S: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ProofBinding)
	}{
		{name: "old challenge replay", mutate: func(candidate *ProofBinding) {
			candidate.Challenge = append([]byte(nil), candidate.Challenge...)
			candidate.Challenge[0] ^= 1
		}},
		{name: "wrong session", mutate: func(candidate *ProofBinding) {
			candidate.SessionID = testIdentifier("other-session")
		}},
		{name: "wrong payer", mutate: func(candidate *ProofBinding) {
			candidate.PayerID = testIdentifier("other-payer")
		}},
		{name: "wrong Relay", mutate: func(candidate *ProofBinding) {
			candidate.RelayID = testIdentifier("other-relay")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := binding
			test.mutate(&candidate)
			if err := VerifyReadyProof(payerPublicKey, candidate, proof); err == nil {
				t.Fatal("proof verified outside its signed binding")
			}
		})
	}
}

func TestReadyProofRejectsVictimPublicKeyCopy(t *testing.T) {
	victimKey := generateIdentity(t)
	attackerKey := generateIdentity(t)
	relayKey := generateIdentity(t)
	victimPublicKey := hex.EncodeToString(victimKey.PublicKey().Bytes())
	attackerPublicKey := hex.EncodeToString(attackerKey.PublicKey().Bytes())
	relayPublicKey := hex.EncodeToString(relayKey.PublicKey().Bytes())
	victimID, _ := IdentityIDFromPublicKeyHex(victimPublicKey)
	attackerID, _ := IdentityIDFromPublicKeyHex(attackerPublicKey)
	relayID, _ := IdentityIDFromPublicKeyHex(relayPublicKey)
	challenge, _ := NewChallenge()
	victimBinding := ProofBinding{
		Challenge: challenge, SessionID: testIdentifier("victim-session"),
		PayerID: victimID, RelayID: relayID,
	}
	if _, err := SignReadyProof(attackerKey, victimBinding); err == nil {
		t.Fatal("attacker signed a proof bound to the victim payer ID")
	}
	attackerBinding := victimBinding
	attackerBinding.PayerID = attackerID
	attackerProof, err := SignReadyProof(attackerKey, attackerBinding)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReadyProof(victimPublicKey, victimBinding, attackerProof); err == nil {
		t.Fatal("attacker proof verified with copied victim public key")
	}
	if err := VerifyReadyProof(strings.ToUpper(victimPublicKey), victimBinding, attackerProof); err == nil {
		t.Fatal("non-canonical public key was accepted")
	}
}

func TestRelayStateProofBindsUnpublishedWatermark(t *testing.T) {
	payerKey := generateIdentity(t)
	relayKey := generateIdentity(t)
	payerPublicKey := hex.EncodeToString(payerKey.PublicKey().Bytes())
	relayPublicKey := hex.EncodeToString(relayKey.PublicKey().Bytes())
	payerID, _ := IdentityIDFromPublicKeyHex(payerPublicKey)
	relayID, _ := IdentityIDFromPublicKeyHex(relayPublicKey)
	challenge, _ := NewChallenge()
	binding := RelayStateProofBinding{
		ProofBinding: ProofBinding{
			Challenge: challenge, SessionID: testIdentifier("state-session"),
			PayerID: payerID, RelayID: relayID,
		},
		CumulativeBytes: 4096, LastRecordID: testIdentifier("last-record"),
		LastRecordSequence: 7, RecordSetDigest: testIdentifier("record-set"),
	}
	proof, err := SignRelayStateProof(relayKey, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayStateProof(relayPublicKey, binding, proof); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*RelayStateProofBinding){
		func(candidate *RelayStateProofBinding) { candidate.CumulativeBytes++ },
		func(candidate *RelayStateProofBinding) { candidate.LastRecordID = testIdentifier("other-record") },
		func(candidate *RelayStateProofBinding) { candidate.LastRecordSequence++ },
		func(candidate *RelayStateProofBinding) { candidate.RecordSetDigest = testIdentifier("other-root") },
		func(candidate *RelayStateProofBinding) { candidate.Challenge[0] ^= 1 },
	}
	for index, mutate := range mutations {
		candidate := binding
		candidate.Challenge = append([]byte(nil), binding.Challenge...)
		mutate(&candidate)
		if err := VerifyRelayStateProof(relayPublicKey, candidate, proof); err == nil {
			t.Fatalf("mutation %d retained a valid Relay state proof", index)
		}
	}
	if _, err := SignRelayStateProof(payerKey, binding); err == nil {
		t.Fatal("payer key signed a Relay-bound state proof")
	}

	empty := binding
	empty.CumulativeBytes = 0
	empty.LastRecordID = strings.Repeat("0", 64)
	empty.LastRecordSequence = 0
	empty.RecordSetDigest = strings.Repeat("0", 64)
	emptyProof, err := SignRelayStateProof(relayKey, empty)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRelayStateProof(relayPublicKey, empty, emptyProof); err != nil {
		t.Fatal(err)
	}
	empty.CumulativeBytes = 1
	if _, err := SignRelayStateProof(relayKey, empty); err == nil {
		t.Fatal("inconsistent empty Relay state was signed")
	}
}

func TestReadyStateProofBindsRelayWatermarkAndDecision(t *testing.T) {
	payerKey := generateIdentity(t)
	relayKey := generateIdentity(t)
	payerPublicKey := hex.EncodeToString(payerKey.PublicKey().Bytes())
	relayPublicKey := hex.EncodeToString(relayKey.PublicKey().Bytes())
	payerID, _ := IdentityIDFromPublicKeyHex(payerPublicKey)
	relayID, _ := IdentityIDFromPublicKeyHex(relayPublicKey)
	challenge, _ := NewChallenge()
	binding := ReadyStateProofBinding{
		RelayStateProofBinding: RelayStateProofBinding{
			ProofBinding: ProofBinding{
				Challenge: challenge, SessionID: testIdentifier("ready-state-session"),
				PayerID: payerID, RelayID: relayID,
			},
			CumulativeBytes: 8192, LastRecordID: testIdentifier("ready-state-record"),
			LastRecordSequence: 9, RecordSetDigest: testIdentifier("ready-state-set"),
		},
		SessionPreexisting: true, RecoveryVoucherID: testIdentifier("recovery-voucher"),
	}
	proof, err := SignReadyStateProof(payerKey, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReadyStateProof(payerPublicKey, binding, proof); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*ReadyStateProofBinding){
		func(candidate *ReadyStateProofBinding) { candidate.CumulativeBytes++ },
		func(candidate *ReadyStateProofBinding) { candidate.LastRecordSequence++ },
		func(candidate *ReadyStateProofBinding) { candidate.SessionPreexisting = false },
		func(candidate *ReadyStateProofBinding) { candidate.RecoveryVoucherID = testIdentifier("other-voucher") },
	}
	for index, mutate := range mutations {
		candidate := binding
		mutate(&candidate)
		if err := VerifyReadyStateProof(payerPublicKey, candidate, proof); err == nil {
			t.Fatalf("ready-state mutation %d retained a valid proof", index)
		}
	}
	inconsistent := binding
	inconsistent.SessionResetRequired = true
	if _, err := SignReadyStateProof(payerKey, inconsistent); err == nil {
		t.Fatal("inconsistent preexisting reset decision was signed")
	}
	rotation := binding
	rotation.SessionPreexisting = false
	rotation.SessionResetRequired = true
	if _, err := SignReadyStateProof(payerKey, rotation); err != nil {
		t.Fatalf("reset decision with a final recovery voucher was rejected: %v", err)
	}
}

func TestReadyProofRejectsHighSAndNonCanonicalSignatures(t *testing.T) {
	payerKey := generateIdentity(t)
	relayKey := generateIdentity(t)
	payerPublicKey := hex.EncodeToString(payerKey.PublicKey().Bytes())
	relayPublicKey := hex.EncodeToString(relayKey.PublicKey().Bytes())
	payerID, _ := IdentityIDFromPublicKeyHex(payerPublicKey)
	relayID, _ := IdentityIDFromPublicKeyHex(relayPublicKey)
	challenge, _ := NewChallenge()
	binding := ProofBinding{
		Challenge: challenge, SessionID: testIdentifier("canonical-session"),
		PayerID: payerID, RelayID: relayID,
	}
	proof, err := SignReadyProof(payerKey, binding)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCanonicalProof(proof, true)
	if err != nil {
		t.Fatal(err)
	}
	parsed.S.Sub(elliptic.P256().Params().N, parsed.S)
	highS, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReadyProof(payerPublicKey, binding, highS); err == nil {
		t.Fatal("high-S malleable proof was accepted")
	}
	if err := VerifyReadyProof(payerPublicKey, binding, append(proof, 0)); err == nil {
		t.Fatal("proof with trailing ASN.1 data was accepted")
	}
}

func TestNewChallengeReturnsFreshNonZeroValues(t *testing.T) {
	first, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != ChallengeSize || len(second) != ChallengeSize || allZero(first) || allZero(second) {
		t.Fatal("challenge length or entropy invariant failed")
	}
	if string(first) == string(second) {
		t.Fatal("two control connections received the same challenge")
	}
}

func generateIdentity(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	identity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testIdentifier(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(digest[:])
}
