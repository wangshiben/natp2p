package admission

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

type businessVerifier struct{ pub *ecdsa.PublicKey }

func (v businessVerifier) Verify(cert *SignedCert, opts VerifyOptions) error {
	return Verify(v.pub, cert, opts)
}

func TestBusinessAdmissionEnvelopeRoundTrip(t *testing.T) {
	caKey, err := GenerateCAKey()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := Sign(caKey, Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(hex.EncodeToString(identity.PublicKey().Bytes())),
		SubjectPubKey: hex.EncodeToString(identity.PublicKey().Bytes()), Role: RoleClient,
		NotBefore: time.Now().Add(-time.Minute).Unix(), NotAfter: time.Now().Add(time.Hour).Unix(), Nonce: "cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewBusinessAdmissionEnvelope(identity, cert, "target", "connection", "leg", "entry", 4, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseBusinessAdmissionEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := VerifyBusinessAdmissionEnvelope(businessVerifier{pub: &caKey.PublicKey}, decoded, "target", "connection", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if decision.SourceNodeID != envelope.SourceNodeID || decision.SourcePublicKey != envelope.SourcePublicKey {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	decoded.TargetNodeID = "other"
	if _, err := VerifyBusinessAdmissionEnvelope(businessVerifier{pub: &caKey.PublicKey}, decoded, "target", "connection", time.Now()); err == nil {
		t.Fatal("tampered target was accepted")
	}
	if _, err := json.Marshal(decoded); err != nil {
		t.Fatal(err)
	}
}

func TestRelayForwardAttestationBindsSourceAndRoute(t *testing.T) {
	caKey, err := GenerateCAKey()
	if err != nil {
		t.Fatal(err)
	}
	clientIdentity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayIdentity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	clientPublicKey := hex.EncodeToString(clientIdentity.PublicKey().Bytes())
	relayPublicKey := hex.EncodeToString(relayIdentity.PublicKey().Bytes())
	clientCertificate, err := Sign(caKey, Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(clientPublicKey), SubjectPubKey: clientPublicKey, Role: RoleClient,
		NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix(), Nonce: "client-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	relayCertificate, err := Sign(caKey, Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(relayPublicKey), SubjectPubKey: relayPublicKey, Role: RoleRelay,
		NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix(), Nonce: "relay-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewBusinessAdmissionEnvelope(clientIdentity, clientCertificate, "target", "connection", "leg", "relay-entry", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddRelayForwardAttestation(envelope, relayIdentity, relayCertificate, now); err != nil {
		t.Fatal(err)
	}
	verifier := businessVerifier{pub: &caKey.PublicKey}
	if err := VerifyRelayForwardAttestation(verifier, envelope, now); err != nil {
		t.Fatalf("valid relay forward attestation rejected: %v", err)
	}
	envelope.ForwardAttestation.TargetNodeID = "other"
	if err := VerifyRelayForwardAttestation(verifier, envelope, now); err == nil {
		t.Fatal("tampered relay forward target was accepted")
	}
}
