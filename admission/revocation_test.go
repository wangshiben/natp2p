package admission

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestRevocationControlSignaturesBindRequestResponseAndEvents(t *testing.T) {
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	publicKeyHex := identityPublicKeyHex(relayPrivateKey.PublicKey())
	certificate, err := Sign(caPrivateKey, Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(publicKeyHex), SubjectPubKey: publicKeyHex,
		Role: RoleRelay, NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix(), Nonce: "sync-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRevocationSyncRequest(relayPrivateKey, certificate, 4, 4, 3, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocationSyncRequest(request, now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	tamperedRequest := request
	tamperedRequest.AfterEpoch++
	if err := VerifyRevocationSyncRequest(tamperedRequest, now); err == nil {
		t.Fatal("tampered request accepted")
	}
	event, err := SignRevocationEvent(caPrivateKey, RevocationEvent{
		Epoch: 5, EventID: "event-5", ScopeType: "billing_key", ScopeID: "key-5",
		ErrorCode: "billing_key_revoked", EffectiveAt: now.Unix(), CreatedAt: now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocationEvent(&caPrivateKey.PublicKey, event); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	tamperedEvent := event
	tamperedEvent.ScopeID = "key-6"
	if err := VerifyRevocationEvent(&caPrivateKey.PublicKey, tamperedEvent); err == nil {
		t.Fatal("tampered event accepted")
	}
	response, err := SignRevocationSyncResponse(caPrivateKey, RevocationSyncResponse{
		Version: RevocationSyncVersion, RelayID: request.RelayID, RequestNonce: request.Nonce,
		FromEpoch: 5, CurrentEpoch: 5, ServerTime: now.Unix(), Events: []RevocationEvent{event},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocationSyncResponse(&caPrivateKey.PublicKey, response, request.RelayID, request.Nonce); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	tamperedResponse := response
	tamperedResponse.CurrentEpoch++
	if err := VerifyRevocationSyncResponse(&caPrivateKey.PublicKey, tamperedResponse, request.RelayID, request.Nonce); err == nil {
		t.Fatal("tampered response accepted")
	}
}

func identityPublicKeyHex(publicKey *ecdh.PublicKey) string {
	const hexadecimal = "0123456789abcdef"
	encoded := publicKey.Bytes()
	result := make([]byte, len(encoded)*2)
	for index, value := range encoded {
		result[index*2] = hexadecimal[value>>4]
		result[index*2+1] = hexadecimal[value&15]
	}
	return string(result)
}
