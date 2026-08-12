package relaynode

import (
	"bnfs_p2p/admission"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRevocationControlPersistsBeforeApplyingAndRestores(t *testing.T) {
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayIdentity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	billingIdentity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	relayPublicKey := hex.EncodeToString(relayIdentity.PublicKey().Bytes())
	billingPublicKey := hex.EncodeToString(billingIdentity.PublicKey().Bytes())
	billingKeyID, err := admission.BillingKeyIDFromPublicKeyHex(billingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	relayID := admission.NodeIDFromPubKeyHex(relayPublicKey)
	certificate, err := admission.Sign(caPrivateKey, admission.Cert{
		SubjectNodeID: relayID, SubjectPubKey: relayPublicKey, Role: admission.RoleRelay,
		NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix(), Nonce: "relay-sync",
		AuthorizationID: admission.NodeAuthorizationID(relayID, billingKeyID), BillingKeyID: billingKeyID,
		BillingPubKey: billingPublicKey, BillingUserID: "user-relay",
	})
	if err != nil {
		t.Fatal(err)
	}
	events := make([]admission.RevocationEvent, 0, 129)
	for epoch := uint64(1); epoch <= 129; epoch++ {
		scopeID := fmt.Sprintf("key-%d", epoch)
		if epoch == 1 {
			scopeID = "key-one"
		}
		event, signErr := admission.SignRevocationEvent(caPrivateKey, admission.RevocationEvent{
			Epoch: epoch, EventID: fmt.Sprintf("event-%d", epoch), ScopeType: "billing_key", ScopeID: scopeID,
			ErrorCode: "billing_key_revoked", EffectiveAt: now.Unix(), CreatedAt: now.Unix(),
		})
		if signErr != nil {
			t.Fatal(signErr)
		}
		events = append(events, event)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != admission.PathControlSync {
			http.NotFound(writer, request)
			return
		}
		var syncRequest admission.RevocationSyncRequest
		if json.NewDecoder(request.Body).Decode(&syncRequest) != nil || admission.VerifyRevocationSyncRequest(syncRequest, time.Now().UTC()) != nil {
			http.Error(writer, "bad request", http.StatusUnauthorized)
			return
		}
		delta := []admission.RevocationEvent{}
		fromEpoch := syncRequest.AfterEpoch
		if syncRequest.AfterEpoch < uint64(len(events)) {
			last := syncRequest.AfterEpoch + 128
			if last > uint64(len(events)) {
				last = uint64(len(events))
			}
			delta = append(delta, events[syncRequest.AfterEpoch:last]...)
			fromEpoch = delta[0].Epoch
		} else if syncRequest.WaitSeconds > 0 {
			select {
			case <-request.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
		response, signErr := admission.SignRevocationSyncResponse(caPrivateKey, admission.RevocationSyncResponse{
			Version: admission.RevocationSyncVersion, RelayID: syncRequest.RelayID,
			RequestNonce: syncRequest.Nonce, FromEpoch: fromEpoch, CurrentEpoch: uint64(len(events)),
			ServerTime: time.Now().UTC().Unix(), Events: delta,
		})
		if signErr != nil {
			http.Error(writer, signErr.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(response)
	}))
	defer server.Close()
	publicKeyPEM, err := admission.MarshalCAPublicKeyPEM(&caPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "revocations.json")
	configure := func(node *RelayNode) {
		t.Helper()
		client := admission.NewCAClient(server.URL)
		if err := client.SetPubKeyPEM(publicKeyPEM); err != nil {
			t.Fatal(err)
		}
		if err := node.SetBillingQueuePath(filepath.Join(filepath.Dir(statePath), "queue.json")); err != nil {
			t.Fatal(err)
		}
		if err := node.SetBillingPrivateKey(billingIdentity); err != nil {
			t.Fatal(err)
		}
		if err := node.SetAdmissionChecked(&AdmissionConfig{
			Mode: AdmissionEnforce, Profile: SecurityProfileProduction, SelfCert: certificate,
			Verifier: client, RevocationStatePath: statePath,
		}); err != nil {
			t.Fatal(err)
		}
		if err := node.ConfigureRevocationControl(client, certificate, statePath); err != nil {
			t.Fatal(err)
		}
	}
	first, err := NewRelayNode(relayIdentity, "127.0.0.1:0", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	configure(first)
	first.businessAdmissionMu.Lock()
	_, denied := first.businessDeniedScopes["billing_key:key-one"]
	first.businessAdmissionMu.Unlock()
	if !denied {
		t.Fatal("signed revocation was not applied")
	}
	first.revocationControl.mu.RLock()
	appliedEpoch := first.revocationControl.state.AppliedEpoch
	first.revocationControl.mu.RUnlock()
	if appliedEpoch != uint64(len(events)) {
		t.Fatalf("initial sync returned before all deltas were applied: got=%d want=%d", appliedEpoch, len(events))
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode=%v", info.Mode().Perm())
	}
	_ = first.Close()

	second, err := NewRelayNode(relayIdentity, "127.0.0.1:0", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	configure(second)
	defer second.Close()
	second.businessAdmissionMu.Lock()
	_, restored := second.businessDeniedScopes["billing_key:key-one"]
	second.businessAdmissionMu.Unlock()
	if !restored {
		t.Fatal("persisted revocation was not restored")
	}
	if !second.revocationSyncFresh() {
		t.Fatal("successful initial sync did not make revocation state fresh")
	}
}
