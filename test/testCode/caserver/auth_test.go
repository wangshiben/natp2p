package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"bnfs_p2p/admission"
)

func TestManagementEndpointsRequireRoleScopedAuthentication(t *testing.T) {
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	publicPEM, err := admission.MarshalCAPublicKeyPEM(&caPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal CA public key: %v", err)
	}
	serverToken := randomBearerToken(t)
	relayToken := randomBearerToken(t)
	clientToken := randomBearerToken(t)
	adminToken := randomBearerToken(t)
	authentication := caAuthentication{
		enrollmentTokens: map[admission.Role]string{
			admission.RoleServer: serverToken,
			admission.RoleRelay:  relayToken,
			admission.RoleClient: clientToken,
		},
		adminToken: adminToken,
	}
	ledger := newLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if ledger.loadErr != nil {
		t.Fatalf("create ledger: %v", ledger.loadErr)
	}
	server := httptest.NewServer(newCAHandler(caPrivateKey, publicPEM, "auth-test", 3600, ledger, authentication))
	t.Cleanup(server.Close)

	identity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	issueBody := admission.IssueRequest{
		SubjectPubKey: hex.EncodeToString(identity.PublicKey().Bytes()),
		Role:          admission.RoleServer,
	}

	if status := authenticatedPost(t, server.URL+admission.PathIssue, issueBody, ""); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /issue status = %d, want %d", status, http.StatusUnauthorized)
	}
	if status := authenticatedPost(t, server.URL+admission.PathIssue, issueBody, relayToken); status != http.StatusForbidden {
		t.Fatalf("wrong-role /issue status = %d, want %d", status, http.StatusForbidden)
	}

	client := admission.NewCAClient(server.URL)
	if err := client.SetIssueBearerToken(serverToken); err != nil {
		t.Fatalf("set issue token: %v", err)
	}
	certificate, err := client.Issue(context.Background(), issueBody)
	if err != nil || certificate == nil {
		t.Fatalf("authenticated issue failed: certificate=%v error=%v", certificate, err)
	}
	credit := admission.CreditRequest{NodeID: certificate.Cert.SubjectNodeID, AddBytes: 1024}
	if status := authenticatedPost(t, server.URL+admission.PathCredit, credit, serverToken); status != http.StatusUnauthorized {
		t.Fatalf("enrollment token authorized /credit: status=%d", status)
	}
	if err := client.SetAdminBearerToken(adminToken); err != nil {
		t.Fatalf("set admin token: %v", err)
	}
	response, err := client.Credit(context.Background(), credit)
	if err != nil || response.Balance != 1024 {
		t.Fatalf("authenticated credit failed: response=%+v error=%v", response, err)
	}
}

func randomBearerToken(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate bearer token: %v", err)
	}
	return hex.EncodeToString(value)
}

func authenticatedPost(t *testing.T, target string, body any, token string) int {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	response.Body.Close()
	return response.StatusCode
}
