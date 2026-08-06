package admissioncli

import (
	"bnfs_p2p/admission"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertificateForIdentityLoadsVerifiedPreSignedCertificate(t *testing.T) {
	certificate, client, publicKey, nodeID := testCertificate(t, admission.RoleServer)
	filename := writeTestCertificate(t, certificate)
	t.Setenv(certificateFileEnv, filename)
	t.Setenv(issueTokenFileEnv, "")

	loaded, err := certificateForIdentity(client, publicKey, nodeID, admission.RoleServer)
	if err != nil {
		t.Fatalf("加载预签证书失败: %v", err)
	}
	if loaded.Cert.SubjectNodeID != nodeID || loaded.Cert.SubjectPubKey != publicKey {
		t.Fatal("预签证书未绑定到本地节点身份")
	}
}

func TestCertificateForIdentityRejectsUnsafePreSignedCertificate(t *testing.T) {
	certificate, client, publicKey, nodeID := testCertificate(t, admission.RoleServer)
	tests := []struct {
		name      string
		prepare   func(*testing.T) string
		role      admission.Role
		publicKey string
		tokenFile string
		wantError string
	}{
		{
			name: "wrong role", prepare: func(t *testing.T) string { return writeTestCertificate(t, certificate) },
			role: admission.RoleRelay, publicKey: publicKey, wantError: "证书角色不匹配",
		},
		{
			name: "wrong local key", prepare: func(t *testing.T) string { return writeTestCertificate(t, certificate) },
			role: admission.RoleServer, publicKey: "04" + strings.Repeat("0", 128), wantError: "公钥与本地身份不匹配",
		},
		{
			name: "unknown field", prepare: func(t *testing.T) string {
				filename := writeTestCertificate(t, certificate)
				encoded, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				encoded = append(encoded[:len(encoded)-2], []byte(",\"unexpected\":true}\n")...)
				if err := os.WriteFile(filename, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
				return filename
			},
			role: admission.RoleServer, publicKey: publicKey, wantError: "unknown field",
		},
		{
			name: "enrollment token conflict", prepare: func(t *testing.T) string { return writeTestCertificate(t, certificate) },
			role: admission.RoleServer, publicKey: publicKey, tokenFile: "/private/enroll.token", wantError: "不能同时配置",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(certificateFileEnv, test.prepare(t))
			t.Setenv(issueTokenFileEnv, test.tokenFile)
			_, err := certificateForIdentity(client, test.publicKey, nodeID, test.role)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("期望错误包含 %q，实际 %v", test.wantError, err)
			}
		})
	}
}

func TestReadBillingPrivateKeyFileValidatesCAWebBundle(t *testing.T) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	publicKeyHex := hex.EncodeToString(publicKey)
	keyID, err := admission.BillingKeyIDFromPublicKeyHex(publicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	bundle := billingPrivateKeyBundle{
		Version: 1, KeyID: keyID, Label: "test-node", Algorithm: "ECDSA_P256_SHA256",
		PrivateKeyJWK: billingPrivateKeyJWK{
			KeyType: "EC", Curve: "P-256",
			X:      base64.RawURLEncoding.EncodeToString(publicKey[1:33]),
			Y:      base64.RawURLEncoding.EncodeToString(publicKey[33:]),
			D:      base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
			KeyOps: []string{"sign"}, Extractable: true,
		},
		PublicKeyHex: publicKeyHex, RegistrationStatus: "active",
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "billing-key.json")
	if err := os.WriteFile(filename, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readBillingPrivateKeyFile(filename)
	if err != nil {
		t.Fatalf("load CA Web billing key: %v", err)
	}
	if hex.EncodeToString(loaded.PublicKey().Bytes()) != publicKeyHex {
		t.Fatal("loaded billing private key changed its public identity")
	}

	bundle.KeyID = strings.Repeat("0", 64)
	encoded, _ = json.Marshal(bundle)
	if err := os.WriteFile(filename, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBillingPrivateKeyFile(filename); err == nil || !strings.Contains(err.Error(), "key_id") {
		t.Fatalf("mismatched key ID was accepted: %v", err)
	}
}

func TestConfiguredBillingPrivateKeyAllowsBoundPreSignedCertificate(t *testing.T) {
	privateKey, filename := writeTestBillingPrivateKey(t)
	t.Setenv(billingKeyFileEnv, filename)
	t.Setenv(certificateFileEnv, filepath.Join(t.TempDir(), "certificate.json"))
	t.Setenv(issueTokenFileEnv, "")

	loaded, configured, err := configuredBillingPrivateKey()
	if err != nil {
		t.Fatalf("预签证书与扣费私钥组合应被接受: %v", err)
	}
	if !configured || !strings.EqualFold(
		hex.EncodeToString(loaded.PublicKey().Bytes()),
		hex.EncodeToString(privateKey.PublicKey().Bytes()),
	) {
		t.Fatal("未加载预签证书对应的扣费私钥")
	}
}

func TestConfiguredBillingPrivateKeyRejectsEnrollmentToken(t *testing.T) {
	_, filename := writeTestBillingPrivateKey(t)
	t.Setenv(billingKeyFileEnv, filename)
	t.Setenv(certificateFileEnv, "")
	t.Setenv(issueTokenFileEnv, filepath.Join(t.TempDir(), "enroll.token"))

	if _, _, err := configuredBillingPrivateKey(); err == nil || !strings.Contains(err.Error(), issueTokenFileEnv) {
		t.Fatalf("扣费私钥与 Enrollment Token 冲突未被拒绝: %v", err)
	}
}

func TestValidateCertificateBillingBinding(t *testing.T) {
	privateKey, _ := writeTestBillingPrivateKey(t)
	publicKey := hex.EncodeToString(privateKey.PublicKey().Bytes())
	keyID, err := admission.BillingKeyIDFromPublicKeyHex(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := strings.Repeat("a", 64)
	certificate := &admission.SignedCert{Cert: admission.Cert{
		SubjectNodeID:   nodeID,
		BillingPubKey:   publicKey,
		BillingKeyID:    keyID,
		AuthorizationID: admission.NodeAuthorizationID(nodeID, keyID),
	}}
	if err := validateCertificateBillingBinding(certificate, nodeID, privateKey); err != nil {
		t.Fatalf("正确的证书扣费绑定被拒绝: %v", err)
	}

	tests := []struct {
		name      string
		mutate    func(*admission.SignedCert)
		wantError string
	}{
		{name: "billing public key", mutate: func(value *admission.SignedCert) {
			value.Cert.BillingPubKey = "04" + strings.Repeat("0", 128)
		}, wantError: "扣费公钥"},
		{name: "billing key ID", mutate: func(value *admission.SignedCert) {
			value.Cert.BillingKeyID = strings.Repeat("0", 64)
		}, wantError: "扣费密钥 ID"},
		{name: "authorization ID", mutate: func(value *admission.SignedCert) {
			value.Cert.AuthorizationID = strings.Repeat("0", 64)
		}, wantError: "节点授权 ID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := *certificate
			test.mutate(&copy)
			if err := validateCertificateBillingBinding(&copy, nodeID, privateKey); err == nil ||
				!strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("期望错误包含 %q，实际 %v", test.wantError, err)
			}
		})
	}
}

func writeTestBillingPrivateKey(t *testing.T) (*ecdh.PrivateKey, string) {
	t.Helper()
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	publicKeyHex := hex.EncodeToString(publicKey)
	keyID, err := admission.BillingKeyIDFromPublicKeyHex(publicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	bundle := billingPrivateKeyBundle{
		Version: 1, KeyID: keyID, Label: "test-node", Algorithm: "ECDSA_P256_SHA256",
		PrivateKeyJWK: billingPrivateKeyJWK{
			KeyType: "EC", Curve: "P-256",
			X:      base64.RawURLEncoding.EncodeToString(publicKey[1:33]),
			Y:      base64.RawURLEncoding.EncodeToString(publicKey[33:]),
			D:      base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
			KeyOps: []string{"sign"}, Extractable: true,
		},
		PublicKeyHex: publicKeyHex, RegistrationStatus: "active",
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "billing-key.json")
	if err := os.WriteFile(filename, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return privateKey, filename
}

func testCertificate(t *testing.T, role admission.Role) (*admission.SignedCert, *admission.CAClient, string, string) {
	t.Helper()
	identity, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := hex.EncodeToString(identity.PublicKey().Bytes())
	nodeID := admission.NodeIDFromPubKeyHex(publicKey)
	caKey, err := admission.GenerateCAKey()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := admission.Sign(caKey, admission.Cert{
		SubjectNodeID: nodeID,
		SubjectPubKey: publicKey,
		Role:          role,
		NotBefore:     time.Now().Add(-time.Minute).Unix(),
		NotAfter:      time.Now().Add(time.Hour).Unix(),
		Nonce:         "test-pre-signed-certificate",
	})
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPEM, err := admission.MarshalCAPublicKeyPEM(&caKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	client := admission.NewCAClient("")
	if err := client.SetPubKeyPEM(publicKeyPEM); err != nil {
		t.Fatal(err)
	}
	return certificate, client, publicKey, nodeID
}

func writeTestCertificate(t *testing.T, certificate *admission.SignedCert) string {
	t.Helper()
	encoded, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "certificate.json")
	if err := os.WriteFile(filename, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return filename
}
