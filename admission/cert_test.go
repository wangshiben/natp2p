package admission

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

// makeNodeKey 生成一把 P-256 ECDH 节点密钥并返回其公钥 hex（与框架 crypoto 口径一致）。
func makeNodeKey(t *testing.T) (*ecdh.PrivateKey, string) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成节点密钥失败: %v", err)
	}
	return priv, hex.EncodeToString(priv.PublicKey().Bytes())
}

func TestSignVerifyRoundTrip(t *testing.T) {
	caPriv, err := GenerateCAKey()
	if err != nil {
		t.Fatalf("生成 CA 密钥失败: %v", err)
	}
	_, pubHex := makeNodeKey(t)

	nonce, _ := NewNonce()
	now := time.Now()
	cert := Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(pubHex),
		SubjectPubKey: pubHex,
		Role:          RoleServer,
		NotBefore:     now.Add(-time.Minute).Unix(),
		NotAfter:      now.Add(time.Hour).Unix(),
		Nonce:         nonce,
	}
	sc, err := Sign(caPriv, cert)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	if err := Verify(&caPriv.PublicKey, sc, VerifyOptions{ExpectRole: RoleServer}); err != nil {
		t.Fatalf("验签应通过, 却失败: %v", err)
	}
	// 绑定到具体 NodeID 也应通过。
	if err := Verify(&caPriv.PublicKey, sc, VerifyOptions{ExpectNodeID: cert.SubjectNodeID}); err != nil {
		t.Fatalf("绑定 NodeID 验签应通过: %v", err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	caPriv, _ := GenerateCAKey()
	_, pubHex := makeNodeKey(t)
	nonce, _ := NewNonce()
	now := time.Now()
	cert := Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(pubHex),
		SubjectPubKey: pubHex,
		Role:          RoleClient,
		NotBefore:     now.Add(-time.Minute).Unix(),
		NotAfter:      now.Add(time.Hour).Unix(),
		Nonce:         nonce,
	}
	sc, _ := Sign(caPriv, cert)

	// 篡改角色 → 验签必须失败。
	sc.Cert.Role = RoleRelay
	if err := Verify(&caPriv.PublicKey, sc, VerifyOptions{}); err == nil {
		t.Fatal("篡改角色后验签应失败, 却通过了")
	}
}

func TestVerifyRejectsWrongCA(t *testing.T) {
	caPriv, _ := GenerateCAKey()
	otherCA, _ := GenerateCAKey()
	_, pubHex := makeNodeKey(t)
	nonce, _ := NewNonce()
	now := time.Now()
	cert := Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(pubHex),
		SubjectPubKey: pubHex,
		Role:          RoleRelay,
		NotBefore:     now.Add(-time.Minute).Unix(),
		NotAfter:      now.Add(time.Hour).Unix(),
		Nonce:         nonce,
	}
	sc, _ := Sign(caPriv, cert)

	// 用别的 CA 公钥验签 → 必须失败。
	if err := Verify(&otherCA.PublicKey, sc, VerifyOptions{}); err == nil {
		t.Fatal("用错误 CA 公钥验签应失败, 却通过了")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	caPriv, _ := GenerateCAKey()
	_, pubHex := makeNodeKey(t)
	nonce, _ := NewNonce()
	past := time.Now().Add(-2 * time.Hour)
	cert := Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(pubHex),
		SubjectPubKey: pubHex,
		Role:          RoleServer,
		NotBefore:     past.Unix(),
		NotAfter:      past.Add(time.Hour).Unix(), // 1 小时前就过期了
		Nonce:         nonce,
	}
	sc, _ := Sign(caPriv, cert)

	if err := Verify(&caPriv.PublicKey, sc, VerifyOptions{}); err == nil {
		t.Fatal("过期证书验签应失败, 却通过了")
	}
	// 跳过时间校验则应通过（其余项有效）。
	if err := Verify(&caPriv.PublicKey, sc, VerifyOptions{SkipTimeCheck: true}); err != nil {
		t.Fatalf("跳过时间校验后应通过: %v", err)
	}
}

func TestVerifyRejectsNodeIDMismatch(t *testing.T) {
	caPriv, _ := GenerateCAKey()
	_, pubHex := makeNodeKey(t)
	nonce, _ := NewNonce()
	now := time.Now()
	cert := Cert{
		SubjectNodeID: "deadbeef", // 与公钥不自洽
		SubjectPubKey: pubHex,
		Role:          RoleServer,
		NotBefore:     now.Add(-time.Minute).Unix(),
		NotAfter:      now.Add(time.Hour).Unix(),
		Nonce:         nonce,
	}
	sc, _ := Sign(caPriv, cert)
	if err := Verify(&caPriv.PublicKey, sc, VerifyOptions{}); err == nil {
		t.Fatal("NodeID 与公钥不自洽应失败, 却通过了")
	}
}

func TestCAPublicKeyPEMRoundTrip(t *testing.T) {
	caPriv, _ := GenerateCAKey()
	pemStr, err := MarshalCAPublicKeyPEM(&caPriv.PublicKey)
	if err != nil {
		t.Fatalf("编码公钥失败: %v", err)
	}
	pub, err := ParseCAPublicKeyPEM(pemStr)
	if err != nil {
		t.Fatalf("解析公钥失败: %v", err)
	}
	// 用解析回来的公钥验签一张真证书。
	_, pubHex := makeNodeKey(t)
	nonce, _ := NewNonce()
	now := time.Now()
	cert := Cert{
		SubjectNodeID: NodeIDFromPubKeyHex(pubHex),
		SubjectPubKey: pubHex,
		Role:          RoleServer,
		NotBefore:     now.Add(-time.Minute).Unix(),
		NotAfter:      now.Add(time.Hour).Unix(),
		Nonce:         nonce,
	}
	sc, _ := Sign(caPriv, cert)
	if err := Verify(pub, sc, VerifyOptions{}); err != nil {
		t.Fatalf("用 PEM 往返后的公钥验签应通过: %v", err)
	}
}

func TestCAPrivateKeyPEMRoundTrip(t *testing.T) {
	caPriv, _ := GenerateCAKey()
	pemStr, err := MarshalCAPrivateKeyPEM(caPriv)
	if err != nil {
		t.Fatalf("编码私钥失败: %v", err)
	}
	priv2, err := ParseCAPrivateKeyPEM(pemStr)
	if err != nil {
		t.Fatalf("解析私钥失败: %v", err)
	}
	if priv2.D.Cmp(caPriv.D) != 0 {
		t.Fatal("私钥往返后不一致")
	}
}
