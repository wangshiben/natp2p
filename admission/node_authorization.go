package admission

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const nodeAuthorizationIDDomain = "CA-NODE-AUTHORIZATION-ID-V1\x00"

func ParseIdentityPublicKey(value string) (*ecdh.PublicKey, error) {
	if value == "" {
		return nil, errors.New("admission: 公钥为空")
	}
	encoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("admission: 公钥不是合法十六进制: %w", err)
	}
	if hex.EncodeToString(encoded) != value {
		return nil, errors.New("admission: 公钥必须使用规范小写十六进制")
	}
	publicKey, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("admission: 公钥不是合法 P-256 公钥: %w", err)
	}
	return publicKey, nil
}

func BillingKeyIDFromPublicKeyHex(publicKeyHex string) (string, error) {
	publicKey, err := ParseIdentityPublicKey(publicKeyHex)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(publicKey.Bytes())
	return hex.EncodeToString(digest[:]), nil
}

func NodeAuthorizationID(nodeID, billingKeyID string) string {
	digest := sha256.Sum256([]byte(nodeAuthorizationIDDomain + nodeID + "\x00" + billingKeyID))
	return hex.EncodeToString(digest[:])
}

func ValidateBillingBinding(cert Cert) error {
	boundFields := 0
	for _, value := range []string{cert.AuthorizationID, cert.BillingKeyID, cert.BillingPubKey} {
		if value != "" {
			boundFields++
		}
	}
	if boundFields == 0 {
		return nil
	}
	if boundFields != 3 {
		return errors.New("admission: 证书扣费授权绑定不完整")
	}
	keyID, err := BillingKeyIDFromPublicKeyHex(cert.BillingPubKey)
	if err != nil {
		return fmt.Errorf("admission: 扣费公钥非法: %w", err)
	}
	if keyID != cert.BillingKeyID {
		return errors.New("admission: 扣费密钥 ID 与扣费公钥不匹配")
	}
	if NodeAuthorizationID(cert.SubjectNodeID, cert.BillingKeyID) != cert.AuthorizationID {
		return errors.New("admission: 节点授权 ID 与节点及扣费密钥不匹配")
	}
	return nil
}

func NewNodeAuthorizationRequest(
	identityPrivateKey *ecdh.PrivateKey,
	billingPrivateKey *ecdh.PrivateKey,
	role Role,
	ttl time.Duration,
) (NodeAuthorizationRequest, error) {
	if identityPrivateKey == nil || billingPrivateKey == nil {
		return NodeAuthorizationRequest{}, errors.New("admission: 节点身份私钥和扣费私钥均不能为空")
	}
	if !role.Valid() {
		return NodeAuthorizationRequest{}, fmt.Errorf("admission: 非法节点角色 %q", role)
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return NodeAuthorizationRequest{}, fmt.Errorf("admission: 生成节点授权 nonce 失败: %w", err)
	}
	billingPublicKey := hex.EncodeToString(billingPrivateKey.PublicKey().Bytes())
	billingKeyID, err := BillingKeyIDFromPublicKeyHex(billingPublicKey)
	if err != nil {
		return NodeAuthorizationRequest{}, err
	}
	request := NodeAuthorizationRequest{
		SubjectPubKey: hex.EncodeToString(identityPrivateKey.PublicKey().Bytes()),
		Role:          role, BillingKeyID: billingKeyID, Timestamp: time.Now().UTC().Unix(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes), TTLSeconds: int64(ttl / time.Second),
	}
	if ttl <= 0 {
		request.TTLSeconds = 0
	}
	if err := SignNodeAuthorizationRequest(&request, identityPrivateKey, billingPrivateKey); err != nil {
		return NodeAuthorizationRequest{}, err
	}
	return request, nil
}

func SignNodeAuthorizationRequest(
	request *NodeAuthorizationRequest,
	identityPrivateKey *ecdh.PrivateKey,
	billingPrivateKey *ecdh.PrivateKey,
) error {
	if request == nil || identityPrivateKey == nil || billingPrivateKey == nil {
		return errors.New("admission: 节点授权请求或签名私钥为空")
	}
	identityPublicKey := hex.EncodeToString(identityPrivateKey.PublicKey().Bytes())
	if request.SubjectPubKey != identityPublicKey {
		return errors.New("admission: 节点身份私钥与授权请求公钥不匹配")
	}
	billingKeyID, err := BillingKeyIDFromPublicKeyHex(hex.EncodeToString(billingPrivateKey.PublicKey().Bytes()))
	if err != nil {
		return err
	}
	if request.BillingKeyID != billingKeyID {
		return errors.New("admission: 扣费私钥与授权请求 Key ID 不匹配")
	}
	digest := sha256.Sum256([]byte(NodeAuthorizationCanonical(*request)))
	request.NodeSignature, err = signAuthorizationDigest(identityPrivateKey, digest[:])
	if err != nil {
		return err
	}
	request.BillingSignature, err = signAuthorizationDigest(billingPrivateKey, digest[:])
	return err
}

func signAuthorizationDigest(privateKey *ecdh.PrivateKey, digest []byte) (string, error) {
	ecdsaKey, err := authorizationECDSAPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, digest)
	if err != nil {
		return "", fmt.Errorf("admission: 节点授权签名失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func authorizationECDSAPrivateKey(privateKey *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	publicKeyBytes := privateKey.PublicKey().Bytes()
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil || y == nil {
		return nil, errors.New("admission: 私钥不是合法的 P-256 密钥")
	}
	scalar := new(big.Int).SetBytes(privateKey.Bytes())
	if scalar.Sign() <= 0 || scalar.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, errors.New("admission: P-256 私钥标量非法")
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: scalar}, nil
}
