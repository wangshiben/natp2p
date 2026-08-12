// Package admissioncli 提供 cmd 层接入网络准入/计费的公共帮助函数：
// 向独立 CA/indexServer Web 服务拉取公钥、申请角色证书，并装配到 relay / nat 节点。
//
// 抽出成包是为了让 relaychat / tunnel 的多个 main 复用同一套接线，避免拷贝漂移。
// 它依赖 admission（中立包）与 relaynode / natnode（装配目标）。
package admissioncli

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/p2pnode/impl/natnode"
	"bnfs_p2p/p2pnode/impl/relaynode"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	issueTokenFileEnv          = "BNFS_CA_ISSUE_TOKEN_FILE"
	securityProfileEnv         = "BNFS_SECURITY_PROFILE"
	certificateFileEnv         = "BNFS_CA_CERT_FILE"
	billingKeyFileEnv          = "BNFS_BILLING_KEY_FILE"
	revocationStateFileEnv     = "BNFS_REVOCATION_STATE_FILE"
	maximumCertificateFileSize = 64 << 10
)

func configuredSecurityProfile() (relaynode.SecurityProfile, error) {
	value := os.Getenv(securityProfileEnv)
	if value == "" {
		value = string(relaynode.SecurityProfileProduction)
	}
	return relaynode.ParseSecurityProfile(value)
}

type billingPrivateKeyJWK struct {
	KeyType     string   `json:"kty"`
	Curve       string   `json:"crv"`
	X           string   `json:"x"`
	Y           string   `json:"y"`
	D           string   `json:"d"`
	KeyOps      []string `json:"key_ops,omitempty"`
	Extractable bool     `json:"ext,omitempty"`
}

type billingPrivateKeyBundle struct {
	Version                   int                  `json:"version"`
	KeyID                     string               `json:"key_id"`
	Label                     string               `json:"label"`
	Algorithm                 string               `json:"algorithm"`
	PrivateKeyJWK             billingPrivateKeyJWK `json:"private_key_jwk"`
	PublicKeyHex              string               `json:"public_key_hex"`
	ChargeEndpoint            string               `json:"charge_endpoint,omitempty"`
	NodeAuthorizationEndpoint string               `json:"node_authorization_endpoint,omitempty"`
	FrameworkEnvironment      string               `json:"framework_environment,omitempty"`
	CanonicalFormat           string               `json:"canonical_format,omitempty"`
	RegistrationStatus        string               `json:"registration_status,omitempty"`
	GeneratedAt               string               `json:"generated_at,omitempty"`
}

// ParseMode 把字符串解析为 relaynode.AdmissionMode；空串按「有 CA 则 enforce，否则 off」。
func ParseMode(s string, caGiven bool) relaynode.AdmissionMode {
	switch s {
	case "off":
		return relaynode.AdmissionOff
	case "warn":
		return relaynode.AdmissionWarn
	case "enforce":
		return relaynode.AdmissionEnforce
	default:
		if caGiven {
			return relaynode.AdmissionEnforce
		}
		return relaynode.AdmissionOff
	}
}

// newClient 创建 CAClient 并拉取缓存 CA 公钥（离线验签前提）。
func newClient(caURL string) (*admission.CAClient, error) {
	cc := admission.NewCAClient(caURL)
	if tokenFile := os.Getenv(issueTokenFileEnv); tokenFile != "" {
		if err := cc.SetIssueBearerTokenFile(tokenFile); err != nil {
			return nil, fmt.Errorf("加载 CA 签发凭据失败: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cc.RefreshPubKey(ctx); err != nil {
		return nil, fmt.Errorf("拉取 CA 公钥失败: %w", err)
	}
	return cc, nil
}

func requestCert(cc *admission.CAClient, pubKeyHex string, role admission.Role) (*admission.SignedCert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sc, err := cc.Issue(ctx, admission.IssueRequest{SubjectPubKey: pubKeyHex, Role: role})
	if err != nil {
		return nil, fmt.Errorf("向 CA 申请 %s 证书失败: %w", role, err)
	}
	return sc, nil
}

func authorizeNodeCert(
	cc *admission.CAClient,
	request admission.NodeAuthorizationRequest,
) (*admission.SignedCert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := cc.AuthorizeNode(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("向 CA 申请 %s 节点扣费授权失败: %w", request.Role, err)
	}
	if err := cc.Verify(response.SignedCert, admission.VerifyOptions{
		ExpectNodeID: response.NodeID, ExpectRole: request.Role,
	}); err != nil {
		return nil, fmt.Errorf("CA 返回的节点扣费证书验签失败: %w", err)
	}
	return response.SignedCert, nil
}

func certificateForIdentity(cc *admission.CAClient, pubKeyHex, nodeID string, role admission.Role) (*admission.SignedCert, error) {
	certificateFile := os.Getenv(certificateFileEnv)
	if certificateFile == "" {
		return requestCert(cc, pubKeyHex, role)
	}
	if os.Getenv(issueTokenFileEnv) != "" {
		return nil, fmt.Errorf("%s 与 %s 不能同时配置", certificateFileEnv, issueTokenFileEnv)
	}
	certificate, err := readCertificateFile(certificateFile)
	if err != nil {
		return nil, fmt.Errorf("加载预签证书失败: %w", err)
	}
	if err := cc.Verify(certificate, admission.VerifyOptions{
		ExpectNodeID: nodeID,
		ExpectRole:   role,
	}); err != nil {
		return nil, fmt.Errorf("预签证书验签失败: %w", err)
	}
	if certificate.Cert.SubjectPubKey != pubKeyHex {
		return nil, fmt.Errorf("预签证书公钥与本地身份不匹配")
	}
	return certificate, nil
}

func readCertificateFile(filename string) (*admission.SignedCert, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumCertificateFileSize {
		return nil, fmt.Errorf("证书文件必须是 1..%d 字节的普通文件", maximumCertificateFileSize)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maximumCertificateFileSize+1))
	decoder.DisallowUnknownFields()
	var certificate admission.SignedCert
	if err := decoder.Decode(&certificate); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("证书文件包含多余 JSON 值")
		}
		return nil, err
	}
	return &certificate, nil
}

func configuredBillingPrivateKey() (*ecdh.PrivateKey, bool, error) {
	filename := os.Getenv(billingKeyFileEnv)
	if filename == "" {
		return nil, false, nil
	}
	if os.Getenv(issueTokenFileEnv) != "" {
		return nil, false, fmt.Errorf("%s 不能与 %s 同时配置",
			billingKeyFileEnv, issueTokenFileEnv)
	}
	privateKey, err := readBillingPrivateKeyFile(filename)
	if err != nil {
		return nil, false, fmt.Errorf("加载 CA Web 扣费私钥失败: %w", err)
	}
	return privateKey, true, nil
}

func readBillingPrivateKeyFile(filename string) (*ecdh.PrivateKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumCertificateFileSize {
		return nil, fmt.Errorf("扣费私钥文件必须是 1..%d 字节的普通文件", maximumCertificateFileSize)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("扣费私钥文件权限必须为 0600 或更严格")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maximumCertificateFileSize+1))
	decoder.DisallowUnknownFields()
	var bundle billingPrivateKeyBundle
	if err := decoder.Decode(&bundle); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("扣费私钥文件包含多余 JSON 值")
		}
		return nil, err
	}
	if bundle.Version != 1 || bundle.Algorithm != "ECDSA_P256_SHA256" ||
		bundle.PrivateKeyJWK.KeyType != "EC" || bundle.PrivateKeyJWK.Curve != "P-256" {
		return nil, fmt.Errorf("扣费私钥格式或算法不受支持")
	}
	privateScalar, err := base64.RawURLEncoding.DecodeString(bundle.PrivateKeyJWK.D)
	if err != nil || len(privateScalar) != 32 {
		return nil, fmt.Errorf("扣费私钥 JWK 的 d 参数无效")
	}
	privateKey, err := ecdh.P256().NewPrivateKey(privateScalar)
	if err != nil {
		return nil, fmt.Errorf("扣费私钥不是合法 P-256 密钥: %w", err)
	}
	publicKey, err := admission.ParseIdentityPublicKey(bundle.PublicKeyHex)
	if err != nil || !bytes.Equal(publicKey.Bytes(), privateKey.PublicKey().Bytes()) {
		return nil, fmt.Errorf("扣费私钥与 public_key_hex 不匹配")
	}
	x, xErr := base64.RawURLEncoding.DecodeString(bundle.PrivateKeyJWK.X)
	y, yErr := base64.RawURLEncoding.DecodeString(bundle.PrivateKeyJWK.Y)
	jwkPublicKey := append([]byte{4}, append(x, y...)...)
	if xErr != nil || yErr != nil || len(x) != 32 || len(y) != 32 ||
		!bytes.Equal(jwkPublicKey, publicKey.Bytes()) {
		return nil, fmt.Errorf("扣费私钥 JWK 公钥坐标不匹配")
	}
	keyID, err := admission.BillingKeyIDFromPublicKeyHex(bundle.PublicKeyHex)
	if err != nil || keyID != bundle.KeyID {
		return nil, fmt.Errorf("扣费私钥 key_id 与公钥指纹不匹配")
	}
	if bundle.RegistrationStatus != "" && bundle.RegistrationStatus != "active" {
		return nil, fmt.Errorf("扣费私钥尚未在 CA Web 确认登记")
	}
	return privateKey, nil
}

func validateCertificateBillingBinding(
	certificate *admission.SignedCert,
	nodeID string,
	billingPrivateKey *ecdh.PrivateKey,
) error {
	if certificate == nil || billingPrivateKey == nil {
		return fmt.Errorf("预签证书或本地扣费私钥为空")
	}
	billingPublicKey := hex.EncodeToString(billingPrivateKey.PublicKey().Bytes())
	billingKeyID, err := admission.BillingKeyIDFromPublicKeyHex(billingPublicKey)
	if err != nil {
		return fmt.Errorf("计算本地扣费密钥 ID 失败: %w", err)
	}
	if certificate.Cert.BillingPubKey != billingPublicKey {
		return fmt.Errorf("预签证书扣费公钥与本地扣费私钥不匹配")
	}
	if certificate.Cert.BillingKeyID != billingKeyID {
		return fmt.Errorf("预签证书扣费密钥 ID 与本地扣费私钥不匹配")
	}
	if certificate.Cert.AuthorizationID != admission.NodeAuthorizationID(nodeID, billingKeyID) {
		return fmt.Errorf("预签证书节点授权 ID 与本地节点及扣费私钥不匹配")
	}
	return nil
}

// SetupRelay 为 relay/index 节点配置准入：拉公钥 + 申请 relay 证书 + SetAdmission。
// caURL 为空则不启用（直接返回 nil）。
func SetupRelay(rn *relaynode.RelayNode, caURL, modeStr string) error {
	profile, err := configuredSecurityProfile()
	if err != nil {
		return err
	}
	if caURL == "" {
		if profile == relaynode.SecurityProfileProduction {
			return fmt.Errorf("生产安全档要求配置 CA URL；本地开发请显式设置 %s=development", securityProfileEnv)
		}
		return nil
	}
	cc, err := newClient(caURL)
	if err != nil {
		return err
	}
	billingPrivateKey, independentBilling, err := configuredBillingPrivateKey()
	if err != nil {
		return err
	}
	if profile == relaynode.SecurityProfileProduction && !independentBilling {
		return fmt.Errorf("生产安全档要求通过 %s 配置独立扣费私钥", billingKeyFileEnv)
	}
	revocationStatePath := os.Getenv(revocationStateFileEnv)
	if profile == relaynode.SecurityProfileProduction && revocationStatePath == "" {
		return fmt.Errorf("生产安全档要求通过 %s 配置持久撤销状态文件", revocationStateFileEnv)
	}
	var cert *admission.SignedCert
	if independentBilling {
		if os.Getenv(certificateFileEnv) != "" {
			cert, err = certificateForIdentity(cc, rn.PubKeyHex(), string(rn.ID()), admission.RoleRelay)
			if err == nil {
				err = validateCertificateBillingBinding(cert, string(rn.ID()), billingPrivateKey)
			}
		} else {
			request, requestErr := rn.BuildNodeAuthorizationRequest(billingPrivateKey, 0)
			if requestErr != nil {
				return requestErr
			}
			cert, err = authorizeNodeCert(cc, request)
		}
		if err == nil {
			err = rn.SetBillingPrivateKey(billingPrivateKey)
		}
	} else {
		cert, err = certificateForIdentity(cc, rn.PubKeyHex(), string(rn.ID()), admission.RoleRelay)
	}
	if err != nil {
		return err
	}
	if err := rn.SetAdmissionChecked(&relaynode.AdmissionConfig{
		Mode: ParseMode(modeStr, true), Profile: profile, SelfCert: cert, Verifier: cc,
		RevocationStatePath: revocationStatePath,
	}); err != nil {
		return err
	}
	if revocationStatePath != "" {
		if err := rn.ConfigureRevocationControl(cc, cert, revocationStatePath); err != nil {
			return err
		}
	}
	fmt.Printf("已启用网络准入: CA=%s mode=%s role=relay certificate=%s\n", caURL, modeStr, certificateSource())
	return nil
}

// SetupNat 为 NAT 节点申请角色证书(indexSign)并注入。caURL 为空则不启用。
// role 用 admission.RoleServer / admission.RoleClient。
func SetupNat(node *natnode.NATNode, caURL string, role admission.Role) error {
	profile, err := configuredSecurityProfile()
	if err != nil {
		return err
	}
	if caURL == "" {
		if profile == relaynode.SecurityProfileProduction {
			return fmt.Errorf("生产安全档要求配置 CA URL；本地开发请显式设置 %s=development", securityProfileEnv)
		}
		return nil
	}
	cc, err := newClient(caURL)
	if err != nil {
		return err
	}
	billingPrivateKey, independentBilling, err := configuredBillingPrivateKey()
	if err != nil {
		return err
	}
	if profile == relaynode.SecurityProfileProduction && !independentBilling {
		return fmt.Errorf("生产安全档要求通过 %s 配置独立扣费私钥", billingKeyFileEnv)
	}
	var cert *admission.SignedCert
	if independentBilling {
		if os.Getenv(certificateFileEnv) != "" {
			cert, err = certificateForIdentity(cc, node.PubKeyHex(), string(node.ID()), role)
			if err == nil {
				err = validateCertificateBillingBinding(cert, string(node.ID()), billingPrivateKey)
			}
		} else {
			request, requestErr := node.BuildNodeAuthorizationRequest(billingPrivateKey, role, 0)
			if requestErr != nil {
				return requestErr
			}
			cert, err = authorizeNodeCert(cc, request)
		}
		if err == nil {
			err = node.SetBillingPrivateKey(billingPrivateKey)
		}
	} else {
		cert, err = certificateForIdentity(cc, node.PubKeyHex(), string(node.ID()), role)
	}
	if err != nil {
		return err
	}
	if err := node.SetAdmissionVerifier(cc); err != nil {
		return err
	}
	b, err := json.Marshal(cert)
	if err != nil {
		return fmt.Errorf("编码 indexSign 失败: %w", err)
	}
	node.SetIndexSign(b)
	fmt.Printf("已配置 indexSign: CA=%s role=%s certificate=%s\n", caURL, role, certificateSource())
	return nil
}

func certificateSource() string {
	if os.Getenv(billingKeyFileEnv) != "" {
		if os.Getenv(certificateFileEnv) != "" {
			return "pre-signed-billing-key"
		}
		return "billing-key-authorization"
	}
	if os.Getenv(certificateFileEnv) != "" {
		return "pre-signed"
	}
	return "issued"
}

// Role helpers（避免调用方 import admission）。
func RoleServer() admission.Role { return admission.RoleServer }
func RoleClient() admission.Role { return admission.RoleClient }
