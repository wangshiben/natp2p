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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	issueTokenFileEnv          = "BNFS_CA_ISSUE_TOKEN_FILE"
	certificateFileEnv         = "BNFS_CA_CERT_FILE"
	maximumCertificateFileSize = 64 << 10
)

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

// SetupRelay 为 relay/index 节点配置准入：拉公钥 + 申请 relay 证书 + SetAdmission。
// caURL 为空则不启用（直接返回 nil）。
func SetupRelay(rn *relaynode.RelayNode, caURL, modeStr string) error {
	if caURL == "" {
		return nil
	}
	cc, err := newClient(caURL)
	if err != nil {
		return err
	}
	cert, err := certificateForIdentity(cc, rn.PubKeyHex(), string(rn.ID()), admission.RoleRelay)
	if err != nil {
		return err
	}
	rn.SetAdmission(&relaynode.AdmissionConfig{
		Mode:     ParseMode(modeStr, true),
		SelfCert: cert,
		Verifier: cc,
	})
	fmt.Printf("已启用网络准入: CA=%s mode=%s role=relay certificate=%s\n", caURL, modeStr, certificateSource())
	return nil
}

// SetupNat 为 NAT 节点申请角色证书(indexSign)并注入。caURL 为空则不启用。
// role 用 admission.RoleServer / admission.RoleClient。
func SetupNat(node *natnode.NATNode, caURL string, role admission.Role) error {
	if caURL == "" {
		return nil
	}
	cc, err := newClient(caURL)
	if err != nil {
		return err
	}
	cert, err := certificateForIdentity(cc, node.PubKeyHex(), string(node.ID()), role)
	if err != nil {
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
	if os.Getenv(certificateFileEnv) != "" {
		return "pre-signed"
	}
	return "issued"
}

// Role helpers（避免调用方 import admission）。
func RoleServer() admission.Role { return admission.RoleServer }
func RoleClient() admission.Role { return admission.RoleClient }
