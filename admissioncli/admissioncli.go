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
	"time"
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
	cert, err := requestCert(cc, rn.PubKeyHex(), admission.RoleRelay)
	if err != nil {
		return err
	}
	rn.SetAdmission(&relaynode.AdmissionConfig{
		Mode:     ParseMode(modeStr, true),
		SelfCert: cert,
		Verifier: cc,
	})
	fmt.Printf("已启用网络准入: CA=%s mode=%s role=relay\n", caURL, modeStr)
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
	cert, err := requestCert(cc, node.PubKeyHex(), role)
	if err != nil {
		return err
	}
	b, err := json.Marshal(cert)
	if err != nil {
		return fmt.Errorf("编码 indexSign 失败: %w", err)
	}
	node.SetIndexSign(b)
	fmt.Printf("已申请 indexSign: CA=%s role=%s\n", caURL, role)
	return nil
}

// Role helpers（避免调用方 import admission）。
func RoleServer() admission.Role { return admission.RoleServer }
func RoleClient() admission.Role { return admission.RoleClient }
