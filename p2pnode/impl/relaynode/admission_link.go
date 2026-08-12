package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/logx"
	"encoding/json"
	"errors"
	"fmt"
)

type SecurityProfile string

const (
	SecurityProfileDevelopment SecurityProfile = "development"
	SecurityProfileStaging     SecurityProfile = "staging"
	SecurityProfileProduction  SecurityProfile = "production"
)

func ParseSecurityProfile(value string) (SecurityProfile, error) {
	// 将部署环境字符串解析为受约束的安全配置档位。
	switch SecurityProfile(value) {
	case SecurityProfileDevelopment, SecurityProfileStaging, SecurityProfileProduction:
		return SecurityProfile(value), nil
	default:
		return "", fmt.Errorf("relaynode: invalid security profile %q", value)
	}
}

// 网络准入（无交互 indexSign 方案，2026-07-07 用户定稿）。
//
// 思路：加入方（relay/NAT 节点）随【第一条消息】携带一份 CA 签发的准入证书(indexSign)——
// 内容含加入节点公钥、随机 salt(Nonce)、签发时间戳(NotBefore/NotAfter)、角色(Role)。
// 验证方用【CA 公钥离线验签】即可，无需请求 index、无需任何交互往返。
//
// 为什么放弃交互式挑战-应答：dual(KCP+TCP) 控制链路会在对端产生两条独立 leg 各自接管，
// 交互握手需要两条 leg rendezvous、易竞态；而无交互 indexSign 每条 leg 自带证书、各自离线
// 验签，天然无竞态，也保住了 KCP+TCP 共存。
//
// 安全边界（诚实标注）：indexSign 证明「CA 授权了该公钥+角色」，不单独证明「出示者持有对应
// 私钥」（证书是明文可抄的）。但数据面仍是端到端 ECDH-TLS：冒用他人证书者没有对应私钥，
// 既无法作为 callee 完成 TLS、也无法解密流量，故最多造成「注册占位/DoS」，不致窃听或计费欺诈。
// 如需私钥持有证明，可后续加一步挑战-应答作为可选增强（当前默认不启用）。

// AdmissionMode 控制准入的强制程度。
type AdmissionMode int

const (
	// AdmissionOff 完全不校验准入证书（默认）。既有行为不变。
	AdmissionOff AdmissionMode = iota
	// AdmissionWarn 校验证书，失败仅记 WARN 但仍放行（灰度/联调用）。
	AdmissionWarn
	// AdmissionEnforce 校验证书，失败即拒绝链路/注册（生产准入）。
	AdmissionEnforce
)

// AdmissionConfig 是 RelayNode 的准入配置。
type AdmissionConfig struct {
	Mode                AdmissionMode
	Profile             SecurityProfile
	SelfCert            *admission.SignedCert  // 本节点持有的准入证书(indexSign)，随 HELLO/注册携带
	Verifier            admission.CertVerifier // 离线证书验证器（通常是 *admission.CAClient）
	RevocationStatePath string
}

func ValidateAdmissionConfig(cfg *AdmissionConfig, verifierNodeID string) error {
	// 在 Relay 启动前检查生产环境证书、验证器和撤销状态路径是否完整。
	if cfg == nil {
		return errors.New("relaynode: admission configuration is required")
	}
	if cfg.Profile == "" {
		return errors.New("relaynode: security profile must be explicit")
	}
	if cfg.Profile == SecurityProfileProduction {
		if cfg.Mode != AdmissionEnforce {
			return errors.New("relaynode: production requires admission enforce")
		}
		if cfg.SelfCert == nil || cfg.Verifier == nil {
			return errors.New("relaynode: production requires a relay certificate and CA verifier")
		}
		if cfg.SelfCert.Cert.Role != admission.RoleRelay || cfg.SelfCert.Cert.SubjectNodeID != verifierNodeID {
			return errors.New("relaynode: production relay certificate does not match identity")
		}
		if cfg.SelfCert.Cert.AuthorizationID == "" || cfg.SelfCert.Cert.BillingKeyID == "" {
			return errors.New("relaynode: production requires an independently bound billing authorization")
		}
		if cfg.RevocationStatePath == "" {
			return errors.New("relaynode: production requires a durable revocation state path")
		}
		if err := cfg.Verifier.Verify(cfg.SelfCert, admission.VerifyOptions{
			ExpectNodeID: verifierNodeID, ExpectRole: admission.RoleRelay,
		}); err != nil {
			return fmt.Errorf("relaynode: production relay certificate verification failed: %w", err)
		}
	}
	if cfg.Profile == SecurityProfileStaging && cfg.Mode == AdmissionOff {
		return errors.New("relaynode: staging cannot disable admission")
	}
	return nil
}

// SetAdmission 安装准入配置。Mode=AdmissionOff（默认）时完全不启用。
// 必须在 Start() / ConnectPeer() 之前调用。
// 启用时同时把 nat→relay 注册准入校验钩子装到底层 TransportCover。
func (n *RelayNode) SetAdmission(cfg *AdmissionConfig) {
	n.mu.Lock()
	n.admission = cfg
	n.mu.Unlock()
	n.applyAdmissionHooks()
}

func (n *RelayNode) SetAdmissionChecked(cfg *AdmissionConfig) error {
	// 校验准入配置后再安装钩子，避免运行中进入半配置状态。
	if err := ValidateAdmissionConfig(cfg, n.idStr()); err != nil {
		return err
	}
	n.SetAdmission(cfg)
	return nil
}

func (n *RelayNode) admissionConfig() *AdmissionConfig {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.admission
}

// admissionEnabled 报告是否需要校验准入证书。
func (n *RelayNode) admissionEnabled() bool {
	cfg := n.admissionConfig()
	return cfg != nil && cfg.Mode != AdmissionOff
}

// selfCertJSON 返回本节点准入证书的 JSON（供随 HELLO/注册携带）。未配置时返回 nil。
func (n *RelayNode) selfCertJSON() []byte {
	cfg := n.admissionConfig()
	if cfg == nil || cfg.SelfCert == nil {
		return nil
	}
	b, err := json.Marshal(cfg.SelfCert)
	if err != nil {
		return nil
	}
	return b
}

// verifyPeerCertJSON 离线校验对端随消息携带的准入证书。
//
//	certJSON     对端携带的 SignedCert JSON（可能为空——老对端/未配置）。
//	expectRole   非空时要求证书角色匹配（控制链路要求对端为 relay）。
//	expectNodeID 非空时要求证书主体等于它（绑定到对端自报身份，防错配/张冠李戴）。
//
// 返回 (peer, nil) 校验通过；(nil, err) 校验失败。校验项由 admission.Verify 完成
// （CA 签名 + NodeID 自洽 + 有效期 + 角色/主体绑定）。
func (n *RelayNode) verifyPeerCertJSON(certJSON []byte, expectRole admission.Role, expectNodeID string) (*admission.Cert, error) {
	cfg := n.admissionConfig()
	if cfg == nil || cfg.Mode == AdmissionOff {
		return nil, nil // 未启用：放行
	}
	if !n.revocationSyncFresh() {
		return nil, errors.New("admission: revocation state is stale")
	}
	if cfg.Verifier == nil {
		if cfg.Mode == AdmissionEnforce {
			return nil, errors.New("admission: 已开启 enforce 但未配置验证器")
		}
		return nil, nil
	}
	if len(certJSON) == 0 {
		return nil, errors.New("admission: 对端未携带准入证书")
	}
	var sc admission.SignedCert
	if err := json.Unmarshal(certJSON, &sc); err != nil {
		return nil, err
	}
	if err := cfg.Verifier.Verify(&sc, admission.VerifyOptions{ExpectRole: expectRole, ExpectNodeID: expectNodeID}); err != nil {
		return nil, err
	}
	if n.businessScopeDenied(sc.Cert) || n.businessCertificateDenied(&sc) {
		return nil, errors.New("admission: peer certificate is revoked")
	}
	return &sc.Cert, nil
}

// gateAdmission 按 Mode 把校验结果转成「是否放行」决策，并统一记日志。
// 返回 true=放行；false=拒绝（调用方应关闭链路/拒绝注册）。
func (n *RelayNode) gateAdmission(cert *admission.Cert, err error, who string) bool {
	cfg := n.admissionConfig()
	if cfg == nil || cfg.Mode == AdmissionOff {
		return true
	}
	if err != nil {
		if cfg.Mode == AdmissionEnforce {
			logx.Errorf("[relaynode] 准入校验失败(enforce, 拒绝) %s: %v", who, err)
			return false
		}
		logx.Warnf("[relaynode] 准入校验失败(warn, 放行) %s: %v", who, err)
		return true
	}
	if cert != nil {
		logx.Infof("[relaynode] 准入校验通过 %s: subject=%.16s role=%s", who, cert.SubjectNodeID, cert.Role)
	}
	return true
}
