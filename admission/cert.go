// Package admission 定义「网络准入证书」的线格式与离线签名/验签算法。
//
// 设计目标（见 DESIGN_准入与计费_评估与决策.md）：
//   - 证书由一个【独立于 p2p 框架】的 CA/indexServer 服务用 ECDSA(P-256) 签发；
//   - 框架侧只需持有 CA 公钥即可【离线】验签，不必在每次校验时请求 CA；
//   - 证书把「节点身份(NodeID/公钥)」与「角色(relay/client/server)」绑定，
//     后者同时服务于计费方向（区分 clientNode / serverNode）。
//
// 本包只依赖 Go 标准库 crypto，不引用框架内任何包，从而与框架保持解耦：
// 日后 CA 做成正式 Web 应用时，可把本包的证书结构作为跨语言线格式契约的参考。
package admission

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Role 是证书声明的节点角色。计费方向据此区分 client / server。
type Role string

const (
	RoleRelay  Role = "relay"  // 中继节点
	RoleClient Role = "client" // 普通客户端（消费方）
	RoleServer Role = "server" // 服务提供方（上行计费对象）
)

// Valid 报告 role 是否为已知取值。
func (r Role) Valid() bool {
	switch r {
	case RoleRelay, RoleClient, RoleServer:
		return true
	}
	return false
}

// Cert 是证书主体（被签名的部分）。
//
// 字段全部为可确定性序列化的标量：Claims 用 json.Marshal 得到 canonical 字节后签名。
// 注意：一旦签发，任何字段改动都会使签名失效——这正是防篡改的基础。
type Cert struct {
	// SubjectNodeID 是证书持有者的 NodeID（= SHA256(SubjectPubKey) 的 hex）。
	SubjectNodeID string `json:"subject_node_id"`
	// SubjectPubKey 是持有者的 P-256 ECDH 公钥 hex（与框架节点身份同源）。
	// 验签方据它核对 NodeID 自洽，并在握手中校验对端确实持有对应私钥。
	SubjectPubKey string `json:"subject_pubkey"`
	// Role 是被授予的角色。
	Role Role `json:"role"`
	// NotBefore / NotAfter 是有效期（Unix 秒）。短期证书靠过期实现「软吊销」。
	NotBefore int64 `json:"not_before"`
	NotAfter  int64 `json:"not_after"`
	// Nonce 是签发方随机数（hex），防止相同 Claims 产生完全相同的证书、便于审计。
	Nonce string `json:"nonce"`
	// Issuer 是签发方标识（如 CA 服务名），仅供人读/审计，不参与信任决策。
	Issuer string `json:"issuer,omitempty"`
}

// SignedCert 是证书主体 + CA 的 ECDSA 签名，即节点随身携带的完整凭证。
type SignedCert struct {
	Cert Cert `json:"cert"`
	// Sig 是 CA 对 canonical(Cert) 的 ECDSA-P256 签名（ASN.1 DER, hex）。
	Sig string `json:"sig"`
}

// canonicalBytes 返回 Cert 的确定性序列化字节，作为签名/验签的输入。
//
// 用 json.Marshal：Go 的 encoding/json 对 struct 按字段声明顺序输出、无随机性，
// 对给定 Cert 值是确定的。跨语言实现须按相同字段顺序与命名产生等价字节。
func (c *Cert) canonicalBytes() ([]byte, error) {
	return json.Marshal(c)
}

// digest 返回 canonical(Cert) 的 SHA-256 摘要，供 ecdsa.Sign/Verify 使用。
func (c *Cert) digest() ([]byte, error) {
	b, err := c.canonicalBytes()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// Sign 用 CA 私钥对证书主体签名，返回完整 SignedCert。
func Sign(priv *ecdsa.PrivateKey, cert Cert) (*SignedCert, error) {
	if priv == nil {
		return nil, errors.New("admission: CA 私钥为空")
	}
	digest, err := cert.digest()
	if err != nil {
		return nil, fmt.Errorf("admission: 计算证书摘要失败: %w", err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		return nil, fmt.Errorf("admission: 签名失败: %w", err)
	}
	return &SignedCert{Cert: cert, Sig: hex.EncodeToString(sig)}, nil
}

// CertVerifier 抽象「用缓存的 CA 公钥离线验签」。*CAClient 满足它。
// 框架侧（relaynode 等）依赖此接口而非具体 CAClient，便于测试注入。
type CertVerifier interface {
	Verify(sc *SignedCert, opts VerifyOptions) error
}

// VerifyOptions 控制验签时的附加校验。
type VerifyOptions struct {
	// Now 是校验时刻（用于有效期判断）；零值表示用 time.Now()。
	Now time.Time
	// ExpectNodeID 非空时，要求证书 SubjectNodeID 与之相等（绑定到具体对端）。
	ExpectNodeID string
	// ExpectRole 非空时，要求证书 Role 与之相等。
	ExpectRole Role
	// SkipTimeCheck 为 true 时跳过有效期校验（仅测试用）。
	SkipTimeCheck bool
}

// Verify 用 CA 公钥离线验签，并做证书自洽与可选的附加校验。
//
// 校验项：
//  1. ECDSA 签名对 canonical(Cert) 有效；
//  2. SubjectNodeID == SHA256(SubjectPubKey)（身份自洽）；
//  3. 有效期（除非 SkipTimeCheck）；
//  4. 可选：ExpectNodeID / ExpectRole。
//
// 注意：本函数只证明「证书由 CA 签发且未被篡改、身份字段自洽」。它【不】证明出示者
// 真的持有 SubjectPubKey 对应私钥——那由握手阶段的 ECDH + ClientHi 交换完成（决策 B）。
func Verify(pub *ecdsa.PublicKey, sc *SignedCert, opts VerifyOptions) error {
	if pub == nil {
		return errors.New("admission: CA 公钥为空")
	}
	if sc == nil {
		return errors.New("admission: 证书为空")
	}
	cert := &sc.Cert

	// 1. 验签。
	sigBytes, err := hex.DecodeString(sc.Sig)
	if err != nil {
		return fmt.Errorf("admission: 签名 hex 解析失败: %w", err)
	}
	digest, err := cert.digest()
	if err != nil {
		return fmt.Errorf("admission: 计算证书摘要失败: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest, sigBytes) {
		return errors.New("admission: 证书签名无效（非 CA 签发或已被篡改）")
	}

	// 2. 身份自洽：NodeID == SHA256(pubkey hex)。
	if err := checkNodeIDMatchesPubKey(cert.SubjectNodeID, cert.SubjectPubKey); err != nil {
		return err
	}

	// 3. 有效期。
	if !opts.SkipTimeCheck {
		now := opts.Now
		if now.IsZero() {
			now = time.Now()
		}
		ts := now.Unix()
		if ts < cert.NotBefore {
			return fmt.Errorf("admission: 证书尚未生效 (now=%d not_before=%d)", ts, cert.NotBefore)
		}
		if ts >= cert.NotAfter {
			return fmt.Errorf("admission: 证书已过期 (now=%d not_after=%d)", ts, cert.NotAfter)
		}
	}

	// 4. 附加校验。
	if opts.ExpectNodeID != "" && opts.ExpectNodeID != cert.SubjectNodeID {
		return fmt.Errorf("admission: 证书主体不匹配: 期望 %.16s 收到 %.16s", opts.ExpectNodeID, cert.SubjectNodeID)
	}
	if opts.ExpectRole != "" && opts.ExpectRole != cert.Role {
		return fmt.Errorf("admission: 证书角色不匹配: 期望 %s 收到 %s", opts.ExpectRole, cert.Role)
	}

	if !cert.Role.Valid() {
		return fmt.Errorf("admission: 证书角色非法: %q", cert.Role)
	}
	return nil
}

// checkNodeIDMatchesPubKey 校验 nodeID == SHA256(pubKeyHex) 的 hex 表示。
func checkNodeIDMatchesPubKey(nodeID, pubKeyHex string) error {
	if nodeID == "" || pubKeyHex == "" {
		return errors.New("admission: 证书缺少 NodeID 或公钥")
	}
	hash := sha256.Sum256([]byte(pubKeyHex))
	want := hex.EncodeToString(hash[:])
	if want != nodeID {
		return fmt.Errorf("admission: NodeID 与公钥不自洽 (期望 %.16s 收到 %.16s)", want, nodeID)
	}
	return nil
}

// NodeIDFromPubKeyHex 是给调用方的便捷函数：由公钥 hex 推导 NodeID，
// 与框架 crypoto.verifyPubKeyToPubKey / TryRegisterRelayStream 的口径一致。
func NodeIDFromPubKeyHex(pubKeyHex string) string {
	hash := sha256.Sum256([]byte(pubKeyHex))
	return hex.EncodeToString(hash[:])
}

// NewNonce 生成一个 16 字节随机 nonce 的 hex 串。
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
