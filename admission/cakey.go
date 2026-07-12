package admission

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// CA 签发密钥的编解码工具。
//
// 选用标准的 SPKI(PKIX) + PEM 编码公钥、SEC1 + PEM 编码私钥：这是跨语言、跨工具通用的
// 格式（openssl、Node.js、Python 均原生支持），便于日后把 CA 换成其它语言写的正式 Web 应用
// 而不破坏已分发的公钥。曲线固定为 P-256，与框架节点身份同曲线。

// GenerateCAKey 生成一把新的 CA ECDSA(P-256) 签发密钥。
func GenerateCAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalCAPublicKeyPEM 把 CA 公钥编码为 PKIX/SPKI PEM（"PUBLIC KEY" 块）。
// 这是 relay 侧要拉取并缓存的内容。
func MarshalCAPublicKeyPEM(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("admission: CA 公钥为空")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("admission: 编码 CA 公钥失败: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// ParseCAPublicKeyPEM 从 PKIX/SPKI PEM 解析出 CA 公钥（P-256）。
func ParseCAPublicKeyPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("admission: CA 公钥 PEM 解析失败（无 PEM 块）")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("admission: CA 公钥 DER 解析失败: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("admission: CA 公钥不是 ECDSA 公钥")
	}
	if ecPub.Curve != elliptic.P256() {
		return nil, errors.New("admission: CA 公钥曲线不是 P-256")
	}
	return ecPub, nil
}

// MarshalCAPrivateKeyPEM 把 CA 私钥编码为 SEC1 PEM（"EC PRIVATE KEY" 块），用于 CA 端持久化。
func MarshalCAPrivateKeyPEM(priv *ecdsa.PrivateKey) (string, error) {
	if priv == nil {
		return "", errors.New("admission: CA 私钥为空")
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("admission: 编码 CA 私钥失败: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// ParseCAPrivateKeyPEM 从 SEC1 PEM 解析 CA 私钥。
func ParseCAPrivateKeyPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("admission: CA 私钥 PEM 解析失败（无 PEM 块）")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("admission: CA 私钥 DER 解析失败: %w", err)
	}
	return priv, nil
}
