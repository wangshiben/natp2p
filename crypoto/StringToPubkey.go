package crypoto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
)

// ExtractPublicKeyFromHex 从 Hex 字符串中提取 ecdsa.PublicKey
// 对应 Node.js 端的 0x04 + X(32字节) + Y(32字节) 格式
func ExtractPublicKeyFromHex(hexStr string) (*ecdh.PublicKey, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	// 直接从字节还原公钥，ecdh 库会自动校验格式
	return ecdh.P256().NewPublicKey(bytes)
}
func MakeKeyPair() (*ecdh.PrivateKey, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
func GetPubKeyStr(key *ecdh.PublicKey) string {
	return hex.EncodeToString(key.Bytes())
}

// GetPrivKeyStr 把 P-256 ECDH 私钥序列化为 hex 字符串（32 字节标量）。
func GetPrivKeyStr(key *ecdh.PrivateKey) string {
	return hex.EncodeToString(key.Bytes())
}

// ExtractPrivateKeyFromHex 从 hex 字符串还原 P-256 ECDH 私钥。
// 与 GetPrivKeyStr 对称，用于从配置 / 存档恢复节点身份。
func ExtractPrivateKeyFromHex(hexStr string) (*ecdh.PrivateKey, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPrivateKey(bytes)
}
