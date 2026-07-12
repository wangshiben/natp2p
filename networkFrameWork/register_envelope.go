package networkFrameWork

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// 注册消息信封（网络准入 indexSign 的承载）。
//
// 背景约束：relay 注册流的第一条消息 payload 传统上是【裸公钥 hex】，且传输层用
// nodeId = SHA256(payload) 派生被托管节点身份、作为 StreamGroup 的 key。为了让加入节点
// 在【同一条注册消息】里携带 CA 签发的准入证书(indexSign) 而不破坏该派生，这里定义一个
// 向后兼容的信封：
//   - 不带证书时：payload 仍是裸公钥 hex（与旧版逐字节一致，老 relay/新 relay 都认）；
//   - 带证书时：payload 是 JSON `{"pk":<公钥hex>,"is":<indexSign JSON>}`。
//     此时 SHA256(payload) 不再等于 SHA256(pk)，故接收侧需用本包 DecodeRegisterPayload
//     取出内部 pk、以 SHA256(pk) 作为真实 nodeId（TransportCover 注册分支会据此修正身份）。
//
// 判别方式：payload 首字节为 '{' 视为 JSON 信封，否则视为裸公钥 hex。裸公钥 hex 永远不会
// 以 '{' 开头，故无歧义、完全向后兼容。

// registerEnvelope 是带证书时的注册 payload JSON 结构。
// 字段名取短名以省字节（注册消息每连接一条，量不大，主要为清晰）。
type registerEnvelope struct {
	PubKey    string `json:"pk"`           // 加入节点公钥 hex
	IndexSign []byte `json:"is,omitempty"` // CA 签发的 indexSign(admission.SignedCert) JSON
}

// EncodeRegisterPayload 构造注册消息 payload。
//   - signJSON 为空：返回裸公钥 hex（向后兼容，与旧行为一致）；
//   - signJSON 非空：返回 JSON 信封 {pk, is}。
func EncodeRegisterPayload(pubKeyHex string, signJSON []byte) []byte {
	if len(signJSON) == 0 {
		return []byte(pubKeyHex)
	}
	b, err := json.Marshal(registerEnvelope{PubKey: pubKeyHex, IndexSign: signJSON})
	if err != nil {
		// 极不可能失败；退回裸公钥保证注册仍可用（只是没带证书）。
		return []byte(pubKeyHex)
	}
	return b
}

// DecodeRegisterPayload 从注册消息 payload 还原 (公钥hex, indexSign JSON)。
//   - 裸公钥 hex（不以 '{' 开头）：返回 (payload, nil)；
//   - JSON 信封：解析返回 (pk, is)。
func DecodeRegisterPayload(payload []byte) (pubKeyHex string, signJSON []byte) {
	if len(payload) == 0 {
		return "", nil
	}
	if payload[0] != '{' {
		return string(payload), nil
	}
	var env registerEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		// 解析失败：当作裸公钥兜底（不太可能，'{' 开头的裸公钥不存在）。
		return string(payload), nil
	}
	return env.PubKey, env.IndexSign
}

// NodeIDFromPubKeyHex 由公钥 hex 派生 nodeId（SHA256 hex），与传输层/证书口径一致。
func NodeIDFromPubKeyHex(pubKeyHex string) string {
	hash := sha256.Sum256([]byte(pubKeyHex))
	return hex.EncodeToString(hash[:])
}
