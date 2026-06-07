package natnode

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bnfs_p2p/p2pnode"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// NATHandshakeHandler 实现 p2pnode.HandshakeHandler，基于 crypoto.NewTLSCrypto。
type NATHandshakeHandler struct {
	privKey *ecdh.PrivateKey
}

// NewNATHandshakeHandler 创建使用指定私钥的握手处理器。
func NewNATHandshakeHandler(privKey *ecdh.PrivateKey) *NATHandshakeHandler {
	return &NATHandshakeHandler{privKey: privKey}
}

// HandshakeIncoming 在入站流上执行服务端 TLS 握手。
// 调用前需已对原始流调用 SetStreamIdentity 绑定身份。
// firstMsg.Payload 是对端的公钥 hex，用于推导其 NodeID。
func (h *NATHandshakeHandler) HandshakeIncoming(ctx context.Context, stream network.Stream, firstMsg *network.Message) (p2pnode.PeerInfo, error) {
	hash := sha256.Sum256(firstMsg.Payload)
	peerID := hex.EncodeToString(hash[:])

	crypto, err := crypoto.NewTLSCrypto(stream, h.privKey)
	if err != nil {
		return p2pnode.PeerInfo{}, fmt.Errorf("natnode: TLS 握手失败: %w", err)
	}
	stream.SetCryptoSuite(crypto)

	return p2pnode.PeerInfo{
		ID:       p2pnode.NodeID(peerID),
		LastSeen: time.Now(),
	}, nil
}

// HandshakeOutgoing 在出站流上执行客户端 TLS 握手。
// 验证连接到的对端与 expectedID 一致。
func (h *NATHandshakeHandler) HandshakeOutgoing(ctx context.Context, stream network.Stream, expectedID p2pnode.NodeID) (p2pnode.PeerInfo, error) {
	crypto, err := crypoto.NewTLSCrypto(stream, h.privKey)
	if err != nil {
		return p2pnode.PeerInfo{}, fmt.Errorf("natnode: TLS 握手失败: %w", err)
	}
	stream.SetCryptoSuite(crypto)

	actualID := stream.NodeId()
	if actualID != string(expectedID) {
		return p2pnode.PeerInfo{}, fmt.Errorf("natnode: 对端 ID 不匹配: 期望 %s, 收到 %s", expectedID, actualID)
	}

	return p2pnode.PeerInfo{
		ID:       expectedID,
		LastSeen: time.Now(),
	}, nil
}
