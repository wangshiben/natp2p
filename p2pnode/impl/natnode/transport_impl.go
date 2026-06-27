package natnode

import (
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"context"
)

// NATTransport 实现 p2pnode.Transport，委托给 networkFrameWork 的拨号/注册函数。
type NATTransport struct {
	pubKeyHex string
}

// NewNATTransport 创建使用指定公钥 hex 进行 relay 通信的 Transport。
func NewNATTransport(pubKeyHex string) *NATTransport {
	return &NATTransport{pubKeyHex: pubKeyHex}
}

// Register 将本节点注册为 relay 可达目标（dual: KCP + TCP 双 leg）。
//
// 恢复 dual 注册以获得 KCP 跨境高吞吐。跨中继桥接侧通过「确定性只桥接 KCP(send-preferred)
// leg」规避双 leg 在 relayStream / 桥接 active 字段上的 failover 竞态
// （见 relaynode.findAndBridge 的 KCP 优先建桥逻辑）。
func (t *NATTransport) Register(ctx context.Context, relayAddr string, publicKeyHex string) (network.Stream, error) {
	return networkFrameWork.TryRegisterRelayStream(publicKeyHex, relayAddr)
}

// Dial 经指定 relay 连接到目标节点（dual: KCP + TCP 双 leg）。
// 返回原始流（首条 hello 已发送）和连接 ID。
func (t *NATTransport) Dial(ctx context.Context, relayAddr string, targetID p2pnode.NodeID) (network.Stream, string, error) {
	return networkFrameWork.TryConnectTCPStream(relayAddr, string(targetID), t.pubKeyHex)
}
