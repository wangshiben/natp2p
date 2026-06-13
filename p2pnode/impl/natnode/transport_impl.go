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

// Register 将本节点注册为 relay 可达目标（TCP 单 leg）。
//
// 使用 TCP 单 leg 注册（而非 dual KCP+TCP）：所有连接都经 relay 中转, relay 在公网且 TCP 稳定;
// 单 leg 彻底避免 relayStream 的 KCP/TCP 双 leg 在中继 / 跨中继转发处的 failover 竞态
// （dual 注册时, relayStream 某条 leg 中途 EOF 会让跨中继数据转发中断, 表现为时好时坏）。
func (t *NATTransport) Register(ctx context.Context, relayAddr string, publicKeyHex string) (network.Stream, error) {
	return networkFrameWork.TryRegisterRelayStreamTCP(publicKeyHex, relayAddr)
}

// Dial 经指定 relay 连接到目标节点（TCP 单 leg）。
// 返回原始流（首条 hello 已发送）和连接 ID。
func (t *NATTransport) Dial(ctx context.Context, relayAddr string, targetID p2pnode.NodeID) (network.Stream, string, error) {
	return networkFrameWork.TryConnectTCPOnlyStream(relayAddr, string(targetID), t.pubKeyHex)
}
