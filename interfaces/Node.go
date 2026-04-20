package interfaces

import (
	"bnfs_p2p/network"
	"math/big"
)

type Node interface {
	PeerID() string
	Pubkey() string                  // 提供公钥
	Verify([]byte) (bool, error)     // 验证某个签名是否由自己生成
	Sign([]byte) ([]byte, error)     // 签名
	LastCalled() int64               // 上次向上一级节点发送心跳包的时间
	XOR(node *Node) (big.Int, error) // 计算这个节点与某个节点的XOR距离
	UpdateLastSeen()
	GetStream() network.Stream // 获取节点的连接(P2P打洞)
}
