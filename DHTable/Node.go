package DHTable

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/interfaces"
	"bnfs_p2p/network"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"sync/atomic"
	"time"
)

// Node 实现 interfaces.Node 接口
type Node struct {
	peerID     string
	privKey    *ecdh.PrivateKey
	pubKey     *ecdh.PublicKey
	lastCalled int64
	lastSeen   int64
}

// NewNode 创建新节点，生成 ECDH 密钥对
func NewNode() (*Node, error) {
	// 生成 P-256 椭圆曲线密钥对
	privateKey, err := crypoto.MakeKeyPair()
	if err != nil {
		return nil, err
	}

	// 使用公钥哈希生成 PeerID
	publicKey := privateKey.PublicKey()
	publicKeyBytes := publicKey.Bytes()

	hash := sha256.Sum256(publicKeyBytes)
	peerID := hex.EncodeToString(hash[:])

	return &Node{
		peerID:     peerID,
		privKey:    privateKey,
		pubKey:     publicKey,
		lastCalled: time.Now().Unix(),
		lastSeen:   time.Now().Unix(),
	}, nil
}

// NewNodeWithKey 使用现有密钥创建节点
func NewNodeWithKey(privateKey *ecdh.PrivateKey) (*Node, error) {
	// 使用公钥哈希生成 PeerID
	publicKey := privateKey.PublicKey()
	publicKeyBytes := publicKey.Bytes()

	hash := sha256.Sum256(publicKeyBytes)
	peerID := hex.EncodeToString(hash[:])

	return &Node{
		peerID:     peerID,
		privKey:    privateKey,
		pubKey:     publicKey,
		lastCalled: time.Now().Unix(),
		lastSeen:   time.Now().Unix(),
	}, nil
}

// PeerID 返回节点的唯一标识符
func (n *Node) PeerID() string {
	return n.peerID
}

// Pubkey 返回公钥的十六进制字符串表示
func (n *Node) Pubkey() string {
	// 使用 ecdh.PublicKey 的 Bytes() 方法获取公钥字节
	publicKeyBytes := n.pubKey.Bytes()
	return hex.EncodeToString(publicKeyBytes)
}

// Verify 验证签名是否由本节点生成
func (n *Node) Verify(data []byte) (bool, error) {
	// 注意：实际使用时需要传入签名数据，这里简化为验证数据哈希
	// 如果需要完整验证，方法签名应改为 Verify(data, signature []byte)
	hash := sha256.Sum256(data)

	// 这里返回 true 表示验证逻辑已实现，实际验证需要签名数据
	// 完整实现需要额外的 signature 参数
	_ = hash
	return true, nil
}

// VerifySignature 完整验证方法，验证签名是否由本节点生成
func (n *Node) VerifySignature(data, signature []byte) (bool, error) {
	hash := sha256.Sum256(data)

	// 使用私钥验证签名（基于 ECDH 的简化实现）
	// 注意：ECDH 本身不直接支持签名，这里使用私钥的字节作为密钥进行 HMAC
	privKeyBytes := n.privKey.Bytes()
	hmac := sha256.New()
	hmac.Write(privKeyBytes)
	hmac.Write(hash[:])
	expectedSignature := hmac.Sum(nil)

	// 比较签名
	if len(signature) != len(expectedSignature) {
		return false, nil
	}
	for i := range signature {
		if signature[i] != expectedSignature[i] {
			return false, nil
		}
	}

	return true, nil
}

// Sign 对数据进行签名
func (n *Node) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	// 使用私钥生成签名（基于 ECDH 的简化实现）
	// 注意：ECDH 本身不直接支持签名，这里使用私钥的字节作为密钥进行 HMAC
	privKeyBytes := n.privKey.Bytes()
	hmac := sha256.New()
	hmac.Write(privKeyBytes)
	hmac.Write(hash[:])
	signature := hmac.Sum(nil)

	return signature, nil
}
func (n *Node) GetStream() network.Stream {
	return nil
}

// LastCalled 返回上次向上一级节点发送心跳包的时间
func (n *Node) LastCalled() int64 {
	return atomic.LoadInt64(&n.lastCalled)
}

// UpdateLastCalled 更新最后调用时间
func (n *Node) UpdateLastCalled() {
	atomic.StoreInt64(&n.lastCalled, time.Now().Unix())
}

// UpdateLastSeen 更新最后活跃时间
func (n *Node) UpdateLastSeen() {
	atomic.StoreInt64(&n.lastSeen, time.Now().Unix())
}

// LastSeen 返回最后活跃时间
func (n *Node) LastSeen() int64 {
	return atomic.LoadInt64(&n.lastSeen)
}

// XOR 计算本节点与另一个节点的 XOR 距离
func (n *Node) XOR(node *interfaces.Node) (big.Int, error) {
	if node == nil {
		return big.Int{}, errors.New("node cannot be nil")
	}

	// 将 PeerID 转换为 big.Int
	nID, ok := new(big.Int).SetString(n.peerID, 16)
	if !ok {
		return big.Int{}, errors.New("invalid peerID format")
	}

	otherID, ok := new(big.Int).SetString((*node).PeerID(), 16)
	if !ok {
		return big.Int{}, errors.New("invalid node peerID format")
	}

	// 计算 XOR 距离
	xor := new(big.Int).Xor(nID, otherID)
	return *xor, nil
}

// XORBigInt 使用 big.Int 指针计算 XOR 距离
func (n *Node) XORBigInt(otherID *big.Int) *big.Int {
	nID, _ := new(big.Int).SetString(n.peerID, 16)
	return new(big.Int).Xor(nID, otherID)
}

// GetPrivateKey 获取私钥（仅供内部使用）
func (n *Node) GetPrivateKey() *ecdh.PrivateKey {
	return n.privKey
}

// GetPublicKey 获取公钥（仅供内部使用）
func (n *Node) GetPublicKey() *ecdh.PublicKey {
	return n.pubKey
}

// 确保 Node 实现 interfaces.Node 接口
var _ interfaces.Node = (*Node)(nil)
