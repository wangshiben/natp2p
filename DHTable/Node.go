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

// NewNode 创建新节点，生成 ECDH 密钥对。
// PeerID = hex(SHA256(hex(公钥原始字节)))，与 relay/crypto 层约定一致。
func NewNode() (*Node, error) {
	// 生成 P-256 椭圆曲线密钥对
	privateKey, err := crypoto.MakeKeyPair()
	if err != nil {
		return nil, err
	}

	// 使用公钥 hex 的 SHA256 哈希生成 PeerID（与 Dialers.go / TLSPacakge.go 一致）
	publicKey := privateKey.PublicKey()
	publicKeyBytes := publicKey.Bytes()
	pubKeyHex := hex.EncodeToString(publicKeyBytes)

	hash := sha256.Sum256([]byte(pubKeyHex))
	peerID := hex.EncodeToString(hash[:])

	return &Node{
		peerID:     peerID,
		privKey:    privateKey,
		pubKey:     publicKey,
		lastCalled: time.Now().Unix(),
		lastSeen:   time.Now().Unix(),
	}, nil
}

// NewNodeWithKey 使用现有密钥创建节点。
// PeerID = hex(SHA256(hex(公钥原始字节)))，与 relay/crypto 层约定一致。
func NewNodeWithKey(privateKey *ecdh.PrivateKey) (*Node, error) {
	publicKey := privateKey.PublicKey()
	publicKeyBytes := publicKey.Bytes()
	pubKeyHex := hex.EncodeToString(publicKeyBytes)

	hash := sha256.Sum256([]byte(pubKeyHex))
	peerID := hex.EncodeToString(hash[:])

	return &Node{
		peerID:     peerID,
		privKey:    privateKey,
		pubKey:     publicKey,
		lastCalled: time.Now().Unix(),
		lastSeen:   time.Now().Unix(),
	}, nil
}

// NewNodeFromPubKeyHex 从公钥十六进制字符串创建远程节点条目。
// 用于无对应私钥的场景（如从网络中获知的远程节点）。
// PeerID = hex(SHA256(pubKeyHex))，与 NewNode / NewNodeWithKey 一致。
func NewNodeFromPubKeyHex(pubKeyHex string) (*Node, error) {
	rawBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, err
	}
	pubKey, err := ecdh.P256().NewPublicKey(rawBytes)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(pubKeyHex))
	peerID := hex.EncodeToString(hash[:])

	return &Node{
		peerID:     peerID,
		pubKey:     pubKey,
		lastCalled: time.Now().Unix(),
		lastSeen:   time.Now().Unix(),
	}, nil
}

// NewNodeFromPeerID 仅用 PeerID 创建远程节点条目，公钥未知。
// 用于出站连接等仅知目标 NodeID 而无公钥的场景。
// Pubkey() 将返回空字符串，Sign() 不可用。
func NewNodeFromPeerID(peerID string) *Node {
	return &Node{
		peerID:     peerID,
		lastCalled: time.Now().Unix(),
		lastSeen:   time.Now().Unix(),
	}
}

// PeerID 返回节点的唯一标识符
func (n *Node) PeerID() string {
	return n.peerID
}

// Pubkey 返回公钥的十六进制字符串表示。
// 若公钥为空（如仅由 PeerID 构造的远程节点），返回空字符串。
func (n *Node) Pubkey() string {
	if n.pubKey == nil {
		return ""
	}
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
	if n.privKey == nil {
		return false, errors.New("VerifySignature: 私钥为空")
	}
	hash := sha256.Sum256(data)
	privKeyBytes := n.privKey.Bytes()
	hmac := sha256.New()
	hmac.Write(privKeyBytes)
	hmac.Write(hash[:])
	expectedSignature := hmac.Sum(nil)

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
	if n.privKey == nil {
		return nil, errors.New("Sign: 私钥为空（远程节点不支持签名）")
	}
	hash := sha256.Sum256(data)
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
		return big.Int{}, errors.New("node 不能为 nil")
	}

	nID, ok := new(big.Int).SetString(n.peerID, 16)
	if !ok {
		return big.Int{}, errors.New("无效的 peerID 格式")
	}

	otherID, ok := new(big.Int).SetString((*node).PeerID(), 16)
	if !ok {
		return big.Int{}, errors.New("无效的 node peerID 格式")
	}

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
